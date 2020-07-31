package snmpgo

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// An argument for creating a SNMP Object
type SNMPArguments struct {
	Version          SNMPVersion   // SNMP version to use
	Network          string        // See net.Dial parameter (The default is `udp`)
	Address          string        // See net.Dial parameter
	Timeout          time.Duration // Request timeout (The default is 5sec)
	Retries          uint          // Number of retries (The default is `0`)
	MessageMaxSize   int           // Maximum size of an SNMP message (The default is `1400`)
	Community        string        // Community (V1 or V2c specific)
	UserName         string        // Security name (V3 specific)
	SecurityLevel    SecurityLevel // Security level (V3 specific)
	AuthPassword     string        // Authentication protocol pass phrase (V3 specific)
	AuthProtocol     AuthProtocol  // Authentication protocol (V3 specific)
	PrivPassword     string        // Privacy protocol pass phrase (V3 specific)
	PrivProtocol     PrivProtocol  // Privacy protocol (V3 specific)
	SecurityEngineId string        // Security engine ID (V3 specific)
	ContextEngineId  string        // Context engine ID (V3 specific)
	ContextName      string        // Context name (V3 specific)

	authEngineBoots int
	authEngineTime  int
}

func (a *SNMPArguments) setDefault() {
	if a.Network == "" {
		a.Network = "udp"
	}
	if a.Timeout <= 0 {
		a.Timeout = timeoutDefault
	}
	if a.MessageMaxSize == 0 {
		a.MessageMaxSize = msgSizeDefault
	}
}

func (a *SNMPArguments) validate() error {
	if v := a.Version; v != V1 && v != V2c && v != V3 {
		return &ArgumentError{
			Value:   v,
			Message: "Unknown SNMP Version",
		}
	}
	// RFC3412 Section 6
	if m := a.MessageMaxSize; (m != 0 && m < msgSizeMinimum) || m > math.MaxInt32 {
		return &ArgumentError{
			Value: m,
			Message: fmt.Sprintf("MessageMaxSize is range %d..%d",
				msgSizeMinimum, math.MaxInt32),
		}
	}
	if a.Version == V3 {
		// RFC3414 Section 5
		if l := len(a.UserName); l < 1 || l > 32 {
			return &ArgumentError{
				Value:   a.UserName,
				Message: "UserName length is range 1..32",
			}
		}
		if a.SecurityLevel > NoAuthNoPriv {
			// RFC3414 Section 11.2
			if len(a.AuthPassword) < 8 {
				return &ArgumentError{
					Value:   a.AuthPassword,
					Message: "AuthPassword is at least 8 characters in length",
				}
			}
			if p := a.AuthProtocol; p != Md5 && p != Sha {
				return &ArgumentError{
					Value:   a.AuthProtocol,
					Message: "Illegal AuthProtocol",
				}
			}
		}
		if a.SecurityLevel > AuthNoPriv {
			// RFC3414 Section 11.2
			if len(a.PrivPassword) < 8 {
				return &ArgumentError{
					Value:   a.PrivPassword,
					Message: "PrivPassword is at least 8 characters in length",
				}
			}
			if p := a.PrivProtocol; p != Des && p != Aes && p != Aes192 && p != Aes256 {
				return &ArgumentError{
					Value:   a.PrivProtocol,
					Message: "Illegal PrivProtocol",
				}
			}
		}
		if a.SecurityEngineId != "" {
			a.SecurityEngineId = stripHexPrefix(a.SecurityEngineId)
			_, err := engineIdToBytes(a.SecurityEngineId)
			if err != nil {
				return err
			}
		}
		if a.ContextEngineId != "" {
			a.ContextEngineId = stripHexPrefix(a.ContextEngineId)
			_, err := engineIdToBytes(a.ContextEngineId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *SNMPArguments) String() string {
	return escape(a)
}

// SNMP Object provides functions for the SNMP Client
type SNMP struct {
	conn   net.Conn
	args   *SNMPArguments
	engine *snmpEngine
}

// Open a connection
func (s *SNMP) Open() (err error) {
	if s.conn != nil {
		return
	}

	err = retry(int(s.args.Retries), func() error {
		conn, e := net.DialTimeout(s.args.Network, s.args.Address, s.args.Timeout)
		if e == nil {
			s.conn = conn
		}
		return e
	})
	if err != nil {
		return
	}

	s.engine = newSNMPEngine(s.args)
	if err = s.engine.Discover(s); err != nil {
		s.Close()
	}
	return
}

// Close a connection
func (s *SNMP) Close() {
	fmt.Println("Close")
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
		s.engine = nil
	}
}

func (s *SNMP) GetRequest(oids Oids) (result Pdu, err error) {
	pdu := NewPduWithOids(s.args.Version, GetRequest, oids)
	return s.sendPdu(pdu)
}

func (s *SNMP) GetNextRequest(oids Oids) (result Pdu, err error) {
	pdu := NewPduWithOids(s.args.Version, GetNextRequest, oids)
	return s.sendPdu(pdu)
}

func (s *SNMP) GetBulkRequest(oids Oids, nonRepeaters, maxRepetitions int) (result Pdu, err error) {

	if s.args.Version < V2c {
		return nil, &ArgumentError{
			Value:   s.args.Version,
			Message: "Unsupported SNMP Version",
		}
	}
	// RFC 3416 Section 3
	if nonRepeaters < 0 || nonRepeaters > math.MaxInt32 {
		return nil, &ArgumentError{
			Value:   nonRepeaters,
			Message: fmt.Sprintf("NonRepeaters is range %d..%d", 0, math.MaxInt32),
		}
	}
	if maxRepetitions < 0 || maxRepetitions > math.MaxInt32 {
		return nil, &ArgumentError{
			Value:   maxRepetitions,
			Message: fmt.Sprintf("NonRepeaters is range %d..%d", 0, math.MaxInt32),
		}
	}

	pdu := NewPduWithOids(s.args.Version, GetBulkRequest, oids)
	pdu.SetNonrepeaters(nonRepeaters)
	pdu.SetMaxRepetitions(maxRepetitions)
	return s.sendPdu(pdu)
}

// This method inquire about OID subtrees by repeatedly using GetBulkRequest.
// Returned PDU contains the varbind list of all subtrees.
// however, if the ErrorStatus of PDU is not the NoError, return only the last query result.
func (s *SNMP) GetBulkWalk(oids Oids, nonRepeaters, maxRepetitions int) (result Pdu, err error) {
	var nonRepBinds, resBinds VarBinds

	oids = append(oids[:nonRepeaters], oids[nonRepeaters:].Sort().UniqBase()...)
	reqOids := make(Oids, len(oids))
	copy(reqOids, oids)

	for len(reqOids) > 0 {
		pdu, err := s.GetBulkRequest(reqOids, nonRepeaters, maxRepetitions)
		if err != nil {
			return nil, err
		}
		if s := pdu.ErrorStatus(); s != NoError &&
			(s != NoSuchName || pdu.ErrorIndex() <= nonRepeaters) {
			return pdu, nil
		}

		varBinds := pdu.VarBinds()

		if nonRepeaters > 0 {
			nonRepBinds = append(nonRepBinds, varBinds[:nonRepeaters]...)
			varBinds = varBinds[nonRepeaters:]
			oids = oids[nonRepeaters:]
			reqOids = reqOids[nonRepeaters:]
			nonRepeaters = 0
		}

		filled := len(varBinds) == len(reqOids)*maxRepetitions
		varBinds = varBinds.Sort().Uniq()

		for i, _ := range reqOids {
			matched := varBinds.MatchBaseOids(oids[i])
			mLength := len(matched)

			if mLength == 0 || resBinds.MatchOid(matched[mLength-1].Oid) != nil {
				reqOids[i] = nil
				continue
			}

			hasError := false
			for _, val := range matched {
				switch val.Variable.(type) {
				case *NoSucheObject, *NoSucheInstance, *EndOfMibView:
					hasError = true
				default:
					resBinds = append(resBinds, val)
					reqOids[i] = val.Oid
				}
			}

			if hasError || (filled && mLength < maxRepetitions) {
				reqOids[i] = nil
			}
		}

		// sweep completed oids
		for i := len(reqOids) - 1; i >= 0; i-- {
			if reqOids[i] == nil {
				reqOids = append(reqOids[:i], reqOids[i+1:]...)
				oids = append(oids[:i], oids[i+1:]...)
			}
		}
	}

	resBinds = append(nonRepBinds, resBinds.Sort().Uniq()...)
	return NewPduWithVarBinds(s.args.Version, GetResponse, resBinds), nil
}

func (s *SNMP) V1Trap(varPduV1 TrapPduV1) (err error) {
	if s.args.Version > V1 {
		return &ArgumentError{
			Value:   s.args.Version,
			Message: "V1trap Unsupported other SNMP Version",
		}
	}

	var buf []byte
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

	//Version
	buf, err = asn1.Marshal(s.args.Version)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//Community
	buf, err = NewOctetString([]byte(s.args.Community)).Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//Data Trap
	buf = []byte{0xa4, 0x00}
	raw.Bytes = append(raw.Bytes, buf...)

	dataTrapLength := len(raw.Bytes)

	//Enterprise
	oid, _ := NewOid(varPduV1.Enterprise)
	buf, err = oid.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//AgentAddr
	var ipByte [4]byte

	for n, v := range strings.Split(varPduV1.AgentAddr, ".") {
		input, _ := strconv.Atoi(v)

		ipByte[n] = (byte)(input)
	}

	ip := NewIpaddress(ipByte[0], ipByte[1], ipByte[2], ipByte[3])
	buf, err = ip.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//GenericTrap
	buf, err = NewInteger((int32)(varPduV1.GenericTrap)).Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//SpecificTrap
	buf, err = NewInteger((int32)(varPduV1.SpecificTrap)).Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//TimeStamp
	buf, err = NewTimeTicks((uint32)(varPduV1.TimeStamp)).Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	//VarBinds
	buf = []byte{0x30, 0x00}
	raw.Bytes = append(raw.Bytes, buf...)

	raw.Bytes[dataTrapLength-1] = (byte)(len(raw.Bytes) - dataTrapLength)

	marbuf, _ := asn1.Marshal(raw)
	fmt.Println(hex.Dump(marbuf))

	s.conn.SetWriteDeadline(time.Now().Add(s.args.Timeout))
	_, err = s.conn.Write(marbuf[:len(marbuf)])
	fmt.Println("err = ", err)
	return err
}

func (s *SNMP) V2Trap(varBinds VarBinds) error {
	return s.v2trap(SNMPTrapV2, varBinds)
}

// Send trap with the authoritative engine boots and time when used with SNMP V3.
func (s *SNMP) V2TrapWithBootsTime(varBinds VarBinds, eBoots, eTime int) error {
	if eBoots < 0 || eBoots > math.MaxInt32 {
		return &ArgumentError{
			Value:   eBoots,
			Message: fmt.Sprintf("EngineBoots is range %d..%d", 0, math.MaxInt32),
		}
	}
	if eTime < 0 || eTime > math.MaxInt32 {
		return &ArgumentError{
			Value:   eTime,
			Message: fmt.Sprintf("EngineTime is range %d..%d", 0, math.MaxInt32),
		}
	}

	defer func() {
		s.args.authEngineBoots = 0
		s.args.authEngineTime = 0
	}()
	s.args.authEngineBoots = eBoots
	s.args.authEngineTime = eTime
	return s.v2trap(SNMPTrapV2, varBinds)
}

func (s *SNMP) InformRequest(varBinds VarBinds) error {
	return s.v2trap(InformRequest, varBinds)
}

func (s *SNMP) v2trap(pduType PduType, varBinds VarBinds) (err error) {
	fmt.Println("v2trap")
	if s.args.Version < V2c {
		return &ArgumentError{
			Value:   s.args.Version,
			Message: "Unsupported SNMP Version",
		}
	}

	pdu := NewPduWithVarBinds(s.args.Version, pduType, varBinds)
	_, err = s.sendPdu(pdu)
	return
}

func (s *SNMP) sendPdu(pdu Pdu) (result Pdu, err error) {
	fmt.Println("sendPdu")
	if err = s.Open(); err != nil {
		return
	}

	retry(int(s.args.Retries), func() error {
		result, err = s.engine.SendPdu(pdu, s.conn, s.args)
		return err
	})
	return
}

func (s *SNMP) String() string {
	if s.conn == nil {
		return fmt.Sprintf(`{"conn": false, "args": %s, "engine": null}`, s.args.String())
	} else {
		return fmt.Sprintf(`{"conn": true, "args": %s, "engine": %s}`,
			s.args.String(), s.engine.String())
	}
}

// Create a SNMP Object
func NewSNMP(args SNMPArguments) (*SNMP, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	args.setDefault()
	return &SNMP{args: &args}, nil
}
