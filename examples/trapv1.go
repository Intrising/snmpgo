package main

import (
	"fmt"

	"../../snmpgo"
)

func test2() {
	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V1,
		Address:   "192.168.16.254:162",
		Retries:   1,
		Community: "public",
	})
	if err != nil {
		// Failed to create snmpgo.SNMP object
		fmt.Println(err)
		return
	}

	var varTrapV1 snmpgo.TrapPduV1

	varTrapV1.Enterprise = "1.3.6.1.4.1.37072.302.2.3"
	varTrapV1.AgentAddr = "192.168.16.221"
	varTrapV1.GenericTrap = 4
	varTrapV1.SpecificTrap = 0
	varTrapV1.TimeStamp = 11934
	varTrapV1.VariableBindings = 0

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		fmt.Println(err)
		return
	}
	defer snmp.Close()

	if err = snmp.V1Trap(varTrapV1); err != nil {
		// Failed to request
		fmt.Println(err)
		return
	}
}

func main() {
	for i := 0; i < 1; i++ {
		test2()
	}
}
