package main

import (
	"snmpgo"
)

func main() {
	var (
		src         []byte
		key         []byte
		engineBoots int32
		salt        int64
	)
	src = []byte{1, 2, 3, 4, 5}
	key = []byte{1, 2, 3, 4, 5}
	engineBoots = 100
	salt = 1234
	snmpgo.EncryptAES(src, key, engineBoots, engineBoots, salt, 192)
	snmpgo.DecryptAES(src, key, engineBoots, engineBoots, salt, 192)
}
