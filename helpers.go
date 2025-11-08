package main

import "bytes"

var SIGNATURE_1 = []byte{0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01}
var SIGNATURE_2 = []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 0x4e}
var SIGNATURE_3 = []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00}

func matchesLoginSignatures(payload []byte) bool {
	return bytes.Equal(payload[0:10], SIGNATURE_1) && bytes.Equal(payload[14:20], SIGNATURE_2)
}

func matchesSmallPacketSignature(payload []byte) bool {
	return bytes.Contains(payload, SIGNATURE_3)
}
