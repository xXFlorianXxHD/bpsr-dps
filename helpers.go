package main

import (
	"bytes"
	"encoding/binary"
)

var SIGNATURE_1 = []byte{0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01}
var SIGNATURE_2 = []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 0x4e}
var SIGNATURE_3 = []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00}

func matchesLoginSignatures(payload []byte) bool {
	return bytes.Equal(payload[0:10], SIGNATURE_1) && bytes.Equal(payload[14:20], SIGNATURE_2)
}

func matchesSmallPacketSignature(payload []byte) bool {
	return bytes.Contains(payload, SIGNATURE_3)
}

func getPacketType(payload []byte) int {
	pt := payload[4:6]
	packetType := binary.BigEndian.Uint16(pt)
	return int(packetType)
}

func getServiceUUID(payload []byte) int {
	sUUID := payload[6:14]
	serviceUUID := binary.BigEndian.Uint64(sUUID)
	return int(serviceUUID)
}

func getMethodIDRaw(payload []byte) int {
	mID := payload[18:22]
	methodIDRaw := binary.BigEndian.Uint32(mID)
	return int(methodIDRaw)
}

func getPacketSize(payload []byte) int {
	ps := payload[:4]
	packetSize := binary.BigEndian.Uint32(ps)
	return int(packetSize)
}
