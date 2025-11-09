package main

import (
	bpsr "bpsr-dps/pkg/pb/proto"
	tcpassembler "bpsr-dps/pkg/tcp"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"github.com/klauspost/compress/zstd"
	"github.com/DataDog/zstd"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"net"
)

type Source struct {
	HostPort
}

type Destination struct {
	HostPort
}

type HostPort struct {
	Host net.IP
	Port layers.TCPPort
}

type SourceDestination struct {
	Source
	Destination
}

type Server struct {
	Source
	Destination
	packets          chan gopacket.Packet
	filteredPackets  chan gopacket.Packet
	assembledPackets chan []byte
}

func getSourceDestinationFromPacket(packet gopacket.Packet) (*SourceDestination, error) {

	//Now we need to identify IPv4 ipv4Layer.
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)

	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("ipv4Layer is not IPv4")
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("tcpLayer is not TCP")
	}

	sd := SourceDestination{
		Source: Source{
			HostPort{
				Host: ipv4.SrcIP,
				Port: tcp.SrcPort,
			},
		},
		Destination: Destination{
			HostPort{
				Host: ipv4.DstIP,
				Port: tcp.DstPort,
			},
		},
	}

	return &sd, nil
}

func NewServerFromPacket(packet gopacket.Packet) (*Server, error) {

	sd, err := getSourceDestinationFromPacket(packet)
	if err != nil {
		return nil, err
	}

	s := Server{
		Source:           sd.Source,
		Destination:      sd.Destination,
		packets:          make(chan gopacket.Packet, 1024),
		filteredPackets:  make(chan gopacket.Packet, 1024),
		assembledPackets: make(chan []byte, 1024),
	}

	return &s, nil

}

func (s *Server) LootPackets() {
	source := NewPCAPPacketSource()
	s.packets = source.Packets()

	s.filterPackets()
	s.foo()
	s.bar()
}

func (s *Server) filterPackets() {
	go func() {
		for packet := range s.packets {
			sd, err := getSourceDestinationFromPacket(packet)
			if err != nil {
				//log.Printf("Error getting source destination: %v", err)
				continue
			}

			if !bytes.Equal(sd.Source.Host, s.Source.Host) {
				continue
			}

			if sd.Source.Port != s.Source.Port {
				continue
			}

			if !bytes.Equal(sd.Destination.Host, s.Destination.Host) {
				continue
			}

			if sd.Destination.Port != s.Destination.Port {
				continue
			}

			s.filteredPackets <- packet
		}
	}()
}

func (s *Server) hasSubPackets(payload []byte, packets chan []byte) bool {

	if len(payload) < 6 {
		return false
	}

	packetSize := getPacketSize(payload)

	if packetSize <= len(payload) {
		subPacket := payload[:packetSize]
		packets <- subPacket
		return s.hasSubPackets(payload[packetSize:], packets)
	}

	return false
}

func (s *Server) foo() {

	reassembler := &tcpassembler.TCPReassembler{Input: s.filteredPackets}
	reassembler.Start()

	go func() {
		for payload := range reassembler.Output {
			s.handlePacket(payload, reassembler.Output)
		}
	}()
}

type GamePacket struct {
	PacketType          int
	IsZSTDCompressed    int
	MessageTypeID       int
	ActualMessageTypeID FragmentType
	Payload             []byte
}

func NewGamePacket(packetType, isZSTDCompressed, messageTypeID int, payload []byte) *GamePacket {

	actualMessageTypeID := FragmentType(messageTypeID)

	return &GamePacket{
		PacketType:          packetType,
		IsZSTDCompressed:    isZSTDCompressed,
		MessageTypeID:       messageTypeID,
		ActualMessageTypeID: actualMessageTypeID,
		Payload:             payload,
	}
}

func (s *Server) handlePacket(payload []byte, packets chan []byte) {
	if len(payload) < 6 {
		return
	}

	packetType := getPacketType(payload)

	isZSTDCompressed := packetType & 0x8000
	messageTypeID := packetType & 0x7fff

	//logrus.Infof("payload size: %d, packetSize: %d, packetType: %d, messageTypeID: %d, isZSTDCompressed: %d", len(payload), packetSize, packetType, messageTypeID, isZSTDCompressed)

	actualMessageTypeID := FragmentType(messageTypeID)

	gamePacket := NewGamePacket(packetType, isZSTDCompressed, messageTypeID, payload)

	switch actualMessageTypeID {
	case Notify:
		s.handleNotify(gamePacket)
	case FrameDown:
		s.handleFrameDown(gamePacket, packets)
	default:
	}
}

func (s *Server) handleFrameDown(gamePacket *GamePacket, packets chan []byte) bool {
	if len(gamePacket.Payload) < 10 {
		return true
	}

	if len(gamePacket.Payload[10:]) == 0 {
		return true
	}

	pak := s.assertDecompressedPayload(gamePacket, 10)

	hasSubPackets := s.hasSubPackets(pak, packets)
	if hasSubPackets {
		return true
	}
	packets <- pak
	return false
}

func (s *Server) assertDecompressedPayload(gamePacket *GamePacket, msgPayloadStart int) []byte {
	msgPayload := gamePacket.Payload[msgPayloadStart:]

	var actualPayload []byte

	if gamePacket.IsZSTDCompressed != 0 {
		result, err := s.DecompressWithCGO(msgPayload)
		if err != nil {
			logrus.Error(err)
			return nil
		}
		actualPayload = result
	} else {
		actualPayload = msgPayload
	}

	return actualPayload
}

func (s *Server) handleNotify(gamePacket *GamePacket) {
	serviceUUID := getServiceUUID(gamePacket.Payload)
	if serviceUUID != 0x0000000063335342 {
		logrus.Errorf("Service UUID: 0x%X", serviceUUID)
		return
	}

	// payload[14:18] = stubID = wasted

	methodIDRaw := getMethodIDRaw(gamePacket.Payload)
	methodID := Opcode(methodIDRaw)

	actualPayload := s.assertDecompressedPayload(gamePacket, 22)

	switch methodID {
	case SyncNearDeltaInfo:
		s.handleSyncNearDeltaInfo(actualPayload)
	default:
		logrus.Debugf("nothing to do")
	}
}

func (s *Server) handleSyncNearDeltaInfo(actualPayload []byte) bool {
	res := bpsr.SyncNearDeltaInfo{}
	//logrus.Infof("len: %d, cap: %d, payload: %v", len(actualPayload), cap(actualPayload), actualPayload)

	err := UnmarshalLenient(actualPayload, &res)
	if err != nil {
		logrus.Errorf("Error unmarshalling SyncNearDeltaInfo: %v", err)
		return true
	}

	for _, v := range res.GetDeltaInfos() {
		for _, vv := range v.GetSkillEffects().GetDamages() {
			av := vv.GetActualValue()
			val := vv.GetValue()
			lucky := vv.GetLuckyValue()

			logrus.Infof("actualValue: %d, value: %d, lucky: %d", av, val, lucky)
		}
	}
	return false
}

func (s *Server) DecompressWithCGO(src []byte) ([]byte, error) {
	// dst=nil lets the library allocate the output buffer.
	return zstd.Decompress(nil, src)
}

//func (s *Server) DecompressZstd(src []byte) ([]byte, error) {
//	logrus.Info("decompressZstd")
//	dec, err := zstd.NewReader(nil) // create a reusable decoder (no bound reader)
//	if err != nil {
//		return nil, err
//	}
//	defer dec.Close() // free resources when you’re done (or reuse the decoder)
//	// DecodeAll returns the full decompressed payload.
//	dst, err := dec.DecodeAll(src, nil) // second arg is optional dst buffer to reuse
//	if err != nil {
//		return nil, err
//	}
//	return dst, nil
//}

func UnmarshalLenient(b []byte, msg proto.Message) error {
	//opt := proto.UnmarshalOptions{
	//	DiscardUnknown: true, // ignore unknown fields
	//	AllowPartial:   true, // allow missing required (proto2)
	//	Merge:          false,
	//}
	//return opt.Unmarshal(b, msg)
	return proto.Unmarshal(b, msg)
}

func (s *Server) bar() {
	go func() {
		logrus.Infof("starting bar")
		for packet := range s.assembledPackets {
			logrus.Warnf("got assembled packet: %v", packet)
		}
	}()
}
