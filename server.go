package main

import (
	bpsr "bpsr-dps/pkg/pb/proto"
	tcpassembler "bpsr-dps/pkg/tcp"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
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

func (s *Server) foo() {

	//reassembledStream := make(chan gopacket.Packet)
	//s.assembledPackets = reassembledStream
	//
	//streamPool := tcpassembly.NewStreamPool(&tcpStream{})
	//assembler := tcpassembly.NewAssembler(streamPool)

	//assembler := tcpassembly.NewAssembler(nil)

	reassembler := &tcpassembler.TCPReassembler{Input: s.filteredPackets}
	reassembler.Start()

	//go func() {
	//	for packet := range s.filteredPackets {
	//		payload := getPayloadFromPacket(packet)
	//
	//		s.assembledPackets <- payload
	//	}
	//}()

	go func() {
		for payload := range reassembler.Output {
			// handle fully-reassembled TCP application data
			//logrus.Infof("GOT REASSEMBLED: %q\n", payload)

			if len(payload) < 6 {
				continue
			}

			ps := payload[:4]
			pt := payload[4:6]

			packetSize := binary.BigEndian.Uint32(ps)
			packetType := binary.BigEndian.Uint16(pt)

			isZSTDCompressed := packetType & 0x8000
			messageTypeID := packetType & 0x7fff

			//logrus.Infof("payload size: %d, packetSize: %d, packetType: %d, messageTypeID: %d, isZSTDCompressed: %d", len(payload), packetSize, packetType, messageTypeID, isZSTDCompressed)

			actualMessageTypeID := FragmentType(messageTypeID)

			switch actualMessageTypeID {
			case Notify:
				//logrus.Infof("received notify packet")
				sUUID := payload[6:14]

				serviceUUID := binary.BigEndian.Uint64(sUUID)

				if serviceUUID != 0x0000000063335342 {
					logrus.Errorf("Service UUID: 0x%X", serviceUUID)
					continue
				}

				// payload[14:18] = stubID = wasted

				mID := payload[18:22]
				methodIDRaw := binary.BigEndian.Uint32(mID)

				msgPayload := payload[22:]

				methodID := Opcode(methodIDRaw)

				//actualPayload := msgPayload

				var actualPayload []byte

				if isZSTDCompressed != 0 {
					result, err := s.DecompressWithCGO(msgPayload)
					if err != nil {
						logrus.Error(err)
						continue
					}
					actualPayload = result
				} else {
					actualPayload = msgPayload
				}

				if methodID == SyncNearDeltaInfo {
					//res := anypb.Any{}
					res := bpsr.SyncNearDeltaInfo{}
					logrus.Infof("len: %d, cap: %d, payload: %v", len(actualPayload), cap(actualPayload), actualPayload)

					err := UnmarshalLenient(actualPayload, &res)
					//err := proto.Unmarshal(actualPayload, &res)
					if err != nil {
						logrus.Errorf("Error unmarshalling SyncNearDeltaInfo: %v", err)

						logrus.Infof("string: %s", hex.EncodeToString(actualPayload))
						continue
					}
					logrus.Warnf("aaaa: %+v", res)

					//for _, v := range res.DeltaInfos {
					//	if v == nil {
					//		continue
					//	}
					//	if v.SkillEffects == nil {
					//		continue
					//	}
					//	for _, vv := range v.SkillEffects.Damages {
					//		if vv == nil {
					//			continue
					//		}
					//		av := vv.ActualValue
					//		val := vv.Value
					//
					//		logrus.Infof("actualValue: %d, value: %d", av, val)
					//	}
					//}
				} else {
					logrus.Warnf("got different opcode %d", methodID)
				}

			case FrameDown:
				//logrus.Infof("frame down")

				if len(payload) < 10 {
					continue
				}

				if len(payload[10:]) == 0 {
					continue
				}

				nestedPacket := payload[10:]
				if isZSTDCompressed != 0 {
					logrus.Infof("%d:%d", len(nestedPacket), packetSize)
					result, err := s.DecompressWithCGO(nestedPacket)
					if err != nil {
						logrus.Error(err)
						continue
					}
					reassembler.Output <- result
					//logrus.Errorf("should decompress LOL")
				} else {
					reassembler.Output <- nestedPacket
				}
			default:
				//logrus.Warnf("wtf")

			}

		}
	}()

	// TODO: this might work, who knows
	//assembledPackets := make(chan []byte)
	//factory := &streamFactory{
	//	assembledPackets: assembledPackets,
	//}
	//streamPool := tcpassembly.NewStreamPool(factory)
	//assembler := tcpassembly.NewAssembler(streamPool)
	//
	//go processPackets(s.filteredPackets, assembler)
	//
	//ticker := time.NewTicker(time.Minute)
	//defer ticker.Stop()
	//for range ticker.C {
	//	assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
	//}

	//go func() {
	//	for packet := range s.filteredPackets {
	//		//logrus.Warnf("got filtered packet: %v", packet)
	//
	//		tcpLayer := packet.Layer(layers.LayerTypeTCP)
	//		if tcpLayer == nil {
	//			continue
	//		}
	//
	//		tcp, _ := tcpLayer.(*layers.TCP)
	//		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	//
	//		//streamFactory := func(net, transport gopacket.Flow) tcpassembly.Stream {
	//		//	readerStream := tcpreader.NewReaderStream()
	//		//	t := tcpStream{
	//		//		net:       net,
	//		//		transport: transport,
	//		//		readerStream:         readerStream,
	//		//	}
	//		//	go t.run() // Start reading from the application layer stream
	//		//	return &t
	//		//}
	//
	//	}
	//}()
}

func processPackets(pktChan <-chan gopacket.Packet, assembler *tcpassembly.Assembler) {
	for pkt := range pktChan {
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			net := pkt.NetworkLayer()
			if net == nil {
				continue // skip packets without a network layer
			}
			assembler.AssembleWithTimestamp(
				net.NetworkFlow(),
				tcp,
				pkt.Metadata().Timestamp,
			)
		}
		// Optionally: assembler.FlushOlderThan(time.Now().Add(-time.Minute))
	}
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
	opt := proto.UnmarshalOptions{
		DiscardUnknown: true, // ignore unknown fields
		AllowPartial:   true, // allow missing required (proto2)
		Merge:          false,
	}
	return opt.Unmarshal(b, msg)
}

func (s *Server) bar() {
	go func() {
		logrus.Infof("starting bar")
		for packet := range s.assembledPackets {
			logrus.Warnf("got assembled packet: %v", packet)
		}
	}()
}
