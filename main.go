package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"log/slog"
	"os"
	"os/signal"
)

const (
	interfaceName = "enp6s0"
	snaplen       = 1500
)

func NewPCAPPacketSource() *gopacket.PacketSource {
	handle, err := pcap.OpenLive(interfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	//iface, err := net.InterfaceByName(interfaceName)
	//if err != nil {
	//	slog.Error("Could not OpenLive", slog.String("err", err.Error()))
	//	os.Exit(1)
	//}

	// Start new Source reader.
	return gopacket.NewPacketSource(handle, handle.LinkType())
}

func main() {

	source := NewPCAPPacketSource()

	// Reading packages.
	for packet := range source.Packets() {
		// Filter by outgoing traffic only.
		// To filter it, we need to compare MAC addresses from out interface and source MAC.
		// To access a mac Address we need to get an Ethernet layer.
		//layer := packet.Layer(layers.LayerTypeEthernet)

		//ethernet, ok := layer.(*layers.Ethernet)
		//if !ok {
		//	slog.Error("Could not get Ethernet layer")
		//	continue
		//}

		//if !bytes.Equal(ethernet.SrcMAC, iface.HardwareAddr) {
		//	// Our interface did not send this packet. It's not outcoming.
		//	continue
		//}

		// Now we need to identify IPv4 layer.
		//layer = packet.Layer(layers.LayerTypeIPv4)

		//ipv4, ok := layer.(*layers.IPv4)
		//if !ok {
		//	// It's not IPv4 traffic.
		//	continue
		//}

		//if ipv4.DstIP.IsPrivate() {
		//	// Do not collect private traffic.
		//	continue
		//}

		//if ipv4.Protocol != layers.IPProtocolUDP {
		//	Ignore not UDP protocol.
		//	continue
		//}

		//err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		//if err != nil {
		//	slog.Error("Could not write a packet to a pcap writer", slog.String("err", err.Error()))
		//
		//	continue
		//}

		//slog.Info("Stored packet", slog.Any("packet", packet))

		payload := getPayloadFromPacket(packet)

		//payload := packet.Data()
		//length := len(payload)
		//if length == 98 {
		//	slog.Info("length == 98", slog.Any("payload", payload))

		if len(payload) < 20 {
			continue
		}

		if matchesLoginSignatures(payload) || matchesSmallPacketSignature(payload) {
			logrus.Warnf("found server UwU")

			s, err := NewServerFromPacket(packet)
			if err != nil {
				panic(err)
			}

			go s.LootPackets()
			break
		}

		//}
		// Let's collect ONLY 100K bytes, just for example perposes.
		//if fileWriter.Len() > 100000 {
		//	break
		//}
	}

	a := make(chan os.Signal, 1)
	signal.Notify(a, os.Interrupt)
	<-a

	//slog.Info("We have successfuly collected bytes", slog.Int("bytes", fileWriter.Len()))

}

func getPayloadFromPacket(packet gopacket.Packet) []byte {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	return tcp.Payload
}
