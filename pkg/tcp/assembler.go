package tcpassembler

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/sirupsen/logrus"
	"time"
)

type TCPReassembler struct {
	Input     chan gopacket.Packet
	Output    chan []byte
	assembler *tcpassembly.Assembler
	done      chan struct{}
}

func (tr *TCPReassembler) Start() {
	tr.Output = make(chan []byte, 100)
	tr.done = make(chan struct{})
	factory := &streamFactory{outChan: tr.Output}
	pool := tcpassembly.NewStreamPool(factory)
	tr.assembler = tcpassembly.NewAssembler(pool)
	go tr.run()
	logrus.Info("TCPReassembler started")
}
func (tr *TCPReassembler) Close() {
	close(tr.done)
	close(tr.Output)
	logrus.Info("TCPReassembler closed")
}
func (tr *TCPReassembler) run() {
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		select {
		case pkt, ok := <-tr.Input:
			if !ok {
				logrus.Warn("Input channel closed")
				return
			}
			tcp, ok := pkt.TransportLayer().(*layers.TCP)
			if !ok {
				logrus.Debugf("Non-TCP packet received: %v", pkt)
				continue
			}
			netLayer := pkt.NetworkLayer()
			if netLayer == nil {
				logrus.Warnf("Packet missing network layer: %v", pkt)
				continue
			}
			netFlow := netLayer.NetworkFlow()
			tr.assembler.AssembleWithTimestamp(netFlow, tcp, pkt.Metadata().Timestamp)
			logrus.Debugf("Packet delivered to assembler: %v -> %v SEQ %v LEN %d SYN:%v FIN:%v",
				netFlow.Src(), netFlow.Dst(), tcp.Seq, len(tcp.Payload), tcp.SYN, tcp.FIN)
		case <-ticker.C:
			tr.assembler.FlushOlderThan(time.Now().Add(-100 * time.Millisecond))
			logrus.Debug("Assembler flushed old streams")
		case <-tr.done:
			logrus.Info("Received done, stopping assembler")
			return
		}
	}
}

// -------- Stream Factory and Stream --------
type streamFactory struct {
	outChan chan<- []byte
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	logrus.Infof("New TCP stream: %v <-> %v", net, transport)

	return &tcpStream{
		net:       net,
		transport: transport,
		outChan:   f.outChan,
	}
}

type tcpStream struct {
	net, transport gopacket.Flow
	outChan        chan<- []byte
	closed         bool
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		//logrus.Infof(
		//	"[%v -> %v] Reassembled %d bytes (skipped: %d)",
		//	s.net, s.transport, len(r.Bytes), r.Skip,
		//)
		// You may also log a preview of the bytes:
		if len(r.Bytes) > 0 {
			preview := r.Bytes
			if len(preview) > 20 {
				preview = preview[:20]
			}
			logrus.Debugf("First bytes: %x", preview)
			copyBytes := make([]byte, len(r.Bytes))
			copy(copyBytes, r.Bytes)
			select {
			case s.outChan <- copyBytes:
				logrus.Debugf("Delivered reassembled bytes to Output channel.")
			default:
				logrus.Warnf("Output channel full, dropping reassembled bytes (%d bytes)", len(copyBytes))
			}
		}
	}
}

// Called when a stream is closed or reset.
func (s *tcpStream) ReassemblyComplete() {
	logrus.Infof("Reassembly complete: %v <-> %v", s.net, s.transport)
	s.closed = true
}
