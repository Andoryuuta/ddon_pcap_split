package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// TCPStream represents a single (bidirectional) TCP stream.
type TCPStream struct {
	sync.Mutex
	net, transport gopacket.Flow
	connLog        *ConnectionLog
	isSideSwapped  bool
	isDDONConn     bool
}

// Accept is called when a TCP packet is received for a stream connection.
func (t *TCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if IsDDONServer(uint16(tcp.SrcPort)) || IsDDONServer(uint16(tcp.DstPort)) {
		// Accept every packet.
		*start = true
		return true
	}

	*start = false
	return false
}

// ReassembledSG is called whenever the reassembler has enough data from tcp packets.
func (t *TCPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	_, _, _, skip := sg.Info()
	length, _ := sg.Lengths()

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		fmt.Printf("Skip: %v\n", skip)
		return
	}

	data := sg.Fetch(length)
	if t.isDDONConn {
		if len(data) < 2 {
			// Not enough to read header prefix length yet.
			sg.KeepFrom(0)
			return
		}

		packetSize := binary.BigEndian.Uint16(data[:2])
		splitPacketLen := int(packetSize) + 2

		// Check if we have enough data for the header + payload
		if len(data) < splitPacketLen {
			// Not enough to read full packet yet.
			sg.KeepFrom(0)
			return
		}

		splitPacket := data[:splitPacketLen]
		t.OutputSplitGamePacket(splitPacket, sg, ac)

		sg.KeepFrom(splitPacketLen)
	}

}

// OutputSplitGamePacket logs the split packet into the connection log.
func (t *TCPStream) OutputSplitGamePacket(splitPacket []byte, sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	sgDir, _, _, _ := sg.Info()
	toServer := sgDir == reassembly.TCPDirClientToServer
	if t.isSideSwapped {
		toServer = !toServer
	}

	dir := ""
	if toServer {
		dir = "C2S"
	} else {
		dir = "S2C"
	}

	encodedData := base64.StdEncoding.EncodeToString([]byte(splitPacket))
	t.connLog.Packets = append(t.connLog.Packets, SplitPacket{
		Timestamp: ac.GetCaptureInfo().Timestamp,
		Direction: dir,
		Data:      encodedData,
	})
}

// ReassemblyComplete handles the completion of the TCP reassembly
func (t *TCPStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	//fmt.Printf("Reassembly completed\n")
	// do not remove the connection to allow last ACK
	return false
}

// TCPStreamFactory provides a simple factory interface for creating new TCPStream instances.
type TCPStreamFactory struct{}

// New is called for each new TCP connection being created.
func (f *TCPStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	// In a normal packet capture, the first packet's would come from the local computer to a DDON game server.
	// As such, the tcp.DstPort should be a DDON server port. If it is not, but the SrcPort is, then we have a swapped pcap
	// (due to capturing midway without the initial connection SYN packet)
	isSideSwapped := !IsDDONServer(uint16(tcp.DstPort)) && IsDDONServer(uint16(tcp.SrcPort))

	if isSideSwapped {
		fmt.Println("WARNING: MISSING INITIAL TCP HANDSHAKE WITH SERVER, WE MAY NOT BE ABLE TO REOVER CAMELLIA KEY FOR THIS PCAP!")
	}

	var usedNet, usedTransport gopacket.Flow
	if !isSideSwapped {
		usedNet = net
		usedTransport = transport
	} else {
		usedNet = net.Reverse()
		usedTransport = transport.Reverse()
	}

	// Populate the inital information about this new connection.
	dstString := fmt.Sprintf("%v:%v", usedNet.Dst().String(), usedTransport.Dst().String())
	dstPort, _ := strconv.Atoi(usedTransport.Dst().String())

	serverType := ""
	if isLoginServer(uint16(dstPort)) {
		serverType = "login"
	} else if isWorldServer(uint16(dstPort)) {
		serverType = "world"
	}

	serverName := ""
	if v, ok := knownHosts[dstString]; ok {
		serverName = v
	}

	connLog := &ConnectionLog{
		Encrypted:    true,
		ServerType:   serverType,
		ServerName:   serverName,
		ServerIP:     dstString,
		LogStartTime: ac.GetCaptureInfo().Timestamp,
		isDDONConn:   IsDDONServer(uint16(tcp.DstPort)) || IsDDONServer(uint16(tcp.SrcPort)),
	}

	ctx := ac.(*CustomReassemblerContext)
	ctx.Lock()
	connectionIndex := len(ctx.ConnectionLogs)
	connLog.ConnectionIndex = connectionIndex
	ctx.ConnectionLogs = append(ctx.ConnectionLogs, connLog)
	ctx.Unlock()

	stream := &TCPStream{
		net:           usedNet,
		transport:     usedTransport,
		connLog:       connLog,
		isSideSwapped: isSideSwapped,
		isDDONConn:    IsDDONServer(uint16(tcp.DstPort)) || IsDDONServer(uint16(tcp.SrcPort)),
	}

	return stream
}

// SplitPacket holds information about a single split packet from the game connection
type SplitPacket struct {
	Timestamp time.Time
	Direction string
	Data      string // base64 encoded packet data
}

// ConnectionLog holds information about a single split TCP connection
type ConnectionLog struct {
	ConnectionIndex int `json:"-"`
	Encrypted       bool
	EncryptionKey   string
	LogStartTime    time.Time
	ServerType      string
	ServerName      string `json:"-"`
	ServerIP        string
	isDDONConn      bool

	Packets []SplitPacket
}

// CustomReassemblerContext holds context for packets passed through the reassembler.
type CustomReassemblerContext struct {
	sync.Mutex

	CaptureInfo    gopacket.CaptureInfo
	ConnectionLogs []*ConnectionLog
}

// GetCaptureInfo gets the capture info
func (c *CustomReassemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
