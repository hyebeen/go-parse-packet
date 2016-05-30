// package goparsepacket
package main

import (
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "eth5"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

var (
	cookieRe = regexp.MustCompile(`Cookie: (:?\w+=.+)+`)
)

func main() {
	f()
}

func f() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPacket := tcpLayer.(*layers.TCP)
			http := string(tcpPacket.Payload)

			if s := cookieRe.FindString(http); len(s) > 0 {
				fmt.Println(s)
			}
		}
	}
}
