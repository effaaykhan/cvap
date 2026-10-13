// Command r2dnontcp is the R2-D safety gate's non-TCP traffic source (ADR-110).
// It runs INSIDE the policed Scan Point network namespace, as the Scan Point's
// own user with no capabilities, and tries the paths that turned one
// tc-accounted buffer into many wire packets, or skipped tc altogether, while
// R2-D was being validated:
//
//	udpseg   UDP_SEGMENT sends: one buffer, up to 64 packets after tc
//	udpfrag  UDP writes larger than the MTU: IP fragments, made before tc
//	raw      an AF_PACKET socket with PACKET_QDISC_BYPASS: needs NET_RAW
//
// It enforces nothing and asserts nothing: the gate judges what reached the
// wire. Each send's outcome is reported, because a refused send (no
// capability, protocol dropped) is the expected safe result.
package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"syscall"
)

type result struct {
	Mode     string `json:"mode"`
	Setup    string `json:"setup_err,omitempty"`
	Sent     int    `json:"sent"`
	Failed   int    `json:"failed"`
	LastErr  string `json:"last_err,omitempty"`
	Segments int    `json:"segments_per_send"`
}

const (
	udpSegment        = 103 // UDP_SEGMENT
	packetQdiscBypass = 20  // PACKET_QDISC_BYPASS
	ethertype         = 0x88b5
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func udp(host string, gso, segs, size, n int) result {
	r := result{Mode: "udp", Segments: 1}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: 9999})
	if err != nil {
		r.Setup = err.Error()
		return r
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, size)
	if gso > 0 {
		r.Mode, r.Segments = "udpseg", segs
		rc, _ := c.SyscallConn()
		var serr error
		_ = rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, udpSegment, gso) })
		if serr != nil {
			r.Setup = serr.Error()
			return r
		}
		buf = make([]byte, gso*segs)
	}
	for range n {
		if _, err := c.Write(buf); err != nil {
			r.Failed++
			r.LastErr = err.Error()
		} else {
			r.Sent++
		}
	}
	return r
}

func raw(n int) result {
	r := result{Mode: "raw", Segments: 1}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethertype)))
	if err != nil {
		r.Setup = err.Error()
		return r
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetQdiscBypass, 1); err != nil {
		r.Setup = err.Error()
		return r
	}
	ifi, err := net.InterfaceByName("eth0")
	if err != nil {
		r.Setup = err.Error()
		return r
	}
	bcast := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(ethertype), Ifindex: ifi.Index, Halen: 6, Addr: bcast}
	f := make([]byte, 60)
	copy(f, bcast[:6])
	copy(f[6:], ifi.HardwareAddr)
	f[12], f[13] = ethertype>>8, ethertype&0xff
	for range n {
		if err := syscall.Sendto(fd, f, 0, sa); err != nil {
			r.Failed++
			r.LastErr = err.Error()
		} else {
			r.Sent++
		}
	}
	return r
}

func main() {
	mode := flag.String("mode", "", "udpseg | udpfrag | raw")
	host := flag.String("host", "", "peer address (udp modes)")
	gso := flag.Int("gso", 100, "udpseg: segment size")
	segs := flag.Int("segs", 64, "udpseg: segments per send")
	size := flag.Int("size", 8000, "udpfrag: datagram size")
	n := flag.Int("n", 50, "sends")
	flag.Parse()
	var r result
	switch *mode {
	case "udpseg":
		r = udp(*host, *gso, *segs, 0, *n)
	case "udpfrag":
		r = udp(*host, 0, 0, *size, *n)
	case "raw":
		r = raw(*n)
	default:
		r = result{Mode: *mode, Setup: "unknown mode"}
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
