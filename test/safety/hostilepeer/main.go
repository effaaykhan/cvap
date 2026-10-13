// Command hostilepeer is the R2-D safety gate's peer (ADR-110): it answers a
// Scan Point's connections with the traffic shapes that drive peer-induced
// packets out of the Scan Point's namespace, plus a sink for the Scan Point's
// own data. It runs at an address inside lab/scope.txt on the internal lab
// network, and only ever answers.
//
//	9001 bulk 1 MiB push              9003 one-byte segments back to back
//	9004 a short reply, then close    9006 ten-byte segments back to back
//	9007 on/off one-byte bursts       9008 silent 1 s, then a flood
//	9016 one byte every 4 ms          9021 ten bytes every 0.1 ms
//	9030 sink: reads and discards (the Scan Point's data, its retransmissions)
package main

import (
	"bytes"
	"io"
	"net"
	"time"
)

func serve(port string, h func(*net.TCPConn)) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer func() { _ = c.Close() }()
			h(c.(*net.TCPConn))
		}()
	}
}

// every writes chunk on a schedule (gap 0: back to back) for d or until the
// client goes away.
func every(c *net.TCPConn, chunk []byte, gap, d time.Duration) {
	_ = c.SetNoDelay(true)
	end := time.Now().Add(d)
	next := time.Now()
	for time.Now().Before(end) {
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(chunk); err != nil {
			return
		}
		if gap > 0 {
			next = next.Add(gap)
			if w := time.Until(next); w > 0 {
				time.Sleep(w)
			}
		}
	}
}

func main() {
	one, ten := []byte{'x'}, []byte("0123456789")
	big := bytes.Repeat([]byte("A"), 1<<20)
	const d = 10 * time.Second
	go serve("9001", func(c *net.TCPConn) {
		_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
		_, _ = c.Write(big)
	})
	go serve("9003", func(c *net.TCPConn) { every(c, one, 0, d) })
	go serve("9004", func(c *net.TCPConn) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write(append([]byte("HTTP/1.0 200 OK\r\nServer: lab\r\n\r\n"), big[:200]...))
	})
	go serve("9006", func(c *net.TCPConn) { every(c, ten, 0, d) })
	go serve("9007", func(c *net.TCPConn) {
		for end := time.Now().Add(d); time.Now().Before(end); {
			every(c, one, 0, 50*time.Millisecond)
			time.Sleep(50 * time.Millisecond)
		}
	})
	go serve("9008", func(c *net.TCPConn) {
		time.Sleep(time.Second)
		every(c, one, 0, d-time.Second)
	})
	go serve("9016", func(c *net.TCPConn) { every(c, one, 4*time.Millisecond, d) })
	go serve("9021", func(c *net.TCPConn) { every(c, ten, 100*time.Microsecond, d) })
	serve("9030", func(c *net.TCPConn) {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	})
}
