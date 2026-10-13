// Command bigtalk is the safety gate's large-response peer: it writes a fixed
// number of bytes to every connection it accepts, concurrently, then
// half-closes, drains what the client sent, and closes (see serve).
//
// The per-operation wire check (safety_wire_ops.py) needs a peer that pushes far
// more than the engine reads, to show what that peer extracts from this end as
// kernel-response traffic. busybox `nc -l` served one connection at a time and
// refused the engine's second, which left the case measuring nothing.
package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// drainFor bounds how long a connection is held open after the body, so a
// client that never closes cannot pin a goroutine.
const drainFor = 10 * time.Second

// serve writes body, then half-closes and drains before closing.
//
// It must not simply Close after the Write: Write returns once the body is in
// the send buffer, not once it is sent, and closing a socket with the client's
// request unread (or receiving that request after the close) makes the kernel
// send an RST and DISCARD everything still unsent. The engine's request arrives
// while this peer is still in slow start, so the body was cut at a flight
// boundary - 15,720 or 26,200 bytes - and the large-response case measured the
// peer aborting itself rather than the engine. Half-closing sends the body and
// a FIN; draining leaves nothing unread at Close. The engine's own RST, which is
// what the case exists to exercise, still ends the transfer whenever it comes.
func serve(c *net.TCPConn, body []byte) {
	defer func() { _ = c.Close() }()
	if err := c.SetWriteDeadline(time.Now().Add(drainFor)); err != nil {
		return
	}
	if _, err := c.Write(body); err != nil {
		return // the client reset or went away: nothing left to send
	}
	if err := c.CloseWrite(); err != nil {
		return
	}
	if err := c.SetReadDeadline(time.Now().Add(drainFor)); err != nil {
		return
	}
	// Until the client closes, resets, or the deadline passes; every one of
	// those ends the drain, and its error is the expected outcome.
	_, _ = io.Copy(io.Discard, c)
}

func main() {
	n, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	body := bytes.Repeat([]byte("A"), n)
	ln, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		panic(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() { serve(c.(*net.TCPConn), body) }()
	}
}
