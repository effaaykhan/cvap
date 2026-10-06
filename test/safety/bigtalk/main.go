// Command bigtalk is the safety gate's large-response peer: it writes a fixed
// number of bytes to every connection it accepts, concurrently, then closes.
//
// The per-operation wire check (safety_wire_ops.py) needs a peer that pushes far
// more than the engine reads, to show what that peer extracts from this end as
// kernel-response traffic. busybox `nc -l` served one connection at a time and
// refused the engine's second, which left the case measuring nothing.
package main

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"time"
)

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
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = c.Write(body)
		}()
	}
}
