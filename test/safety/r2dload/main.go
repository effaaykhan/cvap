// Command r2dload is the R2-D safety gate's traffic source (ADR-110). It runs
// INSIDE the policed Scan Point network namespace, with no capabilities, and
// opens N connections to the hostile peer: reading ones that draw peer-induced
// ACKs, and to the sink port, writing ones that put the Scan Point's own data
// (and, once the policer drops some, its retransmissions) on the wire. Every
// connection ends with SO_LINGER 0, so RSTs after close are part of the run.
//
// It enforces nothing. The ceiling under test is the kernel's; this only makes
// traffic and reports, per connection, what the gate needs to place it.
package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type result struct {
	Port      string `json:"peer_port"`
	LocalPort int    `json:"local_port"`
	ConnectNS int64  `json:"connect_ns"`
	CloseNS   int64  `json:"close_ns"`
	Bytes     int    `json:"bytes"`
	Err       string `json:"err,omitempty"`
}

const sinkPort = "9030"

func one(host, port string, dur, delta time.Duration) result {
	r := result{Port: port}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	tc := c.(*net.TCPConn)
	r.ConnectNS = time.Now().UnixNano()
	r.LocalPort = tc.LocalAddr().(*net.TCPAddr).Port
	deadline := time.Now().Add(dur)
	if port == sinkPort {
		chunk := make([]byte, 16<<10)
		_ = tc.SetWriteDeadline(deadline)
		for time.Now().Before(deadline) {
			n, err := tc.Write(chunk)
			r.Bytes += n
			if err != nil {
				break
			}
		}
	} else {
		if port == "9004" {
			_, _ = tc.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		}
		_ = tc.SetReadDeadline(deadline)
		buf := make([]byte, 16<<10)
		var last time.Time
		for time.Now().Before(deadline) {
			if w := delta - time.Since(last); !last.IsZero() && w > 0 {
				time.Sleep(min(w, time.Until(deadline)))
			}
			last = time.Now()
			n, err := tc.Read(buf)
			r.Bytes += n
			if err != nil {
				break
			}
		}
	}
	_ = tc.SetLinger(0)
	r.CloseNS = time.Now().UnixNano()
	_ = tc.Close()
	return r
}

func main() {
	host := flag.String("host", "", "peer address")
	ports := flag.String("ports", "", "comma-separated peer ports, assigned round-robin")
	n := flag.Int("n", 1, "connections")
	dur := flag.Duration("dur", 3*time.Second, "how long each connection is held")
	delta := flag.Duration("delta", 100*time.Millisecond, "spacing between socket reads")
	flag.Parse()
	pl := strings.Split(*ports, ",")
	out := make([]result, *n)
	var wg sync.WaitGroup
	for i := range *n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = one(*host, pl[i%len(pl)], *dur, *delta)
		}()
	}
	wg.Wait()
	enc := json.NewEncoder(os.Stdout)
	for _, r := range out {
		_ = enc.Encode(r)
	}
}
