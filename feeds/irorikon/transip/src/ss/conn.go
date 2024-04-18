package shadowsocks2

import (
	"io"
	"net"
	"time"
)

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func relay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

type connLastSeen struct {
	net.Conn
	lastSeen time.Time
}

func (c *connLastSeen) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		c.lastSeen = time.Now()
	}
	return
}

func (c *connLastSeen) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if err != nil {
		c.lastSeen = time.Now()
	}
	return
}
