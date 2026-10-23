//go:build linux

package quic

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// What ReadMsgUDP returns for an ICMP error left on the socket (IP_RECVERR): a packet too big or a
// transient unreachable must not close the transport, a refused port must (T-116).
func TestRecvICMPSoftErr(t *testing.T) {
	wrap := func(e error) error { return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvmsg", e)} }
	for _, e := range []error{unix.EMSGSIZE, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EHOSTDOWN} {
		if !isRecvICMPSoftErr(wrap(e)) {
			t.Errorf("%v must be soft", e)
		}
	}
	if isRecvICMPSoftErr(wrap(unix.ECONNREFUSED)) {
		t.Error("ECONNREFUSED must close the transport")
	}
}
