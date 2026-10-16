//go:build linux

package quic

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func appendCmsg(b []byte, level, typ int32, data []byte) []byte {
	start := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(len(data)))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[start]))
	h.Level, h.Type = level, typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[start+unix.CmsgSpace(0):], data)
	return b
}

type groBatchConn struct{ msgs [][2][]byte } // data, oob per call

func (c *groBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	n := 0
	for ; n < len(ms) && len(c.msgs) > 0; n++ {
		m := c.msgs[0]
		c.msgs = c.msgs[1:]
		ms[n].N = copy(ms[n].Buffers[0], m[0])
		ms[n].NN = copy(ms[n].OOB, m[1])
		ms[n].Flags = 0
	}
	return n, nil
}

// T-083: a GRO message is cut by the segment size from the UDP_GRO control
// message; every piece keeps the ECN bits; a message without it is one datagram.
func TestReadGRO(t *testing.T) {
	oobConn, err := newConn(newUDPConnLocalhost(t), true)
	require.NoError(t, err)
	if !oobConn.gro {
		t.Skip("no UDP_GRO on this kernel")
	}
	var seg [4]byte
	nativeEndian.PutUint32(seg[:], 1000)
	coalesced := append(bytes.Repeat([]byte{1}, 1000), append(bytes.Repeat([]byte{2}, 1000), bytes.Repeat([]byte{3}, 500)...)...)
	// IP_TOS carries the header bits: 0b11 is CE
	oob := appendCmsg(appendCmsg(nil, unix.IPPROTO_IP, unix.IP_TOS, []byte{0b11}), unix.SOL_UDP, unix.UDP_GRO, seg[:])
	oobConn.batchConn = &groBatchConn{msgs: [][2][]byte{{coalesced, oob}, {bytes.Repeat([]byte{4}, 200), nil}}}

	for i, want := range []struct {
		b   byte
		n   int
		ecn protocol.ECN
	}{{1, 1000, protocol.ECNCE}, {2, 1000, protocol.ECNCE}, {3, 500, protocol.ECNCE}, {4, 200, protocol.ECNUnsupported}} { // no IP_TOS on the last: unknown
		p, err := oobConn.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte{want.b}, want.n), p.data, "packet %d", i)
		require.Equal(t, want.ecn, p.ecn, "packet %d", i)
		p.buffer.Release()
	}
}
