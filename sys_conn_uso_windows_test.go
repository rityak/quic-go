//go:build windows

package quic

import (
	"bytes"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/stretchr/testify/require"
)

func usoPair(t *testing.T) (send, recv rawConn, to *net.UDPAddr) {
	t.Helper()
	rc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	sc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	recv, err = newConn(rc, true)
	require.NoError(t, err)
	send, err = newConn(sc, true)
	require.NoError(t, err)
	t.Cleanup(func() { recv.Close(); send.Close() })
	return send, recv, rc.LocalAddr().(*net.UDPAddr)
}

func batch(n, size int) []byte {
	b := make([]byte, 0, n*size)
	for i := 0; i < n; i++ {
		b = append(b, bytes.Repeat([]byte{byte('a' + i)}, size)...)
	}
	return b
}

func readN(t *testing.T, c rawConn, n, size int) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(3*time.Second)))
	for i := 0; i < n; i++ {
		p, err := c.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte{byte('a' + i)}, size), p.data, "datagram %d", i)
		p.buffer.Release()
	}
}

// A GSO batch must arrive as separate datagrams in order, whether the stack
// takes it in one WSASendMsg (USO) or the conn falls back to single writes.
func TestUSOBatchArrivesAsDatagrams(t *testing.T) {
	send, recv, to := usoPair(t)
	u, ok := send.(*usoConn)
	if !ok {
		t.Skip("no UDP_SEND_MSG_SIZE on this system")
	}
	require.True(t, send.capabilities().GSO)
	n, err := send.WritePacket(batch(3, 1000), to, nil, 1000, 0)
	require.NoError(t, err)
	require.Equal(t, 3000, n)
	readN(t, recv, 3, 1000)
	t.Logf("segmented send used: %v, receive coalescing: %v", u.ran.Load(), recv.(*usoConn).conn != nil)

	// last segment shorter than gsoSize
	_, err = send.WritePacket(append(batch(2, 1000), 'z'), to, nil, 1000, 0)
	require.NoError(t, err)
	readN(t, recv, 2, 1000)
	require.NoError(t, recv.SetReadDeadline(time.Now().Add(3*time.Second)))
	p, err := recv.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, []byte("z"), p.data)
}

func TestUSOFallbackSendsSingleDatagrams(t *testing.T) {
	send, recv, to := usoPair(t)
	u, ok := send.(*usoConn)
	if !ok {
		t.Skip("no UDP_SEND_MSG_SIZE on this system")
	}
	u.off.Store(true)
	require.False(t, send.capabilities().GSO)
	_, err := send.WritePacket(batch(3, 500), to, nil, 500, 0)
	require.NoError(t, err)
	readN(t, recv, 3, 500)
}

func TestCoalescedSegment(t *testing.T) {
	const word = int(unsafe.Sizeof(uintptr(0)))
	const head = (word + 8 + word - 1) &^ (word - 1)
	msg := func(level, typ int32, v uint32) []byte {
		b := make([]byte, head+8)
		*(*uintptr)(unsafe.Pointer(&b[0])) = uintptr(head + 4)
		*(*int32)(unsafe.Pointer(&b[word])) = level
		*(*int32)(unsafe.Pointer(&b[word+4])) = typ
		*(*uint32)(unsafe.Pointer(&b[head])) = v
		return b
	}
	require.Equal(t, 1200, coalescedSegment(msg(windows.IPPROTO_UDP, udpRecvMaxCoalescedSize, 1200)))
	require.Equal(t, 0, coalescedSegment(msg(windows.IPPROTO_IP, 19, 1200)))
	// the coalescing info after another control message
	require.Equal(t, 1350, coalescedSegment(append(msg(windows.IPPROTO_IP, 19, 7), msg(windows.IPPROTO_UDP, udpRecvMaxCoalescedSize, 1350)...)))
	require.Equal(t, 0, coalescedSegment(nil))
	require.Equal(t, 0, coalescedSegment(make([]byte, head+4))) // zero length field
}

func TestSplitCoalesced(t *testing.T) {
	data := append(batch(2, 1000), batch(1, 500)...)
	ps := splitCoalesced(nil, data, 1000, nil, 0)
	require.Len(t, ps, 3)
	require.Equal(t, data[:1000], ps[0].data)
	require.Equal(t, data[1000:2000], ps[1].data)
	require.Equal(t, data[2000:], ps[2].data)
	require.Len(t, splitCoalesced(nil, data[:1000], 0, nil, 0), 1) // no coalescing info: one datagram
	require.Len(t, splitCoalesced(nil, data, 0, nil, 0), 0)        // one oversized datagram is dropped
}
