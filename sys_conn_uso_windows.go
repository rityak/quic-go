//go:build windows

package quic

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
)

// UDP segmentation offload on Windows (miray T-037, after jaywehosl/qd).
// UDP_SEND_MSG_SIZE lets one WSASendMsg carry a GSO batch that the stack cuts
// into datagrams; UDP_RECV_MAX_COALESCED_SIZE makes the stack hand over several
// received datagrams in one buffer, with the segment size in a control message.
// Without either option the conn behaves like basicConn. MIRAY_QUIC_USO=off
// disables both.
const (
	udpSendMsgSize          = 2 // UDP_SEND_MSG_SIZE
	udpRecvMaxCoalescedSize = 3 // UDP_RECV_MAX_COALESCED_SIZE, also the cmsg type of UDP_COALESCED_INFO
	udpCoalescedMax         = 65527
)

type usoConn struct {
	*basicConn
	raw syscall.RawConn
	v6  bool
	off atomic.Bool // segmented send failed before it ever worked: fall back for good
	ran atomic.Bool // segmented send worked at least once

	// receive coalescing; conn is nil when the option is unavailable
	conn    OOBCapablePacketConn
	scratch []byte
	oob     []byte
	pending []receivedPacket
	next    int
}

func newUSOConn(c OOBCapablePacketConn, supportsDF bool) rawConn {
	b := &basicConn{PacketConn: c, supportsDF: supportsDF}
	if os.Getenv("MIRAY_QUIC_USO") == "off" {
		return b
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return b
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		_, serr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_UDP, udpSendMsgSize)
	}); err != nil || serr != nil {
		return b // no USO on this system
	}
	local, _ := c.LocalAddr().(*net.UDPAddr)
	u := &usoConn{basicConn: b, raw: raw, v6: local == nil || local.IP.To4() == nil}
	if err := raw.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_UDP, udpRecvMaxCoalescedSize, udpCoalescedMax)
	}); err == nil && serr == nil {
		u.conn = c
		u.scratch = make([]byte, 65535)
		u.oob = make([]byte, 64)
	}
	return u
}

func (c *usoConn) ReadPacket() (receivedPacket, error) {
	if c.conn == nil {
		return c.basicConn.ReadPacket()
	}
	for c.next >= len(c.pending) {
		c.pending = c.pending[:0]
		c.next = 0
		n, oobn, _, addr, err := c.conn.ReadMsgUDP(c.scratch, c.oob)
		if err != nil {
			return receivedPacket{}, err
		}
		c.pending = splitCoalesced(c.pending, c.scratch[:n], coalescedSegment(c.oob[:oobn]), addr, monotime.Now())
	}
	p := c.pending[c.next]
	c.pending[c.next] = receivedPacket{}
	c.next++
	return p, nil
}

// splitCoalesced cuts a coalesced receive into datagrams of segment bytes (the
// last may be shorter); segment 0 means one datagram. Oversized pieces are dropped.
func splitCoalesced(out []receivedPacket, data []byte, segment int, addr net.Addr, now monotime.Time) []receivedPacket {
	if segment <= 0 || segment > len(data) {
		segment = len(data)
	}
	for len(data) > 0 {
		size := segment
		if size > len(data) {
			size = len(data)
		}
		if size <= protocol.MaxPacketBufferSize {
			buffer := getPacketBuffer()
			buffer.Data = append(buffer.Data[:0], data[:size]...)
			out = append(out, receivedPacket{remoteAddr: addr, rcvTime: now, data: buffer.Data, buffer: buffer})
		}
		data = data[size:]
	}
	return out
}

// coalescedSegment finds the UDP_COALESCED_INFO control message (a DWORD
// segment size) in WSARecvMsg ancillary data; 0 means not coalesced.
func coalescedSegment(oob []byte) int {
	const word = int(unsafe.Sizeof(uintptr(0)))
	const head = (word + 8 + word - 1) &^ (word - 1) // WSACMSGHDR: SIZE_T len, INT level, INT type, aligned
	for len(oob) >= head+4 {
		size := int(*(*uintptr)(unsafe.Pointer(&oob[0])))
		if size < head+4 || size > len(oob) {
			return 0
		}
		if *(*int32)(unsafe.Pointer(&oob[word])) == windows.IPPROTO_UDP && *(*int32)(unsafe.Pointer(&oob[word+4])) == udpRecvMaxCoalescedSize {
			return int(*(*uint32)(unsafe.Pointer(&oob[head])))
		}
		next := (size + word - 1) &^ (word - 1)
		if next >= len(oob) {
			return 0
		}
		oob = oob[next:]
	}
	return 0
}

func (c *usoConn) capabilities() connCapabilities {
	return connCapabilities{DF: c.supportsDF, GSO: !c.off.Load()}
}

func (c *usoConn) WritePacket(b []byte, addr net.Addr, _ []byte, gsoSize uint16, _ protocol.ECN) (int, error) {
	if gsoSize == 0 || len(b) <= int(gsoSize) {
		return c.WriteTo(b, addr)
	}
	if !c.off.Load() {
		n, err := c.sendSegmented(b, addr, gsoSize)
		if err == nil {
			c.ran.Store(true)
			return n, nil
		}
		if isTransientSendErr(err) {
			return n, err // sendQueue retries the whole batch (T-035)
		}
	}
	// segmented send refused: write the datagrams one by one
	total := len(b)
	for len(b) > 0 {
		size := int(gsoSize)
		if size > len(b) {
			size = len(b)
		}
		seg := b[:size]
		if _, err := c.WriteTo(seg, addr); err != nil {
			if err = retrySend(func() error { _, err := c.WriteTo(seg, addr); return err }, err); err != nil {
				return 0, err
			}
		}
		b = b[size:]
	}
	if !c.ran.Load() {
		c.off.Store(true) // never worked on this socket: stop asking for GSO batches
	}
	return total, nil
}

func (c *usoConn) sendSegmented(b []byte, addr net.Addr, gsoSize uint16) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("uso: not a UDP address")
	}
	ap := ua.AddrPort()
	// the address is built inside a RawSockaddrAny: pointing Name at a smaller
	// sockaddr straddles allocations (checkptr fails under -race, T-065)
	var name syscall.RawSockaddrAny
	var namelen int32
	if c.v6 {
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&name))
		sa6.Family = windows.AF_INET6
		port := (*[2]byte)(unsafe.Pointer(&sa6.Port))
		port[0], port[1] = byte(ap.Port()>>8), byte(ap.Port())
		sa6.Addr = ap.Addr().As16()
		namelen = int32(unsafe.Sizeof(*sa6))
	} else {
		sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&name))
		sa4.Family = windows.AF_INET
		port := (*[2]byte)(unsafe.Pointer(&sa4.Port))
		port[0], port[1] = byte(ap.Port()>>8), byte(ap.Port())
		sa4.Addr = ap.Addr().Unmap().As4()
		namelen = int32(unsafe.Sizeof(*sa4))
	}

	const word = unsafe.Sizeof(uintptr(0))
	const head = (word + 8 + word - 1) &^ (word - 1)
	const space = head + (4+word-1)&^(word-1)
	var ctl [4]uint64
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&ctl[0])), space)
	*(*uintptr)(unsafe.Pointer(&raw[0])) = head + 4
	*(*int32)(unsafe.Pointer(&raw[word])) = windows.IPPROTO_UDP
	*(*int32)(unsafe.Pointer(&raw[word+4])) = udpSendMsgSize
	*(*uint32)(unsafe.Pointer(&raw[head])) = uint32(gsoSize)

	buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
	msg := windows.WSAMsg{
		Name:        &name,
		Namelen:     namelen,
		Buffers:     &buf,
		BufferCount: 1,
		Control:     windows.WSABuf{Len: uint32(space), Buf: &raw[0]},
	}
	var sent uint32
	var serr error
	if err := c.raw.Write(func(fd uintptr) bool {
		serr = windows.WSASendMsg(windows.Handle(fd), &msg, 0, &sent, nil, nil)
		return true
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return int(sent), nil
}
