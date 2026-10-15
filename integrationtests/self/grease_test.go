package self_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	quicproxy "github.com/metacubex/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

// Both ends advertise grease_quic_bit (miray T-038), so short header packets
// in both directions must carry a cleared fixed bit about half of the time,
// and the transfer must still complete.
func TestGreaseQUICBit(t *testing.T) {
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	var short, greased [2]atomic.Int64
	proxy := &quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DropPacket: func(d quicproxy.Direction, _, _ net.Addr, b []byte) bool {
			if len(b) > 0 && b[0]&0x80 == 0 { // short header
				i := 0
				if d == quicproxy.DirectionOutgoing {
					i = 1
				}
				short[i].Add(1)
				if b[0]&0x40 == 0 {
					greased[i].Add(1)
				}
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	data := GeneratePRData(1 << 20)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.OpenUniStream()
		if err != nil {
			return
		}
		_, _ = str.Write(data)
		_ = str.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	got, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, data, got)

	for i, dir := range []string{"client->server", "server->client"} {
		n, g := short[i].Load(), greased[i].Load()
		t.Logf("%s: %d short header packets, %d with the fixed bit cleared", dir, n, g)
		require.NotZero(t, n, dir)
		// half of them at random; generous bounds for small counts
		require.Greater(t, float64(g), 0.2*float64(n), dir)
		require.Less(t, float64(g), 0.8*float64(n), dir)
	}
}
