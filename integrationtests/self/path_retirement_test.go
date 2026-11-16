package self_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

type blackholedMigrationSocket struct{ net.PacketConn }

func (c blackholedMigrationSocket) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func TestMigrationRetiresOldSocketsWithoutClosingStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer listener.Close()
	socket := newUDPConnLocalhost(t)
	tr := &quic.Transport{Conn: socket}
	conn, err := tr.Dial(ctx, listener.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	done := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		if err == nil {
			_, err = io.Copy(stream, stream)
		}
		done <- err
	}()
	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.Close())
		require.NoError(t, <-done)
		require.NoError(t, tr.Close())
		require.NoError(t, socket.Close())
	}()
	deadline, _ := ctx.Deadline()
	require.NoError(t, stream.SetDeadline(deadline))
	exchange := func(sequence byte) {
		t.Helper()
		_, err := stream.Write([]byte{sequence})
		require.NoError(t, err)
		var received [1]byte
		_, err = io.ReadFull(stream, received[:])
		require.NoError(t, err)
		require.Equal(t, sequence, received[0])
	}
	exchange(0)
	require.ErrorContains(t, conn.RetirePathTransport(ctx, tr), "active path")
	for i := byte(1); i <= 8; i++ {
		nextSocket := newUDPConnLocalhost(t)
		next := &quic.Transport{Conn: nextSocket}
		path, err := conn.AddPath(next)
		require.NoError(t, err)
		require.NoError(t, path.Probe(ctx), "migration %d", i)
		require.NoError(t, path.Switch())
		exchange(i)
		require.NoError(t, conn.RetirePathTransport(ctx, tr))
		require.NoError(t, tr.Close())
		require.NoError(t, socket.Close())
		tr, socket = next, nextSocket
		exchange(i + 16)
	}
	failedSocket := newUDPConnLocalhost(t)
	failed := &quic.Transport{Conn: blackholedMigrationSocket{failedSocket}}
	path, err := conn.AddPath(failed)
	require.NoError(t, err)
	probeCtx, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	err = path.Probe(probeCtx)
	stop()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, conn.RetirePathTransport(ctx, failed))
	require.NoError(t, failed.Close())
	require.NoError(t, failedSocket.Close())
	exchange(42)
}
