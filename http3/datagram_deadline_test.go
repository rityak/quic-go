package http3

import (
	"context"
	"testing"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

func TestHTTPDatagramDeadline(t *testing.T) {
	client, _ := newConnPair(t)
	conn := newRawConn(client, true, nil, nil, nil, nil)
	stream, err := client.OpenStream()
	require.NoError(t, err)
	httpStream := newStream(conn.TrackStream(stream), conn, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, httpStream.SendDatagramWithDeadline(ctx, []byte("udp"), time.Time{}), context.Canceled)
	request := &RequestStream{str: httpStream}
	require.ErrorIs(t, request.SendDatagramWithDeadline(ctx, []byte("udp"), time.Time{}), context.Canceled)
	stream.CancelWrite(quic.StreamErrorCode(0x10c))
	require.Error(t, httpStream.SendDatagramWithDeadline(context.Background(), []byte("udp"), time.Time{}))
}
