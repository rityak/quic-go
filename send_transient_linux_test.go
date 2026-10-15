//go:build linux

package quic

import (
	"testing"

	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/testutils/synctest"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"
)

var busySendErrForTest error = unix.ENOBUFS

// A vanished path (network change) loses the packet, not the connection.
func TestSendQueueSurvivesPathGone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		c.EXPECT().Write([]byte("foobar"), gomock.Any(), gomock.Any()).Return(unix.ENETUNREACH)
		c.EXPECT().Write([]byte("second"), gomock.Any(), gomock.Any()).Return(nil)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)
		q.Send(getPacketWithContents([]byte("second")), 6, protocol.ECNNon)

		errChan := make(chan error, 1)
		go func() { errChan <- q.Run() }()
		synctest.Wait()
		q.Close()
		synctest.Wait()
		require.NoError(t, <-errChan)
	})
}
