//go:build linux || windows

package quic

import (
	"testing"

	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/testutils/synctest"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A busy socket is retried and the connection keeps running (miray T-035).
func TestSendQueueRetriesBusySocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		gomock.InOrder(
			c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(busySendErrForTest),
			c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(busySendErrForTest),
			c.EXPECT().Write([]byte("foobar"), gomock.Any(), gomock.Any()).Return(nil),
			c.EXPECT().Write([]byte("second"), gomock.Any(), gomock.Any()).Return(nil),
		)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)
		q.Send(getPacketWithContents([]byte("second")), 6, protocol.ECNNon)

		errChan := make(chan error, 1)
		go func() { errChan <- q.Run() }()
		synctest.Wait()
		select {
		case err := <-errChan:
			t.Fatalf("Run returned %v on a busy socket", err)
		default:
		}
		q.Close()
		synctest.Wait()
		require.NoError(t, <-errChan)
	})
}

// A socket that stays busy loses the packet, not the connection.
func TestSendQueueDropsPacketOnPersistentBusySocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		c.EXPECT().Write([]byte("foobar"), gomock.Any(), gomock.Any()).Return(busySendErrForTest).Times(1 + transientTries)
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
