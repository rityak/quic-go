package quic

import (
	"testing"

	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMigrationPromotesReservedConnectionID(t *testing.T) {
	initial := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	reserved := protocol.ParseConnectionID([]byte{5, 6, 7, 8})
	var retired []uint64
	manager := newConnIDManager(initial, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(frame wire.Frame) {
		retired = append(retired, frame.(*wire.RetireConnectionIDFrame).SequenceNumber)
	})
	require.NoError(t, manager.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: reserved}))
	id, available := manager.GetConnIDForPath(1)
	require.True(t, available)
	require.Equal(t, reserved, id)
	require.Equal(t, initial, manager.Get())
	require.True(t, manager.UseConnIDForPath(1))
	require.Equal(t, reserved, manager.Get())
	require.Equal(t, []uint64{0}, retired)
	require.Empty(t, manager.pathProbing)
}
