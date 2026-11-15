package quic

import (
	"testing"

	"github.com/metacubex/quic-go/internal/ackhandler"
	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/wire"
)

type saturatedFrameStream struct{ id protocol.StreamID }

func (s saturatedFrameStream) popStreamFrame(max protocol.ByteCount, _ protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	return ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: s.id, Data: make([]byte, int(max)-32), DataLenPresent: true}}, nil, true
}
func TestFramerRoundRobinBoundsControlWait(t *testing.T) {
	f := newFramer(newConnectionFlowController(1<<30, 1<<30, nil, nil, nil))
	for i := 0; i < 9; i++ {
		id := protocol.StreamID(i * 4)
		f.AddActiveStream(id, saturatedFrameStream{id})
	}
	seen := make(map[protocol.StreamID]bool)
	for i := 0; i < 9; i++ {
		_, streams, _ := f.Append(nil, nil, 1024, monotime.Now(), protocol.Version1)
		for _, sf := range streams {
			seen[sf.Frame.StreamID] = true
		}
	}
	if len(seen) != 9 {
		t.Fatalf("round-robin scheduler starved streams: %v", seen)
	}
}
