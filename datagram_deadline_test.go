package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/internal/wire"
)

func TestDatagramQueueAdmissionCancellation(t *testing.T) {
	q := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		if err := q.Add(&wire.DatagramFrame{}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.AddContext(ctx, &wire.DatagramFrame{}, time.Time{}) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("admission did not cancel")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := q.AddContext(ctx, &wire.DatagramFrame{}, time.Time{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestDatagramQueueExpiredFrames(t *testing.T) {
	q := newDatagramQueue(func() {}, utils.DefaultLogger)
	expires := time.Now().Add(10 * time.Millisecond)
	if err := q.AddContext(context.Background(), &wire.DatagramFrame{Data: []byte("expired")}, expires); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expires))
	if frame := q.Peek(); frame != nil {
		t.Fatal("expired frame returned")
	}
	if err := q.AddContext(context.Background(), &wire.DatagramFrame{}, time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := q.Add(&wire.DatagramFrame{Data: []byte("legacy")}); err != nil {
		t.Fatal(err)
	}
	if frame := q.Peek(); frame == nil || string(frame.Data) != "legacy" {
		t.Fatal(frame)
	}
}
