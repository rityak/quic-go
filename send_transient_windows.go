//go:build windows

package quic

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// Windows reports WSAENOBUFS when the socket queue is full during a fast
// upload: "try again shortly", not a failed path. Any such write error used to
// end sendQueue.Run and with it the whole connection (miray T-035, after
// jaywehosl/qd).
const (
	transientTries = 12
	transientPause = 250 * time.Microsecond
)

func isTransientSendErr(err error) bool {
	return errors.Is(err, windows.WSAENOBUFS) || errors.Is(err, windows.WSAEWOULDBLOCK)
}

// retrySend retries a busy socket briefly and gives up on the packet, not on
// the connection; it returns the error only if it is no longer transient.
func retrySend(send func() error, err error) error {
	for i := 0; i < transientTries && isTransientSendErr(err); i++ {
		time.Sleep(transientPause)
		err = send()
	}
	if err != nil && isTransientSendErr(err) {
		return nil
	}
	return err
}
