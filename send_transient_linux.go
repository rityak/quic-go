//go:build linux

package quic

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// A full socket queue means "try again shortly", not a failed path. Any write
// error other than "datagram too large" used to end sendQueue.Run and with it
// the whole connection, so a burst of ENOBUFS under load, or a network change,
// dropped every stream of the connection (miray T-035, after jaywehosl/qd).
const (
	transientTries = 12
	transientPause = 250 * time.Microsecond
)

func isBusySendErr(err error) bool {
	return errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN)
}

// The path is gone (interface down, no route, address removed, firewall
// reject): retrying cannot help, but the connection must survive so that
// migration or the next path can carry it; the packet counts as lost.
func isPathGoneErr(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.EADDRNOTAVAIL) ||
		errors.Is(err, unix.EPERM)
}

func isTransientSendErr(err error) bool { return isBusySendErr(err) || isPathGoneErr(err) }

// retrySend retries a busy socket briefly and gives up on the packet, not on
// the connection; it returns the error only if it is no longer transient.
func retrySend(send func() error, err error) error {
	if isPathGoneErr(err) {
		return nil
	}
	for i := 0; i < transientTries && isBusySendErr(err); i++ {
		time.Sleep(transientPause)
		err = send()
	}
	if err != nil && isTransientSendErr(err) {
		return nil
	}
	return err
}
