//go:build !linux && !windows

package quic

func isTransientSendErr(error) bool { return false }

func retrySend(_ func() error, err error) error { return err }
