//go:build windows

package quic

import "golang.org/x/sys/windows"

var busySendErrForTest error = windows.WSAENOBUFS
