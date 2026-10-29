//go:build linux

package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"golang.org/x/sys/unix"
)

// What ReadMsgUDP returns for an ICMP error left on the socket (IP_RECVERR): a packet too big or a
// transient unreachable must not close the transport, a refused port must (T-116).
func TestRecvICMPSoftErr(t *testing.T) {
	wrap := func(e error) error { return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvmsg", e)} }
	for _, e := range []error{unix.EMSGSIZE, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EHOSTDOWN} {
		if !isRecvICMPSoftErr(wrap(e)) {
			t.Errorf("%v must be soft", e)
		}
	}
	if isRecvICMPSoftErr(wrap(unix.ECONNREFUSED)) {
		t.Error("ECONNREFUSED must close the transport")
	}
}

// A connection refused on the transport of one connection keeps it when
// Config.ConnectionRefused says so: a client that hops server ports loses one
// closed port, not the connection (miray T-158). Unset, the transport closes, as
// for a closed server port without hopping (T-116).
func TestConnectionRefusedHook(t *testing.T) {
	for _, keep := range []bool{true, false} {
		t.Run(map[bool]string{true: "kept", false: "closed"}[keep], func(t *testing.T) {
			ln, err := ListenAddr("127.0.0.1:0", selfSignedTLS(t), &Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, err := ln.Accept(context.Background())
					if err != nil {
						return
					}
					go func() {
						for {
							s, err := conn.AcceptStream(context.Background())
							if err != nil {
								return
							}
							go func() { _, _ = io.Copy(s, s); _ = s.Close() }()
						}
					}()
				}
			}()
			closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			closedAddr := closed.LocalAddr()
			_ = closed.Close()

			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			rc, _ := udp.SyscallConn()
			_ = rc.Control(func(fd uintptr) { _ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1) })
			tr := &Transport{Conn: udp}
			tr.SetCreatedConn(true)
			tr.SetSingleUse(true)
			var refused atomic.Int32
			conf := &Config{}
			if keep {
				conf.ConnectionRefused = func() bool { refused.Add(1); return true }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"t"}}
			conn, err := tr.Dial(ctx, ln.Addr(), tlsConf, conf)
			if err != nil {
				t.Fatal(err)
			}
			echo := func() error {
				s, err := conn.OpenStreamSync(ctx)
				if err != nil {
					return err
				}
				_ = s.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = s.Write([]byte("ping")); err != nil {
					return err
				}
				_ = s.Close()
				_, err = io.ReadAll(s)
				return err
			}
			if err := echo(); err != nil {
				t.Fatal(err)
			}
			server := conn.RemoteAddr()
			conn.SetRemoteAddr(closedAddr) // a hop to a closed port
			_ = conn.SendDatagram(nil)     // anything that goes out; the PING below too
			s, _ := conn.OpenStream()
			_, _ = s.Write([]byte("x"))
			time.Sleep(300 * time.Millisecond) // the ICMP comes back
			conn.SetRemoteAddr(server)
			err = echo()
			if keep {
				if err != nil || refused.Load() == 0 {
					t.Fatalf("after the refusal: %v, hook called %d times", err, refused.Load())
				}
			} else if err == nil {
				t.Fatal("the connection survived a refusal without the hook")
			}
		})
	}
}

func selfSignedTLS(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)},
		&x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"t"}}
}
