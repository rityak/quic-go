package wire

import (
	"bytes"
	"testing"
)

func TestParseGreasedLongHeadersPreservesAuthenticatedBytes(t *testing.T) {
	for _, kind := range []byte{0, 1, 2, 3} {
		b := []byte{0x80 | kind<<4, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8}
		if kind == 0 {
			b = append(b, 0)
		}
		if kind == 3 {
			b = append(b, 42)
			b = append(b, make([]byte, 16)...)
		} else {
			b = append(b, 1, 0)
		}
		original := bytes.Clone(b)
		if _, _, _, err := ParsePacket(b); err == nil {
			t.Fatal("strict parser accepted a cleared bit")
		}
		h, packet, rest, err := ParsePacketWithGrease(b, true)
		if err != nil || len(rest) != 0 || h == nil || !bytes.Equal(packet, original) || !bytes.Equal(b, original) {
			t.Fatalf("type %d: header or authenticated bytes changed: %v", kind, err)
		}
		if h.typeByte&0x40 != 0 {
			t.Fatal("header bit was synthesized")
		}
	}
}
