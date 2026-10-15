package quic

import "os"

// greaseQUICBit advertises grease_quic_bit (RFC 9287) and, when the peer does
// too, clears the fixed bit of half the short header packets: a constant bit
// is one more fingerprint for middleboxes that classify QUIC (miray T-038,
// after jaywehosl/qd). MIRAY_QUIC_GREASE=off disables both.
var greaseQUICBit = os.Getenv("MIRAY_QUIC_GREASE") != "off"
