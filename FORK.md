# rityak/quic-go

Module path remains `github.com/metacubex/quic-go`. The fork keeps the upstream
license and follows the `miray` branch. Existing socket, DATAGRAM, GREASE and
recovery changes are listed in README.md.

## NewReno loss reduction

The default sender uses NewReno (`reno=true`). On a new congestion event,
`renoBeta=0.5` implements RFC 9002 section 7.3.2. CUBIC's separate reduction
factor is unchanged. `TestRenoLossHalvesWindow` checks an independently computed
half-window, the slow-start threshold, and no second cut within recovery.
