# rityak/quic-go

Module path remains `github.com/metacubex/quic-go`. The fork keeps the upstream
license and follows the `miray` branch. Existing socket, DATAGRAM, GREASE and
recovery changes are listed in README.md.

## Idle path MTU discovery

The connection timer includes the next PMTU probe deadline. Previously discovery
could stall after the handshake when application datagrams exceeded the initial
packet capacity and therefore never entered the send queue. Probe timing still
respects congestion blocking and pacing; completed or outstanding probes do not
arm another timer. Tests cover an idle path with 40 ms RTT and timer pacing.

## NewReno loss reduction

The default sender uses NewReno (`reno=true`). On a new congestion event,
`renoBeta=0.5` implements RFC 9002 section 7.3.2. CUBIC's separate reduction
factor is unchanged. `TestRenoLossHalvesWindow` checks an independently computed
half-window, the slow-start threshold, and no second cut within recovery.

## HTTP Datagram deadlines

`http3.Stream` and `http3.RequestStream` forward `SendDatagramWithDeadline` to
the existing QUIC queue API, retaining the RFC 9297 quarter-stream-ID prefix.
Canceled calls and closed send streams are rejected before admission. This
prevents CONNECT-UDP from waiting indefinitely behind a full DATAGRAM queue.
The ordinary SendDatagram API and wire format remain unchanged.

## Connection migration lifecycle

`Conn.RetirePathTransport` removes an inactive transport's connection IDs on
the connection event loop and moves reset-token callbacks to the active socket.
The caller can then close the old transport without closing the live connection.
Active and pending paths cannot be retired. The operation reports its committed
result before the caller can dispose of its socket.

Path switches promote the reserved destination connection ID on both peers,
and client PATH_RESPONSE frames leave on the socket that received PATH_CHALLENGE
(RFC 9000 sections 8.2.2 and 9.5). Switch wakes the sender; canceled probes stop
their timer and synchronous probe sends return their packet buffer to the pool.
Tests cover eight consecutive migrations of one open stream, retirement of a
failed candidate, destination-ID promotion, and rejection of active retirement.
