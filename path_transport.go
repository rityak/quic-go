package quic

import (
	"context"
	"errors"

	"github.com/metacubex/quic-go/internal/ackhandler"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/wire"
)

func (c *Conn) respondOnPath(packet receivedPacket, challenge *wire.PathChallengeFrame) error {
	var id protocol.ConnectionID
	active, ok := c.conn.(*sconn)
	if ok && active.rawConn == packet.transport.conn {
		id = c.connIDManager.Get()
	} else {
		pm := c.pathManagerOutgoing.Load()
		if pm == nil {
			return nil
		}
		pm.mx.Lock()
		found := false
		for pathID, path := range pm.paths {
			if path.tr == packet.transport {
				id, found = pm.getConnID(pathID)
				break
			}
		}
		pm.mx.Unlock()
		if !found {
			return nil // A queued packet can outlive retirement of its socket.
		}
	}
	frame := ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: challenge.Data}}
	probe, buffer, err := c.packer.PackPathProbePacket(id, []ackhandler.Frame{frame}, c.version)
	if err != nil {
		return err
	}
	defer buffer.Release()
	c.logShortHeaderPacket(probe, protocol.ECNNon, buffer.Len())
	c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, packet.rcvTime)
	if _, err := packet.transport.WriteTo(buffer.Data, packet.remoteAddr); err != nil {
		c.logger.Debugf("path response send failed: %s", err)
	}
	return nil
}

type pathOperation struct {
	ctx    context.Context
	apply  func() error
	result chan error
}

func (op pathOperation) run() {
	if err := op.ctx.Err(); err != nil {
		op.result <- err
		return
	}
	op.result <- op.apply()
}

// RetirePathTransport removes an inactive transport from this connection's
// routing tables. Stop probing its paths before calling this method. After
// success, closing the transport no longer terminates this connection.
// The active transport and a transport pending activation cannot be retired.
func (c *Conn) RetirePathTransport(ctx context.Context, tr *Transport) error {
	if tr == nil {
		return errors.New("nil path transport")
	}
	op := pathOperation{ctx: ctx, result: make(chan error, 1)}
	op.apply = func() error {
		active, ok := c.conn.(*sconn)
		if !ok || active.rawConn == tr.conn {
			return errors.New("cannot retire active path transport")
		}
		if pm := c.pathManagerOutgoing.Load(); pm != nil {
			if err := pm.retireTransport(tr); err != nil {
				return err
			}
		}
		// Reset-token callbacks initially refer to the handshake transport.
		// Move them before the old socket and its handler map are destroyed.
		for runner := range c.connIDGenerator.connRunners {
			if handler, ok := runner.(*packetHandlerMap); ok && handler.conn == active.rawConn {
				c.connIDManager.moveResetTokens(
					func(token protocol.StatelessResetToken) { handler.AddResetToken(token, c) },
					handler.RemoveResetToken,
				)
				break
			}
		}
		c.connIDGenerator.RemoveConnRunner((*packetHandlerMap)(tr))
		return nil
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	case c.pathOperations <- op:
	}
	// Once admitted, observe whether the operation committed before the caller
	// closes its socket; returning early on cancellation would lose that result.
	select {
	case err := <-op.result:
		return err
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}

func (pm *pathManagerOutgoing) retireTransport(tr *Transport) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()
	for id, path := range pm.paths {
		if path.tr == tr && (id == pm.activePath || path == pm.pathToSwitchTo) {
			return errors.New("cannot retire active path transport")
		}
	}
	for id, path := range pm.paths {
		if path.tr == tr {
			pm.retireConnID(id)
			delete(pm.paths, id)
		}
	}
	return nil
}

func (pm *pathManagerOutgoing) deferPathSwitch(id pathID) {
	pm.mx.Lock()
	defer pm.mx.Unlock()
	if pm.pathToSwitchTo == nil && pm.activePath == id {
		pm.pathToSwitchTo = pm.paths[id]
	}
}

func (m *connIDGenerator) RemoveConnRunner(runner connRunner) {
	callbacks, ok := m.connRunners[runner]
	if !ok {
		return
	}
	if m.initialClientDestConnID != nil {
		callbacks.RemoveConnectionID(*m.initialClientDestConnID)
	}
	for _, id := range m.activeSrcConnIDs {
		callbacks.RemoveConnectionID(id)
	}
	for _, entry := range m.connIDsToRetire {
		callbacks.RemoveConnectionID(entry.connID)
	}
	delete(m.connRunners, runner)
}

func (h *connIDManager) moveResetTokens(add func(protocol.StatelessResetToken), remove func(protocol.StatelessResetToken)) {
	move := func(token protocol.StatelessResetToken) {
		h.removeStatelessResetToken(token)
		add(token)
	}
	if h.activeStatelessResetToken != nil {
		move(*h.activeStatelessResetToken)
	}
	for _, entry := range h.pathProbing {
		move(entry.StatelessResetToken)
	}
	h.addStatelessResetToken, h.removeStatelessResetToken = add, remove
}

// UseConnIDForPath promotes the ID reserved for a probed path, so the old
// path's connection ID is never reused on the new local address (RFC 9000 9.5).
func (h *connIDManager) UseConnIDForPath(id pathID) bool {
	h.assertNotClosed()
	if h.activeConnectionID.Len() == 0 {
		return true
	}
	entry, ok := h.pathProbing[id]
	if !ok {
		if _, available := h.GetConnIDForPath(id); !available {
			return false
		}
		entry, ok = h.pathProbing[id]
	}
	if !ok || entry.SequenceNumber < h.highestRetired {
		return false
	}
	h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: h.activeSequenceNumber})
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	h.activeSequenceNumber = entry.SequenceNumber
	h.activeConnectionID = entry.ConnectionID
	h.activeStatelessResetToken = &entry.StatelessResetToken
	h.packetsSinceLastChange = 0
	delete(h.pathProbing, id)
	return true
}
