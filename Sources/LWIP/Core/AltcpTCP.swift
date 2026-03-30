//
//  AltcpTCP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - AltcpTCPFunctions

/// TCP implementation of AltcpFunctions.
/// This is the bottom layer that actually communicates with the TCP stack.
public final class AltcpTCPFunctions: AltcpFunctions {

    public static let shared = AltcpTCPFunctions()

    private init() {}

    // MARK: - TCP Callback Bridging

    /// Set up TCP callbacks to bridge into altcp
    public func setupCallbacks(_ conn: AltcpControlBlock, pcb: TCPControlBlock) {
        pcb.callbackArg = conn

        pcb.receiveHandler = { [weak conn] (innerPcb: TCPControlBlock, pbuf: Pbuf?, err: LWIPError) -> LWIPError in
            guard let c = conn else {
                if let p = pbuf { _ = Pbuf.free(p) }
                return .ok
            }
            if let recv = c.recvFn {
                return recv(c.arg, c, pbuf, err)
            }
            return .ok
        }

        pcb.sentHandler = { [weak conn] (innerPcb: TCPControlBlock, len: UInt16) -> LWIPError in
            guard let c = conn, let sent = c.sentFn else { return .ok }
            return sent(c.arg, c, len)
        }

        pcb.errorHandler = { [weak conn] (err: LWIPError) -> Void in
            guard let c = conn else { return }
            c.state = nil // PCB already freed
            c.errFn?(c.arg, err)
            c.free()
        }
    }

    /// Remove TCP callbacks
    public func removeCallbacks(_ pcb: TCPControlBlock) {
        pcb.callbackArg = nil
        pcb.receiveHandler = nil
        pcb.sentHandler = nil
        pcb.errorHandler = nil
        pcb.pollHandler = nil
    }

    /// Set up a connection with a TCP PCB
    public func setup(_ conn: AltcpControlBlock, pcb: TCPControlBlock) {
        setupCallbacks(conn, pcb: pcb)
        conn.state = pcb
        conn.fns = AltcpTCPFunctions.shared
    }

    // MARK: - AltcpFunctions Implementation

    public func setPoll(_ conn: AltcpControlBlock, interval: UInt8) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.pollHandler = { [weak conn] (innerPcb: TCPControlBlock) -> LWIPError in
            guard let c = conn, let poll = c.pollFn else { return .ok }
            return poll(c.arg, c)
        }
        pcb.pollInterval = interval
    }

    public func recved(_ conn: AltcpControlBlock, len: UInt16) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        TCPGlobal.shared.recved(pcb: pcb, len: len)
    }

    public func bind(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else { return .invalidValue }
        return TCPGlobal.shared.bind(pcb: pcb, address: ipaddr ?? .any, port: port)
    }

    public func connect(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16, connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else { return .invalidValue }
        conn.connectedFn = connected
        let connectedBridge: ((TCPControlBlock, LWIPError) -> LWIPError)? = { [weak conn] (innerPcb: TCPControlBlock, err: LWIPError) -> LWIPError in
            guard let c = conn, let fn = c.connectedFn else { return .ok }
            return fn(c.arg, c, err)
        }
        return TCPGlobal.shared.connect(pcb: pcb, address: ipaddr ?? .any, port: port, connected: connectedBridge)
    }

    public func listen(_ conn: AltcpControlBlock, backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock? {
        guard let pcb = conn.state as? TCPControlBlock else { return nil }
        guard let listenPCB = TCPGlobal.shared.listen(pcb: pcb, backlog: backlog) else {
            err = .outOfMemory
            return nil
        }
        conn.state = listenPCB
        listenPCB.acceptHandler = { [weak conn] (lpcb: TCPListenControlBlock, newPcb: TCPControlBlock?, acceptErr: LWIPError) -> LWIPError in
            guard let c = conn, let accept = c.acceptFn else { return .invalidArgument }
            guard let newPcb = newPcb else { return .invalidArgument }
            let newConn = AltcpControlBlock()
            AltcpTCPFunctions.shared.setup(newConn, pcb: newPcb)
            return accept(c.arg, newConn, acceptErr)
        }
        return conn
    }

    public func abort(_ conn: AltcpControlBlock) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        TCPGlobal.shared.abort(pcb: pcb)
    }

    public func close(_ conn: AltcpControlBlock) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else {
            conn.free()
            return .ok
        }
        removeCallbacks(pcb)
        let err = TCPGlobal.shared.close(pcb: pcb)
        if err != .ok {
            // Close failed, restore callbacks
            setupCallbacks(conn, pcb: pcb)
            return err
        }
        conn.state = nil
        conn.free()
        return .ok
    }

    public func shutdown(_ conn: AltcpControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else { return .invalidValue }
        return TCPGlobal.shared.shutdown(pcb: pcb, shutRx: shutRx, shutTx: shutTx)
    }

    public func write(_ conn: AltcpControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else { return .invalidValue }
        return TCPGlobal.shared.write(pcb: pcb, data: data, len: len, apiFlags: apiFlags)
    }

    public func output(_ conn: AltcpControlBlock) -> LWIPError {
        guard let pcb = conn.state as? TCPControlBlock else { return .invalidValue }
        return TCPGlobal.shared.output(pcb: pcb)
    }

    public func mss(_ conn: AltcpControlBlock) -> UInt16 {
        guard let pcb = conn.state as? TCPControlBlock else { return 0 }
        return pcb.maxSegmentSize
    }

    public func sndbuf(_ conn: AltcpControlBlock) -> UInt16 {
        guard let pcb = conn.state as? TCPControlBlock else { return 0 }
        return pcb.sendBufferAvailable
    }

    public func sndqueuelen(_ conn: AltcpControlBlock) -> UInt16 {
        guard let pcb = conn.state as? TCPControlBlock else { return 0 }
        return pcb.sendQueueLength
    }

    public func nagleDisable(_ conn: AltcpControlBlock) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.flags.insert(.noDelay)
    }

    public func nagleEnable(_ conn: AltcpControlBlock) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.flags.remove(.noDelay)
    }

    public func nagleDisabled(_ conn: AltcpControlBlock) -> Bool {
        guard let pcb = conn.state as? TCPControlBlock else { return false }
        return pcb.flags.contains(.noDelay)
    }

    public func setPrio(_ conn: AltcpControlBlock, prio: UInt8) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.priority = prio
    }

    public func dealloc(_ conn: AltcpControlBlock) {
        // No private state to clean up for TCP layer
    }

    public func getAddrInfo(_ conn: AltcpControlBlock, local: Bool) -> (IPAddress?, UInt16)? {
        guard let pcb = conn.state as? TCPControlBlock else { return nil }
        if local {
            return (pcb.localIP, pcb.localPort)
        } else {
            return (pcb.remoteIP, pcb.remotePort)
        }
    }

    public func getIP(_ conn: AltcpControlBlock, local: Bool) -> IPAddress? {
        guard let pcb = conn.state as? TCPControlBlock else { return nil }
        return local ? pcb.localIP : pcb.remoteIP
    }

    public func getPort(_ conn: AltcpControlBlock, local: Bool) -> UInt16 {
        guard let pcb = conn.state as? TCPControlBlock else { return 0 }
        return local ? pcb.localPort : pcb.remotePort
    }

    public func keepaliveDisable(_ conn: AltcpControlBlock) {
        // lwIP doesn't have a single "enabled" flag for keepalive;
        // reset keep parameters to defaults (effectively disabled behavior).
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.keepaliveIdle = TCPConstants.keepaliveIdleDefault
        pcb.keepaliveInterval = TCPConstants.keepaliveIntervalDefault
        pcb.keepaliveCount = TCPConstants.keepaliveCountDefault
    }

    public func keepaliveEnable(_ conn: AltcpControlBlock, idle: UInt32, interval: UInt32, count: UInt32) {
        guard let pcb = conn.state as? TCPControlBlock else { return }
        pcb.keepaliveIdle = idle > 0 ? idle : TCPConstants.keepaliveIdleDefault
        pcb.keepaliveInterval = interval > 0 ? interval : TCPConstants.keepaliveIntervalDefault
        pcb.keepaliveCount = count > 0 ? UInt8(min(count, UInt32(UInt8.max))) : TCPConstants.keepaliveCountDefault
    }
}

// MARK: - Factory Functions

extension AltcpTCPFunctions {
    /// Create a new altcp TCP PCB for the given IP type.
    public static func createForIPType(_ ipType: UInt8) -> AltcpControlBlock? {
        guard let tpcb = TCPGlobal.shared.new() else { return nil }
        let conn = AltcpControlBlock()
        AltcpTCPFunctions.shared.setup(conn, pcb: tpcb)
        return conn
    }

    /// Create a new altcp TCP PCB for IPv4.
    public static func create() -> AltcpControlBlock? {
        return createForIPType(0)
    }

    /// Create a new altcp TCP PCB for IPv6.
    public static func createIPv6() -> AltcpControlBlock? {
        return createForIPType(6)
    }

    /// Allocator function for TCP (suitable for use in AltcpAllocator).
    public static func allocate(arg: AnyObject?, ipType: UInt8) -> AltcpControlBlock? {
        return createForIPType(ipType)
    }

    /// Wrap an existing TCP PCB in an altcp PCB.
    public static func wrap(_ tpcb: TCPControlBlock) -> AltcpControlBlock? {
        let conn = AltcpControlBlock()
        AltcpTCPFunctions.shared.setup(conn, pcb: tpcb)
        return conn
    }
}

