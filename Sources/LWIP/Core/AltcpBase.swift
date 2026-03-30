//
//  AltcpBase.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Callback Type Aliases

extension AltcpControlBlock {
    /// Accept callback: called when a new connection is accepted on a listening PCB.
    public typealias AcceptHandler = (_ arg: AnyObject?, _ newConn: AltcpControlBlock, _ err: LWIPError) -> LWIPError

    /// Connected callback: called when a connection is established.
    public typealias ConnectedHandler = (_ arg: AnyObject?, _ conn: AltcpControlBlock, _ err: LWIPError) -> LWIPError

    /// Receive callback: called when data is received.
    public typealias ReceiveHandler = (_ arg: AnyObject?, _ conn: AltcpControlBlock, _ pbuf: Pbuf?, _ err: LWIPError) -> LWIPError

    /// Sent callback: called when previously sent data has been acknowledged.
    public typealias SentHandler = (_ arg: AnyObject?, _ conn: AltcpControlBlock, _ length: UInt16) -> LWIPError

    /// Poll callback: called periodically.
    public typealias PollHandler = (_ arg: AnyObject?, _ conn: AltcpControlBlock) -> LWIPError

    /// Error callback: called on fatal errors.
    public typealias ErrorHandler = (_ arg: AnyObject?, _ err: LWIPError) -> Void

    /// Allocator function: creates a new altcp PCB.
    public typealias AllocatorFunction = (_ arg: AnyObject?, _ ipType: UInt8) -> AltcpControlBlock?
}

// MARK: - AltcpFunctions Protocol

/// Protocol defining the virtual function table for altcp layers.
///
/// Each altcp layer (TCP, TLS, proxy) implements this protocol.
/// The AltcpControlBlock delegates all operations through this interface.
public protocol AltcpFunctions: AnyObject {

    func setPoll(_ conn: AltcpControlBlock, interval: UInt8)
    func recved(_ conn: AltcpControlBlock, len: UInt16)
    func bind(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16) -> LWIPError
    func connect(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16, connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError
    func listen(_ conn: AltcpControlBlock, backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock?
    func abort(_ conn: AltcpControlBlock)
    func close(_ conn: AltcpControlBlock) -> LWIPError
    func shutdown(_ conn: AltcpControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError
    func write(_ conn: AltcpControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError
    func output(_ conn: AltcpControlBlock) -> LWIPError
    func mss(_ conn: AltcpControlBlock) -> UInt16
    func sndbuf(_ conn: AltcpControlBlock) -> UInt16
    func sndqueuelen(_ conn: AltcpControlBlock) -> UInt16
    func nagleDisable(_ conn: AltcpControlBlock)
    func nagleEnable(_ conn: AltcpControlBlock)
    func nagleDisabled(_ conn: AltcpControlBlock) -> Bool
    func setPrio(_ conn: AltcpControlBlock, prio: UInt8)
    func dealloc(_ conn: AltcpControlBlock)
    func getAddrInfo(_ conn: AltcpControlBlock, local: Bool) -> (IPAddress?, UInt16)?
    func getIP(_ conn: AltcpControlBlock, local: Bool) -> IPAddress?
    func getPort(_ conn: AltcpControlBlock, local: Bool) -> UInt16
    func keepaliveDisable(_ conn: AltcpControlBlock)
    func keepaliveEnable(_ conn: AltcpControlBlock, idle: UInt32, interval: UInt32, count: UInt32)
}

/// Default implementations for AltcpFunctions that delegate to inner_conn
public extension AltcpFunctions {
    func keepaliveDisable(_ conn: AltcpControlBlock) {}
    func keepaliveEnable(_ conn: AltcpControlBlock, idle: UInt32, interval: UInt32, count: UInt32) {}
}

// MARK: - AltcpAllocator

/// An altcp allocator combines an allocation function with its argument.
/// Used by altcpNew to create PCBs for the appropriate protocol layer.
public struct AltcpAllocator {
    /// Allocator function
    public var alloc: AltcpControlBlock.AllocatorFunction
    /// Argument passed to the allocator
    public var arg: AnyObject?

    public init(alloc: @escaping AltcpControlBlock.AllocatorFunction, arg: AnyObject? = nil) {
        self.alloc = alloc
        self.arg = arg
    }
}

// MARK: - AltcpControlBlock

/// Application Layered TCP Protocol Control Block.
///
/// This is the central abstraction for altcp. It holds:
/// - A reference to the layer's function table (fns)
/// - An optional inner connection (for layered protocols like TLS-over-TCP)
/// - Application callbacks (accept, recv, sent, poll, err)
/// - Application argument
/// - Layer-specific state
public final class AltcpControlBlock: @unchecked Sendable {
    /// Function table for this layer
    public var fns: AltcpFunctions?

    /// Inner (lower-layer) connection, e.g. TCP under TLS
    public var innerConn: AltcpControlBlock?

    /// Application argument
    public var arg: AnyObject?

    /// Layer-specific state
    public var state: AnyObject?

    // Application callbacks
    public var acceptFn: AltcpControlBlock.AcceptHandler?
    public var connectedFn: AltcpControlBlock.ConnectedHandler?
    public var recvFn: AltcpControlBlock.ReceiveHandler?
    public var sentFn: AltcpControlBlock.SentHandler?
    public var pollFn: AltcpControlBlock.PollHandler?
    public var errFn: AltcpControlBlock.ErrorHandler?

    /// Poll interval
    public var pollInterval: UInt8 = 0

    public init() {}

    // MARK: - API Functions

    /// Set the application argument
    public func setArg(_ arg: AnyObject?) {
        self.arg = arg
    }

    /// Set the accept callback
    public func setAccept(_ accept: AltcpControlBlock.AcceptHandler?) {
        self.acceptFn = accept
    }

    /// Set the receive callback
    public func setRecv(_ recv: AltcpControlBlock.ReceiveHandler?) {
        self.recvFn = recv
    }

    /// Set the sent callback
    public func setSent(_ sent: AltcpControlBlock.SentHandler?) {
        self.sentFn = sent
    }

    /// Set the poll callback and interval
    public func setPoll(_ poll: AltcpControlBlock.PollHandler?, interval: UInt8) {
        self.pollFn = poll
        self.pollInterval = interval
        fns?.setPoll(self, interval: interval)
    }

    /// Set the error callback
    public func setErr(_ err: AltcpControlBlock.ErrorHandler?) {
        self.errFn = err
    }

    /// Notify that data has been received (acknowledge `len` bytes)
    public func recved(_ len: UInt16) {
        fns?.recved(self, len: len)
    }

    /// Bind to a local IP address and port
    public func bind(ipaddr: IPAddress? = nil, port: UInt16) -> LWIPError {
        return fns?.bind(self, ipaddr: ipaddr, port: port) ?? .invalidValue
    }

    /// Initiate a connection
    public func connect(ipaddr: IPAddress?, port: UInt16, connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError {
        return fns?.connect(self, ipaddr: ipaddr, port: port, connected: connected) ?? .invalidValue
    }

    /// Start listening for connections
    public func listen(backlog: UInt8 = 255) -> AltcpControlBlock? {
        var err: LWIPError? = nil
        return fns?.listen(self, backlog: backlog, err: &err)
    }

    /// Listen with error reporting
    public func listen(backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock? {
        return fns?.listen(self, backlog: backlog, err: &err)
    }

    /// Abort the connection
    public func abort() {
        fns?.abort(self)
    }

    /// Close the connection gracefully
    @discardableResult
    public func close() -> LWIPError {
        return fns?.close(self) ?? .invalidValue
    }

    /// Shutdown one or both directions
    public func shutdown(rx: Bool, tx: Bool) -> LWIPError {
        return fns?.shutdown(self, shutRx: rx, shutTx: tx) ?? .invalidValue
    }

    /// Write data to the connection
    public func write(_ data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8 = 0) -> LWIPError {
        return fns?.write(self, data: data, len: len, apiFlags: apiFlags) ?? .invalidValue
    }

    /// Trigger sending of queued data
    @discardableResult
    public func output() -> LWIPError {
        return fns?.output(self) ?? .invalidValue
    }

    /// Get the maximum segment size
    public func mss() -> UInt16 {
        return fns?.mss(self) ?? 0
    }

    /// Get the send buffer size
    public func sndbuf() -> UInt16 {
        return fns?.sndbuf(self) ?? 0
    }

    /// Get the send queue length
    public func sndqueuelen() -> UInt16 {
        return fns?.sndqueuelen(self) ?? 0
    }

    /// Disable the Nagle algorithm
    public func nagleDisable() {
        fns?.nagleDisable(self)
    }

    /// Enable the Nagle algorithm
    public func nagleEnable() {
        fns?.nagleEnable(self)
    }

    /// Check if Nagle is disabled
    public func nagleDisabled() -> Bool {
        return fns?.nagleDisabled(self) ?? false
    }

    /// Set priority
    public func setPrio(_ prio: UInt8) {
        fns?.setPrio(self, prio: prio)
    }

    /// Get address info (IP and port) for local or remote end
    public func getAddrInfo(local: Bool) -> (IPAddress?, UInt16)? {
        return fns?.getAddrInfo(self, local: local)
    }

    /// Get IP address
    public func getIP(local: Bool) -> IPAddress? {
        return fns?.getIP(self, local: local)
    }

    /// Get port number
    public func getPort(local: Bool) -> UInt16 {
        return fns?.getPort(self, local: local) ?? 0
    }

    /// Disable TCP keepalive
    public func keepaliveDisable() {
        fns?.keepaliveDisable(self)
    }

    /// Enable TCP keepalive
    public func keepaliveEnable(idle: UInt32, interval: UInt32, count: UInt32) {
        fns?.keepaliveEnable(self, idle: idle, interval: interval, count: count)
    }

    /// Free this PCB and call dealloc
    public func free() {
        fns?.dealloc(self)
        fns = nil
        innerConn = nil
        state = nil
    }
}

// MARK: - Default Layer Implementations

/// Default implementations that delegate to the inner connection.
/// Useful for building intermediate layers that only override some functions.
public final class AltcpDefaultFunctions: AltcpFunctions {

    public init() {}

    public func setPoll(_ conn: AltcpControlBlock, interval: UInt8) {
        conn.innerConn?.setPoll(conn.pollFn, interval: interval)
    }

    public func recved(_ conn: AltcpControlBlock, len: UInt16) {
        conn.innerConn?.recved(len)
    }

    public func bind(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16) -> LWIPError {
        return conn.innerConn?.bind(ipaddr: ipaddr, port: port) ?? .invalidValue
    }

    public func connect(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16, connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError {
        return conn.innerConn?.connect(ipaddr: ipaddr, port: port, connected: connected) ?? .invalidValue
    }

    public func listen(_ conn: AltcpControlBlock, backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock? {
        return conn.innerConn?.listen(backlog: backlog, err: &err)
    }

    public func abort(_ conn: AltcpControlBlock) {
        conn.innerConn?.abort()
    }

    public func close(_ conn: AltcpControlBlock) -> LWIPError {
        return conn.innerConn?.close() ?? .invalidValue
    }

    public func shutdown(_ conn: AltcpControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError {
        if shutRx && shutTx {
            return close(conn)
        }
        return conn.innerConn?.shutdown(rx: shutRx, tx: shutTx) ?? .invalidValue
    }

    public func write(_ conn: AltcpControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError {
        return conn.innerConn?.write(data, len: len, apiFlags: apiFlags) ?? .invalidValue
    }

    public func output(_ conn: AltcpControlBlock) -> LWIPError {
        return conn.innerConn?.output() ?? .invalidValue
    }

    public func mss(_ conn: AltcpControlBlock) -> UInt16 {
        return conn.innerConn?.mss() ?? 0
    }

    public func sndbuf(_ conn: AltcpControlBlock) -> UInt16 {
        return conn.innerConn?.sndbuf() ?? 0
    }

    public func sndqueuelen(_ conn: AltcpControlBlock) -> UInt16 {
        return conn.innerConn?.sndqueuelen() ?? 0
    }

    public func nagleDisable(_ conn: AltcpControlBlock) {
        conn.innerConn?.nagleDisable()
    }

    public func nagleEnable(_ conn: AltcpControlBlock) {
        conn.innerConn?.nagleEnable()
    }

    public func nagleDisabled(_ conn: AltcpControlBlock) -> Bool {
        return conn.innerConn?.nagleDisabled() ?? false
    }

    public func setPrio(_ conn: AltcpControlBlock, prio: UInt8) {
        conn.innerConn?.setPrio(prio)
    }

    public func dealloc(_ conn: AltcpControlBlock) {
        // Nothing to do by default
    }

    public func getAddrInfo(_ conn: AltcpControlBlock, local: Bool) -> (IPAddress?, UInt16)? {
        return conn.innerConn?.getAddrInfo(local: local)
    }

    public func getIP(_ conn: AltcpControlBlock, local: Bool) -> IPAddress? {
        return conn.innerConn?.getIP(local: local)
    }

    public func getPort(_ conn: AltcpControlBlock, local: Bool) -> UInt16 {
        return conn.innerConn?.getPort(local: local) ?? 0
    }

    public func keepaliveDisable(_ conn: AltcpControlBlock) {
        conn.innerConn?.keepaliveDisable()
    }

    public func keepaliveEnable(_ conn: AltcpControlBlock, idle: UInt32, interval: UInt32, count: UInt32) {
        conn.innerConn?.keepaliveEnable(idle: idle, interval: interval, count: count)
    }
}

// MARK: - Factory Functions

extension AltcpControlBlock {
    /// Create a new altcp PCB using an allocator.
    /// If no allocator is provided, creates a plain TCP connection.
    public static func create(allocator: AltcpAllocator? = nil, ipType: UInt8 = 0) -> AltcpControlBlock? {
        guard let allocator = allocator else {
            return AltcpTCPFunctions.createForIPType(ipType)
        }
        return allocator.alloc(allocator.arg, ipType)
    }

    /// Create a new IPv4 altcp PCB.
    public static func createIPv4(allocator: AltcpAllocator? = nil) -> AltcpControlBlock? {
        return create(allocator: allocator, ipType: 0) // IPADDR_TYPE_V4
    }

    /// Create a new IPv6 altcp PCB.
    public static func createIPv6(allocator: AltcpAllocator? = nil) -> AltcpControlBlock? {
        return create(allocator: allocator, ipType: 6) // IPADDR_TYPE_V6
    }
}

