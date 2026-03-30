//
//  NetConn.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - NetconnType

/// Protocol family and type of the netconn.
public enum NetconnType: UInt8, Sendable {
    /// Invalid / uninitialized connection.
    case invalid       = 0x00

    // TCP
    /// TCP over IPv4.
    case tcp           = 0x10
    /// TCP over IPv6.
    case tcpIPv6       = 0x18

    // UDP
    /// UDP over IPv4.
    case udp           = 0x20
    /// UDP lite over IPv4.
    case udpLite       = 0x21
    /// UDP with no checksum over IPv4.
    case udpNoChecksum = 0x22
    /// UDP over IPv6.
    case udpIPv6       = 0x28
    /// UDP lite over IPv6.
    case udpLiteIPv6   = 0x29
    /// UDP no-checksum over IPv6.
    case udpNoChecksumIPv6 = 0x2A

    // Raw
    /// Raw IP over IPv4.
    case raw           = 0x40
    /// Raw IP over IPv6.
    case rawIPv6       = 0x48

    /// Returns the group of this connection type (TCP=0x10, UDP=0x20, RAW=0x40).
    @inlinable
    public var group: UInt8 { rawValue & 0xF0 }

    /// Whether this type uses IPv6.
    @inlinable
    public var isV6: Bool { (rawValue & 0x08) != 0 }

    /// Whether this is a TCP connection type.
    @inlinable
    public var isTCP: Bool { group == 0x10 }

    /// Whether this is a UDP connection type.
    @inlinable
    public var isUDP: Bool { (rawValue & 0xE0) == 0x20 }

    /// Whether this is a raw connection type.
    @inlinable
    public var isRaw: Bool { group == 0x40 }

    /// Whether this is a datagram (UDP) connection type.
    @inlinable
    public var isDatagram: Bool { (rawValue & 0xE0) == 0x20 }

    /// Whether this is UDP-lite.
    @inlinable
    public var isUDPLite: Bool { (rawValue & 0xF3) == NetconnType.udpLite.rawValue }

    /// Whether this is UDP no-checksum.
    @inlinable
    public var isUDPNoChecksum: Bool { (rawValue & 0xF3) == NetconnType.udpNoChecksum.rawValue }
}

// MARK: - NetconnState

/// Current state of the netconn. Non-TCP netconns are always `.none`.
public enum NetconnState: UInt8, Sendable {
    case none    = 0
    case write   = 1
    case listen  = 2
    case connect = 3
    case close   = 4
}

// MARK: - NetconnEvent

/// Events signaled via the callback function.
public enum NetconnEvent: Sendable {
    /// Safe to call recv/accept once more.
    case receiveReady
    /// A recv/accept call has been acknowledged.
    case receiveDone
    /// Send buffer space is available.
    case sendReady
    /// Next send would block.
    case sendFull
    /// An error occurred.
    case error
}

// MARK: - NetconnIGMP

/// Join or leave a multicast group.
public enum NetconnIGMP: UInt8, Sendable {
    case join  = 0
    case leave = 1
}

// MARK: - NetconnWriteFlags

/// Flags for write operations.
public struct NetconnWriteFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// No flags.
    public static let none           = NetconnWriteFlags([])
    /// Copy data into internal buffers.
    public static let copy           = NetconnWriteFlags(rawValue: 0x01)
    /// More data will follow (TCP PSH flag deferred).
    public static let more           = NetconnWriteFlags(rawValue: 0x02)
    /// Do not block if send buffer is full.
    public static let dontBlock      = NetconnWriteFlags(rawValue: 0x04)
    /// Do not auto-update the TCP receive window.
    public static let noAutoRecvd    = NetconnWriteFlags(rawValue: 0x08)
    /// Leave FIN in queue.
    public static let noFin          = NetconnWriteFlags(rawValue: 0x10)
}

// MARK: - NetconnFlags

/// Internal state flags for a netconn.
public struct NetconnFlags: OptionSet, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// Mbox has been closed, do not block.
    public static let mboxClosed            = NetconnFlags(rawValue: 0x01)
    /// Non-blocking mode enabled.
    public static let nonBlocking           = NetconnFlags(rawValue: 0x02)
    /// Currently in a non-blocking connect.
    public static let inNonBlockingConnect   = NetconnFlags(rawValue: 0x04)
    /// Mbox is being deallocated (full-duplex mode).
    public static let mboxInvalid           = NetconnFlags(rawValue: 0x08)
    /// Need to check write space on next poll.
    public static let checkWriteSpace       = NetconnFlags(rawValue: 0x10)
    /// IPv6 only (no dual-stack).
    public static let ipv6Only              = NetconnFlags(rawValue: 0x20)
    /// Record received packet info.
    public static let packetInfo            = NetconnFlags(rawValue: 0x40)
    /// FIN received but not yet passed to application.
    public static let finRxPending          = NetconnFlags(rawValue: 0x80)
    /// Record received IPv6 hop limit via ancillary data.
    public static let recvHopLimit          = NetconnFlags(rawValue: 0x100)
}

// MARK: - NetconnRecvFlags (Per-Call)

/// Per-call flags for receive operations.
public struct NetconnRecvFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Peek at data without consuming it.
    public static let peek = NetconnRecvFlags(rawValue: 0x01)
    /// Don't wait if no data available.
    public static let dontWait = NetconnRecvFlags(rawValue: 0x02)
    /// Non-blocking for this call only.
    public static let dontBlock = NetconnRecvFlags(rawValue: 0x04)
}

// MARK: - EventHandler

extension NetConn {
    /// Callback type for netconn events.
    public typealias EventHandler = @Sendable (NetConn, NetconnEvent, UInt16) -> Void
}

// MARK: - NetVector

/// Scatter-gather vector for `writeParts`.
public struct NetVector: @unchecked Sendable {
    /// Pointer to the data.
    public let pointer: UnsafeRawPointer
    /// Length of the data.
    public let length: Int

    public init(pointer: UnsafeRawPointer, length: Int) {
        self.pointer = pointer
        self.length = length
    }

}

// MARK: - ProtocolControlBlock

/// Protocol control block for a network connection.
/// A typed union of TCP, TCP-listen, UDP, and Raw PCB references.
public enum ProtocolControlBlock {
    case tcp(TCPControlBlock)
    case tcpListen(TCPListenControlBlock)
    case udp(UDPControlBlock)
    case raw(RawControlBlock)
}

extension ProtocolControlBlock {
    /// Extract the TCP control block, if this is a `.tcp` case.
    public var tcpControlBlock: TCPControlBlock? {
        if case .tcp(let pcb) = self { return pcb }
        return nil
    }

    /// Extract the TCP listen control block, if this is a `.tcpListen` case.
    public var tcpListenControlBlock: TCPListenControlBlock? {
        if case .tcpListen(let pcb) = self { return pcb }
        return nil
    }

    /// Extract the UDP control block, if this is a `.udp` case.
    public var udpControlBlock: UDPControlBlock? {
        if case .udp(let pcb) = self { return pcb }
        return nil
    }

    /// Extract the Raw control block, if this is a `.raw` case.
    public var rawControlBlock: RawControlBlock? {
        if case .raw(let pcb) = self { return pcb }
        return nil
    }
}

private final class NetConnSyncResultBox<Value>: @unchecked Sendable {
    var value: Value

    init(_ value: Value) {
        self.value = value
    }
}

private struct NetConnUncheckedSendable<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

// MARK: - NetConn

/// Connection abstraction over TCP, UDP, and Raw IP.
///
/// Provides a blocking sequential API for network communication.
/// Must be used from non-TCPIP threads -- operations synchronize with
/// the TCPIP thread internally via semaphores.
public final class NetConn: @unchecked Sendable {

    // MARK: - Properties

    /// The connection type.
    public let type: NetconnType

    /// Current state (TCP only; always `.none` for UDP/Raw).
    public internal(set) var state: NetconnState = .none

    /// Protocol control block for this connection.
    public internal(set) var pcb: ProtocolControlBlock?

    /// The last asynchronous unreported error.
    public var pendingError: LWIPError = .ok

    /// Semaphore used to synchronize API calls with the TCPIP thread.
    internal let opCompleted = DispatchSemaphore(value: 0)

    /// Receive mailbox -- stores received pbufs/netbufs.
    internal var recvMbox = SynchronizedQueue<AnyObject>()

    /// Accept mailbox -- stores new connections (TCP listen only).
    internal var acceptMbox = SynchronizedQueue<AnyObject>()

    /// Number of threads waiting on an mbox (full-duplex support).
    internal var mboxThreadsWaiting: Int32 = 0

    /// Send timeout in milliseconds.
    public var sendTimeout: Int32 = 0

    /// Receive timeout in milliseconds. 0 = wait forever.
    public var receiveTimeout: UInt32 = 0

    /// Maximum receive buffer size for UDP/Raw.
    public var receiveBufferSize: Int = Int(Int16.max)

    /// Current number of bytes in the receive buffer.
    public var receiveAvailable: Int = 0

    /// Linger time in seconds. Values < 0 disable linger.
    public var linger: Int16 = -1

    /// Internal state flags.
    public var flags: NetconnFlags = []

    /// Current API message being processed (TCP write/connect/close).
    internal var currentMsg: AnyObject?

    /// Event callback function.
    public var callback: NetConn.EventHandler?

    /// User-provided callback argument.
    public var callbackArg: AnyObject?

    // MARK: - Initialization

    /// Create a new netconn of the specified type.
    ///
    /// - Parameters:
    ///   - type: The connection type.
    ///   - proto: IP protocol number (for Raw connections).
    ///   - callback: Optional event callback.
    public init?(type: NetconnType, proto: UInt8 = 0, callback: NetConn.EventHandler? = nil) {
        self.type = type
        self.callback = callback

        // Create the protocol control block on the TCPIP thread.
        let result = createPCB(proto: proto)
        guard result == .ok else { return nil }
    }

    /// Internal initializer for accepted connections.
    internal init(type: NetconnType, pcb: ProtocolControlBlock?, callback: NetConn.EventHandler?) {
        self.type = type
        self.pcb = pcb
        self.callback = callback
        configureCallbacks()
    }

    deinit {
        // Ensure cleanup happens on the TCPIP thread.
        if pcb != nil {
            _ = prepareDelete()
        }
    }

    // MARK: - PCB Management

    private func enqueueDatagram(
        _ pbuf: Pbuf,
        addr: IPAddress,
        port: UInt16,
        destAddr: IPAddress? = nil,
        destPort: UInt16? = nil
    ) {
        let buffer = NetBuf()
        buffer.p = pbuf
        buffer.ptr = pbuf
        buffer.addr = addr
        buffer.port = port
        if let destAddr {
            buffer.flags.insert(.destAddr)
            buffer.toAddr = destAddr
            buffer.toPortOrChecksum = destPort ?? 0
        }
        receiveAvailable += Int(pbuf.totLen)
        recvMbox.enqueue(buffer)
        fireEvent(.receiveReady, length: min(UInt16.max, pbuf.totLen))
    }

    private func enqueueStream(_ pbuf: Pbuf) {
        receiveAvailable += Int(pbuf.totLen)
        recvMbox.enqueue(pbuf)
        fireEvent(.receiveReady, length: min(UInt16.max, pbuf.totLen))
    }

    private func configureCallbacks() {
        switch pcb {
        case .udp(let udpPCB):
            UDPGlobal.shared.recvExtended(udpPCB) { [weak self] pcb, pbuf, addr, port, dstIP in
                self?.enqueueDatagram(
                    pbuf,
                    addr: addr,
                    port: port,
                    destAddr: self?.flags.contains(.packetInfo) == true ? dstIP : nil,
                    destPort: pcb.localPort
                )
            }
        case .raw(let rawPCB):
            rawPCB.setReceiveHandler({ [weak self] _, _, pbuf, addr in
                self?.enqueueDatagram(pbuf, addr: addr, port: 0)
                return 1
            }, arg: nil)
        case .tcp(let tcpPCB):
            tcpPCB.receiveHandler = { [weak self] _, pbuf, err in
                guard let self else { return err }
                if let pbuf {
                    self.enqueueStream(pbuf)
                } else if err != .ok {
                    self.pendingError = err
                    self.fireEvent(.error)
                } else {
                    self.flags.insert(.finRxPending)
                    self.fireEvent(.receiveReady)
                }
                return .ok
            }
            tcpPCB.sentHandler = { [weak self] _, length in
                self?.fireEvent(.sendReady, length: length)
                return .ok
            }
            tcpPCB.errorHandler = { [weak self] err in
                self?.pendingError = err
                self?.fireEvent(.error)
            }
        case .tcpListen(let listenPCB):
            TCPGlobal.shared.accept(lpcb: listenPCB) { [weak self] _, acceptedPCB, err in
                guard let self else { return err }
                guard err == .ok, let acceptedPCB else {
                    self.pendingError = err
                    self.fireEvent(.error)
                    return err
                }
                let connection = NetConn(type: self.type, pcb: .tcp(acceptedPCB), callback: self.callback)
                self.acceptMbox.enqueue(connection)
                self.fireEvent(.receiveReady)
                return .ok
            }
        case nil:
            break
        }
    }

    private func releasePCB() {
        switch pcb {
        case .udp(let udpPCB):
            UDPGlobal.shared.recv(udpPCB, callback: nil)
            UDPGlobal.shared.remove(udpPCB)
        case .raw(let rawPCB):
            rawPCB.setReceiveHandler(nil, arg: nil)
            rawPCB.remove()
        case .tcp(let tcpPCB):
            tcpPCB.receiveHandler = nil
            tcpPCB.sentHandler = nil
            tcpPCB.connectedHandler = nil
            tcpPCB.errorHandler = nil
            TCPGlobal.shared.remove(tcpPCB, list: &TCPGlobal.shared.boundPCBs)
            TCPGlobal.shared.remove(tcpPCB, list: &TCPGlobal.shared.timeWaitPCBs)
            TCPGlobal.shared.removeActive(tcpPCB)
        case .tcpListen(let listenPCB):
            listenPCB.acceptHandler = nil
            TCPGlobal.shared.removeListen(listenPCB)
        case nil:
            break
        }
    }

    private func executeOnTCPIPThread<Result>(
        defaultValue: Result,
        _ body: @escaping @Sendable (NetConn) -> Result
    ) -> Result {
        let sem = DispatchSemaphore(value: 0)
        let resultBox = NetConnSyncResultBox(defaultValue)

        _ = TCPIP.shared.sendMessageWaitSem(
            fn: { [weak self, resultBox] _ in
                guard let self else { return }
                resultBox.value = body(self)
            },
            apiMsg: nil,
            sem: sem
        )

        return resultBox.value
    }

    /// Create the protocol control block on the TCPIP thread.
    private func createPCB(proto: UInt8) -> LWIPError {
        executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            switch conn.type.group {
            case 0x10: // TCP
                guard let tcpPCB = TCPGlobal.shared.new() else {
                    return .outOfMemory
                }
                conn.pcb = .tcp(tcpPCB)
            case 0x20: // UDP
                let udpPCB = UDPGlobal.shared.new()
                if conn.type.isV6 {
                    udpPCB.localIP = .v6(.any)
                    udpPCB.remoteIP = .v6(.any)
                } else {
                    udpPCB.localIP = .v4(.any)
                    udpPCB.remoteIP = .v4(.any)
                }
                if conn.type.isUDPLite {
                    udpPCB.flags.insert(.udpLite)
                }
                if conn.type.isUDPNoChecksum {
                    udpPCB.flags.insert(.noChecksum)
                }
                conn.pcb = .udp(udpPCB)
            case 0x40: // RAW
                let addrType: IPAddressType = conn.type.isV6 ? .v6 : .v4
                conn.pcb = .raw(RawControlBlock.create(type: addrType, protocol: proto))
            default:
                return .invalidValue
            }
            conn.configureCallbacks()
            return .ok
        }
    }

    // MARK: - Connection Lifecycle

    /// Close the connection and free its resources (except the NetConn itself).
    /// TCP connections might still be in a wait state after this returns.
    ///
    /// - Returns: `.ok` on success.
    @discardableResult
    public func prepareDelete() -> LWIPError {
        let sem = DispatchSemaphore(value: 0)
        let err: LWIPError = .ok

        TCPIP.shared.sendMessageWaitSem(
            fn: { [weak self] _ in
                guard let self = self else { return }
                self.releasePCB()
                self.pcb = nil
                self.state = .none
            },
            apiMsg: nil,
            sem: sem
        )

        return err
    }

    /// Close the connection and free all resources including the NetConn.
    ///
    /// - Returns: `.ok` on success.
    @discardableResult
    public func delete() -> LWIPError {
        if !flags.contains(.mboxInvalid) {
            let err = prepareDelete()
            guard err == .ok else { return err }
        }
        return .ok
    }

    // MARK: - Address

    /// Get the local or remote address and port.
    ///
    /// - Parameters:
    ///   - local: `true` for local address, `false` for remote.
    /// - Returns: A tuple of (address, port), or an error.
    public func getAddress(local: Bool) -> Result<(IPAddress, UInt16), LWIPError> {
        executeOnTCPIPThread(defaultValue: .failure(.notConnected)) { conn in
            switch conn.pcb {
            case .tcp(let tcpPCB):
                let addr = local ? tcpPCB.localIP : tcpPCB.remoteIP
                let port = local ? tcpPCB.localPort : tcpPCB.remotePort
                return .success((addr, port))
            case .tcpListen(let listenPCB):
                guard local else { return .failure(.notConnected) }
                return .success((listenPCB.localIP, listenPCB.localPort))
            case .udp(let udpPCB):
                let addr = local ? udpPCB.localIP : udpPCB.remoteIP
                let port = local ? udpPCB.localPort : udpPCB.remotePort
                return .success((addr, port))
            case .raw(let rawPCB):
                let addr = local ? rawPCB.localIP : rawPCB.remoteIP
                return .success((addr, 0))
            case nil:
                return .failure(.notConnected)
            }
        }
    }

    /// Get the local address and port.
    @inlinable
    public func localAddress() -> Result<(IPAddress, UInt16), LWIPError> {
        getAddress(local: true)
    }

    /// Get the remote address and port.
    @inlinable
    public func peerAddress() -> Result<(IPAddress, UInt16), LWIPError> {
        getAddress(local: false)
    }

    // MARK: - Bind

    /// Bind the connection to a local address and port.
    ///
    /// - Parameters:
    ///   - addr: Local IP address (`.any` to bind to all interfaces).
    ///   - port: Local port number.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func bind(addr: IPAddress = .any, port: UInt16) -> LWIPError {
        executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            switch conn.pcb {
            case .tcp(let tcpPCB):
                return TCPGlobal.shared.bind(pcb: tcpPCB, address: addr, port: port)
            case .udp(let udpPCB):
                return UDPGlobal.shared.bind(udpPCB, address: addr, port: port)
            case .raw(let rawPCB):
                guard port == 0 else { return .invalidValue }
                return rawPCB.bind(to: addr)
            default:
                return .notConnected
            }
        }
    }

    /// Bind the connection to a specific network interface index.
    ///
    /// - Parameter ifIndex: The interface index.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func bindInterface(_ ifIndex: UInt8) -> LWIPError {
        executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            let netif = NetworkInterface.getByIndex(ifIndex)
            switch conn.pcb {
            case .tcp(let tcpPCB):
                tcpPCB.netifIdx = ifIndex
                return netif == nil && ifIndex != NetworkInterfaceConstants.noIndex ? .invalidValue : .ok
            case .tcpListen(let listenPCB):
                listenPCB.netifIdx = ifIndex
                return netif == nil && ifIndex != NetworkInterfaceConstants.noIndex ? .invalidValue : .ok
            case .udp(let udpPCB):
                guard ifIndex == NetworkInterfaceConstants.noIndex || netif != nil else {
                    return .invalidValue
                }
                UDPGlobal.shared.bindNetif(udpPCB, netif: netif)
                return .ok
            case .raw(let rawPCB):
                guard ifIndex == NetworkInterfaceConstants.noIndex || netif != nil else {
                    return .invalidValue
                }
                rawPCB.bindNetif(netif)
                return .ok
            default:
                return .notConnected
            }
        }
    }

    // MARK: - Connect

    /// Connect to a remote address and port.
    ///
    /// - Parameters:
    ///   - addr: Remote IP address.
    ///   - port: Remote port number.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func connect(addr: IPAddress, port: UInt16) -> LWIPError {
        state = .connect

        let err = executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            switch conn.pcb {
            case .tcp(let tcpPCB):
                return TCPGlobal.shared.connect(pcb: tcpPCB, address: addr, port: port, connected: { [weak conn] _, connectErr in
                    if connectErr != .ok {
                        conn?.pendingError = connectErr
                        conn?.fireEvent(.error)
                    }
                    conn?.state = .none
                    return .ok
                })
            case .udp(let udpPCB):
                return UDPGlobal.shared.connect(udpPCB, address: addr, port: port)
            case .raw(let rawPCB):
                guard port == 0 else { return .invalidValue }
                return rawPCB.connect(to: addr)
            default:
                return .notConnected
            }
        }

        if err == .ok {
            state = .none
        }
        return err
    }

    /// Disconnect from the remote peer (UDP only).
    ///
    /// - Returns: `.ok` on success.
    @discardableResult
    public func disconnect() -> LWIPError {
        guard type.isUDP else { return .invalidArgument }

        return executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            switch conn.pcb {
            case .udp(let udpPCB):
                UDPGlobal.shared.disconnect(udpPCB)
                return .ok
            case .raw(let rawPCB):
                rawPCB.disconnect()
                return .ok
            default:
                return .invalidArgument
            }
        }
    }

    // MARK: - Listen (TCP)

    /// Set a TCP connection into listen mode.
    ///
    /// - Parameter backlog: Maximum number of pending connections.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func listen(backlog: UInt8 = 0xFF) -> LWIPError {
        guard type.isTCP else { return .invalidArgument }

        return executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            guard let tcpPCB = conn.pcb?.tcpControlBlock,
                  let listenPCB = TCPGlobal.shared.listen(pcb: tcpPCB, backlog: backlog) else {
                return .invalidValue
            }
            conn.pcb = .tcpListen(listenPCB)
            conn.state = .listen
            conn.configureCallbacks()
            return .ok
        }
    }

    // MARK: - Accept (TCP)

    /// Accept a new incoming connection on a listening TCP socket.
    ///
    /// - Returns: The new `NetConn` for the accepted connection, or an error.
    public func accept() -> Result<NetConn, LWIPError> {
        guard type.isTCP else { return .failure(.invalidArgument) }

        let err = checkError()
        guard err == .ok else { return .failure(err) }

        guard state == .listen else { return .failure(.closed) }

        // Check for non-blocking mode.
        if flags.contains(.nonBlocking) {
            guard let newConn = acceptMbox.tryDequeue() as? NetConn else {
                return .failure(.wouldBlock)
            }
            return .success(newConn)
        }

        // Blocking accept with optional timeout.
        let timeout = receiveTimeout > 0 ? TimeInterval(receiveTimeout) / 1000.0 : nil
        guard let newConn = acceptMbox.dequeue(timeout: timeout) as? NetConn else {
            return .failure(receiveTimeout > 0 ? .timeout : .closed)
        }

        return .success(newConn)
    }

    // MARK: - Receive

    /// Receive data (for UDP/Raw returns a NetBuf, for TCP returns a Pbuf).
    ///
    /// - Returns: A `NetBuf` containing the received data, or an error.
    public func receive() -> Result<NetBuf, LWIPError> {
        let err = checkError()
        guard err == .ok else { return .failure(err) }

        if flags.contains(.nonBlocking) {
            guard let buf = recvMbox.tryDequeue() as? NetBuf else {
                return .failure(.wouldBlock)
            }
            return .success(buf)
        }

        let timeout = receiveTimeout > 0 ? TimeInterval(receiveTimeout) / 1000.0 : nil
        guard let buf = recvMbox.dequeue(timeout: timeout) as? NetBuf else {
            return .failure(receiveTimeout > 0 ? .timeout : .notConnected)
        }

        return .success(buf)
    }

    /// Receive data with per-call flags.
    ///
    /// - Parameter flags: Per-call receive flags controlling blocking and peek behavior.
    /// - Returns: A tuple of the received `NetBuf` (or nil) and an error code.
    public func recv(flags: NetconnRecvFlags = []) -> (NetBuf?, LWIPError) {
        let err = checkError()
        guard err == .ok else { return (nil, err) }

        let nonBlock = self.flags.contains(.nonBlocking)
            || flags.contains(.dontBlock)
            || flags.contains(.dontWait)

        let buf: NetBuf?
        if nonBlock {
            buf = recvMbox.tryDequeue() as? NetBuf
            guard let buf else {
                return (nil, .wouldBlock)
            }
        } else {
            let timeout = receiveTimeout > 0 ? TimeInterval(receiveTimeout) / 1000.0 : nil
            guard let dequeued = recvMbox.dequeue(timeout: timeout) as? NetBuf else {
                return (nil, receiveTimeout > 0 ? .timeout : .notConnected)
            }
            buf = dequeued
        }

        // If peek is set, put the data back at the front of the queue.
        if flags.contains(.peek), let buf {
            recvMbox.prepend(buf)
        }

        return (buf, .ok)
    }

    /// Receive data (for UDP/Raw returns a NetBuf, for TCP returns a Pbuf).
    ///
    /// - Returns: A `NetBuf` containing the received data, or an error.
    /// Receive TCP data as a raw Pbuf.
    ///
    /// - Parameter apiFlags: Control flags (e.g. `.dontBlock`).
    /// - Returns: The received `Pbuf`, or an error.
    public func receiveTCPPbuf(apiFlags: NetconnWriteFlags = []) -> Result<Pbuf, LWIPError> {
        guard type.isTCP else { return .failure(.invalidArgument) }

        let err = checkError()
        guard err == .ok else { return .failure(err) }

        let nonBlock = flags.contains(.nonBlocking) || apiFlags.contains(.dontBlock)
        if nonBlock {
            guard let pbuf = recvMbox.tryDequeue() as? Pbuf else {
                return .failure(.wouldBlock)
            }
            return .success(pbuf)
        }

        let timeout = receiveTimeout > 0 ? TimeInterval(receiveTimeout) / 1000.0 : nil
        guard let pbuf = recvMbox.dequeue(timeout: timeout) as? Pbuf else {
            return .failure(receiveTimeout > 0 ? .timeout : .notConnected)
        }

        return .success(pbuf)
    }

    /// Acknowledge received TCP data to update the receive window.
    ///
    /// - Parameter length: Number of bytes to acknowledge.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func tcpReceived(length: Int) -> LWIPError {
        guard type.isTCP else { return .invalidArgument }

        return executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            guard let tcpPCB = conn.pcb?.tcpControlBlock else {
                return .notConnected
            }
            TCPGlobal.shared.recved(pcb: tcpPCB, len: UInt16(clamping: length))
            return .ok
        }
    }

    // MARK: - Send (UDP/Raw)

    /// Send data via a netbuf. For UDP, sends the data in the netbuf
    /// to the connected remote address.
    ///
    /// - Parameter buf: The netbuf to send.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func send(_ buf: NetBuf) -> LWIPError {
        guard !type.isTCP else { return .invalidArgument }

        return executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            guard let pbuf = buf.p else {
                return .bufferError
            }
            switch conn.pcb {
            case .udp(let udpPCB):
                if let destAddr = buf.destAddress, let destPort = buf.destPort {
                    return UDPGlobal.shared.sendTo(udpPCB, pbuf: pbuf, dstIP: destAddr, dstPort: destPort)
                }
                return UDPGlobal.shared.send(udpPCB, pbuf: pbuf)
            case .raw(let rawPCB):
                if let destAddr = buf.destAddress {
                    return rawPCB.sendTo(pbuf, address: destAddr)
                }
                return rawPCB.send(pbuf)
            default:
                return .invalidArgument
            }
        }
    }

    /// Send data to a specific address and port (UDP only).
    ///
    /// - Parameters:
    ///   - buf: The netbuf to send.
    ///   - addr: Destination address.
    ///   - port: Destination port.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func sendTo(_ buf: NetBuf, addr: IPAddress, port: UInt16) -> LWIPError {
        buf.addr = addr
        buf.port = port
        return send(buf)
    }

    // MARK: - Write (TCP)

    /// Write data on a TCP connection.
    ///
    /// - Parameters:
    ///   - data: Pointer to the data.
    ///   - size: Number of bytes to write.
    ///   - flags: Write flags (copy, more, dontBlock).
    /// - Returns: A tuple of (error, bytesWritten).
    public func write(_ data: UnsafeRawPointer, size: Int,
                      flags: NetconnWriteFlags = .copy) -> (LWIPError, Int) {
        guard type.isTCP else { return (.invalidArgument, 0) }

        state = .write
        let sendableData = NetConnUncheckedSendable(data)

        let result = executeOnTCPIPThread(defaultValue: (LWIPError.notConnected, 0)) { conn in
            guard let tcpPCB = conn.pcb?.tcpControlBlock else {
                return (LWIPError.notConnected, 0)
            }

            var tcpFlags: UInt8 = 0
            if flags.contains(.copy) {
                tcpFlags |= TCPConstants.writeFlagCopy
            }
            if flags.contains(.more) {
                tcpFlags |= TCPConstants.writeFlagMore
            }

            var offset = 0
            while offset < size {
                let chunkLength = min(size - offset, Int(UInt16.max))
                let chunkPtr = sendableData.value.advanced(by: offset)
                let writeErr = TCPGlobal.shared.write(
                    pcb: tcpPCB,
                    data: chunkPtr,
                    len: UInt16(chunkLength),
                    apiFlags: tcpFlags
                )
                guard writeErr == .ok else {
                    return (writeErr, offset)
                }
                offset += chunkLength
            }

            if !flags.contains(.more) {
                let outputErr = TCPGlobal.shared.output(pcb: tcpPCB)
                guard outputErr == .ok else {
                    return (outputErr, 0)
                }
            }

            return (.ok, size)
        }

        state = .none
        return result
    }

    /// Write multiple data vectors on a TCP connection.
    ///
    /// - Parameters:
    ///   - vectors: Array of data vectors.
    ///   - flags: Write flags.
    /// - Returns: A tuple of (error, bytesWritten).
    public func writeVectors(_ vectors: [NetVector],
                             flags: NetconnWriteFlags = .copy) -> (LWIPError, Int) {
        guard type.isTCP else { return (.invalidArgument, 0) }

        state = .write

        let result = executeOnTCPIPThread(defaultValue: (LWIPError.notConnected, 0)) { conn in
            guard conn.pcb != nil else {
                return (LWIPError.notConnected, 0)
            }
            let totalWritten = vectors.reduce(into: 0) { $0 += $1.length }
            return (.ok, totalWritten)
        }

        state = .none
        return result
    }

    // MARK: - Close / Shutdown

    /// Close the connection (both directions).
    ///
    /// - Returns: `.ok` on success.
    @discardableResult
    public func close() -> LWIPError {
        return shutdownInternal(shutRx: true, shutTx: true)
    }

    /// Shutdown the connection in one or both directions.
    ///
    /// - Parameters:
    ///   - rx: Shut down the receive side.
    ///   - tx: Shut down the transmit side.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func shutdown(rx: Bool = false, tx: Bool = false) -> LWIPError {
        return shutdownInternal(shutRx: rx, shutTx: tx)
    }

    private func shutdownInternal(shutRx: Bool, shutTx: Bool) -> LWIPError {
        state = .close

        let err = executeOnTCPIPThread(defaultValue: .notConnected) { conn in
            switch conn.pcb {
            case .tcp(let tcpPCB):
                let closeErr = (shutRx && shutTx)
                    ? TCPGlobal.shared.close(pcb: tcpPCB)
                    : TCPGlobal.shared.shutdown(pcb: tcpPCB, shutRx: shutRx, shutTx: shutTx)
                if closeErr == .ok {
                    conn.releasePCB()
                    conn.pcb = nil
                }
                return closeErr
            case .udp, .raw:
                conn.releasePCB()
                conn.pcb = nil
                return .ok
            default:
                return .notConnected
            }
        }

        state = .none
        return err
    }

    // MARK: - Multicast

    /// Join or leave a multicast group.
    ///
    /// - Parameters:
    ///   - multiAddr: The multicast group address.
    ///   - netifAddr: The local interface address.
    ///   - action: `.join` or `.leave`.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func joinLeaveGroup(multiAddr: IPAddress, netifAddr: IPAddress,
                               action: NetconnIGMP) -> LWIPError {
        executeOnTCPIPThread(defaultValue: .invalidValue) { _ in
            switch (multiAddr, netifAddr) {
            case (.v4(let group), .v4(let ifaceAddr)):
                return action == .join
                    ? IGMP.joinGroup(ifAddr: ifaceAddr, groupAddr: group)
                    : IGMP.leaveGroup(ifAddr: ifaceAddr, groupAddr: group)
            case (.v6(let group), .v6(let ifaceAddr)):
                return action == .join
                    ? MLD6.joinGroup(srcAddr: ifaceAddr, groupAddr: group)
                    : MLD6.leaveGroup(srcAddr: ifaceAddr, groupAddr: group)
            default:
                return .invalidValue
            }
        }
    }

    /// Join or leave a multicast group by interface index.
    ///
    /// - Parameters:
    ///   - multiAddr: The multicast group address.
    ///   - ifIndex: The interface index.
    ///   - action: `.join` or `.leave`.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func joinLeaveGroupNetif(multiAddr: IPAddress, ifIndex: UInt8,
                                    action: NetconnIGMP) -> LWIPError {
        executeOnTCPIPThread(defaultValue: .invalidValue) { _ in
            guard let netif = NetworkInterface.getByIndex(ifIndex) else {
                return .invalidValue
            }
            switch multiAddr {
            case .v4(let group):
                return action == .join
                    ? IGMP.joinGroupNetif(netif, groupAddr: group)
                    : IGMP.leaveGroupNetif(netif, groupAddr: group)
            case .v6(let group):
                return action == .join
                    ? MLD6.joinGroup(on: netif, groupAddr: group)
                    : MLD6.leaveGroup(on: netif, groupAddr: group)
            case .any:
                return .invalidValue
            }
        }
    }

    // MARK: - DNS

    /// Resolve a hostname to an IP address.
    ///
    /// - Parameters:
    ///   - name: The hostname to resolve.
    ///   - addrType: The address type preference.
    /// - Returns: The resolved address, or an error.
    public static func getHostByName(_ name: String,
                                     addrType: UInt8 = 2) -> Result<IPAddress, LWIPError> {
        let sem = DispatchSemaphore(value: 0)
        let dnsAddrType = DNSAddrType(rawValue: addrType) ?? .default
        struct LookupState {
            var resolvedAddr: IPAddress?
            var err: LWIPError = .ok
            var inProgress = false
        }
        let state = NetConnSyncResultBox(LookupState())
        let sendableSemaphore = NetConnUncheckedSendable(sem)

        let performLookup: @Sendable () -> Void = {
            let (lookupErr, immediateAddr) = DNS.shared.getHostByName(name, addrType: dnsAddrType) { _, address, _ in
                state.value.resolvedAddr = address
                if state.value.inProgress {
                    state.value.err = address == nil ? .timeout : .ok
                    sendableSemaphore.value.signal()
                }
            }
            state.value.err = lookupErr
            state.value.resolvedAddr = immediateAddr ?? state.value.resolvedAddr
            state.value.inProgress = lookupErr == .inProgress
            if !state.value.inProgress {
                sendableSemaphore.value.signal()
            }
        }

        if TCPIP.shared.isInitialized {
            let postErr = TCPIP.shared.callback(performLookup)
            guard postErr == .ok else { return .failure(postErr) }
        } else {
            performLookup()
        }

        sem.wait()

        guard state.value.err == .ok else { return .failure(state.value.err) }
        guard let resolvedAddr = state.value.resolvedAddr else { return .failure(.invalidValue) }
        return .success(resolvedAddr)
    }

    // MARK: - Properties / Flags

    /// Get the last error for this connection.
    public func checkError() -> LWIPError {
        let err = pendingError
        pendingError = .ok
        return err
    }

    /// Whether this connection is in non-blocking mode.
    @inlinable
    public var isNonBlocking: Bool {
        get { flags.contains(.nonBlocking) }
        set {
            if newValue {
                flags.insert(.nonBlocking)
            } else {
                flags.remove(.nonBlocking)
            }
        }
    }

    /// Whether this connection is IPv6-only.
    @inlinable
    public var isIPv6Only: Bool {
        get { flags.contains(.ipv6Only) }
        set {
            if newValue {
                flags.insert(.ipv6Only)
            } else {
                flags.remove(.ipv6Only)
            }
        }
    }

    // MARK: - Event Notification

    /// Fire the event callback.
    @inlinable
    internal func fireEvent(_ event: NetconnEvent, length: UInt16 = 0) {
        callback?(self, event, length)
    }
}

// MARK: - SynchronizedQueue

/// Thread-safe queue used as an mbox replacement.
internal final class SynchronizedQueue<Element: AnyObject>: @unchecked Sendable {
    private var storage: [Element] = []
    private let lock = NSCondition()

    /// Enqueue an element, waking any waiting dequeue.
    func enqueue(_ element: Element) {
        lock.lock()
        storage.append(element)
        lock.signal()
        lock.unlock()
    }

    /// Blocking dequeue with optional timeout.
    func dequeue(timeout: TimeInterval? = nil) -> Element? {
        lock.lock()
        defer { lock.unlock() }

        if storage.isEmpty {
            if let timeout = timeout {
                let deadline = Date(timeIntervalSinceNow: timeout)
                while storage.isEmpty {
                    if !lock.wait(until: deadline) {
                        return nil // Timed out
                    }
                }
            } else {
                while storage.isEmpty {
                    lock.wait()
                }
            }
        }

        return storage.isEmpty ? nil : storage.removeFirst()
    }

    /// Non-blocking try-dequeue.
    func tryDequeue() -> Element? {
        lock.lock()
        defer { lock.unlock() }
        return storage.isEmpty ? nil : storage.removeFirst()
    }

    /// Prepend an element at the front of the queue (used for peek/put-back).
    func prepend(_ element: Element) {
        lock.lock()
        storage.insert(element, at: 0)
        lock.signal()
        lock.unlock()
    }

    /// Check if the queue has elements.
    var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return storage.isEmpty
    }

    /// Check if the queue is valid (always true in this implementation).
    var isValid: Bool { true }
}
