//
//  Sockets.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Socket Constants

/// Address families.
public enum AddressFamily: Int32, Sendable {
    case unspec = 0
    case inet   = 2
    case inet6  = 10
}

/// Socket types.
public enum SocketType: Int32, Sendable {
    case stream = 1    // TCP
    case dgram  = 2    // UDP
    case raw    = 3    // Raw IP
}

/// IP protocols.
public enum IPProtocol: Int32, Sendable {
    case ip       = 0
    case icmp     = 1
    case tcp      = 6
    case udp      = 17
    case ipv6     = 41
    case icmpv6   = 58
    case udpLite  = 136
    case raw      = 255
}

/// Shutdown modes.
public enum ShutdownMode: Int32, Sendable {
    case read      = 0
    case write     = 1
    case readWrite = 2
}

/// Socket option levels.
public enum SocketLevel: Int32, Sendable {
    case socket           = 0xFFF
    case ipProtocolIP     = 0
    case ipProtocolTCP    = 6
    case ipProtocolIPv6   = 41
    case ipProtocolUDPLite = 136
}

/// Socket options at SOL_SOCKET level.
public enum SocketOption: Int32, Sendable {
    case acceptConn     = 0x0002
    case reuseAddr      = 0x0004
    case keepAlive      = 0x0008
    case broadcast      = 0x0020
    case linger         = 0x0080
    case sendBuffer     = 0x1001
    case receiveBuffer  = 0x1002
    case sendTimeout    = 0x1005
    case receiveTimeout = 0x1006
    case error          = 0x1007
    case type           = 0x1008
    case noChecksum     = 0x100A
    case bindToDevice   = 0x100B
}

/// IP-level socket options (IPPROTO_IP).
public enum IPSocketOption: Int32, Sendable {
    case typeOfService    = 1    // IP_TOS
    case timeToLive       = 2    // IP_TTL
    case packetInfo       = 8
    case multicastTTL     = 5
    case multicastIF      = 6
    case multicastLoop    = 7
    case addMembership    = 3
    case dropMembership   = 4
}

/// IPv6-level socket options (IPPROTO_IPV6).
public enum IPv6SocketOption: Int32, Sendable {
    case checksum         = 7
    case v6Only           = 27
    case joinGroup        = 12
    case leaveGroup       = 13
    case multicastHops    = 18
    case multicastIF      = 17
    case multicastLoop    = 19
    case packetInfo       = 50    // IPV6_PKTINFO (receive destination addr)
    case recvHopLimit     = 51    // IPV6_RECVHOPLIMIT (receive hop limit)
    case trafficClass     = 67    // IPV6_TCLASS (traffic class / DSCP)
}

// MARK: - Multicast Request Structures

/// IPv4 multicast group membership request, equivalent to `struct ip_mreq`.
public struct IPMulticastRequest: Sendable {
    /// IPv4 multicast group address.
    public var multicastAddress: IPv4Address
    /// Local interface address (use `.any` for default).
    public var interfaceAddress: IPv4Address

    public init(multicastAddress: IPv4Address, interfaceAddress: IPv4Address = .any) {
        self.multicastAddress = multicastAddress
        self.interfaceAddress = interfaceAddress
    }
}

/// IPv6 multicast group membership request, equivalent to `struct ipv6_mreq`.
public struct IPv6MulticastRequest: Sendable {
    /// IPv6 multicast group address.
    public var multicastAddress: IPv6Address
    /// Interface index (0 = default).
    public var interfaceIndex: UInt32

    public init(multicastAddress: IPv6Address, interfaceIndex: UInt32 = 0) {
        self.multicastAddress = multicastAddress
        self.interfaceIndex = interfaceIndex
    }
}

// MARK: - fcntl / ioctl Constants

/// File control commands for ``LWIPSocket/fcntl(_:cmd:val:)``.
public enum FileControlCommand {
    /// Get file status flags.
    public static let getFlags: Int32 = 3   // F_GETFL
    /// Set file status flags.
    public static let setFlags: Int32 = 4   // F_SETFL
}

/// File status flags used with ``FileControlCommand``.
public enum FileStatusFlags {
    /// Non-blocking I/O.
    public static let nonBlock: Int32  = 1  // O_NONBLOCK
    /// Open for reading only.
    public static let readOnly: Int32  = 2  // O_RDONLY
    /// Open for writing only.
    public static let writeOnly: Int32 = 4  // O_WRONLY
    /// Open for reading and writing.
    public static let readWrite: Int32 = 6  // O_RDWR  (O_RDONLY | O_WRONLY)
}

/// I/O control commands for ``LWIPSocket/ioctl(_:cmd:value:)``.
public enum IOControlCommand {
    /// Get number of bytes available to read.
    public static let fionRead: Int = 0x4004_667F
    /// Set/clear non-blocking I/O.
    public static let fionBIO: Int  = Int(bitPattern: UInt(0x8004_667E))
}

/// TCP-level socket options (IPPROTO_TCP).
public enum TCPSocketOption: Int32, Sendable {
    case noDelay      = 0x01
    case keepIdle     = 0x03
    case keepInterval = 0x04
    case keepCount    = 0x05
}

/// UDP-Lite socket options (IPPROTO_UDPLITE).
public enum UDPLiteSocketOption: Int32, Sendable {
    /// Sender checksum coverage length.
    case sendChecksumCoverage = 10   // UDPLITE_SEND_CSCOV
    /// Receiver minimum checksum coverage length.
    case recvChecksumCoverage = 11   // UDPLITE_RECV_CSCOV
}

/// Message flags for send/recv.
public struct MessageFlags: OptionSet, Sendable {
    public let rawValue: Int32
    public init(rawValue: Int32) { self.rawValue = rawValue }

    /// Peek at incoming message without consuming.
    public static let peek      = MessageFlags(rawValue: 0x01)
    /// Wait for full amount (unimplemented).
    public static let waitAll   = MessageFlags(rawValue: 0x02)
    /// Non-blocking for this operation only.
    public static let dontWait  = MessageFlags(rawValue: 0x08)
    /// More data to send (TCP_CORK style).
    public static let more      = MessageFlags(rawValue: 0x10)
    /// Do not send SIGPIPE (unimplemented).
    public static let noSignal  = MessageFlags(rawValue: 0x20)
    /// Message was truncated (set on output by receiveMessage for datagrams).
    public static let truncated = MessageFlags(rawValue: 0x04)
}

/// Poll event flags.
public struct PollEvents: OptionSet, Sendable {
    public let rawValue: Int16
    public init(rawValue: Int16) { self.rawValue = rawValue }

    public static let `in`    = PollEvents(rawValue: 0x01)
    public static let out     = PollEvents(rawValue: 0x02)
    public static let err     = PollEvents(rawValue: 0x04)
    public static let invalid = PollEvents(rawValue: 0x08)
    public static let hup     = PollEvents(rawValue: 0x200)
}

/// Poll file descriptor.
public struct PollFD: Sendable {
    public var fd: Int32
    public var events: PollEvents
    public var revents: PollEvents

    public init(fd: Int32, events: PollEvents) {
        self.fd = fd
        self.events = events
        self.revents = []
    }
}

// MARK: - IOVector

/// Scatter/gather I/O vector, equivalent to POSIX `struct iovec`.
public struct IOVector {
    /// Base address of the buffer.
    public var base: UnsafeMutableRawPointer
    /// Length of the buffer in bytes.
    public var length: Int

    public init(base: UnsafeMutableRawPointer, length: Int) {
        self.base = base
        self.length = length
    }
}

// MARK: - MessageHeader

/// Message header for `sendMessage`/`receiveMessage`, equivalent to POSIX `struct msghdr`.
public struct MessageHeader {
    /// Optional destination/source address.
    public var name: SockAddr?
    /// Scatter/gather I/O vector array.
    public var iov: [IOVector]
    /// Optional ancillary (control) data.
    public var control: [UInt8]?
    /// Output flags set by `receiveMessage`.
    public var flags: MessageFlags

    public init(name: SockAddr? = nil,
                iov: [IOVector] = [],
                control: [UInt8]? = nil,
                flags: MessageFlags = []) {
        self.name = name
        self.iov = iov
        self.control = control
        self.flags = flags
    }
}

// MARK: - SocketAddress

/// IPv4 socket address.
public struct SockAddrIn: Sendable {
    public var family: AddressFamily = .inet
    public var port: UInt16 = 0
    public var addr: IPAddress = .any

    public init() {}
    public init(addr: IPAddress, port: UInt16) {
        self.addr = addr
        self.port = port
    }
}

/// IPv6 socket address.
public struct SockAddrIn6: Sendable {
    public var family: AddressFamily = .inet6
    public var port: UInt16 = 0
    public var flowInfo: UInt32 = 0
    public var addr: IPAddress = .any
    public var scopeId: UInt32 = 0

    public init() {}
    public init(addr: IPAddress, port: UInt16) {
        self.addr = addr
        self.port = port
    }
}

/// Generic socket address.
public struct SockAddr: Sendable {
    public var family: AddressFamily = .unspec
    public var addr: IPAddress = .any
    public var port: UInt16 = 0

    public init() {}
    public init(family: AddressFamily, addr: IPAddress, port: UInt16) {
        self.family = family
        self.addr = addr
        self.port = port
    }
}

/// Linger option.
public struct LingerOption: Sendable {
    public var isEnabled: Bool
    public var timeSeconds: Int32

    public init(isEnabled: Bool = false, timeSeconds: Int32 = 0) {
        self.isEnabled = isEnabled
        self.timeSeconds = timeSeconds
    }

    /// Compatibility alias for older callers.
    public var enabled: Bool {
        get { isEnabled }
        set { isEnabled = newValue }
    }

    /// Compatibility initializer for older callers.
    public init(enabled: Bool = false, timeSeconds: Int32 = 0) {
        self.init(isEnabled: enabled, timeSeconds: timeSeconds)
    }
}

// MARK: - LwIPSock (Internal)

/// Internal socket state, wrapping a NetConn.
internal final class LwIPSock: @unchecked Sendable {
    /// The underlying netconn.
    var conn: NetConn?
    /// Data leftover from a previous read.
    var lastData: AnyObject?  // NetBuf or Pbuf
    /// Receive event counter.
    var rcvEvent: Int16 = 0
    /// Send event counter (buffer space available).
    var sendEvent: UInt16 = 0
    /// Error event.
    var errEvent: UInt16 = 0
    /// Number of threads in select/poll for this socket.
    var selectWaiting: UInt8 = 0
    /// File descriptor usage counter (full-duplex).
    var fdUsed: UInt8 = 0
    /// Pending close/free actions.
    var fdFreePending: UInt8 = 0

    init(conn: NetConn) {
        self.conn = conn
        self.fdUsed = 1
    }
}

// MARK: - FDSet

/// File descriptor set for select().
public struct FDSet: Sendable {
    /// Maximum number of file descriptors.
    public static let maxSize = 64

    /// Bitfield storage.
    @usableFromInline
    internal var bits: UInt64 = 0

    public init() {}

    /// Set a file descriptor in the set.
    @inlinable
    public mutating func set(_ fd: Int32) {
        guard fd >= 0 && fd < FDSet.maxSize else { return }
        bits |= (1 << UInt64(fd))
    }

    /// Clear a file descriptor from the set.
    @inlinable
    public mutating func clear(_ fd: Int32) {
        guard fd >= 0 && fd < FDSet.maxSize else { return }
        bits &= ~(1 << UInt64(fd))
    }

    /// Check if a file descriptor is set.
    @inlinable
    public func isSet(_ fd: Int32) -> Bool {
        guard fd >= 0 && fd < FDSet.maxSize else { return false }
        return (bits & (1 << UInt64(fd))) != 0
    }

    /// Clear all file descriptors.
    @inlinable
    public mutating func zero() {
        bits = 0
    }
}

// MARK: - Timeval

/// Time value for select() timeout.
public struct Timeval: Sendable {
    public var seconds: Int
    public var microseconds: Int

    public init(seconds: Int = 0, microseconds: Int = 0) {
        self.seconds = seconds
        self.microseconds = microseconds
    }

    /// Total time interval in seconds (as Double).
    @inlinable
    public var timeInterval: TimeInterval {
        TimeInterval(seconds) + TimeInterval(microseconds) / 1_000_000
    }

    /// Total time in milliseconds.
    @inlinable
    public var milliseconds: Int {
        seconds * 1000 + microseconds / 1000
    }
}

// MARK: - LWIPSocket

/// BSD socket API for lwIP.
///
/// Provides a numeric file-descriptor-based interface built on the NetConn API.
/// All functions are thread-safe and can be called from any thread.
public final class LWIPSocket: @unchecked Sendable {

    /// Maximum number of sockets.
    public static let maxSockets = 64

    /// Socket offset for file descriptor numbering.
    public static let socketOffset: Int32 = 0

    /// Shared instance.
    public static let shared = LWIPSocket()

    /// Socket table.
    private var sockets: [LwIPSock?]

    /// Lock protecting the socket table.
    private let tableLock = NSLock()

    /// Select/poll notification.
    private let selectSemaphore = DispatchSemaphore(value: 0)

    /// Select callback list.
    private var selectCallbacks: [AnyObject] = []

    private init() {
        sockets = Array(repeating: nil, count: LWIPSocket.maxSockets)
    }

    // MARK: - Socket Allocation

    /// Allocate a new socket slot.
    private func allocSocket(conn: NetConn) -> Int32 {
        tableLock.lock()
        defer { tableLock.unlock() }

        for i in 0..<LWIPSocket.maxSockets {
            if sockets[i] == nil {
                let sock = LwIPSock(conn: conn)
                sockets[i] = sock
                conn.callbackArg = i as AnyObject
                return Int32(i) + LWIPSocket.socketOffset
            }
        }
        return -1
    }

    /// Get the internal socket for a file descriptor.
    internal func getSock(_ fd: Int32) -> LwIPSock? {
        let idx = Int(fd - LWIPSocket.socketOffset)
        guard idx >= 0 && idx < LWIPSocket.maxSockets else { return nil }
        tableLock.lock()
        let sock = sockets[idx]
        tableLock.unlock()
        return sock
    }

    /// Free a socket slot.
    private func freeSocket(_ fd: Int32) {
        let idx = Int(fd - LWIPSocket.socketOffset)
        guard idx >= 0 && idx < LWIPSocket.maxSockets else { return }
        tableLock.lock()
        sockets[idx] = nil
        tableLock.unlock()
    }

    private func optionEnabled(from value: Any) -> Bool? {
        if let flag = value as? Bool {
            return flag
        }
        if let flag = value as? Int32 {
            return flag != 0
        }
        if let flag = value as? UInt8 {
            return flag != 0
        }
        if let flag = value as? UInt32 {
            return flag != 0
        }
        return nil
    }

    private func packetInfoControlData(for netBuf: NetBuf) -> [UInt8]? {
        guard let destAddress = netBuf.destAddress else {
            return nil
        }

        var control = [UInt8]()

        func appendInt32(_ value: Int32) {
            var encoded = value.littleEndian
            withUnsafeBytes(of: &encoded) { control.append(contentsOf: $0) }
        }

        func appendUInt32(_ value: UInt32) {
            var encoded = value.littleEndian
            withUnsafeBytes(of: &encoded) { control.append(contentsOf: $0) }
        }

        switch destAddress {
        case .v4(let ipv4):
            // IPv4 IP_PKTINFO
            appendInt32(IPProtocol.ip.rawValue)
            appendInt32(IPSocketOption.packetInfo.rawValue)
            appendUInt32(UInt32(netBuf.p?.ifIndex ?? 0))
            control.append(contentsOf: [ipv4.octet1, ipv4.octet2, ipv4.octet3, ipv4.octet4])

        case .v6(let ipv6):
            // IPv6 IPV6_PKTINFO: interface index + destination address (16 bytes)
            appendInt32(IPProtocol.ipv6.rawValue)
            appendInt32(IPv6SocketOption.packetInfo.rawValue)
            appendUInt32(UInt32(netBuf.p?.ifIndex ?? 0))
            // Append the 16-byte IPv6 address in network byte order
            appendUInt32(ipv6.addr.0)
            appendUInt32(ipv6.addr.1)
            appendUInt32(ipv6.addr.2)
            appendUInt32(ipv6.addr.3)

        case .any:
            return nil
        }

        return control
    }

    private func socketOptions(for conn: NetConn) -> SocketOptions? {
        switch conn.pcb {
        case .tcp(let tcpPCB):
            return SocketOptions(rawValue: tcpPCB.socketOptions)
        case .tcpListen(let listenPCB):
            return SocketOptions(rawValue: listenPCB.socketOptions)
        case .udp(let udpPCB):
            return SocketOptions(rawValue: udpPCB.soOptions)
        case .raw(let rawPCB):
            return rawPCB.soOptions
        case nil:
            return nil
        }
    }

    @discardableResult
    private func updateSocketOption(_ option: SocketOptions, enabled: Bool, for conn: NetConn) -> Bool {
        switch conn.pcb {
        case .tcp(let tcpPCB):
            var options = SocketOptions(rawValue: tcpPCB.socketOptions)
            if enabled {
                options.insert(option)
            } else {
                options.remove(option)
            }
            tcpPCB.socketOptions = options.rawValue
            return true
        case .tcpListen(let listenPCB):
            var options = SocketOptions(rawValue: listenPCB.socketOptions)
            if enabled {
                options.insert(option)
            } else {
                options.remove(option)
            }
            listenPCB.socketOptions = options.rawValue
            return true
        case .udp(let udpPCB):
            var options = SocketOptions(rawValue: udpPCB.soOptions)
            if enabled {
                options.insert(option)
            } else {
                options.remove(option)
            }
            udpPCB.soOptions = options.rawValue
            return true
        case .raw(let rawPCB):
            if enabled {
                rawPCB.soOptions.insert(option)
            } else {
                rawPCB.soOptions.remove(option)
            }
            return true
        case nil:
            return false
        }
    }

    private func tcpNoDelayEnabled(for conn: NetConn) -> Bool? {
        guard let tcpPCB = conn.pcb?.tcpControlBlock else { return nil }
        return tcpPCB.flags.contains(.noDelay)
    }

    @discardableResult
    private func setTCPNoDelay(_ enabled: Bool, for conn: NetConn) -> Bool {
        guard let tcpPCB = conn.pcb?.tcpControlBlock else { return false }
        if enabled {
            tcpPCB.flags.insert(.noDelay)
        } else {
            tcpPCB.flags.remove(.noDelay)
        }
        return true
    }

    // MARK: - socket()

    /// Create a new socket.
    ///
    /// - Parameters:
    ///   - domain: Address family (AF_INET, AF_INET6).
    ///   - type: Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW).
    ///   - protocol: Protocol number.
    /// - Returns: A file descriptor, or -1 on error.
    public func socket(domain: Int32, type: Int32, protocol proto: Int32) -> Int32 {
        let connType: NetconnType

        switch type {
        case SocketType.stream.rawValue:
            connType = domain == AddressFamily.inet6.rawValue ? .tcpIPv6 : .tcp
        case SocketType.dgram.rawValue:
            if proto == IPProtocol.udpLite.rawValue {
                connType = domain == AddressFamily.inet6.rawValue ? .udpLiteIPv6 : .udpLite
            } else {
                connType = domain == AddressFamily.inet6.rawValue ? .udpIPv6 : .udp
            }
        case SocketType.raw.rawValue:
            connType = domain == AddressFamily.inet6.rawValue ? .rawIPv6 : .raw
        default:
            return -1
        }

        guard let conn = NetConn(type: connType, proto: UInt8(proto), callback: { [weak self] conn, evt, len in
            self?.eventCallback(conn: conn, event: evt, length: len)
        }) else {
            return -1
        }

        let fd = allocSocket(conn: conn)
        if fd < 0 {
            _ = conn.delete()
            return -1
        }

        return fd
    }

    // MARK: - bind()

    /// Bind a socket to a local address.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - addr: Local address.
    /// - Returns: 0 on success, -1 on error.
    public func bind(_ s: Int32, addr: SockAddr) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        let err = conn.bind(addr: addr.addr, port: addr.port)
        return err == .ok ? 0 : -1
    }

    // MARK: - listen()

    /// Put socket into listening mode.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - backlog: Maximum pending connections.
    /// - Returns: 0 on success, -1 on error.
    public func listen(_ s: Int32, backlog: Int32) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        let err = conn.listen(backlog: UInt8(min(backlog, 0xFF)))
        return err == .ok ? 0 : -1
    }

    // MARK: - accept()

    /// Accept a new connection on a listening socket.
    ///
    /// - Parameters:
    ///   - s: Listening socket file descriptor.
    ///   - addr: Output: address of the remote peer.
    /// - Returns: New socket file descriptor, or -1 on error.
    public func accept(_ s: Int32, addr: inout SockAddr?) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        switch conn.accept() {
        case .success(let newConn):
            let newFd = allocSocket(conn: newConn)
            if newFd < 0 {
                _ = newConn.delete()
                return -1
            }
            // Retrieve peer address.
            if case .success(let (peerAddr, peerPort)) = newConn.peerAddress() {
                addr = SockAddr(family: peerAddr.isV4 ? .inet : .inet6,
                               addr: peerAddr, port: peerPort)
            }
            sock.rcvEvent = max(0, sock.rcvEvent - 1)
            return newFd
        case .failure:
            return -1
        }
    }

    // MARK: - connect()

    /// Connect a socket to a remote address.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - addr: Remote address.
    /// - Returns: 0 on success, -1 on error.
    public func connect(_ s: Int32, addr: SockAddr) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        let err = conn.connect(addr: addr.addr, port: addr.port)
        return err == .ok ? 0 : -1
    }

    // MARK: - send() / sendto()

    /// Send data on a connected socket.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - data: Data to send.
    ///   - flags: Message flags.
    /// - Returns: Number of bytes sent, or -1 on error.
    public func send(_ s: Int32, data: UnsafeRawPointer, size: Int,
                     flags: MessageFlags = []) -> Int {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        if conn.type.isTCP {
            var writeFlags: NetconnWriteFlags = .copy
            if flags.contains(.more) {
                writeFlags.insert(.more)
            }
            if flags.contains(.dontWait) {
                writeFlags.insert(.dontBlock)
            }
            let (err, written) = conn.write(data, size: size, flags: writeFlags)
            return err == .ok ? written : -1
        } else {
            let buf = NetBuf()
            guard buf.ref(data, size: UInt16(min(size, Int(UInt16.max)))) == .ok else { return -1 }
            let err = conn.send(buf)
            return err == .ok ? size : -1
        }
    }

    /// Send data to a specific address.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - data: Data to send.
    ///   - size: Size of data.
    ///   - flags: Message flags.
    ///   - to: Destination address.
    /// - Returns: Number of bytes sent, or -1 on error.
    public func sendTo(_ s: Int32, data: UnsafeRawPointer, size: Int,
                       flags: MessageFlags = [], to: SockAddr) -> Int {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        if conn.type.isTCP {
            return send(s, data: data, size: size, flags: flags)
        }

        let buf = NetBuf()
        guard buf.ref(data, size: UInt16(min(size, Int(UInt16.max)))) == .ok else { return -1 }
        let err = conn.sendTo(buf, addr: to.addr, port: to.port)
        return err == .ok ? size : -1
    }

    // MARK: - recv() / recvfrom()

    /// Receive data from a socket.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - buffer: Buffer to receive into.
    ///   - size: Maximum bytes to receive.
    ///   - flags: Message flags.
    /// - Returns: Number of bytes received, or -1 on error.
    public func recv(_ s: Int32, buffer: UnsafeMutableRawPointer, size: Int,
                     flags: MessageFlags = []) -> Int {
        return recvFrom(s, buffer: buffer, size: size, flags: flags, from: nil)
    }

    /// Receive data with source address.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - buffer: Buffer to receive into.
    ///   - size: Maximum bytes to receive.
    ///   - flags: Message flags.
    ///   - from: Output: source address (optional).
    /// - Returns: Number of bytes received, or -1 on error.
    public func recvFrom(_ s: Int32, buffer: UnsafeMutableRawPointer, size: Int,
                         flags: MessageFlags = [], from: UnsafeMutablePointer<SockAddr>?) -> Int {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        if conn.type.isTCP {
            switch conn.receiveTCPPbuf() {
            case .success(let pbuf):
                let copyLen = min(size, Int(pbuf.totalLength))
                _ = pbuf.copyPartial(to: buffer, len: UInt16(copyLen), offset: 0)
                sock.rcvEvent = max(0, sock.rcvEvent - 1)
                return copyLen
            case .failure(let err):
                if err == .closed { return 0 }
                return -1
            }
        } else {
            switch conn.receive() {
            case .success(let buf):
                let copyLen = min(size, Int(buf.totalLength))
                buf.copyPartial(to: buffer, length: UInt16(copyLen))
                if let fromPtr = from {
                    fromPtr.pointee = SockAddr(
                        family: buf.addr.isV4 ? .inet : .inet6,
                        addr: buf.addr,
                        port: buf.port
                    )
                }
                sock.rcvEvent = max(0, sock.rcvEvent - 1)
                return copyLen
            case .failure(let err):
                if err == .closed { return 0 }
                return -1
            }
        }
    }

    // MARK: - read() / write()

    /// Read data from a socket (POSIX-style).
    public func read(_ s: Int32, buffer: UnsafeMutableRawPointer, size: Int) -> Int {
        return recv(s, buffer: buffer, size: size)
    }

    /// Write data to a socket (POSIX-style).
    public func write(_ s: Int32, data: UnsafeRawPointer, size: Int) -> Int {
        return send(s, data: data, size: size)
    }

    // MARK: - close()

    /// Close a socket.
    ///
    /// - Parameter s: Socket file descriptor.
    /// - Returns: 0 on success, -1 on error.
    public func close(_ s: Int32) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        _ = conn.close()
        _ = conn.delete()
        sock.conn = nil
        freeSocket(s)
        return 0
    }

    // MARK: - shutdown()

    /// Shutdown a socket.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - how: Shutdown mode.
    /// - Returns: 0 on success, -1 on error.
    public func shutdown(_ s: Int32, how: Int32) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        let shutRx = (how == ShutdownMode.read.rawValue || how == ShutdownMode.readWrite.rawValue)
        let shutTx = (how == ShutdownMode.write.rawValue || how == ShutdownMode.readWrite.rawValue)

        let err = conn.shutdown(rx: shutRx, tx: shutTx)
        return err == .ok ? 0 : -1
    }

    // MARK: - getsockopt() / setsockopt()

    /// Get a socket option.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - level: Option level.
    ///   - optName: Option name.
    /// - Returns: The option value, or nil on error.
    public func getSocketOption(_ s: Int32, level: Int32, optName: Int32) -> Any? {
        guard let sock = getSock(s), let conn = sock.conn else { return nil }

        // SOL_SOCKET level options.
        if level == SocketLevel.socket.rawValue {
            switch optName {
            case SocketOption.error.rawValue:
                let err = conn.checkError()
                return Int32(err.posixErrno)
            case SocketOption.type.rawValue:
                if conn.type.isTCP { return SocketType.stream.rawValue }
                if conn.type.isUDP { return SocketType.dgram.rawValue }
                return SocketType.raw.rawValue
            case SocketOption.receiveTimeout.rawValue:
                return Timeval(seconds: Int(conn.receiveTimeout / 1000),
                              microseconds: Int((conn.receiveTimeout % 1000) * 1000))
            case SocketOption.sendTimeout.rawValue:
                return Timeval(seconds: Int(conn.sendTimeout / 1000),
                              microseconds: Int(abs(conn.sendTimeout % 1000) * 1000))
            case SocketOption.receiveBuffer.rawValue:
                return Int32(conn.receiveBufferSize)
            case SocketOption.linger.rawValue:
                return LingerOption(isEnabled: conn.linger >= 0,
                                  timeSeconds: conn.linger >= 0 ? Int32(conn.linger) : 0)
            case SocketOption.keepAlive.rawValue:
                return Int32(socketOptions(for: conn)?.contains(.keepAlive) == true ? 1 : 0)
            case SocketOption.reuseAddr.rawValue:
                return Int32(socketOptions(for: conn)?.contains(.reuseAddr) == true ? 1 : 0)
            case SocketOption.broadcast.rawValue:
                return Int32(socketOptions(for: conn)?.contains(.broadcast) == true ? 1 : 0)
            case SocketOption.noChecksum.rawValue:
                guard let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return Int32(udpPCB.flags.contains(.noChecksum) ? 1 : 0)
            case SocketOption.sendBuffer.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock else { return nil }
                return Int32(tcpPCB.sendBufferAvailable)
            case SocketOption.acceptConn.rawValue:
                let isListening: Bool
                switch conn.pcb {
                case .tcpListen:
                    isListening = true
                default:
                    isListening = (conn.state == .listen)
                }
                return Int32(isListening ? 1 : 0)
            case SocketOption.bindToDevice.rawValue:
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    return Int32(tcpPCB.netifIdx)
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    return Int32(udpPCB.netifIdx)
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    return Int32(rawPCB.netifIdx)
                }
                return nil
            default:
                return nil
            }
        }

        if level == IPProtocol.ip.rawValue {
            switch optName {
            case IPSocketOption.packetInfo.rawValue:
                guard conn.type.isUDP else { return nil }
                return Int32(conn.flags.contains(.packetInfo) ? 1 : 0)

            case IPSocketOption.multicastTTL.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return UInt8(udpPCB.multicastTTL)

            case IPSocketOption.multicastIF.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return IPv4Address(networkOrder: udpPCB.multicastIPv4)

            case IPSocketOption.multicastLoop.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return UInt8(udpPCB.flags.contains(.multicastLoop) ? 1 : 0)

            case IPSocketOption.typeOfService.rawValue:
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    return Int32(tcpPCB.tos)
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    return Int32(udpPCB.tos)
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    return Int32(rawPCB.tos)
                }
                return nil

            case IPSocketOption.timeToLive.rawValue:
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    return Int32(tcpPCB.ttl)
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    return Int32(udpPCB.ttl)
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    return Int32(rawPCB.ttl)
                }
                return nil

            default:
                return nil
            }
        }

        if level == IPProtocol.ipv6.rawValue {
            switch optName {
            case IPv6SocketOption.v6Only.rawValue:
                return Int32(conn.isIPv6Only ? 1 : 0)

            case IPv6SocketOption.multicastHops.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return Int32(udpPCB.multicastTTL)

            case IPv6SocketOption.multicastIF.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return Int32(udpPCB.multicastInterfaceIndex)

            case IPv6SocketOption.multicastLoop.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return nil }
                return Int32(udpPCB.flags.contains(.multicastLoop) ? 1 : 0)

            case IPv6SocketOption.packetInfo.rawValue:
                return Int32(conn.flags.contains(.packetInfo) ? 1 : 0)

            case IPv6SocketOption.recvHopLimit.rawValue:
                return Int32(conn.flags.contains(.recvHopLimit) ? 1 : 0)

            case IPv6SocketOption.checksum.rawValue:
                guard conn.type.isRaw,
                      let rawPCB = conn.pcb?.rawControlBlock else { return nil }
                return Int32(rawPCB.checksumOffset)

            case IPv6SocketOption.trafficClass.rawValue:
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    return Int32(tcpPCB.tos)
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    return Int32(udpPCB.tos)
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    return Int32(rawPCB.tos)
                }
                return nil

            default:
                return nil
            }
        }

        if level == IPProtocol.tcp.rawValue {
            switch optName {
            case TCPSocketOption.noDelay.rawValue:
                return Int32(tcpNoDelayEnabled(for: conn) == true ? 1 : 0)
            case TCPSocketOption.keepIdle.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock else { return nil }
                return Int32(tcpPCB.keepaliveIdle / 1000)
            case TCPSocketOption.keepInterval.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock else { return nil }
                return Int32(tcpPCB.keepaliveInterval / 1000)
            case TCPSocketOption.keepCount.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock else { return nil }
                return Int32(tcpPCB.keepaliveCount)
            default:
                return nil
            }
        }

        // IPPROTO_UDPLITE options.
        if level == SocketLevel.ipProtocolUDPLite.rawValue {
            guard conn.type.isUDPLite,
                  let udpPCB = conn.pcb?.udpControlBlock else { return nil }
            switch optName {
            case UDPLiteSocketOption.sendChecksumCoverage.rawValue:
                return Int32(udpPCB.checksumLengthTransmit)
            case UDPLiteSocketOption.recvChecksumCoverage.rawValue:
                return Int32(udpPCB.checksumLengthReceive)
            default:
                return nil
            }
        }

        return nil
    }

    /// Set a socket option.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - level: Option level.
    ///   - optName: Option name.
    ///   - value: Option value.
    /// - Returns: 0 on success, -1 on error.
    @discardableResult
    public func setSocketOption(_ s: Int32, level: Int32, optName: Int32, value: Any) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        if level == SocketLevel.socket.rawValue {
            switch optName {
            case SocketOption.receiveTimeout.rawValue:
                if let tv = value as? Timeval {
                    conn.receiveTimeout = UInt32(tv.milliseconds)
                    return 0
                }
            case SocketOption.sendTimeout.rawValue:
                if let tv = value as? Timeval {
                    conn.sendTimeout = Int32(tv.milliseconds)
                    return 0
                }
            case SocketOption.receiveBuffer.rawValue:
                if let size = value as? Int32 {
                    conn.receiveBufferSize = Int(size)
                    return 0
                }
            case SocketOption.linger.rawValue:
                if let l = value as? LingerOption {
                    conn.linger = l.isEnabled ? Int16(l.timeSeconds) : -1
                    return 0
                }
            case SocketOption.keepAlive.rawValue:
                if let enabled = optionEnabled(from: value),
                   updateSocketOption(.keepAlive, enabled: enabled, for: conn) {
                    return 0
                }
            case SocketOption.reuseAddr.rawValue:
                if let enabled = optionEnabled(from: value),
                   updateSocketOption(.reuseAddr, enabled: enabled, for: conn) {
                    return 0
                }
            case SocketOption.broadcast.rawValue:
                if let enabled = optionEnabled(from: value),
                   updateSocketOption(.broadcast, enabled: enabled, for: conn) {
                    return 0
                }
            case SocketOption.noChecksum.rawValue:
                if let udpPCB = conn.pcb?.udpControlBlock,
                   let enabled = optionEnabled(from: value) {
                    if enabled {
                        udpPCB.flags.insert(.noChecksum)
                    } else {
                        udpPCB.flags.remove(.noChecksum)
                    }
                    return 0
                }
            case SocketOption.sendBuffer.rawValue:
                // SO_SNDBUF is read-only; lwIP does not support dynamic send buffer resizing.
                return -1
            case SocketOption.acceptConn.rawValue:
                // SO_ACCEPTCONN is read-only per POSIX.
                return -1
            case SocketOption.bindToDevice.rawValue:
                if let ifIdx = value as? UInt8 {
                    if let tcpPCB = conn.pcb?.tcpControlBlock {
                        tcpPCB.netifIdx = ifIdx
                    } else if let udpPCB = conn.pcb?.udpControlBlock {
                        udpPCB.netifIdx = ifIdx
                    } else if let rawPCB = conn.pcb?.rawControlBlock {
                        rawPCB.netifIdx = ifIdx
                    } else {
                        return -1
                    }
                    return 0
                } else if let ifIdx = value as? Int32 {
                    let idx = UInt8(truncatingIfNeeded: ifIdx)
                    if let tcpPCB = conn.pcb?.tcpControlBlock {
                        tcpPCB.netifIdx = idx
                    } else if let udpPCB = conn.pcb?.udpControlBlock {
                        udpPCB.netifIdx = idx
                    } else if let rawPCB = conn.pcb?.rawControlBlock {
                        rawPCB.netifIdx = idx
                    } else {
                        return -1
                    }
                    return 0
                }
            default:
                break
            }
        }

        if level == IPProtocol.ip.rawValue {
            switch optName {
            case IPSocketOption.packetInfo.rawValue:
                guard conn.type.isUDP, let enabled = optionEnabled(from: value) else { return -1 }
                if enabled {
                    conn.flags.insert(.packetInfo)
                } else {
                    conn.flags.remove(.packetInfo)
                }
                return 0

            case IPSocketOption.multicastTTL.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return -1 }
                if let v = value as? UInt8 {
                    udpPCB.multicastTTL = v
                } else if let v = value as? Int32 {
                    udpPCB.multicastTTL = UInt8(truncatingIfNeeded: v)
                } else {
                    return -1
                }
                return 0

            case IPSocketOption.multicastIF.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return -1 }
                if let addr = value as? IPv4Address {
                    udpPCB.multicastIPv4 = addr.addr
                } else if let addr = value as? IPAddress, let v4 = addr.ipv4 {
                    udpPCB.multicastIPv4 = v4.addr
                } else {
                    return -1
                }
                return 0

            case IPSocketOption.multicastLoop.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock,
                      let enabled = optionEnabled(from: value) else { return -1 }
                if enabled {
                    udpPCB.flags.insert(.multicastLoop)
                } else {
                    udpPCB.flags.remove(.multicastLoop)
                }
                return 0

            case IPSocketOption.addMembership.rawValue,
                 IPSocketOption.dropMembership.rawValue:
                guard conn.type.isUDP,
                      let mreq = value as? IPMulticastRequest else { return -1 }
                let igmpErr: LWIPError
                if optName == IPSocketOption.addMembership.rawValue {
                    igmpErr = IGMP.joinGroup(ifAddr: mreq.interfaceAddress,
                                             groupAddr: mreq.multicastAddress)
                } else {
                    igmpErr = IGMP.leaveGroup(ifAddr: mreq.interfaceAddress,
                                              groupAddr: mreq.multicastAddress)
                }
                return igmpErr == .ok ? 0 : -1

            case IPSocketOption.typeOfService.rawValue:
                guard let v = value as? Int32 else { return -1 }
                let tosVal = UInt8(truncatingIfNeeded: v)
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    tcpPCB.tos = tosVal
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    udpPCB.tos = tosVal
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    rawPCB.tos = tosVal
                } else {
                    return -1
                }
                return 0

            case IPSocketOption.timeToLive.rawValue:
                guard let v = value as? Int32 else { return -1 }
                let ttlVal = UInt8(truncatingIfNeeded: v)
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    tcpPCB.ttl = ttlVal
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    udpPCB.ttl = ttlVal
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    rawPCB.ttl = ttlVal
                } else {
                    return -1
                }
                return 0

            default:
                break
            }
        }

        // IPPROTO_TCP options.
        if level == IPProtocol.tcp.rawValue {
            switch optName {
            case TCPSocketOption.noDelay.rawValue:
                if let enabled = optionEnabled(from: value),
                   setTCPNoDelay(enabled, for: conn) {
                    return 0
                }
            case TCPSocketOption.keepIdle.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock,
                      let v = value as? Int32 else { return -1 }
                tcpPCB.keepaliveIdle = UInt32(v) * 1000
                return 0
            case TCPSocketOption.keepInterval.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock,
                      let v = value as? Int32 else { return -1 }
                tcpPCB.keepaliveInterval = UInt32(v) * 1000
                return 0
            case TCPSocketOption.keepCount.rawValue:
                guard let tcpPCB = conn.pcb?.tcpControlBlock,
                      let v = value as? Int32 else { return -1 }
                tcpPCB.keepaliveCount = UInt8(min(v, 255))
                return 0
            default:
                break
            }
        }

        // IPPROTO_IPV6 options.
        if level == IPProtocol.ipv6.rawValue {
            switch optName {
            case IPv6SocketOption.v6Only.rawValue:
                if let v = value as? Int32 {
                    conn.isIPv6Only = v != 0
                    return 0
                }

            case IPv6SocketOption.joinGroup.rawValue,
                 IPv6SocketOption.leaveGroup.rawValue:
                guard conn.type.isUDP,
                      let mreq = value as? IPv6MulticastRequest else { return -1 }
                guard mreq.interfaceIndex <= 0xFF else { return -1 }
                guard let netif = NetworkInterface.getByIndex(UInt8(mreq.interfaceIndex)) else {
                    return -1
                }
                let mldErr: LWIPError
                if optName == IPv6SocketOption.joinGroup.rawValue {
                    mldErr = MLD6.joinGroup(on: netif, groupAddr: mreq.multicastAddress)
                } else {
                    mldErr = MLD6.leaveGroup(on: netif, groupAddr: mreq.multicastAddress)
                }
                return mldErr == .ok ? 0 : -1

            case IPv6SocketOption.multicastHops.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return -1 }
                if let v = value as? Int32 {
                    udpPCB.multicastTTL = UInt8(truncatingIfNeeded: v)
                } else if let v = value as? UInt8 {
                    udpPCB.multicastTTL = v
                } else {
                    return -1
                }
                return 0

            case IPv6SocketOption.multicastIF.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock else { return -1 }
                if let v = value as? Int32 {
                    udpPCB.multicastInterfaceIndex = UInt8(truncatingIfNeeded: v)
                } else if let v = value as? UInt8 {
                    udpPCB.multicastInterfaceIndex = v
                } else {
                    return -1
                }
                return 0

            case IPv6SocketOption.multicastLoop.rawValue:
                guard conn.type.isUDP,
                      let udpPCB = conn.pcb?.udpControlBlock,
                      let enabled = optionEnabled(from: value) else { return -1 }
                if enabled {
                    udpPCB.flags.insert(.multicastLoop)
                } else {
                    udpPCB.flags.remove(.multicastLoop)
                }
                return 0

            case IPv6SocketOption.packetInfo.rawValue:
                guard let enabled = optionEnabled(from: value) else { return -1 }
                if enabled {
                    conn.flags.insert(.packetInfo)
                } else {
                    conn.flags.remove(.packetInfo)
                }
                return 0

            case IPv6SocketOption.recvHopLimit.rawValue:
                guard let enabled = optionEnabled(from: value) else { return -1 }
                if enabled {
                    conn.flags.insert(.recvHopLimit)
                } else {
                    conn.flags.remove(.recvHopLimit)
                }
                return 0

            case IPv6SocketOption.checksum.rawValue:
                guard conn.type.isRaw,
                      let rawPCB = conn.pcb?.rawControlBlock,
                      let v = value as? Int32 else { return -1 }
                rawPCB.checksumOffset = UInt16(truncatingIfNeeded: v)
                return 0

            case IPv6SocketOption.trafficClass.rawValue:
                guard let v = value as? Int32 else { return -1 }
                let tclassVal = UInt8(truncatingIfNeeded: v)
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    tcpPCB.tos = tclassVal
                } else if let udpPCB = conn.pcb?.udpControlBlock {
                    udpPCB.tos = tclassVal
                } else if let rawPCB = conn.pcb?.rawControlBlock {
                    rawPCB.tos = tclassVal
                } else {
                    return -1
                }
                return 0

            default:
                break
            }
        }

        // IPPROTO_UDPLITE options.
        if level == SocketLevel.ipProtocolUDPLite.rawValue {
            guard conn.type.isUDPLite,
                  let udpPCB = conn.pcb?.udpControlBlock,
                  let v = value as? Int32 else { return -1 }
            switch optName {
            case UDPLiteSocketOption.sendChecksumCoverage.rawValue:
                udpPCB.checksumLengthTransmit = UInt16(truncatingIfNeeded: v)
                return 0
            case UDPLiteSocketOption.recvChecksumCoverage.rawValue:
                udpPCB.checksumLengthReceive = UInt16(truncatingIfNeeded: v)
                return 0
            default:
                break
            }
        }

        return -1
    }

    // MARK: - getpeername() / getsockname()

    /// Get the remote address of a connected socket.
    public func getPeerName(_ s: Int32) -> SockAddr? {
        guard let sock = getSock(s), let conn = sock.conn else { return nil }
        if case .success(let (addr, port)) = conn.peerAddress() {
            return SockAddr(family: addr.isV4 ? .inet : .inet6, addr: addr, port: port)
        }
        return nil
    }

    /// Get the local address of a socket.
    public func getSockName(_ s: Int32) -> SockAddr? {
        guard let sock = getSock(s), let conn = sock.conn else { return nil }
        if case .success(let (addr, port)) = conn.localAddress() {
            return SockAddr(family: addr.isV4 ? .inet : .inet6, addr: addr, port: port)
        }
        return nil
    }

    // MARK: - select()

    /// Wait for activity on a set of sockets.
    ///
    /// - Parameters:
    ///   - maxfdp1: Highest file descriptor + 1.
    ///   - readSet: File descriptors to watch for readability.
    ///   - writeSet: File descriptors to watch for writability.
    ///   - exceptSet: File descriptors to watch for exceptions.
    ///   - timeout: Timeout (nil = block forever).
    /// - Returns: Number of ready descriptors, or -1 on error.
    public func select(maxfdp1: Int32,
                       readSet: inout FDSet?,
                       writeSet: inout FDSet?,
                       exceptSet: inout FDSet?,
                       timeout: Timeval?) -> Int32 {
        var nReady: Int32 = 0

        // Check all descriptors immediately.
        for fd in LWIPSocket.socketOffset..<maxfdp1 {
            guard let sock = getSock(fd) else { continue }

            if readSet?.isSet(fd) == true && sock.rcvEvent > 0 {
                nReady += 1
            } else {
                readSet?.clear(fd)
            }

            if writeSet?.isSet(fd) == true && sock.sendEvent > 0 {
                nReady += 1
            } else {
                writeSet?.clear(fd)
            }

            if exceptSet?.isSet(fd) == true && sock.errEvent > 0 {
                nReady += 1
            } else {
                exceptSet?.clear(fd)
            }
        }

        if nReady > 0 {
            return nReady
        }

        // Wait for events.
        if let tv = timeout {
            let deadline = DispatchTime.now() + .milliseconds(tv.milliseconds)
            _ = selectSemaphore.wait(timeout: deadline)
        } else {
            selectSemaphore.wait()
        }

        // Re-check after wakeup.
        nReady = 0
        for fd in LWIPSocket.socketOffset..<maxfdp1 {
            guard let sock = getSock(fd) else { continue }

            if readSet?.isSet(fd) == true && sock.rcvEvent > 0 {
                nReady += 1
            } else {
                readSet?.clear(fd)
            }

            if writeSet?.isSet(fd) == true && sock.sendEvent > 0 {
                nReady += 1
            } else {
                writeSet?.clear(fd)
            }

            if exceptSet?.isSet(fd) == true && sock.errEvent > 0 {
                nReady += 1
            } else {
                exceptSet?.clear(fd)
            }
        }

        return nReady
    }

    // MARK: - poll()

    /// Poll for activity on sockets.
    ///
    /// - Parameters:
    ///   - fds: Array of poll file descriptors.
    ///   - timeout: Timeout in milliseconds (-1 = block forever).
    /// - Returns: Number of ready descriptors, or -1 on error.
    public func poll(_ fds: inout [PollFD], timeout: Int32) -> Int32 {
        var nReady: Int32 = 0

        for i in fds.indices {
            fds[i].revents = []
            guard let sock = getSock(fds[i].fd) else {
                fds[i].revents.insert(.invalid)
                nReady += 1
                continue
            }

            if fds[i].events.contains(.in) && sock.rcvEvent > 0 {
                fds[i].revents.insert(.in)
            }
            if fds[i].events.contains(.out) && sock.sendEvent > 0 {
                fds[i].revents.insert(.out)
            }
            if sock.errEvent > 0 {
                fds[i].revents.insert(.err)
            }

            if !fds[i].revents.isEmpty {
                nReady += 1
            }
        }

        if nReady > 0 || timeout == 0 {
            return nReady
        }

        // Wait.
        if timeout > 0 {
            _ = selectSemaphore.wait(timeout: .now() + .milliseconds(Int(timeout)))
        } else {
            selectSemaphore.wait()
        }

        // Re-check.
        nReady = 0
        for i in fds.indices {
            fds[i].revents = []
            guard let sock = getSock(fds[i].fd) else {
                fds[i].revents.insert(.invalid)
                nReady += 1
                continue
            }

            if fds[i].events.contains(.in) && sock.rcvEvent > 0 {
                fds[i].revents.insert(.in)
            }
            if fds[i].events.contains(.out) && sock.sendEvent > 0 {
                fds[i].revents.insert(.out)
            }
            if sock.errEvent > 0 {
                fds[i].revents.insert(.err)
            }

            if !fds[i].revents.isEmpty {
                nReady += 1
            }
        }

        return nReady
    }

    // MARK: - ioctl() / fcntl()

    /// Control socket I/O.
    ///
    /// Supports two commands:
    /// - `IOControlCommand.fionRead` (`FIONREAD`): returns the number of bytes
    ///   available to read. For TCP sockets this includes both data already
    ///   buffered from previous receives and data available in the netconn.
    ///   For UDP/Raw sockets the value is the netconn receive-available count.
    /// - `IOControlCommand.fionBIO` (`FIONBIO`): when `value` is non-zero the
    ///   socket is switched to non-blocking mode; when zero it is switched to
    ///   blocking mode.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - cmd: I/O control command (`IOControlCommand.fionRead` or `IOControlCommand.fionBIO`).
    ///   - value: For `FIONREAD` the result is written here. For `FIONBIO` a
    ///     non-zero input enables non-blocking mode.
    /// - Returns: 0 on success, -1 on error.
    public func ioctl(_ s: Int32, cmd: Int, value: inout Int) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        switch cmd {
        case IOControlCommand.fionRead: // FIONREAD
            var recvAvail = max(0, conn.receiveAvailable)

            // Include data left over from the last recv operation.
            if let lastBuf = sock.lastData {
                if conn.type.isTCP, let pbuf = lastBuf as? Pbuf {
                    recvAvail += Int(pbuf.totalLength)
                } else if let netBuf = lastBuf as? NetBuf {
                    recvAvail += Int(netBuf.totalLength)
                }
            }
            value = recvAvail
            return 0

        case IOControlCommand.fionBIO: // FIONBIO
            conn.isNonBlocking = (value != 0)
            return 0

        default:
            return -1
        }
    }

    /// File control operations.
    ///
    /// A minimal implementation of POSIX `fcntl`. Currently supports `F_GETFL`
    /// and `F_SETFL`. For `F_GETFL`, returns `O_NONBLOCK` combined with the
    /// access mode (`O_RDONLY`, `O_WRONLY`, `O_RDWR`). For TCP sockets the
    /// access mode is derived from whether the connection is still readable
    /// and/or writable; for non-TCP sockets `O_RDWR` is always reported.
    ///
    /// For `F_SETFL`, only `O_NONBLOCK` is supported; the access mode bits in
    /// `val` are ignored as required by POSIX.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - cmd: Command (`FileControlCommand.getFlags` / `FileControlCommand.setFlags`).
    ///   - val: Value for `F_SETFL`.
    /// - Returns: Flags for `F_GETFL`, 0 for success on `F_SETFL`, -1 on error.
    public func fcntl(_ s: Int32, cmd: Int32, val: Int32) -> Int32 {
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        switch cmd {
        case FileControlCommand.getFlags: // F_GETFL
            var ret: Int32 = conn.isNonBlocking ? FileStatusFlags.nonBlock : 0

            var opMode: Int32 = 0
            if conn.type.isTCP {
                if let tcpPCB = conn.pcb?.tcpControlBlock {
                    if !tcpPCB.flags.contains(.rxClosed) {
                        opMode |= FileStatusFlags.readOnly
                    }
                    if !tcpPCB.flags.contains(.fin) {
                        opMode |= FileStatusFlags.writeOnly
                    }
                }
            } else {
                opMode = FileStatusFlags.readWrite
            }

            // Ensure O_RDWR for (O_RDONLY|O_WRONLY) != O_RDWR cases.
            if opMode == (FileStatusFlags.readOnly | FileStatusFlags.writeOnly),
               opMode != FileStatusFlags.readWrite {
                ret |= FileStatusFlags.readWrite
            } else {
                ret |= opMode
            }

            return ret

        case FileControlCommand.setFlags: // F_SETFL
            // Access mode bits are ignored per POSIX.
            let masked = val & ~(FileStatusFlags.readOnly | FileStatusFlags.writeOnly | FileStatusFlags.readWrite)
            // Only O_NONBLOCK is supported; reject any other bits.
            if (masked & ~FileStatusFlags.nonBlock) == 0 {
                conn.isNonBlocking = (masked & FileStatusFlags.nonBlock) != 0
                return 0
            }
            return -1

        default:
            return -1
        }
    }

    // MARK: - Event Callback

    /// Internal callback from NetConn events. Updates socket event counters
    /// and wakes select/poll waiters.
    private func eventCallback(conn: NetConn, event: NetconnEvent, length: UInt16) {
        guard let idx = conn.callbackArg as? Int,
              idx >= 0 && idx < LWIPSocket.maxSockets else { return }

        tableLock.lock()
        guard let sock = sockets[idx] else {
            tableLock.unlock()
            return
        }

        switch event {
        case .receiveReady:
            sock.rcvEvent += 1
        case .receiveDone:
            sock.rcvEvent = max(0, sock.rcvEvent - 1)
        case .sendReady:
            sock.sendEvent += 1
        case .sendFull:
            sock.sendEvent = 0
        case .error:
            sock.errEvent += 1
        }

        tableLock.unlock()

        // Wake up select/poll waiters.
        selectSemaphore.signal()
    }

    // MARK: - sendMessage() (sendmsg)

    /// Send a message on a socket using scatter/gather I/O.
    ///
    /// For TCP (stream) sockets, each I/O vector is sent sequentially via the
    /// existing write path. For UDP/Raw (datagram) sockets, all I/O vectors are
    /// combined into a single datagram before sending.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - msg: The message header containing destination, I/O vectors, and flags.
    ///   - flags: Additional message flags (e.g., `.dontWait`, `.more`).
    /// - Returns: Total number of bytes sent on success, or -1 on error.
    public func sendMessage(_ s: Int32, msg: MessageHeader, flags: MessageFlags = []) -> Int32 {
        guard !msg.iov.isEmpty else { return -1 }
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        // Validate that only supported flags are passed.
        let supportedFlags: MessageFlags = [.dontWait, .more]
        guard flags.isSubset(of: supportedFlags) else { return -1 }

        if conn.type.isTCP {
            // --- TCP: send each iov entry sequentially ---
            var writeFlags: NetconnWriteFlags = .copy
            if flags.contains(.more) {
                writeFlags.insert(.more)
            }
            if flags.contains(.dontWait) {
                writeFlags.insert(.dontBlock)
            }

            var totalWritten: Int = 0
            for iov in msg.iov {
                guard iov.length > 0 else { continue }
                let (err, written) = conn.write(UnsafeRawPointer(iov.base), size: iov.length, flags: writeFlags)
                if err != .ok {
                    // If we already sent some data, return that amount;
                    // otherwise propagate the error.
                    return totalWritten > 0 ? Int32(totalWritten) : -1
                }
                totalWritten += written
            }
            return Int32(totalWritten)
        } else {
            // --- UDP / Raw: combine all iov entries into a single datagram ---
            var totalSize = 0
            for iov in msg.iov {
                totalSize += iov.length
                guard totalSize <= Int(UInt16.max) else { return -1 }  // datagram too large
            }

            let buf = NetBuf()
            guard let payload = buf.alloc(size: UInt16(totalSize)) else { return -1 }

            // Copy all iov data into the contiguous buffer.
            var offset = 0
            for iov in msg.iov {
                guard iov.length > 0 else { continue }
                (payload + offset).copyMemory(from: UnsafeRawPointer(iov.base), byteCount: iov.length)
                offset += iov.length
            }

            // Send to the specified address, or the connected peer.
            let err: LWIPError
            if let dest = msg.name {
                err = conn.sendTo(buf, addr: dest.addr, port: dest.port)
            } else {
                err = conn.send(buf)
            }
            return err == .ok ? Int32(totalSize) : -1
        }
    }

    // MARK: - receiveMessage() (recvmsg)

    /// Receive a message from a socket using scatter/gather I/O.
    ///
    /// For TCP (stream) sockets, data is received sequentially into each I/O
    /// vector buffer. For UDP/Raw sockets, a single datagram is received and
    /// scattered across the I/O vector buffers.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - msg: The message header (modified in place with received data info).
    ///   - flags: Message flags (e.g., `.peek`, `.dontWait`).
    /// - Returns: Total number of bytes received on success, 0 on orderly shutdown, or -1 on error.
    public func receiveMessage(_ s: Int32, msg: inout MessageHeader, flags: MessageFlags = []) -> Int32 {
        guard !msg.iov.isEmpty else { return -1 }
        guard let sock = getSock(s), let conn = sock.conn else { return -1 }

        // Validate that only supported flags are passed.
        let supportedFlags: MessageFlags = [.peek, .dontWait]
        guard flags.isSubset(of: supportedFlags) else { return -1 }

        // Compute total buffer capacity across all iov entries.
        var totalCapacity = 0
        for iov in msg.iov {
            guard iov.length > 0 else { continue }
            totalCapacity += iov.length
        }
        guard totalCapacity > 0 else { return -1 }

        msg.flags = []

        if conn.type.isTCP {
            // --- TCP: receive into each iov sequentially ---
            // Connected sockets ignore msg_name per POSIX.
            var totalReceived: Int = 0
            for (index, iov) in msg.iov.enumerated() {
                guard iov.length > 0 else { continue }

                // After the first successful recv, use non-blocking for
                // subsequent vectors to avoid waiting indefinitely when
                // less data is available than total iov capacity.
                let recvFlags: MessageFlags = index == 0 ? flags : flags.union(.dontWait)
                let received = recvFrom(s, buffer: iov.base, size: iov.length,
                                        flags: recvFlags, from: nil)
                if received > 0 {
                    totalReceived += received
                }
                if received < 0 || received < iov.length || flags.contains(.peek) {
                    // Returned prematurely, or peeking (limited to first iov).
                    if totalReceived <= 0 {
                        return Int32(received)  // propagate error
                    }
                    break
                }
            }
            return Int32(totalReceived)
        } else {
            // --- UDP / Raw: receive one datagram and scatter across iov ---
            switch conn.receive() {
            case .success(let netBuf):
                let datagramLen = Int(netBuf.totalLength)

                // Fill in source address.
                msg.name = SockAddr(
                    family: netBuf.addr.isV4 ? .inet : .inet6,
                    addr: netBuf.addr,
                    port: netBuf.port
                )

                // Scatter the datagram data across the iov entries.
                var remaining = datagramLen
                var srcOffset: UInt16 = 0
                for iov in msg.iov {
                    guard remaining > 0 else { break }
                    let copyLen = min(iov.length, remaining)
                    _ = netBuf.copyPartial(to: iov.base, length: UInt16(copyLen), offset: srcOffset)
                    srcOffset += UInt16(copyLen)
                    remaining -= copyLen
                }

                // If the datagram was larger than the total iov capacity, flag truncation.
                if datagramLen > totalCapacity {
                    msg.flags.insert(.truncated)
                }

                if msg.control != nil {
                    msg.control = packetInfoControlData(for: netBuf) ?? []
                }

                sock.rcvEvent = max(0, sock.rcvEvent - 1)
                return Int32(min(datagramLen, totalCapacity))

            case .failure(let err):
                if err == .closed { return 0 }
                return -1
            }
        }
    }

    // MARK: - readVector() (readv)

    /// Read data from a socket into multiple buffers (scatter read).
    ///
    /// Equivalent to POSIX `readv`. Creates a `MessageHeader` from the I/O vectors
    /// and delegates to `receiveMessage`.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - iov: Array of I/O vectors to scatter data into.
    /// - Returns: Total number of bytes read on success, 0 on orderly shutdown, or -1 on error.
    public func readVector(_ s: Int32, iov: [IOVector]) -> Int32 {
        var msg = MessageHeader(iov: iov)
        return receiveMessage(s, msg: &msg)
    }

    // MARK: - writeVector() (writev)

    /// Write data from multiple buffers to a socket (gather write).
    ///
    /// Equivalent to POSIX `writev`. Creates a `MessageHeader` from the I/O vectors
    /// and delegates to `sendMessage`.
    ///
    /// - Parameters:
    ///   - s: Socket file descriptor.
    ///   - iov: Array of I/O vectors containing data to send.
    /// - Returns: Total number of bytes written on success, or -1 on error.
    public func writeVector(_ s: Int32, iov: [IOVector]) -> Int32 {
        let msg = MessageHeader(iov: iov)
        return sendMessage(s, msg: msg)
    }
}

// MARK: - Address String Conversion

extension LWIPSocket {

    /// Convert a binary IP address to a human-readable string.
    ///
    /// Equivalent to POSIX `inet_ntop`.
    ///
    /// - Parameters:
    ///   - af: Address family (`.inet` for IPv4, `.inet6` for IPv6).
    ///   - address: The IP address to convert.
    /// - Returns: String representation, or `nil` if the address family does not
    ///   match the address type or is unsupported.
    public static func inetNtop(_ af: AddressFamily, address: IPAddress) -> String? {
        switch af {
        case .inet:
            // Accept .v4 directly, or extract the IPv4 portion of an IPv4-mapped IPv6.
            if let v4 = address.ipv4 {
                return v4.description
            }
            if let v6 = address.ipv6, v6.isIPv4Mapped {
                return v6.mappedIPv4.description
            }
            return nil

        case .inet6:
            if let v6 = address.ipv6 {
                return v6.description
            }
            // Wrap an IPv4 address as IPv4-mapped IPv6 when asked for inet6 output.
            if let v4 = address.ipv4 {
                return IPv6Address.ipv4Mapped(v4).description
            }
            return nil

        default:
            return nil
        }
    }

    /// Parse a human-readable IP address string into a binary address.
    ///
    /// Equivalent to POSIX `inet_pton`.
    ///
    /// Unlike the BSD `inet_aton` family, this function enforces strict
    /// formatting rules consistent with `inet_pton(3)`:
    ///
    /// - **IPv4** (`af == .inet`): Only the standard four-octet dotted-decimal
    ///   form `d.d.d.d` is accepted. Each octet must be a plain decimal number
    ///   in 0...255 with no leading zeros (except the single digit `0` itself).
    ///   Hex prefixes, octal prefixes, and short forms like `a.b` or `a.b.c`
    ///   are rejected.
    ///
    /// - **IPv6** (`af == .inet6`): Standard colon-hex notation including `::`
    ///   zero compression and `%zone` suffixes is accepted. IPv4-mapped forms
    ///   such as `::ffff:192.168.1.1` are also supported.
    ///
    /// - Parameters:
    ///   - af: Address family (`.inet` for IPv4, `.inet6` for IPv6).
    ///   - src: The string to parse.
    /// - Returns: The parsed `IPAddress`, or `nil` if parsing fails or the
    ///   address family is unsupported.
    public static func inetPton(_ af: AddressFamily, src: String) -> IPAddress? {
        switch af {
        case .inet:
            return parseStrictIPv4(src)

        case .inet6:
            guard let v6 = IPv6Address(src) else { return nil }
            return .v6(v6)

        default:
            return nil
        }
    }

    // MARK: - Swift-Idiomatic Address Conversion

    /// Convert a binary IP address to a human-readable string.
    ///
    /// Swift-idiomatic wrapper for ``inetNtop(_:address:)``.
    public static func addressToString(_ af: AddressFamily, address: IPAddress) -> String? {
        return inetNtop(af, address: address)
    }

    /// Parse a human-readable IP address string into a binary address.
    ///
    /// Swift-idiomatic wrapper for ``inetPton(_:src:)``.
    public static func stringToAddress(_ af: AddressFamily, src: String) -> IPAddress? {
        return inetPton(af, src: src)
    }

    // MARK: - Strict IPv4 parser (inetPton semantics)

    /// Parse an IPv4 address in strict `inetPton` form: exactly four
    /// decimal octets separated by dots, no leading zeros, no hex/octal,
    /// no short forms.
    private static func parseStrictIPv4(_ src: String) -> IPAddress? {
        let utf8 = Array(src.utf8)
        var index = 0
        var octets: [UInt8] = []
        octets.reserveCapacity(4)

        while octets.count < 4 {
            // Must start with a digit.
            guard index < utf8.count, utf8[index].isASCIIDigit else { return nil }

            // Accumulate the decimal value, watching for leading zeros.
            let start = index
            var value: Int = 0
            while index < utf8.count, utf8[index].isASCIIDigit {
                value = value * 10 + Int(utf8[index] - UInt8(ascii: "0"))
                index += 1
                // Early exit if value already too large.
                if value > 255 { return nil }
            }

            // Reject leading zeros (e.g. "01", "007") but allow bare "0".
            let digitCount = index - start
            if digitCount > 1 && utf8[start] == UInt8(ascii: "0") { return nil }

            octets.append(UInt8(value))

            // After the first three octets we expect a dot; after the fourth
            // we expect end-of-string.
            if octets.count < 4 {
                guard index < utf8.count, utf8[index] == UInt8(ascii: ".") else { return nil }
                index += 1  // consume the dot
            }
        }

        // Must have consumed the entire string.
        guard index == utf8.count else { return nil }

        return .v4(IPv4Address(octets[0], octets[1], octets[2], octets[3]))
    }
}
