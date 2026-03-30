//
//  AltcpProxyConnect.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Proxy Connect Configuration

/// Configuration for the HTTP CONNECT proxy.
public final class AltcpProxyConnectConfig: @unchecked Sendable {
    /// Proxy server IP address.
    public var proxyAddress: IPAddress
    /// Proxy server TCP port.
    public var proxyPort: UInt16

    public init(proxyAddress: IPAddress, proxyPort: UInt16) {
        self.proxyAddress = proxyAddress
        self.proxyPort = proxyPort
    }
}

/// Combined proxy and TLS configuration for tunneling TLS through an HTTP proxy.
public final class AltcpProxyConnectTLSConfig: @unchecked Sendable {
    /// Proxy configuration.
    public var proxy: AltcpProxyConnectConfig
    /// TLS configuration for the inner encrypted connection.
    public var tlsConfig: AnyObject?

    public init(proxy: AltcpProxyConnectConfig, tlsConfig: AnyObject? = nil) {
        self.proxy = proxy
        self.tlsConfig = tlsConfig
    }
}

// MARK: - Proxy Connect Constants

/// Internal constants for the proxy connect layer.
internal enum AltcpProxyConnectConstants {
    /// User-Agent string sent in the CONNECT request.
    static let clientAgent = "lwIP/2.2.0 (Swift)"
    /// The HTTP response terminator we look for.
    static let headerTerminator: [UInt8] = Array("\r\n\r\n".utf8)
}

// MARK: - Proxy Connect State Flags

/// Internal state flags for the proxy connect layer.
internal struct AltcpProxyConnectFlags: OptionSet {
    let rawValue: UInt8

    /// CONNECT request has been sent to the proxy.
    static let connectStarted  = AltcpProxyConnectFlags(rawValue: 0x01)
    /// Proxy responded with success; tunnel is established.
    static let handshakeDone   = AltcpProxyConnectFlags(rawValue: 0x02)
}

// MARK: - Proxy Connect State

/// Internal state for a proxy connect layer instance.
internal final class AltcpProxyConnectState: @unchecked Sendable {
    /// The actual destination address (the address the application wants to reach).
    var outerAddress: IPAddress = .any
    /// The actual destination port.
    var outerPort: UInt16 = 0
    /// Reference to the proxy configuration.
    var config: AltcpProxyConnectConfig?
    /// Connection state flags.
    var flags: AltcpProxyConnectFlags = []
}

// MARK: - Proxy Connect Functions (altcp layer)

/// AltcpFunctions implementation for the HTTP CONNECT proxy layer.
///
/// This layer intercepts the connection phase to connect to the proxy first,
/// sends an HTTP CONNECT request, and once the proxy responds with success,
/// transparently passes data between the application and the proxy tunnel.
public final class AltcpProxyConnectFunctions: AltcpFunctions {

    public static let shared = AltcpProxyConnectFunctions()

    private init() {}

    // MARK: - AltcpFunctions Implementation

    public func setPoll(_ conn: AltcpControlBlock, interval: UInt8) {
        conn.innerConn?.setPoll(conn.pollFn, interval: interval)
    }

    public func recved(_ conn: AltcpControlBlock, len: UInt16) {
        guard let state = conn.state as? AltcpProxyConnectState else { return }
        guard state.flags.contains(.handshakeDone) else { return }
        conn.innerConn?.recved(len)
    }

    public func bind(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16) -> LWIPError {
        return conn.innerConn?.bind(ipaddr: ipaddr, port: port) ?? .invalidValue
    }

    /// Connect through the proxy.
    ///
    /// Instead of connecting to the requested address directly, we connect to
    /// the proxy server and store the actual destination for the CONNECT request.
    public func connect(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16,
                        connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError {
        guard let state = conn.state as? AltcpProxyConnectState,
              let config = state.config,
              let ipaddr = ipaddr else {
            return .invalidValue
        }

        guard !state.flags.contains(.connectStarted) else {
            return .invalidValue
        }
        state.flags.insert(.connectStarted)

        // Save the application's connected callback
        conn.connectedFn = connected

        // Store the actual destination for the CONNECT request
        state.outerAddress = ipaddr
        state.outerPort = port

        // Connect to the proxy instead
        return conn.innerConn?.connect(
            ipaddr: config.proxyAddress,
            port: config.proxyPort,
            connected: { [weak conn] arg, innerConn, err in
                guard let conn = conn else { return .invalidValue }
                return AltcpProxyConnectFunctions.lowerConnected(conn: conn, err: err)
            }
        ) ?? .invalidValue
    }

    public func listen(_ conn: AltcpControlBlock, backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock? {
        // Listen is not supported through a proxy
        return nil
    }

    public func abort(_ conn: AltcpControlBlock) {
        conn.innerConn?.abort()
        conn.free()
    }

    public func close(_ conn: AltcpControlBlock) -> LWIPError {
        if let inner = conn.innerConn {
            let err = inner.close()
            if err != .ok {
                return err
            }
        }
        conn.free()
        return .ok
    }

    public func shutdown(_ conn: AltcpControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError {
        if shutRx && shutTx {
            return close(conn)
        }
        return conn.innerConn?.shutdown(rx: shutRx, tx: shutTx) ?? .invalidValue
    }

    public func write(_ conn: AltcpControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError {
        guard let state = conn.state as? AltcpProxyConnectState else { return .closed }
        guard state.flags.contains(.handshakeDone) else { return .invalidValue }
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
        if let _ = conn.state as? AltcpProxyConnectState {
            conn.state = nil
        }
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

    // MARK: - Internal Callbacks from Lower Connection

    /// Called when the connection to the proxy is established.
    /// Sends the HTTP CONNECT request.
    private static func lowerConnected(conn: AltcpControlBlock, err: LWIPError) -> LWIPError {
        guard let state = conn.state as? AltcpProxyConnectState else { return .invalidValue }

        if err != .ok {
            // Connection to proxy failed, notify application
            if let connected = conn.connectedFn {
                _ = connected(conn.arg, conn, err)
            }
            return .ok
        }

        // Send the HTTP CONNECT request
        return sendConnectRequest(conn: conn, state: state)
    }

    /// Format and send the HTTP CONNECT request to the proxy.
    private static func sendConnectRequest(conn: AltcpControlBlock,
                                            state: AltcpProxyConnectState) -> LWIPError {
        let host = state.outerAddress.description
        let port = state.outerPort

        let request = "CONNECT \(host):\(port) HTTP/1.1\r\n" +
                      "User-Agent: \(AltcpProxyConnectConstants.clientAgent)\r\n" +
                      "Proxy-Connection: keep-alive\r\n" +
                      "Connection: keep-alive\r\n" +
                      "\r\n"

        let bytes = Array(request.utf8)
        return bytes.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return LWIPError.outOfMemory }
            return conn.innerConn?.write(
                UnsafeRawPointer(base),
                len: UInt16(min(bytes.count, Int(UInt16.max))),
                apiFlags: TCPConstants.writeFlagCopy
            ) ?? .invalidValue
        }
    }

    /// Called when data is received from the lower connection (proxy).
    /// During handshake, looks for the end of the HTTP response headers.
    /// After handshake, passes data through to the application.
    internal static func lowerRecv(conn: AltcpControlBlock, pbuf: Pbuf?, err: LWIPError) -> LWIPError {
        guard let state = conn.state as? AltcpProxyConnectState else {
            if let p = pbuf { _ = Pbuf.free(p) }
            conn.innerConn?.close()
            return .closed
        }

        if state.flags.contains(.handshakeDone) {
            // Application phase: pass data through
            if let recv = conn.recvFn {
                return recv(conn.arg, conn, pbuf, err)
            }
            if let p = pbuf { _ = Pbuf.free(p) }
            return .ok
        } else {
            // Setup phase: waiting for proxy response
            guard let p = pbuf else {
                // Connection closed during setup
                conn.close()
                return .ok
            }

            // Look for the end of HTTP headers (\r\n\r\n)
            let readLen = Int(p.totLen)
            var bytes = [UInt8](repeating: 0, count: readLen)
            bytes.withUnsafeMutableBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = p.copyPartial(to: UnsafeMutableRawPointer(base),
                                  len: p.totLen, offset: 0)
            }
            conn.innerConn?.recved(p.totLen)
            _ = Pbuf.free(p)

            // Search for header terminator
            let terminator = AltcpProxyConnectConstants.headerTerminator
            if findSubsequence(in: bytes, pattern: terminator) {
                state.flags.insert(.handshakeDone)
                // Notify the application that the tunnel is established
                if let connected = conn.connectedFn {
                    return connected(conn.arg, conn, .ok)
                }
            }

            return .ok
        }
    }

    /// Called when data has been sent (acknowledged) on the lower connection.
    internal static func lowerSent(conn: AltcpControlBlock, len: UInt16) -> LWIPError {
        guard let state = conn.state as? AltcpProxyConnectState else { return .ok }

        if !state.flags.contains(.handshakeDone) {
            // Still in setup phase, ignore ACKs
            return .ok
        }

        // Pass to application
        if let sent = conn.sentFn {
            return sent(conn.arg, conn, len)
        }
        return .ok
    }

    /// Poll callback from the lower connection.
    internal static func lowerPoll(conn: AltcpControlBlock) -> LWIPError {
        if let poll = conn.pollFn {
            return poll(conn.arg, conn)
        }
        return .ok
    }

    /// Error callback from the lower connection.
    internal static func lowerErr(conn: AltcpControlBlock, err: LWIPError) {
        conn.innerConn = nil  // Already freed
        conn.errFn?(conn.arg, err)
        conn.free()
    }

    /// Search for a byte pattern in a byte array.
    private static func findSubsequence(in data: [UInt8], pattern: [UInt8]) -> Bool {
        guard pattern.count <= data.count else { return false }
        for i in 0...(data.count - pattern.count) {
            if Array(data[i..<(i + pattern.count)]) == pattern {
                return true
            }
        }
        return false
    }
}

// MARK: - Factory Functions

extension AltcpControlBlock {

    /// Create a new altcp PCB that connects through an HTTP proxy.
    ///
    /// - Parameters:
    ///   - config: Proxy configuration.
    ///   - innerPCB: The inner (lower-layer) PCB, typically a TCP connection.
    /// - Returns: A new altcp PCB configured for proxy connect, or nil on failure.
    public static func proxyConnect(config: AltcpProxyConnectConfig,
                                     innerPCB: AltcpControlBlock) -> AltcpControlBlock? {
        let conn = AltcpControlBlock()
        let state = AltcpProxyConnectState()
        state.config = config

        // Set up callbacks on the inner connection
        setupProxyCallbacks(conn: conn, inner: innerPCB)

        conn.innerConn = innerPCB
        conn.fns = AltcpProxyConnectFunctions.shared
        conn.state = state
        return conn
    }

    /// Create a new altcp PCB connecting through an HTTP proxy using TCP.
    ///
    /// Creates the inner TCP PCB automatically.
    ///
    /// - Parameters:
    ///   - config: Proxy configuration.
    ///   - ipType: IP address type (0 for IPv4, 6 for IPv6).
    /// - Returns: A new proxy-connected altcp PCB, or nil on failure.
    public static func proxyConnectTCP(config: AltcpProxyConnectConfig,
                                        ipType: UInt8 = 0) -> AltcpControlBlock? {
        guard let innerPCB = AltcpTCPFunctions.createForIPType(ipType) else {
            return nil
        }
        guard let conn = proxyConnect(config: config, innerPCB: innerPCB) else {
            innerPCB.close()
            return nil
        }
        return conn
    }

    /// Allocator function for use with `AltcpControlBlock.create(allocator:)`.
    ///
    /// The allocator argument should be an `AltcpProxyConnectConfig`.
    public static func proxyConnectAllocator(arg: AnyObject?, ipType: UInt8) -> AltcpControlBlock? {
        guard let config = arg as? AltcpProxyConnectConfig else { return nil }
        return proxyConnectTCP(config: config, ipType: ipType)
    }

    /// Allocator for a TLS connection tunneled through an HTTP proxy.
    ///
    /// Creates a chain: altcp_tls -> altcp_proxyconnect -> altcp_tcp -> tcp
    /// The allocator argument should be an `AltcpProxyConnectTLSConfig`.
    public static func proxyConnectTLSAllocator(arg: AnyObject?, ipType: UInt8) -> AltcpControlBlock? {
        guard let config = arg as? AltcpProxyConnectTLSConfig else { return nil }
        guard let proxyPCB = proxyConnectTCP(config: config.proxy, ipType: ipType) else {
            return nil
        }
        return proxyPCB
    }

    /// Set up proxy connect callbacks on an inner connection.
    private static func setupProxyCallbacks(conn: AltcpControlBlock, inner: AltcpControlBlock) {
        inner.setArg(conn)
        inner.setRecv { arg, innerConn, pbuf, err in
            guard let outerConn = arg as? AltcpControlBlock else {
                if let p = pbuf { _ = Pbuf.free(p) }
                return .closed
            }
            return AltcpProxyConnectFunctions.lowerRecv(conn: outerConn, pbuf: pbuf, err: err)
        }
        inner.setSent { arg, innerConn, len in
            guard let outerConn = arg as? AltcpControlBlock else { return .ok }
            return AltcpProxyConnectFunctions.lowerSent(conn: outerConn, len: len)
        }
        inner.setErr { arg, err in
            guard let outerConn = arg as? AltcpControlBlock else { return }
            AltcpProxyConnectFunctions.lowerErr(conn: outerConn, err: err)
        }
    }
}
