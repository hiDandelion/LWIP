//
//  LwIPerf.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - LwIPerf Configuration

/// LwIPerf configuration constants.
public enum LwIPerfConfig {
    /// Default TCP port for iPerf tests.
    public static let defaultPort: UInt16 = 5001
    /// Maximum idle seconds before aborting a test.
    public static var maxIdleSeconds: UInt8 = 10
    /// Whether to verify received data patterns.
    public static var checkReceivedData: Bool = false
    /// Size of the constant transmit buffer.
    public static let transmitBufferSize: Int = 1600
    /// Default UDP datagram size (matches iPerf2 default).
    public static let udpDefaultDatagramSize: UInt16 = 1470
    /// Default UDP bandwidth target in bits per second (1 Mbit/s).
    public static let udpDefaultBandwidthBps: UInt64 = 1_000_000
    /// UDP client send interval in milliseconds.
    public static let udpClientSendIntervalMs: UInt32 = 10
    /// UDP maximum idle milliseconds before declaring test done on server side.
    public static let udpMaxIdleMs: UInt32 = 10_000
    /// Number of finish datagrams the client sends at the end.
    public static let udpFinishDatagramCount: Int = 10
}

// MARK: - LwIPerf Report Type

/// Result type reported when an iPerf session finishes.
public enum LwIPerfReportType: Int, Sendable, CustomStringConvertible {
    /// The server side test completed successfully.
    case tcpDoneServer              = 0
    /// The client side test completed successfully.
    case tcpDoneClient              = 1
    /// Local error caused the test to abort.
    case tcpAbortedLocal            = 2
    /// Data verification error caused the test to abort.
    case tcpAbortedLocalDataError   = 3
    /// Transmit error caused the test to abort.
    case tcpAbortedLocalTxError     = 4
    /// Remote side aborted the test.
    case tcpAbortedRemote           = 5
    /// The UDP server side test completed successfully.
    case udpDoneServer              = 6
    /// The UDP client side test completed successfully.
    case udpDoneClient              = 7
    /// Local error caused the UDP test to abort.
    case udpAbortedLocal            = 8
    /// Remote side aborted the UDP test.
    case udpAbortedRemote           = 9

    public var description: String {
        switch self {
        case .tcpDoneServer:            return "TCP_DONE_SERVER"
        case .tcpDoneClient:            return "TCP_DONE_CLIENT"
        case .tcpAbortedLocal:          return "TCP_ABORTED_LOCAL"
        case .tcpAbortedLocalDataError: return "TCP_ABORTED_LOCAL_DATAERROR"
        case .tcpAbortedLocalTxError:   return "TCP_ABORTED_LOCAL_TXERROR"
        case .tcpAbortedRemote:         return "TCP_ABORTED_REMOTE"
        case .udpDoneServer:            return "UDP_DONE_SERVER"
        case .udpDoneClient:            return "UDP_DONE_CLIENT"
        case .udpAbortedLocal:          return "UDP_ABORTED_LOCAL"
        case .udpAbortedRemote:         return "UDP_ABORTED_REMOTE"
        }
    }
}

// MARK: - LwIPerf Client Type

/// iPerf client test modes.
public enum LwIPerfClientType: Int, Sendable {
    /// Unidirectional transmit-only test.
    case client   = 0
    /// Bidirectional test running simultaneously.
    case dual     = 1
    /// Bidirectional test running one direction at a time.
    case tradeoff = 2
}

// MARK: - Callback Types

extension LwIPerfServer {
    /// Report callback invoked when an iPerf session completes.
    ///
    /// - Parameters:
    ///   - reportType: The result of the test.
    ///   - localAddress: Local IP address for the session.
    ///   - localPort: Local TCP port.
    ///   - remoteAddress: Remote IP address.
    ///   - remotePort: Remote TCP port.
    ///   - bytesTransferred: Total bytes transferred during the test.
    ///   - durationMs: Test duration in milliseconds.
    ///   - bandwidthKbps: Average bandwidth in kilobits per second.
    public typealias ReportHandler = @Sendable (
        LwIPerfReportType,
        IPAddress, UInt16,
        IPAddress, UInt16,
        UInt32, UInt32, UInt32
    ) -> Void
}

// MARK: - LwIPerf Settings

/// iPerf protocol settings exchanged between client and server (24 bytes).
internal struct LwIPerfSettings {
    /// Flags field (controls test mode).
    static let flagsAnswerTest: UInt32 = 0x8000_0000
    static let flagsAnswerNow: UInt32  = 0x0000_0001

    var flags: UInt32 = 0
    var numThreads: UInt32 = 0
    var remotePort: UInt32 = 0
    var bufferLength: UInt32 = 0
    var windowBandwidth: UInt32 = 0
    /// Positive: bytes to transfer; negative: time in 10ms units.
    var amount: Int32 = 0

    static let size = 24
}

// MARK: - LwIPerf Session Base

/// Base protocol for iPerf sessions (linked list management).
internal class LwIPerfSessionBase: @unchecked Sendable {
    /// Next session in the active list.
    var next: LwIPerfSessionBase?
    /// Whether this is a TCP session.
    var isTCP: Bool = true
    /// Whether this session is a server (true) or client (false).
    var isServer: Bool = false
    /// Master session reference for aborting related sessions.
    weak var relatedMasterState: LwIPerfSessionBase?
}

// MARK: - LwIPerf TCP Session

/// TCP iPerf session state.
internal final class LwIPerfTCPSession: LwIPerfSessionBase, @unchecked Sendable {
    /// The listening TCP PCB (for server sessions).
    var serverPCB: TCPControlBlock?
    /// The connected TCP PCB.
    var connectionPCB: TCPControlBlock?
    /// Timestamp when the test started (ms).
    var timeStarted: UInt32 = 0
    /// Report callback.
    var reportHandler: LwIPerfServer.ReportHandler?
    /// Opaque report argument (unused in Swift, kept for API compat).
    var reportArg: AnyObject?
    /// Poll timeout counter.
    var pollCount: UInt8 = 0
    /// Expected next data byte number (for verification).
    var nextNumber: UInt8 = 0
    /// Whether this is a tradeoff-mode client.
    var clientTradeoffMode: Bool = false
    /// Total bytes transferred.
    var bytesTransferred: UInt32 = 0
    /// iPerf protocol settings received from the peer.
    var settings: LwIPerfSettings = LwIPerfSettings()
    /// Whether settings have been received.
    var hasSettingsBuffer: Bool = false
    /// Whether this server listener is for a specific remote address.
    var specificRemote: Bool = false
    /// Expected remote address for a specific-remote listener.
    var remoteAddress: IPAddress = .any
}

// MARK: - LwIPerf UDP Datagram Header

/// iPerf2-compatible UDP datagram header (16 bytes).
///
/// Each UDP datagram from the client begins with this header.
/// The server uses sequence numbers to detect loss and reordering,
/// and timestamps to compute jitter per RFC 1889.
///
/// Layout (network byte order):
/// ```
/// Offset  Size  Field
///   0       4   sequenceNumber (signed; negative = finish datagram)
///   4       4   seconds        (tv_sec of send timestamp)
///   8       4   microseconds   (tv_usec of send timestamp)
///  12       4   errorCount     (reserved, set to 0 by clients)
///  16       4   outOfOrderCount(reserved, set to 0 by clients)
///  20       4   datagramCount  (reserved, set to 0 by clients)
///  24       4   jitter1        (reserved, set to 0 by clients)
///  28       4   jitter2        (reserved, set to 0 by clients)
/// ```
internal struct LwIPerfUDPDatagram {
    /// Sequence number. Negative values indicate a finish datagram.
    var sequenceNumber: Int32 = 0
    /// Seconds component of the send timestamp.
    var seconds: UInt32 = 0
    /// Microseconds component of the send timestamp.
    var microseconds: UInt32 = 0

    /// Size of the core datagram header (first 12 bytes used for send).
    static let headerSize = 12
}

/// iPerf2-compatible server report header appended to finish ack datagrams (24 bytes).
///
/// When the server receives a finish datagram (negative sequence number),
/// it sends back a single datagram containing both the original 12-byte
/// header and this 24-byte report.
internal struct LwIPerfUDPServerReport {
    /// Flags (currently unused, set to 0).
    var flags: UInt32 = 0
    /// Total bytes received by the server.
    var totalBytes1: UInt32 = 0
    var totalBytes2: UInt32 = 0
    /// Total duration in seconds.
    var durationSeconds: UInt32 = 0
    /// Total duration microseconds remainder.
    var durationMicroseconds: UInt32 = 0
    /// Count of out-of-order datagrams.
    var outOfOrderCount: UInt32 = 0
    /// Count of lost datagrams.
    var lostCount: UInt32 = 0
    /// Total datagrams expected.
    var totalDatagrams: UInt32 = 0
    /// Jitter in seconds.
    var jitterSeconds: UInt32 = 0
    /// Jitter in microseconds.
    var jitterMicroseconds: UInt32 = 0

    /// Size of the server report structure (40 bytes).
    static let size = 40
}

// MARK: - LwIPerf UDP Session

/// UDP iPerf session state.
internal final class LwIPerfUDPSession: LwIPerfSessionBase, @unchecked Sendable {
    /// The UDP PCB for this session.
    var udpPCB: UDPControlBlock?
    /// Timestamp when the test started (ms).
    var timeStarted: UInt32 = 0
    /// Timestamp of last received datagram (ms), used for idle detection.
    var lastReceiveTime: UInt32 = 0
    /// Report callback.
    var reportHandler: LwIPerfServer.ReportHandler?
    /// Total bytes transferred.
    var bytesTransferred: UInt32 = 0
    /// Total datagrams sent or received.
    var datagramCount: UInt32 = 0
    /// Next sequence number for client sending.
    var nextSequenceNumber: Int32 = 1
    /// Highest sequence number received (server side).
    var highestSequenceReceived: Int32 = 0
    /// Count of out-of-order datagrams (server side).
    var outOfOrderCount: UInt32 = 0
    /// Count of lost datagrams (server side).
    var lostCount: UInt32 = 0
    /// Running jitter estimate in microseconds (server side, RFC 1889).
    var jitterMicroseconds: UInt64 = 0
    /// Timestamp of previous received datagram in microseconds (for jitter calc).
    var previousReceiveTimeMicroseconds: UInt64 = 0
    /// Previous datagram send timestamp in microseconds (for jitter calc).
    var previousSendTimeMicroseconds: UInt64 = 0
    /// Remote address for the current test peer.
    var remoteAddress: IPAddress = .any
    /// Remote port for the current test peer.
    var remotePort: UInt16 = 0
    /// Whether we have a connected peer (server side).
    var hasPeer: Bool = false
    /// Whether the test is finished (finish datagram received).
    var finished: Bool = false
    /// iPerf settings (for client mode).
    var settings: LwIPerfSettings = LwIPerfSettings()
    /// Bandwidth target in bits per second (client mode).
    var bandwidthTargetBps: UInt64 = LwIPerfConfig.udpDefaultBandwidthBps
    /// Datagram payload size (client mode).
    var datagramSize: UInt16 = LwIPerfConfig.udpDefaultDatagramSize
    /// Bytes sent in the current send interval (for pacing).
    var bytesSentInInterval: UInt64 = 0
    /// Start time of the current send interval (ms).
    var intervalStartTime: UInt32 = 0
    /// Test duration in milliseconds (client mode). 0 means unlimited.
    var testDurationMs: UInt32 = 10_000
}

// MARK: - LwIPerf Server

/// iPerf-compatible TCP and UDP server for bandwidth measurement.
///
/// Listens for incoming iPerf client connections and measures receive bandwidth.
/// Reports results through a callback when each session completes.
///
/// Usage:
/// ```swift
/// let server = LwIPerfServer()
/// server.start { type, lAddr, lPort, rAddr, rPort, bytes, ms, kbps in
///     print("Test done: \(bytes) bytes in \(ms)ms = \(kbps) kbit/s")
/// }
/// // ...later...
/// server.stop()
/// ```
public final class LwIPerfServer: @unchecked Sendable {

    // MARK: - Properties

    /// List of all active iPerf sessions.
    private var allSessions: LwIPerfSessionBase?

    /// The constant transmit buffer used for client-mode sends.
    /// Uses a repeating '0'-'9' pattern matching the original iPerf protocol.
    private static let transmitBuffer: [UInt8] = {
        var buf = [UInt8](repeating: 0, count: LwIPerfConfig.transmitBufferSize)
        for i in 0..<buf.count {
            buf[i] = UInt8(ascii: "0") + UInt8(i % 10)
        }
        return buf
    }()

    /// Lock for thread safety.
    private let lock = NSLock()

    // MARK: - Initialization

    /// Create a new LwIPerf server.
    public init() {}

    deinit {
        stop()
    }

    // MARK: - Server Lifecycle

    /// Start both TCP and UDP iPerf servers on the default port (5001).
    ///
    /// - Parameter reportHandler: Callback invoked when each test session completes.
    /// - Returns: True if at least one server started successfully.
    @discardableResult
    public func start(reportHandler: @escaping ReportHandler) -> Bool {
        let tcp = startTCPServer(address: .any, port: LwIPerfConfig.defaultPort,
                                 reportHandler: reportHandler)
        let udp = startUDPServer(address: .any, port: LwIPerfConfig.defaultPort,
                                 reportHandler: reportHandler)
        return tcp || udp
    }

    /// Start a TCP iPerf server on a specific address and port.
    ///
    /// - Parameters:
    ///   - address: The local IP address to bind to.
    ///   - port: The local TCP port to bind to.
    ///   - reportHandler: Callback invoked when each test session completes.
    /// - Returns: True if the server started successfully.
    @discardableResult
    public func startTCPServer(address: IPAddress,
                                port: UInt16,
                                reportHandler: @escaping ReportHandler) -> Bool {
        return startTCPServerImpl(address: address, port: port,
                                  reportHandler: reportHandler,
                                  relatedMasterState: nil) != nil
    }

    /// Internal server start implementation that returns the session for linking.
    private func startTCPServerImpl(address: IPAddress,
                                     port: UInt16,
                                     reportHandler: @escaping ReportHandler,
                                     relatedMasterState: LwIPerfSessionBase?) -> LwIPerfTCPSession? {
        lock.lock()
        defer { lock.unlock() }

        let session = LwIPerfTCPSession()
        session.isTCP = true
        session.isServer = true
        session.relatedMasterState = relatedMasterState
        session.reportHandler = reportHandler

        // Create a TCP PCB and bind it.
        let pcb = TCPControlBlock()
        let bindErr = TCPGlobal.shared.bind(pcb: pcb, address: address, port: port)
        if bindErr != .ok {
            return nil
        }

        // Listen with backlog of 1.
        guard let listenPCB = TCPGlobal.shared.listen(pcb: pcb, backlog: 1) else {
            _ = TCPGlobal.shared.close(pcb: pcb)
            return nil
        }

        // Set up accept callback.
        listenPCB.callbackArg = session as AnyObject
        TCPGlobal.shared.accept(lpcb: listenPCB) { [weak self] lpcb, newPCB, err in
            guard let self = self else { return .invalidValue }
            return self.handleAccept(listenerSession: session, newPCB: newPCB, err: err)
        }

        session.serverPCB = pcb
        addSession(session)
        return session
    }

    /// Handle an incoming TCP connection for an iPerf server.
    private func handleAccept(listenerSession: LwIPerfTCPSession,
                               newPCB: TCPControlBlock?,
                               err: LWIPError) -> LWIPError {
        guard err == .ok, let newPCB = newPCB else { return .invalidValue }

        // If this listener is for a specific remote, verify the address.
        if listenerSession.specificRemote {
            if newPCB.remoteIP != listenerSession.remoteAddress {
                return .invalidValue
            }
        }

        lock.lock()

        let conn = LwIPerfTCPSession()
        conn.isTCP = true
        conn.isServer = true
        conn.relatedMasterState = listenerSession
        conn.connectionPCB = newPCB
        conn.timeStarted = currentTimeMs()
        conn.reportHandler = listenerSession.reportHandler

        // Set up TCP callbacks on the new connection PCB.
        setupTCPCallbacks(session: conn, pcb: newPCB)

        // Handle specific-remote listeners (dual/tradeoff mode).
        if listenerSession.specificRemote {
            conn.relatedMasterState = listenerSession.relatedMasterState
            if !listenerSession.clientTradeoffMode || findSession(listenerSession.relatedMasterState!) == nil {
                // Close the listener since it was a one-shot.
                listenerSession.reportHandler = nil  // Prevent report on expected close.
                closeTCPSession(listenerSession, reportType: .tcpAbortedLocal)
            }
        }

        addSession(conn)
        lock.unlock()
        return .ok
    }

    /// Wire up TCP receive, poll, sent, and error callbacks on a session.
    private func setupTCPCallbacks(session: LwIPerfTCPSession, pcb: TCPControlBlock) {
        pcb.receiveHandler = { [weak self] _, pbuf, err in
            guard let self = self else { return .invalidValue }
            return self.handleReceive(session: session, pbuf: pbuf)
        }

        pcb.pollHandler = { [weak self] _ in
            guard let self = self else { return .ok }
            return self.handlePoll(session: session)
        }
        pcb.pollInterval = 2

        pcb.sentHandler = { [weak self] _, len in
            guard let self = self else { return .ok }
            session.pollCount = 0
            if !session.isServer {
                self.sendMoreClientData(session: session)
            }
            return .ok
        }

        pcb.errorHandler = { [weak self] _ in
            guard let self = self else { return }
            self.handleError(session: session)
        }
    }

    /// Stop all running iPerf sessions and the server.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }

        var session = allSessions
        while let current = session {
            let next = current.next
            if let tcpSession = current as? LwIPerfTCPSession {
                closeTCPSession(tcpSession, reportType: .tcpAbortedLocal)
            } else if let udpSession = current as? LwIPerfUDPSession {
                closeUDPSession(udpSession, reportType: .udpAbortedLocal)
            }
            session = next
        }
        allSessions = nil
    }

    /// Abort a specific iPerf session.
    public func abort(session: AnyObject) {
        lock.lock()
        defer { lock.unlock() }

        if let tcpSession = session as? LwIPerfTCPSession {
            closeTCPSession(tcpSession, reportType: .tcpAbortedLocal)
        } else if let udpSession = session as? LwIPerfUDPSession {
            closeUDPSession(udpSession, reportType: .udpAbortedLocal)
        }
    }

    // MARK: - Client

    /// Start a TCP iPerf client connecting to a remote server.
    ///
    /// - Parameters:
    ///   - remoteAddress: The remote server IP address.
    ///   - remotePort: The remote server port.
    ///   - clientType: The test mode (unidirectional, dual, tradeoff).
    ///   - reportHandler: Callback invoked when the test completes.
    /// - Returns: The client session, or nil on failure.
    @discardableResult
    public func startTCPClient(remoteAddress: IPAddress,
                                remotePort: UInt16 = LwIPerfConfig.defaultPort,
                                clientType: LwIPerfClientType = .client,
                                reportHandler: @escaping ReportHandler) -> AnyObject? {
        lock.lock()
        defer { lock.unlock() }

        var settings = LwIPerfSettings()
        switch clientType {
        case .dual:
            settings.flags = (LwIPerfSettings.flagsAnswerTest | LwIPerfSettings.flagsAnswerNow).bigEndian
        case .tradeoff:
            settings.flags = LwIPerfSettings.flagsAnswerTest.bigEndian
        case .client:
            settings.flags = 0
        }
        settings.numThreads = UInt32(1).bigEndian
        settings.remotePort = UInt32(LwIPerfConfig.defaultPort).bigEndian
        // Negative value in 10ms units: -1000 = 10 seconds
        settings.amount = Int32(bitPattern: UInt32(truncatingIfNeeded: Int32(-1000))).bigEndian

        guard let session = startTCPClientImpl(
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            settings: settings,
            reportHandler: reportHandler,
            relatedMasterState: nil
        ) else {
            return nil
        }

        // For dual/tradeoff modes, start a corresponding server.
        if clientType != .client {
            let serverSession = startTCPServerImpl(
                address: session.connectionPCB?.localIP ?? .any,
                port: LwIPerfConfig.defaultPort,
                reportHandler: reportHandler,
                relatedMasterState: session
            )
            if let server = serverSession {
                server.specificRemote = true
                server.remoteAddress = remoteAddress
                if clientType == .tradeoff {
                    server.clientTradeoffMode = true
                }
            } else {
                // Server start failed, abort client.
                closeTCPSession(session, reportType: .tcpAbortedLocal)
                return nil
            }
        }

        return session
    }

    /// Internal client start implementation.
    private func startTCPClientImpl(remoteAddress: IPAddress,
                                     remotePort: UInt16,
                                     settings: LwIPerfSettings,
                                     reportHandler: @escaping ReportHandler,
                                     relatedMasterState: LwIPerfSessionBase?) -> LwIPerfTCPSession? {
        let session = LwIPerfTCPSession()
        session.isTCP = true
        session.isServer = false
        session.relatedMasterState = relatedMasterState
        session.reportHandler = reportHandler
        session.bytesTransferred = 0
        session.nextNumber = 4  // Initial number after 24-byte header
        session.settings = settings
        session.hasSettingsBuffer = true
        session.timeStarted = currentTimeMs()

        let pcb = TCPControlBlock()
        session.connectionPCB = pcb

        // Set up sent, poll, and error callbacks.
        setupTCPCallbacks(session: session, pcb: pcb)

        // Initiate TCP connection.
        let err = TCPGlobal.shared.connect(pcb: pcb, address: remoteAddress, port: remotePort) { [weak self] connPCB, err in
            guard let self = self else { return .invalidValue }
            if err != .ok {
                self.lock.lock()
                self.closeTCPSession(session, reportType: .tcpAbortedRemote)
                self.lock.unlock()
                return .ok
            }
            session.pollCount = 0
            session.timeStarted = self.currentTimeMs()
            self.sendMoreClientData(session: session)
            return .ok
        }

        if err != .ok {
            closeTCPSession(session, reportType: .tcpAbortedLocal)
            return nil
        }

        addSession(session)
        return session
    }

    /// Start a TCP iPerf client on the default port.
    @discardableResult
    public func startTCPClientDefault(remoteAddress: IPAddress,
                                       reportHandler: @escaping ReportHandler) -> AnyObject? {
        return startTCPClient(remoteAddress: remoteAddress,
                               remotePort: LwIPerfConfig.defaultPort,
                               reportHandler: reportHandler)
    }

    // MARK: - Session List Management

    /// Add a session to the active list.
    private func addSession(_ session: LwIPerfSessionBase) {
        session.next = allSessions
        allSessions = session
    }

    /// Remove a session from the active list.
    private func removeSession(_ session: LwIPerfSessionBase) {
        if allSessions === session {
            allSessions = session.next
            return
        }
        var prev: LwIPerfSessionBase? = allSessions
        while let current = prev?.next {
            if current === session {
                prev?.next = current.next
                return
            }
            prev = current
        }
    }

    /// Find a session in the active list.
    private func findSession(_ session: LwIPerfSessionBase) -> LwIPerfSessionBase? {
        var current = allSessions
        while let s = current {
            if s === session { return s }
            current = s.next
        }
        return nil
    }

    // MARK: - Report and Close

    /// Generate a report and invoke the callback for a completed session.
    private func report(session: LwIPerfTCPSession, reportType: LwIPerfReportType) {
        guard let handler = session.reportHandler else { return }

        let now = currentTimeMs()
        let durationMs = now - session.timeStarted
        let bandwidthKbps: UInt32
        if durationMs > 0 {
            bandwidthKbps = (session.bytesTransferred / durationMs) * 8
        } else {
            bandwidthKbps = 0
        }

        let localIP = session.connectionPCB?.localIP ?? .any
        let localPort = session.connectionPCB?.localPort ?? 0
        let remoteIP = session.connectionPCB?.remoteIP ?? .any
        let remotePort = session.connectionPCB?.remotePort ?? 0

        handler(reportType,
                localIP, localPort,
                remoteIP, remotePort,
                session.bytesTransferred, durationMs, bandwidthKbps)
    }

    /// Close a TCP iPerf session and issue a report.
    private func closeTCPSession(_ session: LwIPerfTCPSession,
                                  reportType: LwIPerfReportType) {
        removeSession(session)
        report(session: session, reportType: reportType)

        if let pcb = session.connectionPCB {
            pcb.callbackArg = nil
            pcb.pollHandler = nil
            pcb.sentHandler = nil
            pcb.receiveHandler = nil
            pcb.errorHandler = nil
            let err = TCPGlobal.shared.close(pcb: pcb)
            if err != .ok {
                // Close failed (e.g. out of memory for FIN), abort instead.
                TCPGlobal.shared.abort(pcb: pcb)
            }
            session.connectionPCB = nil
        }

        if let pcb = session.serverPCB {
            session.serverPCB = nil
            _ = TCPGlobal.shared.close(pcb: pcb)
        }
    }

    // MARK: - TCP Callbacks

    /// Handle received data for an iPerf session.
    internal func handleReceive(session: LwIPerfTCPSession,
                                 pbuf: Pbuf?) -> LWIPError {
        guard let p = pbuf else {
            // Connection closed -- test done
            if session.settings.flags.bigEndian & LwIPerfSettings.flagsAnswerTest != 0 {
                if session.settings.flags.bigEndian & LwIPerfSettings.flagsAnswerNow == 0 {
                    // Client requested transmission after test
                    startPassiveTransmit(session: session)
                }
            }
            closeTCPSession(session, reportType: .tcpDoneServer)
            return .ok
        }

        session.pollCount = 0

        let totalLength = p.totLen

        if !session.hasSettingsBuffer {
            // Wait for 24-byte settings header
            guard totalLength >= UInt16(LwIPerfSettings.size) else {
                closeTCPSession(session, reportType: .tcpAbortedLocalDataError)
                _ = Pbuf.free(p)
                return .ok
            }

            // Parse settings from first 24 bytes
            var settingsBytes = [UInt8](repeating: 0, count: LwIPerfSettings.size)
            settingsBytes.withUnsafeMutableBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = p.copyPartial(to: UnsafeMutableRawPointer(base),
                                  len: UInt16(LwIPerfSettings.size), offset: 0)
            }
            session.settings = parseSettings(from: settingsBytes)
            session.hasSettingsBuffer = true
            session.bytesTransferred += UInt32(LwIPerfSettings.size)
            session.timeStarted = currentTimeMs()
            session.nextNumber = 4

            // Check if client wants parallel transmission
            if session.settings.flags.bigEndian & LwIPerfSettings.flagsAnswerTest != 0 {
                if session.settings.flags.bigEndian & LwIPerfSettings.flagsAnswerNow != 0 {
                    startPassiveTransmit(session: session)
                }
            }

            if let connPCB = session.connectionPCB {
                TCPGlobal.shared.recved(pcb: connPCB, len: totalLength)
            }
            _ = Pbuf.free(p)
            return .ok
        }

        // Normal data reception
        if LwIPerfConfig.checkReceivedData {
            var dataBytes = [UInt8](repeating: 0, count: Int(totalLength))
            dataBytes.withUnsafeMutableBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = p.copyPartial(to: UnsafeMutableRawPointer(base),
                                  len: UInt16(totalLength), offset: 0)
            }
            for byte in dataBytes {
                let num = byte - UInt8(ascii: "0")
                if num == session.nextNumber {
                    session.nextNumber += 1
                    if session.nextNumber == 10 {
                        session.nextNumber = 0
                    }
                } else {
                    closeTCPSession(session, reportType: .tcpAbortedLocalDataError)
                    _ = Pbuf.free(p)
                    return .ok
                }
            }
        }

        session.bytesTransferred += UInt32(totalLength)
        if let connPCB = session.connectionPCB {
            TCPGlobal.shared.recved(pcb: connPCB, len: totalLength)
        }
        _ = Pbuf.free(p)
        return .ok
    }

    /// Handle a poll timeout for an iPerf session.
    internal func handlePoll(session: LwIPerfTCPSession) -> LWIPError {
        session.pollCount += 1
        if session.pollCount >= LwIPerfConfig.maxIdleSeconds {
            closeTCPSession(session, reportType: .tcpAbortedLocal)
            return .ok
        }
        if !session.isServer {
            sendMoreClientData(session: session)
        }
        return .ok
    }

    /// Handle a connection error for an iPerf session.
    internal func handleError(session: LwIPerfTCPSession) {
        session.connectionPCB = nil
        session.serverPCB = nil
        closeTCPSession(session, reportType: .tcpAbortedRemote)
    }

    // MARK: - Client Data Sending

    /// Send more data from the client to the server.
    private func sendMoreClientData(session: LwIPerfTCPSession) {
        guard !session.isServer else { return }
        guard let pcb = session.connectionPCB else { return }

        var sendMore = true
        while sendMore {
            sendMore = false

            // Check time or byte limit.
            let amountBE = session.settings.amount.bigEndian
            if amountBE < 0 {
                // Time-limited test.
                let now = currentTimeMs()
                let elapsed = now &- session.timeStarted
                let absAmount = UInt32(bitPattern: Int32(0) &- amountBE)
                let timeLimit = absAmount * 10
                if elapsed >= timeLimit {
                    closeTCPSession(session, reportType: .tcpDoneClient)
                    return
                }
            } else {
                // Byte-limited test.
                let amountBytes = UInt32(bitPattern: amountBE)
                if session.bytesTransferred >= amountBytes {
                    closeTCPSession(session, reportType: .tcpDoneClient)
                    return
                }
            }

            // Determine what to send: settings header first (twice), then data.
            let txData: UnsafeRawPointer
            var txLenMax: UInt16
            var apiFlags: UInt8

            if session.bytesTransferred < 24 {
                // First copy of the 24-byte settings header.
                txData = withUnsafePointer(to: &session.settings) { ptr in
                    return UnsafeRawPointer(ptr).advanced(by: Int(session.bytesTransferred))
                }
                txLenMax = UInt16(24 &- session.bytesTransferred)
                apiFlags = TCPConstants.writeFlagCopy
            } else if session.bytesTransferred < 48 {
                // Second copy of the settings header.
                let offset = session.bytesTransferred &- 24
                txData = withUnsafePointer(to: &session.settings) { ptr in
                    return UnsafeRawPointer(ptr).advanced(by: Int(offset))
                }
                txLenMax = UInt16(48 &- session.bytesTransferred)
                apiFlags = TCPConstants.writeFlagCopy | TCPConstants.writeFlagMore
                sendMore = true
            } else {
                // Regular data from the constant transmit buffer.
                let bufOffset = Int(session.bytesTransferred) % 10
                txData = LwIPerfServer.transmitBuffer.withUnsafeBufferPointer { buf in
                    return UnsafeRawPointer(buf.baseAddress!.advanced(by: bufOffset))
                }
                txLenMax = pcb.maxSegmentSize
                if session.bytesTransferred == 48 {
                    // First data segment after the doubled header -- account for the
                    // fact that the header already consumed 24 bytes of the first segment.
                    txLenMax = pcb.maxSegmentSize > 24 ? pcb.maxSegmentSize - 24 : pcb.maxSegmentSize
                }
                apiFlags = 0  // No copy needed for constant buffer.
                sendMore = true
            }

            // Try to write, halving the length on ERR_MEM.
            var txLen = txLenMax
            var err: LWIPError
            repeat {
                err = TCPGlobal.shared.write(pcb: pcb, data: txData, len: txLen, apiFlags: apiFlags)
                if err == .outOfMemory {
                    txLen /= 2
                }
            } while err == .outOfMemory && txLen >= (pcb.maxSegmentSize / 2)

            if err == .ok {
                session.bytesTransferred += UInt32(txLen)
                session.pollCount = 0
            } else {
                sendMore = false
            }
        }

        // Flush queued data.
        _ = TCPGlobal.shared.output(pcb: pcb)
    }

    /// Start a passive transmit (server responding to client request).
    private func startPassiveTransmit(session: LwIPerfTCPSession) {
        guard let pcb = session.connectionPCB else { return }
        guard let handler = session.reportHandler else { return }

        let remotePort = UInt16(session.settings.remotePort.bigEndian & 0xFFFF)

        var txSettings = session.settings
        txSettings.flags = 0  // Prevent the remote side from starting back as client.

        _ = startTCPClientImpl(
            remoteAddress: pcb.remoteIP,
            remotePort: remotePort,
            settings: txSettings,
            reportHandler: handler,
            relatedMasterState: session.relatedMasterState
        )
    }

    // MARK: - Settings Parsing

    /// Parse iPerf settings from raw bytes.
    private func parseSettings(from bytes: [UInt8]) -> LwIPerfSettings {
        var settings = LwIPerfSettings()
        guard bytes.count >= LwIPerfSettings.size else { return settings }

        settings.flags = readUInt32(bytes, offset: 0)
        settings.numThreads = readUInt32(bytes, offset: 4)
        settings.remotePort = readUInt32(bytes, offset: 8)
        settings.bufferLength = readUInt32(bytes, offset: 12)
        settings.windowBandwidth = readUInt32(bytes, offset: 16)
        settings.amount = Int32(bitPattern: readUInt32(bytes, offset: 20))
        return settings
    }

    // MARK: - UDP Server

    /// Start a UDP iPerf server on a specific address and port.
    ///
    /// - Parameters:
    ///   - address: The local IP address to bind to.
    ///   - port: The local UDP port to bind to.
    ///   - reportHandler: Callback invoked when each test session completes.
    /// - Returns: True if the server started successfully.
    @discardableResult
    public func startUDPServer(address: IPAddress,
                                port: UInt16,
                                reportHandler: @escaping ReportHandler) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        let session = LwIPerfUDPSession()
        session.isTCP = false
        session.isServer = true
        session.reportHandler = reportHandler

        let pcb = UDPGlobal.shared.new()
        let bindErr = UDPGlobal.shared.bind(pcb, address: address, port: port)
        if bindErr != .ok {
            UDPGlobal.shared.remove(pcb)
            return false
        }

        UDPGlobal.shared.recv(pcb) { [weak self] _, pbuf, addr, srcPort in
            guard let self = self else { return }
            self.handleUDPReceive(session: session, pbuf: pbuf,
                                  remoteAddr: addr, remotePort: srcPort)
        }

        session.udpPCB = pcb
        addSession(session)
        return true
    }

    // MARK: - UDP Client

    /// Start a UDP iPerf client sending to a remote server.
    ///
    /// - Parameters:
    ///   - remoteAddress: The remote server IP address.
    ///   - remotePort: The remote server port (default 5001).
    ///   - bandwidthBps: Target bandwidth in bits per second (default 1 Mbit/s).
    ///   - durationMs: Test duration in milliseconds (default 10000).
    ///   - datagramSize: Size of each UDP datagram payload (default 1470).
    ///   - reportHandler: Callback invoked when the test completes.
    /// - Returns: The client session, or nil on failure.
    @discardableResult
    public func startUDPClient(remoteAddress: IPAddress,
                                remotePort: UInt16 = LwIPerfConfig.defaultPort,
                                bandwidthBps: UInt64 = LwIPerfConfig.udpDefaultBandwidthBps,
                                durationMs: UInt32 = 10_000,
                                datagramSize: UInt16 = LwIPerfConfig.udpDefaultDatagramSize,
                                reportHandler: @escaping ReportHandler) -> AnyObject? {
        lock.lock()
        defer { lock.unlock() }

        let session = LwIPerfUDPSession()
        session.isTCP = false
        session.isServer = false
        session.reportHandler = reportHandler
        session.bandwidthTargetBps = bandwidthBps
        session.datagramSize = datagramSize
        session.testDurationMs = durationMs
        session.remoteAddress = remoteAddress
        session.remotePort = remotePort

        // Encode settings for the first datagram.
        session.settings.flags = 0
        session.settings.numThreads = UInt32(1).bigEndian
        session.settings.remotePort = UInt32(remotePort).bigEndian
        session.settings.bufferLength = UInt32(datagramSize).bigEndian
        session.settings.windowBandwidth = UInt32(truncatingIfNeeded: bandwidthBps).bigEndian
        // Negative value in 10ms units.
        let amount10ms = Int32(durationMs / 10)
        session.settings.amount = (0 &- amount10ms).bigEndian

        let pcb = UDPGlobal.shared.new()
        let connectErr = UDPGlobal.shared.connect(pcb, address: remoteAddress, port: remotePort)
        if connectErr != .ok {
            UDPGlobal.shared.remove(pcb)
            return nil
        }

        // Set up receive callback to get server finish report.
        UDPGlobal.shared.recv(pcb) { [weak self] _, pbuf, addr, srcPort in
            guard let self = self else { return }
            self.handleUDPClientReceive(session: session, pbuf: pbuf,
                                         remoteAddr: addr, remotePort: srcPort)
        }

        session.udpPCB = pcb
        session.timeStarted = currentTimeMs()
        session.intervalStartTime = session.timeStarted
        addSession(session)

        // Begin sending data.
        sendUDPClientData(session: session)

        return session
    }

    // MARK: - UDP Receive Handling (Server)

    /// Handle received UDP data for a server session.
    private func handleUDPReceive(session: LwIPerfUDPSession,
                                   pbuf: Pbuf,
                                   remoteAddr: IPAddress,
                                   remotePort: UInt16) {
        lock.lock()
        defer { lock.unlock() }

        let now = currentTimeMs()
        let totalLength = pbuf.totLen

        // Minimum datagram must contain the 12-byte UDP header.
        guard totalLength >= UInt16(LwIPerfUDPDatagram.headerSize) else {
            _ = Pbuf.free(pbuf)
            return
        }

        // Parse the datagram header.
        var headerBytes = [UInt8](repeating: 0, count: LwIPerfUDPDatagram.headerSize)
        headerBytes.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = pbuf.copyPartial(to: UnsafeMutableRawPointer(base),
                                 len: UInt16(LwIPerfUDPDatagram.headerSize), offset: 0)
        }

        let sequenceNumber = Int32(bitPattern: readUInt32(headerBytes, offset: 0))
        let sendSeconds = readUInt32(headerBytes, offset: 4)
        let sendMicroseconds = readUInt32(headerBytes, offset: 8)

        // If no peer yet, this is the start of a new test.
        if !session.hasPeer {
            session.hasPeer = true
            session.remoteAddress = remoteAddr
            session.remotePort = remotePort
            session.timeStarted = now
            session.bytesTransferred = 0
            session.datagramCount = 0
            session.highestSequenceReceived = 0
            session.outOfOrderCount = 0
            session.lostCount = 0
            session.jitterMicroseconds = 0
            session.previousReceiveTimeMicroseconds = 0
            session.previousSendTimeMicroseconds = 0
            session.finished = false
        }

        // Verify the datagram is from the expected peer.
        guard remoteAddr == session.remoteAddress && remotePort == session.remotePort else {
            _ = Pbuf.free(pbuf)
            return
        }

        session.lastReceiveTime = now

        // Check for finish datagram (negative sequence number).
        if sequenceNumber < 0 {
            session.finished = true
            // Compute final stats and send the server report back.
            sendUDPServerReport(session: session, pbuf: pbuf, remoteAddr: remoteAddr,
                                remotePort: remotePort)
            _ = Pbuf.free(pbuf)

            // Report and reset the session for the next test.
            reportUDP(session: session, reportType: .udpDoneServer)
            resetUDPServerSession(session)
            return
        }

        // Update measurement counters.
        session.datagramCount += 1
        session.bytesTransferred += UInt32(totalLength)

        // Sequence number tracking for out-of-order and loss detection.
        if sequenceNumber > session.highestSequenceReceived {
            // Normal in-order delivery (or with gaps).
            let gap = sequenceNumber - session.highestSequenceReceived
            if gap > 1 {
                // Datagrams in between were lost (or will arrive out of order later).
                session.lostCount += UInt32(gap - 1)
            }
            session.highestSequenceReceived = sequenceNumber
        } else {
            // Out-of-order delivery; reclaim one previously counted loss.
            session.outOfOrderCount += 1
            if session.lostCount > 0 {
                session.lostCount -= 1
            }
        }

        // Jitter calculation per RFC 1889.
        let sendTimeMicroseconds = UInt64(sendSeconds) * 1_000_000 + UInt64(sendMicroseconds)
        let receiveTimeMicroseconds = UInt64(now) * 1_000
        if session.previousReceiveTimeMicroseconds != 0 {
            let sendDelta = Int64(sendTimeMicroseconds) - Int64(session.previousSendTimeMicroseconds)
            let recvDelta = Int64(receiveTimeMicroseconds) - Int64(session.previousReceiveTimeMicroseconds)
            var transitDiff = recvDelta - sendDelta
            if transitDiff < 0 { transitDiff = -transitDiff }
            // Exponential weighted moving average: J = J + (|D| - J) / 16
            let jitterSigned = Int64(session.jitterMicroseconds) + (transitDiff - Int64(session.jitterMicroseconds)) / 16
            session.jitterMicroseconds = UInt64(max(0, jitterSigned))
        }
        session.previousSendTimeMicroseconds = sendTimeMicroseconds
        session.previousReceiveTimeMicroseconds = receiveTimeMicroseconds

        _ = Pbuf.free(pbuf)
    }

    /// Send the server finish report back to the client.
    private func sendUDPServerReport(session: LwIPerfUDPSession,
                                      pbuf: Pbuf,
                                      remoteAddr: IPAddress,
                                      remotePort: UInt16) {
        guard let pcb = session.udpPCB else { return }

        let now = currentTimeMs()
        let durationMs = now &- session.timeStarted
        let durationSec = durationMs / 1_000
        let durationUsecRemainder = (durationMs % 1_000) * 1_000

        let reportSize = LwIPerfUDPDatagram.headerSize + LwIPerfUDPServerReport.size
        guard let reportPbuf = Pbuf.alloc(layer: .transport,
                                           length: UInt16(reportSize),
                                           type: .ram) else { return }

        // Build report bytes.
        var reportBytes = [UInt8](repeating: 0, count: reportSize)

        // Copy the original datagram header back (first 12 bytes).
        var headerBytes = [UInt8](repeating: 0, count: LwIPerfUDPDatagram.headerSize)
        headerBytes.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = pbuf.copyPartial(to: UnsafeMutableRawPointer(base),
                                 len: UInt16(LwIPerfUDPDatagram.headerSize), offset: 0)
        }
        for i in 0..<LwIPerfUDPDatagram.headerSize {
            reportBytes[i] = headerBytes[i]
        }

        // Server report fields (at offset 12).
        let offset = LwIPerfUDPDatagram.headerSize
        writeUInt32(&reportBytes, offset: offset + 0, value: 0)  // flags
        writeUInt32(&reportBytes, offset: offset + 4, value: 0)  // totalBytes high
        writeUInt32(&reportBytes, offset: offset + 8, value: session.bytesTransferred)  // totalBytes low
        writeUInt32(&reportBytes, offset: offset + 12, value: durationSec)
        writeUInt32(&reportBytes, offset: offset + 16, value: UInt32(durationUsecRemainder))
        writeUInt32(&reportBytes, offset: offset + 20, value: session.outOfOrderCount)
        writeUInt32(&reportBytes, offset: offset + 24, value: session.lostCount)
        writeUInt32(&reportBytes, offset: offset + 28, value: UInt32(session.highestSequenceReceived))
        // Jitter: seconds and microseconds
        let jitterSec = UInt32(session.jitterMicroseconds / 1_000_000)
        let jitterUsec = UInt32(session.jitterMicroseconds % 1_000_000)
        writeUInt32(&reportBytes, offset: offset + 32, value: jitterSec)
        writeUInt32(&reportBytes, offset: offset + 36, value: jitterUsec)

        reportBytes.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = reportPbuf.take(from: UnsafeRawPointer(base), len: UInt16(reportSize))
        }

        _ = UDPGlobal.shared.sendTo(pcb, pbuf: reportPbuf,
                                     dstIP: remoteAddr, dstPort: remotePort)
        _ = Pbuf.free(reportPbuf)
    }

    /// Reset a UDP server session to accept a new test.
    private func resetUDPServerSession(_ session: LwIPerfUDPSession) {
        session.hasPeer = false
        session.bytesTransferred = 0
        session.datagramCount = 0
        session.highestSequenceReceived = 0
        session.outOfOrderCount = 0
        session.lostCount = 0
        session.jitterMicroseconds = 0
        session.previousReceiveTimeMicroseconds = 0
        session.previousSendTimeMicroseconds = 0
        session.finished = false
        session.nextSequenceNumber = 1
    }

    // MARK: - UDP Client Sending

    /// Send UDP client data, pacing to match the bandwidth target.
    private func sendUDPClientData(session: LwIPerfUDPSession) {
        guard !session.isServer else { return }
        guard let pcb = session.udpPCB else { return }

        let now = currentTimeMs()

        // Check if the test duration has elapsed.
        let elapsed = now &- session.timeStarted
        if elapsed >= session.testDurationMs {
            // Send finish datagrams and close.
            sendUDPFinishDatagrams(session: session)
            return
        }

        // Calculate how many bytes we should have sent by now for pacing.
        let elapsedMs = UInt64(elapsed)
        let targetBytesSoFar = (session.bandwidthTargetBps * elapsedMs) / (8 * 1_000)

        // Send datagrams until we catch up to the target rate.
        while UInt64(session.bytesTransferred) < targetBytesSoFar {
            let datagramSize = session.datagramSize

            guard let pbuf = Pbuf.alloc(layer: .transport,
                                         length: datagramSize,
                                         type: .ram) else { break }

            // Fill payload with the transmit pattern.
            let patternStart = Int(session.bytesTransferred) % 10
            if datagramSize > UInt16(LwIPerfUDPDatagram.headerSize) {
                let patternLen = Int(datagramSize) - LwIPerfUDPDatagram.headerSize
                var patternBytes = [UInt8](repeating: 0, count: patternLen)
                for i in 0..<patternLen {
                    patternBytes[i] = UInt8(ascii: "0") + UInt8((patternStart + i) % 10)
                }
                patternBytes.withUnsafeBufferPointer { buf in
                    guard let base = buf.baseAddress else { return }
                    _ = pbuf.takeAt(from: UnsafeRawPointer(base),
                                    len: UInt16(patternLen),
                                    offset: UInt16(LwIPerfUDPDatagram.headerSize))
                }
            }

            // Build and write the datagram header.
            let sendTimeMicroseconds = UInt64(now) * 1_000
            let sendSec = UInt32(sendTimeMicroseconds / 1_000_000)
            let sendUsec = UInt32(sendTimeMicroseconds % 1_000_000)

            var headerBytes = [UInt8](repeating: 0, count: LwIPerfUDPDatagram.headerSize)
            writeUInt32(&headerBytes, offset: 0, value: UInt32(bitPattern: session.nextSequenceNumber))
            writeUInt32(&headerBytes, offset: 4, value: sendSec)
            writeUInt32(&headerBytes, offset: 8, value: sendUsec)

            // For the very first datagram, embed settings after the header.
            if session.nextSequenceNumber == 1 && datagramSize >= UInt16(LwIPerfUDPDatagram.headerSize + LwIPerfSettings.size) {
                var settingsBytes = [UInt8](repeating: 0, count: LwIPerfSettings.size)
                writeUInt32(&settingsBytes, offset: 0, value: session.settings.flags)
                writeUInt32(&settingsBytes, offset: 4, value: session.settings.numThreads)
                writeUInt32(&settingsBytes, offset: 8, value: session.settings.remotePort)
                writeUInt32(&settingsBytes, offset: 12, value: session.settings.bufferLength)
                writeUInt32(&settingsBytes, offset: 16, value: session.settings.windowBandwidth)
                writeUInt32(&settingsBytes, offset: 20, value: UInt32(bitPattern: session.settings.amount))
                settingsBytes.withUnsafeBufferPointer { buf in
                    guard let base = buf.baseAddress else { return }
                    _ = pbuf.takeAt(from: UnsafeRawPointer(base),
                                    len: UInt16(LwIPerfSettings.size),
                                    offset: UInt16(LwIPerfUDPDatagram.headerSize))
                }
            }

            headerBytes.withUnsafeBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = pbuf.take(from: UnsafeRawPointer(base),
                              len: UInt16(LwIPerfUDPDatagram.headerSize))
            }

            let err = UDPGlobal.shared.send(pcb, pbuf: pbuf)
            _ = Pbuf.free(pbuf)

            if err != .ok { break }

            session.nextSequenceNumber += 1
            session.datagramCount += 1
            session.bytesTransferred += UInt32(datagramSize)
        }

        // Schedule the next send burst after the pacing interval.
        let interval = LwIPerfConfig.udpClientSendIntervalMs
        Timeouts.shared.setTimeout(msecs: interval, handler: { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            // Verify session is still active.
            guard self.findSession(session) != nil else {
                self.lock.unlock()
                return
            }
            self.lock.unlock()
            self.sendUDPClientData(session: session)
        }, name: "lwiperf_udp_send")
    }

    /// Send finish datagrams and close the UDP client session.
    private func sendUDPFinishDatagrams(session: LwIPerfUDPSession) {
        guard let pcb = session.udpPCB else { return }

        let now = currentTimeMs()
        let sendTimeMicroseconds = UInt64(now) * 1_000
        let sendSec = UInt32(sendTimeMicroseconds / 1_000_000)
        let sendUsec = UInt32(sendTimeMicroseconds % 1_000_000)

        // Send multiple finish datagrams with negative sequence numbers.
        let finishSeq: Int32 = 0 &- session.nextSequenceNumber
        for _ in 0..<LwIPerfConfig.udpFinishDatagramCount {
            guard let pbuf = Pbuf.alloc(layer: .transport,
                                         length: session.datagramSize,
                                         type: .ram) else { break }

            var headerBytes = [UInt8](repeating: 0, count: LwIPerfUDPDatagram.headerSize)
            writeUInt32(&headerBytes, offset: 0, value: UInt32(bitPattern: finishSeq))
            writeUInt32(&headerBytes, offset: 4, value: sendSec)
            writeUInt32(&headerBytes, offset: 8, value: sendUsec)

            headerBytes.withUnsafeBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = pbuf.take(from: UnsafeRawPointer(base),
                              len: UInt16(LwIPerfUDPDatagram.headerSize))
            }

            // Fill rest with pattern data.
            if session.datagramSize > UInt16(LwIPerfUDPDatagram.headerSize) {
                let patternLen = Int(session.datagramSize) - LwIPerfUDPDatagram.headerSize
                var patternBytes = [UInt8](repeating: 0, count: patternLen)
                for i in 0..<patternLen {
                    patternBytes[i] = UInt8(ascii: "0") + UInt8(i % 10)
                }
                patternBytes.withUnsafeBufferPointer { buf in
                    guard let base = buf.baseAddress else { return }
                    _ = pbuf.takeAt(from: UnsafeRawPointer(base),
                                    len: UInt16(patternLen),
                                    offset: UInt16(LwIPerfUDPDatagram.headerSize))
                }
            }

            _ = UDPGlobal.shared.send(pcb, pbuf: pbuf)
            _ = Pbuf.free(pbuf)
        }

        // Wait briefly for the server report, then close.
        Timeouts.shared.setTimeout(msecs: 500, handler: { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            guard self.findSession(session) != nil else {
                self.lock.unlock()
                return
            }
            self.closeUDPSession(session, reportType: .udpDoneClient)
            self.lock.unlock()
        }, name: "lwiperf_udp_finish")
    }

    /// Handle received data on the UDP client (server finish report).
    private func handleUDPClientReceive(session: LwIPerfUDPSession,
                                         pbuf: Pbuf,
                                         remoteAddr: IPAddress,
                                         remotePort: UInt16) {
        // The server sends back a report after receiving finish datagrams.
        // We can parse it for stats but the client session will close on timeout.
        let totalLength = pbuf.totLen
        let expectedSize = LwIPerfUDPDatagram.headerSize + LwIPerfUDPServerReport.size

        if totalLength >= UInt16(expectedSize) {
            // Cancel the finish timeout and close immediately with success.
            Timeouts.shared.untimeout(name: "lwiperf_udp_finish")
            lock.lock()
            if findSession(session) != nil {
                closeUDPSession(session, reportType: .udpDoneClient)
            }
            lock.unlock()
        }

        _ = Pbuf.free(pbuf)
    }

    // MARK: - UDP Report and Close

    /// Generate a report for a completed UDP session.
    private func reportUDP(session: LwIPerfUDPSession, reportType: LwIPerfReportType) {
        guard let handler = session.reportHandler else { return }

        let now = currentTimeMs()
        let durationMs = now &- session.timeStarted
        let bandwidthKbps: UInt32
        if durationMs > 0 {
            bandwidthKbps = (session.bytesTransferred / durationMs) * 8
        } else {
            bandwidthKbps = 0
        }

        let localIP = session.udpPCB?.localIP ?? .any
        let localPort = session.udpPCB?.localPort ?? 0
        let remoteIP = session.remoteAddress
        let remotePort = session.remotePort

        handler(reportType,
                localIP, localPort,
                remoteIP, remotePort,
                session.bytesTransferred, durationMs, bandwidthKbps)
    }

    /// Close a UDP iPerf session and issue a report.
    private func closeUDPSession(_ session: LwIPerfUDPSession,
                                  reportType: LwIPerfReportType) {
        removeSession(session)

        // Cancel any pending send timer for this session.
        Timeouts.shared.untimeout(name: "lwiperf_udp_send")
        Timeouts.shared.untimeout(name: "lwiperf_udp_finish")

        reportUDP(session: session, reportType: reportType)

        if let pcb = session.udpPCB {
            pcb.receiveHandler = nil
            UDPGlobal.shared.remove(pcb)
            session.udpPCB = nil
        }
    }

    // MARK: - Helpers

    /// Read a big-endian UInt32 from a byte array.
    private func readUInt32(_ data: [UInt8], offset: Int) -> UInt32 {
        guard offset + 3 < data.count else { return 0 }
        return (UInt32(data[offset]) << 24) |
               (UInt32(data[offset + 1]) << 16) |
               (UInt32(data[offset + 2]) << 8) |
               UInt32(data[offset + 3])
    }

    /// Write a big-endian UInt32 into a byte array.
    private func writeUInt32(_ data: inout [UInt8], offset: Int, value: UInt32) {
        guard offset + 3 < data.count else { return }
        data[offset]     = UInt8((value >> 24) & 0xFF)
        data[offset + 1] = UInt8((value >> 16) & 0xFF)
        data[offset + 2] = UInt8((value >> 8) & 0xFF)
        data[offset + 3] = UInt8(value & 0xFF)
    }

    /// Get the current time in milliseconds (platform-dependent).
    private func currentTimeMs() -> UInt32 {
        return UInt32(DispatchTime.now().uptimeNanoseconds / 1_000_000)
    }
}
