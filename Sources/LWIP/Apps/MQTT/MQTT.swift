//
//  MQTT.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - MQTT Configuration

/// MQTT client configuration constants.
public enum MQTTConfig {
    /// Output ring buffer size (must hold largest outgoing publish topic+payload).
    public static var outputRingBufSize: Int = 256
    /// Receive buffer size for variable headers.
    public static var varHeaderBufferLen: Int = 128
    /// Maximum number of in-flight requests.
    public static var maxInFlightRequests: Int = 4
    /// Cyclic timer interval in seconds.
    public static var cyclicTimerInterval: UInt16 = 5
    /// Request timeout in seconds.
    public static var requestTimeout: UInt16 = 30
    /// Connect response timeout in seconds.
    public static var connectTimeout: UInt16 = 100
    /// Default MQTT port.
    public static let port: UInt16 = 1883
    /// Default MQTT TLS port.
    public static let tlsPort: UInt16 = 8883
}

// MARK: - MQTTConnectionStatus

/// Connection status codes.
public enum MQTTConnectionStatus: Int, Sendable {
    /// Connection accepted by server.
    case accepted                     = 0
    /// Refused: protocol version.
    case refusedProtocolVersion       = 1
    /// Refused: identifier rejected.
    case refusedIdentifier            = 2
    /// Refused: server unavailable.
    case refusedServer                = 3
    /// Refused: bad username/password.
    case refusedUsernamePassword      = 4
    /// Refused: not authorized.
    case refusedNotAuthorized         = 5
    /// Disconnected by client or error.
    case disconnected                 = 256
    /// Connection timed out.
    case timeout                      = 257
}

// MARK: - MQTTMessageType

/// MQTT control message types.
public enum MQTTMessageType: UInt8, Sendable {
    case connect     = 1
    case connAck     = 2
    case publish     = 3
    case pubAck      = 4
    case pubRec      = 5
    case pubRel      = 6
    case pubComp     = 7
    case subscribe   = 8
    case subAck      = 9
    case unsubscribe = 10
    case unsubAck    = 11
    case pingReq     = 12
    case pingResp    = 13
    case disconnect  = 14
}

// MARK: - MQTTConnectState

/// Internal connection state machine states.
internal enum MQTTConnectState: UInt8, Sendable {
    case tcpDisconnected = 0
    case tcpConnecting   = 1
    case mqttConnecting  = 2
    case mqttConnected   = 3
}

// MARK: - MQTTDataFlags

/// Flags for incoming data callbacks.
public struct MQTTDataFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// This is the last fragment of the publish data.
    public static let last = MQTTDataFlags(rawValue: 1)
}

// MARK: - Callback Types

extension MQTTClient {
    /// Connection status callback.
    public typealias ConnectionHandler = @Sendable (MQTTClient, MQTTConnectionStatus) -> Void

    /// Incoming publish notification callback (topic + total length).
    public typealias IncomingPublishHandler = @Sendable (String, UInt32) -> Void

    /// Incoming publish data callback (data fragment).
    public typealias IncomingDataHandler = @Sendable (UnsafeBufferPointer<UInt8>, MQTTDataFlags) -> Void

    /// Request completion callback (for subscribe, unsubscribe, publish with QoS > 0).
    public typealias RequestHandler = @Sendable (LWIPError) -> Void
}

// MARK: - MQTTConnectInfo

/// Client information and connection parameters for MQTT connect.
public struct MQTTConnectInfo: Sendable {
    /// Client identifier (required).
    public var clientId: String
    /// Username (optional).
    public var username: String?
    /// Password (optional).
    public var password: String?
    /// Keep-alive interval in seconds (0 to disable).
    public var keepAlive: UInt16
    /// Will topic (nil to disable will).
    public var willTopic: String?
    /// Will message.
    public var willMessage: String?
    /// Will QoS level (0-2).
    public var willQoS: UInt8
    /// Will retain flag.
    public var willRetain: Bool
    /// Clean session flag (true = discard any previous session state).
    public var cleanSession: Bool

    public init(clientId: String,
                username: String? = nil,
                password: String? = nil,
                keepAlive: UInt16 = 60,
                willTopic: String? = nil,
                willMessage: String? = nil,
                willQoS: UInt8 = 0,
                willRetain: Bool = false,
                cleanSession: Bool = true) {
        self.clientId = clientId
        self.username = username
        self.password = password
        self.keepAlive = keepAlive
        self.willTopic = willTopic
        self.willMessage = willMessage
        self.willQoS = willQoS
        self.willRetain = willRetain
        self.cleanSession = cleanSession
    }
}

// MARK: - MQTTRequest

/// Pending request tracking.
internal final class MQTTRequest: @unchecked Sendable {
    /// Next request in the queue.
    var next: MQTTRequest?
    /// Completion callback.
    var callback: MQTTClient.RequestHandler?
    /// MQTT packet identifier.
    var packetId: UInt16
    /// Timeout in seconds (relative to previous request).
    var timeoutDiff: UInt16

    init(packetId: UInt16, callback: MQTTClient.RequestHandler?, timeout: UInt16) {
        self.packetId = packetId
        self.callback = callback
        self.timeoutDiff = timeout
    }
}

// MARK: - MQTTRingBuffer

/// Ring buffer for output data.
internal struct MQTTRingBuffer {
    var buffer: [UInt8]
    var putIndex: Int = 0
    var getIndex: Int = 0

    init(size: Int = MQTTConfig.outputRingBufSize) {
        buffer = [UInt8](repeating: 0, count: size)
    }

    /// Number of bytes available to read.
    var count: Int {
        if putIndex >= getIndex {
            return putIndex - getIndex
        }
        return buffer.count - getIndex + putIndex
    }

    /// Available space for writing.
    var freeSpace: Int {
        return buffer.count - count - 1
    }

    /// Whether the buffer is empty.
    var isEmpty: Bool { putIndex == getIndex }

    /// Write data into the ring buffer.
    mutating func write(_ data: UnsafeRawPointer, length: Int) -> Int {
        let toWrite = min(length, freeSpace)
        let bytes = data.assumingMemoryBound(to: UInt8.self)

        for i in 0..<toWrite {
            buffer[putIndex] = bytes[i]
            putIndex = (putIndex + 1) % buffer.count
        }
        return toWrite
    }

    /// Write a single byte.
    mutating func writeByte(_ byte: UInt8) -> Bool {
        guard freeSpace > 0 else { return false }
        buffer[putIndex] = byte
        putIndex = (putIndex + 1) % buffer.count
        return true
    }

    /// Read data from the ring buffer into a destination.
    mutating func read(into dest: UnsafeMutableRawPointer, length: Int) -> Int {
        let toRead = min(length, count)
        let bytes = dest.assumingMemoryBound(to: UInt8.self)

        for i in 0..<toRead {
            bytes[i] = buffer[getIndex]
            getIndex = (getIndex + 1) % buffer.count
        }
        return toRead
    }

    /// Peek at data without consuming.
    func peek(at offset: Int) -> UInt8? {
        guard offset < count else { return nil }
        let idx = (getIndex + offset) % buffer.count
        return buffer[idx]
    }

    /// Discard bytes from the read side.
    mutating func skip(_ n: Int) {
        let toSkip = min(n, count)
        getIndex = (getIndex + toSkip) % buffer.count
    }

    /// Reset the buffer.
    mutating func reset() {
        putIndex = 0
        getIndex = 0
    }
}

// MARK: - QoS2State

/// Tracks the phase of a QoS 2 message exchange.
internal enum QoS2Phase: Sendable {
    /// Outgoing: PUBLISH sent, waiting for PUBREC.
    case awaitingPubRec
    /// Outgoing: PUBREC received, PUBREL sent, waiting for PUBCOMP.
    case awaitingPubComp
    /// Incoming: PUBLISH received, PUBREC sent, waiting for PUBREL.
    case awaitingPubRel
}

/// State for a single QoS 2 in-flight message.
internal final class QoS2State: @unchecked Sendable {
    /// MQTT packet identifier.
    let packetId: UInt16
    /// Current phase in the QoS 2 handshake.
    var phase: QoS2Phase

    init(packetId: UInt16, phase: QoS2Phase) {
        self.packetId = packetId
        self.phase = phase
    }
}

// MARK: - MQTTClient

/// MQTT 3.1.1 client.
///
/// Provides connect, disconnect, publish, subscribe, and unsubscribe
/// operations with callback-based asynchronous notification.
public final class MQTTClient: @unchecked Sendable {

    // MARK: - Properties

    /// Timers and timeouts.
    private var cyclicTick: UInt16 = 0
    private var keepAlive: UInt16 = 0
    private var serverWatchdog: UInt16 = 0

    /// Packet identifier generator.
    private var packetIdSeq: UInt16 = 1

    /// Incoming publish packet identifier.
    private var inPubPacketId: UInt16 = 0

    /// QoS 2 in-flight message states (both outgoing and incoming).
    private var qos2InFlight: [QoS2State] = []

    /// Buffered payloads for incoming QoS 2 messages awaiting PUBREL to deliver.
    private var qos2PendingIncoming: [UInt16: (topic: String, totalLength: UInt32,
                                               payload: [UInt8])] = [:]

    /// Connection state.
    internal var connState: MQTTConnectState = .tcpDisconnected

    /// Altcp connection handle (wraps TCP or TLS-over-TCP).
    private var conn: AltcpControlBlock?

    /// Connection callback and argument.
    private var connectCallback: MQTTClient.ConnectionHandler?

    /// Pending request queue head.
    private var pendingRequestQueue: MQTTRequest?

    /// Pre-allocated request pool.
    private var requestPool: [MQTTRequest]

    /// Incoming publish callbacks.
    private var incomingPublishCallback: MQTTClient.IncomingPublishHandler?
    private var incomingDataCallback: MQTTClient.IncomingDataHandler?

    /// Input state.
    private var msgIndex: UInt32 = 0
    private var rxBuffer: [UInt8]

    /// Output ring buffer.
    private var output: MQTTRingBuffer

    /// Lock for thread safety.
    private let lock = NSLock()

    // MARK: - Initialization

    /// Create a new MQTT client.
    public init() {
        requestPool = (0..<MQTTConfig.maxInFlightRequests).map { _ in
            MQTTRequest(packetId: 0, callback: nil, timeout: 0)
        }
        rxBuffer = []
        rxBuffer.reserveCapacity(MQTTConfig.varHeaderBufferLen)
        output = MQTTRingBuffer(size: MQTTConfig.outputRingBufSize)
    }

    deinit {
        disconnect()
    }

    private func copyBytes(from pbuf: Pbuf) -> [UInt8] {
        let totalLen = Int(pbuf.totLen)
        var data = [UInt8](repeating: 0, count: totalLen)
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
        }
        return data
    }

    private func closeAltcpConnection(_ connection: AltcpControlBlock) {
        connection.setRecv(nil)
        connection.setSent(nil)
        connection.setErr(nil)

        let err = connection.close()
        if err != .ok {
            connection.abort()
        }
    }

    // MARK: - Connection

    /// Whether the client is currently connected.
    public var isConnected: Bool {
        lock.lock()
        let connected = connState == .mqttConnected
        lock.unlock()
        return connected
    }

    /// Connect to an MQTT broker.
    ///
    /// - Parameters:
    ///   - address: Server IP address.
    ///   - port: Server port (default: 1883).
    ///   - info: Client connection information.
    ///   - allocator: Optional altcp allocator. When provided, the connection is
    ///     created through this allocator, which may layer TLS on top of TCP.
    ///     When nil, a plain TCP connection is used. Use
    ///     `AltcpTLS.allocator(config:)` to create a TLS allocator.
    ///   - callback: Connection status callback.
    /// - Returns: `.ok` if the connection attempt was started.
    @discardableResult
    public func connect(
        address: IPAddress,
        port: UInt16 = MQTTConfig.port,
        info: MQTTConnectInfo,
        allocator: AltcpAllocator? = nil,
        callback: @escaping MQTTClient.ConnectionHandler
    ) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard connState == .tcpDisconnected else { return .connectionEstablished }

        connectCallback = callback
        keepAlive = info.keepAlive
        packetIdSeq = 1

        // Reset output buffer.
        output.reset()
        resetInputState()

        // Clear pending requests.
        pendingRequestQueue = nil
        for req in requestPool {
            req.next = nil
            req.callback = nil
        }

        // Create connection through altcp (plain TCP or TLS-over-TCP).
        guard let altcpConn = AltcpControlBlock.create(allocator: allocator) else {
            return .outOfMemory
        }
        altcpConn.setArg(nil)
        altcpConn.setRecv { [weak self] _, altcpConn, pbuf, err in
            guard let self else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .ok
            }

            if err != .ok {
                self.lock.lock()
                self.closeConnection(reason: .disconnected)
                self.lock.unlock()
                return .ok
            }

            guard let pbuf else {
                self.lock.lock()
                self.closeConnection(reason: .disconnected)
                self.lock.unlock()
                return .ok
            }

            let data = self.copyBytes(from: pbuf)
            altcpConn.recved(pbuf.totLen)
            data.withUnsafeBufferPointer { buffer in
                self.processIncoming(data: buffer)
            }
            return .ok
        }
        altcpConn.setSent { [weak self] _, _, _ in
            guard let self else { return .ok }
            self.lock.lock()
            self.flushOutput()
            self.lock.unlock()
            return .ok
        }
        altcpConn.setErr { [weak self] _, _ in
            guard let self else { return }
            self.lock.lock()
            self.closeConnection(reason: .disconnected)
            self.lock.unlock()
        }
        conn = altcpConn
        connState = .tcpConnecting

        let connectErr = altcpConn.connect(ipaddr: address, port: port) { [weak self] _, _, err in
            guard let self else { return .ok }
            self.lock.lock()
            defer { self.lock.unlock() }

            guard err == .ok else {
                self.closeConnection(reason: .disconnected)
                return .ok
            }

            self.buildConnectPacket(info: info)
            self.connState = .mqttConnecting
            self.cyclicTick = 0
            self.serverWatchdog = MQTTConfig.connectTimeout
            self.flushOutput()
            return .ok
        }

        if connectErr != .ok {
            closeConnection(reason: .disconnected)
            return connectErr
        }

        return .ok
    }

    /// Disconnect from the MQTT broker.
    public func disconnect() {
        lock.lock()
        defer { lock.unlock() }

        guard connState != .tcpDisconnected else { return }

        // Send DISCONNECT packet if connected.
        if connState == .mqttConnected {
            buildFixedHeader(type: .disconnect, remainingLength: 0)
            flushOutput()
        }

        // Close connection.
        closeConnection(reason: .disconnected)
    }

    // MARK: - Publish

    /// Publish a message to a topic.
    ///
    /// - Parameters:
    ///   - topic: The topic string.
    ///   - payload: The message payload.
    ///   - payloadLength: Length of the payload.
    ///   - qos: Quality of service (0, 1, or 2).
    ///   - retain: Whether to retain the message.
    ///   - callback: Completion callback (QoS > 0 only).
    /// - Returns: `.ok` if the publish was queued.
    @discardableResult
    public func publish(
        topic: String,
        payload: UnsafeRawPointer? = nil,
        payloadLength: UInt16 = 0,
        qos: UInt8 = 0,
        retain: Bool = false,
        callback: MQTTClient.RequestHandler? = nil
    ) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard connState == .mqttConnected else { return .notConnected }

        let topicBytes = Array(topic.utf8)
        var remainingLength = 2 + topicBytes.count + Int(payloadLength)
        var packetId: UInt16 = 0

        if qos > 0 {
            packetId = nextPacketId()
            remainingLength += 2

            // Register pending request.
            guard let request = allocRequest(packetId: packetId,
                                            callback: callback,
                                            timeout: MQTTConfig.requestTimeout) else {
                return .outOfMemory
            }
            appendRequest(request)

            // Track QoS 2 outgoing state for the four-message handshake.
            if qos == 2 {
                let state = QoS2State(packetId: packetId, phase: .awaitingPubRec)
                qos2InFlight.append(state)
            }
        }

        // Build PUBLISH header.
        var flags: UInt8 = 0
        if retain { flags |= 0x01 }
        flags |= (qos & 0x03) << 1

        buildFixedHeader(type: .publish, flags: flags,
                        remainingLength: remainingLength)

        // Topic length + topic.
        _ = output.writeByte(UInt8(topicBytes.count >> 8))
        _ = output.writeByte(UInt8(topicBytes.count & 0xFF))
        for b in topicBytes {
            _ = output.writeByte(b)
        }

        // Packet identifier (QoS > 0).
        if qos > 0 {
            _ = output.writeByte(UInt8(packetId >> 8))
            _ = output.writeByte(UInt8(packetId & 0xFF))
        }

        // Payload.
        if let payload = payload, payloadLength > 0 {
            let bytes = payload.assumingMemoryBound(to: UInt8.self)
            for i in 0..<Int(payloadLength) {
                _ = output.writeByte(bytes[i])
            }
        }

        flushOutput()
        return .ok
    }

    // MARK: - Subscribe / Unsubscribe

    /// Subscribe or unsubscribe from a topic.
    ///
    /// - Parameters:
    ///   - topic: The topic filter.
    ///   - qos: Maximum QoS level (subscribe only).
    ///   - callback: Completion callback.
    ///   - subscribe: `true` to subscribe, `false` to unsubscribe.
    /// - Returns: `.ok` if the request was queued.
    @discardableResult
    public func subUnsub(
        topic: String,
        qos: UInt8 = 0,
        callback: MQTTClient.RequestHandler? = nil,
        subscribe: Bool
    ) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard connState == .mqttConnected else { return .notConnected }

        let topicBytes = Array(topic.utf8)
        let packetId = nextPacketId()

        // Register pending request.
        guard let request = allocRequest(packetId: packetId,
                                        callback: callback,
                                        timeout: MQTTConfig.requestTimeout) else {
            return .outOfMemory
        }
        appendRequest(request)

        let msgType: MQTTMessageType = subscribe ? .subscribe : .unsubscribe
        var remainingLength = 2 + 2 + topicBytes.count  // packet_id + topic_len + topic
        if subscribe { remainingLength += 1 }  // QoS byte

        // Fixed header with reserved bits.
        let reservedFlags: UInt8 = 0x02  // Required for SUBSCRIBE/UNSUBSCRIBE
        buildFixedHeader(type: msgType, flags: reservedFlags,
                        remainingLength: remainingLength)

        // Packet identifier.
        _ = output.writeByte(UInt8(packetId >> 8))
        _ = output.writeByte(UInt8(packetId & 0xFF))

        // Topic length + topic.
        _ = output.writeByte(UInt8(topicBytes.count >> 8))
        _ = output.writeByte(UInt8(topicBytes.count & 0xFF))
        for b in topicBytes {
            _ = output.writeByte(b)
        }

        // QoS (subscribe only).
        if subscribe {
            _ = output.writeByte(qos)
        }

        flushOutput()
        return .ok
    }

    /// Subscribe to a topic.
    @discardableResult
    @inlinable
    public func subscribe(
        topic: String,
        qos: UInt8 = 0,
        callback: MQTTClient.RequestHandler? = nil
    ) -> LWIPError {
        return subUnsub(topic: topic, qos: qos, callback: callback, subscribe: true)
    }

    /// Unsubscribe from a topic.
    @discardableResult
    @inlinable
    public func unsubscribe(
        topic: String,
        callback: MQTTClient.RequestHandler? = nil
    ) -> LWIPError {
        return subUnsub(topic: topic, callback: callback, subscribe: false)
    }

    // MARK: - Incoming Data Callbacks

    /// Set callbacks for incoming publish messages.
    ///
    /// - Parameters:
    ///   - publishCallback: Called when a PUBLISH topic is received.
    ///   - dataCallback: Called with PUBLISH data fragments.
    public func setIncomingPublishCallback(
        publishCallback: @escaping MQTTClient.IncomingPublishHandler,
        dataCallback: @escaping MQTTClient.IncomingDataHandler
    ) {
        lock.lock()
        incomingPublishCallback = publishCallback
        incomingDataCallback = dataCallback
        lock.unlock()
    }

    // MARK: - Internal: Packet Building

    /// Build a fixed header and write it to the output buffer.
    private func buildFixedHeader(type: MQTTMessageType, flags: UInt8 = 0,
                                  remainingLength: Int) {
        let headerByte = (type.rawValue << 4) | (flags & 0x0F)
        _ = output.writeByte(headerByte)

        // Encode remaining length (variable-length encoding).
        var length = remainingLength
        repeat {
            var encodedByte = UInt8(length % 128)
            length /= 128
            if length > 0 {
                encodedByte |= 0x80
            }
            _ = output.writeByte(encodedByte)
        } while length > 0
    }

    /// Build a CONNECT packet.
    private func buildConnectPacket(info: MQTTConnectInfo) {
        var connectFlags: UInt8 = info.cleanSession ? 0x02 : 0x00
        var remainingLength = 10  // Variable header (protocol name + level + flags + keepalive)

        // Client ID.
        let clientIdBytes = Array(info.clientId.utf8)
        remainingLength += 2 + clientIdBytes.count

        // Will.
        if let willTopic = info.willTopic {
            connectFlags |= 0x04  // Will flag
            connectFlags |= (info.willQoS & 0x03) << 3
            if info.willRetain { connectFlags |= 0x20 }

            let willTopicBytes = Array(willTopic.utf8)
            remainingLength += 2 + willTopicBytes.count
            let willMsgBytes = Array((info.willMessage ?? "").utf8)
            remainingLength += 2 + willMsgBytes.count
        }

        // Username.
        if let username = info.username {
            connectFlags |= 0x80
            remainingLength += 2 + Array(username.utf8).count
        }

        // Password.
        if let password = info.password {
            connectFlags |= 0x40
            remainingLength += 2 + Array(password.utf8).count
        }

        // Fixed header.
        buildFixedHeader(type: .connect, remainingLength: remainingLength)

        // Variable header: Protocol Name "MQTT".
        _ = output.writeByte(0x00)
        _ = output.writeByte(0x04)
        for c in "MQTT".utf8 { _ = output.writeByte(c) }

        // Protocol Level.
        _ = output.writeByte(0x04)  // MQTT 3.1.1

        // Connect Flags.
        _ = output.writeByte(connectFlags)

        // Keep Alive.
        _ = output.writeByte(UInt8(info.keepAlive >> 8))
        _ = output.writeByte(UInt8(info.keepAlive & 0xFF))

        // Client ID.
        writeUTF8String(clientIdBytes)

        // Will.
        if let willTopic = info.willTopic {
            writeUTF8String(Array(willTopic.utf8))
            writeUTF8String(Array((info.willMessage ?? "").utf8))
        }

        // Username.
        if let username = info.username {
            writeUTF8String(Array(username.utf8))
        }

        // Password.
        if let password = info.password {
            writeUTF8String(Array(password.utf8))
        }
    }

    /// Write a UTF-8 string with length prefix.
    private func writeUTF8String(_ bytes: [UInt8]) {
        _ = output.writeByte(UInt8(bytes.count >> 8))
        _ = output.writeByte(UInt8(bytes.count & 0xFF))
        for b in bytes { _ = output.writeByte(b) }
    }

    // MARK: - Internal: Request Management

    /// Generate the next packet identifier.
    private func nextPacketId() -> UInt16 {
        let id = packetIdSeq
        packetIdSeq = packetIdSeq == UInt16.max ? 1 : packetIdSeq + 1
        return id
    }

    /// Allocate a request from the pool.
    private func allocRequest(packetId: UInt16, callback: MQTTClient.RequestHandler?,
                              timeout: UInt16) -> MQTTRequest? {
        for req in requestPool {
            if req.callback == nil && req.next == nil && req !== pendingRequestQueue {
                req.packetId = packetId
                req.callback = callback
                req.timeoutDiff = timeout
                return req
            }
        }
        return nil
    }

    /// Append a request to the pending queue.
    private func appendRequest(_ request: MQTTRequest) {
        request.next = nil
        if pendingRequestQueue == nil {
            pendingRequestQueue = request
        } else {
            var tail = pendingRequestQueue
            while tail?.next != nil { tail = tail?.next }
            tail?.next = request
        }
    }

    /// Find and remove a request by packet ID, calling its callback.
    private func completeRequest(packetId: UInt16, error: LWIPError) {
        var prev: MQTTRequest? = nil
        var current = pendingRequestQueue

        while let req = current {
            if req.packetId == packetId {
                if prev == nil {
                    pendingRequestQueue = req.next
                } else {
                    prev?.next = req.next
                }
                req.next = nil
                let cb = req.callback
                req.callback = nil
                cb?(error)
                return
            }
            prev = req
            current = req.next
        }
    }

    // MARK: - Internal: QoS 2 Helpers

    /// Find a QoS 2 in-flight state by packet ID.
    private func findQoS2State(packetId: UInt16) -> QoS2State? {
        return qos2InFlight.first { $0.packetId == packetId }
    }

    /// Remove a QoS 2 in-flight state by packet ID.
    private func removeQoS2State(packetId: UInt16) {
        qos2InFlight.removeAll { $0.packetId == packetId }
    }

    /// Send a simple acknowledgement packet (PUBREC, PUBREL, or PUBCOMP).
    private func sendQoS2Ack(type: MQTTMessageType, packetId: UInt16) {
        // PUBREL requires fixed header flags of 0x02 per MQTT 3.1.1 spec.
        let flags: UInt8 = (type == .pubRel) ? 0x02 : 0x00
        buildFixedHeader(type: type, flags: flags, remainingLength: 2)
        _ = output.writeByte(UInt8(packetId >> 8))
        _ = output.writeByte(UInt8(packetId & 0xFF))
        flushOutput()
    }

    // MARK: - Internal: Output

    /// Flush the output ring buffer to the connection.
    private func flushOutput() {
        guard let connection = conn else { return }

        while !output.isEmpty {
            // Check available send buffer space (backpressure).
            let available = Int(connection.sndbuf())
            guard available > 0 else { break }

            let chunkLen = min(output.count, available, Int(UInt16.max))
            var chunk: [UInt8] = []
            chunk.reserveCapacity(chunkLen)

            for index in 0..<chunkLen {
                guard let byte = output.peek(at: index) else { break }
                chunk.append(byte)
            }

            guard !chunk.isEmpty else { break }

            let writeErr = chunk.withUnsafeBytes { buffer -> LWIPError in
                guard let baseAddress = buffer.baseAddress else { return .ok }
                let apiFlags: UInt8 = output.count > chunk.count
                    ? TCPConstants.writeFlagCopy | TCPConstants.writeFlagMore
                    : TCPConstants.writeFlagCopy
                return connection.write(
                    baseAddress,
                    len: UInt16(chunk.count),
                    apiFlags: apiFlags
                )
            }

            if writeErr == .ok {
                output.skip(chunk.count)
                continue
            }

            if writeErr == .outOfMemory {
                break
            }

            closeConnection(reason: .disconnected)
            return
        }

        let outputErr = connection.output()
        if outputErr != .ok && outputErr != .routingError {
            closeConnection(reason: .disconnected)
        }
    }

    /// Close the connection and notify the callback.
    private func closeConnection(reason: MQTTConnectionStatus) {
        let connection = conn
        connState = .tcpDisconnected
        conn = nil
        serverWatchdog = 0
        cyclicTick = 0
        resetInputState()

        // Clear QoS 2 state.
        qos2InFlight.removeAll()
        qos2PendingIncoming.removeAll()

        // Fail all pending requests.
        var req = pendingRequestQueue
        pendingRequestQueue = nil
        while let r = req {
            let next = r.next
            r.next = nil
            let cb = r.callback
            r.callback = nil
            cb?(.aborted)
            req = next
        }

        // Notify connection callback.
        let callback = connectCallback
        connectCallback = nil

        if let connection {
            closeAltcpConnection(connection)
        }

        callback?(self, reason)
    }

    // MARK: - Internal: Cyclic Timer

    /// Called periodically to handle timeouts and keepalive.
    internal func cyclicTimer() {
        lock.lock()
        defer { lock.unlock() }

        guard connState != .tcpDisconnected else { return }

        cyclicTick += 1

        // Server watchdog.
        if connState == .mqttConnecting {
            if cyclicTick >= serverWatchdog {
                closeConnection(reason: .timeout)
                return
            }
        }

        // Keep alive.
        if connState == .mqttConnected && keepAlive > 0 {
            if cyclicTick >= keepAlive {
                // Send PINGREQ.
                buildFixedHeader(type: .pingReq, remainingLength: 0)
                flushOutput()
                cyclicTick = 0
            }
        }

        // Request timeouts.
        var req = pendingRequestQueue
        while let r = req {
            if r.timeoutDiff > 0 {
                r.timeoutDiff -= min(r.timeoutDiff, MQTTConfig.cyclicTimerInterval)
                if r.timeoutDiff == 0 {
                    let next = r.next
                    completeRequest(packetId: r.packetId, error: .timeout)
                    req = next
                    continue
                }
            }
            req = r.next
        }
    }

    // MARK: - Internal: Incoming Data Processing

    /// Process received TCP data. Called from the TCP receive callback.
    internal func processIncoming(data: UnsafeBufferPointer<UInt8>) {
        lock.lock()
        defer { lock.unlock() }

        guard connState == .mqttConnecting || connState == .mqttConnected else { return }

        if !data.isEmpty {
            rxBuffer.append(contentsOf: data)
            msgIndex = UInt32(rxBuffer.count)
        }

        var consumedBytes = 0

        parseLoop: while consumedBytes < rxBuffer.count {
            switch parseFrame(at: consumedBytes) {
            case .incomplete:
                break parseLoop
            case .invalid:
                closeConnection(reason: .disconnected)
                return
            case .complete(let messageType, let headerByte, let fixedHeaderLength, let remainingLength):
                let messageEnd = consumedBytes + fixedHeaderLength + remainingLength
                guard messageEnd <= rxBuffer.count else {
                    break parseLoop
                }

                let frame = Array(rxBuffer[consumedBytes..<messageEnd])
                frame.withUnsafeBufferPointer { frameBuffer in
                    let payloadOffset = fixedHeaderLength

                    switch messageType {
                    case .connAck:
                        handleConnAck(data: frameBuffer, offset: payloadOffset, length: remainingLength)
                    case .publish:
                        handlePublish(data: frameBuffer, offset: payloadOffset, length: remainingLength,
                                      flags: headerByte & 0x0F)
                    case .pubAck:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            completeRequest(packetId: pktId, error: .ok)
                        }
                    case .pubRec:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            if let state = findQoS2State(packetId: pktId),
                               state.phase == .awaitingPubRec {
                                state.phase = .awaitingPubComp
                                sendQoS2Ack(type: .pubRel, packetId: pktId)
                            }
                        }
                    case .pubRel:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            removeQoS2State(packetId: pktId)

                            if let pending = qos2PendingIncoming.removeValue(forKey: pktId) {
                                incomingPublishCallback?(pending.topic, pending.totalLength)
                                if !pending.payload.isEmpty {
                                    pending.payload.withUnsafeBufferPointer { payloadPtr in
                                        incomingDataCallback?(payloadPtr, .last)
                                    }
                                }
                            }

                            sendQoS2Ack(type: .pubComp, packetId: pktId)
                        }
                    case .pubComp:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            removeQoS2State(packetId: pktId)
                            completeRequest(packetId: pktId, error: .ok)
                        }
                    case .subAck:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            completeRequest(packetId: pktId, error: .ok)
                        }
                    case .unsubAck:
                        if remainingLength >= 2 {
                            let pktId = (UInt16(frameBuffer[payloadOffset]) << 8) | UInt16(frameBuffer[payloadOffset + 1])
                            completeRequest(packetId: pktId, error: .ok)
                        }
                    case .pingResp:
                        serverWatchdog = 0
                    default:
                        break
                    }
                }

                consumedBytes = messageEnd
            }
        }

        if consumedBytes > 0 {
            rxBuffer.removeFirst(consumedBytes)
            msgIndex = UInt32(rxBuffer.count)
        }
    }

    private func resetInputState() {
        msgIndex = 0
        rxBuffer.removeAll(keepingCapacity: true)
    }

    private enum MQTTFrameParseResult {
        case incomplete
        case invalid
        case complete(MQTTMessageType?, UInt8, Int, Int)
    }

    private func parseFrame(at offset: Int) -> MQTTFrameParseResult {
        guard offset < rxBuffer.count else { return .incomplete }

        let headerByte = rxBuffer[offset]
        let messageType = MQTTMessageType(rawValue: headerByte >> 4)

        var remainingLength = 0
        var multiplier = 1
        var index = offset + 1
        var encodedLengthBytes = 0

        while true {
            guard index < rxBuffer.count else { return .incomplete }

            let encodedByte = rxBuffer[index]
            index += 1
            encodedLengthBytes += 1

            remainingLength += Int(encodedByte & 0x7F) * multiplier
            if (encodedByte & 0x80) == 0 {
                return .complete(messageType, headerByte, index - offset, remainingLength)
            }

            guard encodedLengthBytes < 4 else { return .invalid }
            multiplier *= 128
        }
    }

    /// Handle CONNACK packet.
    private func handleConnAck(data: UnsafeBufferPointer<UInt8>, offset: Int, length: Int) {
        guard length >= 2 else { return }
        let returnCode = data[offset + 1]

        if returnCode == 0 {
            connState = .mqttConnected
            cyclicTick = 0
            connectCallback?(self, .accepted)
        } else {
            let status = MQTTConnectionStatus(rawValue: Int(returnCode)) ?? .refusedServer
            closeConnection(reason: status)
        }
    }

    /// Handle PUBLISH packet.
    private func handlePublish(data: UnsafeBufferPointer<UInt8>, offset: Int,
                               length: Int, flags: UInt8) {
        guard length >= 2 else { return }
        var pos = offset

        let topicLen = (Int(data[pos]) << 8) | Int(data[pos + 1])
        pos += 2

        guard pos + topicLen <= offset + length else { return }

        let topicBytes = Array(data[pos..<(pos + topicLen)])
        let topic = String(bytes: topicBytes, encoding: .utf8) ?? ""
        pos += topicLen

        let qos = (flags >> 1) & 0x03

        var packetId: UInt16 = 0
        if qos > 0 {
            guard pos + 2 <= offset + length else { return }
            packetId = (UInt16(data[pos]) << 8) | UInt16(data[pos + 1])
            pos += 2
        }

        let payloadLen = (offset + length) - pos
        let totalLen = UInt32(payloadLen)

        if qos == 2 {
            // QoS 2 incoming: store the message, send PUBREC, and defer delivery
            // until PUBREL is received. We store the payload so we can deliver it
            // when the handshake completes.
            let storedPayload: [UInt8]
            if payloadLen > 0 {
                storedPayload = Array(data[pos..<(pos + payloadLen)])
            } else {
                storedPayload = []
            }

            let state = QoS2State(packetId: packetId, phase: .awaitingPubRel)
            qos2InFlight.append(state)

            // Store topic and payload for deferred delivery.
            qos2PendingIncoming[packetId] = (topic: topic, totalLength: totalLen,
                                             payload: storedPayload)

            sendQoS2Ack(type: .pubRec, packetId: packetId)
        } else {
            // QoS 0 and QoS 1: deliver immediately.
            incomingPublishCallback?(topic, totalLen)

            if payloadLen > 0 {
                let payloadPtr = UnsafeBufferPointer(start: data.baseAddress?.advanced(by: pos),
                                                      count: payloadLen)
                incomingDataCallback?(payloadPtr, .last)
            }

            // Send PUBACK for QoS 1.
            if qos == 1 {
                buildFixedHeader(type: .pubAck, remainingLength: 2)
                _ = output.writeByte(UInt8(packetId >> 8))
                _ = output.writeByte(UInt8(packetId & 0xFF))
                flushOutput()
            }
        }
    }
}
