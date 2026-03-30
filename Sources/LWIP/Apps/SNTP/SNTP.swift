//
//  SNTP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - SNTP Configuration

/// SNTP client configuration constants.
public enum SNTPConfig {
    /// Maximum number of NTP servers.
    public static var maxServers: Int = 1
    /// SNTP port (NTP).
    public static let port: UInt16 = 123
    /// Receive timeout in milliseconds.
    public static var recvTimeout: UInt32 = 15_000
    /// Update delay between polls in milliseconds.
    public static var updateDelay: UInt32 = 3_600_000
    /// Retry timeout in milliseconds.
    public static var retryTimeout: UInt32 = 15_000
    /// Maximum retry timeout in milliseconds.
    public static var retryTimeoutMax: UInt32 = 150_000
    /// Whether retry timeout doubles on each retry.
    public static var retryTimeoutExponential: Bool = true
    /// Enable round-trip delay compensation.
    public static var compensateRoundTrip: Bool = false
    /// Response sanity check level (0-4).
    public static var checkResponse: Int = 0
    /// Monitor server reachability.
    public static var monitorReachability: Bool = true
    /// Support DNS server names.
    public static var supportDNS: Bool = false
    /// Enable startup delay.
    public static var startupDelay: Bool = false
    /// Enable server mode (receive broadcast/multicast NTP packets in addition to polling).
    public static var serverMode: Bool = false
}

// MARK: - SNTP KoD Codes

/// Well-known Kiss-of-Death codes from RFC 4330.
internal enum SNTPKoDCode: String {
    /// Access denied; stop querying this server permanently.
    case deny = "DENY"
    /// Access restricted; stop querying this server permanently.
    case rstr = "RSTR"
    /// Rate exceeded; slow down (increase polling interval).
    case rate = "RATE"
    /// Other/unknown code.
    case unknown = ""

    /// Parse a 4-byte reference identifier into a KoD code.
    static func from(referenceId: UInt32) -> SNTPKoDCode {
        let b0 = UInt8((referenceId >> 24) & 0xFF)
        let b1 = UInt8((referenceId >> 16) & 0xFF)
        let b2 = UInt8((referenceId >> 8) & 0xFF)
        let b3 = UInt8(referenceId & 0xFF)
        let chars = [b0, b1, b2, b3]
        let str = String(chars.map { Character(UnicodeScalar($0)) })
            .trimmingCharacters(in: .controlCharacters)
            .trimmingCharacters(in: .whitespaces)
        switch str {
        case "DENY": return .deny
        case "RSTR": return .rstr
        case "RATE": return .rate
        default:     return .unknown
        }
    }
}

// MARK: - SNTP Operating Mode

/// SNTP operating modes.
public enum SNTPOperatingMode: UInt8, Sendable {
    /// Poll servers using unicast.
    case poll       = 0
    /// Listen only (broadcast/multicast).
    case listenOnly = 1
}

// MARK: - NTP Timestamp

/// NTP timestamp (seconds since 1900-01-01).
public struct NTPTimestamp: Sendable {
    /// Seconds since 1900-01-01.
    public var seconds: UInt32
    /// Fractional seconds (1/2^32 of a second).
    public var fraction: UInt32

    public init(seconds: UInt32 = 0, fraction: UInt32 = 0) {
        self.seconds = seconds
        self.fraction = fraction
    }

    /// Convert NTP timestamp to Unix time (seconds since 1970-01-01).
    public var unixTimestamp: UInt32 {
        // NTP epoch is 1900-01-01, Unix epoch is 1970-01-01.
        // Difference is 70 years = 2208988800 seconds.
        let ntpUnixDiff: UInt32 = 2_208_988_800
        return seconds &- ntpUnixDiff
    }
}

// MARK: - NTP Packet

/// NTP packet structure (48 bytes).
internal struct NTPPacket {
    /// Leap indicator, version, mode.
    var liVnMode: UInt8 = 0
    /// Stratum level.
    var stratum: UInt8 = 0
    /// Polling interval.
    var poll: UInt8 = 0
    /// Precision.
    var precision: Int8 = 0
    /// Root delay.
    var rootDelay: UInt32 = 0
    /// Root dispersion.
    var rootDispersion: UInt32 = 0
    /// Reference identifier.
    var referenceId: UInt32 = 0
    /// Reference timestamp.
    var referenceTimestamp: NTPTimestamp = NTPTimestamp()
    /// Originate timestamp.
    var originateTimestamp: NTPTimestamp = NTPTimestamp()
    /// Receive timestamp.
    var receiveTimestamp: NTPTimestamp = NTPTimestamp()
    /// Transmit timestamp.
    var transmitTimestamp: NTPTimestamp = NTPTimestamp()

    static let size = 48

    /// Build a client request packet.
    static func clientRequest() -> NTPPacket {
        var pkt = NTPPacket()
        pkt.liVnMode = 0x1B  // LI=0, VN=3, Mode=3 (client)
        return pkt
    }

    /// Serialize to bytes (big-endian).
    func toBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: NTPPacket.size)
        bytes[0] = liVnMode
        bytes[1] = stratum
        bytes[2] = poll
        bytes[3] = UInt8(bitPattern: precision)
        writeU32(&bytes, offset: 4, value: rootDelay)
        writeU32(&bytes, offset: 8, value: rootDispersion)
        writeU32(&bytes, offset: 12, value: referenceId)
        writeU32(&bytes, offset: 16, value: referenceTimestamp.seconds)
        writeU32(&bytes, offset: 20, value: referenceTimestamp.fraction)
        writeU32(&bytes, offset: 24, value: originateTimestamp.seconds)
        writeU32(&bytes, offset: 28, value: originateTimestamp.fraction)
        writeU32(&bytes, offset: 32, value: receiveTimestamp.seconds)
        writeU32(&bytes, offset: 36, value: receiveTimestamp.fraction)
        writeU32(&bytes, offset: 40, value: transmitTimestamp.seconds)
        writeU32(&bytes, offset: 44, value: transmitTimestamp.fraction)
        return bytes
    }

    /// Parse from bytes.
    static func fromBytes(_ data: [UInt8]) -> NTPPacket? {
        guard data.count >= NTPPacket.size else { return nil }
        var pkt = NTPPacket()
        pkt.liVnMode = data[0]
        pkt.stratum = data[1]
        pkt.poll = data[2]
        pkt.precision = Int8(bitPattern: data[3])
        pkt.rootDelay = readU32(data, offset: 4)
        pkt.rootDispersion = readU32(data, offset: 8)
        pkt.referenceId = readU32(data, offset: 12)
        pkt.referenceTimestamp = NTPTimestamp(seconds: readU32(data, offset: 16),
                                              fraction: readU32(data, offset: 20))
        pkt.originateTimestamp = NTPTimestamp(seconds: readU32(data, offset: 24),
                                              fraction: readU32(data, offset: 28))
        pkt.receiveTimestamp = NTPTimestamp(seconds: readU32(data, offset: 32),
                                            fraction: readU32(data, offset: 36))
        pkt.transmitTimestamp = NTPTimestamp(seconds: readU32(data, offset: 40),
                                             fraction: readU32(data, offset: 44))
        return pkt
    }

    private func writeU32(_ bytes: inout [UInt8], offset: Int, value: UInt32) {
        bytes[offset]     = UInt8((value >> 24) & 0xFF)
        bytes[offset + 1] = UInt8((value >> 16) & 0xFF)
        bytes[offset + 2] = UInt8((value >> 8) & 0xFF)
        bytes[offset + 3] = UInt8(value & 0xFF)
    }

    private static func readU32(_ bytes: [UInt8], offset: Int) -> UInt32 {
        return (UInt32(bytes[offset]) << 24) |
               (UInt32(bytes[offset + 1]) << 16) |
               (UInt32(bytes[offset + 2]) << 8) |
               UInt32(bytes[offset + 3])
    }
}

// MARK: - SNTP Server

/// An NTP server entry.
public struct SNTPServer: Sendable {
    /// Server IP address.
    public var address: IPAddress
    /// Server hostname (for DNS mode).
    public var hostname: String?
    /// Whether a KOD (Kiss of Death) was received that permanently denies access.
    public var kodReceived: Bool = false
    /// Reachability shift register (RFC 5905). Shifted left on each request;
    /// bit 0 set on valid response. Non-zero means the server is reachable.
    public var reachability: UInt8 = 0

    public init(address: IPAddress, hostname: String? = nil) {
        self.address = address
        self.hostname = hostname
    }

    /// Whether this server entry has a valid (non-any) address or hostname configured.
    public var isConfigured: Bool {
        return address != .any || hostname != nil
    }
}

// MARK: - SNTP Callbacks

extension SNTPClient {
    /// Callback when system time should be set.
    public typealias SetTimeHandler = @Sendable (UInt32, UInt32) -> Void
}

// MARK: - SNTPClient

/// SNTP time synchronization client.
///
/// Periodically queries NTP servers and calls a user-defined function
/// to set the system time. Supports multiple server rotation, Kiss-of-Death
/// handling per RFC 4330, exponential backoff on failure, reachability
/// tracking per RFC 5905, and optional server (broadcast) mode.
public final class SNTPClient: @unchecked Sendable {

    /// Shared instance.
    public static let shared = SNTPClient()

    /// Operating mode.
    private var operatingMode: SNTPOperatingMode = .poll

    /// NTP server list.
    private var servers: [SNTPServer]

    /// Current server index.
    private var currentServer: Int = 0

    /// UDP control block for unicast communication.
    private var udpControlBlock: UDPControlBlock?

    /// UDP control block for broadcast/multicast reception (server mode).
    private var broadcastControlBlock: UDPControlBlock?

    /// Whether the client is running.
    private var isRunning: Bool = false

    /// Current retry timeout (doubles on each failure up to retryTimeoutMax).
    private var currentRetryTimeout: UInt32

    /// Set-time callback.
    public var setTimeCallback: SNTPClient.SetTimeHandler?

    /// Transmit timestamp from our last request (for round-trip compensation).
    private var requestTransmitTimestamp = NTPTimestamp()

    /// Local time (in NTP seconds) when the request was sent (T1).
    private var requestSendTime: UInt32 = 0

    /// Lock.
    private let lock = NSLock()

    private init() {
        servers = Array(repeating: SNTPServer(address: .any),
                       count: SNTPConfig.maxServers)
        currentRetryTimeout = SNTPConfig.retryTimeout
    }

    // MARK: - Configuration

    /// Set the operating mode (must be called before `start`).
    public func setOperatingMode(_ mode: SNTPOperatingMode) {
        lock.lock()
        operatingMode = mode
        lock.unlock()
    }

    /// Get the current operating mode.
    public func getOperatingMode() -> SNTPOperatingMode {
        lock.lock()
        defer { lock.unlock() }
        return operatingMode
    }

    /// Set an NTP server by address. Resets KoD and reachability state.
    public func setServer(index: UInt8, address: IPAddress) {
        let idx = Int(index)
        lock.lock()
        guard idx < servers.count else { lock.unlock(); return }
        servers[idx] = SNTPServer(address: address)
        lock.unlock()
    }

    /// Get an NTP server address.
    public func getServer(index: UInt8) -> IPAddress {
        let idx = Int(index)
        lock.lock()
        defer { lock.unlock() }
        guard idx < servers.count else { return .any }
        return servers[idx].address
    }

    /// Set an NTP server by hostname. Resets KoD state.
    public func setServerName(index: UInt8, name: String) {
        let idx = Int(index)
        lock.lock()
        guard idx < servers.count else { lock.unlock(); return }
        servers[idx].hostname = name
        servers[idx].kodReceived = false
        lock.unlock()
    }

    /// Get an NTP server hostname.
    public func getServerName(index: UInt8) -> String? {
        let idx = Int(index)
        lock.lock()
        defer { lock.unlock() }
        guard idx < servers.count else { return nil }
        return servers[idx].hostname
    }

    /// Check if a KOD was received from a server.
    public func getKODReceived(index: UInt8) -> Bool {
        let idx = Int(index)
        lock.lock()
        defer { lock.unlock() }
        guard idx < servers.count else { return false }
        return servers[idx].kodReceived
    }

    /// Get server reachability shift register (RFC 5905).
    public func getReachability(index: UInt8) -> UInt8 {
        let idx = Int(index)
        lock.lock()
        defer { lock.unlock() }
        guard idx < servers.count else { return 0 }
        return servers[idx].reachability
    }

    /// Check if a server is reachable (any bit set in the reachability register).
    public func isServerReachable(index: UInt8) -> Bool {
        return getReachability(index: index) != 0
    }

    /// Enable server mode: in addition to polling, also listen for
    /// broadcast/multicast NTP packets on the standard NTP port.
    /// Must be called before `start()`.
    public func enableServerMode() {
        SNTPConfig.serverMode = true
    }

    // MARK: - Start / Stop

    /// Initialize and start the SNTP client.
    public func start() {
        lock.lock()
        guard !isRunning else { lock.unlock(); return }
        isRunning = true
        currentRetryTimeout = SNTPConfig.retryTimeout
        let mode = operatingMode
        let serverModeEnabled = SNTPConfig.serverMode
        lock.unlock()

        // Create UDP PCB for normal operation.
        let udpPcb = UDPControlBlock()

        // Set receive callback before binding.
        udpPcb.receiveHandler = { [weak self] _, pbuf, addr, port in
            self?.receivePacket(pbuf: pbuf, from: addr, port: port)
        }

        if mode == .listenOnly {
            // In listen-only mode, bind to NTP port to receive broadcasts.
            _ = UDPGlobal.shared.bind(udpPcb, address: .any, port: SNTPConfig.port)
        } else {
            // In poll mode, bind to an ephemeral port.
            _ = UDPGlobal.shared.bind(udpPcb, address: .any, port: 0)
        }

        lock.lock()
        udpControlBlock = udpPcb
        lock.unlock()

        // If server mode is enabled and we are in poll mode, additionally bind
        // a second PCB to the NTP port for receiving unsolicited broadcasts.
        if serverModeEnabled && mode == .poll {
            let bcastPcb = UDPControlBlock()
            bcastPcb.receiveHandler = { [weak self] _, pbuf, addr, port in
                self?.receivePacket(pbuf: pbuf, from: addr, port: port)
            }
            _ = UDPGlobal.shared.bind(bcastPcb, address: .any, port: SNTPConfig.port)
            lock.lock()
            broadcastControlBlock = bcastPcb
            lock.unlock()
        }

        // Schedule first request.
        if mode == .poll {
            if SNTPConfig.startupDelay {
                let delay = UInt32.random(in: 0...5000)
                scheduleRequest(delayMs: delay)
            } else {
                sendRequest()
            }
        }
    }

    /// Stop the SNTP client.
    public func stop() {
        lock.lock()
        isRunning = false

        // Reset reachability for all servers.
        for i in 0..<servers.count {
            servers[i].reachability = 0
        }

        if let udpPcb = udpControlBlock {
            UDPGlobal.shared.remove(udpPcb)
            udpControlBlock = nil
        }
        if let bcastPcb = broadcastControlBlock {
            UDPGlobal.shared.remove(bcastPcb)
            broadcastControlBlock = nil
        }
        lock.unlock()
    }

    /// Whether the client is running.
    public var isEnabled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isRunning
    }

    // MARK: - Packet Reception

    /// Common packet reception handler shared by both the primary and
    /// broadcast UDP control blocks.
    private func receivePacket(pbuf: Pbuf, from addr: IPAddress, port: UInt16) {
        let totalLen = Int(pbuf.totLen)
        guard totalLen >= NTPPacket.size else {
            _ = Pbuf.free(pbuf)
            return
        }
        var data = [UInt8](repeating: 0, count: totalLen)
        data.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = pbuf.copyPartial(to: UnsafeMutableRawPointer(base),
                                 len: UInt16(totalLen), offset: 0)
        }
        _ = Pbuf.free(pbuf)
        handleResponse(data, from: addr)
    }

    // MARK: - Request / Response

    /// Send an SNTP request to the current server.
    private func sendRequest() {
        lock.lock()
        guard isRunning else { lock.unlock(); return }

        let serverIdx = currentServer
        guard serverIdx < servers.count else { lock.unlock(); return }
        let server = servers[serverIdx]
        let udpPcb = udpControlBlock
        lock.unlock()

        guard let udpPcb = udpPcb else { return }

        // Resolve hostname if needed.
        var serverAddr = server.address
        if let hostname = server.hostname, serverAddr == .any {
            if case .success(let addr) = NetConn.getHostByName(hostname) {
                serverAddr = addr
                lock.lock()
                servers[serverIdx].address = addr
                lock.unlock()
            } else {
                // DNS failed, try next server or retry.
                tryNextServer()
                return
            }
        }

        guard serverAddr != .any else {
            tryNextServer()
            return
        }

        // Build NTP request packet (LI=0, VN=4, Mode=3 client).
        var pkt = NTPPacket()
        pkt.liVnMode = (0x00 << 6) | (4 << 3) | 0x03  // LI=0, VN=4, Mode=Client

        // Store T1 for round-trip compensation and response validation.
        if SNTPConfig.compensateRoundTrip || SNTPConfig.checkResponse >= 2 {
            let now = UInt32(Date().timeIntervalSince1970) &+ 2_208_988_800
            pkt.transmitTimestamp = NTPTimestamp(seconds: now, fraction: 0)
            lock.lock()
            requestTransmitTimestamp = pkt.transmitTimestamp
            requestSendTime = now
            lock.unlock()
        }

        let packetBytes = pkt.toBytes()

        // Allocate a pbuf and send the request.
        guard let p = Pbuf.alloc(layer: .transport, length: UInt16(NTPPacket.size), type: .ram) else {
            // Out of memory, schedule a retry at base retry timeout.
            scheduleRequest(delayMs: SNTPConfig.retryTimeout)
            return
        }

        packetBytes.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            p.payload.copyMemory(from: base, byteCount: NTPPacket.size)
        }

        _ = UDPGlobal.shared.sendTo(udpPcb, pbuf: p, dstIP: serverAddr, dstPort: SNTPConfig.port)
        _ = Pbuf.free(p)

        // Update reachability shift register (indicate packet sent).
        if SNTPConfig.monitorReachability {
            lock.lock()
            if serverIdx < servers.count {
                servers[serverIdx].reachability <<= 1
            }
            lock.unlock()
        }

        // Schedule timeout: on timeout, try the next server.
        scheduleTimeout()
    }

    /// Handle a received NTP response.
    internal func handleResponse(_ data: [UInt8], from: IPAddress) {
        guard let response = NTPPacket.fromBytes(data) else { return }

        lock.lock()
        guard isRunning else { lock.unlock(); return }
        let mode = operatingMode
        lock.unlock()

        // Validate mode field from the response.
        let responseMode = response.liVnMode & 0x07
        let isValidMode: Bool
        switch mode {
        case .poll:
            // Expect server mode (4) in response to our client request.
            isValidMode = responseMode == 0x04
        case .listenOnly:
            // Expect broadcast mode (5).
            isValidMode = responseMode == 0x05
        }

        // In server mode (hybrid), also accept broadcast packets.
        let acceptBroadcast = SNTPConfig.serverMode && responseMode == 0x05

        guard isValidMode || acceptBroadcast else {
            // Wrong mode; ignore and wait for a correct response.
            return
        }

        // Check for Kiss-of-Death (stratum == 0).
        if response.stratum == 0 {
            // Only process KoD in poll mode (per C implementation).
            if mode == .poll {
                handleKoD(refID: response.referenceId, serverIndex: currentServer)
            }
            return
        }

        // --- Response validation (levels 1-4) ---
        let checkLevel = SNTPConfig.checkResponse
        if checkLevel > 0 {
            // Level 1: Reject Kiss-of-Death with unknown code (stratum 0 already handled above,
            // but guard against stratum == 0 slipping through with unknown code).
            if response.stratum == 0 {
                let kod = SNTPKoDCode.from(referenceId: response.referenceId)
                if kod == .unknown {
                    return
                }
            }
        }
        if checkLevel >= 2 {
            // Level 2: Originate timestamp in response must match our request's transmit timestamp.
            lock.lock()
            let sentTimestamp = requestTransmitTimestamp
            lock.unlock()
            if response.originateTimestamp.seconds != sentTimestamp.seconds
                || response.originateTimestamp.fraction != sentTimestamp.fraction {
                return
            }
        }
        if checkLevel >= 3 {
            // Level 3: Server must be synchronized (LI != 3 and stratum != 0).
            let li = (response.liVnMode >> 6) & 0x03
            if li == 3 || response.stratum == 0 {
                return
            }
        }
        if checkLevel >= 4 {
            // Level 4: Root delay and dispersion must be reasonable (< 1 second each).
            // NTP fixed-point: integer part is upper 16 bits, fraction is lower 16 bits.
            let rootDelaySec = response.rootDelay >> 16
            let rootDispSec = response.rootDispersion >> 16
            if rootDelaySec >= 1 || rootDispSec >= 1 {
                return
            }
        }

        // Valid response: update reachability (set bit 0).
        if SNTPConfig.monitorReachability {
            lock.lock()
            if currentServer < servers.count {
                servers[currentServer].reachability |= 1
            }
            lock.unlock()
        }

        // Extract time from transmit timestamp.
        var ntpSec = response.transmitTimestamp.seconds
        var ntpFrac = response.transmitTimestamp.fraction

        // --- Round-trip compensation ---
        if SNTPConfig.compensateRoundTrip {
            // T1 = originate timestamp (our request send time)
            // T2 = receive timestamp (server's receive time)
            // T3 = transmit timestamp (server's transmit time)
            // T4 = local receive time (now)
            let t4 = UInt32(Date().timeIntervalSince1970) &+ 2_208_988_800

            lock.lock()
            let t1 = requestSendTime
            lock.unlock()

            let t2 = response.receiveTimestamp.seconds
            let t3 = response.transmitTimestamp.seconds

            // offset = ((T2 - T1) + (T3 - T4)) / 2
            // Using signed arithmetic to handle the subtraction correctly.
            let diff1 = Int64(t2) - Int64(t1)
            let diff2 = Int64(t3) - Int64(t4)
            let offsetSec = (diff1 + diff2) / 2

            // Apply offset: corrected time = T4 + offset
            let corrected = Int64(t4) + offsetSec
            ntpSec = UInt32(truncatingIfNeeded: corrected)
            ntpFrac = response.transmitTimestamp.fraction
        }

        // Convert fractional part to microseconds.
        let usec = UInt32((UInt64(ntpFrac) * 1_000_000) >> 32)

        // Set system time.
        setTimeCallback?(ntpSec, usec)

        // Correct response: reset retry timeout and schedule next poll.
        if mode == .poll {
            lock.lock()
            currentRetryTimeout = SNTPConfig.retryTimeout
            lock.unlock()

            scheduleRequest(delayMs: SNTPConfig.updateDelay)
        }
    }

    // MARK: - Kiss-of-Death Handling

    /// Handle a Kiss-of-Death packet per RFC 4330.
    ///
    /// - Parameters:
    ///   - refID: The 4-byte reference identifier from the NTP response,
    ///     interpreted as an ASCII KoD code.
    ///   - serverIndex: Index of the server that sent the KoD.
    internal func handleKoD(refID: UInt32, serverIndex: Int) {
        let code = SNTPKoDCode.from(referenceId: refID)

        lock.lock()
        guard serverIndex < servers.count else { lock.unlock(); return }

        switch code {
        case .deny, .rstr:
            // Access permanently denied. Mark server and switch to next.
            servers[serverIndex].kodReceived = true
            lock.unlock()
            kodTryNextServer()

        case .rate:
            // Rate limit: increase polling interval via exponential backoff.
            increaseRetryTimeout()
            let retryDelay = currentRetryTimeout
            lock.unlock()
            scheduleRequest(delayMs: retryDelay)

        case .unknown:
            // Unknown KoD code: mark and try next server (conservative approach).
            servers[serverIndex].kodReceived = true
            lock.unlock()
            kodTryNextServer()
        }
    }

    // MARK: - Server Rotation

    /// Try the next available server, skipping any that have received a KoD denial
    /// or are not configured.
    ///
    /// If no other valid server is found, fall back to the current server and retry
    /// with exponential backoff.
    private func tryNextServer() {
        lock.lock()
        let oldServer = currentServer
        let count = servers.count

        // Try each other server in round-robin order.
        for _ in 0..<(count - 1) {
            currentServer += 1
            if currentServer >= count {
                currentServer = 0
            }
            let candidate = servers[currentServer]
            // Skip servers that received a KoD denial.
            if candidate.kodReceived {
                continue
            }
            // Skip servers that are not configured.
            if !candidate.isConfigured {
                continue
            }
            // Found a valid server: reset retry timeout and send immediately.
            currentRetryTimeout = SNTPConfig.retryTimeout
            lock.unlock()
            sendRequest()
            return
        }

        // No other valid server found; stay on the current server and retry.
        currentServer = oldServer
        increaseRetryTimeout()
        let retryDelay = currentRetryTimeout
        lock.unlock()
        scheduleRequest(delayMs: retryDelay)
    }

    /// Mark the current server as KoD-denied and try the next server.
    private func kodTryNextServer() {
        lock.lock()
        if currentServer < servers.count {
            servers[currentServer].kodReceived = true
        }
        lock.unlock()
        tryNextServer()
    }

    // MARK: - Exponential Backoff

    /// Increase the retry timeout using exponential backoff, capped at the maximum.
    /// Must be called while the lock is held.
    private func increaseRetryTimeout() {
        guard SNTPConfig.retryTimeoutExponential else { return }

        let newTimeout = currentRetryTimeout << 1
        // Guard against overflow and cap at maximum.
        if newTimeout <= SNTPConfig.retryTimeoutMax && newTimeout > currentRetryTimeout {
            currentRetryTimeout = newTimeout
        } else {
            currentRetryTimeout = SNTPConfig.retryTimeoutMax
        }
    }

    // MARK: - Scheduling

    /// Schedule a request after a delay.
    private func scheduleRequest(delayMs: UInt32) {
        TCPIP.shared.timeout(msecs: delayMs) { [weak self] in
            self?.sendRequest()
        }
    }

    /// Schedule a response timeout. On timeout, tries the next server.
    private func scheduleTimeout() {
        TCPIP.shared.timeout(msecs: SNTPConfig.recvTimeout) { [weak self] in
            self?.tryNextServer()
        }
    }

    // MARK: - Reachability

    /// Select the best reachable server index. Returns the first server with
    /// a non-zero reachability register, or falls back to the current server.
    internal func bestReachableServer() -> Int {
        lock.lock()
        defer { lock.unlock() }

        // Prefer servers that are both configured and reachable.
        for i in 0..<servers.count {
            if !servers[i].kodReceived && servers[i].isConfigured
                && servers[i].reachability != 0 {
                return i
            }
        }
        // Fallback: first configured, non-KoD server.
        for i in 0..<servers.count {
            if !servers[i].kodReceived && servers[i].isConfigured {
                return i
            }
        }
        return currentServer
    }

    // MARK: - DHCP Integration

    /// Enable or disable getting NTP servers from DHCP.
    public func setDHCPServerMode(_ enabled: Bool) {
        // In a real implementation, this would register/unregister
        // DHCP option handlers for NTP server addresses.
    }
}

