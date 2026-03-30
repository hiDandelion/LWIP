//
//  PPPUtils.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - PPP String Utilities

/// PPP utility functions for string handling and debug output.
public enum PPPUtils {

    /// Safe string copy that never overflows the destination buffer.
    /// Equivalent to strlcpy -- always null-terminates.
    ///
    /// - Parameters:
    ///   - dest: Destination buffer.
    ///   - src: Source string.
    ///   - maxLen: Maximum length of destination buffer including null terminator.
    /// - Returns: The length of the source string (not including null terminator).
    @discardableResult
    public static func strlcpy(dest: inout [UInt8], src: [UInt8], maxLen: Int) -> Int {
        let srcLen = src.count
        if maxLen > 0 {
            let copyLen = min(srcLen, maxLen - 1)
            for i in 0..<copyLen {
                dest[i] = src[i]
            }
            if copyLen < dest.count {
                dest[copyLen] = 0
            }
        }
        return srcLen
    }

    /// Format a byte buffer as a hex string for debugging.
    ///
    /// - Parameter data: The bytes to format.
    /// - Returns: A string like "01 02 0A FF".
    public static func hexDump(_ data: [UInt8]) -> String {
        return data.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    /// Format a PPP packet for debug logging.
    ///
    /// - Parameters:
    ///   - protocol: The PPP protocol number.
    ///   - data: The packet payload.
    /// - Returns: A human-readable description of the packet.
    public static func formatPacket(protocol proto: UInt16, data: [UInt8]) -> String {
        let protoName: String
        switch proto {
        case PPPProtocol.lcp:    protoName = "LCP"
        case PPPProtocol.ipcp:   protoName = "IPCP"
        case PPPProtocol.ipv6cp: protoName = "IPV6CP"
        case PPPProtocol.ccp:    protoName = "CCP"
        case PPPProtocol.ecp:    protoName = "ECP"
        case PPPProtocol.pap:    protoName = "PAP"
        case PPPProtocol.chap:   protoName = "CHAP"
        case PPPProtocol.eap:    protoName = "EAP"
        case PPPProtocol.ip:     protoName = "IP"
        case PPPProtocol.ipv6:   protoName = "IPv6"
        default:                 protoName = String(format: "0x%04X", proto)
        }

        if data.isEmpty {
            return "\(protoName) (empty)"
        }

        let code = data.first.map { String(format: "code=%d", $0) } ?? ""
        let id = data.count > 1 ? String(format: "id=%d", data[1]) : ""
        let len = data.count > 3
            ? String(format: "len=%d", (UInt16(data[2]) << 8) | UInt16(data[3]))
            : ""

        return "\(protoName) \(code) \(id) \(len)"
    }
}

// MARK: - PPP Log Levels

/// PPP debug log levels.
public enum PPPLogLevel: Int, Sendable {
    case critical = 0
    case error    = 1
    case warning  = 3
    case notice   = 5
    case info     = 7
    case debug    = 9
}

/// PPP namespace for shared utilities.
public enum PPP {
    /// Simple PPP debug logging.
    public static func debugLog(_ level: PPPLogLevel, _ message: @autoclosure () -> String) {
        #if DEBUG
        if level.rawValue <= PPPLogLevel.debug.rawValue {
            print("[PPP \(level)] \(message())")
        }
        #endif
    }
}

// MARK: - Magic Number Generation

/// PPP magic number generator.
///
/// Provides random numbers for PPP protocol negotiation (e.g., LCP magic numbers).
/// Uses a combination of system randomness and a simple PRNG seeded with
/// timing jitter for unpredictability.
public final class PPPMagic {

    /// Shared instance.
    public static let shared = PPPMagic()

    /// Random pool for MD5-based generation.
    private var randomPool = [UInt8](repeating: 0, count: 16)
    /// Pseudo-random incrementer.
    private var randomCount: UInt32 = 0
    /// Random seed.
    private var randomSeed: UInt32 = 0
    /// Whether we have been initialized.
    private var initialized = false

    public init() {}

    /// Initialize the magic number generator.
    public func initialize() {
        randomSeed = randomSeed &+ currentJiffies()
        churnRandom(data: nil)
        initialized = true
    }

    /// Add additional randomness from a system event.
    public func randomize() {
        randomSeed = randomSeed &+ currentJiffies()
        churnRandom(data: nil)
    }

    /// Churn the random pool with new entropy.
    ///
    /// - Parameter data: Optional new random data to mix in.
    private func churnRandom(data: [UInt8]?) {
        var md5 = MD5Context()
        md5.starts()
        md5.update(randomPool)
        if let data = data {
            md5.update(data)
        } else {
            // Mix in system sources of randomness
            randomSeed = randomSeed &+ currentJiffies()
            var sysData = [UInt8](repeating: 0, count: 8)
            sysData[0] = UInt8(truncatingIfNeeded: randomSeed)
            sysData[1] = UInt8(truncatingIfNeeded: randomSeed >> 8)
            sysData[2] = UInt8(truncatingIfNeeded: randomSeed >> 16)
            sysData[3] = UInt8(truncatingIfNeeded: randomSeed >> 24)
            let platformRand = UInt32.random(in: 0...UInt32.max)
            sysData[4] = UInt8(truncatingIfNeeded: platformRand)
            sysData[5] = UInt8(truncatingIfNeeded: platformRand >> 8)
            sysData[6] = UInt8(truncatingIfNeeded: platformRand >> 16)
            sysData[7] = UInt8(truncatingIfNeeded: platformRand >> 24)
            md5.update(sysData)
        }
        randomPool = md5.finish()
    }

    /// Get the current time counter (jiffies equivalent).
    private func currentJiffies() -> UInt32 {
        return UInt32(truncatingIfNeeded: DispatchTime.now().uptimeNanoseconds / 1_000_000)
    }

    /// Generate a new 32-bit magic number.
    public func magic() -> UInt32 {
        if !initialized { initialize() }
        var buf = [UInt8](repeating: 0, count: 4)
        randomBytes(&buf)
        return UInt32(buf[0]) | (UInt32(buf[1]) << 8)
             | (UInt32(buf[2]) << 16) | (UInt32(buf[3]) << 24)
    }

    /// Fill a buffer with random bytes using the random pool.
    public func randomBytes(_ buf: inout [UInt8]) {
        var remaining = buf.count
        var offset = 0
        while remaining > 0 {
            var md5 = MD5Context()
            md5.starts()
            md5.update(randomPool)
            var countBytes = [UInt8](repeating: 0, count: 4)
            countBytes[0] = UInt8(truncatingIfNeeded: randomCount)
            countBytes[1] = UInt8(truncatingIfNeeded: randomCount >> 8)
            countBytes[2] = UInt8(truncatingIfNeeded: randomCount >> 16)
            countBytes[3] = UInt8(truncatingIfNeeded: randomCount >> 24)
            md5.update(countBytes)
            let tmp = md5.finish()
            randomCount = randomCount &+ 1

            let n = min(remaining, 16)
            for i in 0..<n {
                buf[offset + i] = tmp[i]
            }
            offset += n
            remaining -= n
        }
    }

    /// Generate a random number in the range [0, 2^pow - 1].
    public func magicPow(_ pow: UInt8) -> UInt32 {
        let mask: UInt32 = pow >= 32 ? UInt32.max : ((1 << pow) - 1)
        return magic() & mask
    }
}

// MARK: - PPP Encryption Helpers

/// PPP cryptography helper functions.
///
/// Used by MS-CHAP authentication for DES key expansion.
public enum PPPCrypt {

    /// Extract 7 bits from an input byte array starting at the given bit position.
    ///
    /// - Parameters:
    ///   - input: Source byte array.
    ///   - startBit: Starting bit position.
    /// - Returns: The 7-bit value shifted to the high bits (with low bit clear for parity).
    public static func get7Bits(_ input: [UInt8], startBit: Int) -> UInt8 {
        let byteIndex = startBit / 8
        guard byteIndex + 1 < input.count else { return 0 }

        var word = UInt(input[byteIndex]) << 8
        word |= UInt(input[byteIndex + 1])
        word >>= (15 - (startBit % 8 + 7))

        return UInt8(word & 0xFE)
    }

    /// Expand a 56-bit DES key to a 64-bit key with parity bits.
    ///
    /// This is used by MS-CHAP for challenge-response computation.
    /// The input is 7 bytes (56 bits), the output is 8 bytes (56 data + 8 parity).
    ///
    /// - Parameter key56: The 56-bit key (7 bytes).
    /// - Returns: The 64-bit key (8 bytes) with parity bits added.
    public static func expand56to64(key56: [UInt8]) -> [UInt8] {
        guard key56.count >= 7 else {
            return [UInt8](repeating: 0, count: 8)
        }
        // Pad to at least 8 bytes for safe access
        let padded = key56 + [0]

        var desKey = [UInt8](repeating: 0, count: 8)
        desKey[0] = get7Bits(padded, startBit: 0)
        desKey[1] = get7Bits(padded, startBit: 7)
        desKey[2] = get7Bits(padded, startBit: 14)
        desKey[3] = get7Bits(padded, startBit: 21)
        desKey[4] = get7Bits(padded, startBit: 28)
        desKey[5] = get7Bits(padded, startBit: 35)
        desKey[6] = get7Bits(padded, startBit: 42)
        desKey[7] = get7Bits(padded, startBit: 49)
        return desKey
    }
}

// MARK: - EUI-64 Identifier

/// EUI-64 identifier used for IPv6CP interface ID negotiation.
public struct EUI64: Equatable, Sendable {
    /// The 8-byte EUI-64 value.
    public var bytes: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    public init() {
        bytes = (0, 0, 0, 0, 0, 0, 0, 0)
    }

    public init(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8,
                _ b4: UInt8, _ b5: UInt8, _ b6: UInt8, _ b7: UInt8) {
        bytes = (b0, b1, b2, b3, b4, b5, b6, b7)
    }

    /// Create an EUI-64 from a 6-byte MAC address using the IEEE method.
    /// Inserts 0xFF-0xFE in the middle and flips the universal/local bit.
    public init(mac: [UInt8]) {
        guard mac.count >= 6 else {
            bytes = (0, 0, 0, 0, 0, 0, 0, 0)
            return
        }
        bytes = (
            mac[0] ^ 0x02,  // Flip the U/L bit
            mac[1],
            mac[2],
            0xFF,
            0xFE,
            mac[3],
            mac[4],
            mac[5]
        )
    }

    /// Whether this EUI-64 is all zeros.
    public var isZero: Bool {
        return bytes.0 == 0 && bytes.1 == 0 && bytes.2 == 0 && bytes.3 == 0
            && bytes.4 == 0 && bytes.5 == 0 && bytes.6 == 0 && bytes.7 == 0
    }

    /// XOR two EUI-64 identifiers.
    public static func ^ (lhs: EUI64, rhs: EUI64) -> EUI64 {
        return EUI64(lhs.bytes.0 ^ rhs.bytes.0, lhs.bytes.1 ^ rhs.bytes.1,
                     lhs.bytes.2 ^ rhs.bytes.2, lhs.bytes.3 ^ rhs.bytes.3,
                     lhs.bytes.4 ^ rhs.bytes.4, lhs.bytes.5 ^ rhs.bytes.5,
                     lhs.bytes.6 ^ rhs.bytes.6, lhs.bytes.7 ^ rhs.bytes.7)
    }

    /// Format as a human-readable string (xxxx:xxxx:xxxx:xxxx).
    public func toString() -> String {
        return String(format: "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      bytes.0, bytes.1, bytes.2, bytes.3,
                      bytes.4, bytes.5, bytes.6, bytes.7)
    }

    /// Get the bytes as an array.
    public func toArray() -> [UInt8] {
        return [bytes.0, bytes.1, bytes.2, bytes.3,
                bytes.4, bytes.5, bytes.6, bytes.7]
    }

    public static func == (lhs: EUI64, rhs: EUI64) -> Bool {
        return lhs.bytes.0 == rhs.bytes.0 && lhs.bytes.1 == rhs.bytes.1
            && lhs.bytes.2 == rhs.bytes.2 && lhs.bytes.3 == rhs.bytes.3
            && lhs.bytes.4 == rhs.bytes.4 && lhs.bytes.5 == rhs.bytes.5
            && lhs.bytes.6 == rhs.bytes.6 && lhs.bytes.7 == rhs.bytes.7
    }
}

// MARK: - Demand Dialing

/// PPP network protocol mode for demand dialing.
public enum NPMode: UInt8, Sendable {
    /// Pass packets normally.
    case pass   = 0
    /// Drop packets with error.
    case error  = 1
    /// Queue packets for later.
    case queue  = 2
    /// Drop packets silently.
    case drop   = 3
}

/// Demand dialing support for PPP.
///
/// When demand dialing is enabled, the PPP link is only brought up
/// when interesting traffic is detected. Packets received while the
/// link is down are queued and transmitted when the link comes up.
public final class DemandDialer {

    /// Queued packet.
    public struct QueuedPacket {
        public var data: [UInt8]
        public var length: Int

        public init(data: [UInt8]) {
            self.data = data
            self.length = data.count
        }
    }

    /// PPP FCS lookup table (CRC-16/HDLC).
    private static let fcsTable: [UInt16] = {
        var table = [UInt16](repeating: 0, count: 256)
        for i in 0..<256 {
            var fcs = UInt16(i)
            for _ in 0..<8 {
                if (fcs & 1) != 0 {
                    fcs = (fcs >> 1) ^ 0x8408
                } else {
                    fcs >>= 1
                }
            }
            table[i] = fcs
        }
        return table
    }()

    /// PPP FCS good final value.
    private static let goodFCS: UInt16 = 0xF0B8

    /// Frame buffer for loopback processing.
    public var frame = [UInt8]()
    /// Maximum frame size.
    public var frameMax: Int
    /// Whether escape was seen in async framing.
    public var escapeFlag: Bool = false
    /// Whether current frame should be flushed.
    public var flushFlag: Bool = false
    /// Running FCS value.
    public var fcs: UInt16

    /// Pending packet queue.
    public var pendingQueue = [QueuedPacket]()

    /// Maximum number of queued packets.
    public var maxQueueSize: Int = 64

    /// NCP protocol mode table (indexed by protocol ID).
    /// Tracks the current mode for each NCP (IPCP, IPv6CP, etc.).
    public var ncpModes: [UInt16: NPMode] = [
        PPPProtocol.ip:   .pass,
        PPPProtocol.ipv6: .pass,
    ]

    /// Callback invoked to initiate the PPP connection when interesting traffic is detected.
    public var dialCallback: (() -> Void)?

    /// Whether the link is currently being dialed.
    public var isDialing: Bool = false

    /// Initialize demand dialer with default MRU.
    public init(mru: Int = 1500) {
        frameMax = mru + 4 + 2  // PPP_HDRLEN + PPP_FCSLEN
        frame.reserveCapacity(frameMax)
        fcs = 0xFFFF  // PPP_INITFCS
    }

    /// Whether demand dialing is enabled.
    public var isDemandMode: Bool = false

    /// Idle timeout in seconds (0 = no idle timeout).
    public var idleTimeout: UInt32 = 0

    /// Last time an interesting packet was seen (for idle detection).
    private var lastActiveTime: UInt64 = 0

    /// Callback invoked when idle timeout is reached.
    public var idleCallback: (() -> Void)?

    /// Active filter: if set, only packets matching this filter trigger dialing.
    /// The filter receives the PPP protocol and data, returning true if interesting.
    public var activeFilter: ((_ proto: UInt16, _ data: [UInt8]) -> Bool)?

    /// Configure the interface for demand dialing.
    ///
    /// Sets up the demand dialer for operation, clearing all state
    /// and preparing the frame buffer.
    public func configure() {
        frame.removeAll(keepingCapacity: true)
        pendingQueue.removeAll()
        escapeFlag = false
        flushFlag = false
        fcs = 0xFFFF
        isDialing = false
        isDemandMode = true
        lastActiveTime = currentTime()
    }

    /// Block all network protocols (queue packets instead of passing them).
    /// Called when demand mode is active and the link is down.
    public func block() {
        for key in ncpModes.keys {
            ncpModes[key] = .queue
        }
    }

    /// Unblock all network protocols (pass packets normally).
    /// Called when the link comes up and queued packets should flow.
    public func unblock() {
        for key in ncpModes.keys {
            ncpModes[key] = .pass
        }
    }

    /// Discard all queued packets and set NCPs to error mode.
    public func discard() {
        pendingQueue.removeAll()
        frame.removeAll(keepingCapacity: true)
        flushFlag = false
        escapeFlag = false
        fcs = 0xFFFF
        for key in ncpModes.keys {
            ncpModes[key] = .error
        }
    }

    /// Get the current NCP mode for a given protocol.
    ///
    /// - Parameter proto: The PPP protocol number (e.g., PPPProtocol.ip).
    /// - Returns: The current mode for the protocol.
    public func ncpMode(for proto: UInt16) -> NPMode {
        return ncpModes[proto] ?? .pass
    }

    /// Set the NCP mode for a given protocol.
    ///
    /// - Parameters:
    ///   - mode: The new mode.
    ///   - proto: The PPP protocol number.
    public func setNCPMode(_ mode: NPMode, for proto: UInt16) {
        ncpModes[proto] = mode
    }

    /// Handle a packet in demand mode. Returns the action to take.
    ///
    /// - Parameter data: The PPP frame data (with header).
    /// - Returns: The mode indicating how the packet should be handled.
    public func demandInput(_ data: [UInt8]) -> NPMode {
        guard data.count >= 4 else { return .drop }

        let proto = (UInt16(data[2]) << 8) | UInt16(data[3])
        let mode = ncpMode(for: proto)

        switch mode {
        case .queue:
            enqueue(data)
            // Trigger dial if this is interesting traffic
            if isActivePacket(data) && !isDialing {
                isDialing = true
                dialCallback?()
            }
            return .queue
        case .error:
            return .error
        case .drop:
            return .drop
        case .pass:
            return .pass
        }
    }

    /// Queue a packet for later transmission.
    ///
    /// - Parameter data: The packet data (including PPP header).
    public func enqueue(_ data: [UInt8]) {
        if pendingQueue.count >= maxQueueSize {
            // Drop oldest packet to make room
            pendingQueue.removeFirst()
        }
        pendingQueue.append(QueuedPacket(data: data))
    }

    /// Retransmit all queued packets now that the link is up.
    ///
    /// - Parameter output: Callback to send each packet.
    public func retransmit(output: ([UInt8]) -> Void) {
        let packets = pendingQueue
        pendingQueue.removeAll()
        isDialing = false
        for pkt in packets {
            output(pkt.data)
        }
    }

    /// Check whether a packet is "interesting" enough to bring up the link.
    /// Control protocols (LCP, authentication, NCP negotiation) are not interesting.
    /// Only data protocols (IP, IPv6, etc.) trigger demand dialing.
    ///
    /// - Parameter data: The PPP frame data.
    /// - Returns: `true` if the link should be brought up.
    public func isActivePacket(_ data: [UInt8]) -> Bool {
        guard data.count >= 4 else { return false }
        // Extract PPP protocol from header
        let proto = (UInt16(data[2]) << 8) | UInt16(data[3])
        // Control protocols (>= 0x8000) and LCP-range (>= 0xC000) don't trigger dial
        if (proto & 0x8000) != 0 { return false }
        // VJ compressed packets are interesting
        if proto == PPPProtocol.vj || proto == PPPProtocol.vjUncomp { return true }
        // IP and IPv6 data is interesting
        if proto == PPPProtocol.ip || proto == PPPProtocol.ipv6 { return true }
        return false
    }

    /// Called when a PPP phase transition occurs.
    ///
    /// Integrates demand dialing with PPP phase transitions:
    /// - When entering NETWORK phase: unblock NCPs and retransmit queued packets
    /// - When entering DEAD/DISCONNECT: block NCPs and prepare for demand mode
    /// - When entering HOLDOFF: discard queued packets
    ///
    /// - Parameters:
    ///   - newPhase: The new PPP phase.
    ///   - output: Callback to send queued packets when unblocking.
    public func handlePhaseTransition(newPhase: PPPPhase, output: (([UInt8]) -> Void)? = nil) {
        switch newPhase {
        case .running:
            // Link is up -- unblock and retransmit
            unblock()
            if let output = output {
                retransmit(output: output)
            }
            isDialing = false
            lastActiveTime = currentTime()

        case .dead, .disconnect:
            if isDemandMode {
                // Link went down in demand mode -- queue packets
                block()
            } else {
                discard()
            }

        case .holdoff:
            // Holdoff period -- discard old packets
            discard()

        case .dormant:
            // Ready for demand dialing
            block()

        default:
            break
        }
    }

    /// Check if the link has been idle and should be disconnected.
    ///
    /// - Returns: `true` if idle timeout has been reached.
    public func checkIdle() -> Bool {
        guard idleTimeout > 0 else { return false }
        let elapsed = currentTime() - lastActiveTime
        return elapsed >= UInt64(idleTimeout) * 1_000_000_000
    }

    /// Mark the link as active (reset idle timer).
    public func markActive() {
        lastActiveTime = currentTime()
    }

    /// Get the current time in nanoseconds.
    private func currentTime() -> UInt64 {
        return DispatchTime.now().uptimeNanoseconds
    }

    /// Check whether a packet passes the active filter.
    ///
    /// If no active filter is set, uses the default isActivePacket() check.
    ///
    /// - Parameter data: The PPP frame data.
    /// - Returns: `true` if the packet is interesting for demand dialing.
    public func passesActiveFilter(_ data: [UInt8]) -> Bool {
        guard data.count >= 4 else { return false }
        let proto = (UInt16(data[2]) << 8) | UInt16(data[3])
        if let filter = activeFilter {
            return filter(proto, data)
        }
        return isActivePacket(data)
    }

    /// Detect whether a frame is a loopback (echoed PPP control traffic).
    /// During demand mode, our own LCP/NCP packets may be looped back by the
    /// loopback interface. These should be filtered out rather than treated
    /// as incoming traffic from a peer.
    ///
    /// - Parameters:
    ///   - data: The received PPP frame data.
    ///   - ourMagic: Our LCP magic number (0 if not negotiated).
    /// - Returns: `true` if this appears to be a loopback frame.
    public func isLoopbackFrame(_ data: [UInt8], ourMagic: UInt32) -> Bool {
        guard data.count >= 4 else { return false }
        let proto = (UInt16(data[2]) << 8) | UInt16(data[3])

        // Only LCP frames can be reliably detected as loopback
        guard proto == PPPProtocol.lcp else { return false }

        // Need at least PPP header (4) + LCP code(1) + id(1) + len(2) + magic(4)
        guard data.count >= 12 && ourMagic != 0 else { return false }

        // Check if magic number in the frame matches ours (bytes 8..11 in the frame)
        let frameMagic = (UInt32(data[8]) << 24) | (UInt32(data[9]) << 16)
                       | (UInt32(data[10]) << 8) | UInt32(data[11])
        return frameMagic == ourMagic
    }

    /// Process a byte received on the loopback channel during demand mode.
    /// Assembles async HDLC frames for loopback detection.
    ///
    /// - Parameter byte: The received byte.
    /// - Returns: A complete frame if one has been assembled, or nil.
    public func loopbackInput(byte: UInt8) -> [UInt8]? {
        // HDLC flag (0x7E) marks frame boundaries
        if byte == 0x7E {
            if !frame.isEmpty && !flushFlag {
                // Check FCS
                if fcs == DemandDialer.goodFCS && frame.count >= 2 {
                    // Remove FCS bytes and return the frame
                    let result = Array(frame[0..<(frame.count - 2)])
                    frame.removeAll(keepingCapacity: true)
                    fcs = 0xFFFF
                    return result
                }
            }
            frame.removeAll(keepingCapacity: true)
            fcs = 0xFFFF
            flushFlag = false
            escapeFlag = false
            return nil
        }

        if flushFlag { return nil }

        // HDLC escape (0x7D)
        if byte == 0x7D {
            escapeFlag = true
            return nil
        }

        var inputByte = byte
        if escapeFlag {
            inputByte ^= 0x20
            escapeFlag = false
        }

        // Check for frame overflow
        guard frame.count < frameMax else {
            flushFlag = true
            return nil
        }

        frame.append(inputByte)
        fcs = DemandDialer.fcsTable[Int((fcs ^ UInt16(inputByte)) & 0xFF)] ^ (fcs >> 8)
        return nil
    }
}

// MARK: - Multilink PPP

/// Endpoint discriminator classes for multilink PPP.
public enum EndpointDiscClass: UInt8, Sendable {
    /// Null class (no discriminator).
    case null     = 0
    /// Local string.
    case local    = 1
    /// IP address.
    case ip       = 2
    /// MAC address.
    case mac      = 3
    /// Magic number block.
    case magic    = 4
    /// Phone number.
    case phone    = 5
}

/// Endpoint discriminator for multilink PPP.
public struct EndpointDiscriminator {
    /// Maximum endpoint discriminator value length.
    public static let maxLength: Int = 20

    /// Discriminator class.
    public var discClass: EndpointDiscClass = .null
    /// Discriminator value.
    public var value = [UInt8](repeating: 0, count: EndpointDiscriminator.maxLength)
    /// Actual length of the value.
    public var length: Int = 0

    public init() {}

    /// Format the endpoint discriminator as a human-readable string.
    public func toString() -> String {
        let classNames = ["null", "local", "IP", "MAC", "magic", "phone"]
        let className: String
        if discClass.rawValue <= 5 {
            className = classNames[Int(discClass.rawValue)]
        } else {
            className = "\(discClass.rawValue)"
        }

        if discClass == .null && length == 0 {
            return "null"
        }

        if discClass == .ip && length == 4 {
            let addr = "\(value[0]).\(value[1]).\(value[2]).\(value[3])"
            return "IP:\(addr)"
        }

        var result = "\(className):"
        for i in 0..<min(length, EndpointDiscriminator.maxLength) {
            result += String(format: "%02x", value[i])
        }
        return result
    }
}

/// Multilink PPP fragment header flags.
public struct MultilinkFlags {
    /// Beginning fragment of a packet.
    public static let beginBit: UInt8 = 0x80
    /// Ending fragment of a packet.
    public static let endBit: UInt8   = 0x40
}

/// A single multilink PPP fragment awaiting reassembly.
public struct MultilinkFragment {
    /// Fragment sequence number.
    public var sequenceNumber: UInt32
    /// Whether this is the beginning fragment.
    public var isBegin: Bool
    /// Whether this is the ending fragment.
    public var isEnd: Bool
    /// Fragment payload data.
    public var data: [UInt8]

    public init(sequenceNumber: UInt32, isBegin: Bool, isEnd: Bool, data: [UInt8]) {
        self.sequenceNumber = sequenceNumber
        self.isBegin = isBegin
        self.isEnd = isEnd
        self.data = data
    }
}

/// Represents an active multilink bundle, tracking member links and
/// fragment reassembly state.
public final class MultilinkBundle {
    /// Bundle identifier (derived from endpoint discriminator + peer name).
    public var bundleID: String
    /// Peer endpoint discriminator.
    public var peerEndpoint = EndpointDiscriminator()
    /// Peer authentication name.
    public var peerAuthName: String = ""
    /// Number of active links in this bundle.
    public var linkCount: Int = 0
    /// Whether short (12-bit) sequence numbers are in use.
    public var shortSequence: Bool = false
    /// Next expected sequence number for reassembly.
    public var nextSequence: UInt32 = 0
    /// Sequence number mask (0xFFF for short, 0xFFFFFF for long).
    public var sequenceMask: UInt32 = 0x00FFFFFF
    /// MRRU (Maximum Receive Reconstructed Unit) for the bundle.
    public var mrru: UInt16 = 1500
    /// Pending fragments awaiting reassembly, keyed by first sequence number.
    public var pendingFragments: [MultilinkFragment] = []

    public init(bundleID: String) {
        self.bundleID = bundleID
    }
}

/// Multilink PPP support (RFC 1990).
///
/// Provides multilink PPP bundle management with fragment reassembly.
/// Manages bundles in-memory (no TDB dependency), suitable for
/// embedded environments.
public final class MultilinkPPP {

    /// Whether multilink is being used.
    public var doingMultilink: Bool = false
    /// Whether we are the bundle master.
    public var multilinkMaster: Bool = false
    /// Our endpoint discriminator.
    public var endpoint = EndpointDiscriminator()
    /// Bundle identifier string.
    public var bundleID: String?
    /// Whether short (12-bit) sequence numbers are in use.
    public var shortSequence: Bool = false
    /// Our MRRU (Maximum Receive Reconstructed Unit).
    public var ourMRRU: UInt16 = 1500
    /// Peer's MRRU.
    public var peerMRRU: UInt16 = 1500

    /// Known bundles, keyed by bundle ID.
    private var bundles: [String: MultilinkBundle] = [:]

    /// The bundle we are currently part of (if any).
    public var currentBundle: MultilinkBundle?

    /// Whether to require endpoint discriminator for bundle identification.
    public var requireEndpointDisc: Bool = true

    /// Number of fragments to allow in reassembly before discarding stale.
    public var maxPendingFragments: Int = 64

    /// Transmit sequence number for outgoing fragments.
    private var txSequence: UInt32 = 0

    public init() {}

    /// Check multilink options and adjust LCP negotiation parameters.
    ///
    /// If multilink is requested, MRRU must be negotiated.
    /// Returns whether multilink should be attempted.
    ///
    /// - Parameters:
    ///   - mru: The negotiated MRU (used as fallback if no MRRU).
    ///   - mrru: The MRRU value from LCP negotiation, or nil if not negotiated.
    /// - Returns: `true` if multilink should be attempted.
    public func checkOptions(mru: UInt16, mrru: UInt16?) -> Bool {
        guard let mrru = mrru else {
            // No MRRU means no multilink
            return false
        }
        // MRRU must be at least 128 (RFC 1990 minimum)
        guard mrru >= 128 else { return false }
        ourMRRU = mrru
        return true
    }

    /// Encode multilink LCP options for inclusion in Configure-Request.
    ///
    /// Adds MRRU option (type 17) and endpoint discriminator (type 19)
    /// to the LCP option buffer.
    ///
    /// - Parameter buffer: The buffer to append options to.
    /// - Returns: Number of bytes written.
    public func addLCPOptions(buffer: inout [UInt8]) -> Int {
        var written = 0

        // MRRU option (type 17, length 4)
        buffer.append(17)  // CI_MRRU
        buffer.append(4)
        buffer.append(UInt8(ourMRRU >> 8))
        buffer.append(UInt8(ourMRRU & 0xFF))
        written += 4

        // Short Sequence Number Header Format option (type 18, length 2)
        if shortSequence {
            buffer.append(18)  // CI_SSNHF
            buffer.append(2)
            written += 2
        }

        // Endpoint Discriminator option (type 19, length = 3 + value)
        if endpoint.discClass != .null || endpoint.length > 0 {
            let epLen = 3 + endpoint.length  // type(1) + len(1) + class(1) + value
            buffer.append(19)  // CI_EPDISC
            buffer.append(UInt8(epLen))
            buffer.append(endpoint.discClass.rawValue)
            for i in 0..<endpoint.length {
                buffer.append(endpoint.value[i])
            }
            written += epLen
        }

        return written
    }

    /// Parse multilink LCP options from a peer's Configure-Request.
    ///
    /// - Parameter data: The option data from the peer.
    /// - Returns: Parsed MRRU and endpoint discriminator, or nil if invalid.
    public func parseLCPOptions(_ data: [UInt8]) -> (mrru: UInt16, epDisc: EndpointDiscriminator, shortSeq: Bool)? {
        var mrru: UInt16 = 0
        var epDisc = EndpointDiscriminator()
        var shortSeq = false
        var offset = 0

        while offset + 2 <= data.count {
            let optType = data[offset]
            let optLen = Int(data[offset + 1])
            guard optLen >= 2 && offset + optLen <= data.count else { break }

            switch optType {
            case 17:  // CI_MRRU
                guard optLen == 4 else { break }
                mrru = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])

            case 18:  // CI_SSNHF (Short Sequence Number Header Format)
                guard optLen == 2 else { break }
                shortSeq = true

            case 19:  // CI_EPDISC (Endpoint Discriminator)
                guard optLen >= 3 else { break }
                epDisc.discClass = EndpointDiscClass(rawValue: data[offset + 2]) ?? .null
                let valueLen = min(optLen - 3, EndpointDiscriminator.maxLength)
                epDisc.length = valueLen
                for i in 0..<valueLen {
                    epDisc.value[i] = data[offset + 3 + i]
                }

            default:
                break
            }

            offset += optLen
        }

        guard mrru >= 128 else { return nil }
        return (mrru, epDisc, shortSeq)
    }

    /// Reset the transmit sequence number (e.g., when a new bundle is created).
    public func resetTxSequence() {
        txSequence = 0
    }

    /// Compute a bundle identifier from the endpoint discriminator and peer name.
    ///
    /// - Parameters:
    ///   - peerEndpoint: The peer's endpoint discriminator.
    ///   - peerName: The peer's authenticated name.
    /// - Returns: A string that uniquely identifies the bundle.
    private func computeBundleID(peerEndpoint: EndpointDiscriminator, peerName: String) -> String {
        return "\(peerName)@\(peerEndpoint.toString())"
    }

    /// Create or join a multilink bundle.
    ///
    /// - Parameters:
    ///   - peerEndpoint: The peer's endpoint discriminator.
    ///   - peerName: The peer's authenticated name.
    ///   - mrru: The negotiated MRRU for the bundle.
    ///   - shortSeq: Whether short sequence numbers were negotiated.
    /// - Returns: `true` if we joined an existing bundle, `false` if new.
    public func joinBundle(
        peerEndpoint: EndpointDiscriminator = EndpointDiscriminator(),
        peerName: String = "",
        mrru: UInt16 = 1500,
        shortSeq: Bool = false
    ) -> Bool {
        doingMultilink = true
        peerMRRU = mrru
        shortSequence = shortSeq

        let id = computeBundleID(peerEndpoint: peerEndpoint, peerName: peerName)
        bundleID = id

        // Check for an existing bundle to join
        if let existing = bundles[id] {
            existing.linkCount += 1
            currentBundle = existing
            multilinkMaster = false
            return true
        }

        // Create a new bundle
        let bundle = MultilinkBundle(bundleID: id)
        bundle.peerEndpoint = peerEndpoint
        bundle.peerAuthName = peerName
        bundle.linkCount = 1
        bundle.shortSequence = shortSeq
        bundle.sequenceMask = shortSeq ? 0x0FFF : 0x00FFFFFF
        bundle.mrru = mrru

        bundles[id] = bundle
        currentBundle = bundle
        multilinkMaster = true
        return false
    }

    /// Leave the current bundle.
    public func exitBundle() {
        if let bundle = currentBundle {
            bundle.linkCount -= 1
            if bundle.linkCount <= 0 {
                bundles.removeValue(forKey: bundle.bundleID)
            }
        }
        doingMultilink = false
        multilinkMaster = false
        currentBundle = nil
        bundleID = nil
    }

    /// Handle bundle termination.
    public func bundleTerminated() {
        if let bundle = currentBundle {
            bundles.removeValue(forKey: bundle.bundleID)
        }
        doingMultilink = false
        multilinkMaster = false
        currentBundle = nil
    }

    // MARK: - Fragment Header Parsing

    /// Parse a multilink fragment header from received data.
    ///
    /// Short sequence number format (4 bytes):
    ///   [B|E|0|0| seq(12 bits) ] [seq low 8 bits] [payload...]
    ///
    /// Long sequence number format (6 bytes):
    ///   [B|E|0|0|0|0|0|0] [seq high 16 bits] [seq low 8 bits] [payload...]
    ///
    /// - Parameter data: The multilink PPP payload (after PPP header).
    /// - Returns: A parsed fragment and the offset to the payload data, or nil on error.
    public func parseFragmentHeader(_ data: [UInt8]) -> (MultilinkFragment, Int)? {
        let useShort = currentBundle?.shortSequence ?? shortSequence

        if useShort {
            // Short sequence number format: 4 bytes header
            guard data.count >= 4 else { return nil }
            let flags = data[0]
            let isBegin = (flags & MultilinkFlags.beginBit) != 0
            let isEnd = (flags & MultilinkFlags.endBit) != 0
            let seq = (UInt32(data[0] & 0x0F) << 8) | UInt32(data[1])
            // Bytes 2..3 are PID (protocol ID) in the first fragment
            let fragment = MultilinkFragment(
                sequenceNumber: seq,
                isBegin: isBegin,
                isEnd: isEnd,
                data: Array(data[2...])
            )
            return (fragment, 2)
        } else {
            // Long sequence number format: 6 bytes header (flags + 3 byte seq)
            guard data.count >= 4 else { return nil }
            let flags = data[0]
            let isBegin = (flags & MultilinkFlags.beginBit) != 0
            let isEnd = (flags & MultilinkFlags.endBit) != 0
            let seq = (UInt32(data[1]) << 16) | (UInt32(data[2]) << 8) | UInt32(data[3])
            let fragment = MultilinkFragment(
                sequenceNumber: seq,
                isBegin: isBegin,
                isEnd: isEnd,
                data: Array(data[4...])
            )
            return (fragment, 4)
        }
    }

    // MARK: - Fragment Reassembly

    /// Process a received multilink fragment and attempt reassembly.
    ///
    /// - Parameter data: The multilink PPP payload (after PPP header).
    /// - Returns: The reassembled packet if complete, or nil if still waiting for fragments.
    public func receiveFragment(_ data: [UInt8]) -> [UInt8]? {
        guard let bundle = currentBundle else { return nil }
        guard let (fragment, _) = parseFragmentHeader(data) else { return nil }

        // If Begin and End are both set, this is a complete (unfragmented) packet
        if fragment.isBegin && fragment.isEnd {
            bundle.nextSequence = (fragment.sequenceNumber &+ 1) & bundle.sequenceMask
            return fragment.data
        }

        // Add fragment to pending list
        bundle.pendingFragments.append(fragment)

        // Attempt reassembly: look for a contiguous run from Begin to End
        return attemptReassembly(bundle: bundle)
    }

    /// Attempt to reassemble a complete packet from pending fragments.
    ///
    /// - Parameter bundle: The bundle to check for complete packets.
    /// - Returns: The reassembled packet, or nil if not yet complete.
    private func attemptReassembly(bundle: MultilinkBundle) -> [UInt8]? {
        // Sort fragments by sequence number
        bundle.pendingFragments.sort { $0.sequenceNumber < $1.sequenceNumber }

        // Find a Begin fragment
        guard let beginIdx = bundle.pendingFragments.firstIndex(where: { $0.isBegin }) else {
            return nil
        }

        let beginSeq = bundle.pendingFragments[beginIdx].sequenceNumber

        // Walk forward from the Begin fragment looking for contiguous sequence
        // numbers ending with an End fragment
        var currentSeq = beginSeq
        var endIdx: Int?

        for i in beginIdx..<bundle.pendingFragments.count {
            let frag = bundle.pendingFragments[i]
            let expectedSeq = (beginSeq &+ UInt32(i - beginIdx)) & bundle.sequenceMask
            guard frag.sequenceNumber == expectedSeq else {
                break // Gap in sequence -- can't reassemble yet
            }
            currentSeq = frag.sequenceNumber
            if frag.isEnd {
                endIdx = i
                break
            }
        }

        guard let endIndex = endIdx else {
            // Discard stale fragments that are before the begin sequence
            bundle.pendingFragments.removeAll { frag in
                let diff = (beginSeq &- frag.sequenceNumber) & bundle.sequenceMask
                return diff > 0 && diff < bundle.sequenceMask / 2 && !frag.isBegin
            }
            return nil
        }

        // Reassemble the packet from beginIdx to endIndex
        var reassembled = [UInt8]()
        let mrruLimit = Int(bundle.mrru)
        for i in beginIdx...endIndex {
            reassembled.append(contentsOf: bundle.pendingFragments[i].data)
            if reassembled.count > mrruLimit {
                // Exceeds MRRU -- discard
                bundle.pendingFragments.removeSubrange(beginIdx...endIndex)
                return nil
            }
        }

        // Remove the reassembled fragments
        bundle.pendingFragments.removeSubrange(beginIdx...endIndex)

        // Update expected sequence
        bundle.nextSequence = (currentSeq &+ 1) & bundle.sequenceMask

        return reassembled
    }

    /// Create multilink fragment headers for a packet that needs to be fragmented.
    ///
    /// - Parameters:
    ///   - data: The packet data to fragment.
    ///   - fragmentSize: The maximum payload size per fragment.
    /// - Returns: An array of fragments ready to send, each with the multilink header prepended.
    public func fragmentPacket(_ data: [UInt8], fragmentSize: Int) -> [[UInt8]] {
        guard let bundle = currentBundle, fragmentSize > 0, !data.isEmpty else {
            return [data]
        }

        let useShort = bundle.shortSequence

        var fragments = [[UInt8]]()
        var offset = 0

        while offset < data.count {
            let remaining = data.count - offset
            let chunkSize = min(remaining, fragmentSize)
            let isBegin = (offset == 0)
            let isEnd = (offset + chunkSize >= data.count)

            var header = [UInt8]()
            var flags: UInt8 = 0
            if isBegin { flags |= MultilinkFlags.beginBit }
            if isEnd { flags |= MultilinkFlags.endBit }

            let seq = bundle.nextSequence
            bundle.nextSequence = (seq &+ 1) & bundle.sequenceMask

            if useShort {
                // Short format: 2 bytes (flags + 12-bit seq)
                header.append(flags | UInt8((seq >> 8) & 0x0F))
                header.append(UInt8(seq & 0xFF))
            } else {
                // Long format: 4 bytes (flags + 24-bit seq)
                header.append(flags)
                header.append(UInt8((seq >> 16) & 0xFF))
                header.append(UInt8((seq >> 8) & 0xFF))
                header.append(UInt8(seq & 0xFF))
            }

            header.append(contentsOf: data[offset..<(offset + chunkSize)])
            fragments.append(header)
            offset += chunkSize
        }

        return fragments
    }
}

// MARK: - IPv6CP (IPv6 Control Protocol)

/// IPv6CP configuration option types.
public enum IPv6CPOptionType: UInt8, Sendable {
    /// Interface identifier (EUI-64).
    case interfaceID = 1
    /// IPv6 compression protocol.
    case compressProtocol = 2
}

/// IPv6CP compression protocol types.
public enum IPv6CPCompressType: UInt16, Sendable {
    /// No compression.
    case none = 0
    /// Header compression (RFC 2507).
    case headerCompression = 0x0061
}

/// IPv6CP negotiation options.
public struct IPv6CPOptions {
    /// Whether to negotiate an interface identifier.
    public var negotiateInterfaceID: Bool = true
    /// Our interface identifier (EUI-64).
    public var ourInterfaceID = EUI64()
    /// Peer's interface identifier.
    public var hisInterfaceID = EUI64()
    /// Whether to negotiate compression.
    public var negotiateCompression: Bool = false
    /// Compression protocol type.
    public var compressType: IPv6CPCompressType = .none

    public init() {}
}

/// IPv6 Control Protocol (IPv6CP).
///
/// Negotiates IPv6 interface identifiers between PPP peers.
/// Each side provides an EUI-64 identifier that forms the lower 64 bits
/// of the link-local IPv6 address (fe80::xxxx:xxxx:xxxx:xxxx).
public final class IPv6CP: FSMCallbacks, @unchecked Sendable {

    /// The IPv6CP FSM instance.
    public var fsm: FSM

    /// Our desired options.
    public var wantOptions = IPv6CPOptions()
    /// Options we agreed to use (our side).
    public var goOptions = IPv6CPOptions()
    /// Options we allow the peer to request.
    public var allowOptions = IPv6CPOptions()
    /// Options the peer agreed to use.
    public var hisOptions = IPv6CPOptions()

    /// Parent PPP connection.
    public weak var pcb: PPPControlBlock?

    /// Number of times we've regenerated our interface ID due to collisions.
    private var collisionCount: Int = 0

    /// Maximum number of collision resolution attempts before giving up.
    public static let maxCollisions: Int = 10

    public var protocolName: String { "IPV6CP" }

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
        self.fsm = FSM(pcb: pcb)
        self.fsm.protocolNumber = PPPProtocol.ipv6cp
        self.fsm.callbacks = self
    }

    /// Initialize IPv6CP with default options.
    public func initialize() {
        fsm.initialize()
        wantOptions = IPv6CPOptions()
        goOptions = IPv6CPOptions()
        allowOptions = IPv6CPOptions()
        hisOptions = IPv6CPOptions()
        collisionCount = 0
    }

    /// Generate a random interface identifier for negotiation.
    public func generateInterfaceID() -> EUI64 {
        let m = PPPMagic.shared
        let r1 = m.magic()
        let r2 = m.magic()
        return EUI64(
            UInt8(truncatingIfNeeded: r1),
            UInt8(truncatingIfNeeded: r1 >> 8),
            UInt8(truncatingIfNeeded: r1 >> 16),
            UInt8(truncatingIfNeeded: r1 >> 24),
            UInt8(truncatingIfNeeded: r2),
            UInt8(truncatingIfNeeded: r2 >> 8),
            UInt8(truncatingIfNeeded: r2 >> 16),
            UInt8(truncatingIfNeeded: r2 >> 24)
        )
    }

    /// Reset configuration information (FSM callback).
    public func resetCI() {
        goOptions = wantOptions
        if goOptions.ourInterfaceID.isZero {
            goOptions.ourInterfaceID = generateInterfaceID()
        }
    }

    /// Return the length of our configuration information.
    public func ciLength() -> Int {
        if goOptions.negotiateInterfaceID {
            return 2 + 8  // type(1) + length(1) + EUI-64(8)
        }
        return 0
    }

    /// Add our configuration information to the buffer.
    public func addCI(buffer: inout [UInt8]) -> Int {
        var written = 0
        if goOptions.negotiateInterfaceID {
            buffer.append(IPv6CPOptionType.interfaceID.rawValue)
            buffer.append(10)  // Length: type(1) + len(1) + value(8)
            buffer.append(contentsOf: goOptions.ourInterfaceID.toArray())
            written = 10
        }
        if goOptions.negotiateCompression && goOptions.compressType != .none {
            buffer.append(IPv6CPOptionType.compressProtocol.rawValue)
            buffer.append(4)  // Length: type(1) + len(1) + compressType(2)
            buffer.append(UInt8(goOptions.compressType.rawValue >> 8))
            buffer.append(UInt8(goOptions.compressType.rawValue & 0xFF))
            written += 4
        }
        return written
    }

    /// Process an ACK of our configuration information.
    public func ackCI(data: [UInt8]) -> Bool {
        var offset = 0
        if goOptions.negotiateInterfaceID {
            guard data.count >= offset + 10 else { return false }
            guard data[offset] == IPv6CPOptionType.interfaceID.rawValue else { return false }
            guard data[offset + 1] == 10 else { return false }
            let ackedID = EUI64(
                data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5],
                data[offset + 6], data[offset + 7],
                data[offset + 8], data[offset + 9]
            )
            guard ackedID == goOptions.ourInterfaceID else { return false }
            offset += 10
        }
        if goOptions.negotiateCompression && goOptions.compressType != .none {
            guard data.count >= offset + 4 else { return false }
            guard data[offset] == IPv6CPOptionType.compressProtocol.rawValue else { return false }
            guard data[offset + 1] == 4 else { return false }
            let ackedType = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])
            guard ackedType == goOptions.compressType.rawValue else { return false }
            offset += 4
        }
        return offset == data.count
    }

    /// Process a request for our peer's configuration.
    public func requestCI(data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        var offset = 0
        var code: FSMCode = .configureAcknowledgment
        var nakBuffer = [UInt8]()

        while offset + 2 <= data.count {
            let optType = data[offset]
            let optLen = Int(data[offset + 1])
            guard optLen >= 2 && offset + optLen <= data.count else { break }

            if optType == IPv6CPOptionType.interfaceID.rawValue {
                guard optLen == 10 else {
                    reject.append(contentsOf: data[offset..<offset + optLen])
                    code = .configureReject
                    offset += optLen
                    continue
                }
                let peerID = EUI64(
                    data[offset + 2], data[offset + 3],
                    data[offset + 4], data[offset + 5],
                    data[offset + 6], data[offset + 7],
                    data[offset + 8], data[offset + 9]
                )
                if peerID.isZero {
                    // Peer sent zero ID -- NAK with a suggested ID
                    if code != .configureReject {
                        code = .configureNegativeAcknowledgment
                    }
                    let suggestedID = generateInterfaceID()
                    nakBuffer.append(IPv6CPOptionType.interfaceID.rawValue)
                    nakBuffer.append(10)
                    nakBuffer.append(contentsOf: suggestedID.toArray())
                } else if peerID == goOptions.ourInterfaceID {
                    // Collision: peer chose the same ID as us
                    collisionCount += 1
                    if collisionCount > IPv6CP.maxCollisions {
                        // Too many collisions -- reject
                        reject.append(contentsOf: data[offset..<offset + optLen])
                        code = .configureReject
                    } else {
                        // NAK with a different suggested ID and regenerate our own
                        if code != .configureReject {
                            code = .configureNegativeAcknowledgment
                        }
                        let suggestedID = generateInterfaceID()
                        nakBuffer.append(IPv6CPOptionType.interfaceID.rawValue)
                        nakBuffer.append(10)
                        nakBuffer.append(contentsOf: suggestedID.toArray())
                        // Also regenerate our own to avoid future collisions
                        goOptions.ourInterfaceID = generateInterfaceID()
                    }
                } else {
                    hisOptions.hisInterfaceID = peerID
                    collisionCount = 0
                }

            } else if optType == IPv6CPOptionType.compressProtocol.rawValue {
                guard allowOptions.negotiateCompression && optLen == 4 else {
                    reject.append(contentsOf: data[offset..<offset + optLen])
                    if code == .configureAcknowledgment { code = .configureReject }
                    offset += optLen
                    continue
                }
                let peerCompressType = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])
                if let compType = IPv6CPCompressType(rawValue: peerCompressType) {
                    hisOptions.negotiateCompression = true
                    hisOptions.compressType = compType
                } else {
                    // Unknown compression type -- reject
                    reject.append(contentsOf: data[offset..<offset + optLen])
                    if code == .configureAcknowledgment { code = .configureReject }
                }

            } else {
                // Unknown option -- reject
                reject.append(contentsOf: data[offset..<offset + optLen])
                if code == .configureAcknowledgment {
                    code = .configureReject
                }
            }

            offset += optLen
        }

        // Build the output based on result
        switch code {
        case .configureAcknowledgment:
            reject = data
        case .configureNegativeAcknowledgment:
            reject = nakBuffer
        default:
            break
        }

        return code
    }

    // MARK: - FSMCallbacks Conformance

    public func resetCI(_ fsm: FSM) {
        resetCI()
    }

    public func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        return addCI(buffer: &buffer)
    }

    public func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        return ackCI(data: data)
    }

    public func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        // Process NAK: peer suggests different interface ID or compression.
        var offset = 0
        while offset + 2 <= data.count {
            let optType = data[offset]
            let optLen = Int(data[offset + 1])
            guard optLen >= 2 && offset + optLen <= data.count else { break }

            if optType == IPv6CPOptionType.interfaceID.rawValue && optLen == 10 {
                if treatAsReject {
                    goOptions.negotiateInterfaceID = false
                } else {
                    let suggestedID = EUI64(
                        data[offset + 2], data[offset + 3],
                        data[offset + 4], data[offset + 5],
                        data[offset + 6], data[offset + 7],
                        data[offset + 8], data[offset + 9]
                    )
                    if !suggestedID.isZero {
                        goOptions.ourInterfaceID = suggestedID
                    } else {
                        goOptions.ourInterfaceID = generateInterfaceID()
                    }
                }
            } else if optType == IPv6CPOptionType.compressProtocol.rawValue && optLen == 4 {
                if treatAsReject {
                    goOptions.negotiateCompression = false
                } else {
                    let suggestedType = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])
                    if let compType = IPv6CPCompressType(rawValue: suggestedType) {
                        goOptions.compressType = compType
                    } else {
                        goOptions.negotiateCompression = false
                    }
                }
            }
            offset += optLen
        }
        return true
    }

    public func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        // Process Reject: peer doesn't support our options.
        var offset = 0
        while offset + 2 <= data.count {
            let optType = data[offset]
            let optLen = Int(data[offset + 1])
            guard optLen >= 2 && offset + optLen <= data.count else { break }

            if optType == IPv6CPOptionType.interfaceID.rawValue {
                goOptions.negotiateInterfaceID = false
            } else if optType == IPv6CPOptionType.compressProtocol.rawValue {
                goOptions.negotiateCompression = false
            }
            offset += optLen
        }
        return true
    }

    public func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        return requestCI(data: data, reject: &reject)
    }

    public func up(_ fsm: FSM) {
        up()
    }

    public func down(_ fsm: FSM) {
        down()
    }

    public func starting(_ fsm: FSM) {
        // Signal lower layers to come up (e.g., start LCP if not already running).
        PPP.debugLog(.info, "IPv6CP starting")
    }

    public func finished(_ fsm: FSM) {
        // Signal that IPv6CP no longer needs the lower layer.
        PPP.debugLog(.info, "IPv6CP finished")
    }

    /// Open the IPv6CP negotiation.
    public func open() {
        fsm.open()
    }

    /// Close the IPv6CP negotiation.
    public func close(reason: String? = nil) {
        fsm.close(reason: reason)
    }

    /// Lower layer is up.
    public func lowerUp() {
        fsm.lowerUp()
    }

    /// Lower layer is down.
    public func lowerDown() {
        fsm.lowerDown()
    }

    /// Handle incoming IPv6CP packet.
    public func input(data: [UInt8]) {
        guard data.count >= 4 else { return }
        let code = data[0]
        let id = data[1]
        let payload = data.count > 4 ? Array(data[4...]) : []
        fsm.input(code: code, id: id, data: payload)
    }

    /// Called when IPv6CP reaches OPENED state.
    public func up() {
        // Configure the IPv6 interface with negotiated identifiers
        PPP.debugLog(.info, "IPv6CP up: our=\(goOptions.ourInterfaceID.toString()) "
                         + "his=\(hisOptions.hisInterfaceID.toString())")
    }

    /// Called when IPv6CP leaves OPENED state.
    public func down() {
        PPP.debugLog(.info, "IPv6CP down")
    }
}

// MARK: - PPP API (Thread-Safe Wrapper)

/// PPP API error type.
public typealias PPPAPIError = LWIPError

/// Thread-safe PPP API.
///
/// Provides a safe interface for PPP operations that can be called
/// from any thread. Operations are dispatched to the TCP/IP processing
/// queue to ensure thread safety.
public final class PPPAPI {

    /// The processing queue for thread-safe PPP operations.
    private let queue: DispatchQueue

    /// Initialize with a serial dispatch queue.
    public init(queue: DispatchQueue = DispatchQueue(label: "ppp.api", qos: .utility)) {
        self.queue = queue
    }

    private func configureNetif(_ netif: NetworkInterface, for pcb: PPPControlBlock) {
        if netif.name == (0, 0) {
            netif.name = (UInt8(ascii: "p"), UInt8(ascii: "p"))
        }
        if netif.mtu == 0 {
            netif.mtu = PPPControlBlock.defaultMTU
        }
        if netif.mtuIPv6 == 0 {
            netif.mtuIPv6 = netif.mtu
        }

        netif.output = { [weak pcb] _, pbuf, _ in
            pcb?.sendNetworkPacket(pbuf, protocol: PPPProtocol.ip) ?? .notConnected
        }
        netif.outputIP6 = { [weak pcb] _, pbuf, _ in
            pcb?.sendNetworkPacket(pbuf, protocol: PPPProtocol.ipv6) ?? .notConnected
        }
    }

    private func makePCB(
        netif: NetworkInterface,
        linkStatusCallback: ((_ pcb: PPPControlBlock, _ err: LWIPError) -> Void)?,
        phaseCallback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)?
    ) -> PPPControlBlock {
        let pcb = PPPControlBlock()
        pcb.netif = netif
        pcb.linkStatusCallback = linkStatusCallback
        pcb.notifyPhaseCallback = phaseCallback
        configureNetif(netif, for: pcb)
        return pcb
    }

    /// Set the default PPP connection (thread-safe).
    public func setDefault(_ pcb: PPPControlBlock, completion: ((LWIPError) -> Void)? = nil) {
        queue.async {
            guard let netif = pcb.netif else {
                completion?(.invalidValue)
                return
            }
            NetworkInterface.setDefault(netif)
            completion?(.ok)
        }
    }

    /// Connect the PPP link (thread-safe).
    ///
    /// - Parameters:
    ///   - pcb: The PPP connection.
    ///   - holdoff: Delay in seconds before connecting.
    ///   - completion: Completion handler with result.
    public func connect(_ pcb: PPPControlBlock, holdoff: UInt16 = 0, completion: ((LWIPError) -> Void)? = nil) {
        let work = {
            pcb.open()
            completion?(.ok)
        }
        if holdoff == 0 {
            queue.async(execute: work)
        } else {
            queue.asyncAfter(deadline: .now() + .seconds(Int(holdoff)), execute: work)
        }
    }

    /// Disconnect the PPP link (thread-safe).
    ///
    /// - Parameters:
    ///   - pcb: The PPP connection.
    ///   - noCarrier: If true, indicates carrier loss rather than user request.
    ///   - completion: Completion handler with result.
    public func close(_ pcb: PPPControlBlock, noCarrier: Bool = false, completion: ((LWIPError) -> Void)? = nil) {
        queue.async {
            pcb.close()
            completion?(.ok)
        }
    }

    /// Free the PPP connection (thread-safe).
    ///
    /// - Parameters:
    ///   - pcb: The PPP connection to free.
    ///   - completion: Completion handler with result.
    public func free(_ pcb: PPPControlBlock, completion: ((LWIPError) -> Void)? = nil) {
        queue.async {
            pcb.free()
            completion?(.ok)
        }
    }

    /// Register a notify-phase callback (thread-safe).
    public func setNotifyPhaseCallback(
        _ pcb: PPPControlBlock,
        callback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)?,
        completion: ((LWIPError) -> Void)? = nil
    ) {
        queue.async {
            pcb.notifyPhaseCallback = callback
            completion?(.ok)
        }
    }

    /// Create a PPPoS connection (thread-safe).
    public func createPPPoS(
        interface netif: NetworkInterface,
        serialIO: SerialIO,
        linkStatusCallback: ((_ pcb: PPPControlBlock, _ err: LWIPError) -> Void)? = nil,
        phaseCallback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)? = nil,
        completion: ((PPPControlBlock?) -> Void)? = nil
    ) {
        queue.async {
            let pcb = self.makePCB(
                netif: netif,
                linkStatusCallback: linkStatusCallback,
                phaseCallback: phaseCallback
            )
            let transport = PPPoS(pcb: pcb)
            transport.serialDevice = serialIO
            pcb.transport = transport
            completion?(pcb)
        }
    }

    /// Create a PPPoE connection (thread-safe).
    public func createPPPoE(
        interface netif: NetworkInterface,
        ethernetInterface: NetworkInterface,
        serviceName: String = "",
        concentratorName: String = "",
        linkStatusCallback: ((_ pcb: PPPControlBlock, _ err: LWIPError) -> Void)? = nil,
        phaseCallback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)? = nil,
        completion: ((PPPControlBlock?) -> Void)? = nil
    ) {
        queue.async {
            let pcb = self.makePCB(
                netif: netif,
                linkStatusCallback: linkStatusCallback,
                phaseCallback: phaseCallback
            )
            let transport = PPPoE(pcb: pcb)
            transport.ethNetif = ethernetInterface
            transport.serviceName = serviceName
            transport.concentratorName = concentratorName
            pcb.transport = transport
            completion?(pcb)
        }
    }

    /// Create a PPPoL2TP connection (thread-safe).
    public func createPPPoL2TP(
        interface netif: NetworkInterface,
        tunnelInterface: NetworkInterface? = nil,
        remoteAddress: IPAddress,
        port: UInt16 = 1701,
        secret: [UInt8] = [],
        linkStatusCallback: ((_ pcb: PPPControlBlock, _ err: LWIPError) -> Void)? = nil,
        phaseCallback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)? = nil,
        completion: ((PPPControlBlock?) -> Void)? = nil
    ) {
        queue.async {
            let pcb = self.makePCB(
                netif: netif,
                linkStatusCallback: linkStatusCallback,
                phaseCallback: phaseCallback
            )
            let transport = PPPoL2TP(pcb: pcb)
            let udpPCB = UDPGlobal.shared.new()

            if let tunnelInterface {
                UDPGlobal.shared.bindNetif(udpPCB, netif: tunnelInterface)
            }
            guard UDPGlobal.shared.bind(udpPCB, address: .any, port: 0) == .ok else {
                completion?(nil)
                return
            }
            UDPGlobal.shared.recv(udpPCB) { [weak transport] _, pbuf, _, _ in
                defer { _ = pbuf.free() }
                transport?.input(pbuf: pbuf)
            }

            transport.udpControlBlock = udpPCB
            transport.remoteAddr = remoteAddress
            transport.remotePort = port
            transport.tunnelSecret = secret
            pcb.transport = transport
            completion?(pcb)
        }
    }

    /// Perform a PPP ioctl operation (thread-safe).
    ///
    /// - Parameters:
    ///   - pcb: The PPP connection.
    ///   - command: The ioctl command.
    ///   - argument: The ioctl argument.
    ///   - completion: Completion handler with result.
    public func ioctl(_ pcb: PPPControlBlock, command: UInt8, argument: Any?, completion: ((LWIPError) -> Void)? = nil) {
        queue.async {
            let _ = pcb
            let _ = command
            let _ = argument
            completion?(.invalidArgument)
        }
    }
}
