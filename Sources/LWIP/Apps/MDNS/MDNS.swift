//
//  MDNS.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - mDNS Configuration

/// mDNS responder configuration.
public enum MDNSConfig {
    /// Maximum label length in a DNS name.
    public static let labelMaxLen = 63
    /// Maximum total domain name length.
    public static let domainMaxLen = 256
    /// Maximum number of services per interface.
    public static var maxServices: Int = 4
    /// TTL for host records (seconds).
    public static var hostTTL: UInt32 = 120
    /// TTL for service records (seconds).
    public static var serviceTTL: UInt32 = 4500
    /// Maximum number of active search requests.
    public static var maxSearchRequests: Int = 2
    /// mDNS port.
    public static let port: UInt16 = 5353
    /// IPv4 multicast address for mDNS (224.0.0.251).
    public static let ipv4MulticastAddr = IPAddress.v4(IPv4Address(224, 0, 0, 251))
    /// Probing conflict result.
    public static let probingConflict: UInt8 = 0
    /// Probing success result.
    public static let probingSuccessful: UInt8 = 1
    /// Enable mDNS search.
    public static var searchEnabled: Bool = false
    /// DNS header size (12 bytes).
    public static let dnsHeaderSize: Int = 12
    /// Maximum output packet size.
    public static let outputPacketSize: Int = 1460
    /// Number of domain offset slots for compression.
    public static let numDomainOffsets: Int = 10
    /// SRV record priority.
    public static let srvPriority: UInt16 = 0
    /// SRV record weight.
    public static let srvWeight: UInt16 = 0
    /// Probe count (RFC 6762 section 8.1).
    public static let probeCount: Int = 3
    /// Probe delay in milliseconds.
    public static let probeDelayMs: UInt32 = 250
    /// Announce count (RFC 6762 section 8.3).
    public static let announceCount: Int = 2
    /// Announce initial delay in milliseconds.
    public static let announceDelayMs: UInt32 = 1000
    /// DNS class IN.
    public static let dnsClassIN: UInt16 = 1
    /// DNS class ANY.
    public static let dnsClassANY: UInt16 = 255
    /// Response flag (QR bit).
    public static let flagResponse: UInt8 = 0x80
    /// Authoritative answer flag.
    public static let flagAuthoritative: UInt8 = 0x04
    /// Truncation flag.
    public static let flagTruncated: UInt8 = 0x02
    /// Domain name compression jump marker.
    public static let domainJump: UInt16 = 0xC000
    /// Domain name compression jump size in bytes.
    public static let domainJumpSize: Int = 2
    /// Read name error sentinel.
    public static let readNameError: UInt16 = 0xFFFF
    /// Response delay range (20-120ms).
    public static let responseDelayMin: UInt32 = 20
    public static let responseDelayMax: UInt32 = 120
    /// Truncated question response delay range (400-500ms, RFC 6762 section 7.2).
    public static let responseTCDelayMin: UInt32 = 400
    public static let responseTCDelayMax: UInt32 = 500
    /// Probe tiebreak conflict delay in milliseconds (RFC 6762 section 8.2).
    public static let probeTiebreakConflictDelayMs: UInt32 = 1000
    /// Maximum number of authoritative answers to collect for probe tiebreaking.
    public static let probeTiebreakMaxAnswers: Int = 5
    /// Goodbye TTL (RFC 6762 section 10.1).
    public static let goodbyeTTL: UInt32 = 0
    /// IP + UDP header overhead (IPv4: 20 + 8 = 28 bytes).
    public static let ipUdpHeaderSize: Int = 28
    /// Search result flags.
    public static let searchResultFirst: Int = 1
    public static let searchResultLast: Int = 2
    /// Maximum number of stored mDNS packets (for TC known-answer collection).
    public static var maxStoredPackets: Int = 4
}

// MARK: - Lexicographic Comparison Result

/// Result of lexicographic comparison for probe tiebreaking (RFC 6762 Section 8.2).
internal enum LexicographicalResult {
    case equal
    case earlier  // Our record is lexicographically earlier (we lose)
    case later    // Our record is lexicographically later (we win)
}

// MARK: - DNS-SD Protocol

/// DNS-SD transport protocol.
public enum MDNSProtocol: UInt8, Sendable {
    case udp = 0
    case tcp = 1

    /// Protocol string for DNS-SD ("_tcp" or "_udp").
    public var dnsString: String {
        switch self {
        case .udp: return "_udp"
        case .tcp: return "_tcp"
        }
    }
}

// MARK: - DNS Record Types

/// DNS record types used in mDNS.
public enum DNSRecordType: UInt16, Sendable {
    case a     = 1     // IPv4 address
    case ptr   = 12    // Pointer
    case txt   = 16    // Text
    case aaaa  = 28    // IPv6 address
    case srv   = 33    // Service
    case nsec  = 47    // NSEC (negative response / type bitmap)
    case any   = 255   // Any type (query only)
}

// MARK: - Reply Bitmask

/// Bitmask for which reply records to send.
internal struct ReplyFlags: OptionSet {
    let rawValue: UInt16
    init(rawValue: UInt16) { self.rawValue = rawValue }

    static let hostA            = ReplyFlags(rawValue: 0x0001)
    static let hostPtrV4        = ReplyFlags(rawValue: 0x0002)
    static let hostAAAA         = ReplyFlags(rawValue: 0x0004)
    static let hostPtrV6        = ReplyFlags(rawValue: 0x0008)
    static let serviceTypePTR   = ReplyFlags(rawValue: 0x0010)
    static let serviceNamePTR   = ReplyFlags(rawValue: 0x0020)
    static let serviceSRV       = ReplyFlags(rawValue: 0x0040)
    static let serviceTXT       = ReplyFlags(rawValue: 0x0080)
}

// MARK: - MDNSState

/// mDNS probing/announcing state machine.
internal enum MDNSState {
    case off
    case probeWait
    case probing
    case announceWait
    case announcing
    case complete
}

// MARK: - MDNSDomain

/// Encoded DNS domain name.
public struct MDNSDomain: Sendable {
    /// Encoded domain name bytes (label-length-prefixed format).
    public var name: [UInt8]
    /// Total length including terminal zero.
    public var length: UInt16
    /// Whether compression of this domain is disallowed.
    public var skipCompression: Bool

    public init() {
        name = [UInt8](repeating: 0, count: MDNSConfig.domainMaxLen)
        length = 1  // Just the terminal zero.
        skipCompression = false
    }

    /// Build a domain from label components.
    public init(labels: [String]) {
        name = [UInt8](repeating: 0, count: MDNSConfig.domainMaxLen)
        length = 0
        skipCompression = false

        var offset = 0
        for label in labels {
            let bytes = Array(label.utf8)
            guard bytes.count <= MDNSConfig.labelMaxLen else { continue }
            guard offset + 1 + bytes.count < MDNSConfig.domainMaxLen else { break }
            name[offset] = UInt8(bytes.count)
            offset += 1
            for b in bytes {
                name[offset] = b
                offset += 1
            }
        }
        name[offset] = 0  // Terminal zero.
        length = UInt16(offset + 1)
    }

    /// Add a label to this domain.
    @discardableResult
    public mutating func addLabel(_ label: String) -> LWIPError {
        let bytes = Array(label.utf8)
        return addLabel(bytes, count: UInt8(bytes.count))
    }

    /// Add a label from raw bytes to this domain.
    @discardableResult
    public mutating func addLabel(_ bytes: [UInt8], count: UInt8) -> LWIPError {
        if count > MDNSConfig.labelMaxLen { return .invalidValue }
        if count > 0 && (1 + Int(count) + Int(length) >= MDNSConfig.domainMaxLen) { return .invalidValue }
        if count == 0 && (1 + Int(length) > MDNSConfig.domainMaxLen) { return .invalidValue }

        name[Int(length)] = count
        length += 1
        if count > 0 {
            for i in 0..<Int(count) {
                name[Int(length) + i] = bytes[i]
            }
            length += UInt16(count)
        }
        return .ok
    }

    /// Add a zero-length terminal label.
    @discardableResult
    public mutating func addTerminator() -> LWIPError {
        return addLabel([], count: 0)
    }

    /// Add ".local" suffix (label "local" + terminator).
    @discardableResult
    public mutating func addDotLocal() -> LWIPError {
        var res = addLabel("local")
        if res != .ok { return res }
        res = addTerminator()
        return res
    }

    /// Add another domain's encoded bytes to this domain.
    @discardableResult
    public mutating func addDomain(_ source: MDNSDomain) -> LWIPError {
        let len = source.length
        if len > 0 && (1 + Int(len) + Int(length) >= MDNSConfig.domainMaxLen) { return .invalidValue }
        if len == 0 && (1 + Int(length) > MDNSConfig.domainMaxLen) { return .invalidValue }

        if len > 0 {
            for i in 0..<Int(len) {
                name[Int(length) + i] = source.name[i]
            }
            length += len
        } else {
            name[Int(length)] = 0
            length += 1
        }
        return .ok
    }

    /// Get the labels as an array of strings.
    public var labels: [String] {
        var result: [String] = []
        var offset = 0
        while offset < Int(length) {
            let labelLen = Int(name[offset])
            guard labelLen > 0 else { break }
            offset += 1
            let start = offset
            offset += labelLen
            guard offset <= Int(length) else { break }
            result.append(String(bytes: name[start..<offset], encoding: .utf8) ?? "")
        }
        return result
    }

    /// Get the full domain as a dotted string.
    public var dotted: String {
        labels.joined(separator: ".")
    }

    /// Case-insensitive domain equality.
    public func equals(_ other: MDNSDomain) -> Bool {
        if length != other.length { return false }
        var ptrA = 0
        var ptrB = 0
        while ptrA < Int(length) && ptrB < Int(length) {
            let lenA = name[ptrA]
            let lenB = other.name[ptrB]
            if lenA != lenB { return false }
            if lenA == 0 { break }
            ptrA += 1
            ptrB += 1
            for i in 0..<Int(lenA) {
                let a = name[ptrA + i]
                let b = other.name[ptrB + i]
                // Case-insensitive ASCII comparison
                let la = (a >= 0x41 && a <= 0x5A) ? a + 0x20 : a
                let lb = (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b
                if la != lb { return false }
            }
            ptrA += Int(lenA)
            ptrB += Int(lenA)
        }
        return true
    }
}

// MARK: - Domain Building Helpers

/// Build the hostname.local. domain.
internal func mdnsBuildHostDomain(hostname: String) -> MDNSDomain {
    var domain = MDNSDomain()
    domain.addLabel(hostname)
    domain.addDotLocal()
    return domain
}

/// Build the _services._dns-sd._udp.local. domain.
internal func mdnsBuildDnssdDomain() -> MDNSDomain {
    var domain = MDNSDomain()
    domain.addLabel("_services")
    domain.addLabel("_dns-sd")
    domain.addLabel("_udp")
    domain.addDotLocal()
    return domain
}

/// Build a service domain: [name.]_type._proto.local.
internal func mdnsBuildServiceDomain(service: MDNSService, includeName: Bool) -> MDNSDomain {
    var domain = MDNSDomain()
    if includeName {
        domain.addLabel(service.name)
    }
    domain.addLabel(service.serviceType)
    domain.addLabel(service.proto.dnsString)
    domain.addDotLocal()
    return domain
}

// MARK: - MDNSRRInfo

/// DNS resource record info (shared between questions and answers).
public struct MDNSRRInfo: Sendable {
    public var domain: MDNSDomain
    public var type: UInt16
    public var klass: UInt16

    public init(domain: MDNSDomain = MDNSDomain(), type: UInt16 = 0, klass: UInt16 = 0) {
        self.domain = domain
        self.type = type
        self.klass = klass
    }
}

// MARK: - MDNSQuestion

/// DNS question record.
internal struct MDNSQuestion {
    var info: MDNSRRInfo
    var unicast: Bool

    init() {
        info = MDNSRRInfo()
        unicast = false
    }
}

// MARK: - MDNSAnswer

/// DNS answer record.
public struct MDNSAnswer: Sendable {
    public var info: MDNSRRInfo
    /// Cache flush bit.
    public var cacheFlush: UInt16
    /// TTL in seconds.
    public var ttl: UInt32
    /// Length of variable answer data.
    public var rdLength: UInt16
    /// Offset in packet for variable answer data.
    public var rdOffset: UInt16

    public init() {
        info = MDNSRRInfo()
        cacheFlush = 0
        ttl = 0
        rdLength = 0
        rdOffset = 0
    }
}

// MARK: - MDNSPacket (Parsed Incoming Packet)

/// Parsed mDNS packet for incoming processing.
internal struct MDNSInPacket {
    var sourceAddr: IPAddress = .any
    var sourcePort: UInt16 = 0
    var receivedUnicast: Bool = false
    var data: [UInt8] = []
    var parseOffset: Int = 0
    var txId: UInt16 = 0
    var questions: UInt16 = 0
    var questionsLeft: UInt16 = 0
    var answers: UInt16 = 0
    var answersLeft: UInt16 = 0
    var authoritative: UInt16 = 0
    var authoritativeLeft: UInt16 = 0
    var additional: UInt16 = 0
    var additionalLeft: UInt16 = 0
}

// MARK: - MDNSOutPacket (Packet Being Built)

/// Output packet being constructed.
internal struct MDNSOutPacket {
    var buffer: [UInt8] = []
    var writeOffset: Int = MDNSConfig.dnsHeaderSize
    var questions: UInt16 = 0
    var answers: UInt16 = 0
    var authoritative: UInt16 = 0
    var additional: UInt16 = 0
    var domainOffsets: [UInt16] = Array(repeating: 0, count: MDNSConfig.numDomainOffsets)

    init() {
        buffer = [UInt8](repeating: 0, count: MDNSConfig.outputPacketSize)
    }
}

// MARK: - MDNSOutMsg (What to send)

/// Description of what records to include in an outgoing message.
internal struct MDNSOutMsg {
    var hostReplies: ReplyFlags = []
    var servReplies: [ReplyFlags]
    var hostQuestions: Bool = false
    var servQuestions: [Bool]
    var flags: UInt8 = 0
    var cacheFlush: Bool = true
    var destAddr: IPAddress = MDNSConfig.ipv4MulticastAddr
    var destPort: UInt16 = MDNSConfig.port
    var txId: UInt16 = 0
    var legacyQuery: Bool = false
    var unicastReplyRequested: Bool = false
    var probeQueryReceived: Bool = false
    /// Whether to include an NSEC record for the host name (name matched but type didn't).
    var hostNSEC: Bool = false
    /// Whether to include an NSEC record per service instance (name matched but type didn't).
    var servNSEC: [Bool]

    init() {
        servReplies = Array(repeating: [], count: MDNSConfig.maxServices)
        servQuestions = Array(repeating: false, count: MDNSConfig.maxServices)
        servNSEC = Array(repeating: false, count: MDNSConfig.maxServices)
    }
}

// MARK: - Wire Format Helpers

/// Write a UInt16 in big-endian to a buffer at offset.
@inline(__always)
internal func writeU16(_ buffer: inout [UInt8], offset: Int, value: UInt16) {
    buffer[offset]     = UInt8(value >> 8)
    buffer[offset + 1] = UInt8(value & 0xFF)
}

/// Write a UInt32 in big-endian to a buffer at offset.
@inline(__always)
internal func writeU32(_ buffer: inout [UInt8], offset: Int, value: UInt32) {
    buffer[offset]     = UInt8((value >> 24) & 0xFF)
    buffer[offset + 1] = UInt8((value >> 16) & 0xFF)
    buffer[offset + 2] = UInt8((value >> 8)  & 0xFF)
    buffer[offset + 3] = UInt8(value & 0xFF)
}

/// Read a UInt16 in big-endian from a buffer at offset.
@inline(__always)
internal func readU16(_ data: [UInt8], offset: Int) -> UInt16 {
    return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
}

/// Read a UInt32 in big-endian from a buffer at offset.
@inline(__always)
internal func readU32(_ data: [UInt8], offset: Int) -> UInt32 {
    return (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16) |
           (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
}

// MARK: - DNS Name Reading from Wire

/// Read a possibly compressed domain name from packet data.
/// Returns the new offset after the name, or readNameError on failure.
internal func mdnsReadName(_ data: [UInt8], offset: Int, domain: inout MDNSDomain, depth: Int = 0) -> Int {
    guard depth <= 5 else { return Int(MDNSConfig.readNameError) }
    var off = offset
    var returnOffset = -1 // track whether we jumped

    while off < data.count {
        let c = data[off]
        off += 1

        // Compressed label?
        if (c & 0xC0) == 0xC0 {
            guard off < data.count else { return Int(MDNSConfig.readNameError) }
            let jumpAddr = (Int(c & 0x3F) << 8) | Int(data[off])
            off += 1
            if returnOffset < 0 { returnOffset = off }
            guard jumpAddr >= MDNSConfig.dnsHeaderSize && jumpAddr < data.count else {
                return Int(MDNSConfig.readNameError)
            }
            let res = mdnsReadName(data, offset: jumpAddr, domain: &domain, depth: depth + 1)
            if res == Int(MDNSConfig.readNameError) { return res }
            return returnOffset
        }

        // Normal label
        guard c <= MDNSConfig.labelMaxLen else { return Int(MDNSConfig.readNameError) }

        if c == 0 {
            // Terminal zero
            domain.addLabel([], count: 0)
            break
        }

        guard off + Int(c) <= data.count else { return Int(MDNSConfig.readNameError) }
        guard Int(c) + Int(domain.length) < MDNSConfig.domainMaxLen else {
            return Int(MDNSConfig.readNameError)
        }
        let labelBytes = Array(data[off..<(off + Int(c))])
        domain.addLabel(labelBytes, count: c)
        off += Int(c)
    }

    return returnOffset >= 0 ? returnOffset : off
}

// MARK: - DNS Name Writing with Compression

/// Attempt to compress a domain against a previously written domain in the output buffer.
/// Returns the number of bytes of the new domain to write before the jump, and updates
/// jumpOffset to where to jump if compression was found.
internal func mdnsCompressDomain(
    outBuffer: [UInt8],
    existingOffset: inout UInt16,
    domain: MDNSDomain
) -> Int {
    // Read the existing domain from the output buffer
    var target = MDNSDomain()
    let targetEnd = mdnsReadName(outBuffer, offset: Int(existingOffset), domain: &target)
    if targetEnd == Int(MDNSConfig.readNameError) { return Int(domain.length) }
    let targetLen = UInt8(targetEnd - Int(existingOffset))

    var writelen: Int = 0
    var ptr = 0

    while writelen < Int(domain.length) {
        let domainlen = Int(domain.length) - writelen
        if domainlen <= Int(target.length) && domainlen > MDNSConfig.domainJumpSize {
            let targetpos = Int(target.length) - domainlen
            if (targetpos + MDNSConfig.domainJumpSize) >= Int(targetLen) {
                break
            }
            if Int(target.length) >= domainlen {
                let match = domain.name[writelen..<(writelen + domainlen)]
                    .elementsEqual(target.name[targetpos..<(targetpos + domainlen)])
                if match {
                    existingOffset += UInt16(targetpos)
                    return writelen
                }
            }
        }
        // Skip to next label
        let labellen = Int(domain.name[ptr])
        writelen += 1 + labellen
        ptr += 1 + labellen
    }
    return Int(domain.length)
}

/// Write a domain name to the output packet, with compression.
internal func mdnsWriteDomain(_ outpkt: inout MDNSOutPacket, domain: MDNSDomain) {
    var writelen = Int(domain.length)
    var jumpOffset: UInt16 = 0

    if !domain.skipCompression {
        for i in 0..<MDNSConfig.numDomainOffsets {
            var offset = outpkt.domainOffsets[i]
            if offset != 0 {
                let len = mdnsCompressDomain(
                    outBuffer: outpkt.buffer,
                    existingOffset: &offset,
                    domain: domain
                )
                if len < writelen {
                    writelen = len
                    jumpOffset = offset
                }
            }
        }
    }

    if writelen > 0 {
        // Write uncompressed part
        for i in 0..<writelen {
            guard outpkt.writeOffset + i < outpkt.buffer.count else { break }
            outpkt.buffer[outpkt.writeOffset + i] = domain.name[i]
        }

        // Store offset of this new domain for future compression
        for i in 0..<MDNSConfig.numDomainOffsets {
            if outpkt.domainOffsets[i] == 0 {
                outpkt.domainOffsets[i] = UInt16(outpkt.writeOffset)
                break
            }
        }

        outpkt.writeOffset += writelen
    }

    if jumpOffset != 0 {
        // Write compression pointer (2 bytes)
        let jump = MDNSConfig.domainJump | jumpOffset
        guard outpkt.writeOffset + 1 < outpkt.buffer.count else { return }
        writeU16(&outpkt.buffer, offset: outpkt.writeOffset, value: jump)
        outpkt.writeOffset += MDNSConfig.domainJumpSize
    }
}

// MARK: - DNS Question / Answer Writing

/// Write a question (domain + type + class) to the output packet.
internal func mdnsAddQuestion(
    _ outpkt: inout MDNSOutPacket,
    domain: MDNSDomain,
    type: UInt16,
    klass: UInt16,
    unicast: Bool
) {
    mdnsWriteDomain(&outpkt, domain: domain)

    guard outpkt.writeOffset + 4 <= outpkt.buffer.count else { return }
    writeU16(&outpkt.buffer, offset: outpkt.writeOffset, value: type)
    outpkt.writeOffset += 2

    var classVal = klass
    if unicast { classVal |= 0x8000 }
    writeU16(&outpkt.buffer, offset: outpkt.writeOffset, value: classVal)
    outpkt.writeOffset += 2
}

/// Write a full answer record to the output packet.
internal func mdnsAddAnswer(
    _ outpkt: inout MDNSOutPacket,
    domain: MDNSDomain,
    type: UInt16,
    klass: UInt16,
    cacheFlush: Bool,
    ttl: UInt32,
    rdata: [UInt8]?,
    answerDomain: MDNSDomain?
) {
    // Write name + type + class (like a question)
    mdnsAddQuestion(&outpkt, domain: domain, type: type, klass: klass, unicast: cacheFlush)

    guard outpkt.writeOffset + 6 <= outpkt.buffer.count else { return }

    // Write TTL
    writeU32(&outpkt.buffer, offset: outpkt.writeOffset, value: ttl)
    outpkt.writeOffset += 4

    // Reserve RDLENGTH position
    let rdlenOffset = outpkt.writeOffset
    outpkt.writeOffset += 2

    let answerDataStart = outpkt.writeOffset

    // Write RDATA
    if let rdata = rdata {
        for byte in rdata {
            guard outpkt.writeOffset < outpkt.buffer.count else { break }
            outpkt.buffer[outpkt.writeOffset] = byte
            outpkt.writeOffset += 1
        }
    }

    // Write answer domain (for PTR, SRV)
    if let ansDomain = answerDomain {
        mdnsWriteDomain(&outpkt, domain: ansDomain)
    }

    // Write actual RDLENGTH
    let rdlen = UInt16(outpkt.writeOffset - answerDataStart)
    writeU16(&outpkt.buffer, offset: rdlenOffset, value: rdlen)
}

// MARK: - DNS Header Writing

/// Write the DNS header to an output packet.
internal func mdnsWriteHeader(_ outpkt: inout MDNSOutPacket, msg: MDNSOutMsg) {
    // ID
    writeU16(&outpkt.buffer, offset: 0, value: msg.txId)
    // FLAGS: flags1 in byte 2, flags2 in byte 3
    outpkt.buffer[2] = msg.flags
    outpkt.buffer[3] = 0
    // QDCOUNT
    writeU16(&outpkt.buffer, offset: 4, value: outpkt.questions)
    // ANCOUNT
    writeU16(&outpkt.buffer, offset: 6, value: outpkt.answers)
    // NSCOUNT (authoritative)
    writeU16(&outpkt.buffer, offset: 8, value: outpkt.authoritative)
    // ARCOUNT (additional)
    writeU16(&outpkt.buffer, offset: 10, value: outpkt.additional)
}

// MARK: - Callback Types

extension MDNSResponder {
    /// Callback for getting service TXT records.
    public typealias TXTRecordHandler = @Sendable (MDNSService) -> Void

    /// Callback for probing name result.
    public typealias NameResultHandler = @Sendable (NetworkInterface, UInt8, Int8) -> Void

    /// Callback for search results.
    public typealias SearchResultHandler = @Sendable (MDNSAnswer, String, Int, Int, AnyObject?) -> Void
}

// MARK: - MDNSService

/// Registered mDNS service.
public final class MDNSService: @unchecked Sendable {
    /// Service instance name.
    public var name: String
    /// Service type (e.g., "_http").
    public var serviceType: String
    /// Protocol.
    public var proto: MDNSProtocol
    /// Port number.
    public var port: UInt16
    /// TXT record callback.
    public var txtCallback: MDNSResponder.TXTRecordHandler?
    /// User data for TXT callback.
    public var txtUserData: AnyObject?
    /// TXT record items.
    public internal(set) var txtRecords: [String] = []

    public init(name: String, serviceType: String, proto: MDNSProtocol,
                port: UInt16, txtCallback: MDNSResponder.TXTRecordHandler? = nil,
                txtUserData: AnyObject? = nil) {
        self.name = name
        self.serviceType = serviceType
        self.proto = proto
        self.port = port
        self.txtCallback = txtCallback
        self.txtUserData = txtUserData
    }

    /// Add a TXT record item.
    ///
    /// - Parameters:
    ///   - txt: The TXT record string (e.g., "key=value").
    ///   - length: Length of the string.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func addTxtItem(_ txt: String) -> LWIPError {
        guard txt.utf8.count <= 255 else { return .invalidValue }
        txtRecords.append(txt)
        return .ok
    }

    /// Build TXT rdata: each item is length-prefixed.
    internal func buildTxtData() -> [UInt8] {
        // Call the user TXT callback if set, to let user populate txtRecords
        txtCallback?(self)

        var data: [UInt8] = []
        if txtRecords.isEmpty {
            // Empty TXT record: single zero-length string
            data.append(0)
            return data
        }
        for record in txtRecords {
            let bytes = Array(record.utf8)
            data.append(UInt8(min(bytes.count, 255)))
            data.append(contentsOf: bytes.prefix(255))
        }
        return data
    }
}

// MARK: - MDNSHost

/// mDNS host info associated with a network interface.
internal final class MDNSHost: @unchecked Sendable {
    /// Hostname.
    var hostname: String
    /// Services registered on this host.
    var services: [MDNSService?]
    /// State machine state.
    var state: MDNSState = .off
    /// Number of probes/announces sent in current state.
    var sentNum: Int = 0

    init(hostname: String) {
        self.hostname = hostname
        self.services = Array(repeating: nil, count: MDNSConfig.maxServices)
    }

    /// Whether the host is still probing.
    var probing: Bool {
        switch state {
        case .off, .probeWait, .probing, .announceWait:
            return true
        case .announcing, .complete:
            return false
        }
    }
}

// MARK: - MDNSSearchRequest

/// Active mDNS search request (port of mdns_request from C).
/// Tracks a service search query and its result callback.
internal final class MDNSSearchRequest: @unchecked Sendable {
    /// Name of service instance to search for (optional).
    var name: String
    /// Service type domain (e.g., the encoded form of "_http").
    var service: MDNSDomain
    /// Protocol (UDP or TCP).
    var proto: MDNSProtocol
    /// DNS query type (usually PTR).
    var queryType: UInt16
    /// Whether only PTR answers should be accepted.
    var onlyPTR: Bool
    /// Result callback.
    var resultCallback: MDNSResponder.SearchResultHandler?
    /// User argument for callback.
    var arg: AnyObject?

    init() {
        name = ""
        service = MDNSDomain()
        proto = .udp
        queryType = DNSRecordType.ptr.rawValue
        onlyPTR = false
        resultCallback = nil
        arg = nil
    }
}

// MARK: - PendingTCQuery (RFC 6762 Section 7.2)

/// A truncated query waiting for follow-up known-answer packets.
///
/// When a query arrives with the TC (truncation) bit set, the responder
/// stores the parsed question data and collects any subsequent known-answer
/// packets that arrive from the same source within a 400-500ms window.
/// After the timer fires the query is handled with all collected known
/// answers applied for suppression.
internal final class PendingTCQuery: @unchecked Sendable {
    /// Source address of the querier.
    let sourceAddr: IPAddress
    /// Source port of the querier.
    let sourcePort: UInt16
    /// Network interface the truncated query arrived on.
    let netif: NetworkInterface
    /// Raw packet data of the original truncated query.
    let data: [UInt8]
    /// Additional known-answer packets received from the same source while
    /// the TC delay timer is running. Each entry is the raw packet bytes.
    var knownAnswerPackets: [[UInt8]] = []

    init(sourceAddr: IPAddress, sourcePort: UInt16, netif: NetworkInterface, data: [UInt8]) {
        self.sourceAddr = sourceAddr
        self.sourcePort = sourcePort
        self.netif = netif
        self.data = data
    }
}

// MARK: - MDNSResponder

/// Multicast DNS responder.
///
/// Responds to mDNS queries for registered hostnames and services.
/// Supports DNS-SD service discovery.
public final class MDNSResponder: @unchecked Sendable {

    /// Shared instance.
    public static let shared = MDNSResponder()

    /// Hosts indexed by network interface.
    private var hosts: [ObjectIdentifier: MDNSHost] = [:]

    /// Name result callback.
    private var nameResultCallback: MDNSResponder.NameResultHandler?

    /// UDP control block for mDNS.
    private var udpControlBlock: UDPControlBlock?

    /// Whether the responder is initialized.
    private var initialized = false

    /// Lock.
    private let lock = NSLock()

    /// Mapping from interface identifier to the interface itself (needed for timers).
    private var interfaces: [ObjectIdentifier: NetworkInterface] = [:]

    /// Active search requests (indexed by slot).
    private var searchRequests: [MDNSSearchRequest?] = Array(
        repeating: nil, count: MDNSConfig.maxSearchRequests
    )

    /// Truncated queries waiting for follow-up known-answer packets
    /// (RFC 6762 Section 7.2).
    private var pendingTCQueries: [PendingTCQuery] = []

    private init() {}

    // MARK: - Initialization

    /// Initialize the mDNS responder.
    public func initialize() {
        lock.lock()
        defer { lock.unlock() }

        guard !initialized else { return }
        initialized = true

        // Create UDP PCB and bind to mDNS port.
        let udpPcb = UDPControlBlock()
        udpControlBlock = udpPcb

        // Bind to mDNS port on all interfaces.
        UDPGlobal.shared.bind(udpPcb, address: .any, port: MDNSConfig.port)

        // Set TTL for mDNS (255 as per RFC 6762).
        udpPcb.ttl = 255
        udpPcb.multicastTTL = 255

        // Set up receive callback.
        udpPcb.receiveHandler = { [weak self] pcb, pbuf, srcAddr, srcPort in
            self?.handleUDPReceive(pcb: pcb, pbuf: pbuf, srcAddr: srcAddr, srcPort: srcPort)
        }
    }

    // MARK: - UDP Receive Handler

    /// Handle incoming UDP data on port 5353.
    private func handleUDPReceive(pcb: UDPControlBlock, pbuf: Pbuf, srcAddr: IPAddress, srcPort: UInt16) {
        // Copy pbuf payload into a byte array for parsing
        let totalLen = Int(pbuf.totLen)
        guard totalLen >= MDNSConfig.dnsHeaderSize else { return }

        var data = [UInt8](repeating: 0, count: totalLen)
        var p: Pbuf? = pbuf
        var offset = 0
        while let current = p {
            let len = Int(current.len)
            current.payload.withMemoryRebound(to: UInt8.self, capacity: len) { ptr in
                for i in 0..<len {
                    data[offset + i] = ptr[i]
                }
            }
            offset += len
            p = current.next
        }

        // Determine which network interface received this
        let netifIdx = pbuf.ifIndex
        guard let netif = NetworkInterface.getByIndex(netifIdx) else { return }

        processReceived(data: data, from: srcAddr, port: srcPort, netif: netif)
    }

    // MARK: - Name Result Callback

    /// Register a callback for probing name results.
    public func registerNameResultCallback(_ cb: @escaping MDNSResponder.NameResultHandler) {
        lock.lock()
        nameResultCallback = cb
        lock.unlock()
    }

    // MARK: - Network Interface Management

    /// Add a network interface with a hostname.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - hostname: The hostname for this interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func addNetif(_ netif: NetworkInterface, hostname: String) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        let key = ObjectIdentifier(netif)
        guard hosts[key] == nil else { return .addressInUse }

        let host = MDNSHost(hostname: hostname)
        hosts[key] = host
        interfaces[key] = netif

        // Join multicast group on this interface (224.0.0.251).
        // In a real lwIP integration, this calls igmp_joingroup_netif.

        // Start probing for name uniqueness.
        startProbing(netif: netif, host: host)

        return .ok
    }

    /// Remove a network interface.
    /// Sends goodbye messages (TTL=0) for all previously-announced records
    /// before removing the interface (RFC 6762 Section 10.1).
    @discardableResult
    public func removeNetif(_ netif: NetworkInterface) -> LWIPError {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return .invalidValue }
        // Only send goodbye if the host had completed probing/announcing.
        let shouldGoodbye = !host.probing && host.state != .off
        lock.unlock()

        if shouldGoodbye {
            sendGoodbye(for: netif)
        }

        lock.lock()
        hosts[key] = nil
        interfaces[key] = nil
        lock.unlock()
        return .ok
    }

    /// Rename a network interface's hostname.
    @discardableResult
    public func renameNetif(_ netif: NetworkInterface, hostname: String) -> LWIPError {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return .invalidValue }
        host.hostname = hostname
        host.state = .off
        host.sentNum = 0
        lock.unlock()

        // Re-probe with new name.
        startProbing(netif: netif, host: host)
        return .ok
    }

    /// Check if an interface is actively responding to mDNS.
    public func netifActive(_ netif: NetworkInterface) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { return false }
        return !host.probing
    }

    // MARK: - Service Management

    /// Add a service to a network interface.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - name: Service instance name.
    ///   - serviceType: Service type (e.g., "_http").
    ///   - proto: Transport protocol.
    ///   - port: Service port.
    ///   - txtCallback: TXT record generation callback.
    ///   - txtUserData: User data for TXT callback.
    /// - Returns: Service slot index (0-based), or -1 on error.
    public func addService(
        _ netif: NetworkInterface,
        name: String,
        serviceType: String,
        proto: MDNSProtocol,
        port: UInt16,
        txtCallback: MDNSResponder.TXTRecordHandler? = nil,
        txtUserData: AnyObject? = nil
    ) -> Int8 {
        lock.lock()
        defer { lock.unlock() }

        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { return -1 }

        // Find empty slot.
        for i in 0..<host.services.count {
            if host.services[i] == nil {
                let service = MDNSService(
                    name: name,
                    serviceType: serviceType,
                    proto: proto,
                    port: port,
                    txtCallback: txtCallback,
                    txtUserData: txtUserData
                )
                host.services[i] = service
                return Int8(i)
            }
        }

        return -1
    }

    /// Delete a service by slot.
    /// Sends a goodbye message for the service before removing it (RFC 6762 Section 10.1).
    @discardableResult
    public func deleteService(_ netif: NetworkInterface, slot: UInt8) -> LWIPError {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return .invalidValue }
        guard Int(slot) < host.services.count else { lock.unlock(); return .invalidValue }
        guard let service = host.services[Int(slot)] else { lock.unlock(); return .invalidValue }
        let shouldGoodbye = !host.probing && host.state != .off
        lock.unlock()

        if shouldGoodbye {
            sendServiceGoodbye(for: netif, host: host, service: service)
        }

        lock.lock()
        host.services[Int(slot)] = nil
        lock.unlock()
        return .ok
    }

    /// Rename a service.
    @discardableResult
    public func renameService(_ netif: NetworkInterface, slot: UInt8, name: String) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { return .invalidValue }
        guard Int(slot) < host.services.count else { return .invalidValue }
        guard let service = host.services[Int(slot)] else { return .invalidValue }

        service.name = name
        return .ok
    }

    /// Get user data for a service's TXT callback.
    public func getServiceTxtUserData(_ netif: NetworkInterface, slot: Int8) -> AnyObject? {
        lock.lock()
        defer { lock.unlock() }

        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { return nil }
        guard Int(slot) < host.services.count else { return nil }
        return host.services[Int(slot)]?.txtUserData
    }

    // MARK: - Announcements

    /// Announce presence (gratuitous mDNS response).
    public func announce(_ netif: NetworkInterface) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        lock.unlock()

        // Build and send announcement packets for the host and all services.
        buildAndSendAnnouncement(netif: netif, host: host)
    }

    /// Restart mDNS after a network change (with optional delay).
    public func restart(_ netif: NetworkInterface) {
        restartDelay(netif, delay: 0)
    }

    /// Restart mDNS with a delay.
    public func restartDelay(_ netif: NetworkInterface, delay: UInt32) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        host.state = .off
        host.sentNum = 0
        lock.unlock()

        if delay > 0 {
            TCPIP.shared.timeout(msecs: delay) { [weak self] in
                self?.startProbing(netif: netif, host: host)
            }
        } else {
            startProbing(netif: netif, host: host)
        }
    }

    // MARK: - Active Service Search (RFC 6762 / RFC 6763)

    /// Search for a service on the network.
    ///
    /// Sends an mDNS query for the specified service type and invokes
    /// `resultCallback` for each matching response received. The search
    /// remains active until `searchStop` is called with the returned ID.
    ///
    /// - Parameters:
    ///   - name: Optional service instance name to search for. When `nil`,
    ///     the query asks for all instances of the service type (PTR query).
    ///   - serviceType: Service type (e.g., "_http").
    ///   - proto: Transport protocol (.tcp or .udp).
    ///   - netif: Network interface to search on.
    ///   - resultCallback: Called with each matching answer.
    ///   - arg: User argument passed to callback.
    /// - Returns: Request ID (slot index) on success, or an error.
    @discardableResult
    public func searchService(
        name: String?,
        serviceType: String,
        proto: MDNSProtocol,
        netif: NetworkInterface,
        resultCallback: @escaping MDNSResponder.SearchResultHandler,
        arg: AnyObject? = nil
    ) -> Result<UInt8, LWIPError> {
        guard MDNSConfig.searchEnabled else { return .failure(.invalidValue) }
        guard self.udpControlBlock != nil else { return .failure(.invalidValue) }
        guard serviceType.utf8.count <= MDNSConfig.labelMaxLen else { return .failure(.invalidValue) }
        if let n = name {
            guard n.utf8.count <= MDNSConfig.labelMaxLen else { return .failure(.invalidValue) }
        }

        lock.lock()
        // Find an empty request slot.
        var slot: Int = -1
        for i in 0..<searchRequests.count {
            if searchRequests[i] == nil || searchRequests[i]?.resultCallback == nil {
                slot = i
                break
            }
        }
        guard slot >= 0 else {
            lock.unlock()
            return .failure(.outOfMemory)
        }

        let req = MDNSSearchRequest()
        req.resultCallback = resultCallback
        req.arg = arg
        req.proto = proto
        req.queryType = DNSRecordType.ptr.rawValue
        req.name = name ?? ""

        // Build the service domain for matching incoming responses.
        // For "_services._dns-sd._udp" type queries, mark as PTR-only.
        if proto == .udp && serviceType == "_services._dns-sd" {
            req.onlyPTR = true
        }
        // Encode the service type into the request's domain for later matching.
        req.service = MDNSDomain()
        req.service.addLabel(serviceType)

        searchRequests[slot] = req
        lock.unlock()

        // Build the query domain: [name.]_type._proto.local
        var queryDomain = MDNSDomain()
        if let n = name, !n.isEmpty {
            queryDomain.addLabel(n)
        }
        queryDomain.addLabel(serviceType)
        queryDomain.addLabel(proto.dnsString)
        queryDomain.addDotLocal()

        // Determine query type: PTR for service enumeration, SRV/TXT for specific names.
        let qtype: UInt16
        if name != nil && !name!.isEmpty {
            qtype = DNSRecordType.any.rawValue
        } else {
            qtype = DNSRecordType.ptr.rawValue
        }

        var outpkt = MDNSOutPacket()
        mdnsAddQuestion(&outpkt, domain: queryDomain, type: qtype,
                        klass: MDNSConfig.dnsClassIN, unicast: false)
        outpkt.questions += 1

        var msg = MDNSOutMsg()
        msg.flags = 0  // query, not response
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)

        return .success(UInt8(slot))
    }

    /// Stop an active search.
    ///
    /// Clears the search request identified by `requestId` so that no further
    /// callbacks will be invoked for it.
    ///
    /// - Parameter requestId: The search request ID returned by `searchService`.
    public func searchStop(requestId: UInt8) {
        lock.lock()
        defer { lock.unlock() }
        let idx = Int(requestId)
        guard idx < searchRequests.count else { return }
        searchRequests[idx]?.resultCallback = nil
        searchRequests[idx] = nil
    }

    /// Build a request domain for matching incoming answers against a search request.
    ///
    /// - Parameters:
    ///   - request: The search request.
    ///   - includeName: Whether to prepend the instance name.
    /// - Returns: The constructed domain.
    private func mdnsBuildRequestDomain(request: MDNSSearchRequest, includeName: Bool) -> MDNSDomain {
        var domain = MDNSDomain()
        if includeName && !request.name.isEmpty {
            domain.addLabel(request.name)
        }
        domain.addDomain(request.service)
        domain.addLabel(request.proto.dnsString)
        domain.addDotLocal()
        return domain
    }

    /// Check whether an incoming answer matches a search request.
    /// Returns a non-zero reply mask on match.
    private func checkSearchRequest(_ request: MDNSSearchRequest, rr: MDNSRRInfo) -> ReplyFlags {
        guard rr.klass == MDNSConfig.dnsClassIN || rr.klass == MDNSConfig.dnsClassANY else {
            return []
        }

        var replies: ReplyFlags = []

        // Check PTR for the service type (no instance name).
        let typeDomain = mdnsBuildRequestDomain(request: request, includeName: false)
        if rr.domain.equals(typeDomain) &&
           (rr.type == DNSRecordType.ptr.rawValue || rr.type == DNSRecordType.any.rawValue) {
            replies.insert(.serviceTypePTR)
        }

        // Check SRV/TXT for the service instance (with name).
        if !request.name.isEmpty {
            let instDomain = mdnsBuildRequestDomain(request: request, includeName: true)
            if rr.domain.equals(instDomain) {
                if rr.type == DNSRecordType.srv.rawValue || rr.type == DNSRecordType.any.rawValue {
                    replies.insert(.serviceSRV)
                }
                if rr.type == DNSRecordType.txt.rawValue || rr.type == DNSRecordType.any.rawValue {
                    replies.insert(.serviceTXT)
                }
            }
        }

        return replies
    }

    /// Look up a matching search request for an incoming answer.
    /// Returns the first request whose domain/type matches the answer.
    private func lookupSearchRequest(rr: MDNSRRInfo) -> MDNSSearchRequest? {
        for req in searchRequests {
            guard let r = req, r.resultCallback != nil else { continue }
            if !checkSearchRequest(r, rr: rr).isEmpty {
                return r
            }
        }
        return nil
    }

    // MARK: - Probing (RFC 6762 Section 8.1)

    /// Start probing for name uniqueness.
    /// Sends 3 probe queries at 250ms intervals. If no conflict is detected,
    /// transitions to announcing state.
    private func startProbing(netif: NetworkInterface, host: MDNSHost) {
        host.state = .probeWait
        host.sentNum = 0

        // Schedule the first probe (random 0-250ms delay per RFC 6762).
        let initialDelay = UInt32.random(in: 0...MDNSConfig.probeDelayMs)
        TCPIP.shared.timeout(msecs: initialDelay) { [weak self] in
            self?.probeAndAnnounce(netif: netif, host: host)
        }
    }

    /// State machine for probing and announcing (mirrors mdns_probe_and_announce in C).
    private func probeAndAnnounce(netif: NetworkInterface, host: MDNSHost) {
        switch host.state {
        case .off, .probeWait, .probing:
            // Send a probe
            sendProbe(netif: netif, host: host)
            host.state = .probing
            host.sentNum += 1

            if host.sentNum >= MDNSConfig.probeCount {
                // Probing done, transition to announce
                host.state = .announceWait
                host.sentNum = 0
            }

            // Schedule next probe or first announce
            TCPIP.shared.timeout(msecs: MDNSConfig.probeDelayMs) { [weak self] in
                self?.probeAndAnnounce(netif: netif, host: host)
            }

        case .announceWait, .announcing:
            if host.sentNum == 0 {
                // Probing was successful
                host.state = .announcing

                // Notify the callback
                nameResultCallback?(netif, MDNSConfig.probingSuccessful, 0)
            }

            // Send announcement
            buildAndSendAnnouncement(netif: netif, host: host)
            host.sentNum += 1

            if host.sentNum >= MDNSConfig.announceCount {
                // All announcements sent
                host.state = .complete
                host.sentNum = 0
            } else {
                // Schedule next announcement with doubling delay (1s, 2s, ...)
                let delay = MDNSConfig.announceDelayMs * UInt32(1 << (host.sentNum - 1))
                TCPIP.shared.timeout(msecs: delay) { [weak self] in
                    self?.probeAndAnnounce(netif: netif, host: host)
                }
            }

        case .complete:
            break
        }
    }

    /// Send a single mDNS probe packet (QU query for our records, with authority section
    /// containing our proposed records for tiebreaking).
    private func sendProbe(netif: NetworkInterface, host: MDNSHost) {
        var outpkt = MDNSOutPacket()

        // Add questions: ANY type query for our hostname (unicast-response requested)
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        mdnsAddQuestion(&outpkt, domain: hostDomain, type: DNSRecordType.any.rawValue,
                        klass: MDNSConfig.dnsClassIN, unicast: true)
        outpkt.questions += 1

        // Also add questions for each service instance
        for service in host.services {
            guard let svc = service else { continue }
            let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
            mdnsAddQuestion(&outpkt, domain: svcDomain, type: DNSRecordType.any.rawValue,
                            klass: MDNSConfig.dnsClassIN, unicast: true)
            outpkt.questions += 1
        }

        // Authority section: add our proposed A record for tiebreaking
        if !netif.ipAddr.isAny {
            let addrBytes = ipv4AddressBytes(netif.ipAddr)
            mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
            outpkt.authoritative += 1
        }

        // Add AAAA records for valid IPv6 addresses
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if netif.ipv6AddressStates[i].isValid {
                let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                              klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                              ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
                outpkt.authoritative += 1
            }
        }

        // Add SRV records for services in authority section
        for service in host.services {
            guard let svc = service else { continue }
            let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
            let srvData = buildSRVData(service: svc)
            let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
            mdnsAddAnswer(&outpkt, domain: svcDomain, type: DNSRecordType.srv.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.hostTTL, rdata: srvData, answerDomain: srvHost)
            outpkt.authoritative += 1
        }

        // Write header: this is a query (not response), ID = 0
        var msg = MDNSOutMsg()
        msg.flags = 0  // query, not response
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)
    }

    // MARK: - Announcement (RFC 6762 Section 8.3)

    /// Build and send an mDNS announcement.
    private func buildAndSendAnnouncement(netif: NetworkInterface, host: MDNSHost) {
        var outpkt = MDNSOutPacket()

        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)

        // A record for hostname -> IPv4 address
        if !netif.ipAddr.isAny {
            let addrBytes = ipv4AddressBytes(netif.ipAddr)
            mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                          ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
            outpkt.answers += 1
        }

        // AAAA records for hostname -> IPv6 addresses
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if netif.ipv6AddressStates[i].isValid {
                let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                              klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                              ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
                outpkt.answers += 1
            }
        }

        // Service records
        let dnssdDomain = mdnsBuildDnssdDomain()

        for service in host.services {
            guard let svc = service else { continue }

            let serviceTypeDomain = mdnsBuildServiceDomain(service: svc, includeName: false)
            let serviceInstanceDomain = mdnsBuildServiceDomain(service: svc, includeName: true)

            // PTR: _services._dns-sd._udp.local -> _type._proto.local
            mdnsAddAnswer(&outpkt, domain: dnssdDomain, type: DNSRecordType.ptr.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.serviceTTL, rdata: nil, answerDomain: serviceTypeDomain)
            outpkt.answers += 1

            // PTR: _type._proto.local -> name._type._proto.local
            mdnsAddAnswer(&outpkt, domain: serviceTypeDomain, type: DNSRecordType.ptr.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.hostTTL, rdata: nil, answerDomain: serviceInstanceDomain)
            outpkt.answers += 1

            // SRV: name._type._proto.local -> priority, weight, port, hostname.local
            let srvData = buildSRVData(service: svc)
            let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
            mdnsAddAnswer(&outpkt, domain: serviceInstanceDomain, type: DNSRecordType.srv.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                          ttl: MDNSConfig.hostTTL, rdata: srvData, answerDomain: srvHost)
            outpkt.answers += 1

            // TXT: name._type._proto.local -> TXT data
            let txtData = svc.buildTxtData()
            mdnsAddAnswer(&outpkt, domain: serviceInstanceDomain, type: DNSRecordType.txt.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                          ttl: MDNSConfig.hostTTL, rdata: txtData, answerDomain: nil)
            outpkt.answers += 1

            // Additional: A/AAAA records for the host
            if !netif.ipAddr.isAny {
                let addrBytes = ipv4AddressBytes(netif.ipAddr)
                mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                              klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                              ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
                outpkt.additional += 1
            }
        }

        // Write DNS header: this is a response with AA flag
        var msg = MDNSOutMsg()
        msg.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)
    }

    // MARK: - Input Processing

    /// Process a received mDNS packet.
    internal func processReceived(data: [UInt8], from: IPAddress, port: UInt16, netif: NetworkInterface) {
        guard data.count >= MDNSConfig.dnsHeaderSize else { return }

        let key = ObjectIdentifier(netif)
        lock.lock()
        guard let host = hosts[key] else { lock.unlock(); return }
        lock.unlock()

        // Parse DNS header
        var pkt = MDNSInPacket()
        pkt.sourceAddr = from
        pkt.sourcePort = port
        pkt.data = data
        pkt.txId = readU16(data, offset: 0)
        let flags1 = data[2]
        pkt.questions = readU16(data, offset: 4)
        pkt.questionsLeft = pkt.questions
        pkt.answers = readU16(data, offset: 6)
        pkt.answersLeft = pkt.answers
        pkt.authoritative = readU16(data, offset: 8)
        pkt.authoritativeLeft = pkt.authoritative
        pkt.additional = readU16(data, offset: 10)
        pkt.additionalLeft = pkt.additional
        pkt.parseOffset = MDNSConfig.dnsHeaderSize

        // Ignore non-standard opcodes
        let opcode = (flags1 >> 3) & 0x0F
        guard opcode == 0 else { return }

        if (flags1 & MDNSConfig.flagResponse) != 0 {
            // This is a response
            handleResponse(pkt: &pkt, netif: netif, host: host)
        } else {
            // This is a query (or a known-answer follow-up)
            if pkt.questions > 0 && (flags1 & MDNSConfig.flagTruncated) != 0 {
                // New truncated query: store and defer 400-500ms per RFC 6762 Section 7.2.
                storeTruncatedQuery(data: data, from: from, port: port, netif: netif)
            } else if pkt.questions == 0 && pkt.answers > 0 {
                // A packet with zero questions and some answers may be a follow-up
                // known-answer packet for a previously received truncated query
                // (RFC 6762 Section 7.2).
                lock.lock()
                let matched = appendKnownAnswerPacket(data: data, from: from, port: port)
                lock.unlock()
                if matched {
                    // Successfully chained to a pending TC query; nothing else to do.
                    return
                }
                // Not a follow-up; fall through to normal question handling.
                handleQuestion(pkt: &pkt, netif: netif, host: host)
            } else {
                handleQuestion(pkt: &pkt, netif: netif, host: host)
            }
        }
    }

    /// Handle an incoming mDNS response (during probing, check for conflicts;
    /// always check for active search matches).
    private func handleResponse(pkt: inout MDNSInPacket, netif: NetworkInterface, host: MDNSHost) {
        // Ignore responses not from port 5353 (RFC 6762 section 6)
        guard pkt.sourcePort == MDNSConfig.port else { return }

        // Look for a search request matching questions (best-effort).
        var activeSearchReq: MDNSSearchRequest? = nil
        if MDNSConfig.searchEnabled {
            // Peek at questions to match against active searches before skipping them.
            var peekPkt = pkt
            while peekPkt.questionsLeft > 0 {
                if let q = readQuestion(&peekPkt) {
                    if let req = lookupSearchRequest(rr: q.info) {
                        activeSearchReq = req
                    }
                }
            }
        }

        // Skip all questions (advance the real parse offset past them).
        while pkt.questionsLeft > 0 {
            guard skipQuestion(&pkt) else { return }
        }

        // Check all answer sections for conflicts and search matches.
        var totalLeft = pkt.answersLeft + pkt.authoritativeLeft + pkt.additionalLeft
        var isFirstSearchResult = true

        while totalLeft > 0 {
            guard let ans = readAnswer(&pkt, numLeft: &totalLeft) else { return }

            // Skip answers with type ANY or class != IN.
            if ans.info.type == DNSRecordType.any.rawValue ||
               ans.info.klass != MDNSConfig.dnsClassIN {
                continue
            }

            // --- Search request dispatching ---
            if MDNSConfig.searchEnabled {
                // If the previous match was PTR-only, verify this answer still matches.
                if let req = activeSearchReq, req.onlyPTR {
                    let svcDomain = mdnsBuildRequestDomain(request: req, includeName: false)
                    if !ans.info.domain.equals(svcDomain) {
                        activeSearchReq = nil
                    }
                }
                // Try harder to find a match if we don't have one yet.
                if activeSearchReq == nil {
                    activeSearchReq = lookupSearchRequest(rr: ans.info)
                }
                if let req = activeSearchReq, let callback = req.resultCallback {
                    var flags = 0
                    if isFirstSearchResult { flags |= MDNSConfig.searchResultFirst }
                    if totalLeft == 0 { flags |= MDNSConfig.searchResultLast }

                    if req.onlyPTR {
                        if ans.info.type == DNSRecordType.ptr.rawValue {
                            flags = MDNSConfig.searchResultFirst | MDNSConfig.searchResultLast
                        } else {
                            // Skip non-PTR answers for PTR-only requests.
                            continue
                        }
                    }

                    // Extract rdata as a string for the callback (domain name or raw bytes).
                    let rdStart = Int(ans.rdOffset)
                    let rdLen = Int(ans.rdLength)
                    var varpart = ""
                    if (ans.info.type == DNSRecordType.ptr.rawValue ||
                        ans.info.type == DNSRecordType.srv.rawValue) &&
                       rdStart < pkt.data.count {
                        // Decompress domain in rdata.
                        let domOffset = ans.info.type == DNSRecordType.srv.rawValue ? 6 : 0
                        var domain = MDNSDomain()
                        let res = mdnsReadName(pkt.data, offset: rdStart + domOffset, domain: &domain)
                        if res != Int(MDNSConfig.readNameError) {
                            varpart = domain.dotted
                        }
                    } else if rdStart + rdLen <= pkt.data.count {
                        varpart = String(bytes: pkt.data[rdStart..<(rdStart + rdLen)],
                                         encoding: .utf8) ?? ""
                    }

                    callback(ans, varpart, rdLen, flags, req.arg)
                    isFirstSearchResult = false
                }
            }

            // --- Conflict detection ---
            // During probing/announce-wait, check for name conflicts.
            if host.state == .probing || host.state == .announceWait {
                let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
                if ans.info.domain.equals(hostDomain) {
                    handleProbeConflict(netif: netif, host: host, slot: 0)
                    return
                }

                for (i, service) in host.services.enumerated() {
                    guard let svc = service else { continue }
                    let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
                    if ans.info.domain.equals(svcDomain) {
                        handleProbeConflict(netif: netif, host: host, slot: Int8(i + 1))
                        return
                    }
                }
            }
            // During announcing/complete, check for conflict resolution (RFC 6762 section 9).
            else if host.state == .announcing || host.state == .complete {
                let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
                if ans.info.domain.equals(hostDomain) {
                    var conflict = true
                    if ans.info.type == DNSRecordType.a.rawValue {
                        if ans.rdLength == 4 {
                            let addrBytes = ipv4AddressBytes(netif.ipAddr)
                            let rdStart = Int(ans.rdOffset)
                            if rdStart + 4 <= pkt.data.count &&
                               Array(pkt.data[rdStart..<rdStart+4]) == addrBytes {
                                conflict = false
                            }
                        }
                    } else if ans.info.type == DNSRecordType.aaaa.rawValue {
                        if ans.rdLength == 16 {
                            let rdStart = Int(ans.rdOffset)
                            if rdStart + 16 <= pkt.data.count {
                                for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
                                    if netif.ipv6AddressStates[i].isValid {
                                        let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                                        if Array(pkt.data[rdStart..<rdStart+16]) == addrBytes {
                                            conflict = false
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if conflict {
                        handleProbeConflict(netif: netif, host: host, slot: 0)
                        return
                    }
                }

                // Also check service domains during conflict resolution.
                for (i, service) in host.services.enumerated() {
                    guard let svc = service else { continue }
                    let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
                    if ans.info.domain.equals(svcDomain) {
                        var svcConflict = true
                        // Check SRV rdata match.
                        if ans.info.type == DNSRecordType.srv.rawValue && ans.rdLength >= 6 {
                            let rdStart = Int(ans.rdOffset)
                            if rdStart + 6 <= pkt.data.count {
                                let priority = readU16(pkt.data, offset: rdStart)
                                let weight = readU16(pkt.data, offset: rdStart + 2)
                                let port = readU16(pkt.data, offset: rdStart + 4)
                                if priority == MDNSConfig.srvPriority &&
                                   weight == MDNSConfig.srvWeight &&
                                   port == svc.port {
                                    var srvDomain = MDNSDomain()
                                    let res = mdnsReadName(pkt.data, offset: rdStart + 6, domain: &srvDomain)
                                    let myHost = mdnsBuildHostDomain(hostname: host.hostname)
                                    if res != Int(MDNSConfig.readNameError) && srvDomain.equals(myHost) {
                                        svcConflict = false
                                    }
                                }
                            }
                        }
                        // Check TXT rdata match.
                        else if ans.info.type == DNSRecordType.txt.rawValue {
                            let txtData = svc.buildTxtData()
                            if Int(ans.rdLength) == txtData.count {
                                let rdStart = Int(ans.rdOffset)
                                if rdStart + txtData.count <= pkt.data.count &&
                                   Array(pkt.data[rdStart..<rdStart + txtData.count]) == txtData {
                                    svcConflict = false
                                }
                            }
                        }
                        if svcConflict {
                            // Reset to probing to reconfirm uniqueness.
                            restart(netif)
                            return
                        }
                    }
                }
            }
        }
    }

    /// Handle a probe conflict.
    private func handleProbeConflict(netif: NetworkInterface, host: MDNSHost, slot: Int8) {
        host.state = .off
        host.sentNum = 0

        // Inform the user of the conflict
        nameResultCallback?(netif, MDNSConfig.probingConflict, slot)
    }

    /// Handle an incoming mDNS question: determine what to reply.
    private func handleQuestion(pkt: inout MDNSInPacket, netif: NetworkInterface, host: MDNSHost) {
        // If still probing, handle probe tiebreaking but don't answer
        if host.state == .probing || host.state == .announceWait {
            // Check if this is a probe (questions > 0, answers == 0, authoritative > 0)
            if pkt.questions > 0 && pkt.answers == 0 && pkt.authoritative > 0 {
                handleProbeTiebreaking(pkt: &pkt, netif: netif, host: host)
            }
            return
        }

        // Only answer questions in COMPLETE or ANNOUNCING state
        guard host.state == .complete || host.state == .announcing else { return }

        var reply = MDNSOutMsg()
        var unicastRequested = false

        // Parse questions
        while pkt.questionsLeft > 0 {
            guard let question = readQuestion(&pkt) else { return }

            if question.unicast {
                unicastRequested = true
            }

            // Check if question matches our host records
            let hostResult = checkHostQuestion(netif: netif, host: host, rr: question.info)
            reply.hostReplies.formUnion(hostResult.replies)
            // If the hostname matched but no reply flags were set, the queried type
            // is not available at this name and we need an NSEC negative response
            // (only when a specific type was asked, not ANY).
            if hostResult.nameMatched && hostResult.replies.isEmpty &&
               question.info.type != DNSRecordType.any.rawValue {
                reply.hostNSEC = true
            }

            // Check if question matches our services
            for (i, service) in host.services.enumerated() {
                guard let svc = service else { continue }
                let svcResult = checkServiceQuestion(service: svc, rr: question.info)
                reply.servReplies[i].formUnion(svcResult.replies)
                // If the service instance name matched but no type-specific reply flags
                // were set, we need an NSEC for this service instance.
                if svcResult.instanceNameMatched && svcResult.replies.isEmpty &&
                   question.info.type != DNSRecordType.any.rawValue {
                    reply.servNSEC[i] = true
                }
            }
        }

        // Parse known answers (RFC 6762 Section 7.1): suppress records the
        // querier already knows about with sufficient remaining TTL.
        parseKnownAnswers(pkt: &pkt, netif: netif, host: host, reply: &reply)

        // Check if we have anything to send (including NSEC records)
        var anyReplies = !reply.hostReplies.isEmpty || reply.hostNSEC
        for i in 0..<reply.servReplies.count {
            if !reply.servReplies[i].isEmpty || reply.servNSEC[i] { anyReplies = true }
        }
        guard anyReplies else { return }

        // Build and send reply
        reply.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        reply.cacheFlush = (pkt.sourcePort == MDNSConfig.port)

        // Determine destination
        if unicastRequested || pkt.sourcePort != MDNSConfig.port {
            // Legacy query or unicast requested: reply to sender
            reply.destAddr = pkt.sourceAddr
            reply.destPort = pkt.sourcePort
            if pkt.sourcePort != MDNSConfig.port && pkt.questions == 1 {
                reply.legacyQuery = true
                reply.txId = pkt.txId
            }
        } else {
            reply.destAddr = MDNSConfig.ipv4MulticastAddr
            reply.destPort = MDNSConfig.port
        }

        buildAndSendReply(netif: netif, host: host, msg: reply)
    }

    /// Result of checking a host question: reply flags and whether the name matched.
    internal struct HostQuestionResult {
        var replies: ReplyFlags = []
        var nameMatched: Bool = false
    }

    /// Check what host replies a question demands.
    private func checkHostQuestion(netif: NetworkInterface, host: MDNSHost, rr: MDNSRRInfo) -> HostQuestionResult {
        var result = HostQuestionResult()

        guard rr.klass == MDNSConfig.dnsClassIN || rr.klass == MDNSConfig.dnsClassANY else {
            return result
        }

        // Check for hostname.local
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        if rr.domain.equals(hostDomain) {
            result.nameMatched = true
            if !netif.ipAddr.isAny &&
               (rr.type == DNSRecordType.a.rawValue || rr.type == DNSRecordType.any.rawValue) {
                result.replies.insert(.hostA)
            }
            if rr.type == DNSRecordType.aaaa.rawValue || rr.type == DNSRecordType.any.rawValue {
                for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
                    if netif.ipv6AddressStates[i].isValid {
                        result.replies.insert(.hostAAAA)
                        break
                    }
                }
            }
        }

        return result
    }

    /// Result of checking a service question: reply flags and whether the instance name matched.
    internal struct ServiceQuestionResult {
        var replies: ReplyFlags = []
        var instanceNameMatched: Bool = false
    }

    /// Check what service replies a question demands.
    private func checkServiceQuestion(service: MDNSService, rr: MDNSRRInfo) -> ServiceQuestionResult {
        var result = ServiceQuestionResult()

        guard rr.klass == MDNSConfig.dnsClassIN || rr.klass == MDNSConfig.dnsClassANY else {
            return result
        }

        // _services._dns-sd._udp.local?
        let dnssdDomain = mdnsBuildDnssdDomain()
        if rr.domain.equals(dnssdDomain) &&
           (rr.type == DNSRecordType.ptr.rawValue || rr.type == DNSRecordType.any.rawValue) {
            result.replies.insert(.serviceTypePTR)
        }

        // _type._proto.local?
        let typeDomain = mdnsBuildServiceDomain(service: service, includeName: false)
        if rr.domain.equals(typeDomain) &&
           (rr.type == DNSRecordType.ptr.rawValue || rr.type == DNSRecordType.any.rawValue) {
            result.replies.insert(.serviceNamePTR)
        }

        // name._type._proto.local?
        let instDomain = mdnsBuildServiceDomain(service: service, includeName: true)
        if rr.domain.equals(instDomain) {
            result.instanceNameMatched = true
            if rr.type == DNSRecordType.srv.rawValue || rr.type == DNSRecordType.any.rawValue {
                result.replies.insert(.serviceSRV)
            }
            if rr.type == DNSRecordType.txt.rawValue || rr.type == DNSRecordType.any.rawValue {
                result.replies.insert(.serviceTXT)
            }
        }

        return result
    }

    // MARK: - Known-Answer Suppression (RFC 6762 Section 7.1)

    /// Parse the Answer section of an incoming query and suppress records the
    /// querier already knows.
    ///
    /// Per RFC 6762 Section 7.1, when a querier includes a record in the Answer
    /// section of a query and the TTL is more than half the true TTL, the
    /// responder SHOULD NOT answer with that record.
    ///
    /// The cache-flush bit (top bit of the class field) in a known-answer record
    /// is masked off before comparison so that it does not prevent a match.
    ///
    /// - Parameters:
    ///   - pkt: The incoming packet (parseOffset should be past the question section).
    ///   - netif: The network interface this packet arrived on.
    ///   - host: The local mDNS host state.
    ///   - reply: The reply message whose flags will be cleared for suppressed records.
    private func parseKnownAnswers(
        pkt: inout MDNSInPacket,
        netif: NetworkInterface,
        host: MDNSHost,
        reply: inout MDNSOutMsg
    ) {
        var answersLeft = pkt.answersLeft
        while answersLeft > 0 {
            guard let ans = readAnswer(&pkt, numLeft: &answersLeft) else {
                pkt.answersLeft = answersLeft
                return
            }

            // Skip known answers with type ANY or class ANY (RFC 6762 Section 7.1)
            if ans.info.type == DNSRecordType.any.rawValue ||
               ans.info.klass == MDNSConfig.dnsClassANY {
                continue
            }

            // --- Host record suppression ---
            let hostMatch = checkHostQuestion(netif: netif, host: host, rr: ans.info)
            let matchedHostFlags = reply.hostReplies.intersection(hostMatch.replies)

            if !matchedHostFlags.isEmpty && ans.ttl > (MDNSConfig.hostTTL / 2) {
                // The known answer matches a host record we planned to send and
                // the TTL is more than half remaining. Verify the rdata payload.

                if ans.info.type == DNSRecordType.ptr.rawValue {
                    // PTR rdata is a domain name -- read and compare to our hostname.
                    var knownDomain = MDNSDomain()
                    let len = mdnsReadName(pkt.data, offset: Int(ans.rdOffset), domain: &knownDomain)
                    let myDomain = mdnsBuildHostDomain(hostname: host.hostname)
                    if len != Int(MDNSConfig.readNameError) && knownDomain.equals(myDomain) {
                        if matchedHostFlags.contains(.hostPtrV4) {
                            reply.hostReplies.remove(.hostPtrV4)
                        }
                        if matchedHostFlags.contains(.hostPtrV6) {
                            reply.hostReplies.remove(.hostPtrV6)
                        }
                    }
                } else if matchedHostFlags.contains(.hostA) {
                    // A record rdata is a 4-byte IPv4 address.
                    if ans.rdLength == 4 {
                        let rdStart = Int(ans.rdOffset)
                        guard rdStart + 4 <= pkt.data.count else { continue }
                        let myAddr = ipv4AddressBytes(netif.ipAddr)
                        if pkt.data[rdStart..<(rdStart + 4)].elementsEqual(myAddr) {
                            reply.hostReplies.remove(.hostA)
                        }
                    }
                } else if matchedHostFlags.contains(.hostAAAA) {
                    // AAAA record rdata is a 16-byte IPv6 address.
                    // Suppress the specific address that matches.
                    if ans.rdLength == 16 {
                        let rdStart = Int(ans.rdOffset)
                        guard rdStart + 16 <= pkt.data.count else { continue }
                        let knownAddr = Array(pkt.data[rdStart..<(rdStart + 16)])
                        var anyV6Left = false
                        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
                            if netif.ipv6AddressStates[i].isValid {
                                let myAddr = ipv6AddressBytes(netif.ipv6Address(at: i))
                                if knownAddr.elementsEqual(myAddr) {
                                    // This specific IPv6 address is known; we still
                                    // keep the AAAA flag if other addresses remain
                                    // unsuppressed, but we cannot track per-address
                                    // suppression with a single flag. For correctness
                                    // when there is only one valid IPv6 address, clear it.
                                    continue
                                }
                                anyV6Left = true
                            }
                        }
                        if !anyV6Left {
                            reply.hostReplies.remove(.hostAAAA)
                        }
                    }
                }
            }

            // --- Service record suppression ---
            for (i, service) in host.services.enumerated() {
                guard let svc = service else { continue }
                let svcMatch = checkServiceQuestion(service: svc, rr: ans.info)
                let matchedSvcFlags = reply.servReplies[i].intersection(svcMatch.replies)

                // Determine the TTL threshold: service-type PTR uses serviceTTL,
                // all other service records use hostTTL.
                var rrTTL = MDNSConfig.hostTTL
                if matchedSvcFlags.contains(.serviceTypePTR) {
                    rrTTL = MDNSConfig.serviceTTL
                }

                guard !matchedSvcFlags.isEmpty && ans.ttl > (rrTTL / 2) else { continue }

                if ans.info.type == DNSRecordType.ptr.rawValue {
                    // PTR rdata is a domain name.
                    var knownDomain = MDNSDomain()
                    let len = mdnsReadName(pkt.data, offset: Int(ans.rdOffset), domain: &knownDomain)
                    guard len != Int(MDNSConfig.readNameError) else { continue }

                    if matchedSvcFlags.contains(.serviceTypePTR) {
                        let myDomain = mdnsBuildServiceDomain(service: svc, includeName: false)
                        if knownDomain.equals(myDomain) {
                            reply.servReplies[i].remove(.serviceTypePTR)
                        }
                    }
                    if matchedSvcFlags.contains(.serviceNamePTR) {
                        let myDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
                        if knownDomain.equals(myDomain) {
                            reply.servReplies[i].remove(.serviceNamePTR)
                        }
                    }
                } else if matchedSvcFlags.contains(.serviceSRV) {
                    // SRV rdata: priority (2) + weight (2) + port (2) + target domain.
                    let rdStart = Int(ans.rdOffset)
                    guard rdStart + 6 <= pkt.data.count else { continue }

                    let priority = readU16(pkt.data, offset: rdStart)
                    let weight = readU16(pkt.data, offset: rdStart + 2)
                    let port = readU16(pkt.data, offset: rdStart + 4)

                    guard priority == MDNSConfig.srvPriority &&
                          weight == MDNSConfig.srvWeight &&
                          port == svc.port else { continue }

                    var knownTarget = MDNSDomain()
                    let tlen = mdnsReadName(pkt.data, offset: rdStart + 6, domain: &knownTarget)
                    guard tlen != Int(MDNSConfig.readNameError) else { continue }

                    let myTarget = mdnsBuildHostDomain(hostname: host.hostname)
                    if knownTarget.equals(myTarget) {
                        reply.servReplies[i].remove(.serviceSRV)
                    }
                } else if matchedSvcFlags.contains(.serviceTXT) {
                    // TXT rdata: length-prefixed strings.
                    let rdStart = Int(ans.rdOffset)
                    let rdLen = Int(ans.rdLength)
                    guard rdStart + rdLen <= pkt.data.count else { continue }

                    let myTxt = svc.buildTxtData()
                    if rdLen == myTxt.count &&
                       pkt.data[rdStart..<(rdStart + rdLen)].elementsEqual(myTxt) {
                        reply.servReplies[i].remove(.serviceTXT)
                    }
                }
            }
        }
        pkt.answersLeft = answersLeft
    }

    /// Build and send a reply based on the collected reply flags.
    /// Handles NSEC negative responses and large response fragmentation.
    private func buildAndSendReply(netif: NetworkInterface, host: MDNSHost, msg: MDNSOutMsg) {
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        let ttl = msg.legacyQuery ? UInt32(10) : MDNSConfig.hostTTL
        let maxPacketSize = mdnsMaxPacketSize(netif: netif)

        // Collect all records to write, then fragment across packets if needed.
        var records: [MDNSRecordEntry] = []

        // Host replies
        if msg.hostReplies.contains(.hostA) && !netif.ipAddr.isAny {
            let addrBytes = ipv4AddressBytes(netif.ipAddr)
            records.append(MDNSRecordEntry(
                domain: hostDomain, type: DNSRecordType.a.rawValue,
                klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                ttl: ttl, rdata: addrBytes, answerDomain: nil, section: .answer))
        }

        if msg.hostReplies.contains(.hostAAAA) {
            for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
                if netif.ipv6AddressStates[i].isValid {
                    let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                    records.append(MDNSRecordEntry(
                        domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                        klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                        ttl: ttl, rdata: addrBytes, answerDomain: nil, section: .answer))
                }
            }
        }

        // NSEC for host: name existed but queried type was not available
        if msg.hostNSEC {
            let nsecRdata = buildHostNSECData(netif: netif, hostDomain: hostDomain)
            records.append(MDNSRecordEntry(
                domain: hostDomain, type: DNSRecordType.nsec.rawValue,
                klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                ttl: ttl, rdata: nsecRdata.rdata, answerDomain: nil,
                section: .authoritative))
        }

        // Service replies
        let dnssdDomain = mdnsBuildDnssdDomain()

        for (i, service) in host.services.enumerated() {
            guard let svc = service else { continue }
            let svcFlags = msg.servReplies[i]
            let needsNSEC = msg.servNSEC[i]
            guard !svcFlags.isEmpty || needsNSEC else { continue }

            let typeDomain = mdnsBuildServiceDomain(service: svc, includeName: false)
            let instDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
            let svcTTL = msg.legacyQuery ? UInt32(10) : MDNSConfig.serviceTTL

            if svcFlags.contains(.serviceTypePTR) {
                records.append(MDNSRecordEntry(
                    domain: dnssdDomain, type: DNSRecordType.ptr.rawValue,
                    klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                    ttl: svcTTL, rdata: nil, answerDomain: typeDomain, section: .answer))
            }

            if svcFlags.contains(.serviceNamePTR) {
                records.append(MDNSRecordEntry(
                    domain: typeDomain, type: DNSRecordType.ptr.rawValue,
                    klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                    ttl: ttl, rdata: nil, answerDomain: instDomain, section: .answer))
            }

            if svcFlags.contains(.serviceSRV) {
                let srvData = buildSRVData(service: svc)
                let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
                records.append(MDNSRecordEntry(
                    domain: instDomain, type: DNSRecordType.srv.rawValue,
                    klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                    ttl: ttl, rdata: srvData, answerDomain: srvHost, section: .answer))
            }

            if svcFlags.contains(.serviceTXT) {
                let txtData = svc.buildTxtData()
                records.append(MDNSRecordEntry(
                    domain: instDomain, type: DNSRecordType.txt.rawValue,
                    klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                    ttl: ttl, rdata: txtData, answerDomain: nil, section: .answer))
            }

            // NSEC for service instance: name existed but queried type was not available
            if needsNSEC {
                let nsecRdata = buildServiceInstanceNSECData(instDomain: instDomain)
                records.append(MDNSRecordEntry(
                    domain: instDomain, type: DNSRecordType.nsec.rawValue,
                    klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                    ttl: ttl, rdata: nsecRdata.rdata, answerDomain: nil,
                    section: .authoritative))
            }

            // Additional records: if SRV or name PTR was requested, add A/AAAA as additional
            if svcFlags.contains(.serviceNamePTR) || svcFlags.contains(.serviceSRV) {
                if !msg.hostReplies.contains(.hostA) && !netif.ipAddr.isAny {
                    let addrBytes = ipv4AddressBytes(netif.ipAddr)
                    records.append(MDNSRecordEntry(
                        domain: hostDomain, type: DNSRecordType.a.rawValue,
                        klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                        ttl: ttl, rdata: addrBytes, answerDomain: nil, section: .additional))
                }

                if !msg.hostReplies.contains(.hostAAAA) {
                    for j in 0..<NetworkInterfaceConstants.ipv6AddressCount {
                        if netif.ipv6AddressStates[j].isValid {
                            let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: j))
                            records.append(MDNSRecordEntry(
                                domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                                klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                                ttl: ttl, rdata: addrBytes, answerDomain: nil, section: .additional))
                        }
                    }
                }

                // Also add SRV and TXT as additional if not already present
                if !svcFlags.contains(.serviceSRV) {
                    let srvData = buildSRVData(service: svc)
                    let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
                    records.append(MDNSRecordEntry(
                        domain: instDomain, type: DNSRecordType.srv.rawValue,
                        klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                        ttl: ttl, rdata: srvData, answerDomain: srvHost, section: .additional))
                }

                if !svcFlags.contains(.serviceTXT) {
                    let txtData = svc.buildTxtData()
                    records.append(MDNSRecordEntry(
                        domain: instDomain, type: DNSRecordType.txt.rawValue,
                        klass: MDNSConfig.dnsClassIN, cacheFlush: msg.cacheFlush,
                        ttl: ttl, rdata: txtData, answerDomain: nil, section: .additional))
                }
            }
        }

        // Fragment records across multiple packets if needed (RFC 6762 Section 17)
        sendFragmentedReply(records: records, msg: msg, maxPacketSize: maxPacketSize,
                            destAddr: msg.destAddr, destPort: msg.destPort, via: netif)
    }

    // MARK: - Probe Tiebreaking (RFC 6762 Section 8.2)

    /// Perform lexicographic comparison of two answer records.
    ///
    /// Compares class, type, then rdata byte-by-byte. For SRV records the
    /// rdata comparison decompresses the target domain name before comparing.
    ///
    /// - Parameters:
    ///   - pktA: Packet data containing answer A's rdata.
    ///   - ansA: The first answer record.
    ///   - pktB: Packet data containing answer B's rdata.
    ///   - ansB: The second answer record.
    /// - Returns: The lexicographic ordering, or `nil` if decompression failed.
    internal func mdnsLexicographicalComparison(
        pktA: [UInt8], ansA: MDNSAnswer,
        pktB: [UInt8], ansB: MDNSAnswer
    ) -> LexicographicalResult? {
        // Compare classes.
        if ansA.info.klass != ansB.info.klass {
            return ansA.info.klass > ansB.info.klass ? .later : .earlier
        }

        // Compare types.
        if ansA.info.type != ansB.info.type {
            return ansA.info.type > ansB.info.type ? .later : .earlier
        }

        // Compare rdata. SRV records need special handling because the target
        // hostname in the rdata may be compressed.
        if ansA.info.type == DNSRecordType.srv.rawValue {
            // Compare the first 6 bytes (priority + weight + port) directly.
            let srvFixedLen = 6
            let aStart = Int(ansA.rdOffset)
            let bStart = Int(ansB.rdOffset)
            for i in 0..<srvFixedLen {
                guard aStart + i < pktA.count && bStart + i < pktB.count else {
                    return nil
                }
                let ab = pktA[aStart + i]
                let bb = pktB[bStart + i]
                if ab != bb {
                    return ab > bb ? .later : .earlier
                }
            }
            // Decompress the target domain names and compare.
            var domainA = MDNSDomain()
            var domainB = MDNSDomain()
            let resA = mdnsReadName(pktA, offset: aStart + srvFixedLen, domain: &domainA)
            guard resA != Int(MDNSConfig.readNameError) else { return nil }
            let resB = mdnsReadName(pktB, offset: bStart + srvFixedLen, domain: &domainB)
            guard resB != Int(MDNSConfig.readNameError) else { return nil }

            let len = min(Int(domainA.length), Int(domainB.length))
            for i in 0..<len {
                if domainA.name[i] != domainB.name[i] {
                    return domainA.name[i] > domainB.name[i] ? .later : .earlier
                }
            }
            if domainA.length != domainB.length {
                return domainA.length > domainB.length ? .later : .earlier
            }
        } else {
            // Generic byte-by-byte comparison of rdata.
            let aStart = Int(ansA.rdOffset)
            let bStart = Int(ansB.rdOffset)
            let len = min(Int(ansA.rdLength), Int(ansB.rdLength))
            for i in 0..<len {
                guard aStart + i < pktA.count && bStart + i < pktB.count else {
                    return nil
                }
                let ab = pktA[aStart + i]
                let bb = pktB[bStart + i]
                if ab != bb {
                    return ab > bb ? .later : .earlier
                }
            }
            if ansA.rdLength != ansB.rdLength {
                return ansA.rdLength > ansB.rdLength ? .later : .earlier
            }
        }

        return .equal
    }

    /// Handle probe tiebreaking per RFC 6762 Section 8.2.
    ///
    /// When we are probing and receive a probe from another host for the same
    /// name, we must compare the authority sections lexicographically.
    /// - If our records are lexicographically later, we win and continue.
    /// - If our records are earlier, we lose and must defer (restart with 1s delay).
    /// - If equal, no conflict; continue probing.
    private func handleProbeTiebreaking(pkt: inout MDNSInPacket, netif: NetworkInterface, host: MDNSHost) {
        // Generate our own probe packet for comparison.
        let myProbeData = buildProbePacketData(netif: netif, host: host)
        var myPkt = MDNSInPacket()
        myPkt.data = myProbeData
        myPkt.parseOffset = MDNSConfig.dnsHeaderSize
        myPkt.questions = readU16(myProbeData, offset: 4)
        myPkt.questionsLeft = myPkt.questions
        myPkt.answers = readU16(myProbeData, offset: 6)
        myPkt.answersLeft = myPkt.answers
        myPkt.authoritative = readU16(myProbeData, offset: 8)
        myPkt.authoritativeLeft = myPkt.authoritative
        myPkt.additional = readU16(myProbeData, offset: 10)
        myPkt.additionalLeft = myPkt.additional

        // Save initial parse state so we can iterate over multiple probes.
        let pktOrigParseOffset = pkt.parseOffset
        let pktOrigQuestionsLeft = pkt.questionsLeft

        // For each of our probe questions, see if the incoming packet has a
        // matching question.  When a match is found, compare the authority
        // sections to decide the tiebreaker.
        while myPkt.questionsLeft > 0 {
            guard let myQuestion = readQuestion(&myPkt) else { return }

            // Save state for the search.
            let myParseAfterQ = myPkt.parseOffset
            let myQLAfterQ = myPkt.questionsLeft

            // Reset incoming packet to scan its questions.
            pkt.parseOffset = pktOrigParseOffset
            pkt.questionsLeft = pktOrigQuestionsLeft

            var matched = false
            while pkt.questionsLeft > 0 {
                guard let pktQ = readQuestion(&pkt) else { return }
                // We probe for type ANY so we only compare domains.
                if pktQ.info.domain.equals(myQuestion.info.domain) {
                    matched = true
                    break
                }
            }

            guard matched else {
                // No match for this question; try our next question.
                myPkt.parseOffset = myParseAfterQ
                myPkt.questionsLeft = myQLAfterQ
                continue
            }

            // Skip remaining questions in both packets so we can read the authority sections.
            while pkt.questionsLeft > 0 {
                guard skipQuestion(&pkt) else { return }
            }
            while myPkt.questionsLeft > 0 {
                guard skipQuestion(&myPkt) else { return }
            }

            // Collect and sort authoritative answers that answer the matched question.
            let myAnswers = collectSortedAuthorityAnswers(
                pkt: &myPkt, question: myQuestion, data: myProbeData
            )
            let pktAnswers = collectSortedAuthorityAnswers(
                pkt: &pkt, question: myQuestion, data: pkt.data
            )

            // Pairwise lexicographic comparison.
            let minCount = min(myAnswers.count, pktAnswers.count)
            for i in 0..<minCount {
                guard let result = mdnsLexicographicalComparison(
                    pktA: myProbeData, ansA: myAnswers[i],
                    pktB: pkt.data, ansB: pktAnswers[i]
                ) else { return }

                switch result {
                case .later:
                    // We win the tiebreak -- ignore the incoming probe.
                    return
                case .earlier:
                    // We lose the tiebreak -- restart probing after 1s delay.
                    restartDelay(netif, delay: MDNSConfig.probeTiebreakConflictDelayMs)
                    return
                case .equal:
                    continue
                }
            }

            // All compared records were equal; check if one side has more.
            if myAnswers.count != pktAnswers.count {
                if myAnswers.count > pktAnswers.count {
                    return // We win (more records).
                } else {
                    restartDelay(netif, delay: MDNSConfig.probeTiebreakConflictDelayMs)
                    return
                }
            }

            // No conflict on this probe question; restore state for next iteration.
            myPkt.parseOffset = myParseAfterQ
            myPkt.questionsLeft = myQLAfterQ
            pkt.parseOffset = pktOrigParseOffset
            pkt.questionsLeft = pktOrigQuestionsLeft
            pkt.authoritativeLeft = pkt.authoritative
            myPkt.authoritativeLeft = myPkt.authoritative
        }
    }

    /// Build the raw bytes of our probe packet for tiebreaking comparison.
    /// This mirrors what `sendProbe` writes, but returns the raw buffer instead
    /// of sending it.
    private func buildProbePacketData(netif: NetworkInterface, host: MDNSHost) -> [UInt8] {
        var outpkt = MDNSOutPacket()

        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        mdnsAddQuestion(&outpkt, domain: hostDomain, type: DNSRecordType.any.rawValue,
                        klass: MDNSConfig.dnsClassIN, unicast: true)
        outpkt.questions += 1

        for service in host.services {
            guard let svc = service else { continue }
            let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
            mdnsAddQuestion(&outpkt, domain: svcDomain, type: DNSRecordType.any.rawValue,
                            klass: MDNSConfig.dnsClassIN, unicast: true)
            outpkt.questions += 1
        }

        if !netif.ipAddr.isAny {
            let addrBytes = ipv4AddressBytes(netif.ipAddr)
            mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
            outpkt.authoritative += 1
        }

        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if netif.ipv6AddressStates[i].isValid {
                let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                              klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                              ttl: MDNSConfig.hostTTL, rdata: addrBytes, answerDomain: nil)
                outpkt.authoritative += 1
            }
        }

        for service in host.services {
            guard let svc = service else { continue }
            let svcDomain = mdnsBuildServiceDomain(service: svc, includeName: true)
            let srvData = buildSRVData(service: svc)
            let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
            mdnsAddAnswer(&outpkt, domain: svcDomain, type: DNSRecordType.srv.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                          ttl: MDNSConfig.hostTTL, rdata: srvData, answerDomain: srvHost)
            outpkt.authoritative += 1
        }

        var msg = MDNSOutMsg()
        msg.flags = 0
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        return Array(outpkt.buffer[0..<outpkt.writeOffset])
    }

    /// Collect authoritative answers from a packet that answer the given question,
    /// sorted lexicographically from smallest to largest.
    private func collectSortedAuthorityAnswers(
        pkt: inout MDNSInPacket,
        question: MDNSQuestion,
        data: [UInt8]
    ) -> [MDNSAnswer] {
        var answers: [MDNSAnswer] = []
        var authLeft = pkt.authoritativeLeft

        while authLeft > 0 {
            guard let ans = readAnswer(&pkt, numLeft: &authLeft) else { break }

            // Check if this answer matches the question.
            let typeMatch = (question.info.type == DNSRecordType.any.rawValue ||
                             question.info.type == ans.info.type)
            guard typeMatch && question.info.domain.equals(ans.info.domain) else { continue }

            // Insertion sort: keep the list sorted from smallest to largest.
            var insertIdx = answers.count
            for (idx, existing) in answers.enumerated() {
                if let cmp = mdnsLexicographicalComparison(
                    pktA: data, ansA: ans,
                    pktB: data, ansB: existing
                ), cmp == .earlier {
                    insertIdx = idx
                    break
                }
            }
            answers.insert(ans, at: insertIdx)

            if answers.count > MDNSConfig.probeTiebreakMaxAnswers {
                answers.removeLast()
            }
        }

        pkt.authoritativeLeft = authLeft
        return answers
    }

    // MARK: - NSEC Record Writing (RFC 6762 Section 6.1)

    /// Write an NSEC resource record into an output packet.
    ///
    /// Per RFC 6762, NSEC records are used as negative responses to indicate
    /// which record types exist for a given name.  The "Next Domain Name" in
    /// mDNS is always the owner name itself (there is no zone ordering).
    ///
    /// - Parameters:
    ///   - outpkt: The output packet to write into.
    ///   - name: The domain name this NSEC covers.
    ///   - types: The DNS record types that exist for `name`.
    ///   - cacheFlush: Whether to set the cache-flush bit.
    ///   - ttl: Time-to-live value.
    ///   - section: Which DNS section the record belongs to.
    internal func writeNSECRecord(
        outpkt: inout MDNSOutPacket,
        name: MDNSDomain,
        types: [UInt16],
        cacheFlush: Bool,
        ttl: UInt32,
        section: RecordSection
    ) {
        let bitmap = buildNSECTypeBitmap(types: types)
        var rdata = domainToWireBytes(name)
        rdata.append(contentsOf: bitmap)

        mdnsAddAnswer(&outpkt, domain: name, type: DNSRecordType.nsec.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: cacheFlush,
                      ttl: ttl, rdata: rdata, answerDomain: nil)

        switch section {
        case .answer:       outpkt.answers += 1
        case .authoritative: outpkt.authoritative += 1
        case .additional:   outpkt.additional += 1
        }
    }

    // MARK: - Domain Name Compression (RFC 1035 Section 4.1.4)

    /// Write a domain name with compression into an output packet.
    ///
    /// Checks if a suffix of `name` already appears earlier in the packet
    /// (tracked via `outpkt.domainOffsets`). If so, writes only the unique
    /// prefix labels followed by a 2-byte compression pointer instead of
    /// repeating the full name.
    ///
    /// This is a convenience wrapper around `mdnsWriteDomain` that makes the
    /// compression behaviour explicit. The underlying implementation already
    /// performs compression via `mdnsCompressDomain`.
    ///
    /// - Parameters:
    ///   - name: The domain name to write.
    ///   - outpkt: The output packet to write into.
    /// - Returns: The offset at which the name was written (for potential
    ///   future back-references), or -1 if the write failed.
    @discardableResult
    internal func writeDomainCompressed(
        name: MDNSDomain,
        into outpkt: inout MDNSOutPacket
    ) -> Int {
        let startOffset = outpkt.writeOffset
        mdnsWriteDomain(&outpkt, domain: name)
        return outpkt.writeOffset > startOffset ? startOffset : -1
    }

    // MARK: - Packet Reading Helpers

    /// Read a question from the packet, advancing parseOffset.
    private func readQuestion(_ pkt: inout MDNSInPacket) -> MDNSQuestion? {
        guard pkt.questionsLeft > 0 else { return nil }
        guard pkt.parseOffset < pkt.data.count else { return nil }

        pkt.questionsLeft -= 1

        // Read domain name
        var domain = MDNSDomain()
        let newOffset = mdnsReadName(pkt.data, offset: pkt.parseOffset, domain: &domain)
        guard newOffset != Int(MDNSConfig.readNameError) else { return nil }
        pkt.parseOffset = newOffset

        // Read type (2 bytes)
        guard pkt.parseOffset + 4 <= pkt.data.count else { return nil }
        let qtype = readU16(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 2

        // Read class (2 bytes)
        let qclass = readU16(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 2

        var question = MDNSQuestion()
        question.info.domain = domain
        question.info.type = qtype
        question.info.klass = qclass & 0x7FFF
        question.unicast = (qclass & 0x8000) != 0

        return question
    }

    /// Skip a question in the packet without fully parsing.
    private func skipQuestion(_ pkt: inout MDNSInPacket) -> Bool {
        guard pkt.questionsLeft > 0 else { return false }
        pkt.questionsLeft -= 1

        var domain = MDNSDomain()
        let newOffset = mdnsReadName(pkt.data, offset: pkt.parseOffset, domain: &domain)
        guard newOffset != Int(MDNSConfig.readNameError) else { return false }
        pkt.parseOffset = newOffset

        // Skip type + class (4 bytes)
        guard pkt.parseOffset + 4 <= pkt.data.count else { return false }
        pkt.parseOffset += 4
        return true
    }

    /// Read an answer from the packet, advancing parseOffset.
    /// The numLeft counter is decremented. It can represent answers, authoritative, or additional.
    private func readAnswer(_ pkt: inout MDNSInPacket, numLeft: inout UInt16) -> MDNSAnswer? {
        guard numLeft > 0 else { return nil }
        guard pkt.parseOffset < pkt.data.count else { return nil }

        numLeft -= 1

        // Read domain name
        var domain = MDNSDomain()
        let newOffset = mdnsReadName(pkt.data, offset: pkt.parseOffset, domain: &domain)
        guard newOffset != Int(MDNSConfig.readNameError) else { return nil }
        pkt.parseOffset = newOffset

        // Read type + class + TTL + rdlength (10 bytes)
        guard pkt.parseOffset + 10 <= pkt.data.count else { return nil }
        let atype = readU16(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 2
        let aclass = readU16(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 2
        let attl = readU32(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 4
        let rdlength = readU16(pkt.data, offset: pkt.parseOffset)
        pkt.parseOffset += 2

        var answer = MDNSAnswer()
        answer.info.domain = domain
        answer.info.type = atype
        answer.info.klass = aclass & 0x7FFF
        answer.cacheFlush = aclass & 0x8000
        answer.ttl = attl
        answer.rdLength = rdlength
        answer.rdOffset = UInt16(pkt.parseOffset)

        // Skip rdata
        pkt.parseOffset += Int(rdlength)

        return answer
    }

    // MARK: - Packet Sending

    /// Send an outgoing packet via UDP.
    private func sendPacket(_ outpkt: MDNSOutPacket, to dest: IPAddress, port: UInt16, via netif: NetworkInterface) {
        guard let pcb = self.udpControlBlock else { return }
        guard outpkt.writeOffset > MDNSConfig.dnsHeaderSize else { return }

        // Create a Pbuf with the packet data
        let dataLen = UInt16(min(outpkt.writeOffset, outpkt.buffer.count))
        guard let pbuf = Pbuf.alloc(layer: .transport, length: dataLen, type: .ram) else { return }

        // Copy data into pbuf
        pbuf.payload.withMemoryRebound(to: UInt8.self, capacity: Int(dataLen)) { ptr in
            for i in 0..<Int(dataLen) {
                ptr[i] = outpkt.buffer[i]
            }
        }

        // Determine source IP
        let srcIP: IPAddress
        if let localAddr = IPDispatch.netifGetLocalIP(netif, dest: dest) {
            srcIP = localAddr
        } else if !netif.ipAddr.isAny {
            srcIP = .v4(netif.ipAddr)
        } else {
            srcIP = .any
        }

        UDPGlobal.shared.sendToIf(pcb, pbuf: pbuf, dstIP: dest, dstPort: port,
                                   netif: netif, srcIP: srcIP)
    }

    // MARK: - Helper Functions

    /// Build SRV rdata: priority (2 bytes) + weight (2 bytes) + port (2 bytes).
    /// The target hostname is added separately as an answer domain.
    private func buildSRVData(service: MDNSService) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: 6)
        writeU16(&data, offset: 0, value: MDNSConfig.srvPriority)
        writeU16(&data, offset: 2, value: MDNSConfig.srvWeight)
        writeU16(&data, offset: 4, value: service.port)
        return data
    }

    /// Get the 4-byte wire representation of an IPv4 address.
    private func ipv4AddressBytes(_ addr: IPv4Address) -> [UInt8] {
        // addr.addr is in network byte order
        return [
            addr.byte(at: 0),
            addr.byte(at: 1),
            addr.byte(at: 2),
            addr.byte(at: 3)
        ]
    }

    /// Overload for IPAddress (extracts IPv4).
    private func ipv4AddressBytes(_ addr: IPAddress) -> [UInt8] {
        if case .v4(let v4) = addr {
            return ipv4AddressBytes(v4)
        }
        return [0, 0, 0, 0]
    }

    /// Get the 16-byte wire representation of an IPv6 address.
    private func ipv6AddressBytes(_ addr: IPv6Address) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 16)
        // Each word is in network byte order already
        let words = [addr.addr.0, addr.addr.1, addr.addr.2, addr.addr.3]
        for w in 0..<4 {
            let word = words[w]
            bytes[w * 4]     = UInt8((word)       & 0xFF)
            bytes[w * 4 + 1] = UInt8((word >> 8)  & 0xFF)
            bytes[w * 4 + 2] = UInt8((word >> 16) & 0xFF)
            bytes[w * 4 + 3] = UInt8((word >> 24) & 0xFF)
        }
        return bytes
    }

    // MARK: - Goodbye Messages (RFC 6762 Section 10.1)

    /// Send goodbye messages (TTL=0) for all records on a network interface.
    /// Per RFC 6762 Section 10.1, when a host is shutting down, its interface goes down,
    /// or a DHCP lease expires, the responder sends records with TTL=0 so other hosts
    /// flush them from their caches.
    public func sendGoodbye(for netif: NetworkInterface) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        lock.unlock()

        var outpkt = MDNSOutPacket()
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)

        // Goodbye A record
        if !netif.ipAddr.isAny {
            let addrBytes = ipv4AddressBytes(netif.ipAddr)
            mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                          klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                          ttl: MDNSConfig.goodbyeTTL, rdata: addrBytes, answerDomain: nil)
            outpkt.answers += 1
        }

        // Goodbye AAAA records
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if netif.ipv6AddressStates[i].isValid {
                let addrBytes = ipv6AddressBytes(netif.ipv6Address(at: i))
                mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                              klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                              ttl: MDNSConfig.goodbyeTTL, rdata: addrBytes, answerDomain: nil)
                outpkt.answers += 1
            }
        }

        // Goodbye service records
        let dnssdDomain = mdnsBuildDnssdDomain()
        for service in host.services {
            guard let svc = service else { continue }
            addServiceGoodbyeRecords(&outpkt, host: host, service: svc, dnssdDomain: dnssdDomain,
                                     hostDomain: hostDomain)
        }

        guard outpkt.answers > 0 else { return }

        // Write header: response with AA flag
        var msg = MDNSOutMsg()
        msg.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)

        // Reset state machine so no further announcements are sent.
        lock.lock()
        host.state = .off
        host.sentNum = 0
        lock.unlock()
    }

    /// Send a goodbye for a single service being unregistered.
    private func sendServiceGoodbye(for netif: NetworkInterface, host: MDNSHost, service: MDNSService) {
        var outpkt = MDNSOutPacket()
        let dnssdDomain = mdnsBuildDnssdDomain()
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)

        addServiceGoodbyeRecords(&outpkt, host: host, service: service,
                                 dnssdDomain: dnssdDomain, hostDomain: hostDomain)

        guard outpkt.answers > 0 else { return }

        var msg = MDNSOutMsg()
        msg.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)
    }

    /// Send goodbye for a specific IPv4 address that has changed or been removed.
    /// Called when a DHCP lease changes or an address is removed from an interface.
    public func sendAddressGoodbye(for netif: NetworkInterface, oldIPv4: IPv4Address) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        guard !host.probing && host.state != .off else { lock.unlock(); return }
        lock.unlock()

        var outpkt = MDNSOutPacket()
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        let addrBytes = ipv4AddressBytes(oldIPv4)

        mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.a.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                      ttl: MDNSConfig.goodbyeTTL, rdata: addrBytes, answerDomain: nil)
        outpkt.answers += 1

        var msg = MDNSOutMsg()
        msg.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)
    }

    /// Send goodbye for a specific IPv6 address that has changed or been removed.
    public func sendIPv6AddressGoodbye(for netif: NetworkInterface, oldIPv6: IPv6Address) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        guard !host.probing && host.state != .off else { lock.unlock(); return }
        lock.unlock()

        var outpkt = MDNSOutPacket()
        let hostDomain = mdnsBuildHostDomain(hostname: host.hostname)
        let addrBytes = ipv6AddressBytes(oldIPv6)

        mdnsAddAnswer(&outpkt, domain: hostDomain, type: DNSRecordType.aaaa.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                      ttl: MDNSConfig.goodbyeTTL, rdata: addrBytes, answerDomain: nil)
        outpkt.answers += 1

        var msg = MDNSOutMsg()
        msg.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        msg.txId = 0
        mdnsWriteHeader(&outpkt, msg: msg)

        sendPacket(outpkt, to: MDNSConfig.ipv4MulticastAddr, port: MDNSConfig.port, via: netif)
    }

    /// Notify the responder that an interface has gone down.
    /// Sends goodbye messages and stops the state machine.
    public func notifyInterfaceDown(_ netif: NetworkInterface) {
        lock.lock()
        let key = ObjectIdentifier(netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        let shouldGoodbye = !host.probing && host.state != .off
        lock.unlock()

        if shouldGoodbye {
            sendGoodbye(for: netif)
        } else {
            // Just stop the state machine without sending goodbye
            lock.lock()
            host.state = .off
            host.sentNum = 0
            lock.unlock()
        }
    }

    /// Notify the responder that a DHCP lease has expired.
    /// Equivalent to interface down from an mDNS perspective.
    public func notifyDHCPLeaseExpired(_ netif: NetworkInterface) {
        notifyInterfaceDown(netif)
    }

    /// Add goodbye records (TTL=0) for a single service to an output packet.
    private func addServiceGoodbyeRecords(
        _ outpkt: inout MDNSOutPacket,
        host: MDNSHost,
        service: MDNSService,
        dnssdDomain: MDNSDomain,
        hostDomain: MDNSDomain
    ) {
        let serviceTypeDomain = mdnsBuildServiceDomain(service: service, includeName: false)
        let serviceInstanceDomain = mdnsBuildServiceDomain(service: service, includeName: true)

        // PTR: _services._dns-sd._udp.local -> _type._proto.local (TTL=0)
        mdnsAddAnswer(&outpkt, domain: dnssdDomain, type: DNSRecordType.ptr.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                      ttl: MDNSConfig.goodbyeTTL, rdata: nil, answerDomain: serviceTypeDomain)
        outpkt.answers += 1

        // PTR: _type._proto.local -> name._type._proto.local (TTL=0)
        mdnsAddAnswer(&outpkt, domain: serviceTypeDomain, type: DNSRecordType.ptr.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: false,
                      ttl: MDNSConfig.goodbyeTTL, rdata: nil, answerDomain: serviceInstanceDomain)
        outpkt.answers += 1

        // SRV: name._type._proto.local (TTL=0)
        let srvData = buildSRVData(service: service)
        let srvHost = mdnsBuildHostDomain(hostname: host.hostname)
        mdnsAddAnswer(&outpkt, domain: serviceInstanceDomain, type: DNSRecordType.srv.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                      ttl: MDNSConfig.goodbyeTTL, rdata: srvData, answerDomain: srvHost)
        outpkt.answers += 1

        // TXT: name._type._proto.local (TTL=0)
        let txtData = service.buildTxtData()
        mdnsAddAnswer(&outpkt, domain: serviceInstanceDomain, type: DNSRecordType.txt.rawValue,
                      klass: MDNSConfig.dnsClassIN, cacheFlush: true,
                      ttl: MDNSConfig.goodbyeTTL, rdata: txtData, answerDomain: nil)
        outpkt.answers += 1
    }

    // MARK: - Negative Responses / NSEC Records (RFC 6762 Section 6.1)

    /// NSEC record data: the complete RDATA in wire format.
    /// Per RFC 4034 Section 4, the NSEC RDATA is:
    ///   Next Domain Name (wire-format) || Type Bit Maps
    /// Per RFC 6762 Section 6.1, for mDNS the "next domain name" is the
    /// owner name itself (since there is no zone concept).
    internal struct NSECData {
        /// Complete NSEC RDATA: next-domain-name bytes followed by type bitmap.
        var rdata: [UInt8]
    }

    /// Build an NSEC type bitmap covering the given DNS record types.
    /// Follows the encoding from RFC 4034 Section 4.1.2:
    ///   - Window block 0 (covers types 0..255)
    ///   - Bitmap length: number of bytes needed to cover the highest type number
    ///   - Bitmap: bit N of byte N/8 set for each present type, where bit 0 is the MSB
    private func buildNSECTypeBitmap(types: [UInt16]) -> [UInt8] {
        guard !types.isEmpty else { return [] }

        // All types we deal with are < 256, so they fit in window block 0.
        var maxType: UInt16 = 0
        for t in types {
            if t > maxType { maxType = t }
        }

        // Bitmap length in bytes: enough to cover the highest type number.
        // Type N is in byte N/8 (0-based), bit (7 - (N % 8)).
        let bitmapLen = Int(maxType / 8) + 1
        var bitmap = [UInt8](repeating: 0, count: bitmapLen)

        for t in types {
            let byteIdx = Int(t) / 8
            let bitIdx = 7 - (Int(t) % 8)
            bitmap[byteIdx] |= UInt8(1 << bitIdx)
        }

        // Window block header: window number (0) + bitmap length
        var result: [UInt8] = [0, UInt8(bitmapLen)]
        result.append(contentsOf: bitmap)
        return result
    }

    /// Encode a domain name into raw bytes (label-length-prefixed wire format)
    /// suitable for embedding in RDATA fields like NSEC's "Next Domain Name".
    private func domainToWireBytes(_ domain: MDNSDomain) -> [UInt8] {
        return Array(domain.name[0..<Int(domain.length)])
    }

    /// Build NSEC rdata for the host name.
    /// The host name can have A and/or AAAA records depending on the interface.
    private func buildHostNSECData(netif: NetworkInterface, hostDomain: MDNSDomain) -> NSECData {
        var availableTypes: [UInt16] = []

        if !netif.ipAddr.isAny {
            availableTypes.append(DNSRecordType.a.rawValue)
        }
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if netif.ipv6AddressStates[i].isValid {
                availableTypes.append(DNSRecordType.aaaa.rawValue)
                break
            }
        }

        let bitmap = buildNSECTypeBitmap(types: availableTypes)
        var rdata = domainToWireBytes(hostDomain)
        rdata.append(contentsOf: bitmap)
        return NSECData(rdata: rdata)
    }

    /// Build NSEC rdata for a service instance name.
    /// Service instance names can have SRV and TXT records.
    private func buildServiceInstanceNSECData(instDomain: MDNSDomain) -> NSECData {
        let availableTypes: [UInt16] = [
            DNSRecordType.txt.rawValue,
            DNSRecordType.srv.rawValue
        ]
        let bitmap = buildNSECTypeBitmap(types: availableTypes)
        var rdata = domainToWireBytes(instDomain)
        rdata.append(contentsOf: bitmap)
        return NSECData(rdata: rdata)
    }

    // MARK: - Large Response Fragmentation (RFC 6762 Section 17)

    /// DNS record section classification for correct header counts.
    internal enum RecordSection {
        case answer
        case authoritative
        case additional
    }

    /// A single DNS resource record entry to be placed in an outgoing message.
    /// Used by the fragmentation engine to collect all records before deciding
    /// how to split them across packets.
    internal struct MDNSRecordEntry {
        var domain: MDNSDomain
        var type: UInt16
        var klass: UInt16
        var cacheFlush: Bool
        var ttl: UInt32
        var rdata: [UInt8]?
        var answerDomain: MDNSDomain?
        var section: RecordSection
    }

    /// Compute the maximum mDNS payload size for an interface.
    /// This is the interface MTU minus IP and UDP header overhead.
    /// Falls back to the configured outputPacketSize if MTU is unset.
    private func mdnsMaxPacketSize(netif: NetworkInterface) -> Int {
        if netif.mtu > 0 {
            let maxPayload = Int(netif.mtu) - MDNSConfig.ipUdpHeaderSize
            return min(maxPayload, MDNSConfig.outputPacketSize)
        }
        return MDNSConfig.outputPacketSize
    }

    /// Estimate the wire size of a record without actually writing it.
    /// This is a conservative upper-bound (no compression applied).
    private func estimateRecordSize(_ entry: MDNSRecordEntry) -> Int {
        // domain name + type(2) + class(2) + TTL(4) + rdlength(2) + rdata + answer domain
        var size = Int(entry.domain.length) + 2 + 2 + 4 + 2
        if let rdata = entry.rdata {
            size += rdata.count
        }
        if let ansDomain = entry.answerDomain {
            size += Int(ansDomain.length)
        }
        return size
    }

    /// Write a single record entry into an output packet and increment the
    /// appropriate section counter.
    private func writeRecordEntry(_ entry: MDNSRecordEntry, to outpkt: inout MDNSOutPacket) {
        mdnsAddAnswer(&outpkt, domain: entry.domain, type: entry.type,
                      klass: entry.klass, cacheFlush: entry.cacheFlush,
                      ttl: entry.ttl, rdata: entry.rdata, answerDomain: entry.answerDomain)
        switch entry.section {
        case .answer:       outpkt.answers += 1
        case .authoritative: outpkt.authoritative += 1
        case .additional:   outpkt.additional += 1
        }
    }

    /// Send a collection of records, splitting across multiple DNS messages
    /// when the total size exceeds maxPacketSize.
    ///
    /// Records are written in order. When adding a record would exceed the
    /// size limit, the current packet is finalized and sent, then a new
    /// packet is started. The first packet in a multi-packet sequence does
    /// NOT get the TC (truncation) bit; truncation is only meaningful for
    /// queries per RFC 6762 Section 17. Each message is a self-contained
    /// response with its own correct header counts.
    private func sendFragmentedReply(
        records: [MDNSRecordEntry],
        msg: MDNSOutMsg,
        maxPacketSize: Int,
        destAddr: IPAddress,
        destPort: UInt16,
        via netif: NetworkInterface
    ) {
        guard !records.isEmpty else { return }

        var outpkt = MDNSOutPacket()
        var recordIdx = 0

        while recordIdx < records.count {
            let entry = records[recordIdx]
            let entrySize = estimateRecordSize(entry)

            // If this single record cannot even fit in an empty packet, write it
            // anyway (degenerate case -- better than dropping it silently).
            let wouldExceed = outpkt.writeOffset + entrySize > maxPacketSize
                              && outpkt.writeOffset > MDNSConfig.dnsHeaderSize

            if wouldExceed {
                // Finalize and send the current packet before starting a new one.
                mdnsWriteHeader(&outpkt, msg: msg)
                sendPacket(outpkt, to: destAddr, port: destPort, via: netif)

                // Start a fresh packet for the remaining records.
                outpkt = MDNSOutPacket()
            }

            writeRecordEntry(entry, to: &outpkt)
            recordIdx += 1
        }

        // Send the final (or only) packet.
        if outpkt.writeOffset > MDNSConfig.dnsHeaderSize {
            mdnsWriteHeader(&outpkt, msg: msg)
            sendPacket(outpkt, to: destAddr, port: destPort, via: netif)
        }
    }

    // MARK: - Truncation (TC) Bit Handling (RFC 6762 Section 7.2)

    /// Store an incoming truncated query and schedule a delayed response.
    ///
    /// Per RFC 6762 Section 7.2, when a query has the TC flag set the
    /// querier may send additional known-answer packets within the next
    /// 400-500ms. We store the original packet and wait for those
    /// follow-up packets before processing.
    private func storeTruncatedQuery(
        data: [UInt8],
        from: IPAddress,
        port: UInt16,
        netif: NetworkInterface
    ) {
        lock.lock()
        // Enforce the maximum number of stored packets.
        guard pendingTCQueries.count < MDNSConfig.maxStoredPackets else {
            lock.unlock()
            return
        }
        let pending = PendingTCQuery(sourceAddr: from, sourcePort: port,
                                     netif: netif, data: data)
        pendingTCQueries.append(pending)
        lock.unlock()

        // Schedule the deferred handler with a random 400-500ms delay.
        let tcDelay = UInt32.random(
            in: MDNSConfig.responseTCDelayMin...MDNSConfig.responseTCDelayMax
        )
        TCPIP.shared.timeout(msecs: tcDelay) { [weak self] in
            self?.handleTCTimeout(pending)
        }
    }

    /// Try to append a known-answer-only packet to a matching pending TC query.
    ///
    /// Called when we receive a packet with zero questions and some answers
    /// while at least one truncated query is pending. If the source address
    /// and port match a pending query we chain the packet data so
    /// `handleTCTimeout` can apply all known answers during suppression.
    ///
    /// - Returns: `true` if the packet was consumed by a pending TC query.
    /// - Note: Caller must hold `lock`.
    private func appendKnownAnswerPacket(
        data: [UInt8],
        from: IPAddress,
        port: UInt16
    ) -> Bool {
        for pending in pendingTCQueries {
            if pending.sourcePort == port && pending.sourceAddr == from {
                // Enforce a reasonable cap on chained packets.
                guard pending.knownAnswerPackets.count < MDNSConfig.maxStoredPackets else {
                    return true // Matched but full; discard silently.
                }
                pending.knownAnswerPackets.append(data)
                return true
            }
        }
        return false
    }

    /// Timer callback for a previously stored truncated query.
    ///
    /// Processes the original query just like `handleQuestion` does,
    /// but additionally parses known-answer sections from any follow-up
    /// packets that were collected during the TC delay window.
    private func handleTCTimeout(_ pending: PendingTCQuery) {
        // Remove from the pending list.
        lock.lock()
        pendingTCQueries.removeAll { $0 === pending }
        let key = ObjectIdentifier(pending.netif)
        guard let host = hosts[key] else { lock.unlock(); return }
        lock.unlock()

        guard host.state == .complete || host.state == .announcing else { return }

        let data = pending.data
        guard data.count >= MDNSConfig.dnsHeaderSize else { return }

        // Re-parse the original truncated query.
        var pkt = MDNSInPacket()
        pkt.sourceAddr = pending.sourceAddr
        pkt.sourcePort = pending.sourcePort
        pkt.data = data
        pkt.txId = readU16(data, offset: 0)
        pkt.questions = readU16(data, offset: 4)
        pkt.questionsLeft = pkt.questions
        pkt.answers = readU16(data, offset: 6)
        pkt.answersLeft = pkt.answers
        pkt.authoritative = readU16(data, offset: 8)
        pkt.authoritativeLeft = pkt.authoritative
        pkt.additional = readU16(data, offset: 10)
        pkt.additionalLeft = pkt.additional
        pkt.parseOffset = MDNSConfig.dnsHeaderSize

        // Parse the question section and build reply flags, same as handleQuestion.
        var reply = MDNSOutMsg()
        var unicastRequested = false

        while pkt.questionsLeft > 0 {
            guard let question = readQuestion(&pkt) else { return }
            if question.unicast { unicastRequested = true }

            let hostResult = checkHostQuestion(netif: pending.netif, host: host,
                                               rr: question.info)
            reply.hostReplies.formUnion(hostResult.replies)
            if hostResult.nameMatched && hostResult.replies.isEmpty &&
               question.info.type != DNSRecordType.any.rawValue {
                reply.hostNSEC = true
            }

            for (i, service) in host.services.enumerated() {
                guard let svc = service else { continue }
                let svcResult = checkServiceQuestion(service: svc, rr: question.info)
                reply.servReplies[i].formUnion(svcResult.replies)
                if svcResult.instanceNameMatched && svcResult.replies.isEmpty &&
                   question.info.type != DNSRecordType.any.rawValue {
                    reply.servNSEC[i] = true
                }
            }
        }

        // Apply known-answer suppression from the original truncated packet.
        parseKnownAnswers(pkt: &pkt, netif: pending.netif, host: host, reply: &reply)

        // Also apply known-answer suppression from follow-up packets
        // (RFC 6762 Section 7.2).
        for kaData in pending.knownAnswerPackets {
            guard kaData.count >= MDNSConfig.dnsHeaderSize else { continue }

            var kaPkt = MDNSInPacket()
            kaPkt.sourceAddr = pending.sourceAddr
            kaPkt.sourcePort = pending.sourcePort
            kaPkt.data = kaData
            kaPkt.questions = readU16(kaData, offset: 4)
            kaPkt.questionsLeft = kaPkt.questions
            kaPkt.answers = readU16(kaData, offset: 6)
            kaPkt.answersLeft = kaPkt.answers
            kaPkt.authoritative = readU16(kaData, offset: 8)
            kaPkt.authoritativeLeft = kaPkt.authoritative
            kaPkt.additional = readU16(kaData, offset: 10)
            kaPkt.additionalLeft = kaPkt.additional
            kaPkt.parseOffset = MDNSConfig.dnsHeaderSize

            // Skip past any questions (there should be none, but be safe).
            while kaPkt.questionsLeft > 0 {
                guard skipQuestion(&kaPkt) else { break }
            }

            // Parse the answer section for known-answer suppression.
            parseKnownAnswers(pkt: &kaPkt, netif: pending.netif, host: host,
                              reply: &reply)
        }

        // Check if we still have anything to send after suppression.
        var anyReplies = !reply.hostReplies.isEmpty || reply.hostNSEC
        for i in 0..<reply.servReplies.count {
            if !reply.servReplies[i].isEmpty || reply.servNSEC[i] { anyReplies = true }
        }
        guard anyReplies else { return }

        // Build and send the reply.
        reply.flags = MDNSConfig.flagResponse | MDNSConfig.flagAuthoritative
        reply.cacheFlush = (pkt.sourcePort == MDNSConfig.port)

        if unicastRequested || pkt.sourcePort != MDNSConfig.port {
            reply.destAddr = pkt.sourceAddr
            reply.destPort = pkt.sourcePort
            if pkt.sourcePort != MDNSConfig.port && pkt.questions == 1 {
                reply.legacyQuery = true
                reply.txId = pkt.txId
            }
        } else {
            reply.destAddr = MDNSConfig.ipv4MulticastAddr
            reply.destPort = MDNSConfig.port
        }

        buildAndSendReply(netif: pending.netif, host: host, msg: reply)
    }
}

