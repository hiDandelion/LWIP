//
//  DNS.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - DNS Constants

/// Namespace for DNS protocol constants.
public enum DNSConstants {
    /// DNS server port.
    public static let serverPort: UInt16 = 53
    /// mDNS multicast port (RFC 6762).
    public static let mdnsPort: UInt16 = 5353
    /// DNS timer period in milliseconds.
    public static let timerInterval: UInt32 = 1000
    /// Maximum hostname length.
    public static let maxNameLength: Int = 256
    /// Maximum number of retries before giving up.
    public static let maxRetries: UInt8 = 4
    /// DNS cache entry TTL when response has TTL=0 (1 second).
    public static let minimumTTL: UInt32 = 1
    /// DNS resource record maximum TTL (one week).
    public static let maxTTL: UInt32 = 604_800
    /// DNS query section size (QTYPE + QCLASS, 4 bytes).
    public static let querySize: Int = 4
    /// DNS answer section fixed fields size (TYPE + CLASS + TTL + RDLENGTH, 10 bytes).
    public static let answerSize: Int = 10
    /// Maximum number of DNS servers (from configuration).
    public static var maxServers: Int { lwipConfig.dnsMaxServers }
    /// Maximum number of concurrent pending queries (from configuration).
    public static var tableSize: Int { lwipConfig.dnsTableSize }
    /// Maximum number of cache entries (from configuration).
    public static var cacheSize: Int { lwipConfig.dnsCacheSize }
    /// DNS header size in bytes.
    public static let headerSize: Int = 12
    /// Maximum CNAME chain depth to follow (prevents infinite loops).
    public static let maxCNAMEChainDepth: Int = 8
    /// Maximum number of negative cache entries.
    public static var negativeCacheSize: Int { lwipConfig.dnsCacheSize }
    /// Maximum number of CNAME cache entries.
    public static var cnameCacheSize: Int { lwipConfig.dnsCacheSize }
    /// Default negative cache TTL when SOA record is absent (5 minutes).
    public static let defaultNegativeTTL: UInt32 = 300
}

// MARK: - DNS RR Types

/// DNS resource record types.
public enum DNSRRType: UInt16, Sendable {
    case a     = 1     // IPv4 host address
    case ns    = 2     // Authoritative name server
    case md    = 3     // Mail destination (obsolete, use MX)
    case mf    = 4     // Mail forwarder (obsolete, use MX)
    case cname = 5     // Canonical name (alias)
    case soa   = 6     // Start of authority
    case mb    = 7     // Mailbox domain name (experimental)
    case mg    = 8     // Mail group member (experimental)
    case mr    = 9     // Mail rename domain name (experimental)
    case null  = 10    // Null RR (experimental)
    case wks   = 11    // Well known service description
    case ptr   = 12    // Domain name pointer
    case hinfo = 13    // Host information
    case minfo = 14    // Mailbox or mail list information
    case mx    = 15    // Mail exchange
    case txt   = 16    // Text strings
    case aaaa  = 28    // IPv6 host address
    case srv   = 33    // Service location
    case any   = 255   // Any type
}

/// DNS resource record class.
public enum DNSRRClass: UInt16, Sendable {
    case `in`  = 1     // Internet
    case cs    = 2     // CSNET class (obsolete)
    case ch    = 3     // CHAOS class
    case hs    = 4     // Hesiod
    case any   = 255   // Any class
    case flush = 0x800 // mDNS cache flush bit
}

// MARK: - DNS Protocol Flags

/// DNS header flag bits.
public struct DNSFlag1: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let response        = DNSFlag1(rawValue: 0x80)
    public static let opcodeStatus    = DNSFlag1(rawValue: 0x10)
    public static let opcodeInverse   = DNSFlag1(rawValue: 0x08)
    public static let authoritative   = DNSFlag1(rawValue: 0x04)
    public static let truncated       = DNSFlag1(rawValue: 0x02)
    public static let recursionDesired = DNSFlag1(rawValue: 0x01)
}

public struct DNSFlag2: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let recursionAvailable = DNSFlag2(rawValue: 0x80)
    public static let errMask            = DNSFlag2(rawValue: 0x0F)
}

/// DNS Flag2 error response codes.
public enum DNSResponseCode {
    /// No error.
    public static let none: UInt8 = 0x00
    /// Name error (NXDOMAIN).
    public static let nameError: UInt8 = 0x03
}

// MARK: - DNS Address Type

/// DNS address resolution type.
public enum DNSAddrType: UInt8, Sendable {
    case ipv4     = 0
    case ipv6     = 1
    case ipv4ipv6 = 2  // Try IPv4 first, then IPv6
    case ipv6ipv4 = 3  // Try IPv6 first, then IPv4

    public static let `default`: DNSAddrType = .ipv4ipv6
}

// MARK: - DNS Header

/// DNS message header (12 bytes).
public struct DNSHeader {
    public var id: UInt16 = 0
    public var flags1: UInt8 = 0
    public var flags2: UInt8 = 0
    public var numQuestions: UInt16 = 0
    public var numAnswers: UInt16 = 0
    public var numAuthRR: UInt16 = 0
    public var numExtraRR: UInt16 = 0

    public init() {}

    /// Serialize to bytes (big-endian).
    public func serialize() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: DNSConstants.headerSize)
        bytes[0] = UInt8(id >> 8)
        bytes[1] = UInt8(id & 0xFF)
        bytes[2] = flags1
        bytes[3] = flags2
        bytes[4] = UInt8(numQuestions >> 8)
        bytes[5] = UInt8(numQuestions & 0xFF)
        bytes[6] = UInt8(numAnswers >> 8)
        bytes[7] = UInt8(numAnswers & 0xFF)
        bytes[8] = UInt8(numAuthRR >> 8)
        bytes[9] = UInt8(numAuthRR & 0xFF)
        bytes[10] = UInt8(numExtraRR >> 8)
        bytes[11] = UInt8(numExtraRR & 0xFF)
        return bytes
    }

    /// Deserialize from bytes.
    public static func deserialize(from data: [UInt8]) -> DNSHeader? {
        guard data.count >= DNSConstants.headerSize else { return nil }
        var hdr = DNSHeader()
        hdr.id = (UInt16(data[0]) << 8) | UInt16(data[1])
        hdr.flags1 = data[2]
        hdr.flags2 = data[3]
        hdr.numQuestions = (UInt16(data[4]) << 8) | UInt16(data[5])
        hdr.numAnswers = (UInt16(data[6]) << 8) | UInt16(data[7])
        hdr.numAuthRR = (UInt16(data[8]) << 8) | UInt16(data[9])
        hdr.numExtraRR = (UInt16(data[10]) << 8) | UInt16(data[11])
        return hdr
    }
}

// MARK: - DNS Cache Entry

/// A cached DNS lookup result.
public struct DNSCacheEntry: Sendable {
    public var name: String = ""
    public var address: IPAddress = .any
    public var ttl: UInt32 = 0
    public var addrType: DNSAddrType = .default

    /// Whether this entry is still valid (TTL > 0).
    @inlinable
    public var isValid: Bool { ttl > 0 && !name.isEmpty }

    public init() {}
}

// MARK: - DNS Query State

/// State of a pending DNS query.
public enum DNSQueryState: UInt8, Sendable {
    case unused     = 0
    case new        = 1
    case requesting = 2
    case done       = 3
}

// MARK: - DNS Table Entry

/// A pending DNS query entry.
public final class DNSTableEntry {
    public var name: String = ""
    public var state: DNSQueryState = .unused
    public var serverIdx: UInt8 = 0
    public var txID: UInt16 = 0
    public var retries: UInt8 = 0
    public var timer: UInt32 = 0

    public var addrType: DNSAddrType = .default
    public var result: IPAddress = .any
    public var ttl: UInt32 = 0
    public var seqNo: UInt8 = 0

    /// The DNS query type (A, AAAA, SRV, TXT, MX). Defaults to `.a`.
    public var queryType: DNSRRType = .a

    /// Accumulated SRV records from the response (for SRV queries).
    public var srvRecords: [DNSSRVRecord] = []

    /// Accumulated MX records from the response (for MX queries).
    public var mxRecords: [DNSMXRecord] = []

    /// TXT record data from the response (for TXT queries).
    public var txtRecord: DNSTXTRecord? = nil

    /// Extended-record callbacks (for SRV/TXT/MX queries).
    public var recordCallbacks: [DNSRecordFoundHandler] = []
    public var recordCallbackArgs: [AnyObject?] = []

    /// CNAME chain depth counter (prevents infinite CNAME loops).
    public var cnameDepth: Int = 0

    /// Whether this query targets an mDNS `.local` name.
    public var isMdns: Bool = false

    /// Index into the DNS PCB pool (used when random source ports are enabled).
    /// A value >= `DNS.maxSourcePorts` means no dedicated PCB is assigned.
    public var pcbIdx: UInt8 = UInt8.max

    /// Callbacks waiting for this query to complete.
    public var callbacks: [(String, IPAddress?, AnyObject?) -> Void] = []
    public var callbackArgs: [AnyObject?] = []

    /// Whether the entry is currently in use.
    @inlinable
    public var isActive: Bool { state != .unused }

    public init() {}

    public func reset() {
        name = ""
        state = .unused
        serverIdx = 0
        txID = 0
        retries = 0
        timer = 0
        result = .any
        ttl = 0
        seqNo = 0
        queryType = .a
        srvRecords.removeAll()
        mxRecords.removeAll()
        txtRecord = nil
        recordCallbacks.removeAll()
        recordCallbackArgs.removeAll()
        cnameDepth = 0
        isMdns = false
        pcbIdx = UInt8.max
        callbacks.removeAll()
        callbackArgs.removeAll()
    }
}

// MARK: - DNS Record Data Types

/// Parsed SRV record data (RFC 2782).
public struct DNSSRVRecord: Sendable, Equatable {
    /// Priority of this target host (lower is preferred).
    public var priority: UInt16
    /// Weight for load balancing among targets with the same priority.
    public var weight: UInt16
    /// TCP or UDP port on which the service is to be found.
    public var port: UInt16
    /// The canonical hostname of the machine providing the service.
    public var target: String

    public init(priority: UInt16 = 0, weight: UInt16 = 0, port: UInt16 = 0, target: String = "") {
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target
    }
}

/// Parsed MX record data (RFC 1035 section 3.3.9).
public struct DNSMXRecord: Sendable, Equatable {
    /// Preference value (lower is preferred).
    public var preference: UInt16
    /// The domain name of the mail exchange host.
    public var exchange: String

    public init(preference: UInt16 = 0, exchange: String = "") {
        self.preference = preference
        self.exchange = exchange
    }
}

/// Parsed TXT record data (RFC 1035 section 3.3.14).
public struct DNSTXTRecord: Sendable, Equatable {
    /// Raw text strings from the TXT record.
    public var strings: [String]
    /// Parsed key=value pairs (for records following the RFC 6763 convention).
    public var keyValues: [(key: String, value: String)]

    public init(strings: [String] = [], keyValues: [(key: String, value: String)] = []) {
        self.strings = strings
        self.keyValues = keyValues
    }

    public static func == (lhs: DNSTXTRecord, rhs: DNSTXTRecord) -> Bool {
        guard lhs.strings == rhs.strings else { return false }
        guard lhs.keyValues.count == rhs.keyValues.count else { return false }
        for (l, r) in zip(lhs.keyValues, rhs.keyValues) {
            if l.key != r.key || l.value != r.value { return false }
        }
        return true
    }
}

/// Result of a DNS query that may return non-address records.
public enum DNSRecordResult: Sendable {
    /// Standard address result (A or AAAA).
    case address(IPAddress)
    /// SRV records, sorted by priority then weight.
    case srv([DNSSRVRecord])
    /// MX records, sorted by preference.
    case mx([DNSMXRecord])
    /// TXT record data.
    case txt(DNSTXTRecord)
    /// CNAME alias.
    case cname(String)
}

/// Callback type for extended DNS queries returning record data.
/// - Parameters:
///   - name: The hostname that was looked up.
///   - result: The parsed record result, or nil on failure.
///   - arg: User-specified callback argument.
public typealias DNSRecordFoundHandler = (String, DNSRecordResult?, AnyObject?) -> Void

// MARK: - CNAME Cache Entry

/// A cached CNAME mapping.
public struct DNSCNAMECacheEntry: Sendable {
    /// The alias name (the name that was queried).
    public var alias: String = ""
    /// The canonical name (the CNAME target).
    public var canonical: String = ""
    /// Remaining TTL in seconds.
    public var ttl: UInt32 = 0

    /// Whether this entry is still valid.
    @inlinable
    public var isValid: Bool { ttl > 0 && !alias.isEmpty }

    public init() {}
}

// MARK: - Negative Cache Entry

/// A cached NXDOMAIN / negative response.
public struct DNSNegativeCacheEntry: Sendable {
    /// The hostname that received a negative response.
    public var name: String = ""
    /// The query type that was negative.
    public var queryType: DNSRRType = .a
    /// Remaining TTL in seconds (from SOA minimum TTL).
    public var ttl: UInt32 = 0

    /// Whether this entry is still valid.
    @inlinable
    public var isValid: Bool { ttl > 0 && !name.isEmpty }

    public init() {}
}

// MARK: - DNS Found Callback

/// Callback type invoked when a hostname lookup completes.
/// - Parameters:
///   - name: The hostname that was looked up.
///   - address: The resolved IP address, or nil on failure.
///   - arg: User-specified callback argument.
public typealias DNSFoundHandler = (String, IPAddress?, AnyObject?) -> Void

// MARK: - Local Host Entry

/// An entry in the DNS local host list, mapping a hostname to an IP address.
public struct LocalHostEntry: Sendable, Equatable {
    /// The hostname for this entry.
    public var hostname: String
    /// The IP address associated with the hostname.
    public var addr: IPAddress

    public init(hostname: String, addr: IPAddress) {
        self.hostname = hostname
        self.addr = addr
    }
}

// MARK: - DNS Resolver

/// The DNS resolver module. Manages servers, cache, and pending queries.
public final class DNS {
    public static let shared = DNS()

    // DNS servers
    private var servers: [IPAddress] = []

    // DNS cache
    private var cache: [DNSCacheEntry] = []

    // CNAME mapping cache
    private var cnameCache: [DNSCNAMECacheEntry] = []

    // Negative response cache (NXDOMAIN)
    private var negativeCache: [DNSNegativeCacheEntry] = []

    // Pending query table
    private var table: [DNSTableEntry] = []

    // UDP control block pool for sending/receiving DNS queries.
    // When `dnsSecureRandomSourcePort` is enabled, each active query gets its own
    // PCB with a unique random source port (mitigates DNS cache poisoning attacks).
    // When disabled, only `dnsPCBs[0]` is used (shared by all queries).
    private var dnsPCBs: [UDPControlBlock?] = []

    /// Maximum number of source port PCBs (matches DNS table size when random ports enabled).
    static var maxSourcePorts: Int {
        lwipConfig.dnsSecureRandomSourcePort ? lwipConfig.dnsTableSize : 1
    }

    /// Index of the last allocated PCB (for round-robin reuse when pool is full).
    private var lastPCBIdx: UInt8 = 0

    // Legacy accessor for the shared (non-random-port) PCB at index 0.
    private var udpControlBlock: UDPControlBlock? {
        get { dnsPCBs.isEmpty ? nil : dnsPCBs[0] }
    }

    // Transaction ID counter
    private var txIDCounter: UInt16 = 0

    // Sequence number for tracking entry age (for eviction in enqueue)
    private var seqNoCounter: UInt8 = 0

    // Timer tick counter
    private var timerTicks: UInt32 = 0

    // mDNS multicast group addresses (RFC 6762)
    private static let mdnsMulticastV4 = IPAddress.v4(IPv4Address(224, 0, 0, 251))
    private static let mdnsMulticastV6 = IPAddress.v6(IPv6Address(0xFF020000, 0, 0, 0xFB))

    // MARK: - Local Host List

    /// Dynamic local host list for overriding DNS lookups.
    /// Entries in this list are checked before the cache and before
    /// sending any network DNS query.
    public private(set) var localHostList: [LocalHostEntry] = []

    private init() {}

    // MARK: - Initialization

    /// Initialize the DNS resolver.
    public func initialize() {
        // Allocate arrays from configuration
        servers = Array(repeating: .any, count: DNSConstants.maxServers)
        cache = Array(repeating: DNSCacheEntry(), count: DNSConstants.cacheSize)
        cnameCache = Array(repeating: DNSCNAMECacheEntry(), count: DNSConstants.cnameCacheSize)
        negativeCache = Array(repeating: DNSNegativeCacheEntry(), count: DNSConstants.negativeCacheSize)
        table = (0..<DNSConstants.tableSize).map { _ in DNSTableEntry() }

        // Allocate the PCB pool
        dnsPCBs = Array(repeating: nil, count: DNS.maxSourcePorts)

        if !lwipConfig.dnsSecureRandomSourcePort {
            // Non-random-port mode: create a single shared PCB
            let udpPCB = UDPGlobal.shared.new()
            let bindErr = UDPGlobal.shared.bind(udpPCB, address: .any, port: 0)
            if bindErr == .ok {
                UDPGlobal.shared.recv(udpPCB) { [weak self] pcb, pbuf, addr, port in
                    self?.recvCallback(pcb: pcb, pbuf: pbuf, addr: addr, port: port)
                }
            }
            dnsPCBs[0] = udpPCB
        }
        // Random-port mode: PCBs are allocated per-query in allocRandomPortPCB()

        // Initialize transaction ID with secure randomization
        if lwipConfig.dnsSecureRandomTxID {
            txIDCounter = UInt16(truncatingIfNeeded: arc4random())
        } else {
            #if DEBUG
            txIDCounter = 0x1234
            #else
            txIDCounter = UInt16(truncatingIfNeeded: arc4random())
            #endif
        }
    }

    // MARK: - PCB Pool Management (dns_alloc_random_port / dns_alloc_pcb)

    /// Allocate a UDP PCB bound to a random ephemeral port.
    private func allocRandomPortPCB() -> UDPControlBlock? {
        let pcb = UDPGlobal.shared.new()
        let port = UInt16(49152 + (arc4random() % 16384))
        let err = UDPGlobal.shared.bind(pcb, address: .any, port: port)
        guard err == .ok else {
            UDPGlobal.shared.remove(pcb)
            return nil
        }
        UDPGlobal.shared.recv(pcb) { [weak self] pcb, pbuf, addr, port in
            self?.recvCallback(pcb: pcb, pbuf: pbuf, addr: addr, port: port)
        }
        return pcb
    }

    /// Allocate a PCB index from the pool for a new query.
    /// Creates a new PCB with a random port if a free slot is available,
    /// otherwise reuses an existing one round-robin.
    private func allocPCBIndex() -> UInt8 {
        let maxPorts = DNS.maxSourcePorts

        // Find a free slot and allocate a new random-port PCB
        for i in 0..<maxPorts {
            if dnsPCBs[i] == nil {
                dnsPCBs[i] = allocRandomPortPCB()
                if dnsPCBs[i] != nil {
                    lastPCBIdx = UInt8(i)
                    return UInt8(i)
                }
            }
        }

        // No free slot: reuse an existing PCB round-robin
        for i in 0..<maxPorts {
            let idx = (Int(lastPCBIdx) + 1 + i) % maxPorts
            if dnsPCBs[idx] != nil {
                lastPCBIdx = UInt8(idx)
                return UInt8(idx)
            }
        }

        return UInt8(maxPorts) // signals failure
    }

    /// Release a PCB back to the pool if no other active query is using it.
    private func releasePCBIfUnused(entryIndex: Int) {
        guard lwipConfig.dnsSecureRandomSourcePort else { return }
        let entry = table[entryIndex]
        let pcbIdx = entry.pcbIdx
        guard pcbIdx < UInt8(DNS.maxSourcePorts) else { return }

        // Check if any other requesting entry shares this PCB
        for i in 0..<table.count {
            if i == entryIndex { continue }
            if table[i].state == .requesting && table[i].pcbIdx == pcbIdx {
                // Another query is still using this PCB; just detach this entry
                entry.pcbIdx = UInt8.max
                return
            }
        }

        // No other query uses it — free the PCB
        if let pcb = dnsPCBs[Int(pcbIdx)] {
            UDPGlobal.shared.remove(pcb)
            dnsPCBs[Int(pcbIdx)] = nil
        }
        entry.pcbIdx = UInt8.max
    }

    /// Generate the next transaction ID, optionally using secure randomization.
    private func nextTransactionID() -> UInt16 {
        if lwipConfig.dnsSecureRandomTxID {
            return UInt16(truncatingIfNeeded: arc4random())
        }
        txIDCounter &+= 1
        return txIDCounter
    }

    /// Whether a hostname should be resolved via mDNS multicast.
    private func isMdnsName(_ hostname: String) -> Bool {
        guard lwipConfig.dnsSupportMdnsQueries else { return false }
        return hostname.hasSuffix(".local") || hostname.hasSuffix(".local.")
    }

    // MARK: - Server Configuration

    /// Set a DNS server address.
    ///
    /// - Parameters:
    ///   - index: Server index (0 to DNSConstants.maxServers - 1).
    ///   - address: The server IP address.
    public func setServer(index: Int, address: IPAddress) {
        guard index >= 0 && index < DNSConstants.maxServers && index < servers.count else { return }
        servers[index] = address
    }

    /// Get the address of a DNS server.
    ///
    /// - Parameter index: Server index.
    /// - Returns: The server address, or .any if not configured.
    public func getServer(index: Int) -> IPAddress {
        guard index >= 0 && index < DNSConstants.maxServers && index < servers.count else { return .any }
        return servers[index]
    }

    // MARK: - Local Host List Management

    /// Look up a hostname in the local host list.
    ///
    /// Performs a case-insensitive match against entries in the local host list.
    /// If the hostname ends with a trailing dot, the dot is stripped before comparison.
    ///
    /// - Parameters:
    ///   - hostname: The hostname to look up.
    ///   - addrType: The address type filter. Only entries whose address matches
    ///               the requested type are returned. For dual-stack types
    ///               (`.ipv4ipv6`, `.ipv6ipv4`), IPv4 is matched for the former
    ///               and IPv6 for the latter (no fallback).
    /// - Returns: The matching IP address, or `nil` if no match is found.
    public func localLookup(hostname: String, addrType: DNSAddrType = .default) -> IPAddress? {
        guard !hostname.isEmpty else { return nil }

        var name = hostname
        if name.hasSuffix(".") {
            name = String(name.dropLast())
        }
        guard name.count < DNSConstants.maxNameLength else { return nil }

        for entry in localHostList {
            if entry.hostname.caseInsensitiveCompare(name) == .orderedSame {
                if addressMatchesType(entry.addr, addrType: addrType) {
                    return entry.addr
                }
            }
        }
        return nil
    }

    /// Add a hostname/IP address pair to the local host list.
    ///
    /// The new entry is inserted at the front of the list (matching the C
    /// implementation's linked-list prepend behavior). Duplicate entries
    /// are not checked; callers should remove existing entries first if
    /// uniqueness is desired.
    ///
    /// - Parameters:
    ///   - hostname: The hostname to add.
    ///   - addr: The IP address to associate with the hostname.
    /// - Returns: `.ok` on success, `.invalidArgument` if the hostname is empty
    ///            or exceeds the maximum name length.
    @discardableResult
    public func localAddHost(hostname: String, addr: IPAddress) -> LWIPError {
        guard !hostname.isEmpty, hostname.count <= DNSConstants.maxNameLength else {
            return .invalidArgument
        }
        let entry = LocalHostEntry(hostname: hostname, addr: addr)
        localHostList.insert(entry, at: 0)
        return .ok
    }

    /// Remove entries from the local host list that match the given hostname
    /// and/or IP address.
    ///
    /// Either parameter may be `nil` to act as a wildcard:
    /// - If both are provided, only entries matching **both** are removed.
    /// - If only `hostname` is provided, all entries for that hostname are removed.
    /// - If only `addr` is provided, all entries for that address are removed.
    /// - If both are `nil`, the entire list is cleared.
    ///
    /// Hostname comparison is case-insensitive.
    ///
    /// - Parameters:
    ///   - hostname: The hostname to match, or `nil` to match any hostname.
    ///   - addr: The address to match, or `nil` to match any address.
    /// - Returns: The number of entries removed.
    @discardableResult
    public func localRemoveHost(hostname: String? = nil, addr: IPAddress? = nil) -> Int {
        var removed = 0
        localHostList.removeAll { entry in
            let hostnameMatches = hostname == nil ||
                entry.hostname.caseInsensitiveCompare(hostname!) == .orderedSame
            let addrMatches = addr == nil || entry.addr == addr!
            if hostnameMatches && addrMatches {
                removed += 1
                return true
            }
            return false
        }
        return removed
    }

    /// Iterate over all entries in the local host list.
    ///
    /// The callback is invoked once for each entry. If `callback` is `nil`,
    /// the method simply returns the number of entries without calling anything.
    ///
    /// - Parameter callback: A closure called with each entry's hostname and address.
    /// - Returns: The total number of entries in the local host list.
    @discardableResult
    public func localIterate(callback: ((String, IPAddress) -> Void)? = nil) -> Int {
        for entry in localHostList {
            callback?(entry.hostname, entry.addr)
        }
        return localHostList.count
    }

    /// Check whether an IP address matches the requested DNS address type.
    private func addressMatchesType(_ addr: IPAddress, addrType: DNSAddrType) -> Bool {
        switch addrType {
        case .ipv4, .ipv4ipv6:
            return addr.isV4
        case .ipv6, .ipv6ipv4:
            return addr.isV6
        }
    }

    // MARK: - Hostname Resolution

    /// Resolve a hostname to an IP address.
    ///
    /// - Parameters:
    ///   - hostname: The hostname to resolve.
    ///   - addrType: The type of address to resolve (IPv4, IPv6, or dual-stack).
    ///   - found: Callback invoked when the lookup completes or fails.
    ///   - arg: User argument passed to the callback.
    /// - Returns:
    ///   - .ok: Result is already available (cached); callback was invoked.
    ///   - .inProgress: Query has been sent; callback will be invoked later.
    ///   - .invalidArgument: Invalid argument.
    @discardableResult
    public func getHostByName(_ hostname: String,
                              addrType: DNSAddrType = .default,
                              found: @escaping DNSFoundHandler,
                              arg: AnyObject? = nil) -> (LWIPError, IPAddress?) {
        guard !hostname.isEmpty && hostname.count <= DNSConstants.maxNameLength else {
            return (.invalidArgument, nil)
        }

        // Check if hostname is already an IP address (dotted-decimal)
        if let addr = parseIPAddress(hostname) {
            found(hostname, addr, arg)
            return (.ok, addr)
        }

        // Check local host list before cache and network query
        if let addr = localLookup(hostname: hostname, addrType: addrType) {
            found(hostname, addr, arg)
            return (.ok, addr)
        }

        // Check negative cache first (NXDOMAIN)
        let queryRRType: DNSRRType = (addrType == .ipv6 || addrType == .ipv6ipv4) ? .aaaa : .a
        if lookupNegativeCache(name: hostname, queryType: queryRRType) {
            found(hostname, nil, arg)
            return (.ok, nil)
        }

        // Follow CNAME cache chain before checking address cache
        let resolvedName = followCNAMECache(hostname)

        // Check cache (using resolved CNAME target if applicable)
        for i in 0..<cache.count {
            if cache[i].isValid && cache[i].name.caseInsensitiveCompare(resolvedName) == .orderedSame {
                let matchesType: Bool
                switch addrType {
                case .ipv4:
                    matchesType = cache[i].address.isV4
                case .ipv6:
                    matchesType = cache[i].address.isV6
                default:
                    matchesType = true
                }
                if matchesType {
                    let addr = cache[i].address
                    found(hostname, addr, arg)
                    return (.ok, addr)
                }
            }
        }

        // Check the DNS table for cached DONE entries
        let hostNameLength = hostname.count
        for i in 0..<table.count {
            if table[i].state == .done &&
               table[i].name.caseInsensitiveCompare(hostname) == .orderedSame &&
               addressMatchesType(table[i].result, addrType: addrType) {
                let addr = table[i].result
                found(hostname, addr, arg)
                return (.ok, addr)
            }
        }

        // For dual-stack, also check fallback type in the table
        if addrType == .ipv4ipv6 || addrType == .ipv6ipv4 {
            let fallbackType: DNSAddrType = (addrType == .ipv4ipv6) ? .ipv6 : .ipv4
            for i in 0..<table.count {
                if table[i].state == .done &&
                   table[i].name.caseInsensitiveCompare(hostname) == .orderedSame &&
                   addressMatchesType(table[i].result, addrType: fallbackType) {
                    let addr = table[i].result
                    found(hostname, addr, arg)
                    return (.ok, addr)
                }
            }
        }

        // Determine if this is an mDNS query
        let isMdns = isMdnsName(hostname)

        // Prevent calling callback if no server is set (non-mDNS only)
        if !isMdns && servers[0].isAnyAddress {
            return (.invalidValue, nil)
        }

        // Enqueue the query
        let enqueueResult = enqueue(
            name: hostname,
            hostNameLength: hostNameLength,
            callback: found,
            callbackArg: arg,
            dnsAddressType: addrType
        )
        return (enqueueResult, nil)
    }

    /// Simplified API: resolve hostname, returning result via callback.
    @discardableResult
    public func gethostbyname(_ hostname: String,
                              found: @escaping DNSFoundHandler,
                              arg: AnyObject? = nil) -> LWIPError {
        let (err, _) = getHostByName(hostname, found: found, arg: arg)
        return err
    }

    // MARK: - Enqueue (dns_enqueue)

    /// Queue a new hostname for resolution and send a DNS query.
    ///
    /// First checks for a duplicate in-flight request for the same hostname
    /// and address type. If found, the callback is added to the existing entry
    /// and `.inProgress` is returned immediately.
    ///
    /// Otherwise, searches for an unused table entry, or reuses the oldest
    /// completed (`.done`) entry via sequence-number-based eviction.
    ///
    /// Fills in the entry with the query parameters, assigns a sequence number,
    /// and calls `checkEntry(index:)` to immediately transition from `.new`
    /// to `.requesting` and send the query packet.
    ///
    /// - Parameters:
    ///   - name: The hostname to resolve.
    ///   - hostNameLength: The length of the hostname.
    ///   - callback: Callback to invoke when resolution completes.
    ///   - callbackArg: User argument passed to the callback.
    ///   - dnsAddressType: The address type to resolve.
    ///   - queryType: The DNS RR type to query for (default `.a`).
    ///   - recordCallback: Optional callback for extended record data (SRV/TXT/MX).
    /// - Returns: `.inProgress` if the query was enqueued, or an error code.
    private func enqueue(
        name: String,
        hostNameLength: Int,
        callback: @escaping DNSFoundHandler,
        callbackArg: AnyObject?,
        dnsAddressType: DNSAddrType,
        queryType: DNSRRType = .a,
        recordCallback: DNSRecordFoundHandler? = nil
    ) -> LWIPError {
        let namelen = min(hostNameLength, DNSConstants.maxNameLength - 1)
        let truncatedName = String(name.prefix(namelen))

        // Check for duplicate entries (same hostname already being queried)
        for i in 0..<table.count {
            let entry = table[i]
            if entry.state == .requesting &&
               entry.name.caseInsensitiveCompare(truncatedName) == .orderedSame {
                // If address types don't match, allow a parallel query
                if entry.addrType != dnsAddressType {
                    continue
                }
                // Duplicate: attach callback to the existing entry
                entry.callbacks.append(callback)
                entry.callbackArgs.append(callbackArg)
                return .inProgress
            }
        }

        // Search for an unused entry, or find the oldest completed entry to evict
        var foundIndex: Int = -1
        var oldestSeqAge: UInt8 = 0
        var oldestSeqIndex: Int = -1

        for i in 0..<table.count {
            let entry = table[i]
            if entry.state == .unused {
                foundIndex = i
                break
            }
            // Track oldest .done entry by sequence number distance
            if entry.state == .done {
                let age = seqNoCounter &- entry.seqNo
                if age > oldestSeqAge || oldestSeqIndex < 0 {
                    oldestSeqAge = age
                    oldestSeqIndex = i
                }
            }
        }

        // If no unused entry found, try to evict the oldest completed one
        if foundIndex < 0 {
            if oldestSeqIndex >= 0 && table[oldestSeqIndex].state == .done {
                foundIndex = oldestSeqIndex
            } else {
                // Table is full, no evictable entry
                return .outOfMemory
            }
        }

        let entry = table[foundIndex]

        // Fill the entry
        entry.state = .new
        entry.name = truncatedName
        entry.addrType = dnsAddressType
        entry.queryType = queryType
        entry.seqNo = seqNoCounter
        entry.result = .any
        entry.ttl = 0
        entry.retries = 0
        entry.serverIdx = 0
        entry.timer = 0
        entry.isMdns = isMdnsName(name)
        entry.cnameDepth = 0
        entry.srvRecords.removeAll()
        entry.mxRecords.removeAll()
        entry.txtRecord = nil
        entry.callbacks = [callback]
        entry.callbackArgs = [callbackArg]
        if let recordCB = recordCallback {
            entry.recordCallbacks = [recordCB]
            entry.recordCallbackArgs = [callbackArg]
        } else {
            entry.recordCallbacks.removeAll()
            entry.recordCallbackArgs.removeAll()
        }

        // Allocate a dedicated PCB with random source port if configured
        if lwipConfig.dnsSecureRandomSourcePort {
            entry.pcbIdx = allocPCBIndex()
            if entry.pcbIdx >= UInt8(DNS.maxSourcePorts) {
                entry.state = .unused
                entry.callbacks.removeAll()
                entry.callbackArgs.removeAll()
                return .outOfMemory
            }
        } else {
            entry.pcbIdx = 0
        }

        seqNoCounter &+= 1

        // Immediately process the entry (transitions to REQUESTING and sends query)
        checkEntry(index: foundIndex)

        return .inProgress
    }

    // MARK: - Timer

    /// DNS timer function. Call every `DNSConstants.timerInterval` (1000 ms).
    public func timerFired() {
        timerTicks &+= 1

        // Decrement cache TTLs
        for i in 0..<cache.count {
            if cache[i].ttl > 0 {
                cache[i].ttl -= 1
            }
        }

        // Decrement CNAME cache TTLs
        for i in 0..<cnameCache.count {
            if cnameCache[i].ttl > 0 {
                cnameCache[i].ttl -= 1
            }
        }

        // Decrement negative cache TTLs
        for i in 0..<negativeCache.count {
            if negativeCache[i].ttl > 0 {
                negativeCache[i].ttl -= 1
            }
        }

        // Check all table entries for timeouts/retries
        checkAllEntries()
    }

    // MARK: - Entry Checking (dns_check_entry / dns_check_entries)

    /// Check all entries in the DNS table. Called by the DNS timer.
    private func checkAllEntries() {
        for i in 0..<table.count {
            checkEntry(index: i)
        }
    }

    /// Check a single DNS table entry.
    ///
    /// - For `.new` entries: assign a unique transaction ID, transition to `.requesting`,
    ///   and send the first DNS query.
    /// - For `.requesting` entries: decrement the timer. On timeout, either retry with
    ///   exponential backoff (incrementing retries, rotating servers) or fail the query.
    ///   `entry.timer` counts down to 0, then `retries` is
    ///   incremented and timer is set to the retry count for exponential backoff.
    /// - For `.done` entries: decrement TTL and flush when expired.
    ///
    /// - Parameter index: Index into the DNS table.
    private func checkEntry(index: Int) {
        guard index >= 0 && index < table.count else { return }
        let entry = table[index]

        switch entry.state {
        case .new:
            // Initialize new entry
            entry.txID = createTransactionID()
            entry.state = .requesting
            entry.serverIdx = 0
            entry.timer = 1
            entry.retries = 0

            // Send DNS packet for this entry
            sendQuery(entryIndex: index)

        case .requesting:
            // Decrement timer; when it reaches zero, take action
            if entry.timer > 0 {
                entry.timer -= 1
            }
            if entry.timer == 0 {
                entry.retries += 1
                if entry.retries >= DNSConstants.maxRetries {
                    // Check if a backup server is available
                    if backupServerAvailable(entry: entry) && !entry.isMdns {
                        // Switch to the next server and reset retries
                        entry.serverIdx += 1
                        entry.timer = 1
                        entry.retries = 0
                    } else {
                        // All retries exhausted: fail the query
                        completeQuery(entry: entry, address: nil)
                        entry.state = .unused
                        return
                    }
                } else {
                    // Wait longer for the next retry (exponential backoff)
                    entry.timer = UInt32(entry.retries)
                }

                // Send DNS packet for this entry (retry or new server)
                sendQuery(entryIndex: index)
            }

        case .done:
            // Check if TTL has expired (C: if (entry->ttl == 0 || --entry->ttl == 0))
            if entry.ttl == 0 {
                entry.state = .unused
            } else {
                entry.ttl -= 1
                if entry.ttl == 0 {
                    entry.state = .unused
                }
            }

        case .unused:
            break
        }
    }

    /// Check whether there are backup DNS servers available to try.
    private func backupServerAvailable(entry: DNSTableEntry) -> Bool {
        let nextIdx = Int(entry.serverIdx) + 1
        if nextIdx < DNSConstants.maxServers && !servers[nextIdx].isAnyAddress {
            return true
        }
        return false
    }

    // MARK: - Query Construction (dns_send)

    /// Build and send a DNS query packet for the given table entry.
    ///
    /// Constructs a DNS message with:
    /// - Header: ID from the entry's txID, flags=RD (recursion desired), QDCOUNT=1.
    /// - Question section: QNAME encoded from the entry's hostname in DNS label format,
    ///   QTYPE=A (for IPv4) or AAAA (for IPv6), QCLASS=IN.
    ///
    /// Sends via UDP to the configured DNS server. For mDNS queries (`.local` suffix),
    /// sends to the multicast group instead. Handles server rotation on retries by
    /// using `entry.serverIdx`.
    ///
    /// - Parameter entryIndex: Index into the DNS table.
    /// - Returns: `.ok` on success, or an error code.
    @discardableResult
    private func sendQuery(entryIndex: Int) -> LWIPError {
        guard entryIndex >= 0 && entryIndex < table.count else { return .invalidArgument }
        let entry = table[entryIndex]

        // Select the appropriate PCB: per-entry PCB (random port) or shared PCB
        let pcbIdx = Int(entry.pcbIdx)
        let udpPCB: UDPControlBlock
        if lwipConfig.dnsSecureRandomSourcePort {
            guard pcbIdx < DNS.maxSourcePorts, let pcb = dnsPCBs[pcbIdx] else {
                return .invalidArgument
            }
            udpPCB = pcb
        } else {
            guard let pcb = dnsPCBs[0] else { return .invalidArgument }
            udpPCB = pcb
        }

        // Validate server address (mDNS entries bypass this check)
        if !entry.isMdns {
            let serverIdx = Int(entry.serverIdx)
            guard serverIdx < DNSConstants.maxServers else { return .invalidArgument }
            if servers[serverIdx].isAnyAddress {
                // DNS server not valid anymore (e.g., PPP netif shut down)
                completeQuery(entry: entry, address: nil)
                entry.state = .unused
                return .ok
            }
        }

        // Calculate packet size: header + encoded name + 2 (null term already in name) + query fields
        let encodedName = encodeDNSName(entry.name)
        guard !encodedName.isEmpty else { return .invalidValue }
        let packetSize = DNSConstants.headerSize + encodedName.count + DNSConstants.querySize

        // Allocate pbuf
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(packetSize), type: .ram) else {
            return .outOfMemory
        }

        // Build DNS header
        var hdr = DNSHeader()
        hdr.id = entry.txID
        hdr.flags1 = DNSFlag1.recursionDesired.rawValue
        hdr.flags2 = 0
        hdr.numQuestions = 1
        let headerBytes = hdr.serialize()
        _ = headerBytes.withUnsafeBufferPointer { buf in
            pbuf.take(from: buf.baseAddress!, len: UInt16(headerBytes.count))
        }

        // Write the encoded hostname (QNAME) after the header
        var queryIdx = UInt16(DNSConstants.headerSize)
        _ = encodedName.withUnsafeBufferPointer { buf in
            pbuf.takeAt(from: buf.baseAddress!, len: UInt16(buf.count), offset: queryIdx)
        }
        queryIdx += UInt16(encodedName.count)

        // Determine query type: use explicit queryType for SRV/TXT/MX,
        // otherwise derive from address type for A/AAAA.
        let queryType: UInt16
        switch entry.queryType {
        case .srv, .txt, .mx:
            queryType = entry.queryType.rawValue
        default:
            switch entry.addrType {
            case .ipv6, .ipv6ipv4:
                queryType = DNSRRType.aaaa.rawValue
            case .ipv4, .ipv4ipv6:
                queryType = DNSRRType.a.rawValue
            }
        }

        // Write QTYPE and QCLASS (each 2 bytes, big-endian)
        let queryFields: [UInt8] = [
            UInt8(queryType >> 8), UInt8(queryType & 0xFF),
            UInt8(DNSRRClass.in.rawValue >> 8), UInt8(DNSRRClass.in.rawValue & 0xFF)
        ]
        _ = queryFields.withUnsafeBufferPointer { buf in
            pbuf.takeAt(from: buf.baseAddress!, len: UInt16(buf.count), offset: queryIdx)
        }

        // Determine destination address and port
        let destAddr: IPAddress
        let destPort: UInt16

        if entry.isMdns {
            destPort = DNSConstants.mdnsPort
            switch entry.addrType {
            case .ipv6, .ipv6ipv4:
                destAddr = DNS.mdnsMulticastV6
            default:
                destAddr = DNS.mdnsMulticastV4
            }
        } else {
            destPort = DNSConstants.serverPort
            destAddr = servers[Int(entry.serverIdx)]
        }

        // Send the packet
        let err = UDPGlobal.shared.sendTo(udpPCB, pbuf: pbuf,
                                           dstIP: destAddr,
                                           dstPort: destPort)

        return err
    }

    /// Convenience: send query for an entry by reference (locates index in the table).
    private func sendQuery(entry: DNSTableEntry) {
        guard let index = table.firstIndex(where: { $0 === entry }) else { return }
        sendQuery(entryIndex: index)
    }

    // MARK: - Response Parsing (dns_recv)

    /// UDP receive callback for DNS responses. Registered with the UDP PCB.
    private func recvCallback(pcb: UDPControlBlock, pbuf: Pbuf, addr: IPAddress, port: UInt16) {
        receiveResponse(pcb: pcb, pbuf: pbuf, addr: addr, port: port)
    }

    /// Parse and process a DNS response packet.
    ///
    /// Validates the response header (QR=1, matching transaction ID, RCODE).
    /// Verifies the question section matches the original query. Parses the
    /// answer section for A (IPv4) or AAAA (IPv6) records. Extracts TTL.
    /// Handles CNAME chasing by following CNAME records in the answer section
    /// and re-issuing the query if the final answer is not found.
    /// For dual-stack queries, falls back to the other address type on failure.
    ///
    /// - Parameters:
    ///   - pcb: The UDP control block that received the packet.
    ///   - pbuf: The received packet buffer.
    ///   - addr: Source IP address of the response.
    ///   - port: Source port of the response.
    private func receiveResponse(pcb: UDPControlBlock, pbuf: Pbuf, addr: IPAddress, port: UInt16) {
        // Is the DNS message big enough?
        let minSize = UInt16(DNSConstants.headerSize + DNSConstants.querySize)
        guard pbuf.totLen >= minSize else { return }

        // Read header from pbuf
        let hdrID = pbuf.getUInt16(at: 0)
        let flags1 = pbuf.getByte(at: 2)
        let flags2 = pbuf.getByte(at: 3)
        let numQuestions = pbuf.getUInt16(at: 4)
        let numAnswers = pbuf.getUInt16(at: 6)

        // Match the transaction ID with a pending table entry
        var matchedIndex: Int = -1
        for i in 0..<table.count {
            let entry = table[i]
            if entry.state == .requesting && entry.txID == hdrID {
                matchedIndex = i
                break
            }
        }
        guard matchedIndex >= 0 else { return }
        let entry = table[matchedIndex]

        // Must be a response (QR bit set)
        guard (flags1 & DNSFlag1.response.rawValue) != 0 else { return }

        // Check for truncated response (TC flag).  Truncated UDP responses
        // contain incomplete answer sections and must not be parsed.  Discard
        // the response and retry the query so it can be resent (potentially
        // to the next DNS server).
        if lwipConfig.dnsRetryOnTruncation &&
           DNSFlag1(rawValue: flags1).contains(.truncated) {
            // Bump retries so the next checkEntry pass will resend quickly.
            // If retries are already at the max the normal retry/failover
            // logic inside checkEntry will rotate to a backup server or
            // fail the query gracefully.
            entry.timer = 1
            entry.retries = entry.retries < DNSConstants.maxRetries
                ? entry.retries : DNSConstants.maxRetries - 1
            checkEntry(index: matchedIndex)
            return
        }

        // Must have exactly 1 question
        guard numQuestions == 1 else { return }

        // Verify the response comes from the expected server (RFC 5452)
        if !entry.isMdns {
            guard addr == servers[Int(entry.serverIdx)] else { return }
        }

        // Compare the name in the question section with the entry's name
        var resIdx = compareName(entry.name, atOffset: UInt16(DNSConstants.headerSize), in: pbuf)
        guard resIdx != 0xFFFF else { return }

        // Verify the question QTYPE and QCLASS match
        guard Int(resIdx) + DNSConstants.querySize <= Int(pbuf.totLen) else { return }
        let qType = pbuf.getUInt16(at: Int(resIdx))
        let qClass = pbuf.getUInt16(at: Int(resIdx) + 2)

        guard qClass == DNSRRClass.in.rawValue else { return }
        let isIPv6 = entry.addrType == .ipv6 || entry.addrType == .ipv6ipv4

        // Validate QTYPE matches what we asked for
        switch entry.queryType {
        case .srv:
            guard qType == DNSRRType.srv.rawValue else { return }
        case .txt:
            guard qType == DNSRRType.txt.rawValue else { return }
        case .mx:
            guard qType == DNSRRType.mx.rawValue else { return }
        default:
            if isIPv6 {
                guard qType == DNSRRType.aaaa.rawValue else { return }
            } else {
                guard qType == DNSRRType.a.rawValue else { return }
            }
        }

        // Skip past the question section
        guard Int(resIdx) + DNSConstants.querySize <= 0xFFFF else { return }
        resIdx = resIdx &+ UInt16(DNSConstants.querySize)

        // Read the number of authority RRs for SOA parsing (negative caching)
        let numAuthRR = pbuf.getUInt16(at: 8)

        // Check for error in flags2
        let responseCode = flags2 & DNSFlag2.errMask.rawValue
        if responseCode != 0 {
            // NXDOMAIN: cache the negative result if we can find a SOA minimum TTL
            if responseCode == DNSResponseCode.nameError {
                let soaTTL = parseSOAMinimumTTL(pbuf: pbuf, offset: resIdx,
                                                 numAnswers: numAnswers,
                                                 numAuthRR: numAuthRR)
                let negativeTTL = min(soaTTL ?? DNSConstants.defaultNegativeTTL,
                                      DNSConstants.maxTTL)
                let negativeQueryType = entry.queryType == .a || entry.queryType == .aaaa
                    ? (isIPv6 ? DNSRRType.aaaa : DNSRRType.a) : entry.queryType
                addToNegativeCache(name: entry.name, queryType: negativeQueryType,
                                   ttl: max(negativeTTL, DNSConstants.minimumTTL))
            }

            // Error response. If a backup server is available, retry via that server.
            if backupServerAvailable(entry: entry) {
                entry.retries = DNSConstants.maxRetries - 1
                entry.timer = 1
                checkEntry(index: matchedIndex)
                return
            }
            // No backup; fall through to fail the query below
        } else {
            // Parse answer records
            var answersRemaining = numAnswers
            var cnameTarget: String? = nil
            var cnameTTL: UInt32 = 0

            while answersRemaining > 0 && resIdx < pbuf.totLen {
                // Skip the answer RR's name
                let nameEnd = skipName(atOffset: resIdx, in: pbuf)
                guard nameEnd != 0xFFFF else { return }
                resIdx = nameEnd

                // Read the answer fixed fields (TYPE, CLASS, TTL, RDLENGTH)
                guard Int(resIdx) + DNSConstants.answerSize <= Int(pbuf.totLen) else { return }
                let ansType = pbuf.getUInt16(at: Int(resIdx))
                let ansClass = pbuf.getUInt16(at: Int(resIdx) + 2)
                let ansTTL = pbuf.getUInt32(at: Int(resIdx) + 4)
                let ansLen = pbuf.getUInt16(at: Int(resIdx) + 8)

                guard Int(resIdx) + DNSConstants.answerSize <= 0xFFFF else { return }
                resIdx = resIdx &+ UInt16(DNSConstants.answerSize)

                if ansClass == DNSRRClass.in.rawValue {
                    // --- A/AAAA handling (for address queries) ---
                    if entry.queryType == .a || entry.queryType == .aaaa {
                        // Check for A record (IPv4)
                        if ansType == DNSRRType.a.rawValue && ansLen == 4 && !isIPv6 {
                            guard Int(resIdx) + 4 <= Int(pbuf.totLen) else { return }
                            let b0 = UInt32(pbuf.getByte(at: Int(resIdx)))
                            let b1 = UInt32(pbuf.getByte(at: Int(resIdx) + 1))
                            let b2 = UInt32(pbuf.getByte(at: Int(resIdx) + 2))
                            let b3 = UInt32(pbuf.getByte(at: Int(resIdx) + 3))
                            let addrVal = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                            entry.result = .v4(IPv4Address(networkOrder: addrVal.bigEndian))
                            // If we followed a CNAME to get here, cache the mapping
                            if let cname = cnameTarget {
                                addToCNAMECache(alias: entry.name, canonical: cname,
                                                ttl: max(cnameTTL, DNSConstants.minimumTTL))
                            }
                            handleCorrectResponse(entryIndex: matchedIndex, ttl: ansTTL)
                            return
                        }
                        // Check for AAAA record (IPv6)
                        if ansType == DNSRRType.aaaa.rawValue && ansLen == 16 && isIPv6 {
                            guard Int(resIdx) + 16 <= Int(pbuf.totLen) else { return }
                            let w0 = pbuf.getUInt32(at: Int(resIdx))
                            let w1 = pbuf.getUInt32(at: Int(resIdx) + 4)
                            let w2 = pbuf.getUInt32(at: Int(resIdx) + 8)
                            let w3 = pbuf.getUInt32(at: Int(resIdx) + 12)
                            entry.result = .v6(IPv6Address(w0.bigEndian, w1.bigEndian, w2.bigEndian, w3.bigEndian))
                            if let cname = cnameTarget {
                                addToCNAMECache(alias: entry.name, canonical: cname,
                                                ttl: max(cnameTTL, DNSConstants.minimumTTL))
                            }
                            handleCorrectResponse(entryIndex: matchedIndex, ttl: ansTTL)
                            return
                        }
                    }

                    // --- CNAME record handling (applies to all query types) ---
                    if ansType == DNSRRType.cname.rawValue {
                        let allBytes = extractAllBytes(from: pbuf)
                        if let cname = decodeDNSNameFromMessage(bytes: allBytes, offset: Int(resIdx)) {
                            // Cache the CNAME mapping
                            let originalName = entry.name
                            cnameTarget = cname
                            cnameTTL = ansTTL
                            addToCNAMECache(alias: originalName, canonical: cname,
                                            ttl: max(ansTTL, DNSConstants.minimumTTL))
                            // Update entry name to follow the CNAME
                            entry.name = cname
                        }
                    }

                    // --- SRV record handling ---
                    if ansType == DNSRRType.srv.rawValue && entry.queryType == .srv {
                        if let srvRecord = parseSRVRecord(pbuf: pbuf, offset: Int(resIdx),
                                                           rdataLen: Int(ansLen)) {
                            entry.srvRecords.append(srvRecord)
                            entry.ttl = max(entry.ttl, ansTTL)
                        }
                    }

                    // --- MX record handling ---
                    if ansType == DNSRRType.mx.rawValue && entry.queryType == .mx {
                        if let mxRecord = parseMXRecord(pbuf: pbuf, offset: Int(resIdx),
                                                         rdataLen: Int(ansLen)) {
                            entry.mxRecords.append(mxRecord)
                            entry.ttl = max(entry.ttl, ansTTL)
                        }
                    }

                    // --- TXT record handling ---
                    if ansType == DNSRRType.txt.rawValue && entry.queryType == .txt {
                        let txtRecord = parseTXTRecord(pbuf: pbuf, offset: Int(resIdx),
                                                        rdataLen: Int(ansLen))
                        entry.txtRecord = txtRecord
                        entry.ttl = ansTTL
                    }
                }

                // Skip this answer's RDATA
                guard Int(resIdx) + Int(ansLen) <= 0xFFFF else { return }
                resIdx = resIdx &+ ansLen
                answersRemaining -= 1
            }

            // --- Handle completed SRV/MX/TXT queries ---
            if entry.queryType == .srv && !entry.srvRecords.isEmpty {
                // Sort SRV records by priority (ascending), then weight (descending)
                entry.srvRecords.sort { a, b in
                    if a.priority != b.priority { return a.priority < b.priority }
                    return a.weight > b.weight
                }
                handleCorrectRecordResponse(entryIndex: matchedIndex, ttl: entry.ttl)
                return
            }

            if entry.queryType == .mx && !entry.mxRecords.isEmpty {
                // Sort MX records by preference (ascending)
                entry.mxRecords.sort { $0.preference < $1.preference }
                handleCorrectRecordResponse(entryIndex: matchedIndex, ttl: entry.ttl)
                return
            }

            if entry.queryType == .txt && entry.txtRecord != nil {
                handleCorrectRecordResponse(entryIndex: matchedIndex, ttl: entry.ttl)
                return
            }

            // --- CNAME following for A/AAAA queries ---
            // If we got a CNAME but no matching A/AAAA record in this response,
            // re-query for the canonical name (with depth limit).
            if cnameTarget != nil && (entry.queryType == .a || entry.queryType == .aaaa) {
                entry.cnameDepth += 1
                if entry.cnameDepth <= DNSConstants.maxCNAMEChainDepth {
                    // Re-issue query with the CNAME target
                    entry.state = .new
                    entry.retries = 0
                    checkEntry(index: matchedIndex)
                    return
                }
                // CNAME chain too deep; fail the query
            }

            // No matching answer found for A/AAAA queries. Try dual-stack fallback.
            if (entry.queryType == .a || entry.queryType == .aaaa) &&
               (entry.addrType == .ipv4ipv6 || entry.addrType == .ipv6ipv4) {
                if entry.addrType == .ipv4ipv6 {
                    entry.addrType = .ipv6
                    entry.queryType = .aaaa
                } else {
                    entry.addrType = .ipv4
                    entry.queryType = .a
                }
                entry.state = .new
                checkEntry(index: matchedIndex)
                return
            }

            // If no answers at all with zero answers, add to negative cache
            if numAnswers == 0 {
                let soaTTL = parseSOAMinimumTTL(pbuf: pbuf, offset: resIdx,
                                                 numAnswers: 0, numAuthRR: numAuthRR)
                let negativeTTL = min(soaTTL ?? DNSConstants.defaultNegativeTTL,
                                      DNSConstants.maxTTL)
                let negativeQueryType = entry.queryType == .a || entry.queryType == .aaaa
                    ? (isIPv6 ? DNSRRType.aaaa : DNSRRType.a) : entry.queryType
                addToNegativeCache(name: entry.name, queryType: negativeQueryType,
                                   ttl: max(negativeTTL, DNSConstants.minimumTTL))
            }
        }

        // No valid answer and no fallback: fail the query
        completeQuery(entry: entry, address: nil)
        entry.state = .unused
    }

    /// Extract raw bytes from a pbuf into an array.
    private func extractBytes(from pbuf: Pbuf, offset: Int, count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            bytes[i] = pbuf.getByte(at: offset + i)
        }
        return bytes
    }

    // MARK: - Correct Response Handling (dns_correct_response)

    /// Save TTL and invoke callbacks for a correct DNS response.
    ///
    /// Sets the entry to `.done` state, clamps TTL to `maxTTL`, invokes the
    /// found callbacks, and also adds the result to the cache. If TTL is 0
    /// (per RFC 883: "only usable for the transaction in progress"),
    /// the entry is immediately flushed.
    ///
    /// - Parameters:
    ///   - entryIndex: Index into the DNS table.
    ///   - ttl: The TTL from the answer resource record.
    private func handleCorrectResponse(entryIndex: Int, ttl: UInt32) {
        guard entryIndex >= 0 && entryIndex < table.count else { return }
        let entry = table[entryIndex]

        // Release the dedicated PCB now that the query is complete.
        releasePCBIfUnused(entryIndex: entryIndex)

        entry.state = .done

        // Clamp TTL to maximum
        entry.ttl = min(ttl, DNSConstants.maxTTL)

        // Add to cache
        let cacheAddrType: DNSAddrType = entry.result.isV6 ? .ipv6 : .ipv4
        addToCache(name: entry.name, address: entry.result,
                   ttl: max(entry.ttl, DNSConstants.minimumTTL),
                   addrType: cacheAddrType)

        // Invoke callbacks
        let name = entry.name
        let result = entry.result
        let callbacks = entry.callbacks
        let args = entry.callbackArgs
        entry.callbacks.removeAll()
        entry.callbackArgs.removeAll()

        for i in 0..<callbacks.count {
            let arg = i < args.count ? args[i] : nil
            callbacks[i](name, result, arg)
        }

        // If TTL is 0, flush immediately (RFC 883 page 29)
        if entry.ttl == 0 {
            if entry.state == .done {
                entry.state = .unused
            }
        }
    }

    // MARK: - Response Validation (dns_correct_response check)

    /// Validate that a DNS response matches the query for a given table entry.
    ///
    /// Checks that:
    /// - The transaction ID in the response matches the entry's txID.
    /// - The QR (response) flag is set in flags1.
    /// - There are no errors in flags2 (RCODE == 0).
    ///
    /// - Parameters:
    ///   - entryIndex: Index into the DNS table.
    ///   - pbuf: The received packet buffer.
    /// - Returns: `true` if the response is valid for the given entry.
    public func isCorrectResponse(entryIndex: Int, pbuf: Pbuf) -> Bool {
        guard entryIndex >= 0 && entryIndex < table.count else { return false }
        let entry = table[entryIndex]
        guard entry.state == .requesting else { return false }
        guard pbuf.totLen >= UInt16(DNSConstants.headerSize) else { return false }

        let responseID = pbuf.getUInt16(at: 0)
        let flags1 = pbuf.getByte(at: 2)
        let flags2 = pbuf.getByte(at: 3)

        // Transaction ID must match
        guard responseID == entry.txID else { return false }

        // Must be a response (QR bit set)
        guard (flags1 & DNSFlag1.response.rawValue) != 0 else { return false }

        // No errors in response code
        guard (flags2 & DNSFlag2.errMask.rawValue) == DNSResponseCode.none else { return false }

        return true
    }

    // MARK: - Transaction ID Generation (dns_create_txid)

    /// Generate a random 16-bit transaction ID for DNS queries.
    ///
    /// Ensures the generated ID does not conflict with any in-flight queries
    /// (entries in `.requesting` state). This prevents transaction ID reuse
    /// which could cause response mismatches.
    ///
    /// - Returns: A unique 16-bit transaction ID.
    private func createTransactionID() -> UInt16 {
        while true {
            let txid = nextTransactionID()
            // Check uniqueness against all outstanding queries
            var unique = true
            for entry in table {
                if entry.state == .requesting && entry.txID == txid {
                    unique = false
                    break
                }
            }
            if unique {
                return txid
            }
        }
    }

    // MARK: - Dual-stack fallback

    /// For dual-stack queries, try the other address type if the first failed.
    /// Returns true if a retry was initiated.
    private func tryFallbackAddrType(entry: DNSTableEntry) -> Bool {
        switch entry.addrType {
        case .ipv4ipv6:
            // IPv4 failed, try IPv6
            entry.addrType = .ipv6
            entry.retries = 0
            entry.txID = createTransactionID()
            sendQuery(entry: entry)
            return true
        case .ipv6ipv4:
            // IPv6 failed, try IPv4
            entry.addrType = .ipv4
            entry.retries = 0
            entry.txID = createTransactionID()
            sendQuery(entry: entry)
            return true
        default:
            return false
        }
    }

    // MARK: - Query Completion

    /// Complete a query: invoke all registered callbacks and free the entry.
    private func completeQuery(entry: DNSTableEntry, address: IPAddress?) {
        // Release the dedicated PCB before resetting the entry.
        if let idx = table.firstIndex(where: { $0 === entry }) {
            releasePCBIfUnused(entryIndex: idx)
        }

        let name = entry.name
        let callbacks = entry.callbacks
        let args = entry.callbackArgs
        let recordCallbacks = entry.recordCallbacks
        let recordArgs = entry.recordCallbackArgs

        entry.reset()

        for i in 0..<callbacks.count {
            let arg = i < args.count ? args[i] : nil
            callbacks[i](name, address, arg)
        }

        // Invoke record callbacks with nil result on failure
        for i in 0..<recordCallbacks.count {
            let arg = i < recordArgs.count ? recordArgs[i] : nil
            recordCallbacks[i](name, nil, arg)
        }
    }

    // MARK: - Cache Management

    /// Add a resolved name to the cache, evicting the oldest entry if full.
    private func addToCache(name: String, address: IPAddress, ttl: UInt32, addrType: DNSAddrType) {
        // Look for an existing entry to update
        for i in 0..<cache.count {
            if cache[i].name == name && cache[i].addrType == addrType {
                cache[i].address = address
                cache[i].ttl = ttl
                return
            }
        }

        // Find an empty slot
        for i in 0..<cache.count {
            if !cache[i].isValid {
                cache[i].name = name
                cache[i].address = address
                cache[i].ttl = ttl
                cache[i].addrType = addrType
                return
            }
        }

        // Evict the entry with the lowest TTL
        var minIdx = 0
        var minTTL = cache[0].ttl
        for i in 1..<cache.count {
            if cache[i].ttl < minTTL {
                minTTL = cache[i].ttl
                minIdx = i
            }
        }
        cache[minIdx].name = name
        cache[minIdx].address = address
        cache[minIdx].ttl = ttl
        cache[minIdx].addrType = addrType
    }

    // MARK: - DNS Name Encoding/Decoding

    // MARK: Pbuf-based name utilities (dns_compare_name / dns_skip_name)

    /// Compare a dotted hostname string with an encoded DNS name in a pbuf.
    ///
    /// Walks through the DNS wire-format name in the pbuf and compares each
    /// label (case-insensitive) against the corresponding label in the dotted
    /// hostname string. Does **not** follow compression pointers, since the
    /// query we sent never uses compression, so a compressed response name
    /// cannot match.
    ///
    /// - Parameters:
    ///   - query: The dotted hostname from the DNS table entry.
    ///   - offset: Start offset into the pbuf where the encoded name begins.
    ///   - pbuf: The packet buffer containing the DNS response.
    /// - Returns: The offset immediately after the encoded name if names match,
    ///            or `0xFFFF` if they differ or an error occurs.
    private func compareName(_ query: String, atOffset startOffset: UInt16, in pbuf: Pbuf) -> UInt16 {
        var responseOffset = startOffset
        var queryIndex = query.utf8.startIndex

        let queryUTF8 = query.utf8

        repeat {
            guard let n = pbuf.getByteAt(offset: responseOffset) else { return 0xFFFF }
            if responseOffset == 0xFFFF { return 0xFFFF }
            responseOffset &+= 1

            // RFC 1035 - 4.1.4: Message compression
            if (n & 0xC0) == 0xC0 {
                // Compressed name: cannot be equal since we don't send compressed names
                return 0xFFFF
            } else {
                // Not compressed: n is the label length
                var remaining = Int(n)
                while remaining > 0 {
                    guard let c = pbuf.getByteAt(offset: responseOffset) else { return 0xFFFF }
                    guard queryIndex < queryUTF8.endIndex else { return 0xFFFF }

                    let queryChar = queryUTF8[queryIndex]
                    // Case-insensitive comparison
                    if toLower(queryChar) != toLower(c) {
                        return 0xFFFF
                    }
                    if responseOffset == 0xFFFF { return 0xFFFF }
                    responseOffset &+= 1
                    queryIndex = queryUTF8.index(after: queryIndex)
                    remaining -= 1
                }
                // After each label, the query should have a '.' separator or end
                if queryIndex < queryUTF8.endIndex {
                    if queryUTF8[queryIndex] == UInt8(ascii: ".") {
                        queryIndex = queryUTF8.index(after: queryIndex)
                    }
                }
            }

            guard let nextByte = pbuf.getByteAt(offset: responseOffset) else { return 0xFFFF }
            if nextByte == 0 { break }
        } while true

        // Both query and response name should be fully consumed
        // (query might have a trailing dot that was already skipped)
        if queryIndex < queryUTF8.endIndex {
            // Query has remaining characters
            return 0xFFFF
        }

        if responseOffset == 0xFFFF { return 0xFFFF }
        return responseOffset &+ 1
    }

    /// Skip over a compressed DNS name in a pbuf.
    ///
    /// Walks through the encoded name, handling compression pointers (RFC 1035
    /// section 4.1.4). When a compression pointer is encountered, the function
    /// stops (since we only need the offset past the name, not its value).
    ///
    /// - Parameters:
    ///   - offset: Start offset into the pbuf.
    ///   - pbuf: The packet buffer containing the DNS message.
    /// - Returns: The offset after the encoded name, or `0xFFFF` on error.
    private func skipName(atOffset startOffset: UInt16, in pbuf: Pbuf) -> UInt16 {
        var offset = startOffset

        repeat {
            guard let n = pbuf.getByteAt(offset: offset) else { return 0xFFFF }
            offset &+= 1
            if offset == 0 { return 0xFFFF } // overflow

            // RFC 1035 - 4.1.4: Message compression
            if (n & 0xC0) == 0xC0 {
                // Compressed name: pointer is 2 bytes total, we already read one
                // Just skip the second byte and we're done
                break
            } else {
                // Not compressed: skip n bytes
                if Int(offset) + Int(n) >= Int(pbuf.totLen) {
                    return 0xFFFF
                }
                offset = offset &+ UInt16(n)
            }

            guard let nextByte = pbuf.getByteAt(offset: offset) else { return 0xFFFF }
            if nextByte == 0 { break }
        } while true

        if offset == 0xFFFF { return 0xFFFF }
        return offset &+ 1
    }

    /// Convert an ASCII byte to lowercase.
    @inline(__always)
    private func toLower(_ c: UInt8) -> UInt8 {
        if c >= 0x41 && c <= 0x5A { // 'A'...'Z'
            return c | 0x20
        }
        return c
    }

    // MARK: Byte-array based name utilities (legacy)

    /// Skip a DNS name in the wire format (handles compression pointers).
    /// Returns the offset after the name, or -1 on error.
    private func skipDNSName(bytes: [UInt8], offset: Int) -> Int {
        var pos = offset
        var jumped = false
        var jumpedTo = 0

        while pos < bytes.count {
            let labelLen = bytes[pos]
            if labelLen == 0 {
                return jumped ? jumpedTo : pos + 1
            }
            if (labelLen & 0xC0) == 0xC0 {
                // Compression pointer
                guard pos + 1 < bytes.count else { return -1 }
                if !jumped {
                    jumpedTo = pos + 2
                    jumped = true
                }
                let ptrOffset = (Int(labelLen & 0x3F) << 8) | Int(bytes[pos + 1])
                if ptrOffset >= pos { return -1 } // Forward references not allowed
                pos = ptrOffset
            } else {
                pos += 1 + Int(labelLen)
            }
        }
        return -1
    }

    /// Decode a DNS name from wire format to a dotted string.
    private func decodeDNSName(bytes: [UInt8], offset: Int) -> String? {
        var pos = offset
        var parts: [String] = []
        var jumps = 0
        let maxJumps = bytes.count // Prevent infinite loops

        while pos < bytes.count && jumps < maxJumps {
            let labelLen = bytes[pos]
            if labelLen == 0 { break }
            if (labelLen & 0xC0) == 0xC0 {
                guard pos + 1 < bytes.count else { return nil }
                let ptrOffset = (Int(labelLen & 0x3F) << 8) | Int(bytes[pos + 1])
                pos = ptrOffset
                jumps += 1
            } else {
                let start = pos + 1
                let end = start + Int(labelLen)
                guard end <= bytes.count else { return nil }
                if let label = String(bytes: bytes[start..<end], encoding: .utf8) {
                    parts.append(label)
                }
                pos = end
            }
        }

        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }

    /// Encode a hostname into DNS label format.
    public func encodeDNSName(_ hostname: String) -> [UInt8] {
        var result = [UInt8]()
        let labels = hostname.split(separator: ".", omittingEmptySubsequences: true)
        for label in labels {
            let labelBytes = Array(label.utf8)
            if labelBytes.count > 63 { return [] }
            result.append(UInt8(labelBytes.count))
            result.append(contentsOf: labelBytes)
        }
        result.append(0)
        return result
    }

    // MARK: - IP Address Parsing

    /// Try to parse a string as a dotted-decimal IPv4 address.
    private func parseIPAddress(_ str: String) -> IPAddress? {
        let parts = str.split(separator: ".")
        guard parts.count == 4 else { return nil }

        var addr: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            addr = (addr << 8) | UInt32(octet)
        }
        return .v4(IPv4Address(networkOrder: addr.bigEndian))
    }

    // MARK: - SRV/TXT/MX Query APIs

    /// Query for SRV records for a given service name.
    ///
    /// The hostname should be in DNS-SD format, e.g. "_http._tcp.example.com".
    ///
    /// - Parameters:
    ///   - hostname: The service name to query for SRV records.
    ///   - found: Callback invoked with the SRV record results, or nil on failure.
    ///   - arg: User argument passed to the callback.
    /// - Returns: `.inProgress` if the query was enqueued, or an error code.
    @discardableResult
    public func querySRV(_ hostname: String,
                         found: @escaping DNSRecordFoundHandler,
                         arg: AnyObject? = nil) -> LWIPError {
        guard !hostname.isEmpty && hostname.count <= DNSConstants.maxNameLength else {
            return .invalidArgument
        }
        // Check negative cache
        if lookupNegativeCache(name: hostname, queryType: .srv) {
            found(hostname, nil, arg)
            return .ok
        }
        guard !servers[0].isAnyAddress else { return .invalidValue }
        // Use a no-op address callback; the real result goes through the record callback
        let noopCallback: DNSFoundHandler = { _, _, _ in }
        return enqueue(
            name: hostname,
            hostNameLength: hostname.count,
            callback: noopCallback,
            callbackArg: arg,
            dnsAddressType: .ipv4,
            queryType: .srv,
            recordCallback: found
        )
    }

    /// Query for TXT records for a given hostname.
    ///
    /// - Parameters:
    ///   - hostname: The hostname to query for TXT records.
    ///   - found: Callback invoked with the TXT record results, or nil on failure.
    ///   - arg: User argument passed to the callback.
    /// - Returns: `.inProgress` if the query was enqueued, or an error code.
    @discardableResult
    public func queryTXT(_ hostname: String,
                         found: @escaping DNSRecordFoundHandler,
                         arg: AnyObject? = nil) -> LWIPError {
        guard !hostname.isEmpty && hostname.count <= DNSConstants.maxNameLength else {
            return .invalidArgument
        }
        if lookupNegativeCache(name: hostname, queryType: .txt) {
            found(hostname, nil, arg)
            return .ok
        }
        guard !servers[0].isAnyAddress else { return .invalidValue }
        let noopCallback: DNSFoundHandler = { _, _, _ in }
        return enqueue(
            name: hostname,
            hostNameLength: hostname.count,
            callback: noopCallback,
            callbackArg: arg,
            dnsAddressType: .ipv4,
            queryType: .txt,
            recordCallback: found
        )
    }

    /// Query for MX records for a given domain.
    ///
    /// - Parameters:
    ///   - hostname: The domain to query for MX records.
    ///   - found: Callback invoked with the MX record results (sorted by preference),
    ///            or nil on failure.
    ///   - arg: User argument passed to the callback.
    /// - Returns: `.inProgress` if the query was enqueued, or an error code.
    @discardableResult
    public func queryMX(_ hostname: String,
                        found: @escaping DNSRecordFoundHandler,
                        arg: AnyObject? = nil) -> LWIPError {
        guard !hostname.isEmpty && hostname.count <= DNSConstants.maxNameLength else {
            return .invalidArgument
        }
        if lookupNegativeCache(name: hostname, queryType: .mx) {
            found(hostname, nil, arg)
            return .ok
        }
        guard !servers[0].isAnyAddress else { return .invalidValue }
        let noopCallback: DNSFoundHandler = { _, _, _ in }
        return enqueue(
            name: hostname,
            hostNameLength: hostname.count,
            callback: noopCallback,
            callbackArg: arg,
            dnsAddressType: .ipv4,
            queryType: .mx,
            recordCallback: found
        )
    }

    // MARK: - Record Response Completion

    /// Complete a successful SRV/TXT/MX query: invoke record callbacks.
    ///
    /// - Parameters:
    ///   - entryIndex: Index into the DNS table.
    ///   - ttl: The TTL to assign to the completed entry.
    private func handleCorrectRecordResponse(entryIndex: Int, ttl: UInt32) {
        guard entryIndex >= 0 && entryIndex < table.count else { return }
        let entry = table[entryIndex]

        releasePCBIfUnused(entryIndex: entryIndex)

        entry.state = .done
        entry.ttl = min(ttl, DNSConstants.maxTTL)

        let name = entry.name
        let recordCallbacks = entry.recordCallbacks
        let recordArgs = entry.recordCallbackArgs

        // Build the result
        let result: DNSRecordResult?
        switch entry.queryType {
        case .srv:
            result = entry.srvRecords.isEmpty ? nil : .srv(entry.srvRecords)
        case .mx:
            result = entry.mxRecords.isEmpty ? nil : .mx(entry.mxRecords)
        case .txt:
            result = entry.txtRecord.map { .txt($0) }
        default:
            result = nil
        }

        entry.recordCallbacks.removeAll()
        entry.recordCallbackArgs.removeAll()
        entry.callbacks.removeAll()
        entry.callbackArgs.removeAll()

        for i in 0..<recordCallbacks.count {
            let arg = i < recordArgs.count ? recordArgs[i] : nil
            recordCallbacks[i](name, result, arg)
        }

        if entry.ttl == 0 && entry.state == .done {
            entry.state = .unused
        }
    }

    // MARK: - SRV Record Parsing

    /// Parse an SRV record from RDATA in a pbuf.
    ///
    /// SRV RDATA format (RFC 2782):
    ///   - 2 bytes: priority
    ///   - 2 bytes: weight
    ///   - 2 bytes: port
    ///   - variable: target domain name (wire format)
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DNS response.
    ///   - offset: Offset to the start of the SRV RDATA.
    ///   - rdataLen: Length of the RDATA section.
    /// - Returns: A parsed `DNSSRVRecord`, or nil on error.
    private func parseSRVRecord(pbuf: Pbuf, offset: Int, rdataLen: Int) -> DNSSRVRecord? {
        // Minimum SRV RDATA: 2+2+2+1 = 7 bytes (priority+weight+port+root name)
        guard rdataLen >= 7, offset + rdataLen <= Int(pbuf.totLen) else { return nil }

        let priority = pbuf.getUInt16(at: offset)
        let weight = pbuf.getUInt16(at: offset + 2)
        let port = pbuf.getUInt16(at: offset + 4)

        // Decode the target domain name (may use compression pointers)
        let allBytes = extractAllBytes(from: pbuf)
        guard let target = decodeDNSNameFromMessage(bytes: allBytes, offset: offset + 6) else {
            return nil
        }

        return DNSSRVRecord(priority: priority, weight: weight, port: port, target: target)
    }

    // MARK: - MX Record Parsing

    /// Parse an MX record from RDATA in a pbuf.
    ///
    /// MX RDATA format (RFC 1035 section 3.3.9):
    ///   - 2 bytes: preference
    ///   - variable: exchange domain name (wire format)
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DNS response.
    ///   - offset: Offset to the start of the MX RDATA.
    ///   - rdataLen: Length of the RDATA section.
    /// - Returns: A parsed `DNSMXRecord`, or nil on error.
    private func parseMXRecord(pbuf: Pbuf, offset: Int, rdataLen: Int) -> DNSMXRecord? {
        // Minimum MX RDATA: 2+1 = 3 bytes (preference + root name)
        guard rdataLen >= 3, offset + rdataLen <= Int(pbuf.totLen) else { return nil }

        let preference = pbuf.getUInt16(at: offset)

        let allBytes = extractAllBytes(from: pbuf)
        guard let exchange = decodeDNSNameFromMessage(bytes: allBytes, offset: offset + 2) else {
            return nil
        }

        return DNSMXRecord(preference: preference, exchange: exchange)
    }

    // MARK: - TXT Record Parsing

    /// Parse a TXT record from RDATA in a pbuf.
    ///
    /// TXT RDATA format (RFC 1035 section 3.3.14):
    ///   One or more character-strings. Each is a length byte followed by
    ///   that many bytes of text.
    ///
    /// Also parses key=value pairs per RFC 6763 (DNS-SD TXT records).
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DNS response.
    ///   - offset: Offset to the start of the TXT RDATA.
    ///   - rdataLen: Length of the RDATA section.
    /// - Returns: A parsed `DNSTXTRecord`.
    private func parseTXTRecord(pbuf: Pbuf, offset: Int, rdataLen: Int) -> DNSTXTRecord {
        var record = DNSTXTRecord()
        var pos = offset
        let end = offset + rdataLen

        while pos < end && pos < Int(pbuf.totLen) {
            let strLen = Int(pbuf.getByte(at: pos))
            pos += 1
            guard pos + strLen <= end && pos + strLen <= Int(pbuf.totLen) else { break }

            var strBytes = [UInt8](repeating: 0, count: strLen)
            for i in 0..<strLen {
                strBytes[i] = pbuf.getByte(at: pos + i)
            }
            pos += strLen

            if let str = String(bytes: strBytes, encoding: .utf8) {
                record.strings.append(str)
                // Parse key=value pairs (RFC 6763)
                if let eqIdx = str.firstIndex(of: "=") {
                    let key = String(str[str.startIndex..<eqIdx])
                    let value = String(str[str.index(after: eqIdx)...])
                    record.keyValues.append((key: key, value: value))
                }
            }
        }

        return record
    }

    // MARK: - CNAME Cache Management

    /// Add a CNAME mapping to the cache.
    ///
    /// - Parameters:
    ///   - alias: The alias name (the original query name).
    ///   - canonical: The canonical name (the CNAME target).
    ///   - ttl: TTL for the cache entry.
    private func addToCNAMECache(alias: String, canonical: String, ttl: UInt32) {
        // Update existing entry
        for i in 0..<cnameCache.count {
            if cnameCache[i].alias.caseInsensitiveCompare(alias) == .orderedSame {
                cnameCache[i].canonical = canonical
                cnameCache[i].ttl = ttl
                return
            }
        }

        // Find an empty slot
        for i in 0..<cnameCache.count {
            if !cnameCache[i].isValid {
                cnameCache[i].alias = alias
                cnameCache[i].canonical = canonical
                cnameCache[i].ttl = ttl
                return
            }
        }

        // Evict the entry with the lowest TTL
        var minIdx = 0
        var minTTL = cnameCache[0].ttl
        for i in 1..<cnameCache.count {
            if cnameCache[i].ttl < minTTL {
                minTTL = cnameCache[i].ttl
                minIdx = i
            }
        }
        cnameCache[minIdx].alias = alias
        cnameCache[minIdx].canonical = canonical
        cnameCache[minIdx].ttl = ttl
    }

    /// Follow a CNAME chain in the cache, returning the final canonical name.
    ///
    /// Follows up to `maxCNAMEChainDepth` links to prevent infinite loops.
    ///
    /// - Parameter name: The hostname to resolve through CNAME cache.
    /// - Returns: The final canonical name, or the original name if no CNAME mapping exists.
    private func followCNAMECache(_ name: String) -> String {
        var current = name
        var depth = 0

        while depth < DNSConstants.maxCNAMEChainDepth {
            var foundNext = false
            for i in 0..<cnameCache.count {
                if cnameCache[i].isValid &&
                   cnameCache[i].alias.caseInsensitiveCompare(current) == .orderedSame {
                    current = cnameCache[i].canonical
                    foundNext = true
                    break
                }
            }
            if !foundNext { break }
            depth += 1
        }

        return current
    }

    // MARK: - Negative Cache Management

    /// Add a negative (NXDOMAIN) result to the negative cache.
    ///
    /// - Parameters:
    ///   - name: The hostname that received a negative response.
    ///   - queryType: The RR type that was queried.
    ///   - ttl: TTL for the negative cache entry (from SOA minimum TTL).
    private func addToNegativeCache(name: String, queryType: DNSRRType, ttl: UInt32) {
        // Update existing entry
        for i in 0..<negativeCache.count {
            if negativeCache[i].name.caseInsensitiveCompare(name) == .orderedSame &&
               negativeCache[i].queryType == queryType {
                negativeCache[i].ttl = ttl
                return
            }
        }

        // Find an empty slot
        for i in 0..<negativeCache.count {
            if !negativeCache[i].isValid {
                negativeCache[i].name = name
                negativeCache[i].queryType = queryType
                negativeCache[i].ttl = ttl
                return
            }
        }

        // Evict the entry with the lowest TTL
        var minIdx = 0
        var minTTL = negativeCache[0].ttl
        for i in 1..<negativeCache.count {
            if negativeCache[i].ttl < minTTL {
                minTTL = negativeCache[i].ttl
                minIdx = i
            }
        }
        negativeCache[minIdx].name = name
        negativeCache[minIdx].queryType = queryType
        negativeCache[minIdx].ttl = ttl
    }

    /// Check if a hostname has a valid negative cache entry.
    ///
    /// - Parameters:
    ///   - name: The hostname to check.
    ///   - queryType: The RR type to check.
    /// - Returns: `true` if a valid negative cache entry exists for this name and type.
    private func lookupNegativeCache(name: String, queryType: DNSRRType) -> Bool {
        for i in 0..<negativeCache.count {
            if negativeCache[i].isValid &&
               negativeCache[i].name.caseInsensitiveCompare(name) == .orderedSame &&
               negativeCache[i].queryType == queryType {
                return true
            }
        }
        return false
    }

    // MARK: - SOA Record Parsing (for negative caching)

    /// Parse the authority section of a DNS response to extract the SOA minimum TTL.
    ///
    /// When a DNS server returns NXDOMAIN, the authority section typically contains
    /// a SOA record. The minimum TTL field of the SOA record (the last 4-byte field
    /// in the RDATA) is used as the negative cache TTL per RFC 2308.
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DNS response.
    ///   - offset: Offset past the answer section (start of authority section).
    ///   - numAnswers: Number of answer RRs to skip.
    ///   - numAuthRR: Number of authority RRs to search.
    /// - Returns: The SOA minimum TTL, or nil if no SOA record was found.
    private func parseSOAMinimumTTL(pbuf: Pbuf, offset: UInt16,
                                     numAnswers: UInt16, numAuthRR: UInt16) -> UInt32? {
        var resIdx = offset

        // Skip remaining answer records (in case offset is mid-answers)
        var answersToSkip = numAnswers
        while answersToSkip > 0 && resIdx < pbuf.totLen {
            let nameEnd = skipName(atOffset: resIdx, in: pbuf)
            guard nameEnd != 0xFFFF else { return nil }
            resIdx = nameEnd
            guard Int(resIdx) + DNSConstants.answerSize <= Int(pbuf.totLen) else { return nil }
            let ansLen = pbuf.getUInt16(at: Int(resIdx) + 8)
            resIdx = resIdx &+ UInt16(DNSConstants.answerSize) &+ ansLen
            answersToSkip -= 1
        }

        // Parse authority RRs looking for SOA
        var authRemaining = numAuthRR
        while authRemaining > 0 && resIdx < pbuf.totLen {
            let nameEnd = skipName(atOffset: resIdx, in: pbuf)
            guard nameEnd != 0xFFFF else { return nil }
            resIdx = nameEnd

            guard Int(resIdx) + DNSConstants.answerSize <= Int(pbuf.totLen) else { return nil }
            let rrType = pbuf.getUInt16(at: Int(resIdx))
            let rrLen = pbuf.getUInt16(at: Int(resIdx) + 8)

            resIdx = resIdx &+ UInt16(DNSConstants.answerSize)

            if rrType == DNSRRType.soa.rawValue {
                // SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
                // The minimum TTL is the last 4 bytes of the RDATA
                let rdataEnd = Int(resIdx) + Int(rrLen)
                guard rdataEnd <= Int(pbuf.totLen) && rrLen >= 4 else { return nil }
                // The minimum field is the last 4 bytes of the SOA RDATA
                let minimumTTL = pbuf.getUInt32(at: rdataEnd - 4)
                return minimumTTL
            }

            guard Int(resIdx) + Int(rrLen) <= 0xFFFF else { return nil }
            resIdx = resIdx &+ rrLen
            authRemaining -= 1
        }

        return nil
    }

    // MARK: - Message-level DNS Name Decoding

    /// Decode a DNS name from a full DNS message byte array, handling compression pointers.
    ///
    /// Unlike `decodeDNSName(bytes:offset:)` which works on RDATA-only byte arrays,
    /// this method works on the full message and correctly resolves compression
    /// pointers that reference earlier parts of the message.
    ///
    /// - Parameters:
    ///   - bytes: The full DNS message bytes.
    ///   - offset: Offset to the start of the name within the message.
    /// - Returns: The decoded dotted hostname, or nil on error.
    private func decodeDNSNameFromMessage(bytes: [UInt8], offset: Int) -> String? {
        var pos = offset
        var parts: [String] = []
        var jumps = 0
        let maxJumps = 256 // Prevent infinite loops from malformed packets

        while pos < bytes.count && jumps < maxJumps {
            let labelLen = bytes[pos]
            if labelLen == 0 { break }
            if (labelLen & 0xC0) == 0xC0 {
                // Compression pointer
                guard pos + 1 < bytes.count else { return nil }
                let ptrOffset = (Int(labelLen & 0x3F) << 8) | Int(bytes[pos + 1])
                guard ptrOffset < bytes.count else { return nil }
                pos = ptrOffset
                jumps += 1
            } else {
                let start = pos + 1
                let end = start + Int(labelLen)
                guard end <= bytes.count else { return nil }
                if let label = String(bytes: bytes[start..<end], encoding: .utf8) {
                    parts.append(label)
                }
                pos = end
            }
        }

        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }

    /// Extract all bytes from a pbuf into a single byte array.
    /// Used for decoding DNS names that may contain compression pointers
    /// referencing earlier parts of the message.
    private func extractAllBytes(from pbuf: Pbuf) -> [UInt8] {
        return extractBytes(from: pbuf, offset: 0, count: Int(pbuf.totLen))
    }
}
