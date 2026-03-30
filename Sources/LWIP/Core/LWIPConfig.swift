//
//  LWIPConfig.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

/// lwIP compile-time configuration.
///
/// To override defaults, create a new `LWIPConfig` value via `LWIPConfig.default`
/// and mutate the properties you need before passing it to `LWIPStack.initialize(config:)`.
/// The static constants below represent the "factory" defaults from lwIP.
public struct LWIPConfig: Sendable {

    // MARK: - NO_SYS

    /// When `true`, use lwIP without OS-awareness (no threads, semaphores, mutexes, or mboxes).
    public var noSys: Bool = false

    // MARK: - Timers

    /// Enable sys_timeout and lwip-internal cyclic timers.
    public var timers: Bool = true
    /// Set to `true` to provide your own timer implementation.
    public var timersCustom: Bool = false

    // MARK: - Core locking

    /// Enable MPU-compatible mode.
    public var mpuCompatible: Bool = false
    /// Create a global mutex held during TCPIP thread operations.
    public var tcpipCoreLocking: Bool = true
    /// Grab the core lock for input packets too.
    public var tcpipCoreLockingInput: Bool = false
    /// Enable inter-task protection for critical regions.
    public var sysLightweightProt: Bool = true

    // MARK: - Memory options

    /// Memory alignment in bytes.
    public var memAlignment: Int = 4
    /// Size of the heap memory in bytes.
    public var memSize: Int = 1600
    /// Use the heap allocator for all pool allocations.
    public var mempMemMalloc: Bool = false
    /// Use memory pools for heap allocation.
    public var memUsePools: Bool = false
    /// Use custom pool definitions.
    public var mempUseCustomPools: Bool = false
    /// Use a custom allocator (libc malloc or user-provided).
    public var memCustomAllocator: Bool = false

    // MARK: - Internal memory pool sizes

    public var pbufPoolCount: Int = 16
    public var rawPCBPoolCount: Int = 4
    public var udpPCBPoolCount: Int = 4
    public var tcpPCBPoolCount: Int = 5
    public var tcpListenPCBPoolCount: Int = 8
    public var tcpSegmentPoolCount: Int = 16
    public var reassemblyPoolCount: Int = 5
    public var fragmentBufferPoolCount: Int = 15
    public var arpQueuePoolCount: Int = 30
    public var igmpGroupPoolCount: Int = 8
    public var netbufPoolCount: Int = 2
    public var netconnPoolCount: Int = 4
    public var selectCallbackPoolCount: Int = 4
    public var tcpipAPIMessagePoolCount: Int = 8
    public var tcpipInputMessagePoolCount: Int = 8
    public var netdbPoolCount: Int = 1
    public var localhostListPoolCount: Int = 1
    public var pbufBufferPoolCount: Int = 16

    // MARK: - ARP options

    public var arp: Bool = true
    public var arpTableSize: Int = 10
    public var arpMaxAge: Int = 300
    public var arpQueueing: Bool = false
    public var arpQueueLen: Int = 3
    public var etharpSupportVlan: Bool = false
    public var ethernet: Bool = true

    // MARK: - Broadcast filter options

    /// Per-PCB broadcast filter on send.
    public var ipSofBroadcast: Bool = false
    /// Per-PCB broadcast filter on receive.
    public var ipSofBroadcastRecv: Bool = false

    // MARK: - IPv4 options

    public var ipv4: Bool = true
    public var ipForward: Bool = false
    public var ipReassembly: Bool = true
    public var ipFrag: Bool = true
    public var ipOptionsAllowed: Bool = true
    public var ipReassMaxAge: Int = 15
    public var ipReassMaxPbufs: Int = 10
    public var ipDefaultTTL: Int = 255

    // MARK: - ICMP options

    public var icmp: Bool = true
    public var icmpTTL: Int = 255
    public var broadcastPing: Bool = false
    public var multicastPing: Bool = false

    // MARK: - RAW options

    public var raw: Bool = false
    public var rawTTL: Int = 255

    // MARK: - DHCP options

    public var dhcp: Bool = false
    public var dhcpDoesAcdCheck: Bool = false

    // MARK: - AUTOIP options

    public var autoip: Bool = false
    /// Enable DHCP/AutoIP cooperation: start AutoIP after this many DHCP discover attempts.
    /// Set to 0 to disable.
    public var dhcpAutoipCoopTries: UInt8 = 0

    // MARK: - ACD options

    public var acd: Bool = false

    // MARK: - IGMP options

    public var igmp: Bool = true
    /// Enable IGMPv3 source-specific multicast support.
    public var igmpV3: Bool = true

    // MARK: - DNS options

    public var dns: Bool = false
    public var dnsMaxServers: Int = 2
    /// Maximum number of concurrent pending DNS queries.
    public var dnsTableSize: Int = 4
    /// Maximum number of cached DNS entries.
    public var dnsCacheSize: Int = 4
    /// Use cryptographically random transaction IDs for DNS queries.
    public var dnsSecureRandomTxID: Bool = true
    /// Use randomized source ports for DNS queries (mitigates cache poisoning).
    public var dnsSecureRandomSourcePort: Bool = true
    /// Route queries for `.local` hostnames to mDNS multicast (RFC 6762).
    public var dnsSupportMdnsQueries: Bool = true
    /// Retry DNS queries that arrive with the TC (truncation) flag set.
    /// When enabled, a truncated UDP response is discarded and the query is
    /// retried (potentially to the next server).
    public var dnsRetryOnTruncation: Bool = true

    // MARK: - UDP options

    public var udp: Bool = true
    public var udpLite: Bool = false
    public var udpTTL: Int = 255

    // MARK: - TCP options

    public var tcp: Bool = true
    public var tcpTTL: Int = 255
    public var tcpMaxRtx: Int = 12
    public var tcpSynMaxRtx: Int = 6
    public var tcpQueueOoseq: Bool = true
    public var tcpMSS: Int = 536
    public var tcpSndBuf: Int = 256 * 6
    public var tcpSndQueueLen: Int = (4 * (256 * 6) / 536)
    public var tcpSndLowat: Int = max((2 * (256 * 6)) / 5, (256 * 6) - (4 * 536) - 1)
    public var tcpWnd: Int = 4 * 536
    public var tcpWndUpdateThreshold: Int = min(4 * 536 / 4, 536 * 4)
    public var tcpListenBacklog: Bool = false
    public var tcpDefaultListenBacklog: Int = 0xFF
    public var tcpOversize: Int = 536
    /// TCP receive window scale factor (shift count). When window scaling
    /// is negotiated, the advertised window is ``tcpWnd`` >> ``tcpReceiveWindowScale``.
    /// Must be in range 0...14.
    public var tcpReceiveWindowScale: UInt8 = 0
    /// Enable TCP window scaling (RFC 7323).
    public var tcpWindowScaling: Bool = false
    /// Enable TCP SACK output (RFC 2018).
    public var tcpSackOut: Bool = false
    /// Maximum number of SACK ranges reported.
    public var tcpMaxSackNum: Int = 4
    /// TCP_SNDQUEUELOWAT: low-watermark for send queue length.
    public var tcpSndQueueLowat: Int = 5
    /// Enable single-pbuf TX optimization.
    public var netifTxSinglePbuf: Bool = false
    /// Maximum bytes queued on ooseq per connection (0 = no limit).
    public var tcpOoseqBytesLimit: Int = 0
    /// Maximum pbufs queued on ooseq per connection (0 = no limit).
    public var tcpOoseqPbufsLimit: Int = 0

    // MARK: - IPv6 options

    public var ipv6: Bool = true
    public var ipv6Scopes: Bool = true
    public var ipv6ScopesDebug: Bool = false
    public var ipv6NumAddresses: Int = 3
    public var ipv6ForwardEnabled: Bool = false
    public var ipv6FragEnabled: Bool = true
    public var ipv6ReassMaxPbufs: Int = 10
    public var ipv6AddressLifetimes: Bool = true
    public var ipv6Dhcp6: Bool = false

    // MARK: - Pbuf options

    public var pbufLinkHlen: Int = 14 + 0 // ETH_PAD_SIZE = 0
    public var pbufLinkEncapsulationHlen: Int = 0
    public var pbufPoolBufsize: Int = 256 // LWIP_MEM_ALIGN_SIZE(TCP_MSS+40+...)

    // MARK: - Network interface options

    public var netifHostname: Bool = false
    public var netifApiEnabled: Bool = false
    public var singleNetif: Bool = false
    public var numNetifs: Int = 1

    // MARK: - LOOPIF options

    public var loopbackEnabled: Bool = false
    public var loopbackMaxPbufs: Int = 0

    // MARK: - Socket options

    public var socketEnabled: Bool = true
    public var netconnEnabled: Bool = true
    /// Enable full-duplex netconn API.
    public var netconnFullDuplex: Bool = false
    /// Require per-thread semaphore for netconn.
    public var netconnSemPerThread: Bool = false

    // MARK: - TCP API style

    /// Use event-based TCP API.
    public var eventApi: Bool = false
    /// Use callback-based TCP API.
    public var callbackApi: Bool = true

    // MARK: - AltCP options

    /// Enable the application-layered TCP API.
    public var altcp: Bool = false

    // MARK: - Bridge options

    /// Enable Ethernet bridging.
    public var bridgeEnabled: Bool = false

    // MARK: - Multicast

    public var multicastTxOptions: Bool = true

    // MARK: - PPP options

    public var pppSupport: Bool = false
    /// PPP over Serial.
    public var ppposSupport: Bool = false
    /// PPP over Ethernet.
    public var pppoeSupport: Bool = false
    /// PPP over L2TP.
    public var pppol2tpSupport: Bool = false
    /// PPP IPv4 support.
    public var pppIpv4Support: Bool = true
    /// PPP IPv6 support.
    public var pppIpv6Support: Bool = false
    /// CCP (compression) support.
    public var ccpSupport: Bool = false
    /// MPPE encryption support.
    public var mppeSupport: Bool = false
    /// Enable the PPP API (requires !noSys).
    public var pppApi: Bool = false

    // MARK: - Checksum options

    public var checksumCheckIP: Bool = true
    public var checksumCheckUDP: Bool = true
    public var checksumCheckTCP: Bool = true
    public var checksumCheckICMP: Bool = true
    public var checksumCheckICMP6: Bool = true
    public var checksumGenIP: Bool = true
    public var checksumGenUDP: Bool = true
    public var checksumGenTCP: Bool = true
    public var checksumGenICMP: Bool = true
    public var checksumGenICMP6: Bool = true

    // MARK: - Statistics

    public var stats: Bool = true
    public var statsDisplay: Bool = false
    public var statsLarge: Bool = false
    public var linkStats: Bool = true
    public var etharpStats: Bool = true
    public var ipStats: Bool = true
    public var ipFragStats: Bool = true
    public var icmpStats: Bool = true
    public var igmpStats: Bool = true
    public var udpStats: Bool = true
    public var tcpStats: Bool = true
    public var memStats: Bool = true
    public var mempStats: Bool = true
    public var sysStats: Bool = true
    public var ip6Stats: Bool = true
    public var icmp6Stats: Bool = true
    public var ip6FragStats: Bool = true
    public var mld6Stats: Bool = true
    public var nd6Stats: Bool = true
    public var mib2Stats: Bool = false

    // MARK: - Debugging flags

    public var debugEnabled: Bool = {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }()

    // MARK: - Initialization

    /// The default configuration matching lwIP's `opt.h` defaults.
    // MARK: - ND6 options

    public var nd6NumNeighbors: Int = 10
    public var nd6NumDestinations: Int = 10
    public var nd6NumPrefixes: Int = 5
    public var nd6NumRouters: Int = 3
    public var nd6MaxMulticastSolicit: Int = 3
    public var nd6DelayFirstProbeTime: UInt32 = 5000
    public var nd6ReachableTime: UInt32 = 30000
    public var nd6RetransTimer: UInt32 = 1000
    public var nd6AllowRAUpdates: Bool = true
    public var nd6TCPReachabilityHints: Bool = true
    public var nd6RDNSSMaxDNSServers: Int = 0
    public var nd6Queueing: Bool = true

    // MARK: - MLD6 options

    public var ipv6MLD: Bool = true

    // MARK: - Router solicitation

    public var ipv6SendRouterSolicit: Bool = true

    // MARK: - Autoconfig

    public var ipv6Autoconfig: Bool = true

    // MARK: - DAD

    public var ipv6DupDetectAttempts: UInt8 = 1

    // MARK: - Multicast ping

    public var multicastPingEnabled: Bool = false

    public static let `default` = LWIPConfig()

    public init() {}
}

/// The active lwIP configuration. Initialized to defaults.
/// Set this before calling `LWIPStack.initialize()` to customize behavior.
nonisolated(unsafe) public var lwipConfig = LWIPConfig.default

// MARK: - Static convenience accessors for LWIPConfig

extension LWIPConfig {
    /// Convenience static accessors reading from the global `lwipConfig`.
    @inlinable public static var ipv6Forward: Bool { lwipConfig.ipv6ForwardEnabled }
    @inlinable public static var ipv6MLD: Bool { lwipConfig.ipv6MLD }
    @inlinable public static var ipv6Frag: Bool { lwipConfig.ipv6FragEnabled }
    @inlinable public static var ipv6Reassembly: Bool { lwipConfig.ipv6FragEnabled }
    @inlinable public static var ipv6DHCPv6: Bool { lwipConfig.ipv6Dhcp6 }
    @inlinable public static var multicastPing: Bool { lwipConfig.multicastPingEnabled }
    @inlinable public static var checksumCheckICMPv6: Bool { lwipConfig.checksumCheckICMP6 }
    @inlinable public static var checksumGenICMPv6: Bool { lwipConfig.checksumGenICMP6 }
    @inlinable public static var ipv6SendRouterSolicit: Bool { lwipConfig.ipv6SendRouterSolicit }
    @inlinable public static var nd6NumNeighbors: Int { lwipConfig.nd6NumNeighbors }
    @inlinable public static var nd6NumDestinations: Int { lwipConfig.nd6NumDestinations }
    @inlinable public static var nd6NumPrefixes: Int { lwipConfig.nd6NumPrefixes }
    @inlinable public static var nd6NumRouters: Int { lwipConfig.nd6NumRouters }
    @inlinable public static var nd6MaxMulticastSolicit: Int { lwipConfig.nd6MaxMulticastSolicit }
    @inlinable public static var nd6DelayFirstProbeTime: UInt32 { lwipConfig.nd6DelayFirstProbeTime }
    @inlinable public static var ipv6DupDetectAttempts: UInt8 { lwipConfig.ipv6DupDetectAttempts }
    @inlinable public static var ipv6Autoconfig: Bool { lwipConfig.ipv6Autoconfig }
}
