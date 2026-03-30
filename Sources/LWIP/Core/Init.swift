//
//  Init.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Version Information

/// lwIP version numbers.
public enum LWIPVersion {
    /// Major version of the stack.
    public static let major: Int = 2
    /// Minor version of the stack.
    public static let minor: Int = 2
    /// Revision of the stack.
    public static let revision: Int = 2

    /// Release candidate marker:
    /// - 255 = official release
    /// - 0   = development version
    /// - 1..254 = release candidate
    public static let rc: Int = 0

    /// 255 for official releases.
    public static let rcRelease: Int = 255
    /// 0 for development versions.
    public static let rcDevelopment: Int = 0

    /// True if this is an official release build.
    public static var isRelease: Bool { rc == rcRelease }
    /// True if this is a development build.
    public static var isDevelopment: Bool { rc == rcDevelopment }
    /// True if this is a release candidate.
    public static var isRC: Bool { !isRelease && !isDevelopment }

    /// Packed 32-bit version number: (major<<24 | minor<<16 | revision<<8 | rc).
    public static var version: UInt32 {
        (UInt32(major) << 24) | (UInt32(minor) << 16) | (UInt32(revision) << 8) | UInt32(rc)
    }

    /// Human-readable version string (e.g. "2.2.2d" for development).
    public static var versionString: String {
        let suffix: String
        if isRelease {
            suffix = ""
        } else if isDevelopment {
            suffix = "d"
        } else {
            suffix = "rc\(rc)"
        }
        return "\(major).\(minor).\(revision)\(suffix)"
    }
}

// MARK: - LWIP Namespace

/// Top-level namespace for lwIP stack operations.
public enum LWIPStack {
    /// Initialize all lwIP modules with the global configuration.
    ///
    /// Call this once before using any lwIP functionality.
    /// In `NO_SYS` mode use this directly;
    /// use `TCPIP.shared.initialize()` for threaded mode.
    public static func initialize() {
        initialize(config: lwipConfig)
    }

    /// Initialize all lwIP modules with a custom configuration.
    public static func initialize(config: LWIPConfig) {
        initializeStack(config: config)
    }

    /// Run sanity checks on the current configuration.
    /// Returns an array of warning/error strings. An empty array means all checks passed.
    public static func validateConfiguration(config: LWIPConfig = lwipConfig) -> [String] {
        return validateConfig(config: config)
    }
}

// MARK: - Initialization

/// Internal initialization implementation.
internal func initializeStack(config: LWIPConfig) {
    // Store the configuration
    lwipConfig = config

    // Initialize core allocators and global state before protocol modules.
    Mem.initialize()
    Memp.initialize()
    NetworkInterface.initializeSubsystem()

    IPGlobals.shared.currentNetif = nil
    IPGlobals.shared.currentInputNetif = nil
    IPGlobals.shared.currentIPHeaderTotLen = 0
    IPGlobals.shared.currentSrcAddr = .v4(.any)
    IPGlobals.shared.currentDestAddr = .v4(.any)
    IPGlobals.shared.currentHeaderProto = 0

    // Initialize statistics
    LWIPStats.shared.initialize()

    // Initialize system abstraction
    if !config.noSys {
        LWIPSystem.initialize()
    }

    EthARP.initialize()
    IGMP.initialize()
    ND6.initialize()
    RawControlBlock.initialize()
    UDPGlobal.shared.initialize()
    TCPGlobal.shared.initialize()
    DNS.shared.initialize()
    Timeouts.shared.initialize()

    Debug.print(
        DebugFlags.on.rawValue,
        "lwIP \(LWIPVersion.versionString) initialized (Swift port)\n"
    )
}

// MARK: - Configuration validation

/// Internal validation implementation.
internal func validateConfig(config: LWIPConfig) -> [String] {
    var errors: [String] = []

    if config.udp == false && config.dhcp {
        errors.append("DHCP requires UDP to be enabled.")
    }
    if config.udp == false && config.dns {
        errors.append("DNS requires UDP to be enabled.")
    }
    if config.tcp {
        if config.tcpSndBuf < 2 * config.tcpMSS {
            errors.append("TCP_SND_BUF must be at least 2 * TCP_MSS.")
        }
        if config.tcpWnd < config.tcpMSS {
            errors.append("TCP_WND must be at least TCP_MSS.")
        }
        if config.tcpSndQueueLen < 2 {
            errors.append("TCP_SND_QUEUELEN must be at least 2.")
        }
        if config.tcpMaxRtx > 12 || config.tcpSynMaxRtx > 12 {
            errors.append("TCPConstants.maxRetransmissions and TCPConstants.synMaxRetransmissions must be <= 12.")
        }
    }
    if config.igmp && !config.ipv4 {
        errors.append("IGMP requires IPv4 to be enabled.")
    }
    if config.igmp && !config.multicastTxOptions {
        errors.append("IGMP requires LWIP_MULTICAST_TX_OPTIONS to be enabled.")
    }
    if (config.socketEnabled || config.netconnEnabled) && config.noSys {
        errors.append("Sequential API (sockets/netconn) requires NO_SYS=false.")
    }
    if config.tcpipCoreLockingInput && !config.tcpipCoreLocking {
        errors.append("LWIP_TCPIP_CORE_LOCKING_INPUT requires LWIP_TCPIP_CORE_LOCKING.")
    }

    // ---------------------------------------------------------------
    // Broadcast filter checks
    // ---------------------------------------------------------------

    if !config.ipSofBroadcast && config.ipSofBroadcastRecv {
        errors.append("IP_SOF_BROADCAST_RECV requires IP_SOF_BROADCAST to be enabled.")
    }

    // ---------------------------------------------------------------
    // UDP-lite / multicast dependency checks
    // ---------------------------------------------------------------

    if !config.udp && config.udpLite {
        errors.append("UDP Lite requires UDP to be enabled.")
    }

    if !config.udp && !config.raw && config.multicastTxOptions {
        errors.append("LWIP_MULTICAST_TX_OPTIONS requires UDP and/or RAW to be enabled.")
    }

    // ---------------------------------------------------------------
    // Pool allocator checks (only when not using heap for pools)
    // ---------------------------------------------------------------

    if !config.mempMemMalloc {
        if config.arp && config.arpQueueing && config.arpQueuePoolCount <= 0 {
            errors.append("ARP queueing requires MEMP_NUM_ARP_QUEUE >= 1.")
        }
        if config.raw && config.rawPCBPoolCount <= 0 {
            errors.append("RAW requires MEMP_NUM_RAW_PCB >= 1.")
        }
        if config.udp && config.udpPCBPoolCount <= 0 {
            errors.append("UDP requires MEMP_NUM_UDP_PCB >= 1.")
        }
        if config.tcp && config.tcpPCBPoolCount <= 0 {
            errors.append("TCP requires MEMP_NUM_TCP_PCB >= 1.")
        }
        if config.igmp && config.igmpGroupPoolCount <= 1 {
            errors.append("IGMP requires MEMP_NUM_IGMP_GROUP > 1.")
        }
        if (config.netconnEnabled || config.socketEnabled) && config.tcpipAPIMessagePoolCount <= 0 {
            errors.append("Sequential API requires MEMP_NUM_TCPIP_MSG_API >= 1.")
        }
        if config.ipReassembly && config.reassemblyPoolCount > config.ipReassMaxPbufs {
            errors.append("MEMP_NUM_REASSDATA > IP_REASS_MAX_PBUFS does not make sense; each reassembly needs at least 2 pbufs.")
        }
    }

    // ---------------------------------------------------------------
    // TCP window scaling checks
    // ---------------------------------------------------------------

    if config.tcpWindowScaling {
        if config.tcp && config.tcpWnd > 0xFFFF_FFFF {
            errors.append("TCP_WND must fit in a UInt32 when window scaling is enabled.")
        }
        if config.tcp && config.tcpReceiveWindowScale > 14 {
            errors.append("TCP_RCV_SCALE must not exceed 14.")
        }
        if config.tcp && config.tcpWnd > (0xFFFF << config.tcpReceiveWindowScale) {
            errors.append("TCP_WND is larger than LWIP_WND_SCALE allows.")
        }
        if config.tcp && (config.tcpWnd >> config.tcpReceiveWindowScale) == 0 {
            errors.append("TCP_WND is too small for the configured TCP_RCV_SCALE (results in zero window).")
        }
    } else {
        if config.tcp && config.tcpWnd > 0xFFFF {
            errors.append("TCP_WND must fit in a UInt16 (or enable window scaling).")
        }
    }

    // ---------------------------------------------------------------
    // TCP send queue checks
    // ---------------------------------------------------------------

    if config.tcp && config.tcpSndQueueLen > 0xFFFF {
        errors.append("TCP_SND_QUEUELEN must fit in a UInt16.")
    }

    // ---------------------------------------------------------------
    // TCP retransmission / backlog checks
    // ---------------------------------------------------------------

    if config.tcp && config.tcpListenBacklog
        && (config.tcpDefaultListenBacklog < 0 || config.tcpDefaultListenBacklog > 0xFF) {
        errors.append("TCP_DEFAULT_LISTEN_BACKLOG must fit in a UInt8 (0...255).")
    }

    // ---------------------------------------------------------------
    // TCP SACK checks
    // ---------------------------------------------------------------

    if config.tcp && config.tcpSackOut && !config.tcpQueueOoseq {
        errors.append("LWIP_TCP_SACK_OUT requires TCP_QUEUE_OOSEQ to be enabled.")
    }
    if config.tcp && config.tcpSackOut && config.tcpMaxSackNum < 1 {
        errors.append("LWIP_TCP_MAX_SACK_NUM must be at least 1.")
    }

    // ---------------------------------------------------------------
    // API / NO_SYS checks
    // ---------------------------------------------------------------

    if config.netifApiEnabled && config.noSys {
        errors.append("NETIF API requires NO_SYS=false.")
    }
    if config.pppApi && config.noSys {
        errors.append("PPP API requires NO_SYS=false.")
    }
    if config.pppApi && !config.pppSupport {
        errors.append("PPP API requires PPP_SUPPORT to be enabled.")
    }

    // ---------------------------------------------------------------
    // TCP event/callback API checks
    // ---------------------------------------------------------------

    if config.tcp {
        if config.eventApi && config.callbackApi {
            errors.append("Exactly one of LWIP_EVENT_API and LWIP_CALLBACK_API must be enabled, not both.")
        }
        if !config.eventApi && !config.callbackApi {
            errors.append("Exactly one of LWIP_EVENT_API and LWIP_CALLBACK_API must be enabled.")
        }
    }

    // ---------------------------------------------------------------
    // AltCP checks
    // ---------------------------------------------------------------

    if config.altcp && config.eventApi {
        errors.append("LWIP_ALTCP does not work with LWIP_EVENT_API.")
    }
    if config.altcp && !config.tcp {
        errors.append("LWIP_ALTCP requires TCP to be enabled.")
    }

    // ---------------------------------------------------------------
    // DHCP / AutoIP cooperation checks
    // ---------------------------------------------------------------

    if config.dhcpAutoipCoopTries > 0 && (!config.dhcp || !config.autoip) {
        errors.append("DHCP/AutoIP cooperation requires both LWIP_DHCP and LWIP_AUTOIP to be enabled.")
    }
    if config.dhcpDoesAcdCheck && (!config.dhcp || !config.arp || !config.acd) {
        errors.append("DHCP ACD checking requires LWIP_DHCP, LWIP_ARP, and LWIP_ACD to be enabled.")
    }
    if !config.arp && config.autoip {
        errors.append("AUTOIP requires ARP to be enabled.")
    }

    // ---------------------------------------------------------------
    // Ethernet dependency checks
    // ---------------------------------------------------------------

    if !config.ethernet && config.arp {
        errors.append("LWIP_ARP requires LWIP_ETHERNET to be enabled.")
    }
    if !config.ethernet && config.pppoeSupport {
        errors.append("PPPOE_SUPPORT requires LWIP_ETHERNET to be enabled.")
    }
    if config.bridgeEnabled && !config.ethernet {
        errors.append("Bridging requires LWIP_ETHERNET to be enabled.")
    }

    // ---------------------------------------------------------------
    // Memory allocator consistency checks
    // ---------------------------------------------------------------

    if config.memUsePools && config.memCustomAllocator {
        errors.append("MEM_USE_POOLS cannot be used together with MEM_CUSTOM_ALLOCATOR.")
    }
    if config.memUsePools && !config.mempUseCustomPools {
        errors.append("MEM_USE_POOLS requires MEMP_USE_CUSTOM_POOLS to be enabled.")
    }
    if config.mempMemMalloc && config.memUsePools {
        errors.append("MEMP_MEM_MALLOC and MEM_USE_POOLS cannot both be enabled.")
    }

    // ---------------------------------------------------------------
    // Pbuf pool buffer size check
    // ---------------------------------------------------------------

    if config.pbufPoolBufsize <= config.memAlignment {
        errors.append("PBUF_POOL_BUFSIZE must be greater than MEM_ALIGNMENT.")
    }

    // ---------------------------------------------------------------
    // PPP checks
    // ---------------------------------------------------------------

    if config.pppSupport && !config.ppposSupport && !config.pppoeSupport && !config.pppol2tpSupport {
        errors.append("PPP_SUPPORT requires at least one of PPPOS_SUPPORT, PPPOE_SUPPORT, or PPPOL2TP_SUPPORT.")
    }
    if config.pppSupport && !config.pppIpv4Support && !config.pppIpv6Support {
        errors.append("PPP_SUPPORT requires PPP_IPV4_SUPPORT and/or PPP_IPV6_SUPPORT.")
    }
    if config.pppSupport && config.pppIpv4Support && !config.ipv4 {
        errors.append("PPP_IPV4_SUPPORT requires LWIP_IPV4 to be enabled.")
    }
    if config.pppSupport && config.pppIpv6Support && !config.ipv6 {
        errors.append("PPP_IPV6_SUPPORT requires LWIP_IPV6 to be enabled.")
    }
    if config.pppSupport && config.ccpSupport && !config.mppeSupport {
        errors.append("CCP_SUPPORT requires MPPE_SUPPORT to be enabled.")
    }

    // ---------------------------------------------------------------
    // TCP single-pbuf TX check
    // ---------------------------------------------------------------

    if config.tcp && config.netifTxSinglePbuf && config.tcpOversize == 0 {
        errors.append("LWIP_NETIF_TX_SINGLE_PBUF requires TCP_OVERSIZE to be enabled (non-zero).")
    }

    // ---------------------------------------------------------------
    // Netconn full-duplex check
    // ---------------------------------------------------------------

    if config.netconnFullDuplex && !config.netconnSemPerThread {
        errors.append("LWIP_NETCONN_FULLDUPLEX requires LWIP_NETCONN_SEM_PER_THREAD.")
    }

    // ---------------------------------------------------------------
    // TCP sanity checks (matching lwip_sanity_check in C)
    // ---------------------------------------------------------------

    if config.tcp {
        if !config.mempMemMalloc && config.tcpSegmentPoolCount < config.tcpSndQueueLen {
            errors.append("MEMP_NUM_TCP_SEG should be at least as large as TCP_SND_QUEUELEN.")
        }
        if config.tcpSndQueueLen < 2 * (config.tcpSndBuf / config.tcpMSS) {
            errors.append("TCP_SND_QUEUELEN must be at least 2 * (TCP_SND_BUF / TCP_MSS).")
        }
        if config.tcpSndLowat >= config.tcpSndBuf {
            errors.append("TCP_SNDLOWAT must be less than TCP_SND_BUF.")
        }
        if config.tcpMSS >= (16 * 1024) - 1 {
            errors.append("TCP_MSS must be <= 16382 to prevent UInt16 underflow in TCP_SNDLOWAT calculation.")
        }
        if config.tcpSndLowat >= 0xFFFF - (4 * config.tcpMSS) {
            errors.append("TCP_SNDLOWAT must be at least 4*MSS below UInt16 overflow.")
        }
        if config.tcpSndQueueLowat >= config.tcpSndQueueLen {
            errors.append("TCP_SNDQUEUELOWAT must be less than TCP_SND_QUEUELEN.")
        }
        let totalHeaders = config.pbufLinkEncapsulationHlen + config.pbufLinkHlen + 20 + 20
        if !config.mempMemMalloc && config.pbufPoolCount > 0
            && config.pbufPoolBufsize <= totalHeaders {
            errors.append(
                "PBUF_POOL_BUFSIZE does not provide enough space for protocol headers."
            )
        }
        if !config.mempMemMalloc && config.pbufPoolCount > 0
            && config.tcpWnd > config.pbufPoolCount * (config.pbufPoolBufsize - totalHeaders) {
            errors.append(
                "TCP_WND is larger than space provided by PBUF_POOL_SIZE * (PBUF_POOL_BUFSIZE - protocol headers)."
            )
        }
    }

    // ---------------------------------------------------------------
    // IPv6 dependency checks
    // ---------------------------------------------------------------

    if config.ipv6MLD && !config.ipv6 {
        errors.append("MLD6 requires LWIP_IPV6 to be enabled.")
    }
    if config.ipv6Dhcp6 && !config.ipv6 {
        errors.append("DHCPv6 requires LWIP_IPV6 to be enabled.")
    }

    return errors
}
