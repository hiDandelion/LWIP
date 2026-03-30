//
//  Stats.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Protocol statistics

/// Statistics for a single protocol (IP, TCP, UDP, ICMP, etc.).
public struct ProtocolStats: Sendable {
    /// Transmitted packets.
    public var transmitted: UInt32 = 0
    /// Received packets.
    public var received: UInt32 = 0
    /// Forwarded packets.
    public var forwarded: UInt32 = 0
    /// Dropped packets.
    public var dropped: UInt32 = 0
    /// Checksum errors.
    public var checksumErrors: UInt32 = 0
    /// Invalid length errors.
    public var lengthErrors: UInt32 = 0
    /// Out of memory errors.
    public var memoryErrors: UInt32 = 0
    /// Routing errors.
    public var routingErrors: UInt32 = 0
    /// Protocol errors.
    public var protocolErrors: UInt32 = 0
    /// Option errors.
    public var optionErrors: UInt32 = 0
    /// Miscellaneous errors.
    public var errors: UInt32 = 0
    /// Cache hits.
    public var cacheHits: UInt32 = 0

    public init() {}
}

// MARK: - IGMP / MLD statistics

/// Statistics for IGMP / MLD protocols.
public struct IGMPStats: Sendable {
    /// Transmitted packets.
    public var transmitted: UInt32 = 0
    /// Received packets.
    public var received: UInt32 = 0
    /// Dropped packets.
    public var dropped: UInt32 = 0
    /// Checksum errors.
    public var checksumErrors: UInt32 = 0
    /// Invalid length errors.
    public var lengthErrors: UInt32 = 0
    /// Out of memory errors.
    public var memoryErrors: UInt32 = 0
    /// Protocol errors.
    public var protocolErrors: UInt32 = 0
    /// Received v1 messages.
    public var receivedV1: UInt32 = 0
    /// Received group-specific messages.
    public var receivedGroup: UInt32 = 0
    /// Received general queries.
    public var receivedGeneral: UInt32 = 0
    /// Received reports.
    public var receivedReport: UInt32 = 0
    /// Transmitted join messages.
    public var transmittedJoin: UInt32 = 0
    /// Transmitted leave messages.
    public var transmittedLeave: UInt32 = 0
    /// Transmitted reports.
    public var transmittedReport: UInt32 = 0

    public init() {}
}

// MARK: - Memory statistics

/// Statistics for a memory allocator (heap or pool).
public struct MemoryStats: Sendable {
    /// Human-readable name for this allocator.
    public var name: String
    /// Number of allocation errors.
    public var errors: UInt32 = 0
    /// Total available memory.
    public var available: Int = 0
    /// Currently used memory.
    public var used: Int = 0
    /// Peak used memory (high water mark).
    public var peak: Int = 0
    /// Number of illegal free operations.
    public var illegal: UInt32 = 0

    public init(name: String = "") {
        self.name = name
    }
}

// MARK: - System element statistics

/// Statistics for a system element type (semaphores, mutexes, mailboxes).
public struct SysElementStats: Sendable {
    /// Currently in use.
    public var used: UInt32 = 0
    /// Maximum ever in use.
    public var max: UInt32 = 0
    /// Errors.
    public var err: UInt32 = 0

    public init() {}
}

// MARK: - System statistics

/// Aggregate system resource statistics.
public struct SystemStats: Sendable {
    public var sem: SysElementStats = SysElementStats()
    public var mutex: SysElementStats = SysElementStats()
    public var mbox: SysElementStats = SysElementStats()

    public init() {}
}

// MARK: - MIB2 statistics

/// SNMP MIB2 counters.
public struct MIB2Stats: Sendable {
    // IPv4
    public var ipInHdrErrors: UInt32 = 0
    public var ipInAddrErrors: UInt32 = 0
    public var ipInUnknownProtos: UInt32 = 0
    public var ipInDiscards: UInt32 = 0
    public var ipInDelivers: UInt32 = 0
    public var ipOutRequests: UInt32 = 0
    public var ipOutDiscards: UInt32 = 0
    public var ipOutNoRoutes: UInt32 = 0
    public var ipReasmOks: UInt32 = 0
    public var ipReasmFails: UInt32 = 0
    public var ipFragOks: UInt32 = 0
    public var ipFragFails: UInt32 = 0
    public var ipFragCreates: UInt32 = 0
    public var ipReasmReqds: UInt32 = 0
    public var ipForwDatagrams: UInt32 = 0
    public var ipInReceives: UInt32 = 0
    // IPv6
    public var ip6ReasmOks: UInt32 = 0
    // TCP
    public var tcpActiveOpens: UInt32 = 0
    public var tcpPassiveOpens: UInt32 = 0
    public var tcpAttemptFails: UInt32 = 0
    public var tcpEstabResets: UInt32 = 0
    public var tcpOutSegs: UInt32 = 0
    public var tcpRetransSegs: UInt32 = 0
    public var tcpInSegs: UInt32 = 0
    public var tcpInErrs: UInt32 = 0
    public var tcpOutRsts: UInt32 = 0
    // UDP
    public var udpInDatagrams: UInt32 = 0
    public var udpNoPorts: UInt32 = 0
    public var udpInErrors: UInt32 = 0
    public var udpOutDatagrams: UInt32 = 0
    // ICMP
    public var icmpInMsgs: UInt32 = 0
    public var icmpInErrors: UInt32 = 0
    public var icmpInDestUnreachs: UInt32 = 0
    public var icmpInTimeExcds: UInt32 = 0
    public var icmpInParmProbs: UInt32 = 0
    public var icmpInSrcQuenchs: UInt32 = 0
    public var icmpInRedirects: UInt32 = 0
    public var icmpInEchos: UInt32 = 0
    public var icmpInEchoReps: UInt32 = 0
    public var icmpInTimestamps: UInt32 = 0
    public var icmpInTimestampReps: UInt32 = 0
    public var icmpInAddrMasks: UInt32 = 0
    public var icmpInAddrMaskReps: UInt32 = 0
    public var icmpOutMsgs: UInt32 = 0
    public var icmpOutErrors: UInt32 = 0
    public var icmpOutDestUnreachs: UInt32 = 0
    public var icmpOutTimeExcds: UInt32 = 0
    public var icmpOutEchos: UInt32 = 0
    public var icmpOutEchoReps: UInt32 = 0

    public init() {}
}

// MARK: - MIB2 network interface counters

/// SNMP MIB2 per-interface counters.
public struct MIB2NetifCounters: Sendable {
    public var ifInOctets: UInt32 = 0
    public var ifInUcastPkts: UInt32 = 0
    public var ifInNUcastPkts: UInt32 = 0
    public var ifInDiscards: UInt32 = 0
    public var ifInErrors: UInt32 = 0
    public var ifInUnknownProtos: UInt32 = 0
    public var ifOutOctets: UInt32 = 0
    public var ifOutUcastPkts: UInt32 = 0
    public var ifOutNUcastPkts: UInt32 = 0
    public var ifOutDiscards: UInt32 = 0
    public var ifOutErrors: UInt32 = 0

    public init() {}
}

// MARK: - Aggregate statistics container

/// The global lwIP statistics container.
/// In the Swift port, all fields are always present (not conditionally compiled).
/// Check `lwipConfig.stats` before recording if you want to match the C behavior.
public final class LWIPStats: @unchecked Sendable {
    // Protocol stats
    public var link: ProtocolStats = ProtocolStats()
    public var etharp: ProtocolStats = ProtocolStats()
    public var ipFrag: ProtocolStats = ProtocolStats()
    public var ip: ProtocolStats = ProtocolStats()
    public var icmp: ProtocolStats = ProtocolStats()
    public var igmp: IGMPStats = IGMPStats()
    public var udp: ProtocolStats = ProtocolStats()
    public var tcp: ProtocolStats = ProtocolStats()

    // Memory stats
    public var mem: MemoryStats = MemoryStats(name: "MEM")

    // System stats
    public var sys: SystemStats = SystemStats()

    // IPv6 stats
    public var ip6: ProtocolStats = ProtocolStats()
    public var icmp6: ProtocolStats = ProtocolStats()
    public var ip6Frag: ProtocolStats = ProtocolStats()
    public var mld6: IGMPStats = IGMPStats()
    public var nd6: ProtocolStats = ProtocolStats()

    // MIB2 stats
    public var mib2: MIB2Stats = MIB2Stats()

    public init() {}

    /// Reset all statistics to zero.
    public func reset() {
        link = ProtocolStats()
        etharp = ProtocolStats()
        ipFrag = ProtocolStats()
        ip = ProtocolStats()
        icmp = ProtocolStats()
        igmp = IGMPStats()
        udp = ProtocolStats()
        tcp = ProtocolStats()
        mem = MemoryStats(name: "MEM")
        sys = SystemStats()
        ip6 = ProtocolStats()
        icmp6 = ProtocolStats()
        ip6Frag = ProtocolStats()
        mld6 = IGMPStats()
        nd6 = ProtocolStats()
        mib2 = MIB2Stats()
    }
}

extension LWIPStats {
    /// The global statistics instance.
    public static let shared = LWIPStats()
}

// MARK: - Stats initialization

extension LWIPStats {
    /// Initialize the statistics module.
    public func initialize() {
        mem.name = "MEM"
    }
}

// MARK: - Display helpers

extension ProtocolStats {
    /// Print a summary of this protocol's statistics.
    public func display(name: String) {
        Debug.platformDiagnostic("""

            \(name)
            \ttransmitted: \(transmitted)
            \treceived: \(received)
            \tforwarded: \(forwarded)
            \tdropped: \(dropped)
            \tchecksumErrors: \(checksumErrors)
            \tlengthErrors: \(lengthErrors)
            \tmemoryErrors: \(memoryErrors)
            \troutingErrors: \(routingErrors)
            \tprotocolErrors: \(protocolErrors)
            \toptionErrors: \(optionErrors)
            \terrors: \(errors)
            \tcacheHits: \(cacheHits)

            """)
    }
}

extension IGMPStats {
    /// Print a summary of IGMP/MLD statistics.
    public func display(name: String) {
        Debug.platformDiagnostic("""

            \(name)
            \txmit: \(transmitted)
            \trecv: \(received)
            \tdrop: \(dropped)
            \tchkerr: \(checksumErrors)
            \tlenerr: \(lengthErrors)
            \tmemerr: \(memoryErrors)
            \tproterr: \(protocolErrors)
            \trx_v1: \(receivedV1)
            \trx_group: \(receivedGroup)
            \trx_general: \(receivedGeneral)
            \trx_report: \(receivedReport)
            \ttx_join: \(transmittedJoin)
            \ttx_leave: \(transmittedLeave)
            \ttx_report: \(transmittedReport)

            """)
    }
}

extension MemoryStats {
    /// Print a summary of memory statistics.
    public func display() {
        Debug.platformDiagnostic("""

            MEM \(name)
            \tavail: \(available)
            \tused: \(used)
            \tmax: \(peak)
            \terr: \(errors)

            """)
    }
}

extension SystemStats {
    /// Print system resource statistics.
    public func display() {
        Debug.platformDiagnostic("""

            SYS
            \tsem.used: \(sem.used)
            \tsem.max: \(sem.max)
            \tsem.err: \(sem.err)
            \tmutex.used: \(mutex.used)
            \tmutex.max: \(mutex.max)
            \tmutex.err: \(mutex.err)
            \tmbox.used: \(mbox.used)
            \tmbox.max: \(mbox.max)
            \tmbox.err: \(mbox.err)

            """)
    }
}

extension LWIPStats {
    /// Print all statistics.
    public func display() {
        link.display(name: "LINK")
        etharp.display(name: "ETHARP")
        ipFrag.display(name: "IP_FRAG")
        ip6Frag.display(name: "IPv6 FRAG")
        ip.display(name: "IP")
        nd6.display(name: "ND")
        ip6.display(name: "IPv6")
        igmp.display(name: "IGMP")
        mld6.display(name: "MLDv1")
        icmp.display(name: "ICMP")
        icmp6.display(name: "ICMPv6")
        udp.display(name: "UDP")
        tcp.display(name: "TCP")
        mem.display()
        sys.display()
    }
}
