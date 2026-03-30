//
//  IGMP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IGMP Constants

/// Namespace for IGMP protocol constants.
public enum IGMPConstants {
    /// Timer interval in milliseconds.
    public static let timerInterval: UInt16 = 100
    /// V1 delaying member timer (in ticks).
    public static let v1DelayingMemberTimer: UInt8 = UInt8(1000 / Int(timerInterval))
    /// Join delaying member timer (in ticks).
    public static let joinDelayingMemberTimer: UInt8 = UInt8(500 / Int(timerInterval))
    /// TTL value for IGMP packets.
    public static let timeToLive: UInt8 = 1
    /// Minimum message length (IGMPv2 header size).
    public static let minimumLength: UInt16 = 8
    /// Minimum IGMPv3 query length (12 bytes: 8-byte base header + 4 bytes of v3 fields).
    public static let v3QueryMinLength: UInt16 = 12
    /// Router alert option value.
    public static let routerAlert: UInt16 = 0x9404
    /// Router alert option length.
    public static let routerAlertLength: UInt16 = 4
    /// IGMPv3 Membership Report header size (type + reserved + checksum + reserved + numRecords).
    public static let v3ReportHeaderLength: UInt16 = 8
    /// IGMPv3 group record header size (record type + aux data len + num sources + group address).
    public static let v3GroupRecordHeaderLength: UInt16 = 8
    /// IGMPv3 report destination: 224.0.0.22
    public static let v3ReportAddress = IPv4Address(224, 0, 0, 22)
    /// Default IGMPv2 compatibility timeout in ticks (400 seconds / timerInterval).
    public static let v2CompatibilityTimeout: UInt16 = UInt16(400_000 / Int(timerInterval))
}

// MARK: - IGMP Message Types

/// IGMP message type codes.
public enum IGMPMessageType: UInt8, Sendable {
    case membershipQuery    = 0x11
    case v1MemberReport     = 0x12
    case v2MemberReport     = 0x16
    case leaveGroup         = 0x17
    case v3MemberReport     = 0x22
}

// MARK: - IGMPv3 Record Types

/// IGMPv3 group record types (RFC 3376 Section 4.2.12).
public enum IGMPv3RecordType: UInt8, Sendable {
    case modeIsInclude     = 1
    case modeIsExclude     = 2
    case changeToInclude   = 3
    case changeToExclude   = 4
    case allowNewSources   = 5
    case blockOldSources   = 6
}

// MARK: - IGMPv3 Group Record

/// IGMPv3 group record for Membership Reports.
public struct IGMPv3GroupRecord {
    public var recordType: IGMPv3RecordType
    public var auxDataLen: UInt8
    public var groupAddress: IPv4Address
    public var sources: [IPv4Address]

    public init(recordType: IGMPv3RecordType, auxDataLen: UInt8 = 0,
                groupAddress: IPv4Address, sources: [IPv4Address] = []) {
        self.recordType = recordType
        self.auxDataLen = auxDataLen
        self.groupAddress = groupAddress
        self.sources = sources
    }
}

// MARK: - IGMPv3 Query

/// IGMPv3 Membership Query (variable length).
public struct IGMPv3Query {
    public var maxResponseCode: UInt8    // May use floating-point encoding
    public var groupAddress: IPv4Address
    public var suppressRouterProcessing: Bool
    public var qrv: UInt8                // Querier's Robustness Variable
    public var qqic: UInt8               // Querier's Query Interval Code
    public var sources: [IPv4Address]    // Source list for group-source queries

    public init() {
        maxResponseCode = 0
        groupAddress = .any
        suppressRouterProcessing = false
        qrv = 0
        qqic = 0
        sources = []
    }
}

// MARK: - IGMPv3 Filter Mode

/// Filter mode for IGMPv3 source filtering.
public enum IGMPFilterMode: Sendable {
    case include  // Only receive from listed sources
    case exclude  // Receive from all EXCEPT listed sources
}

// MARK: - IGMP Group State

/// Group membership states.
public enum IGMPGroupState: UInt8, Sendable {
    case nonMember      = 0
    case delayingMember = 1
    case idleMember     = 2
}

// MARK: - IGMP Message

/// IGMP packet format (8 bytes).
public struct IGMPMessage {
    public var messageType: UInt8
    public var maximumResponseTime: UInt8
    public var checksum: UInt16
    public var groupAddress: IPv4Address

    public init() {
        messageType = 0
        maximumResponseTime = 0
        checksum = 0
        groupAddress = .any
    }

    public static let size: Int = 8
}

// MARK: - IGMP Group

/// Represents an IGMP multicast group membership on an interface.
public final class IGMPGroup {
    /// Next group in the linked list.
    public var next: IGMPGroup?
    /// The multicast group address.
    public var groupAddress: IPv4Address
    /// Whether we were the last to report.
    public var lastReporterFlag: Bool
    /// Current state of the group.
    public var groupState: IGMPGroupState
    /// Timer for reporting (in ticks of IGMPConstants.timerInterval).
    public var timer: UInt16
    /// Reference count (number of simultaneous uses).
    public var use: UInt8

    // MARK: IGMPv3 source filtering state

    /// Filter mode for IGMPv3 source filtering.
    public var filterMode: IGMPFilterMode = .exclude
    /// Source list for IGMPv3 source-specific multicast.
    public var sourceList: [IPv4Address] = []
    /// Tracks compatibility mode for this group (2 = IGMPv2, 3 = IGMPv3).
    public var igmpVersion: UInt8 = 2

    public init(address: IPv4Address = .any) {
        self.groupAddress = address
        self.lastReporterFlag = false
        self.groupState = .nonMember
        self.timer = 0
        self.use = 0
        self.next = nil
    }
}

// MARK: - IGMP Module

/// IGMP protocol implementation (IGMPv2 + IGMPv3 RFC 3376).
public enum IGMP {

    /// All-systems multicast address: 224.0.0.1
    public static let allSystems = IPv4Address(224, 0, 0, 1)

    /// All-routers multicast address: 224.0.0.2
    public static let allRouters = IPv4Address(224, 0, 0, 2)

    /// Per-interface IGMPv2 compatibility timer (ticks remaining).
    /// When non-zero, the interface operates in IGMPv2 compatibility mode.
    private static var v2CompatibilityTimers: [ObjectIdentifier: UInt16] = [:]

    // MARK: - Initialization

    /// Initialize the IGMP module. Call once at startup.
    public static func initialize() {
        // Constants are statically initialized
    }

    // MARK: - Start / Stop

    /// Start IGMP processing on an interface.
    ///
    /// - Parameter netif: The network interface.
    /// - Returns: `.ok` on success, `.outOfMemory` on allocation failure.
    public static func start(on netif: NetworkInterface) -> LWIPError {
        guard let group = lookupGroup(on: netif, addr: allSystems) else {
            return .outOfMemory
        }

        group.groupState = .idleMember
        group.use += 1

        if lwipConfig.igmpV3 {
            group.igmpVersion = 3
        }

        // Allow IGMP messages at the MAC level
        _ = netif.igmpMacFilter?(netif, allSystems, .add)

        return .ok
    }

    /// Stop IGMP processing on an interface, freeing all groups.
    ///
    /// - Parameter netif: The network interface.
    /// - Returns: `.ok`
    @discardableResult
    public static func stop(on netif: NetworkInterface) -> LWIPError {
        var group = netif.igmpData
        netif.igmpData = nil

        while let g = group {
            let next = g.next
            _ = netif.igmpMacFilter?(netif, g.groupAddress, .delete)
            group = next
        }

        v2CompatibilityTimers.removeValue(forKey: ObjectIdentifier(netif))
        return .ok
    }

    // MARK: - Report Groups

    /// Re-report all group memberships on an interface (e.g., after link up).
    public static func reportGroups(on netif: NetworkInterface) {
        if lwipConfig.igmpV3 && !isV2CompatibilityMode(netif) {
            // Send a single IGMPv3 report covering all groups
            var groups: [IGMPGroup] = []
            var group = netif.igmpData?.next
            while let g = group {
                groups.append(g)
                group = g.next
            }
            if !groups.isEmpty {
                sendV3Report(netif: netif, groups: groups)
            }
        } else {
            // Skip allsystems (first in list)
            var group = netif.igmpData?.next
            while let g = group {
                delayingMember(g, maxResp: IGMPConstants.joinDelayingMemberTimer)
                group = g.next
            }
        }
    }

    // MARK: - Group Lookup

    /// Search for an existing group on an interface.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - addr: The multicast group address.
    /// - Returns: The matching group, or `nil`.
    public static func lookForGroup(on netif: NetworkInterface, addr: IPv4Address) -> IGMPGroup? {
        var group = netif.igmpData
        while let g = group {
            if g.groupAddress == addr {
                return g
            }
            group = g.next
        }
        return nil
    }

    /// Find or create a group on an interface.
    private static func lookupGroup(on netif: NetworkInterface, addr: IPv4Address) -> IGMPGroup? {
        // Search existing
        if let existing = lookForGroup(on: netif, addr: addr) {
            return existing
        }

        // Create new
        let group = IGMPGroup(address: addr)

        if lwipConfig.igmpV3 {
            group.igmpVersion = 3
        }

        let listHead = netif.igmpData
        if listHead == nil {
            // First entry (should be allsystems)
            group.next = nil
            netif.igmpData = group
        } else {
            // Append after first entry
            group.next = listHead!.next
            listHead!.next = group
        }

        return group
    }

    /// Remove a group from the interface's list.
    @discardableResult
    private static func removeGroup(from netif: NetworkInterface, group: IGMPGroup) -> LWIPError {
        var prev = netif.igmpData
        while let p = prev {
            if p.next === group {
                p.next = group.next
                return .ok
            }
            prev = p.next
        }
        return .invalidArgument
    }

    // MARK: - IGMPv2 Compatibility Mode

    /// Check whether the interface is in IGMPv2 compatibility mode.
    private static func isV2CompatibilityMode(_ netif: NetworkInterface) -> Bool {
        let key = ObjectIdentifier(netif)
        if let remaining = v2CompatibilityTimers[key], remaining > 0 {
            return true
        }
        return false
    }

    /// Enter IGMPv2 compatibility mode on an interface.
    private static func enterV2CompatibilityMode(_ netif: NetworkInterface) {
        let key = ObjectIdentifier(netif)
        v2CompatibilityTimers[key] = IGMPConstants.v2CompatibilityTimeout

        // Downgrade all groups on this interface to v2 mode
        var group = netif.igmpData
        while let g = group {
            g.igmpVersion = 2
            group = g.next
        }
    }

    // MARK: - IGMPv3 Max Response Code Decoding

    /// Decode Max Response Code using the floating-point encoding from RFC 3376 Section 4.1.1.
    /// If code < 128, the value is the code itself.
    /// If code >= 128, decode as mantissa/exponent: (mant | 0x10) << (exp + 3).
    private static func decodeMaxResponseCode(_ code: UInt8) -> UInt16 {
        if code < 128 {
            return UInt16(code)
        }
        let mant = UInt16(code & 0x0F)
        let exp = UInt16((code >> 4) & 0x07)
        return (mant | 0x10) << (exp + 3)
    }

    // MARK: - IGMPv3 Query Parsing

    /// Parse an IGMPv3 query from the packet buffer.
    ///
    /// - Parameter p: The received packet (payload at IGMP header).
    /// - Returns: The parsed query, or `nil` if the packet is too short.
    private static func parseV3Query(_ p: Pbuf) -> IGMPv3Query? {
        // An IGMPv3 query must be at least 12 bytes
        guard p.len >= IGMPConstants.v3QueryMinLength else {
            return nil
        }

        var query = IGMPv3Query()
        query.maxResponseCode = p.readByte(at: 1)
        // Group address at bytes 4..7
        let g0 = UInt32(p.readByte(at: 4))
        let g1 = UInt32(p.readByte(at: 5))
        let g2 = UInt32(p.readByte(at: 6))
        let g3 = UInt32(p.readByte(at: 7))
        query.groupAddress = IPv4Address(networkOrder: g0 | (g1 << 8) | (g2 << 16) | (g3 << 24))

        // Byte 8: Resv (4 bits) + S flag (1 bit) + QRV (3 bits)
        let flags = p.readByte(at: 8)
        query.suppressRouterProcessing = (flags & 0x08) != 0
        query.qrv = flags & 0x07

        // Byte 9: QQIC
        query.qqic = p.readByte(at: 9)

        // Bytes 10..11: Number of Sources (big-endian)
        let numSourcesHi = UInt16(p.readByte(at: 10))
        let numSourcesLo = UInt16(p.readByte(at: 11))
        let numSources = (numSourcesHi << 8) | numSourcesLo

        // Validate length: 12 + numSources * 4
        let expectedLen = UInt16(12) + numSources * 4
        guard p.len >= expectedLen else {
            return nil
        }

        // Parse source addresses
        query.sources = []
        for i in 0..<numSources {
            let offset = Int(12 + i * 4)
            let s0 = UInt32(p.readByte(at: offset))
            let s1 = UInt32(p.readByte(at: offset + 1))
            let s2 = UInt32(p.readByte(at: offset + 2))
            let s3 = UInt32(p.readByte(at: offset + 3))
            query.sources.append(IPv4Address(networkOrder: s0 | (s1 << 8) | (s2 << 16) | (s3 << 24)))
        }

        return query
    }

    // MARK: - Input

    /// Process an incoming IGMP packet.
    ///
    /// - Parameters:
    ///   - p: The received packet (payload at IGMP header).
    ///   - netif: The receiving network interface.
    ///   - dest: The destination IP address of the packet.
    public static func input(_ p: Pbuf, netif: NetworkInterface, dest: IPv4Address) {
        // Validate length
        guard p.len >= IGMPConstants.minimumLength else {
            p.free()
            return
        }

        // Verify checksum
        let igmpPayload = UnsafeRawPointer(p.payload)
        guard InetChecksum.checksum(igmpPayload, len: p.len) == 0 else {
            p.free()
            return
        }

        // Parse the base IGMP message
        let igmp = p.readIGMPMessage()

        switch igmp.messageType {
        case IGMPMessageType.membershipQuery.rawValue:
            // Determine v2 vs v3 query based on length
            if lwipConfig.igmpV3 && p.len > IGMPConstants.minimumLength {
                // IGMPv3 query (> 8 bytes)
                handleV3Query(p, dest: dest, netif: netif)
            } else {
                // IGMPv2 query (exactly 8 bytes) - enter v2 compatibility mode if v3 is enabled
                if lwipConfig.igmpV3 {
                    enterV2CompatibilityMode(netif)
                }

                // Find the group for this destination
                guard let group = lookForGroup(on: netif, addr: dest) else {
                    p.free()
                    return
                }
                handleQuery(igmp, dest: dest, netif: netif, group: group)
            }

        case IGMPMessageType.v1MemberReport.rawValue,
             IGMPMessageType.v2MemberReport.rawValue:
            // Another host on the network has reported membership for this group.
            // If we were in the delaying member state (about to send our own report),
            // cancel our pending report (report suppression per RFC 2236).
            // Note: IGMPv3 reports (0x22) do NOT suppress other reports (RFC 3376 Section 7.2.2).
            guard let group = lookForGroup(on: netif, addr: dest) else {
                p.free()
                return
            }
            if group.groupState == .delayingMember {
                group.timer = 0
                group.groupState = .idleMember
                group.lastReporterFlag = false
            }

        default:
            break
        }

        p.free()
    }

    /// Handle an IGMPv2 membership query.
    private static func handleQuery(_ igmp: IGMPMessage, dest: IPv4Address,
                                     netif: NetworkInterface, group: IGMPGroup) {
        if dest == allSystems && igmp.groupAddress.isAny {
            // General query
            var maxResponseTime = igmp.maximumResponseTime
            if maxResponseTime == 0 {
                // V1 query - treat as V2
                maxResponseTime = IGMPConstants.v1DelayingMemberTimer
            }

            // Process all groups except allsystems
            var groupRef = netif.igmpData?.next
            while let g = groupRef {
                delayingMember(g, maxResp: maxResponseTime)
                groupRef = g.next
            }
        } else if !igmp.groupAddress.isAny {
            // Group-specific query
            let targetGroup: IGMPGroup?
            if dest == allSystems {
                // Re-lookup for the specific group address
                targetGroup = lookForGroup(on: netif, addr: igmp.groupAddress)
            } else {
                targetGroup = group
            }
            if let tg = targetGroup {
                delayingMember(tg, maxResp: igmp.maximumResponseTime)
            }
        }
    }

    /// Handle an IGMPv3 membership query.
    private static func handleV3Query(_ p: Pbuf, dest: IPv4Address, netif: NetworkInterface) {
        guard let query = parseV3Query(p) else { return }

        // Decode max response time using floating-point encoding
        let maxRespDecoded = decodeMaxResponseCode(query.maxResponseCode)
        // Convert from 1/10 second units to timer ticks
        let maxRespTicks = UInt8(truncatingIfNeeded: min(UInt16(UInt8.max),
            max(1, maxRespDecoded / (IGMPConstants.timerInterval / 10))))

        if query.groupAddress.isAny && query.sources.isEmpty {
            // General Query: schedule reports for all groups except allsystems
            var groupRef = netif.igmpData?.next
            while let g = groupRef {
                g.igmpVersion = 3
                delayingMember(g, maxResp: maxRespTicks)
                groupRef = g.next
            }
        } else if !query.groupAddress.isAny && query.sources.isEmpty {
            // Group-Specific Query: schedule report for the specific group
            if let group = lookForGroup(on: netif, addr: query.groupAddress) {
                group.igmpVersion = 3
                delayingMember(group, maxResp: maxRespTicks)
            }
        } else if !query.groupAddress.isAny && !query.sources.isEmpty {
            // Group-and-Source-Specific Query: only report if we have matching sources
            if let group = lookForGroup(on: netif, addr: query.groupAddress) {
                group.igmpVersion = 3
                // Check for intersection between query source list and group source list
                let matchingSources = group.sourceList.filter { query.sources.contains($0) }
                if group.filterMode == .exclude || !matchingSources.isEmpty {
                    delayingMember(group, maxResp: maxRespTicks)
                }
            }
        }
    }

    // MARK: - Join / Leave

    /// Join a multicast group on matching interfaces.
    ///
    /// - Parameters:
    ///   - ifAddr: Interface address filter (`.any` = all IGMP interfaces).
    ///   - groupAddr: The multicast group address to join.
    /// - Returns: `.ok` on success.
    public static func joinGroup(ifAddr: IPv4Address, groupAddr: IPv4Address) -> LWIPError {
        guard groupAddr.isMulticast else { return .invalidValue }
        guard groupAddr != allSystems else { return .invalidValue }

        var err: LWIPError = .invalidValue
        var netif = IPv4.netifList
        while let n = netif {
            if n.flags.contains(.igmp) && (ifAddr.isAny || n.ipAddr == ifAddr) {
                let result = joinGroupNetif(n, groupAddr: groupAddr)
                if result != .ok { return result }
                err = .ok
            }
            netif = n.next
        }
        return err
    }

    /// Join a multicast group on a specific interface.
    public static func joinGroupNetif(_ netif: NetworkInterface, groupAddr: IPv4Address) -> LWIPError {
        guard groupAddr.isMulticast else { return .invalidValue }
        guard groupAddr != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let group = lookupGroup(on: netif, addr: groupAddr) else {
            return .outOfMemory
        }

        if group.groupState == .nonMember {
            // New group - set up MAC filter and send initial report
            if group.use == 0 {
                _ = netif.igmpMacFilter?(netif, groupAddr, .add)
            }

            if lwipConfig.igmpV3 && !isV2CompatibilityMode(netif) {
                // IGMPv3: send a Change-to-Exclude report (ASM join)
                group.filterMode = .exclude
                group.sourceList = []
                group.igmpVersion = 3
                let record = IGMPv3GroupRecord(recordType: .changeToExclude,
                                               groupAddress: group.groupAddress)
                sendV3Report(netif: netif, records: [record])
            } else {
                sendMessage(netif: netif, group: group, type: .v2MemberReport)
            }

            startTimer(group, maxTime: IGMPConstants.joinDelayingMemberTimer)
            group.groupState = .delayingMember
        }

        group.use += 1
        return .ok
    }

    /// Leave a multicast group on matching interfaces.
    public static func leaveGroup(ifAddr: IPv4Address, groupAddr: IPv4Address) -> LWIPError {
        guard groupAddr.isMulticast else { return .invalidValue }
        guard groupAddr != allSystems else { return .invalidValue }

        var err: LWIPError = .invalidValue
        var netif = IPv4.netifList
        while let n = netif {
            if n.flags.contains(.igmp) && (ifAddr.isAny || n.ipAddr == ifAddr) {
                let result = leaveGroupNetif(n, groupAddr: groupAddr)
                if err != .ok {
                    err = result
                }
            }
            netif = n.next
        }
        return err
    }

    /// Leave a multicast group on a specific interface.
    public static func leaveGroupNetif(_ netif: NetworkInterface, groupAddr: IPv4Address) -> LWIPError {
        guard groupAddr.isMulticast else { return .invalidValue }
        guard groupAddr != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let group = lookForGroup(on: netif, addr: groupAddr) else {
            return .invalidValue
        }

        if group.use <= 1 {
            removeGroup(from: netif, group: group)

            if lwipConfig.igmpV3 && !isV2CompatibilityMode(netif) {
                // IGMPv3: send a Change-to-Include {} report (leave)
                let record = IGMPv3GroupRecord(recordType: .changeToInclude,
                                               groupAddress: group.groupAddress,
                                               sources: [])
                sendV3Report(netif: netif, records: [record])
            } else if group.lastReporterFlag {
                sendMessage(netif: netif, group: group, type: .leaveGroup)
            }

            _ = netif.igmpMacFilter?(netif, groupAddr, .delete)
        } else {
            group.use -= 1
        }

        return .ok
    }

    // MARK: - Source-Specific Multicast (IGMPv3)

    /// Join a source-specific multicast group (IGMPv3 include mode).
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - group: The multicast group address.
    ///   - source: The source address to receive from.
    /// - Returns: `.ok` on success.
    public static func joinSourceGroup(netif: NetworkInterface, group: IPv4Address,
                                       source: IPv4Address) -> LWIPError {
        guard lwipConfig.igmpV3 else { return .invalidValue }
        guard group.isMulticast else { return .invalidValue }
        guard group != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let grp = lookupGroup(on: netif, addr: group) else {
            return .outOfMemory
        }

        if grp.groupState == .nonMember {
            // First join on this group
            if grp.use == 0 {
                _ = netif.igmpMacFilter?(netif, group, .add)
            }
            grp.filterMode = .include
            grp.sourceList = [source]
            grp.igmpVersion = 3
            grp.groupState = .idleMember
            grp.use += 1

            // Send Allow New Sources report
            let record = IGMPv3GroupRecord(recordType: .allowNewSources,
                                           groupAddress: group, sources: [source])
            sendV3Report(netif: netif, records: [record])
        } else {
            // Group already exists - add source if not present
            if !grp.sourceList.contains(source) {
                grp.sourceList.append(source)

                let record = IGMPv3GroupRecord(recordType: .allowNewSources,
                                               groupAddress: group, sources: [source])
                sendV3Report(netif: netif, records: [record])
            }
            grp.use += 1
        }

        return .ok
    }

    /// Leave a source-specific multicast group.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - group: The multicast group address.
    ///   - source: The source address to stop receiving from.
    /// - Returns: `.ok` on success.
    public static func leaveSourceGroup(netif: NetworkInterface, group: IPv4Address,
                                        source: IPv4Address) -> LWIPError {
        guard lwipConfig.igmpV3 else { return .invalidValue }
        guard group.isMulticast else { return .invalidValue }
        guard group != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let grp = lookForGroup(on: netif, addr: group) else {
            return .invalidValue
        }

        grp.sourceList.removeAll { $0 == source }

        // Send Block Old Sources report
        let record = IGMPv3GroupRecord(recordType: .blockOldSources,
                                       groupAddress: group, sources: [source])
        sendV3Report(netif: netif, records: [record])

        // If no sources remain and in include mode, leave the group entirely
        if grp.filterMode == .include && grp.sourceList.isEmpty {
            if grp.use <= 1 {
                removeGroup(from: netif, group: grp)
                _ = netif.igmpMacFilter?(netif, group, .delete)
            } else {
                grp.use -= 1
            }
        }

        return .ok
    }

    /// Block a specific source from a multicast group (IGMPv3 exclude mode).
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - group: The multicast group address.
    ///   - source: The source address to block.
    /// - Returns: `.ok` on success.
    public static func blockSource(netif: NetworkInterface, group: IPv4Address,
                                   source: IPv4Address) -> LWIPError {
        guard lwipConfig.igmpV3 else { return .invalidValue }
        guard group.isMulticast else { return .invalidValue }
        guard group != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let grp = lookForGroup(on: netif, addr: group) else {
            return .invalidValue
        }

        // Block only makes sense in exclude mode (ASM groups)
        guard grp.filterMode == .exclude else { return .invalidValue }

        if !grp.sourceList.contains(source) {
            grp.sourceList.append(source)

            let record = IGMPv3GroupRecord(recordType: .blockOldSources,
                                           groupAddress: group, sources: [source])
            sendV3Report(netif: netif, records: [record])
        }

        return .ok
    }

    /// Unblock a specific source from a multicast group.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - group: The multicast group address.
    ///   - source: The source address to unblock.
    /// - Returns: `.ok` on success.
    public static func unblockSource(netif: NetworkInterface, group: IPv4Address,
                                     source: IPv4Address) -> LWIPError {
        guard lwipConfig.igmpV3 else { return .invalidValue }
        guard group.isMulticast else { return .invalidValue }
        guard group != allSystems else { return .invalidValue }
        guard netif.flags.contains(.igmp) else { return .invalidValue }

        guard let grp = lookForGroup(on: netif, addr: group) else {
            return .invalidValue
        }

        guard grp.filterMode == .exclude else { return .invalidValue }

        grp.sourceList.removeAll { $0 == source }

        let record = IGMPv3GroupRecord(recordType: .allowNewSources,
                                       groupAddress: group, sources: [source])
        sendV3Report(netif: netif, records: [record])

        return .ok
    }

    // MARK: - Timer

    /// IGMP timer function. Call every IGMPConstants.timerInterval milliseconds.
    public static func timer() {
        var netif = IPv4.netifList
        while let n = netif {
            // Decrement v2 compatibility timer
            let key = ObjectIdentifier(n)
            if let remaining = v2CompatibilityTimers[key], remaining > 0 {
                let newVal = remaining - 1
                v2CompatibilityTimers[key] = newVal
                if newVal == 0 {
                    // Upgrade all groups back to v3
                    var group = n.igmpData
                    while let g = group {
                        if lwipConfig.igmpV3 {
                            g.igmpVersion = 3
                        }
                        group = g.next
                    }
                }
            }

            var group = n.igmpData
            while let g = group {
                if g.timer > 0 {
                    g.timer -= 1
                    if g.timer == 0 {
                        timeout(netif: n, group: g)
                    }
                }
                group = g.next
            }
            netif = n.next
        }
    }

    /// Handle a group timer expiration.
    private static func timeout(netif: NetworkInterface, group: IGMPGroup) {
        if group.groupState == .delayingMember && group.groupAddress != allSystems {
            group.groupState = .idleMember

            if lwipConfig.igmpV3 && group.igmpVersion == 3 && !isV2CompatibilityMode(netif) {
                // Send an IGMPv3 Current-State report
                let recordType: IGMPv3RecordType = group.filterMode == .include
                    ? .modeIsInclude : .modeIsExclude
                let record = IGMPv3GroupRecord(recordType: recordType,
                                               groupAddress: group.groupAddress,
                                               sources: group.sourceList)
                sendV3Report(netif: netif, records: [record])
            } else {
                sendMessage(netif: netif, group: group, type: .v2MemberReport)
            }
        }
    }

    /// Start a timer for a group.
    private static func startTimer(_ group: IGMPGroup, maxTime: UInt8) {
        let mt = UInt16(maxTime)
        if mt > 2 {
            group.timer = UInt16.random(in: 1...mt)
        } else {
            group.timer = 1
        }
    }

    /// Handle delayed membership reporting.
    private static func delayingMember(_ group: IGMPGroup, maxResp: UInt8) {
        if group.groupState == .idleMember ||
           (group.groupState == .delayingMember &&
            (group.timer == 0 || maxResp < UInt8(truncatingIfNeeded: group.timer))) {
            startTimer(group, maxTime: maxResp)
            group.groupState = .delayingMember
        }
    }

    // MARK: - Send

    /// Send an IGMP message via the IP layer with Router Alert option.
    private static func igmpIPOutputIf(_ p: Pbuf, src: IPv4Address,
                                        dest: IPv4Address, netif: NetworkInterface) -> LWIPError {
        // Router alert option: 0x9404, 0x0000
        let ra: [UInt8] = [
            UInt8(IGMPConstants.routerAlert >> 8), UInt8(IGMPConstants.routerAlert & 0xFF),
            0x00, 0x00
        ]
        return IPv4.outputIf(p, src: src, dest: dest,
                             ttl: IGMPConstants.timeToLive, tos: 0, proto: IPProtocolNumber.igmp,
                             netif: netif, ipOptions: ra)
    }

    /// Send an IGMPv2 packet for a specific group.
    private static func sendMessage(netif: NetworkInterface, group: IGMPGroup, type: IGMPMessageType) {
        guard let p = Pbuf.alloc(layer: .transport, length: IGMPConstants.minimumLength, type: .ram) else {
            return
        }

        guard p.len >= IGMPConstants.minimumLength else {
            p.free()
            return
        }

        let src = netif.ipAddr
        var dest: IPv4Address

        var igmp = IGMPMessage()
        igmp.messageType = type.rawValue
        igmp.maximumResponseTime = 0
        igmp.groupAddress = group.groupAddress

        if type == .v2MemberReport {
            dest = group.groupAddress
            group.lastReporterFlag = true
        } else if type == .leaveGroup {
            dest = IGMP.allRouters
        } else {
            p.free()
            return
        }

        igmp.checksum = 0
        p.writeIGMPMessage(igmp)

        // Calculate checksum over the IGMP message
        igmp.checksum = InetChecksum.checksum(UnsafeRawPointer(p.payload), len: IGMPConstants.minimumLength)
        p.writeIGMPMessage(igmp)

        let _ = igmpIPOutputIf(p, src: src, dest: dest, netif: netif)
        p.free()
    }

    // MARK: - IGMPv3 Membership Report

    /// Build and send an IGMPv3 Membership Report containing the specified group records.
    private static func sendV3Report(netif: NetworkInterface, records: [IGMPv3GroupRecord]) {
        guard !records.isEmpty else { return }

        // Calculate total message length
        var totalLen: UInt16 = IGMPConstants.v3ReportHeaderLength
        for record in records {
            totalLen += IGMPConstants.v3GroupRecordHeaderLength + UInt16(record.sources.count) * 4
        }

        guard let p = Pbuf.alloc(layer: .transport, length: totalLen, type: .ram) else {
            return
        }

        guard p.len >= totalLen else {
            p.free()
            return
        }

        var offset = 0

        // Type: 0x22 (IGMPv3 Membership Report)
        p.writeByte(IGMPMessageType.v3MemberReport.rawValue, at: offset)
        offset += 1

        // Reserved
        p.writeByte(0, at: offset)
        offset += 1

        // Checksum placeholder (bytes 2..3)
        p.writeByte(0, at: offset)
        p.writeByte(0, at: offset + 1)
        offset += 2

        // Reserved (bytes 4..5)
        p.writeByte(0, at: offset)
        p.writeByte(0, at: offset + 1)
        offset += 2

        // Number of Group Records (bytes 6..7, big-endian)
        let numRecords = UInt16(records.count)
        p.writeByte(UInt8(numRecords >> 8), at: offset)
        p.writeByte(UInt8(numRecords & 0xFF), at: offset + 1)
        offset += 2

        // Write each group record
        for record in records {
            // Record Type (1 byte)
            p.writeByte(record.recordType.rawValue, at: offset)
            offset += 1

            // Aux Data Len (1 byte)
            p.writeByte(record.auxDataLen, at: offset)
            offset += 1

            // Number of Sources (2 bytes, big-endian)
            let numSources = UInt16(record.sources.count)
            p.writeByte(UInt8(numSources >> 8), at: offset)
            p.writeByte(UInt8(numSources & 0xFF), at: offset + 1)
            offset += 2

            // Multicast Address (4 bytes)
            let g = record.groupAddress.addr
            p.writeByte(UInt8(truncatingIfNeeded: g), at: offset)
            p.writeByte(UInt8(truncatingIfNeeded: g >> 8), at: offset + 1)
            p.writeByte(UInt8(truncatingIfNeeded: g >> 16), at: offset + 2)
            p.writeByte(UInt8(truncatingIfNeeded: g >> 24), at: offset + 3)
            offset += 4

            // Source Addresses (4 bytes each)
            for source in record.sources {
                let s = source.addr
                p.writeByte(UInt8(truncatingIfNeeded: s), at: offset)
                p.writeByte(UInt8(truncatingIfNeeded: s >> 8), at: offset + 1)
                p.writeByte(UInt8(truncatingIfNeeded: s >> 16), at: offset + 2)
                p.writeByte(UInt8(truncatingIfNeeded: s >> 24), at: offset + 3)
                offset += 4
            }
        }

        // Calculate and write checksum (bytes 2..3)
        let checksum = InetChecksum.checksum(UnsafeRawPointer(p.payload), len: totalLen)
        p.writeByte(UInt8(checksum >> 8), at: 2)
        p.writeByte(UInt8(checksum & 0xFF), at: 3)

        let src = netif.ipAddr
        let _ = igmpIPOutputIf(p, src: src, dest: IGMPConstants.v3ReportAddress, netif: netif)
        p.free()
    }

    /// Convenience overload: build group records from a list of IGMPGroup objects
    /// and send as a single IGMPv3 Membership Report.
    private static func sendV3Report(netif: NetworkInterface, groups: [IGMPGroup]) {
        var records: [IGMPv3GroupRecord] = []
        for group in groups {
            let recordType: IGMPv3RecordType = group.filterMode == .include
                ? .modeIsInclude : .modeIsExclude
            records.append(IGMPv3GroupRecord(recordType: recordType,
                                             groupAddress: group.groupAddress,
                                             sources: group.sourceList))
        }
        sendV3Report(netif: netif, records: records)
    }
}
