//
//  MLD6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Hop limit for MLD messages.
private let mld6HopLimit: UInt8 = 1

/// Initial join delaying member timer in milliseconds.
private let mld6JoinDelayingMemberTimerMs: UInt16 = 500

/// Hop-by-hop header length for MLD packets.
private let mld6HBHLength: Int = 8

/// Default MLDv2 Robustness Variable (RFC 3810 section 9.1).
private let mld6DefaultRobustnessVariable: UInt8 = 2

/// Default MLDv2 Query Interval in seconds (RFC 3810 section 9.2).
private let mld6DefaultQueryIntervalSec: UInt16 = 125

/// Older Version Querier Present Timeout multiplier.
/// = (Robustness Variable * Query Interval) + one Query Response Interval
/// We use ticks at timerInterval granularity.
private func mld6OlderVersionQuerierTimeout(robustness: UInt8, queryIntervalMs: UInt32, queryResponseMs: UInt16) -> UInt16 {
    let totalMs = UInt32(robustness) * queryIntervalMs + UInt32(queryResponseMs)
    return UInt16(min(totalMs / UInt32(MLD6.timerInterval), UInt32(UInt16.max)))
}

/// MLDv2 all-MLDv2-capable-routers link-local address: ff02::16
private let mld6v2RoutersAddress = IPv6Address(
    ByteOrder.hostToNetwork(0xFF02_0000), 0, 0, ByteOrder.hostToNetwork(0x0000_0016)
)

// MARK: - MLD Group State

/// MLD group membership states.
public enum MLD6GroupState: UInt8, Sendable {
    case nonMember      = 0
    case delayingMember = 1
    case idleMember     = 2
}

// MARK: - MLDv2 Compatibility Mode

/// The MLD protocol version currently in use on an interface.
public enum MLD6CompatibilityMode: UInt8, Sendable {
    case v2 = 2
    case v1 = 1
}

// MARK: - MLDv2 Record Types (RFC 3810 Section 5.2.12)

/// MLDv2 Multicast Address Record types.
public enum MLD6RecordType: UInt8, Sendable {
    case modeIsInclude       = 1
    case modeIsExclude       = 2
    case changeToIncludeMode = 3
    case changeToExcludeMode = 4
    case allowNewSources     = 5
    case blockOldSources     = 6
}

// MARK: - MLDv2 Source Filter

/// Filter mode for source-specific multicast (SSM).
public enum MLD6FilterMode: UInt8, Sendable {
    /// Include mode: accept only packets from listed sources.
    case include = 0
    /// Exclude mode: accept packets from all sources except listed.
    case exclude = 1
}

/// Per-group source filter state for MLDv2.
public struct MLD6SourceFilter: Sendable {
    /// Current filter mode.
    public var filterMode: MLD6FilterMode
    /// List of source addresses in the filter.
    public var sources: [IPv6Address]

    public init(filterMode: MLD6FilterMode = .exclude, sources: [IPv6Address] = []) {
        self.filterMode = filterMode
        self.sources = sources
    }

    /// An empty EXCLUDE filter (receive from all sources) -- the default on join.
    public static let excludeNone = MLD6SourceFilter(filterMode: .exclude, sources: [])

    /// An empty INCLUDE filter (receive from no sources) -- equivalent to leaving.
    public static let includeNone = MLD6SourceFilter(filterMode: .include, sources: [])
}

// MARK: - MLDv2 Query Header (RFC 3810 Section 5.1)

/// MLDv2 query message header. Extends MLDv1 query with additional fields.
/// Minimum length: 28 bytes (24-byte MLDv1 header + 4 bytes for S/QRV/QQIC/NumSources).
/// Source addresses follow immediately after the fixed header.
public struct MLD6v2QueryHeader: Sendable {
    /// Minimum length of an MLDv2 query (without source addresses).
    public static let minimumLength: Int = 28

    // MLDv1-compatible fields
    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    public var maxRespCode: UInt16
    public var reserved: UInt16
    public var multicastAddress: IPv6Address

    // MLDv2-specific fields (byte 24 onwards)
    /// S flag (suppress router-side processing) and QRV (Querier's Robustness Variable).
    public var suppressFlag: Bool
    public var qrv: UInt8
    /// QQIC (Querier's Query Interval Code).
    public var qqic: UInt8
    /// Number of source addresses.
    public var numSources: UInt16

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + Self.minimumLength else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.type = p.load(fromByteOffset: 0, as: UInt8.self)
        self.code = p.load(fromByteOffset: 1, as: UInt8.self)
        self.checksum = p.loadUnaligned(fromByteOffset: 2, as: UInt16.self).bigEndian
        self.maxRespCode = p.loadUnaligned(fromByteOffset: 4, as: UInt16.self).bigEndian
        self.reserved = p.loadUnaligned(fromByteOffset: 6, as: UInt16.self).bigEndian
        self.multicastAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )
        let sqrv = p.load(fromByteOffset: 24, as: UInt8.self)
        self.suppressFlag = (sqrv & 0x08) != 0
        self.qrv = sqrv & 0x07
        self.qqic = p.load(fromByteOffset: 25, as: UInt8.self)
        self.numSources = p.loadUnaligned(fromByteOffset: 26, as: UInt16.self).bigEndian
    }

    /// Read a source address at a given index from the query.
    @inlinable
    public static func readSourceAddress(from pbuf: Pbuf, offset: Int, index: Int) -> IPv6Address? {
        let srcOffset = offset + Self.minimumLength + index * 16
        guard pbuf.length >= srcOffset + 16 else { return nil }
        let p = pbuf.payload.advanced(by: srcOffset)
        return IPv6Address(
            p.loadUnaligned(fromByteOffset: 0, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 4, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self)
        )
    }

    /// Decode the Maximum Response Code into milliseconds (RFC 3810 Section 5.1.3).
    /// If the code < 32768, it is a linear value in milliseconds.
    /// Otherwise it is a floating-point encoded value.
    @inlinable
    public var maxRespDelayMs: UInt32 {
        MLD6v2QueryHeader.decodeExponentialValue(maxRespCode)
    }

    /// Decode the QQIC into seconds (RFC 3810 Section 5.1.9).
    @inlinable
    public var queryIntervalMs: UInt32 {
        UInt32(MLD6v2QueryHeader.decodeExponentialByte(qqic)) * 1000
    }

    /// Decode a 16-bit exponential value per RFC 3810 Section 5.1.3.
    @inlinable
    public static func decodeExponentialValue(_ code: UInt16) -> UInt32 {
        if code < 0x8000 {
            return UInt32(code)
        }
        // Floating-point: 1MMM MMMM MMMM EEEE -> (0x1000 | mant) << (exp + 3)
        let exp = UInt32((code >> 12) & 0x07)
        let mant = UInt32(code & 0x0FFF)
        return (0x1000 | mant) << (exp + 3)
    }

    /// Decode an 8-bit exponential code per RFC 3810 Section 5.1.9.
    @inlinable
    public static func decodeExponentialByte(_ code: UInt8) -> UInt16 {
        if code < 128 {
            return UInt16(code)
        }
        // Floating-point: 1MMM MEEE -> (0x10 | mant) << (exp + 3)
        let exp = UInt16(code & 0x07)
        let mant = UInt16((code >> 3) & 0x0F)
        return (0x10 | mant) << (exp + 3)
    }
}

// MARK: - MLD Group

/// An MLD multicast group membership entry.
public final class MLD6Group: @unchecked Sendable {
    /// Next group in linked list.
    public var next: MLD6Group?
    /// Multicast group address.
    public var groupAddress: IPv6Address
    /// Whether we were the last to report.
    public var lastReporterFlag: Bool
    /// Current group state.
    public var groupState: MLD6GroupState
    /// Timer for delayed reporting (in MLD timer ticks).
    public var timer: UInt16
    /// Use count (number of joins).
    public var useCount: UInt8

    // -- MLDv2 state --

    /// Source filter for this group (MLDv2).
    public var sourceFilter: MLD6SourceFilter

    /// Number of remaining state-change report retransmissions (MLDv2).
    /// When a filter change occurs, this is set to [Robustness Variable] - 1
    /// and decremented each time a retransmission is sent.
    public var retransmitCount: UInt8

    /// The record type to send in state-change retransmissions.
    public var pendingRecordType: MLD6RecordType?

    /// Sources to include in the pending state-change record (for ALLOW/BLOCK).
    public var pendingSources: [IPv6Address]

    public init(address: IPv6Address) {
        self.groupAddress = address
        self.lastReporterFlag = false
        self.groupState = .idleMember
        self.timer = 0
        self.useCount = 0
        self.next = nil
        self.sourceFilter = .excludeNone
        self.retransmitCount = 0
        self.pendingRecordType = nil
        self.pendingSources = []
    }
}

// MARK: - MLD Header

/// MLD message header (28 bytes: 8-byte ICMPv6-like header + 16-byte multicast address).
public struct MLD6Header: Sendable {
    public static let length: Int = 24

    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    public var maxRespDelay: UInt16
    public var reserved: UInt16
    public var multicastAddress: IPv6Address

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + Self.length else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.type = p.load(fromByteOffset: 0, as: UInt8.self)
        self.code = p.load(fromByteOffset: 1, as: UInt8.self)
        self.checksum = p.loadUnaligned(fromByteOffset: 2, as: UInt16.self).bigEndian
        self.maxRespDelay = p.loadUnaligned(fromByteOffset: 4, as: UInt16.self).bigEndian
        self.reserved = p.loadUnaligned(fromByteOffset: 6, as: UInt16.self).bigEndian
        self.multicastAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )
    }

    @inlinable
    public func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: type, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: code, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: checksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: maxRespDelay.bigEndian, toByteOffset: 4, as: UInt16.self)
        p.storeBytes(of: reserved.bigEndian, toByteOffset: 6, as: UInt16.self)
        multicastAddress.writeNetworkBytes(to: p.advanced(by: 8))
    }
}

// MARK: - MLDv2 Report Header (RFC 3810 Section 5.2)

/// MLDv2 Report message fixed header (8 bytes).
/// Type(1) + Reserved(1) + Checksum(2) + Reserved(2) + Num Records(2)
/// Followed by Multicast Address Records.
public struct MLD6v2ReportHeader: Sendable {
    public static let length: Int = 8

    public var type: UInt8
    public var reserved1: UInt8
    public var checksum: UInt16
    public var reserved2: UInt16
    public var numRecords: UInt16

    @inlinable
    public func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: type, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: reserved1, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: checksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: reserved2.bigEndian, toByteOffset: 4, as: UInt16.self)
        p.storeBytes(of: numRecords.bigEndian, toByteOffset: 6, as: UInt16.self)
    }
}

/// An MLDv2 Multicast Address Record (variable length).
/// Record Type(1) + Aux Data Len(1) + Num Sources(2) + Multicast Address(16) + Sources(N*16)
public struct MLD6v2AddressRecord: Sendable {
    /// Fixed part of a record (without source addresses).
    public static let fixedLength: Int = 20

    public var recordType: MLD6RecordType
    public var auxDataLen: UInt8
    public var numSources: UInt16
    public var multicastAddress: IPv6Address
    public var sources: [IPv6Address]

    public init(recordType: MLD6RecordType, multicastAddress: IPv6Address, sources: [IPv6Address] = []) {
        self.recordType = recordType
        self.auxDataLen = 0
        self.numSources = UInt16(sources.count)
        self.multicastAddress = multicastAddress
        self.sources = sources
    }

    /// Total byte length of this record.
    @inlinable
    public var totalLength: Int {
        Self.fixedLength + sources.count * 16 + Int(auxDataLen) * 4
    }

    /// Write this record to a raw pointer, returning bytes written.
    @inlinable
    @discardableResult
    public func write(to p: UnsafeMutableRawPointer) -> Int {
        p.storeBytes(of: recordType.rawValue, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: auxDataLen, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: numSources.bigEndian, toByteOffset: 2, as: UInt16.self)
        multicastAddress.writeNetworkBytes(to: p.advanced(by: 4))
        for (i, src) in sources.enumerated() {
            src.writeNetworkBytes(to: p.advanced(by: 20 + i * 16))
        }
        return totalLength
    }
}

// MARK: - MLD6 Per-Interface State

/// Per-interface MLDv2 state, tracked alongside the group list.
public final class MLD6InterfaceState: @unchecked Sendable {
    /// Current compatibility mode.
    public var compatibilityMode: MLD6CompatibilityMode = .v2
    /// v1 compatibility timer (in MLD timer ticks). When >0, operate in v1 mode.
    public var v1CompatibilityTimer: UInt16 = 0
    /// Querier's Robustness Variable (learned from queries, default 2).
    public var robustnessVariable: UInt8 = mld6DefaultRobustnessVariable
    /// Querier's Query Interval in milliseconds (learned from queries).
    public var queryIntervalMs: UInt32 = UInt32(mld6DefaultQueryIntervalSec) * 1000

    public init() {}
}

// MARK: - MLD6 Module

/// Multicast Listener Discovery v1/v2 protocol processing.
public enum MLD6 {

    /// MLD timer interval in milliseconds.
    public static let timerInterval: UInt16 = 100

    // MARK: - Group Management

    /// Look up a multicast group on a network interface.
    @inlinable
    public static func lookForGroup(on netif: NetworkInterface,
                                    address: IPv6Address) -> MLD6Group? {
        var group = netif.mld6Groups
        while let g = group {
            if g.groupAddress == address {
                return g
            }
            group = g.next
        }
        return nil
    }

    /// Create a new MLD group entry on an interface.
    private static func newGroup(on netif: NetworkInterface,
                                 address: IPv6Address) -> MLD6Group? {
        let group = MLD6Group(address: address)
        group.next = netif.mld6Groups
        netif.mld6Groups = group
        return group
    }

    /// Remove a group from the interface's linked list.
    @discardableResult
    private static func removeGroup(from netif: NetworkInterface,
                                    group: MLD6Group) -> LWIPError {
        if netif.mld6Groups === group {
            netif.mld6Groups = group.next
            return .ok
        }
        var current = netif.mld6Groups
        while let c = current {
            if c.next === group {
                c.next = group.next
                return .ok
            }
            current = c.next
        }
        return .invalidArgument
    }

    // MARK: - Stop / Report

    /// Stop MLD processing on an interface.
    @discardableResult
    public static func stop(on netif: NetworkInterface) -> LWIPError {
        var group = netif.mld6Groups
        netif.mld6Groups = nil

        while let g = group {
            let next = g.next
            netif.mldMacFilter?(netif, g.groupAddress, .delete)
            group = next
        }
        return .ok
    }

    /// Report all group memberships on an interface.
    /// In v2 mode, immediately sends a comprehensive MLDv2 report with
    /// current-state records for every joined group, then schedules
    /// delayed follow-ups.
    public static func reportGroups(on netif: NetworkInterface) {
        if netif.mld6State.compatibilityMode == .v2 {
            // Collect current-state records for all groups and send a single report.
            var records: [MLD6v2AddressRecord] = []
            var group = netif.mld6Groups
            while let g = group {
                let filter = g.sourceFilter
                let recType: MLD6RecordType = (filter.filterMode == .exclude)
                    ? .modeIsExclude : .modeIsInclude
                records.append(MLD6v2AddressRecord(
                    recordType: recType,
                    multicastAddress: g.groupAddress,
                    sources: filter.sources
                ))
                group = g.next
            }
            if !records.isEmpty {
                sendMLDv2Report(on: netif, records: records)
            }
        }

        // Also schedule delayed reports (works for both v1 and v2).
        var group = netif.mld6Groups
        while let g = group {
            delayedReport(g, maxResp: mld6JoinDelayingMemberTimerMs)
            group = g.next
        }
    }

    // MARK: - Input

    /// Process an incoming MLD message (v1 or v2).
    public static func input(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        // Peek at the type byte to decide how to parse.
        guard pbuf.length >= 1 else {
            pbuf.free()
            return
        }
        let typeByte = pbuf.payload.load(fromByteOffset: 0, as: UInt8.self)

        switch typeByte {
        case ICMPv6Type.multicastListenerQuery.rawValue:
            inputQuery(pbuf, on: inputNetif)

        case ICMPv6Type.multicastListenerReport.rawValue:
            inputV1Report(pbuf, on: inputNetif)

        case ICMPv6Type.multicastListenerDone.rawValue:
            // Do nothing, router will query us
            break

        case ICMPv6Type.multicastListenerV2Report.rawValue:
            // MLDv2 reports are sent to ff02::16; we do not need to suppress
            // our own reports based on them (MLDv2 has no report suppression).
            break

        default:
            break
        }

        pbuf.free()
    }

    /// Handle an incoming Multicast Listener Query (type 130).
    /// Distinguishes MLDv1 (24 bytes) from MLDv2 (>=28 bytes) queries.
    private static func inputQuery(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        let ctx = IPv6.currentContext
        let ifState = inputNetif.mld6State

        // Try to parse as MLDv2 query first (>= 28 bytes).
        if let v2Hdr = MLD6v2QueryHeader(reading: pbuf) {
            // Update interface-level parameters from the querier.
            if v2Hdr.qrv > 0 {
                ifState.robustnessVariable = v2Hdr.qrv
            }
            if v2Hdr.qqic > 0 {
                ifState.queryIntervalMs = v2Hdr.queryIntervalMs
            }

            let maxRespMs = v2Hdr.maxRespDelayMs

            // Determine if this is an MLDv1 query disguised as a short packet
            // or a true MLDv2 query. An MLDv1 query is exactly 24 bytes.
            let isV2Query = (pbuf.length >= MLD6v2QueryHeader.minimumLength)

            if isV2Query && v2Hdr.numSources > 0 && !v2Hdr.multicastAddress.isAny {
                // MLDv2 group-and-source-specific query.
                // Read source list from the query.
                var querySources: [IPv6Address] = []
                for i in 0..<Int(v2Hdr.numSources) {
                    if let src = MLD6v2QueryHeader.readSourceAddress(from: pbuf, offset: 0, index: i) {
                        querySources.append(src)
                    }
                }

                if let group = lookForGroup(on: inputNetif, address: ctx.currentDest) {
                    if ifState.compatibilityMode == .v2 {
                        // Schedule an MLDv2 current-state report for this group,
                        // filtered to the queried sources.
                        delayedReport(group, maxRespMs: maxRespMs)
                    } else {
                        // v1 compat: respond with v1 report
                        delayedReport(group, maxResp: clampMaxRespToV1(maxRespMs))
                    }
                }
            } else if !v2Hdr.multicastAddress.isAny {
                // Group-specific query (no source list).
                if let group = lookForGroup(on: inputNetif, address: ctx.currentDest) {
                    if ifState.compatibilityMode == .v2 {
                        delayedReport(group, maxRespMs: maxRespMs)
                    } else {
                        delayedReport(group, maxResp: clampMaxRespToV1(maxRespMs))
                    }
                }
            } else if ctx.currentDest.isAllNodesLinkLocal && v2Hdr.multicastAddress.isAny {
                // General query: schedule reports for all non-trivial groups.
                var group = inputNetif.mld6Groups
                while let g = group {
                    if !g.groupAddress.isMulticastInterfaceLocal &&
                       !g.groupAddress.isAllNodesLinkLocal {
                        if ifState.compatibilityMode == .v2 {
                            delayedReport(g, maxRespMs: maxRespMs)
                        } else {
                            delayedReport(g, maxResp: clampMaxRespToV1(maxRespMs))
                        }
                    }
                    group = g.next
                }
            }
            return
        }

        // Fall back to MLDv1 query parsing (24 bytes).
        guard let mldHdr = MLD6Header(reading: pbuf) else { return }

        // An MLDv1 query means there is an MLDv1 querier on the link.
        // Start the v1 compatibility timer.
        let v1Timeout = mld6OlderVersionQuerierTimeout(
            robustness: ifState.robustnessVariable,
            queryIntervalMs: ifState.queryIntervalMs,
            queryResponseMs: mldHdr.maxRespDelay
        )
        ifState.v1CompatibilityTimer = v1Timeout
        ifState.compatibilityMode = .v1

        if ctx.currentDest.isAllNodesLinkLocal && mldHdr.multicastAddress.isAny {
            // General query
            var group = inputNetif.mld6Groups
            while let g = group {
                if !g.groupAddress.isMulticastInterfaceLocal &&
                   !g.groupAddress.isAllNodesLinkLocal {
                    delayedReport(g, maxResp: mldHdr.maxRespDelay)
                }
                group = g.next
            }
        } else {
            // Group-specific query
            if let group = lookForGroup(on: inputNetif, address: ctx.currentDest) {
                delayedReport(group, maxResp: mldHdr.maxRespDelay)
            }
        }
    }

    /// Handle an incoming MLDv1 Report (type 131).
    private static func inputV1Report(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        let ctx = IPv6.currentContext
        if let group = lookForGroup(on: inputNetif, address: ctx.currentDest) {
            // Report suppression (MLDv1 only -- v2 does not suppress).
            if inputNetif.mld6State.compatibilityMode == .v1 {
                if group.groupState == .delayingMember {
                    group.timer = 0
                    group.groupState = .idleMember
                    group.lastReporterFlag = false
                }
            }
        }
    }

    /// Clamp a 32-bit max response delay in ms to a UInt16 for v1 processing.
    private static func clampMaxRespToV1(_ ms: UInt32) -> UInt16 {
        UInt16(min(ms, UInt32(UInt16.max)))
    }

    // MARK: - Join / Leave

    /// Join a multicast group on matching interfaces.
    ///
    /// - Parameters:
    ///   - srcAddr: Source address to match interface, or `.any` for all.
    ///   - groupAddr: Multicast group address to join.
    @discardableResult
    public static func joinGroup(srcAddr: IPv6Address,
                                 groupAddr: IPv6Address) -> LWIPError {
        var err: LWIPError = .invalidValue
        var netif = NetworkInterface.list
        while let n = netif {
            if srcAddr.isAny || n.hasIPv6Address(srcAddr) {
                err = joinGroup(on: n, groupAddr: groupAddr)
                if err != .ok { return err }
            }
            netif = n.next
        }
        return err
    }

    /// Join a multicast group on a specific interface.
    /// In v2 mode, sends an MLDv2 CHANGE_TO_EXCLUDE_MODE report (EXCLUDE {} = join all).
    /// In v1 mode, sends an MLDv1 Report.
    @discardableResult
    public static func joinGroup(on netif: NetworkInterface,
                                 groupAddr: IPv6Address) -> LWIPError {
        var addr = groupAddr
        if !addr.hasZone && addr.isMulticast {
            addr = addr.withZone(for: netif)
        }

        if let group = lookForGroup(on: netif, address: addr) {
            group.useCount += 1
            return .ok
        }

        // Create new group (default filter: EXCLUDE {} = receive all sources)
        guard let group = newGroup(on: netif, address: addr) else {
            return .outOfMemory
        }

        // Activate MAC filter
        netif.mldMacFilter?(netif, addr, .add)

        if netif.mld6State.compatibilityMode == .v2 {
            // MLDv2: send CHANGE_TO_EXCLUDE_MODE with empty source list.
            let record = MLD6v2AddressRecord(
                recordType: .changeToExcludeMode,
                multicastAddress: addr,
                sources: []
            )
            sendMLDv2Report(on: netif, records: [record])
            scheduleRetransmission(on: netif, group: group,
                                   recordType: .changeToExcludeMode, sources: [])
        } else {
            // MLDv1: send Report + schedule delayed report.
            sendMLDMessage(on: netif, group: group, type: ICMPv6Type.multicastListenerReport.rawValue)
        }
        delayedReport(group, maxResp: mld6JoinDelayingMemberTimerMs)

        group.useCount += 1
        return .ok
    }

    /// Leave a multicast group on matching interfaces.
    @discardableResult
    public static func leaveGroup(srcAddr: IPv6Address,
                                  groupAddr: IPv6Address) -> LWIPError {
        var err: LWIPError = .invalidValue
        var netif = NetworkInterface.list
        while let n = netif {
            if srcAddr.isAny || n.hasIPv6Address(srcAddr) {
                let res = leaveGroup(on: n, groupAddr: groupAddr)
                if err != .ok { err = res }
            }
            netif = n.next
        }
        return err
    }

    /// Leave a multicast group on a specific interface.
    /// In v2 mode, sends an MLDv2 CHANGE_TO_INCLUDE_MODE with empty source list (= leave).
    /// In v1 mode, sends an MLDv1 Done message.
    @discardableResult
    public static func leaveGroup(on netif: NetworkInterface,
                                  groupAddr: IPv6Address) -> LWIPError {
        var addr = groupAddr
        if !addr.hasZone && addr.isMulticast {
            addr = addr.withZone(for: netif)
        }

        guard let group = lookForGroup(on: netif, address: addr) else {
            return .invalidValue
        }

        if group.useCount <= 1 {
            removeGroup(from: netif, group: group)

            if netif.mld6State.compatibilityMode == .v2 {
                // MLDv2: send CHANGE_TO_INCLUDE_MODE with empty sources (= leave).
                let record = MLD6v2AddressRecord(
                    recordType: .changeToIncludeMode,
                    multicastAddress: addr,
                    sources: []
                )
                sendMLDv2Report(on: netif, records: [record])
            } else if group.lastReporterFlag {
                sendMLDMessage(on: netif, group: group, type: ICMPv6Type.multicastListenerDone.rawValue)
            }

            netif.mldMacFilter?(netif, addr, .delete)
        } else {
            group.useCount -= 1
        }

        return .ok
    }

    // MARK: - Timer

    /// Periodic MLD timer. Must be called every `MLD6.timerInterval` ms.
    /// Handles:
    /// - MLDv1 delayed report expiry
    /// - MLDv2 state-change report retransmissions
    /// - v1 compatibility timer countdown
    public static func timer() {
        var netif = NetworkInterface.list
        while let n = netif {
            let ifState = n.mld6State

            // Tick down the v1 compatibility timer.
            if ifState.v1CompatibilityTimer > 0 {
                ifState.v1CompatibilityTimer -= 1
                if ifState.v1CompatibilityTimer == 0 {
                    ifState.compatibilityMode = .v2
                }
            }

            var group = n.mld6Groups
            while let g = group {
                // MLDv1 / general delayed report timer.
                if g.timer > 0 {
                    g.timer -= 1
                    if g.timer == 0 && g.groupState == .delayingMember {
                        if ifState.compatibilityMode == .v2 {
                            // Send MLDv2 current-state report for this group.
                            sendMLDv2CurrentStateReport(on: n, group: g)
                        } else {
                            // Send MLDv1 report.
                            sendMLDMessage(on: n, group: g, type: ICMPv6Type.multicastListenerReport.rawValue)
                        }
                        g.groupState = .idleMember
                    }
                }

                // MLDv2 state-change retransmission.
                if ifState.compatibilityMode == .v2 && g.retransmitCount > 0 {
                    g.retransmitCount -= 1
                    if let recordType = g.pendingRecordType {
                        let record = MLD6v2AddressRecord(
                            recordType: recordType,
                            multicastAddress: g.groupAddress,
                            sources: g.pendingSources
                        )
                        sendMLDv2Report(on: n, records: [record])
                    }
                    if g.retransmitCount == 0 {
                        g.pendingRecordType = nil
                        g.pendingSources = []
                    }
                }

                group = g.next
            }
            netif = n.next
        }
    }

    // MARK: - MLDv2 Source-Filtered Join / Leave

    /// Join a multicast group with a source filter on a specific interface (MLDv2).
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - groupAddr: Multicast group address.
    ///   - filter: The desired source filter.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func joinGroupWithSources(on netif: NetworkInterface,
                                            groupAddr: IPv6Address,
                                            filter: MLD6SourceFilter) -> LWIPError {
        var addr = groupAddr
        if !addr.hasZone && addr.isMulticast {
            addr = addr.withZone(for: netif)
        }

        if let group = lookForGroup(on: netif, address: addr) {
            // Group already exists -- update source filter.
            let oldFilter = group.sourceFilter
            group.sourceFilter = filter
            group.useCount += 1

            if netif.mld6State.compatibilityMode == .v2 {
                scheduleFilterChangeReport(on: netif, group: group, oldFilter: oldFilter, newFilter: filter)
            }
            return .ok
        }

        // New group.
        guard let group = newGroup(on: netif, address: addr) else {
            return .outOfMemory
        }

        group.sourceFilter = filter
        netif.mldMacFilter?(netif, addr, .add)

        if netif.mld6State.compatibilityMode == .v2 {
            // Send initial MLDv2 state-change report.
            let recordType: MLD6RecordType = (filter.filterMode == .exclude)
                ? .changeToExcludeMode : .changeToIncludeMode
            let record = MLD6v2AddressRecord(
                recordType: recordType,
                multicastAddress: addr,
                sources: filter.sources
            )
            sendMLDv2Report(on: netif, records: [record])
            scheduleRetransmission(on: netif, group: group, recordType: recordType, sources: filter.sources)
        } else {
            // v1 fallback
            sendMLDMessage(on: netif, group: group, type: ICMPv6Type.multicastListenerReport.rawValue)
            delayedReport(group, maxResp: mld6JoinDelayingMemberTimerMs)
        }

        group.useCount += 1
        return .ok
    }

    /// Leave a multicast group with source filter update on a specific interface (MLDv2).
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - groupAddr: Multicast group address.
    ///   - filter: The new source filter (use `.includeNone` to fully leave).
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func leaveGroupWithSources(on netif: NetworkInterface,
                                             groupAddr: IPv6Address,
                                             filter: MLD6SourceFilter) -> LWIPError {
        var addr = groupAddr
        if !addr.hasZone && addr.isMulticast {
            addr = addr.withZone(for: netif)
        }

        guard let group = lookForGroup(on: netif, address: addr) else {
            return .invalidValue
        }

        let oldFilter = group.sourceFilter

        // If the new filter is INCLUDE with no sources, this is a full leave.
        if filter.filterMode == .include && filter.sources.isEmpty {
            if group.useCount <= 1 {
                removeGroup(from: netif, group: group)

                if netif.mld6State.compatibilityMode == .v2 {
                    // Send CHANGE_TO_INCLUDE_MODE with empty source list (= leave).
                    let record = MLD6v2AddressRecord(
                        recordType: .changeToIncludeMode,
                        multicastAddress: addr,
                        sources: []
                    )
                    sendMLDv2Report(on: netif, records: [record])
                } else if group.lastReporterFlag {
                    sendMLDMessage(on: netif, group: group, type: ICMPv6Type.multicastListenerDone.rawValue)
                }

                netif.mldMacFilter?(netif, addr, .delete)
            } else {
                group.useCount -= 1
                group.sourceFilter = filter
                if netif.mld6State.compatibilityMode == .v2 {
                    scheduleFilterChangeReport(on: netif, group: group, oldFilter: oldFilter, newFilter: filter)
                }
            }
        } else {
            // Partial source filter update (not a full leave).
            group.sourceFilter = filter
            if netif.mld6State.compatibilityMode == .v2 {
                scheduleFilterChangeReport(on: netif, group: group, oldFilter: oldFilter, newFilter: filter)
            }
        }

        return .ok
    }

    // MARK: - Private Helpers

    /// Schedule a delayed membership report (MLDv1 style, maxResp in ms as UInt16).
    private static func delayedReport(_ group: MLD6Group, maxResp: UInt16) {
        var maxTicks = maxResp / MLD6.timerInterval
        if maxTicks == 0 { maxTicks = 1 }

        // Randomize if possible
        maxTicks = UInt16.random(in: 1...maxTicks)

        if group.groupState == .idleMember ||
           (group.groupState == .delayingMember &&
            (group.timer == 0 || maxTicks < group.timer)) {
            group.timer = maxTicks
            group.groupState = .delayingMember
        }
    }

    /// Schedule a delayed membership report (MLDv2 style, maxResp in ms as UInt32).
    private static func delayedReport(_ group: MLD6Group, maxRespMs: UInt32) {
        var maxTicks = UInt32(maxRespMs) / UInt32(MLD6.timerInterval)
        if maxTicks == 0 { maxTicks = 1 }
        let clamped = UInt16(min(maxTicks, UInt32(UInt16.max)))
        let randomized = UInt16.random(in: 1...clamped)

        if group.groupState == .idleMember ||
           (group.groupState == .delayingMember &&
            (group.timer == 0 || randomized < group.timer)) {
            group.timer = randomized
            group.groupState = .delayingMember
        }
    }

    /// Select source address for MLD messages on the given interface.
    private static func selectSourceAddress(on netif: NetworkInterface) -> IPv6Address {
        if netif.ipv6AddressIsValid(index: 0) {
            return netif.ipv6Address(at: 0)
        }
        return .any
    }

    /// Send an MLDv1 report or done message.
    private static func sendMLDMessage(on netif: NetworkInterface,
                                       group: MLD6Group,
                                       type: UInt8) {
        // Allocate: MLD header + HBH header space
        guard let pbuf = Pbuf.alloc(layer: .ip,
                                    length: UInt16(MLD6Header.length + mld6HBHLength),
                                    type: .ram) else {
            return
        }

        // Move past HBH header space
        guard pbuf.removeHeader(mld6HBHLength) else {
            pbuf.free()
            return
        }

        let srcAddr = selectSourceAddress(on: netif)

        // Write MLD header
        let p = pbuf.payload
        p.storeBytes(of: type, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self) // checksum placeholder
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 4, as: UInt16.self) // max resp delay
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 6, as: UInt16.self) // reserved
        group.groupAddress.writeNetworkBytes(to: p.advanced(by: 8))

        // Checksum (respects per-netif offload flags)
        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf,
                proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.length),
                src: srcAddr,
                dest: group.groupAddress
            )
            p.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        // Add hop-by-hop router alert header
        let _ = IPv6.addHopByHopRouterAlert(pbuf,
                                             nextHeader: IPv6NextHeader.icmpv6.rawValue,
                                             alertValue: IPv6RouterAlert.mldValue)

        if type == ICMPv6Type.multicastListenerReport.rawValue {
            group.lastReporterFlag = true
        }

        // Send
        IPv6.outputIf(pbuf,
                      src: srcAddr.isAny ? nil : srcAddr,
                      dest: group.groupAddress,
                      hopLimit: mld6HopLimit,
                      trafficClass: 0,
                      nextHeader: IPv6NextHeader.hopByHop.rawValue,
                      netif: netif)
        pbuf.free()
    }

    // MARK: - MLDv2 Report Generation

    /// Send an MLDv2 Report (type 143) containing the given address records.
    /// The report is sent to ff02::16 (all-MLDv2-capable-routers).
    private static func sendMLDv2Report(on netif: NetworkInterface,
                                        records: [MLD6v2AddressRecord]) {
        guard !records.isEmpty else { return }

        // Calculate total payload size.
        var recordsLength = 0
        for r in records {
            recordsLength += r.totalLength
        }
        let payloadLength = MLD6v2ReportHeader.length + recordsLength

        // Allocate: payload + HBH header space
        guard let pbuf = Pbuf.alloc(layer: .ip,
                                    length: UInt16(payloadLength + mld6HBHLength),
                                    type: .ram) else {
            return
        }

        // Move past HBH header space
        guard pbuf.removeHeader(mld6HBHLength) else {
            pbuf.free()
            return
        }

        let srcAddr = selectSourceAddress(on: netif)
        let destAddr = mld6v2RoutersAddress

        // Write MLDv2 Report header.
        let p = pbuf.payload
        var hdr = MLD6v2ReportHeader(
            type: ICMPv6Type.multicastListenerV2Report.rawValue,
            reserved1: 0,
            checksum: 0,
            reserved2: 0,
            numRecords: UInt16(records.count)
        )
        hdr.write(to: p)

        // Write address records.
        var offset = MLD6v2ReportHeader.length
        for record in records {
            let written = record.write(to: p.advanced(by: offset))
            offset += written
        }

        // Checksum (respects per-netif offload flags)
        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf,
                proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.length),
                src: srcAddr,
                dest: destAddr
            )
            p.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        // Add hop-by-hop router alert header
        let _ = IPv6.addHopByHopRouterAlert(pbuf,
                                             nextHeader: IPv6NextHeader.icmpv6.rawValue,
                                             alertValue: IPv6RouterAlert.mldValue)

        // Send to ff02::16
        IPv6.outputIf(pbuf,
                      src: srcAddr.isAny ? nil : srcAddr,
                      dest: destAddr,
                      hopLimit: mld6HopLimit,
                      trafficClass: 0,
                      nextHeader: IPv6NextHeader.hopByHop.rawValue,
                      netif: netif)
        pbuf.free()
    }

    /// Send an MLDv2 current-state report for a single group.
    /// Used in response to queries.
    private static func sendMLDv2CurrentStateReport(on netif: NetworkInterface,
                                                    group: MLD6Group) {
        let filter = group.sourceFilter
        let recordType: MLD6RecordType = (filter.filterMode == .exclude)
            ? .modeIsExclude : .modeIsInclude
        let record = MLD6v2AddressRecord(
            recordType: recordType,
            multicastAddress: group.groupAddress,
            sources: filter.sources
        )
        sendMLDv2Report(on: netif, records: [record])
        group.lastReporterFlag = true
    }

    // MARK: - MLDv2 State Change Reports

    /// Compute and send the appropriate MLDv2 state-change record(s) when
    /// a group's source filter changes.
    private static func scheduleFilterChangeReport(on netif: NetworkInterface,
                                                   group: MLD6Group,
                                                   oldFilter: MLD6SourceFilter,
                                                   newFilter: MLD6SourceFilter) {
        var records: [MLD6v2AddressRecord] = []

        if oldFilter.filterMode != newFilter.filterMode {
            // Filter mode changed.
            let recordType: MLD6RecordType = (newFilter.filterMode == .exclude)
                ? .changeToExcludeMode : .changeToIncludeMode
            records.append(MLD6v2AddressRecord(
                recordType: recordType,
                multicastAddress: group.groupAddress,
                sources: newFilter.sources
            ))
            // Schedule retransmissions for the mode change.
            scheduleRetransmission(on: netif, group: group, recordType: recordType, sources: newFilter.sources)
        } else {
            // Same mode -- compute source list diffs.
            let oldSet = Set(oldFilter.sources)
            let newSet = Set(newFilter.sources)

            let added = newSet.subtracting(oldSet)
            let removed = oldSet.subtracting(newSet)

            if !added.isEmpty {
                let rec = MLD6v2AddressRecord(
                    recordType: .allowNewSources,
                    multicastAddress: group.groupAddress,
                    sources: Array(added)
                )
                records.append(rec)
                scheduleRetransmission(on: netif, group: group, recordType: .allowNewSources, sources: Array(added))
            }

            if !removed.isEmpty {
                let rec = MLD6v2AddressRecord(
                    recordType: .blockOldSources,
                    multicastAddress: group.groupAddress,
                    sources: Array(removed)
                )
                records.append(rec)
                // If we already have an ALLOW pending, the BLOCK retransmission
                // will overwrite it. In a production implementation, both would
                // be tracked separately. For simplicity we use the last one.
                scheduleRetransmission(on: netif, group: group, recordType: .blockOldSources, sources: Array(removed))
            }
        }

        if !records.isEmpty {
            sendMLDv2Report(on: netif, records: records)
        }
    }

    /// Schedule retransmission of a state-change record [Robustness Variable - 1] more times.
    private static func scheduleRetransmission(on netif: NetworkInterface,
                                               group: MLD6Group,
                                               recordType: MLD6RecordType,
                                               sources: [IPv6Address]) {
        let rv = netif.mld6State.robustnessVariable
        let retransmissions = (rv > 1) ? (rv - 1) : 0
        group.retransmitCount = retransmissions
        group.pendingRecordType = recordType
        group.pendingSources = sources
    }
}
