//
//  SNMPMIB2.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Helper: encode UInt32 as big-endian bytes

private func encodeUInt32(_ value: UInt32, into buffer: inout [UInt8]) -> Int16 {
    buffer[0] = UInt8((value >> 24) & 0xFF)
    buffer[1] = UInt8((value >> 16) & 0xFF)
    buffer[2] = UInt8((value >> 8) & 0xFF)
    buffer[3] = UInt8(value & 0xFF)
    return 4
}

private func encodeInt32(_ value: Int32, into buffer: inout [UInt8]) -> Int16 {
    if value == 0 {
        buffer[0] = 0
        return 1
    }
    var v = value
    var bytes = [UInt8]()
    let negative = v < 0
    while v != 0 && v != -1 {
        bytes.insert(UInt8(v & 0xFF), at: 0)
        v >>= 8
    }
    if negative && (bytes[0] & 0x80) == 0 {
        bytes.insert(0xFF, at: 0)
    } else if !negative && (bytes[0] & 0x80) != 0 {
        bytes.insert(0, at: 0)
    }
    for i in 0..<bytes.count {
        buffer[i] = bytes[i]
    }
    return Int16(bytes.count)
}

private func encodeIPv4(_ addr: IPv4Address, into buffer: inout [UInt8]) -> Int16 {
    let raw = addr.addr
    buffer[0] = UInt8(raw & 0xFF)
    buffer[1] = UInt8((raw >> 8) & 0xFF)
    buffer[2] = UInt8((raw >> 16) & 0xFF)
    buffer[3] = UInt8((raw >> 24) & 0xFF)
    return 4
}

/// Helper to build a read-only Counter32 scalar node.
private func counterNode(oid: UInt32, getValue: @escaping () -> UInt32) -> SNMPScalarNode {
    let node = SNMPScalarNode(
        oid: oid,
        asn1Type: SNMPASN1.typeCounter32,
        access: .readOnly,
        getValue: { _, buffer in encodeUInt32(getValue(), into: &buffer) }
    )
    node.setupScalarCallbacks()
    return node
}

/// Helper to build a read-only Gauge32 scalar node.
private func gaugeNode(oid: UInt32, getValue: @escaping () -> UInt32) -> SNMPScalarNode {
    let node = SNMPScalarNode(
        oid: oid,
        asn1Type: SNMPASN1.typeGauge32,
        access: .readOnly,
        getValue: { _, buffer in encodeUInt32(getValue(), into: &buffer) }
    )
    node.setupScalarCallbacks()
    return node
}

/// Helper to build a read-only INTEGER scalar node.
private func intNode(oid: UInt32, getValue: @escaping () -> Int32) -> SNMPScalarNode {
    let node = SNMPScalarNode(
        oid: oid,
        asn1Type: SNMPASN1.typeInteger,
        access: .readOnly,
        getValue: { _, buffer in encodeInt32(getValue(), into: &buffer) }
    )
    node.setupScalarCallbacks()
    return node
}

/// Helper to build a read-only TimeTicks scalar node.
private func timeTicksNode(oid: UInt32, getValue: @escaping () -> UInt32) -> SNMPScalarNode {
    let node = SNMPScalarNode(
        oid: oid,
        asn1Type: SNMPASN1.typeTimeTicks,
        access: .readOnly,
        getValue: { _, buffer in encodeUInt32(getValue(), into: &buffer) }
    )
    node.setupScalarCallbacks()
    return node
}

/// Parse an IPv4 address from OID components at given offset.
/// OID components are individual octets in network order.
private func ipv4FromOID(_ oid: [UInt32], at offset: Int) -> IPv4Address {
    return IPv4Address(
        UInt8(oid[offset] & 0xFF),
        UInt8(oid[offset+1] & 0xFF),
        UInt8(oid[offset+2] & 0xFF),
        UInt8(oid[offset+3] & 0xFF)
    )
}

// MARK: - Helper: iterate network interfaces

private func forEachNetif(_ body: (NetworkInterface) -> Void) {
    var netif = NetworkInterface.list
    while let n = netif {
        body(n)
        netif = n.next
    }
}

private func netifCount() -> Int32 {
    var count: Int32 = 0
    forEachNetif { _ in count += 1 }
    return count
}

private func netifByNum(_ num: UInt32) -> NetworkInterface? {
    var netif = NetworkInterface.list
    while let n = netif {
        if UInt32(n.num) + 1 == num { return n }
        netif = n.next
    }
    return nil
}

// MARK: - Interfaces Group (1.3.6.1.2.1.2)

/// MIB-II Interfaces Group (1.3.6.1.2.1.2)
///
/// Implements:
/// - ifNumber              (1.3.6.1.2.1.2.1.0)
/// - ifTable               (1.3.6.1.2.1.2.2) with 22 columns
public final class MIB2InterfacesGroup: @unchecked Sendable {
    public static let shared = MIB2InterfacesGroup()

    public init() {}

    public func buildTreeNode() -> SNMPTreeNode {
        let ifNumberNode = intNode(oid: 1, getValue: { netifCount() })

        let ifColumns: [SNMPTableNode.Column] = [
            .init(subOID: 1, asn1Type: SNMPASN1.typeInteger, access: .readOnly),     // ifIndex
            .init(subOID: 2, asn1Type: SNMPASN1.typeOctetString, access: .readOnly),  // ifDescr
            .init(subOID: 3, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ifType
            .init(subOID: 4, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ifMtu
            .init(subOID: 5, asn1Type: SNMPASN1.typeGauge32, access: .readOnly),      // ifSpeed
            .init(subOID: 6, asn1Type: SNMPASN1.typeOctetString, access: .readOnly),  // ifPhysAddress
            .init(subOID: 7, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ifAdminStatus
            .init(subOID: 8, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ifOperStatus
            .init(subOID: 9, asn1Type: SNMPASN1.typeTimeTicks, access: .readOnly),    // ifLastChange
            .init(subOID: 10, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInOctets
            .init(subOID: 11, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInUcastPkts
            .init(subOID: 12, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInNUcastPkts
            .init(subOID: 13, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInDiscards
            .init(subOID: 14, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInErrors
            .init(subOID: 15, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifInUnknownProtos
            .init(subOID: 16, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifOutOctets
            .init(subOID: 17, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifOutUcastPkts
            .init(subOID: 18, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifOutNUcastPkts
            .init(subOID: 19, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifOutDiscards
            .init(subOID: 20, asn1Type: SNMPASN1.typeCounter32, access: .readOnly),   // ifOutErrors
            .init(subOID: 21, asn1Type: SNMPASN1.typeGauge32, access: .readOnly),     // ifOutQLen
            .init(subOID: 22, asn1Type: SNMPASN1.typeObjectID, access: .readOnly),    // ifSpecific
        ]

        let ifGetCell: (UInt32, [UInt32], SNMPNodeInstance) -> SNMPError = {
            column, rowOID, instance in
            guard rowOID.count == 1, let netif = netifByNum(rowOID[0]) else {
                return .noSuchInstance
            }
            let c = netif.mib2Counters
            instance.getValue = { _, buffer in
                switch column {
                case 1:  return encodeInt32(Int32(netif.num) + 1, into: &buffer)
                case 2:
                    let name = String(UnicodeScalar(netif.name.0)) + String(UnicodeScalar(netif.name.1))
                    let data = Array(name.utf8)
                    for i in 0..<data.count { buffer[i] = data[i] }
                    return Int16(data.count)
                case 3:  return encodeInt32(Int32(netif.linkType), into: &buffer)
                case 4:  return encodeInt32(Int32(netif.mtu), into: &buffer)
                case 5:  return encodeUInt32(netif.linkSpeed, into: &buffer)
                case 6:
                    for i in 0..<Int(netif.hwAddrLen) { buffer[i] = netif.hwAddr[i] }
                    return Int16(netif.hwAddrLen)
                case 7:  return encodeInt32(netif.flags.contains(.up) ? 1 : 2, into: &buffer)
                case 8:
                    let status: Int32
                    if netif.flags.contains(.up) {
                        status = netif.flags.contains(.linkUp) ? 1 : 7
                    } else {
                        status = 2
                    }
                    return encodeInt32(status, into: &buffer)
                case 9:  return encodeUInt32(netif.lastChange, into: &buffer)
                case 10: return encodeUInt32(c.ifInOctets, into: &buffer)
                case 11: return encodeUInt32(c.ifInUcastPkts, into: &buffer)
                case 12: return encodeUInt32(c.ifInNUcastPkts, into: &buffer)
                case 13: return encodeUInt32(c.ifInDiscards, into: &buffer)
                case 14: return encodeUInt32(c.ifInErrors, into: &buffer)
                case 15: return encodeUInt32(c.ifInUnknownProtos, into: &buffer)
                case 16: return encodeUInt32(c.ifOutOctets, into: &buffer)
                case 17: return encodeUInt32(c.ifOutUcastPkts, into: &buffer)
                case 18: return encodeUInt32(c.ifOutNUcastPkts, into: &buffer)
                case 19: return encodeUInt32(c.ifOutDiscards, into: &buffer)
                case 20: return encodeUInt32(c.ifOutErrors, into: &buffer)
                case 21: return encodeUInt32(0, into: &buffer)  // ifOutQLen always 0
                case 22:
                    buffer[0] = 0; buffer[1] = 0  // zeroDotZero = 0.0
                    return 2
                default: return 0
                }
            }
            return .noError
        }

        let ifGetNextCell: (UInt32, inout [UInt32], SNMPNodeInstance) -> SNMPError = {
            _, rowOID, _ in
            let startNum: UInt32 = rowOID.isEmpty ? 0 : rowOID[0]
            var minNum: UInt32 = .max
            var found = false
            forEachNetif { n in
                let idx = UInt32(n.num) + 1
                if idx > startNum && idx < minNum {
                    minNum = idx
                    found = true
                }
            }
            guard found else { return .noSuchInstance }
            rowOID = [minNum]
            return .noError
        }

        let ifTable = SNMPTableNode(
            oid: 2, columns: ifColumns, getCell: ifGetCell, getNextCell: ifGetNextCell
        )

        return SNMPTreeNode(oid: 2, subnodes: [ifNumberNode, ifTable])
    }
}

// MARK: - IP Group (1.3.6.1.2.1.4)

/// MIB-II IP Group (1.3.6.1.2.1.4)
///
/// Implements 19 scalar counters from the IP protocol statistics.
public final class MIB2IPGroup: @unchecked Sendable {
    public static let shared = MIB2IPGroup()

    /// ipForwarding: 1 = forwarding, 2 = not forwarding
    public var ipForwarding: Int32 = 2
    /// ipDefaultTTL
    public var ipDefaultTTL: Int32 = Int32(NetworkInterfaceConstants.defaultTTL)

    public init() {}

    public func buildTreeNode() -> SNMPTreeNode {
        let group = self
        let s = { LWIPStats.shared.mib2 }

        let forwardingNode = SNMPScalarNode(
            oid: 1,
            asn1Type: SNMPASN1.typeInteger,
            access: .readWrite,
            getValue: { _, buffer in encodeInt32(group.ipForwarding, into: &buffer) },
            setTest: { _, _, value in
                guard value.count >= 1 else { return .wrongLength }
                let v = Int32(Int8(bitPattern: value[0]))
                if v != 1 && v != 2 { return .wrongValue }
                return .noError
            },
            setValue: { _, _, value in
                group.ipForwarding = Int32(Int8(bitPattern: value[0]))
                return .noError
            }
        )
        forwardingNode.setupScalarCallbacks()

        let ttlNode = SNMPScalarNode(
            oid: 2,
            asn1Type: SNMPASN1.typeInteger,
            access: .readWrite,
            getValue: { _, buffer in encodeInt32(group.ipDefaultTTL, into: &buffer) },
            setTest: { _, _, value in
                guard value.count >= 1 else { return .wrongLength }
                return .noError
            },
            setValue: { _, _, value in
                group.ipDefaultTTL = Int32(value[0])
                return .noError
            }
        )
        ttlNode.setupScalarCallbacks()

        let nodes: [SNMPNode] = [
            forwardingNode,
            ttlNode,
            counterNode(oid: 3,  getValue: { s().ipInReceives }),
            counterNode(oid: 4,  getValue: { s().ipInHdrErrors }),
            counterNode(oid: 5,  getValue: { s().ipInAddrErrors }),
            counterNode(oid: 6,  getValue: { s().ipForwDatagrams }),
            counterNode(oid: 7,  getValue: { s().ipInUnknownProtos }),
            counterNode(oid: 8,  getValue: { s().ipInDiscards }),
            counterNode(oid: 9,  getValue: { s().ipInDelivers }),
            counterNode(oid: 10, getValue: { s().ipOutRequests }),
            counterNode(oid: 11, getValue: { s().ipOutDiscards }),
            counterNode(oid: 12, getValue: { s().ipOutNoRoutes }),
            intNode(oid: 13, getValue: { 0 }),    // ipReasmTimeout
            counterNode(oid: 14, getValue: { s().ipReasmReqds }),
            counterNode(oid: 15, getValue: { s().ipReasmOks }),
            counterNode(oid: 16, getValue: { s().ipReasmFails }),
            counterNode(oid: 17, getValue: { s().ipFragOks }),
            counterNode(oid: 18, getValue: { s().ipFragFails }),
            counterNode(oid: 19, getValue: { s().ipFragCreates }),
            counterNode(oid: 23, getValue: { 0 }),  // ipRoutingDiscards
        ]

        // Add ipRouteTable (OID 21) and ipNetToMediaTable (OID 22)
        var allNodes = nodes
        allNodes.append(MIB2IPRouteTable.shared.buildTableNode())
        allNodes.append(MIB2IPNetToMediaTable.shared.buildTableNode())

        return SNMPTreeNode(oid: 4, subnodes: allNodes)
    }
}

// MARK: - IP Route Table (1.3.6.1.2.1.4.21)

/// MIB-II ipRouteTable (1.3.6.1.2.1.4.21)
///
/// RFC 1213 IP routing table. In lwIP each network interface essentially
/// represents one route entry (its directly-connected network/mask).
public final class MIB2IPRouteTable: @unchecked Sendable {
    public static let shared = MIB2IPRouteTable()

    public init() {}

    public func buildTableNode() -> SNMPTableNode {
        let columns: [SNMPTableNode.Column] = [
            .init(subOID: 1,  asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),    // ipRouteDest
            .init(subOID: 2,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteIfIndex
            .init(subOID: 3,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteMetric1
            .init(subOID: 4,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteMetric2
            .init(subOID: 5,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteMetric3
            .init(subOID: 6,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteMetric4
            .init(subOID: 7,  asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),    // ipRouteNextHop
            .init(subOID: 8,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteType
            .init(subOID: 9,  asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteProto
            .init(subOID: 10, asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteAge
            .init(subOID: 11, asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),    // ipRouteMask
            .init(subOID: 12, asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // ipRouteMetric5
            .init(subOID: 13, asn1Type: SNMPASN1.typeObjectID, access: .readOnly),  // ipRouteInfo
        ]

        // Row index is the destination IP address (4 OID components).
        let getCellFn: (UInt32, [UInt32], SNMPNodeInstance) -> SNMPError = {
            column, rowOID, instance in
            guard rowOID.count == 4 else { return .noSuchInstance }
            let destIP = ipv4FromOID(rowOID, at: 0)

            // Find the interface whose network matches this destination.
            var found: NetworkInterface?
            forEachNetif { n in
                let network = IPv4Address(networkOrder: n.ipAddr.addr & n.netmask.addr)
                if network == destIP {
                    found = n
                }
            }
            guard let netif = found else { return .noSuchInstance }

            instance.getValue = { _, buffer in
                switch column {
                case 1:  // ipRouteDest – network address
                    return encodeIPv4(IPv4Address(networkOrder: netif.ipAddr.addr & netif.netmask.addr), into: &buffer)
                case 2:  // ipRouteIfIndex
                    return encodeInt32(Int32(netif.num) + 1, into: &buffer)
                case 3:  // ipRouteMetric1
                    return encodeInt32(0, into: &buffer)
                case 4:  // ipRouteMetric2
                    return encodeInt32(-1, into: &buffer)
                case 5:  // ipRouteMetric3
                    return encodeInt32(-1, into: &buffer)
                case 6:  // ipRouteMetric4
                    return encodeInt32(-1, into: &buffer)
                case 7:  // ipRouteNextHop – gateway
                    return encodeIPv4(netif.gateway, into: &buffer)
                case 8:  // ipRouteType – 3 = direct (connected)
                    return encodeInt32(3, into: &buffer)
                case 9:  // ipRouteProto – 2 = local
                    return encodeInt32(2, into: &buffer)
                case 10: // ipRouteAge
                    return encodeInt32(0, into: &buffer)
                case 11: // ipRouteMask
                    return encodeIPv4(netif.netmask, into: &buffer)
                case 12: // ipRouteMetric5
                    return encodeInt32(-1, into: &buffer)
                case 13: // ipRouteInfo – zeroDotZero (0.0)
                    buffer[0] = 0; buffer[1] = 0
                    return 2
                default: return 0
                }
            }
            return .noError
        }

        let getNextCellFn: (UInt32, inout [UInt32], SNMPNodeInstance) -> SNMPError = {
            _, rowOID, _ in
            // Collect all route destination addresses and sort them.
            var dests = [(UInt32, UInt32, UInt32, UInt32)]()
            forEachNetif { n in
                let network = IPv4Address(networkOrder: n.ipAddr.addr & n.netmask.addr)
                let raw = network.addr
                let a = UInt32(raw & 0xFF)
                let b = UInt32((raw >> 8) & 0xFF)
                let c = UInt32((raw >> 16) & 0xFF)
                let d = UInt32((raw >> 24) & 0xFF)
                dests.append((a, b, c, d))
            }
            dests.sort { lhs, rhs in
                if lhs.0 != rhs.0 { return lhs.0 < rhs.0 }
                if lhs.1 != rhs.1 { return lhs.1 < rhs.1 }
                if lhs.2 != rhs.2 { return lhs.2 < rhs.2 }
                return lhs.3 < rhs.3
            }

            // Find the first destination strictly greater than the current row OID.
            for dest in dests {
                let candidate = [dest.0, dest.1, dest.2, dest.3]
                if rowOID.isEmpty || candidate.lexicographicallyPrecedes(rowOID) == false && candidate != rowOID {
                    rowOID = candidate
                    return .noError
                }
            }
            return .noSuchInstance
        }

        return SNMPTableNode(
            oid: 21, columns: columns, getCell: getCellFn, getNextCell: getNextCellFn
        )
    }
}

// MARK: - IP Net-to-Media Table (1.3.6.1.2.1.4.22)

/// MIB-II ipNetToMediaTable (1.3.6.1.2.1.4.22)
///
/// RFC 1213 ARP/neighbor mapping table. Queries `EthARP.table` for entries
/// that are in stable or static state.
public final class MIB2IPNetToMediaTable: @unchecked Sendable {
    public static let shared = MIB2IPNetToMediaTable()

    public init() {}

    public func buildTableNode() -> SNMPTableNode {
        let columns: [SNMPTableNode.Column] = [
            .init(subOID: 1, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ipNetToMediaIfIndex
            .init(subOID: 2, asn1Type: SNMPASN1.typeOctetString, access: .readOnly),  // ipNetToMediaPhysAddress
            .init(subOID: 3, asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),       // ipNetToMediaNetAddress
            .init(subOID: 4, asn1Type: SNMPASN1.typeInteger, access: .readOnly),      // ipNetToMediaType
        ]

        // Row index is ifIndex(1) + IP address(4) = 5 OID components.
        let getCellFn: (UInt32, [UInt32], SNMPNodeInstance) -> SNMPError = {
            column, rowOID, instance in
            guard rowOID.count == 5 else { return .noSuchInstance }
            let ifIndex = rowOID[0]
            let ipAddr = ipv4FromOID(rowOID, at: 1)

            // Search the ARP table for a matching entry.
            for entry in EthARP.table {
                guard entry.state == .stable || entry.state == .stableReRequesting1
                    || entry.state == .stableReRequesting2 || entry.state == .staticEntry
                else { continue }
                guard let entryNetif = entry.netif else { continue }
                let entryIfIndex = UInt32(entryNetif.num) + 1
                if entryIfIndex == ifIndex && entry.ipAddr == ipAddr {
                    let capturedEntry = entry
                    let capturedIfIndex = entryIfIndex
                    instance.getValue = { _, buffer in
                        switch column {
                        case 1: // ipNetToMediaIfIndex
                            return encodeInt32(Int32(capturedIfIndex), into: &buffer)
                        case 2: // ipNetToMediaPhysAddress (6-byte MAC)
                            let mac = capturedEntry.ethAddr
                            buffer[0] = mac[0]
                            buffer[1] = mac[1]
                            buffer[2] = mac[2]
                            buffer[3] = mac[3]
                            buffer[4] = mac[4]
                            buffer[5] = mac[5]
                            return 6
                        case 3: // ipNetToMediaNetAddress
                            return encodeIPv4(capturedEntry.ipAddr, into: &buffer)
                        case 4: // ipNetToMediaType
                            let mediaType: Int32
                            if capturedEntry.state == .staticEntry {
                                mediaType = 4  // static
                            } else {
                                mediaType = 3  // dynamic
                            }
                            return encodeInt32(mediaType, into: &buffer)
                        default: return 0
                        }
                    }
                    return .noError
                }
            }
            return .noSuchInstance
        }

        let getNextCellFn: (UInt32, inout [UInt32], SNMPNodeInstance) -> SNMPError = {
            _, rowOID, _ in
            // Collect all valid ARP entries sorted by (ifIndex, ip0, ip1, ip2, ip3).
            var entries = [(UInt32, UInt32, UInt32, UInt32, UInt32)]()
            for entry in EthARP.table {
                guard entry.state == .stable || entry.state == .stableReRequesting1
                    || entry.state == .stableReRequesting2 || entry.state == .staticEntry
                else { continue }
                guard let entryNetif = entry.netif else { continue }
                let ifIdx = UInt32(entryNetif.num) + 1
                let raw = entry.ipAddr.addr
                let a = UInt32(raw & 0xFF)
                let b = UInt32((raw >> 8) & 0xFF)
                let c = UInt32((raw >> 16) & 0xFF)
                let d = UInt32((raw >> 24) & 0xFF)
                entries.append((ifIdx, a, b, c, d))
            }
            entries.sort { lhs, rhs in
                if lhs.0 != rhs.0 { return lhs.0 < rhs.0 }
                if lhs.1 != rhs.1 { return lhs.1 < rhs.1 }
                if lhs.2 != rhs.2 { return lhs.2 < rhs.2 }
                if lhs.3 != rhs.3 { return lhs.3 < rhs.3 }
                return lhs.4 < rhs.4
            }

            for e in entries {
                let candidate = [e.0, e.1, e.2, e.3, e.4]
                if rowOID.isEmpty || (candidate.lexicographicallyPrecedes(rowOID) == false && candidate != rowOID) {
                    rowOID = candidate
                    return .noError
                }
            }
            return .noSuchInstance
        }

        return SNMPTableNode(
            oid: 22, columns: columns, getCell: getCellFn, getNextCell: getNextCellFn
        )
    }
}

// MARK: - ICMP Group (1.3.6.1.2.1.5)

/// MIB-II ICMP Group (1.3.6.1.2.1.5)
///
/// Implements 26 scalar counters for ICMP statistics.
public final class MIB2ICMPGroup: @unchecked Sendable {
    public static let shared = MIB2ICMPGroup()

    public init() {}

    public func buildTreeNode() -> SNMPTreeNode {
        let s = { LWIPStats.shared.mib2 }

        let nodes: [SNMPNode] = [
            counterNode(oid: 1,  getValue: { s().icmpInMsgs }),
            counterNode(oid: 2,  getValue: { s().icmpInErrors }),
            counterNode(oid: 3,  getValue: { s().icmpInDestUnreachs }),
            counterNode(oid: 4,  getValue: { s().icmpInTimeExcds }),
            counterNode(oid: 5,  getValue: { s().icmpInParmProbs }),
            counterNode(oid: 6,  getValue: { s().icmpInSrcQuenchs }),
            counterNode(oid: 7,  getValue: { s().icmpInRedirects }),
            counterNode(oid: 8,  getValue: { s().icmpInEchos }),
            counterNode(oid: 9,  getValue: { s().icmpInEchoReps }),
            counterNode(oid: 10, getValue: { s().icmpInTimestamps }),
            counterNode(oid: 11, getValue: { s().icmpInTimestampReps }),
            counterNode(oid: 12, getValue: { s().icmpInAddrMasks }),
            counterNode(oid: 13, getValue: { s().icmpInAddrMaskReps }),
            counterNode(oid: 14, getValue: { s().icmpOutMsgs }),
            counterNode(oid: 15, getValue: { s().icmpOutErrors }),
            counterNode(oid: 16, getValue: { s().icmpOutDestUnreachs }),
            counterNode(oid: 17, getValue: { s().icmpOutTimeExcds }),
            counterNode(oid: 18, getValue: { 0 }),  // icmpOutParmProbs
            counterNode(oid: 19, getValue: { 0 }),  // icmpOutSrcQuenchs
            counterNode(oid: 20, getValue: { 0 }),  // icmpOutRedirects
            counterNode(oid: 21, getValue: { s().icmpOutEchos }),
            counterNode(oid: 22, getValue: { s().icmpOutEchoReps }),
            counterNode(oid: 23, getValue: { 0 }),  // icmpOutTimestamps
            counterNode(oid: 24, getValue: { 0 }),  // icmpOutTimestampReps
            counterNode(oid: 25, getValue: { 0 }),  // icmpOutAddrMasks
            counterNode(oid: 26, getValue: { 0 }),  // icmpOutAddrMaskReps
        ]

        return SNMPTreeNode(oid: 5, subnodes: nodes)
    }
}

// MARK: - TCP Group (1.3.6.1.2.1.6)

/// MIB-II TCP Group (1.3.6.1.2.1.6)
///
/// Implements:
/// - 15 scalar values (algorithm, limits, counters)
/// - tcpConnTable (1.3.6.1.2.1.6.13) for active IPv4 TCP connections
public final class MIB2TCPGroup: @unchecked Sendable {
    public static let shared = MIB2TCPGroup()

    public init() {}

    /// Count TCP PCBs in ESTABLISHED or CLOSE_WAIT state.
    private func tcpCurrEstab() -> UInt32 {
        var count: UInt32 = 0
        var pcb = TCPGlobal.shared.activePCBs
        while let p = pcb {
            if p.state == .established || p.state == .closeWait {
                count += 1
            }
            pcb = p.next
        }
        return count
    }

    public func buildTreeNode() -> SNMPTreeNode {
        let group = self
        let s = { LWIPStats.shared.mib2 }

        let nodes: [SNMPNode] = [
            intNode(oid: 1, getValue: { 4 }),                       // tcpRtoAlgorithm (vanj)
            intNode(oid: 2, getValue: { 1000 }),                    // tcpRtoMin (ms)
            intNode(oid: 3, getValue: { 60000 }),                   // tcpRtoMax (ms)
            intNode(oid: 4, getValue: { -1 }),                      // tcpMaxConn (dynamic)
            counterNode(oid: 5,  getValue: { s().tcpActiveOpens }),
            counterNode(oid: 6,  getValue: { s().tcpPassiveOpens }),
            counterNode(oid: 7,  getValue: { s().tcpAttemptFails }),
            counterNode(oid: 8,  getValue: { s().tcpEstabResets }),
            gaugeNode(oid: 9,    getValue: { group.tcpCurrEstab() }),
            counterNode(oid: 10, getValue: { s().tcpInSegs }),
            counterNode(oid: 11, getValue: { s().tcpOutSegs }),
            counterNode(oid: 12, getValue: { s().tcpRetransSegs }),
            // OID 13 = tcpConnTable (below)
            counterNode(oid: 14, getValue: { s().tcpInErrs }),
            counterNode(oid: 15, getValue: { s().tcpOutRsts }),
        ]

        let tcpConnTable = buildTCPConnTable()

        var allNodes = [SNMPNode]()
        // Insert scalars up to OID 12, then table at 13, then remaining scalars
        for node in nodes {
            if node.oid == 14 {
                allNodes.append(tcpConnTable)
            }
            allNodes.append(node)
        }

        return SNMPTreeNode(oid: 6, subnodes: allNodes)
    }

    /// tcpConnTable (1.3.6.1.2.1.6.13)
    /// Indexed by: localIP(4) + localPort(1) + remoteIP(4) + remotePort(1)
    private func buildTCPConnTable() -> SNMPTableNode {
        let columns: [SNMPTableNode.Column] = [
            .init(subOID: 1, asn1Type: SNMPASN1.typeInteger, access: .readOnly),    // tcpConnState
            .init(subOID: 2, asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),      // tcpConnLocalAddress
            .init(subOID: 3, asn1Type: SNMPASN1.typeInteger, access: .readOnly),     // tcpConnLocalPort
            .init(subOID: 4, asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),      // tcpConnRemAddress
            .init(subOID: 5, asn1Type: SNMPASN1.typeInteger, access: .readOnly),     // tcpConnRemPort
        ]

        let getCellFn: (UInt32, [UInt32], SNMPNodeInstance) -> SNMPError = {
            column, rowOID, instance in
            // rowOID = [ip0, ip1, ip2, ip3, localPort, rip0, rip1, rip2, rip3, remotePort]
            guard rowOID.count == 10 else { return .noSuchInstance }
            let localIP = ipv4FromOID(rowOID, at: 0)
            let localPort = UInt16(rowOID[4])
            let remoteIP = ipv4FromOID(rowOID, at: 5)
            let remotePort = UInt16(rowOID[9])

            // Search listen PCBs
            var lpcb = TCPGlobal.shared.listenPCBs
            while let l = lpcb {
                if l.localPort == localPort {
                    let lAddr = l.localIP.ipv4 ?? .any
                    if lAddr == localIP && remoteIP == .any && remotePort == 0 {
                        instance.getValue = { _, buffer in
                            switch column {
                            case 1: return encodeInt32(Int32(TCPState.listen.rawValue) + 1, into: &buffer)
                            case 2: return encodeIPv4(lAddr, into: &buffer)
                            case 3: return encodeInt32(Int32(l.localPort), into: &buffer)
                            case 4: return encodeIPv4(.any, into: &buffer)
                            case 5: return encodeInt32(0, into: &buffer)
                            default: return 0
                            }
                        }
                        return .noError
                    }
                }
                lpcb = l.next
            }

            // Search active PCBs
            var pcb = TCPGlobal.shared.activePCBs
            while let p = pcb {
                let pLocal = p.localIP.ipv4 ?? .any
                let pRemote = p.remoteIP.ipv4 ?? .any
                if pLocal == localIP && p.localPort == localPort &&
                   pRemote == remoteIP && p.remotePort == remotePort {
                    instance.getValue = { _, buffer in
                        switch column {
                        case 1: return encodeInt32(Int32(p.state.rawValue) + 1, into: &buffer)
                        case 2: return encodeIPv4(pLocal, into: &buffer)
                        case 3: return encodeInt32(Int32(p.localPort), into: &buffer)
                        case 4: return encodeIPv4(pRemote, into: &buffer)
                        case 5: return encodeInt32(Int32(p.remotePort), into: &buffer)
                        default: return 0
                        }
                    }
                    return .noError
                }
                pcb = p.next
            }

            return .noSuchInstance
        }

        let getNextCellFn: (UInt32, inout [UInt32], SNMPNodeInstance) -> SNMPError = {
            _, rowOID, _ in
            // Collect all TCP connections as 10-component row indices:
            // [localIP(4), localPort(1), remoteIP(4), remotePort(1)]
            var entries = [[UInt32]]()

            // Listen PCBs: remote is 0.0.0.0:0
            var lpcb = TCPGlobal.shared.listenPCBs
            while let l = lpcb {
                let lAddr = l.localIP.ipv4 ?? .any
                let raw = lAddr.addr
                let entry: [UInt32] = [
                    UInt32(raw & 0xFF), UInt32((raw >> 8) & 0xFF),
                    UInt32((raw >> 16) & 0xFF), UInt32((raw >> 24) & 0xFF),
                    UInt32(l.localPort),
                    0, 0, 0, 0, // remote IP = 0.0.0.0
                    0            // remote port = 0
                ]
                entries.append(entry)
                lpcb = l.next
            }

            // Active PCBs
            var pcb = TCPGlobal.shared.activePCBs
            while let p = pcb {
                let lAddr = p.localIP.ipv4 ?? .any
                let rAddr = p.remoteIP.ipv4 ?? .any
                let lRaw = lAddr.addr
                let rRaw = rAddr.addr
                let entry: [UInt32] = [
                    UInt32(lRaw & 0xFF), UInt32((lRaw >> 8) & 0xFF),
                    UInt32((lRaw >> 16) & 0xFF), UInt32((lRaw >> 24) & 0xFF),
                    UInt32(p.localPort),
                    UInt32(rRaw & 0xFF), UInt32((rRaw >> 8) & 0xFF),
                    UInt32((rRaw >> 16) & 0xFF), UInt32((rRaw >> 24) & 0xFF),
                    UInt32(p.remotePort)
                ]
                entries.append(entry)
                pcb = p.next
            }

            // Sort lexicographically
            entries.sort { lhs, rhs in
                for i in 0..<lhs.count {
                    if lhs[i] != rhs[i] { return lhs[i] < rhs[i] }
                }
                return false
            }

            // Find the first entry strictly after the current rowOID
            for entry in entries {
                if rowOID.isEmpty || (entry.lexicographicallyPrecedes(rowOID) == false && entry != rowOID) {
                    rowOID = entry
                    return .noError
                }
            }
            return .noSuchInstance
        }

        return SNMPTableNode(
            oid: 13, columns: columns, getCell: getCellFn, getNextCell: getNextCellFn
        )
    }
}

// MARK: - UDP Group (1.3.6.1.2.1.7)

/// MIB-II UDP Group (1.3.6.1.2.1.7)
///
/// Implements:
/// - 4 scalar counters
/// - udpTable (1.3.6.1.2.1.7.5) for local UDP endpoints
public final class MIB2UDPGroup: @unchecked Sendable {
    public static let shared = MIB2UDPGroup()

    public init() {}

    public func buildTreeNode() -> SNMPTreeNode {
        let s = { LWIPStats.shared.mib2 }

        let scalars: [SNMPNode] = [
            counterNode(oid: 1, getValue: { s().udpInDatagrams }),
            counterNode(oid: 2, getValue: { s().udpNoPorts }),
            counterNode(oid: 3, getValue: { s().udpInErrors }),
            counterNode(oid: 4, getValue: { s().udpOutDatagrams }),
        ]

        let udpTable = buildUDPTable()

        var nodes = scalars
        nodes.append(udpTable)
        return SNMPTreeNode(oid: 7, subnodes: nodes)
    }

    /// udpTable (1.3.6.1.2.1.7.5)
    /// Indexed by: localIP(4) + localPort(1)
    private func buildUDPTable() -> SNMPTableNode {
        let columns: [SNMPTableNode.Column] = [
            .init(subOID: 1, asn1Type: SNMPASN1.typeIPAddr, access: .readOnly),   // udpLocalAddress
            .init(subOID: 2, asn1Type: SNMPASN1.typeInteger, access: .readOnly),   // udpLocalPort
        ]

        let getCellFn: (UInt32, [UInt32], SNMPNodeInstance) -> SNMPError = {
            column, rowOID, instance in
            guard rowOID.count == 5 else { return .noSuchInstance }
            let localIP = ipv4FromOID(rowOID, at: 0)
            let localPort = UInt16(rowOID[4])

            var pcb = UDPGlobal.shared.pcbs
            while let p = pcb {
                let pLocal = p.localIP.ipv4 ?? .any
                if pLocal == localIP && p.localPort == localPort {
                    instance.getValue = { _, buffer in
                        switch column {
                        case 1: return encodeIPv4(pLocal, into: &buffer)
                        case 2: return encodeInt32(Int32(p.localPort), into: &buffer)
                        default: return 0
                        }
                    }
                    return .noError
                }
                pcb = p.next
            }
            return .noSuchInstance
        }

        let getNextCellFn: (UInt32, inout [UInt32], SNMPNodeInstance) -> SNMPError = {
            _, rowOID, _ in
            // Collect all UDP endpoints as 5-component row indices:
            // [localIP(4), localPort(1)]
            var entries = [[UInt32]]()

            var pcb = UDPGlobal.shared.pcbs
            while let p = pcb {
                let lAddr = p.localIP.ipv4 ?? .any
                let raw = lAddr.addr
                let entry: [UInt32] = [
                    UInt32(raw & 0xFF), UInt32((raw >> 8) & 0xFF),
                    UInt32((raw >> 16) & 0xFF), UInt32((raw >> 24) & 0xFF),
                    UInt32(p.localPort)
                ]
                entries.append(entry)
                pcb = p.next
            }

            // Sort lexicographically
            entries.sort { lhs, rhs in
                for i in 0..<lhs.count {
                    if lhs[i] != rhs[i] { return lhs[i] < rhs[i] }
                }
                return false
            }

            // Find the first entry strictly after the current rowOID
            for entry in entries {
                if rowOID.isEmpty || (entry.lexicographicallyPrecedes(rowOID) == false && entry != rowOID) {
                    rowOID = entry
                    return .noError
                }
            }
            return .noSuchInstance
        }

        return SNMPTableNode(
            oid: 5, columns: columns, getCell: getCellFn, getNextCell: getNextCellFn
        )
    }
}

// MARK: - SNMP Stats Group (1.3.6.1.2.1.11)

/// MIB-II SNMP Group (1.3.6.1.2.1.11)
///
/// Implements 30 scalar counters for SNMP agent statistics,
/// plus 2 control values (snmpEnableAuthenTraps, silentDrops, proxyDrops).
public final class MIB2SNMPGroup: @unchecked Sendable {
    public static let shared = MIB2SNMPGroup()

    /// snmpEnableAuthenTraps: 1 = enabled, 2 = disabled
    public var enableAuthenTraps: Int32 = 1

    public init() {}

    public func buildTreeNode() -> SNMPTreeNode {
        let group = self
        let s = { SNMPStatistics.shared }

        let authenTrapsNode = SNMPScalarNode(
            oid: 30,
            asn1Type: SNMPASN1.typeInteger,
            access: .readWrite,
            getValue: { _, buffer in encodeInt32(group.enableAuthenTraps, into: &buffer) },
            setTest: { _, _, value in
                guard value.count >= 1 else { return .wrongLength }
                let v = Int32(Int8(bitPattern: value[0]))
                if v != 1 && v != 2 { return .wrongValue }
                return .noError
            },
            setValue: { _, _, value in
                group.enableAuthenTraps = Int32(Int8(bitPattern: value[0]))
                return .noError
            }
        )
        authenTrapsNode.setupScalarCallbacks()

        let nodes: [SNMPNode] = [
            counterNode(oid: 1,  getValue: { s().inPkts }),
            counterNode(oid: 2,  getValue: { s().outPkts }),
            counterNode(oid: 3,  getValue: { s().inBadVersions }),
            counterNode(oid: 4,  getValue: { s().inBadCommunityNames }),
            counterNode(oid: 5,  getValue: { s().inBadCommunityUses }),
            counterNode(oid: 6,  getValue: { s().inASNParseErrs }),
            // OID 7 is not defined
            counterNode(oid: 8,  getValue: { s().inTooBigs }),
            counterNode(oid: 9,  getValue: { s().inNoSuchNames }),
            counterNode(oid: 10, getValue: { s().inBadValues }),
            counterNode(oid: 11, getValue: { s().inReadOnlys }),
            counterNode(oid: 12, getValue: { s().inGenErrs }),
            counterNode(oid: 13, getValue: { s().inTotalReqVars }),
            counterNode(oid: 14, getValue: { s().inTotalSetVars }),
            counterNode(oid: 15, getValue: { s().inGetRequests }),
            counterNode(oid: 16, getValue: { s().inGetNexts }),
            counterNode(oid: 17, getValue: { s().inSetRequests }),
            counterNode(oid: 18, getValue: { s().inGetResponses }),
            counterNode(oid: 19, getValue: { s().inTraps }),
            counterNode(oid: 20, getValue: { s().outTooBigs }),
            counterNode(oid: 21, getValue: { s().outNoSuchNames }),
            counterNode(oid: 22, getValue: { s().outBadValues }),
            // OID 23 is not defined
            counterNode(oid: 24, getValue: { s().outGenErrs }),
            counterNode(oid: 25, getValue: { s().outGetRequests }),
            counterNode(oid: 26, getValue: { s().outGetNexts }),
            counterNode(oid: 27, getValue: { s().outSetRequests }),
            counterNode(oid: 28, getValue: { s().outGetResponses }),
            counterNode(oid: 29, getValue: { s().outTraps }),
            authenTrapsNode,
            counterNode(oid: 31, getValue: { 0 }),  // snmpSilentDrops
            counterNode(oid: 32, getValue: { 0 }),  // snmpProxyDrops
        ]

        return SNMPTreeNode(oid: 11, subnodes: nodes)
    }
}

// MARK: - Combined MIB-II Builder

extension MIB2SystemGroup {
    /// Build a complete MIB-II with all groups (system, interfaces, IP, ICMP, TCP, UDP, SNMP).
    public func buildFullMIB2() -> SNMPMIB {
        let systemTreeNode = SNMPTreeNode(oid: 1, subnodes: [
            buildSysDescrNode(),
            buildSysObjectIDNode(),
            buildSysUpTimeNode(),
            buildSysContactNode(),
            buildSysNameNode(),
            buildSysLocationNode(),
            buildSysServicesNode(),
        ])

        let mib2Root = SNMPTreeNode(oid: 1, subnodes: [
            systemTreeNode,                                   // .1 (system)
            MIB2InterfacesGroup.shared.buildTreeNode(),       // .2 (interfaces)
            MIB2IPGroup.shared.buildTreeNode(),               // .4 (ip)
            MIB2ICMPGroup.shared.buildTreeNode(),             // .5 (icmp)
            MIB2TCPGroup.shared.buildTreeNode(),              // .6 (tcp)
            MIB2UDPGroup.shared.buildTreeNode(),              // .7 (udp)
            MIB2SNMPGroup.shared.buildTreeNode(),             // .11 (snmp)
        ])

        return SNMPMIB(baseOID: [1, 3, 6, 1, 2, 1], rootNode: mib2Root)
    }
}

extension SNMPAgent {
    /// Create and start an SNMP agent with all MIB-II groups.
    public func startWithFullMIB2() -> LWIPError {
        let mib2 = MIB2SystemGroup.shared.buildFullMIB2()
        setMIBs([mib2])
        return start()
    }
}
