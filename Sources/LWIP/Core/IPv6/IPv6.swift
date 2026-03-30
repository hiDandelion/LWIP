//
//  IPv6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for IPv6 header-related constants.
public enum IPv6HeaderConstants {
    /// Minimum MTU as required by RFC 2460.
    public static let minimumMTU: UInt16 = 1280
    /// Header length in bytes.
    public static let length: Int = 40
}

/// IPv6 next-header / protocol numbers.
public enum IPv6NextHeader: UInt8, Sendable, Equatable {
    case hopByHop    = 0
    case tcp         = 6
    case udp         = 17
    case encaps      = 41
    case routing     = 43
    case fragment    = 44
    case icmpv6      = 58
    case none        = 59
    case destOpts    = 60
    case udpLite     = 136
}

/// IPv6 extension header option types.
public enum IPv6OptionType: UInt8, Sendable {
    case pad1         = 0
    case padN         = 1
    case routerAlert  = 5
    case jumbo        = 194
    case homeAddress  = 201
}

/// Router alert option constants.
public enum IPv6RouterAlert {
    public static let dataLength: UInt8 = 2
    public static let mldValue: UInt16 = 0
}

/// IPv6 routing header types.
public enum IPv6RoutingType {
    public static let type2: UInt8 = 2
    public static let rpl: UInt8 = 3
}

// MARK: - IPv6 Header

/// IPv6 packet header (40 bytes).
///
/// Layout:
/// - Bits [31:28] version (4), [27:20] traffic class (8), [19:0] flow label (20)
/// - payloadLength: UInt16
/// - nextHeader: UInt8
/// - hopLimit: UInt8
/// - src: IPv6Address
/// - dest: IPv6Address
public struct IPv6Header: Sendable {
    /// Combined version (4 bits), traffic class (8 bits), flow label (20 bits).
    public var versionTrafficClassFlowLabel: UInt32
    /// Payload length in bytes (network byte order value already converted).
    public var payloadLength: UInt16
    /// Next header protocol number.
    public var nextHeader: UInt8
    /// Hop limit.
    public var hopLimit: UInt8
    /// Source address.
    public var src: IPv6Address
    /// Destination address.
    public var dest: IPv6Address

    @inlinable
    public var version: UInt8 {
        UInt8((versionTrafficClassFlowLabel >> 28) & 0x0F)
    }

    @inlinable
    public var trafficClass: UInt8 {
        UInt8((versionTrafficClassFlowLabel >> 20) & 0xFF)
    }

    @inlinable
    public var flowLabel: UInt32 {
        versionTrafficClassFlowLabel & 0x000F_FFFF
    }

    @inlinable
    public init(trafficClass tc: UInt8 = 0, flowLabel fl: UInt32 = 0,
                payloadLength: UInt16 = 0, nextHeader: UInt8 = 0,
                hopLimit: UInt8 = 255,
                src: IPv6Address = .any, dest: IPv6Address = .any) {
        self.versionTrafficClassFlowLabel =
            (6 << 28) | (UInt32(tc) << 20) | (fl & 0x000F_FFFF)
        self.payloadLength = payloadLength
        self.nextHeader = nextHeader
        self.hopLimit = hopLimit
        self.src = src
        self.dest = dest
    }

    /// Read an IPv6 header from a Pbuf's payload at a given offset.
    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + IPv6HeaderConstants.length else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.versionTrafficClassFlowLabel = p.loadUnaligned(fromByteOffset: 0, as: UInt32.self).bigEndian
        self.payloadLength = p.loadUnaligned(fromByteOffset: 4, as: UInt16.self).bigEndian
        self.nextHeader = p.load(fromByteOffset: 6, as: UInt8.self)
        self.hopLimit = p.load(fromByteOffset: 7, as: UInt8.self)
        self.src = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )
        self.dest = IPv6Address(
            p.loadUnaligned(fromByteOffset: 24, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 28, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 32, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 36, as: UInt32.self)
        )
    }

    /// Write this header into a Pbuf's payload at a given offset.
    @inlinable
    public func write(to pbuf: Pbuf, offset: Int = 0) {
        let p = pbuf.payload.advanced(by: offset)
        p.storeBytes(of: versionTrafficClassFlowLabel.bigEndian, toByteOffset: 0, as: UInt32.self)
        p.storeBytes(of: payloadLength.bigEndian, toByteOffset: 4, as: UInt16.self)
        p.storeBytes(of: nextHeader, toByteOffset: 6, as: UInt8.self)
        p.storeBytes(of: hopLimit, toByteOffset: 7, as: UInt8.self)
        src.writeNetworkBytes(to: p.advanced(by: 8))
        dest.writeNetworkBytes(to: p.advanced(by: 24))
    }
}

// MARK: - Hop-by-Hop / Destination Options Header

/// Common structure for Hop-by-Hop and Destination options extension headers.
public struct IPv6ExtensionHeader: Sendable {
    public var nextHeader: UInt8
    /// Header extension length in 8-octet units (not counting first 8 octets).
    public var headerExtLength: UInt8

    /// Total header length in bytes.
    @inlinable
    public var totalLength: Int { 8 * (1 + Int(headerExtLength)) }

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + 2 else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.nextHeader = p.load(fromByteOffset: 0, as: UInt8.self)
        self.headerExtLength = p.load(fromByteOffset: 1, as: UInt8.self)
    }
}

// MARK: - Fragment Header

/// IPv6 Fragment extension header (8 bytes).
public struct IPv6FragmentHeader: Sendable {
    public static let length: Int = 8
    public static let offsetMask: UInt16 = 0xFFF8
    public static let moreFlag: UInt16 = 0x0001

    public var nextHeader: UInt8
    public var reserved: UInt8
    public var fragmentOffset: UInt16
    public var identification: UInt32

    /// Fragment offset in bytes (upper 13 bits).
    @inlinable
    public var offset: UInt16 { fragmentOffset & Self.offsetMask }

    /// More fragments flag.
    @inlinable
    public var moreFragments: Bool { (fragmentOffset & Self.moreFlag) != 0 }

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + 8 else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.nextHeader = p.load(fromByteOffset: 0, as: UInt8.self)
        self.reserved = p.load(fromByteOffset: 1, as: UInt8.self)
        self.fragmentOffset = p.loadUnaligned(fromByteOffset: 2, as: UInt16.self).bigEndian
        self.identification = p.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
    }
}

// MARK: - Routing Header

/// IPv6 Routing extension header.
public struct IPv6RoutingHeader: Sendable {
    public var nextHeader: UInt8
    public var headerExtLength: UInt8
    public var routingType: UInt8
    public var segmentsLeft: UInt8

    @inlinable
    public var totalLength: Int { 8 * (1 + Int(headerExtLength)) }

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + 4 else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.nextHeader = p.load(fromByteOffset: 0, as: UInt8.self)
        self.headerExtLength = p.load(fromByteOffset: 1, as: UInt8.self)
        self.routingType = p.load(fromByteOffset: 2, as: UInt8.self)
        self.segmentsLeft = p.load(fromByteOffset: 3, as: UInt8.self)
    }
}

// MARK: - Current Packet Context

/// Thread-local (global in single-threaded lwIP) context for the packet
/// currently being processed.
public final class IPv6InputContext: @unchecked Sendable {
    public var currentHeader: IPv6Header?
    public var currentNetif: NetworkInterface?
    public var inputNetif: NetworkInterface?
    public var currentSrc: IPv6Address = .any
    public var currentDest: IPv6Address = .any
    public var headerTotalLength: UInt16 = 0

    public init() {}

    @inlinable
    public func reset() {
        currentHeader = nil
        currentNetif = nil
        inputNetif = nil
        currentSrc = .any
        currentDest = .any
        headerTotalLength = 0
    }
}

// MARK: - IPv6 Module

/// IPv6 protocol processing.
public enum IPv6 {

    /// Global input context (lwIP is single-threaded).
    public static let currentContext = IPv6InputContext()

    // MARK: - Routing

    /// Find the appropriate network interface for a given IPv6 source/destination.
    ///
    /// Follows RFC routing heuristics:
    /// 1. Single netif fast path
    /// 2. Zoned destination match
    /// 3. Scoped source/destination match
    /// 4. Destination subnet match to configured address
    /// 5. Router-announced route (via ND6)
    /// 6. Source address match
    /// 7. Default netif
    public static func route(src: IPv6Address, dest: IPv6Address) -> NetworkInterface? {
        let list = NetworkInterface.list

        // Fast path: single interface
        if let first = list, first.next == nil {
            guard first.isUp && first.isLinkUp else { return nil }
            if dest.hasZone && !dest.testZone(on: first) { return nil }
            return first
        }

        // Zoned destination
        if dest.hasZone {
            var netif = list
            while let n = netif {
                if dest.testZone(on: n) && n.isUp && n.isLinkUp {
                    return n
                }
                netif = n.next
            }
            return nil
        }

        // Scoped source/dest
        if dest.isLinkLocal || dest.isMulticastLinkLocal || dest.isMulticastInterfaceLocal ||
           src.isLinkLocal || src.isLoopback {
            // Match by source address
            var netif = list
            while let n = netif {
                if n.isUp && n.isLinkUp {
                    for i in 0..<n.ipv6AddressCount {
                        if n.ipv6AddressIsValid(index: i) &&
                           n.ipv6Address(at: i).equalsIgnoringZone(src) {
                            return n
                        }
                    }
                }
                netif = n.next
            }
            return nil
        }

        // Destination subnet match
        var netif = list
        while let n = netif {
            if n.isUp && n.isLinkUp {
                for i in 0..<n.ipv6AddressCount {
                    if n.ipv6AddressIsValid(index: i) {
                        let addr = n.ipv6Address(at: i)
                        if dest.matchesSubnet(of: addr) &&
                           (n.ipv6AddressIsStatic(index: i) || dest == addr) {
                            return n
                        }
                    }
                }
            }
            netif = n.next
        }

        // ND6 router-announced route
        if let routeNetif = ND6.findRoute(for: dest) {
            return routeNetif
        }

        // Source address match (unscoped)
        if !src.isAny {
            netif = list
            while let n = netif {
                if n.isUp && n.isLinkUp {
                    for i in 0..<n.ipv6AddressCount {
                        if n.ipv6AddressIsValid(index: i) && src == n.ipv6Address(at: i) {
                            return n
                        }
                    }
                }
                netif = n.next
            }
        }

        // Loopback fallback
        if dest.isLoopback {
            if let def = NetworkInterface.defaultInterface, def.isUp {
                return def
            }
            netif = list
            while let n = netif {
                if n.isUp { return n }
                netif = n.next
            }
            return nil
        }

        // Default netif
        guard let def = NetworkInterface.defaultInterface,
              def.isUp && def.isLinkUp else {
            return nil
        }
        return def
    }

    // MARK: - Source Address Selection

    /// Select the best IPv6 source address for a destination on a given interface.
    ///
    /// Implements RFC 6724 Sec. 5 (Rules 1, 2, 3, 8 partially).
    public static func selectSourceAddress(on netif: NetworkInterface,
                                           for dest: IPv6Address) -> IPv6Address? {
        let destScope = dest.addressScope

        var bestAddr: IPv6Address? = nil
        var bestScope: Int8 = -1
        var bestPref: Bool = false
        var bestBits: Bool = false

        for i in 0..<netif.ipv6AddressCount {
            guard netif.ipv6AddressIsValid(index: i) else { continue }
            let cand = netif.ipv6Address(at: i)
            let candScope = cand.addressScope
            let candPref = netif.ipv6AddressIsPreferred(index: i)
            let candBits = cand.matchesSubnet(of: dest)

            // Rule 1: exact match
            if candBits && cand == dest {
                return cand
            }

            if bestAddr == nil ||
               (candScope < bestScope && candScope >= destScope) ||
               (candScope > bestScope && bestScope < destScope) ||
               (candScope == bestScope && ((candPref && !bestPref) ||
                (candPref == bestPref && candBits && !bestBits))) {
                bestAddr = cand
                bestScope = candScope
                bestPref = candPref
                bestBits = candBits
            }
        }

        return bestAddr
    }

    // MARK: - Input

    /// Process an incoming IPv6 packet.
    ///
    /// - Parameters:
    ///   - pbuf: The received packet (payload pointing to IPv6 header).
    ///   - inputNetif: The interface on which the packet was received.
    /// - Returns: `.ok` always (drops are handled internally).
    @discardableResult
    public static func input(_ pbuf: Pbuf, on inputNetif: NetworkInterface) -> LWIPError {
        // Parse IPv6 header
        guard let ip6hdr = IPv6Header(reading: pbuf) else {
            pbuf.free()
            return .ok
        }

        // Version check
        guard ip6hdr.version == 6 else {
            pbuf.free()
            return .ok
        }

        // Length checks
        let plen = Int(ip6hdr.payloadLength)
        guard IPv6HeaderConstants.length <= pbuf.length,
              plen <= pbuf.totalLength - IPv6HeaderConstants.length else {
            pbuf.free()
            return .ok
        }

        // Trim to actual IPv6 packet size
        pbuf.realloc(to: UInt16(IPv6HeaderConstants.length + plen))

        // Extract and validate addresses
        let srcAddr = ip6hdr.src
        let destAddr = ip6hdr.dest

        // Reject IPv4-mapped and multicast source
        if srcAddr.isIPv4Mapped || destAddr.isIPv4Mapped || srcAddr.isMulticast {
            pbuf.free()
            return .ok
        }

        // Set current context
        let ctx = IPv6.currentContext
        ctx.currentHeader = ip6hdr
        ctx.currentSrc = srcAddr
        ctx.currentDest = destAddr
        ctx.currentNetif = inputNetif
        ctx.inputNetif = inputNetif

        // Find matching interface
        var matchedNetif: NetworkInterface? = nil

        if destAddr.isMulticast {
            // All-nodes multicast always accepted
            if destAddr.isAllNodesInterfaceLocal || destAddr.isAllNodesLinkLocal {
                matchedNetif = inputNetif
            } else if let _ = MLD6.lookForGroup(on: inputNetif, address: destAddr) {
                matchedNetif = inputNetif
            }
        } else {
            // Unicast: check if destination matches any address on input netif
            if IPv6.inputAccept(on: inputNetif) {
                matchedNetif = inputNetif
            } else if destAddr.isLinkLocal || srcAddr.isLinkLocal {
                // Link-local scope - don't check other interfaces
                matchedNetif = nil
            } else if destAddr.isLoopback || srcAddr.isLoopback {
                matchedNetif = nil
            } else {
                // Check other interfaces
                var netif = NetworkInterface.list
                while let n = netif {
                    if n !== inputNetif && IPv6.inputAccept(on: n) {
                        matchedNetif = n
                        break
                    }
                    netif = n.next
                }
            }
        }

        // Validate source address: unspecified source only with solicited-node dest
        if srcAddr.isAny && !destAddr.isSolicitedNode {
            pbuf.free()
            ctx.reset()
            return .ok
        }

        // Packet not for us?
        guard let netif = matchedNetif else {
            // Forward if unicast
            if !destAddr.isMulticast {
                if LWIPConfig.ipv6Forward {
                    IPv6.forward(pbuf, header: ip6hdr, inputNetif: inputNetif)
                }
            }
            pbuf.free()
            ctx.reset()
            return .ok
        }

        ctx.currentNetif = netif

        // Process extension headers
        var nextHeaderByte = ip6hdr.nextHeader
        var hlen: Int = IPv6HeaderConstants.length
        var hlenTotal: Int = IPv6HeaderConstants.length

        // Move past IPv6 header
        pbuf.removeHeader(IPv6HeaderConstants.length)

        extensionLoop: while nextHeaderByte != IPv6NextHeader.none.rawValue {
            switch nextHeaderByte {
            case IPv6NextHeader.hopByHop.rawValue:
                guard let extHdr = IPv6ExtensionHeader(reading: pbuf) else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                nextHeaderByte = extHdr.nextHeader
                hlen = extHdr.totalLength
                guard pbuf.length >= 8 && hlen <= pbuf.length else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                hlenTotal += hlen

                // Process hop-by-hop options
                var optOffset = 2
                while optOffset < hlen {
                    let optType = pbuf.payload.load(fromByteOffset: optOffset, as: UInt8.self)
                    if optType == IPv6OptionType.pad1.rawValue {
                        optOffset += 1
                        continue
                    }
                    guard optOffset + 1 < hlen else { break }
                    let optDLen = Int(pbuf.payload.load(fromByteOffset: optOffset + 1, as: UInt8.self))

                    switch optType {
                    case IPv6OptionType.padN.rawValue,
                         IPv6OptionType.routerAlert.rawValue,
                         IPv6OptionType.jumbo.rawValue:
                        break
                    default:
                        let action = (optType >> 6) & 0x3
                        switch action {
                        case 1:
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        case 2:
                            ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedOption, offset: UInt32(optOffset))
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        case 3:
                            if !destAddr.isMulticast {
                                ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedOption, offset: UInt32(optOffset))
                            }
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        default:
                            break
                        }
                    }
                    optOffset += 2 + optDLen
                }
                pbuf.removeHeader(hlen)

            case IPv6NextHeader.destOpts.rawValue:
                guard let extHdr = IPv6ExtensionHeader(reading: pbuf) else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                nextHeaderByte = extHdr.nextHeader
                hlen = extHdr.totalLength
                guard pbuf.length >= 8 && hlen <= pbuf.length else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                hlenTotal += hlen

                // Process destination options (similar to hop-by-hop)
                var optOffset = 2
                while optOffset < hlen {
                    let optType = pbuf.payload.load(fromByteOffset: optOffset, as: UInt8.self)
                    if optType == IPv6OptionType.pad1.rawValue {
                        optOffset += 1
                        continue
                    }
                    guard optOffset + 1 < hlen else { break }
                    let optDLen = Int(pbuf.payload.load(fromByteOffset: optOffset + 1, as: UInt8.self))

                    switch optType {
                    case IPv6OptionType.padN.rawValue,
                         IPv6OptionType.routerAlert.rawValue,
                         IPv6OptionType.jumbo.rawValue,
                         IPv6OptionType.homeAddress.rawValue:
                        break
                    default:
                        let action = (optType >> 6) & 0x3
                        switch action {
                        case 1:
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        case 2:
                            ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedOption, offset: UInt32(optOffset))
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        case 3:
                            if !destAddr.isMulticast {
                                ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedOption, offset: UInt32(optOffset))
                            }
                            pbuf.free()
                            ctx.reset()
                            return .ok
                        default:
                            break
                        }
                    }
                    optOffset += 2 + optDLen
                }
                pbuf.removeHeader(hlen)

            case IPv6NextHeader.routing.rawValue:
                guard let routHdr = IPv6RoutingHeader(reading: pbuf) else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                nextHeaderByte = routHdr.nextHeader
                hlen = routHdr.totalLength
                guard pbuf.length >= 8 && hlen <= pbuf.length else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                hlenTotal += hlen

                if routHdr.segmentsLeft > 0 {
                    // Length must be even
                    if routHdr.headerExtLength & 0x1 != 0 {
                        ICMPv6.sendParameterProblem(pbuf, code: .erroneousField, offset: UInt32(hlenTotal - hlen + 1))
                        pbuf.free()
                        ctx.reset()
                        return .ok
                    }
                    switch routHdr.routingType {
                    case IPv6RoutingType.type2, IPv6RoutingType.rpl:
                        break // known types - skip
                    default:
                        ICMPv6.sendParameterProblem(pbuf, code: .erroneousField, offset: UInt32(hlenTotal - hlen + 2))
                        pbuf.free()
                        ctx.reset()
                        return .ok
                    }
                }
                pbuf.removeHeader(hlen)

            case IPv6NextHeader.fragment.rawValue:
                guard let fragHdr = IPv6FragmentHeader(reading: pbuf) else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                nextHeaderByte = fragHdr.nextHeader
                hlen = IPv6FragmentHeader.length
                guard hlen <= pbuf.length else {
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }
                hlenTotal += hlen

                // Check payload alignment for more-fragments
                if fragHdr.moreFragments && (ip6hdr.payloadLength & 0x7) != 0 {
                    ICMPv6.sendParameterProblem(pbuf, code: .erroneousField, offset: 4) // _plen offset
                    pbuf.free()
                    ctx.reset()
                    return .ok
                }

                // Unfragmented (offset=0, M=0)?
                if !fragHdr.moreFragments && fragHdr.offset == 0 {
                    pbuf.removeHeader(hlen)
                } else {
                    // Reassembly
                    if LWIPConfig.ipv6Reassembly {
                        ctx.headerTotalLength = UInt16(hlenTotal)
                        if let reassembled = IPv6Frag.reassemble(pbuf) {
                            // Reassembled: restart from IPv6 header
                            guard let newHdr = IPv6Header(reading: reassembled) else {
                                reassembled.free()
                                ctx.reset()
                                return .ok
                            }
                            ctx.currentHeader = newHdr
                            nextHeaderByte = newHdr.nextHeader
                            hlen = IPv6HeaderConstants.length
                            hlenTotal = IPv6HeaderConstants.length
                            reassembled.removeHeader(IPv6HeaderConstants.length)
                            // Continue processing with reassembled packet
                            // (pbuf variable is now the reassembled one)
                        } else {
                            // Not yet complete
                            ctx.reset()
                            return .ok
                        }
                    } else {
                        pbuf.free()
                        ctx.reset()
                        return .ok
                    }
                }

            default:
                break extensionLoop
            }

            // Hop-by-Hop must be first
            if nextHeaderByte == IPv6NextHeader.hopByHop.rawValue {
                ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedNextHeader, offset: UInt32(hlenTotal))
                pbuf.free()
                ctx.reset()
                return .ok
            }
        }

        // Deliver to upper layer
        ctx.headerTotalLength = UInt16(hlenTotal)
        IPGlobals.shared.currentNetif = netif
        IPGlobals.shared.currentInputNetif = inputNetif
        IPGlobals.shared.currentIPHeaderTotLen = UInt16(hlenTotal)
        IPGlobals.shared.currentSrcAddr = .v6(srcAddr)
        IPGlobals.shared.currentDestAddr = .v6(destAddr)
        IPGlobals.shared.currentHeaderProto = nextHeaderByte

        defer {
            IPGlobals.shared.currentNetif = nil
            IPGlobals.shared.currentInputNetif = nil
            IPGlobals.shared.currentIPHeaderTotLen = 0
            IPGlobals.shared.currentSrcAddr = .v4(.any)
            IPGlobals.shared.currentDestAddr = .v4(.any)
            IPGlobals.shared.currentHeaderProto = 0
            ctx.reset()
        }

        let rawState: RawInputState
        if pbuf.addHeader(hlenTotal) {
            rawState = RawControlBlock.handleInput(pbuf, inputNetif)
            if rawState == .eaten {
                return .ok
            }
            _ = pbuf.removeHeader(hlenTotal)
        } else {
            rawState = .none
        }

        switch nextHeaderByte {
        case IPv6NextHeader.none.rawValue:
            pbuf.free()

        case IPv6NextHeader.udp.rawValue, IPv6NextHeader.udpLite.rawValue:
            UDPGlobal.shared.input(pbuf: pbuf, netif: inputNetif, srcIP: .v6(srcAddr), dstIP: .v6(destAddr))

        case IPv6NextHeader.tcp.rawValue:
            TCPInput.shared.input(pbuf: pbuf, netif: inputNetif, srcIP: .v6(srcAddr), dstIP: .v6(destAddr))

        case IPv6NextHeader.icmpv6.rawValue:
            ICMPv6.input(pbuf, on: inputNetif)

        default:
            // Unknown protocol
            if rawState == .none && !destAddr.isMulticast && ip6hdr.nextHeader != IPv6NextHeader.icmpv6.rawValue {
                _ = pbuf.addHeader(hlenTotal)
                ICMPv6.sendParameterProblem(pbuf, code: .unrecognizedNextHeader, offset: 6) // nexth offset
            }
            pbuf.free()
        }
        return .ok
    }

    // MARK: - Output

    /// Send an IPv6 packet on a specific network interface.
    ///
    /// Constructs the IPv6 header. If `src` is `.any`, selects a source address.
    /// If `dest` is nil, assumes header is already included in `pbuf`.
    ///
    /// - Parameters:
    ///   - pbuf: The packet data (payload at protocol data).
    ///   - src: Source address (nil or `.any` for auto-selection).
    ///   - dest: Destination address.
    ///   - hopLimit: Hop limit.
    ///   - trafficClass: Traffic class.
    ///   - nextHeader: Next header value.
    ///   - netif: Output interface.
    /// - Returns: `.ok` on success, error otherwise.
    @discardableResult
    public static func outputIf(_ pbuf: Pbuf,
                                src: IPv6Address?,
                                dest: IPv6Address,
                                hopLimit: UInt8,
                                trafficClass: UInt8,
                                nextHeader: UInt8,
                                netif: NetworkInterface) -> LWIPError {
        var srcUsed = src
        if let s = src, s.isAny {
            srcUsed = selectSourceAddress(on: netif, for: dest)
            if srcUsed == nil || srcUsed!.isAny {
                return .routingError
            }
        }
        return outputIfSrc(pbuf, src: srcUsed, dest: dest,
                           hopLimit: hopLimit, trafficClass: trafficClass,
                           nextHeader: nextHeader, netif: netif)
    }

    /// Same as `outputIf` but does not replace `.any` source address.
    @discardableResult
    public static func outputIfSrc(_ pbuf: Pbuf,
                                   src: IPv6Address?,
                                   dest: IPv6Address,
                                   hopLimit: UInt8,
                                   trafficClass: UInt8,
                                   nextHeader: UInt8,
                                   netif: NetworkInterface) -> LWIPError {
        var destAddr = dest

        // Assign zone if needed
        if !dest.hasZone && dest.needsZone {
            destAddr = dest.withZone(for: netif)
        }

        // Build IPv6 header
        guard pbuf.addHeader(IPv6HeaderConstants.length) else {
            return .bufferError
        }

        let srcAddr = src ?? .any
        var hdr = IPv6Header(
            trafficClass: trafficClass,
            flowLabel: 0,
            payloadLength: UInt16(pbuf.totalLength - IPv6HeaderConstants.length),
            nextHeader: nextHeader,
            hopLimit: hopLimit,
            src: srcAddr,
            dest: destAddr
        )
        hdr.write(to: pbuf)

        // Loopback check
        if destAddr.isLoopback {
            return netif.loopOutput(pbuf)
        }
        for i in 0..<netif.ipv6AddressCount {
            if netif.ipv6AddressIsValid(index: i) && destAddr == netif.ipv6Address(at: i) {
                return netif.loopOutput(pbuf)
            }
        }

        // Fragment if needed
        if LWIPConfig.ipv6Frag {
            let mtu = netif.mtuIPv6
            if mtu > 0 && UInt16(pbuf.totalLength) > ND6.getDestinationMTU(for: destAddr, on: netif) {
                return IPv6Frag.fragment(pbuf, on: netif, to: destAddr)
            }
        }

        return netif.outputIPv6(pbuf, to: destAddr)
    }

    /// Send an IPv6 packet, automatically selecting the output interface.
    @discardableResult
    public static func output(_ pbuf: Pbuf,
                              src: IPv6Address?,
                              dest: IPv6Address,
                              hopLimit: UInt8,
                              trafficClass: UInt8,
                              nextHeader: UInt8) -> LWIPError {
        guard let netif = route(src: src ?? .any, dest: dest) else {
            return .routingError
        }
        return outputIf(pbuf, src: src, dest: dest,
                        hopLimit: hopLimit, trafficClass: trafficClass,
                        nextHeader: nextHeader, netif: netif)
    }

    // MARK: - Add Hop-by-Hop Router Alert

    /// Add a hop-by-hop header with router alert option.
    /// Used by MLD6 before sending.
    public static func addHopByHopRouterAlert(_ pbuf: Pbuf, nextHeader: UInt8, alertValue: UInt16) -> Bool {
        // HBH header is 8 bytes: nexth(1) + hlen(1) + option_type(1) + option_len(1) + value(2) + pad(2)
        let hbhLen = 8
        guard pbuf.addHeader(hbhLen) else { return false }
        let p = pbuf.payload
        p.storeBytes(of: nextHeader, toByteOffset: 0, as: UInt8.self)      // next header
        p.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)        // length (0 = 8 bytes)
        p.storeBytes(of: IPv6OptionType.routerAlert.rawValue, toByteOffset: 2, as: UInt8.self) // option type
        p.storeBytes(of: IPv6RouterAlert.dataLength, toByteOffset: 3, as: UInt8.self) // option data len
        p.storeBytes(of: alertValue.bigEndian, toByteOffset: 4, as: UInt16.self)    // alert value
        p.storeBytes(of: UInt8(1), toByteOffset: 6, as: UInt8.self)        // PadN option type
        p.storeBytes(of: UInt8(0), toByteOffset: 7, as: UInt8.self)        // PadN length
        return true
    }

    // MARK: - Forwarding

    /// Forward an IPv6 packet to another interface.
    static func forward(_ pbuf: Pbuf, header: IPv6Header, inputNetif: NetworkInterface) {
        let dest = header.dest
        let src = header.src

        // Don't forward link-local or loopback
        guard !dest.isLinkLocal && !dest.isLoopback else { return }

        // Find output netif
        guard let outNetif = route(src: .any, dest: dest) else {
            if header.nextHeader != IPv6NextHeader.icmpv6.rawValue {
                ICMPv6.sendDestUnreachable(pbuf, code: .noRoute)
            }
            return
        }

        // Don't forward between zones
        if src.hasZone && !src.testZone(on: outNetif) { return }
        if src.isLoopback { return }

        // Don't bounce back on same interface
        guard outNetif !== inputNetif else { return }

        // Decrement hop limit
        var mutableHdr = header
        mutableHdr.hopLimit -= 1
        if mutableHdr.hopLimit == 0 {
            if header.nextHeader != IPv6NextHeader.icmpv6.rawValue {
                ICMPv6.sendTimeExceeded(pbuf, code: .hopLimitExceeded)
            }
            return
        }

        // Write updated hop limit back
        pbuf.payload.storeBytes(of: mutableHdr.hopLimit, toByteOffset: 7, as: UInt8.self)

        // Check MTU
        if outNetif.mtu > 0 && UInt16(pbuf.totalLength) > outNetif.mtu {
            if header.nextHeader != IPv6NextHeader.icmpv6.rawValue {
                ICMPv6.sendPacketTooBig(pbuf, mtu: UInt32(outNetif.mtu))
            }
            return
        }

        // Transmit
        let _ = outNetif.outputIPv6(pbuf, to: dest)
    }

    // MARK: - Private Helpers

    /// Check if a packet should be accepted on the given netif.
    private static func inputAccept(on netif: NetworkInterface) -> Bool {
        guard netif.isUp else { return false }
        let dest = IPv6.currentContext.currentDest
        for i in 0..<netif.ipv6AddressCount {
            if netif.ipv6AddressIsValid(index: i) && dest == netif.ipv6Address(at: i) {
                return true
            }
        }
        return false
    }
}
