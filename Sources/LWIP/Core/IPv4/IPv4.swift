//
//  IPv4.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IPv4 Header Constants

/// Namespace for IPv4 header-related constants.
public enum IPv4HeaderConstants {
    /// Standard IPv4 header length in bytes (no options).
    public static let standardLength: UInt16 = 20
    /// Maximum IPv4 header length with options.
    public static let maximumLength: UInt16 = 60
}

/// Namespace for IPv4 fragment flag constants.
public enum IPv4FragmentFlag {
    /// Reserved fragment flag.
    public static let reserved: UInt16       = 0x8000
    /// Don't fragment flag.
    public static let dontFragment: UInt16   = 0x4000
    /// More fragments flag.
    public static let moreFragments: UInt16  = 0x2000
    /// Mask for fragment offset bits.
    public static let offsetMask: UInt16     = 0x1FFF
}

/// IPv4/IPv6 protocol numbers.
public enum IPProtocolNumber {
    public static let icmp: UInt8    = 1
    public static let igmp: UInt8    = 2
    public static let tcp: UInt8     = 6
    public static let udp: UInt8     = 17
    public static let udpLite: UInt8 = 136
}

// MARK: - IPv4 Header

/// IPv4 packet header (20 bytes minimum, stored in network byte order).
public struct IPv4Header {
    /// Version (4 bits) + IHL (4 bits)
    public var versionIHL: UInt8
    /// Type of service
    public var typeOfService: UInt8
    /// Total length (network byte order)
    public var totalLength: UInt16
    /// Identification (network byte order)
    public var identification: UInt16
    /// Flags + Fragment offset (network byte order)
    public var flagsFragOffset: UInt16
    /// Time to live
    public var timeToLive: UInt8
    /// Protocol number
    public var protocolNumber: UInt8
    /// Header checksum (network byte order)
    public var checksum: UInt16
    /// Source address (network byte order)
    public var src: IPv4Address
    /// Destination address (network byte order)
    public var dest: IPv4Address

    public init() {
        versionIHL = 0x45 // version 4, IHL 5
        typeOfService = 0
        totalLength = 0
        identification = 0
        flagsFragOffset = 0
        timeToLive = 0
        protocolNumber = 0
        checksum = 0
        src = .any
        dest = .any
    }

    // Accessor helpers
    @inlinable public var version: UInt8 { versionIHL >> 4 }
    @inlinable public var ihl: UInt8 { versionIHL & 0x0F }
    @inlinable public var headerLengthBytes: UInt16 { UInt16(ihl) * 4 }

    @inlinable
    public var totalLengthHost: UInt16 { totalLength.bigEndian }

    @inlinable
    public var identificationHost: UInt16 { identification.bigEndian }

    @inlinable
    public var offsetHost: UInt16 { flagsFragOffset.bigEndian }

    @inlinable
    public var fragmentOffsetBytes: UInt16 { (offsetHost & IPv4FragmentFlag.offsetMask) * 8 }

    @inlinable
    public var hasMoreFragments: Bool { (flagsFragOffset.bigEndian & IPv4FragmentFlag.moreFragments) != 0 }

    @inlinable
    public var dontFragment: Bool { (flagsFragOffset.bigEndian & IPv4FragmentFlag.dontFragment) != 0 }

    @inlinable
    public mutating func setVersionIHL(version v: UInt8, ihl hl: UInt8) {
        versionIHL = (v << 4) | hl
    }
}

// MARK: - IP Data (current packet context)

/// Stores per-packet state used during input processing.
public final class IPv4InputContext {
    /// The netif the packet matched.
    public var currentNetif: NetworkInterface?
    /// The netif the packet was received on.
    public var currentInputNetif: NetworkInterface?
    /// Current IP header pointer (reference into Pbuf payload).
    public var currentIPv4Header: IPv4Header?
    /// Header total length in bytes.
    public var currentIPHeaderTotLen: UInt16 = 0
    /// Source address from current packet.
    public var currentSrc: IPv4Address = .any
    /// Destination address from current packet.
    public var currentDest: IPv4Address = .any

    public init() {}
}

// MARK: - IPv4 Module

/// IPv4 protocol implementation.
public enum IPv4 {

    /// Global input context.
    public static var inputContext = IPv4InputContext()

    /// The IP identification counter for outgoing packets.
    @usableFromInline
    static var ipID: UInt16 = 0

    /// Default multicast output interface.
    public static var defaultMulticastNetif: NetworkInterface?

    /// Global list of network interfaces.
    public static var netifList: NetworkInterface?

    /// Default network interface.
    public static var netifDefault: NetworkInterface?

    // MARK: - Next ID

    @inlinable
    public static func nextID() -> UInt16 {
        let id = ipID
        ipID &+= 1
        return id
    }

    // MARK: - Routing

    /// Find the appropriate network interface for the given destination address.
    public static func route(dest: IPv4Address) -> NetworkInterface? {
        // Use multicast default if configured
        if dest.isMulticast, let mcastNetif = defaultMulticastNetif {
            return mcastNetif
        }

        // Iterate through netifs looking for a matching network
        var netif = netifList
        while let n = netif {
            if n.isUp && n.isLinkUp && !n.ipAddr.isAny {
                // Network mask match
                if dest.isOnNetwork(as: n.ipAddr, mask: n.netmask) {
                    return n
                }
                // Gateway match on point-to-point interface
                if !n.flags.contains(.broadcast) && dest == n.gateway {
                    return n
                }
            }
            netif = n.next
        }

        // Loopback check
        if dest.isLoopback {
            if let nd = netifDefault, nd.isUp {
                return nd
            }
            var n2 = netifList
            while let n = n2 {
                if n.isUp { return n }
                n2 = n.next
            }
            return nil
        }

        // Fall back to default.
        // Note: the original lwIP rejects the default netif when ipAddr is .any,
        // but TUN-based proxies use 0.0.0.0/0 catch-all interfaces that need to
        // route all outbound traffic. Allow the default netif regardless of its
        // IP address so responses (SYN-ACK, data) reach the TUN device.
        guard let nd = netifDefault, nd.isUp, nd.isLinkUp,
              !dest.isLoopback else {
            return nil
        }
        return nd
    }

    /// Route with optional source address hint.
    @inlinable
    public static func routeSrc(src: IPv4Address?, dest: IPv4Address) -> NetworkInterface? {
        // Source routing hook could be added here
        return route(dest: dest)
    }

    // MARK: - Can Forward

    /// Determine if a packet can be forwarded.
    private static func canForward(_ p: Pbuf) -> Bool {
        let addrHost = inputContext.currentDest.addr.byteSwapped

        // Don't route link-layer broadcasts/multicasts
        if p.flags.contains(.llBroadcast) { return false }
        if p.flags.contains(.llMulticast) || (addrHost & 0xF0000000) == 0xE0000000 { return false }

        // Experimental addresses
        if (addrHost & 0xF0000000) == 0xF0000000 { return false }

        // Class A: don't route 0.x.x.x or 127.x.x.x
        if (addrHost & 0x80000000) == 0 {
            let net = addrHost & 0xFF000000
            if net == 0 || net == (127 << 24) { return false }
        }

        return true
    }

    // MARK: - Forward

    /// Forward an IPv4 packet to another interface.
    public static func forward(_ p: Pbuf, header: inout IPv4Header, inp: NetworkInterface) {
        guard canForward(p) else { return }

        // Don't forward link-local
        if inputContext.currentDest.isLinkLocal { return }

        guard let netif = routeSrc(src: inputContext.currentSrc, dest: inputContext.currentDest) else {
            return
        }

        // Don't forward back on the same interface (unless configured)
        if !lwipConfig.ipForward { return }

        // Decrement TTL
        header.timeToLive &-= 1
        if header.timeToLive == 0 {
            // Send ICMP time exceeded (if not ICMP itself)
            if header.protocolNumber != IPProtocolNumber.icmp {
                ICMP.sendTimeExceeded(p, type: .ttlExceeded)
            }
            return
        }

        // Incrementally update the IP checksum for TTL decrement
        if header.checksum >= UInt16(bigEndian: 0xFFFF &- 0x0100) {
            header.checksum = header.checksum &+ UInt16(bigEndian: 0x0100) &+ 1
        } else {
            header.checksum = header.checksum &+ UInt16(bigEndian: 0x0100)
        }

        // Write back the modified header into the pbuf
        p.writeHeader(header)

        // Check MTU and fragment if needed
        if netif.mtu > 0 && p.totLen > netif.mtu {
            if !header.dontFragment {
                if lwipConfig.ipFrag {
                    IPv4Frag.fragment(p, netif: netif, dest: inputContext.currentDest)
                }
            } else {
                if lwipConfig.icmp {
                    ICMP.sendDestUnreachable(p, type: .fragmentationNeeded)
                }
            }
            return
        }

        // Transmit on the chosen interface
        netif.output?(netif, p, inputContext.currentDest)
    }

    // MARK: - Input Accept

    /// Check if the current input packet should be accepted on this netif.
    private static func inputAccept(_ netif: NetworkInterface) -> Bool {
        guard netif.isUp && !netif.ipAddr.isAny else { return false }

        // Unicast to this interface?
        if inputContext.currentDest == netif.ipAddr { return true }

        // Broadcast on this interface?
        if inputContext.currentDest.isBroadcast(on: netif) { return true }

        // Loopback
        if inputContext.currentDest.isLoopback { return true }

        return false
    }

    // MARK: - Input

    /// Main IPv4 input processing. Called when an IP packet is received.
    ///
    /// - Parameters:
    ///   - p: The received packet with payload pointing to the IP header.
    ///   - inp: The network interface on which the packet was received.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func input(_ p: Pbuf, inp: NetworkInterface) -> LWIPError {
        // Identify the IP header
        guard p.len >= IPv4HeaderConstants.standardLength else {
            p.free()
            return .ok
        }

        var iphdr = p.readIPv4Header()

        // Version check
        guard iphdr.version == 4 else {
            p.free()
            return .ok
        }

        let iphdrHLen = iphdr.headerLengthBytes
        let iphdrLen = iphdr.totalLengthHost

        // Trim pbuf to IP length (important for packets < 60 bytes)
        if iphdrLen < p.totLen {
            p.realloc(to: iphdrLen)
        }

        // Validate header length
        guard iphdrHLen <= p.len, iphdrLen <= p.totLen, iphdrHLen >= IPv4HeaderConstants.standardLength else {
            p.free()
            return .ok
        }

        // Verify checksum (respects per-netif offload flags)
        if lwipConfig.checksumCheckIP && inp.isChecksumEnabled(.checkIP) {
            if InetChecksum.checksum(UnsafeRawPointer(p.payload), len: UInt16(iphdrHLen)) != 0 {
                p.free()
                return .ok
            }
        }

        // Copy addresses to context
        inputContext.currentDest = iphdr.dest
        inputContext.currentSrc = iphdr.src

        var matchedNetif: NetworkInterface?
        var checkIPSrc = true

        // Match packet against interfaces
        if inputContext.currentDest.isMulticast {
            if lwipConfig.igmp && inp.flags.contains(.igmp) {
                if IGMP.lookForGroup(on: inp, addr: inputContext.currentDest) != nil {
                    // IGMP snooping: allow 0.0.0.0 source for 224.0.0.1
                    let allSystems = IPv4Address(224, 0, 0, 1)
                    if inputContext.currentDest == allSystems && inputContext.currentSrc.isAny {
                        checkIPSrc = false
                    }
                    matchedNetif = inp
                }
            } else {
                if inp.isUp && !inp.ipAddr.isAny {
                    matchedNetif = inp
                }
            }
        } else {
            if inputAccept(inp) {
                matchedNetif = inp
            } else if !inputContext.currentDest.isLoopback {
                var n = netifList
                while let netif = n {
                    if netif !== inp && inputAccept(netif) {
                        matchedNetif = netif
                        break
                    }
                    n = netif.next
                }
            }
        }

        // DHCP: accept link-layer addressed packets even if no netif matched
        if matchedNetif == nil && lwipConfig.dhcp {
            if iphdr.protocolNumber == IPProtocolNumber.udp && p.len >= iphdrHLen + 4 {
                // Read destination port (2 bytes at offset iphdrHLen + 2)
                let dstPort = p.readUInt16(at: Int(iphdrHLen) + 2)
                if dstPort == UInt16(bigEndian: 68) { // DHCP client port
                    matchedNetif = inp
                    checkIPSrc = false
                }
            }
        }

        // Validate source address
        if checkIPSrc && !inputContext.currentSrc.isAny {
            if inputContext.currentSrc.isBroadcast(on: inp) || inputContext.currentSrc.isMulticast {
                p.free()
                return .ok
            }
        }

        // Packet not for us?
        guard let netif = matchedNetif else {
            if lwipConfig.ipForward && !inputContext.currentDest.isBroadcast(on: inp) {
                forward(p, header: &iphdr, inp: inp)
            }
            p.free()
            return .ok
        }

        // Fragment reassembly
        if (iphdr.flagsFragOffset.bigEndian & (IPv4FragmentFlag.offsetMask | IPv4FragmentFlag.moreFragments)) != 0 {
            if lwipConfig.ipReassembly {
                guard let reassembled = IPv4Frag.reassemble(p) else {
                    return .ok
                }
                // Re-read the header from the reassembled packet
                iphdr = reassembled.readIPv4Header()
                // Continue with reassembled as `p` - but we can't reassign let.
                // In real code we'd use the reassembled buffer from here.
                return processTransportLayer(reassembled, header: iphdr, hlen: iphdr.headerLengthBytes, netif: netif, inp: inp)
            } else {
                p.free()
                return .ok
            }
        }

        // Process options check
        if !lwipConfig.ipOptionsAllowed && iphdrHLen > IPv4HeaderConstants.standardLength {
            // Allow IGMP router alert
            if !lwipConfig.igmp || iphdr.protocolNumber != IPProtocolNumber.igmp {
                p.free()
                return .ok
            }
        }

        return processTransportLayer(p, header: iphdr, hlen: iphdrHLen, netif: netif, inp: inp)
    }

    /// Dispatch to upper-layer protocols after IP processing.
    private static func processTransportLayer(_ p: Pbuf, header: IPv4Header, hlen: UInt16, netif: NetworkInterface, inp: NetworkInterface) -> LWIPError {
        inputContext.currentNetif = netif
        inputContext.currentInputNetif = inp
        inputContext.currentIPv4Header = header
        inputContext.currentIPHeaderTotLen = hlen
        IPGlobals.shared.currentNetif = netif
        IPGlobals.shared.currentInputNetif = inp
        IPGlobals.shared.currentIPHeaderTotLen = hlen
        IPGlobals.shared.currentSrcAddr = .v4(inputContext.currentSrc)
        IPGlobals.shared.currentDestAddr = .v4(inputContext.currentDest)
        IPGlobals.shared.currentHeaderProto = header.protocolNumber

        defer {
            inputContext.currentNetif = nil
            inputContext.currentInputNetif = nil
            inputContext.currentIPv4Header = nil
            inputContext.currentIPHeaderTotLen = 0
            inputContext.currentSrc = .any
            inputContext.currentDest = .any

            IPGlobals.shared.currentNetif = nil
            IPGlobals.shared.currentInputNetif = nil
            IPGlobals.shared.currentIPHeaderTotLen = 0
            IPGlobals.shared.currentSrcAddr = .v4(.any)
            IPGlobals.shared.currentDestAddr = .v4(.any)
            IPGlobals.shared.currentHeaderProto = 0
        }

        let rawState = RawControlBlock.handleInput(p, inp)
        if rawState == .eaten {
            return .ok
        }

        // Remove IP header to expose transport payload
        _ = p.removeHeader(Int(hlen))

        switch header.protocolNumber {
        case IPProtocolNumber.udp:
            UDPGlobal.shared.input(pbuf: p, netif: inp, srcIP: .v4(inputContext.currentSrc), dstIP: .v4(inputContext.currentDest))
        case IPProtocolNumber.tcp:
            TCPInput.shared.input(pbuf: p, netif: inp, srcIP: .v4(inputContext.currentSrc), dstIP: .v4(inputContext.currentDest))
        case IPProtocolNumber.icmp:
            ICMP.input(p, netif: inp)
        case IPProtocolNumber.igmp:
            IGMP.input(p, netif: inp, dest: inputContext.currentDest)
        default:
            // Unknown protocol: send ICMP dest unreachable only if raw sockets did not consume it.
            if rawState == .none && lwipConfig.icmp &&
                !inputContext.currentDest.isBroadcast(on: netif) &&
                !inputContext.currentDest.isMulticast {
                _ = p.addHeader(Int(hlen))
                ICMP.sendDestUnreachable(p, type: .protocolUnreachable)
            }
            p.free()
        }

        return .ok
    }

    // MARK: - Output

    /// Send an IP packet on a specific network interface.
    ///
    /// Constructs the IP header and calculates checksum. If `src` is nil or `.any`,
    /// the interface's address is used.
    ///
    /// - Parameters:
    ///   - p: Packet to send (payload points to transport data).
    ///   - src: Source IP address (nil = use interface address).
    ///   - dest: Destination IP address.
    ///   - ttl: Time to live.
    ///   - tos: Type of service.
    ///   - proto: Protocol number.
    ///   - netif: Network interface to send on.
    ///   - ipOptions: Optional IP options bytes.
    /// - Returns: `.ok` on success, `.bufferError` if header space unavailable.
    public static func outputIf(_ p: Pbuf, src: IPv4Address?, dest: IPv4Address,
                                 ttl: UInt8, tos: UInt8, proto: UInt8,
                                 netif: NetworkInterface,
                                 ipOptions: [UInt8]? = nil) -> LWIPError {
        var srcUsed = src ?? .any
        if srcUsed.isAny {
            srcUsed = netif.ipAddr
        }
        return outputIfSrc(p, src: srcUsed, dest: dest, ttl: ttl, tos: tos,
                           proto: proto, netif: netif, ipOptions: ipOptions)
    }

    /// Output with explicit source (not replaced by interface address when `.any`).
    public static func outputIfSrc(_ p: Pbuf, src: IPv4Address?, dest: IPv4Address,
                                    ttl: UInt8, tos: UInt8, proto: UInt8,
                                    netif: NetworkInterface,
                                    ipOptions: [UInt8]? = nil) -> LWIPError {
        // Handle IP options
        var ipHLen: UInt16 = IPv4HeaderConstants.standardLength
        if let options = ipOptions, !options.isEmpty {
            let optLen = UInt16(options.count)
            guard optLen <= IPv4HeaderConstants.maximumLength - IPv4HeaderConstants.standardLength else { return .invalidValue }
            let optLenAligned = (optLen + 3) & ~3
            ipHLen += optLenAligned

            guard p.addHeader(Int(optLenAligned)) else { return .bufferError }
            p.writeBytes(options, at: 0)
            // Zero padding
            if optLenAligned > optLen {
                p.zeroFill(at: Int(optLen), count: Int(optLenAligned - optLen))
            }
        }

        // Add IP header
        guard p.addHeader(Int(ipHLen)) else { return .bufferError }

        var iphdr = IPv4Header()
        iphdr.timeToLive = ttl
        iphdr.protocolNumber = proto
        iphdr.dest = dest
        iphdr.setVersionIHL(version: 4, ihl: UInt8(ipHLen / 4))
        iphdr.typeOfService = tos
        iphdr.totalLength = p.totLen.bigEndian
        iphdr.flagsFragOffset = 0
        iphdr.identification = nextID().bigEndian

        if let s = src {
            iphdr.src = s
        } else {
            iphdr.src = .any
        }

        // Calculate checksum (respects per-netif offload flags)
        iphdr.checksum = 0
        if lwipConfig.checksumGenIP && netif.isChecksumEnabled(.genIP) {
            p.writeIPv4Header(iphdr)
            iphdr.checksum = InetChecksum.checksum(UnsafeRawPointer(p.payload), len: UInt16(ipHLen))
        }
        p.writeIPv4Header(iphdr)

        // Loopback check
        if dest == netif.ipAddr || dest.isLoopback {
            if lwipConfig.loopbackEnabled {
                return netif.loopOutput?(netif, p) ?? .ok
            }
        }

        // Fragmentation check
        if lwipConfig.ipFrag && netif.mtu > 0 && p.totLen > netif.mtu {
            return IPv4Frag.fragment(p, netif: netif, dest: dest)
        }

        // Send via interface
        return netif.output?(netif, p, dest) ?? .interfaceError
    }

    /// Send an IP packet, finding the route automatically.
    ///
    /// - Parameters:
    ///   - p: Packet to send.
    ///   - src: Source address (nil = auto).
    ///   - dest: Destination address.
    ///   - ttl: Time to live.
    ///   - tos: Type of service.
    ///   - proto: Protocol number.
    /// - Returns: `.ok` on success, `.routingError` if no route found.
    public static func output(_ p: Pbuf, src: IPv4Address?, dest: IPv4Address,
                               ttl: UInt8, tos: UInt8, proto: UInt8) -> LWIPError {
        guard let netif = routeSrc(src: src, dest: dest) else {
            return .routingError
        }
        return outputIf(p, src: src, dest: dest, ttl: ttl, tos: tos,
                        proto: proto, netif: netif)
    }
}

// MARK: - IPv4Address Extensions for NetworkInterface

extension IPv4Address {
    /// Check whether the address is a broadcast for the given interface
    /// (limited broadcast 255.255.255.255 or subnet broadcast).
    @inlinable
    public func isBroadcast(on netif: NetworkInterface) -> Bool {
        if addr == IPv4Address.rawBroadcast { return true }
        if addr == IPv4Address.rawAny { return false }
        let mask = netif.netmask.addr
        let hostAll = ~mask
        if hostAll != 0 {
            let net = netif.ipAddr.addr & mask
            if addr == (net | hostAll) { return true }
        }
        return false
    }

    /// Check whether addresses are on the same network (uses isOnSameNetwork).
    @inlinable
    public func isOnNetwork(as other: IPv4Address, mask: IPv4Address) -> Bool {
        isOnSameNetwork(as: other, mask: mask)
    }
}

// MARK: - Pbuf IPv4 Header Extensions

extension Pbuf {

    /// Copy from an IPv4Header struct to the payload.
    public func copyFromPayload(_ header: IPv4Header, offset: Int, length: Int) {
        withUnsafeBytes(of: header) { buf in
            for i in 0..<Swift.min(length, buf.count) {
                writeByte(buf[i], at: offset + i)
            }
        }
    }

    /// Copy partial data from this pbuf to a raw pointer.
    public func copyPartialTo(_ dest: UnsafeMutableRawPointer, length: Int, srcOffset: Int) {
        let _ = copyPartial(to: dest, len: UInt16(length), offset: UInt16(srcOffset))
    }

    // MARK: - IPv4 Header Read/Write

    /// Read an IPv4Header from the start of the payload.
    public func readIPv4Header() -> IPv4Header {
        var hdr = IPv4Header()
        hdr.versionIHL = readByte(at: 0)
        hdr.typeOfService = readByte(at: 1)
        hdr.totalLength = readUInt16(at: 2)
        hdr.identification = readUInt16(at: 4)
        hdr.flagsFragOffset = readUInt16(at: 6)
        hdr.timeToLive = readByte(at: 8)
        hdr.protocolNumber = readByte(at: 9)
        hdr.checksum = readUInt16(at: 10)

        let srcB0 = UInt32(readByte(at: 12))
        let srcB1 = UInt32(readByte(at: 13))
        let srcB2 = UInt32(readByte(at: 14))
        let srcB3 = UInt32(readByte(at: 15))
        hdr.src = IPv4Address(networkOrder: srcB0 | (srcB1 << 8) | (srcB2 << 16) | (srcB3 << 24))

        let dstB0 = UInt32(readByte(at: 16))
        let dstB1 = UInt32(readByte(at: 17))
        let dstB2 = UInt32(readByte(at: 18))
        let dstB3 = UInt32(readByte(at: 19))
        hdr.dest = IPv4Address(networkOrder: dstB0 | (dstB1 << 8) | (dstB2 << 16) | (dstB3 << 24))

        return hdr
    }

    /// Write an IPv4Header to the start of the payload.
    public func writeIPv4Header(_ hdr: IPv4Header) {
        writeByte(hdr.versionIHL, at: 0)
        writeByte(hdr.typeOfService, at: 1)
        writeByte(UInt8(truncatingIfNeeded: hdr.totalLength >> 8), at: 2)
        writeByte(UInt8(truncatingIfNeeded: hdr.totalLength), at: 3)
        writeByte(UInt8(truncatingIfNeeded: hdr.identification >> 8), at: 4)
        writeByte(UInt8(truncatingIfNeeded: hdr.identification), at: 5)
        writeByte(UInt8(truncatingIfNeeded: hdr.flagsFragOffset >> 8), at: 6)
        writeByte(UInt8(truncatingIfNeeded: hdr.flagsFragOffset), at: 7)
        writeByte(hdr.timeToLive, at: 8)
        writeByte(hdr.protocolNumber, at: 9)
        writeByte(UInt8(truncatingIfNeeded: hdr.checksum >> 8), at: 10)
        writeByte(UInt8(truncatingIfNeeded: hdr.checksum), at: 11)

        let s = hdr.src.addr
        writeByte(UInt8(truncatingIfNeeded: s), at: 12)
        writeByte(UInt8(truncatingIfNeeded: s >> 8), at: 13)
        writeByte(UInt8(truncatingIfNeeded: s >> 16), at: 14)
        writeByte(UInt8(truncatingIfNeeded: s >> 24), at: 15)

        let d = hdr.dest.addr
        writeByte(UInt8(truncatingIfNeeded: d), at: 16)
        writeByte(UInt8(truncatingIfNeeded: d >> 8), at: 17)
        writeByte(UInt8(truncatingIfNeeded: d >> 16), at: 18)
        writeByte(UInt8(truncatingIfNeeded: d >> 24), at: 19)
    }

    /// Write header data back into the pbuf (for forwarding).
    public func writeHeader(_ header: IPv4Header) {
        writeIPv4Header(header)
    }

    // MARK: - ICMP Header Read/Write

    /// Read an ICMP echo header from the payload.
    public func readICMPEchoHeader() -> ICMPEchoHeader {
        var h = ICMPEchoHeader()
        h.type = readByte(at: 0)
        h.code = readByte(at: 1)
        h.checksum = readUInt16(at: 2)
        h.identifier = readUInt16(at: 4)
        h.sequenceNumber = readUInt16(at: 6)
        return h
    }

    /// Write an ICMP echo header to the payload.
    public func writeICMPEchoHeader(_ h: ICMPEchoHeader) {
        writeByte(h.type, at: 0)
        writeByte(h.code, at: 1)
        writeByte(UInt8(truncatingIfNeeded: h.checksum >> 8), at: 2)
        writeByte(UInt8(truncatingIfNeeded: h.checksum), at: 3)
        writeByte(UInt8(truncatingIfNeeded: h.identifier >> 8), at: 4)
        writeByte(UInt8(truncatingIfNeeded: h.identifier), at: 5)
        writeByte(UInt8(truncatingIfNeeded: h.sequenceNumber >> 8), at: 6)
        writeByte(UInt8(truncatingIfNeeded: h.sequenceNumber), at: 7)
    }

    /// Read an ICMP header from the payload.
    public func readICMPHeader() -> ICMPHeader {
        var h = ICMPHeader()
        h.type = readByte(at: 0)
        h.code = readByte(at: 1)
        h.checksum = readUInt16(at: 2)
        let d0 = UInt32(readByte(at: 4))
        let d1 = UInt32(readByte(at: 5))
        let d2 = UInt32(readByte(at: 6))
        let d3 = UInt32(readByte(at: 7))
        h.data = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3
        return h
    }

    /// Write an ICMP header to the payload.
    public func writeICMPHeader(_ h: ICMPHeader) {
        writeByte(h.type, at: 0)
        writeByte(h.code, at: 1)
        writeByte(UInt8(truncatingIfNeeded: h.checksum >> 8), at: 2)
        writeByte(UInt8(truncatingIfNeeded: h.checksum), at: 3)
        writeByte(UInt8(truncatingIfNeeded: h.data >> 24), at: 4)
        writeByte(UInt8(truncatingIfNeeded: h.data >> 16), at: 5)
        writeByte(UInt8(truncatingIfNeeded: h.data >> 8), at: 6)
        writeByte(UInt8(truncatingIfNeeded: h.data), at: 7)
    }

    // MARK: - IGMP Message Read/Write

    /// Read an IGMP message from the payload.
    public func readIGMPMessage() -> IGMPMessage {
        var m = IGMPMessage()
        m.messageType = readByte(at: 0)
        m.maximumResponseTime = readByte(at: 1)
        m.checksum = readUInt16(at: 2)
        let g0 = UInt32(readByte(at: 4))
        let g1 = UInt32(readByte(at: 5))
        let g2 = UInt32(readByte(at: 6))
        let g3 = UInt32(readByte(at: 7))
        m.groupAddress = IPv4Address(networkOrder: g0 | (g1 << 8) | (g2 << 16) | (g3 << 24))
        return m
    }

    /// Write an IGMP message to the payload.
    public func writeIGMPMessage(_ m: IGMPMessage) {
        writeByte(m.messageType, at: 0)
        writeByte(m.maximumResponseTime, at: 1)
        writeByte(UInt8(truncatingIfNeeded: m.checksum >> 8), at: 2)
        writeByte(UInt8(truncatingIfNeeded: m.checksum), at: 3)
        let g = m.groupAddress.addr
        writeByte(UInt8(truncatingIfNeeded: g), at: 4)
        writeByte(UInt8(truncatingIfNeeded: g >> 8), at: 5)
        writeByte(UInt8(truncatingIfNeeded: g >> 16), at: 6)
        writeByte(UInt8(truncatingIfNeeded: g >> 24), at: 7)
    }

    // MARK: - ARP Header Read/Write

    /// Read an ARP header from the payload.
    public func readARPHeader() -> ARPHeader {
        var h = ARPHeader()
        h.hardwareType = readUInt16(at: 0)
        h.proto = readUInt16(at: 2)
        h.hardwareLength = readByte(at: 4)
        h.protoLen = readByte(at: 5)
        h.opcode = readUInt16(at: 6)
        h.senderHWAddr = EthAddr(readByte(at: 8), readByte(at: 9), readByte(at: 10),
                                  readByte(at: 11), readByte(at: 12), readByte(at: 13))
        let s0 = UInt32(readByte(at: 14)); let s1 = UInt32(readByte(at: 15))
        let s2 = UInt32(readByte(at: 16)); let s3 = UInt32(readByte(at: 17))
        h.senderIPAddr = IPv4Address(networkOrder: s0 | (s1 << 8) | (s2 << 16) | (s3 << 24))
        h.targetHWAddr = EthAddr(readByte(at: 18), readByte(at: 19), readByte(at: 20),
                                  readByte(at: 21), readByte(at: 22), readByte(at: 23))
        let d0 = UInt32(readByte(at: 24)); let d1 = UInt32(readByte(at: 25))
        let d2 = UInt32(readByte(at: 26)); let d3 = UInt32(readByte(at: 27))
        h.targetIPAddr = IPv4Address(networkOrder: d0 | (d1 << 8) | (d2 << 16) | (d3 << 24))
        return h
    }

    /// Write an ARP header to the payload.
    public func writeARPHeader(_ h: ARPHeader) {
        writeByte(UInt8(truncatingIfNeeded: h.hardwareType >> 8), at: 0)
        writeByte(UInt8(truncatingIfNeeded: h.hardwareType), at: 1)
        writeByte(UInt8(truncatingIfNeeded: h.proto >> 8), at: 2)
        writeByte(UInt8(truncatingIfNeeded: h.proto), at: 3)
        writeByte(h.hardwareLength, at: 4)
        writeByte(h.protoLen, at: 5)
        writeByte(UInt8(truncatingIfNeeded: h.opcode >> 8), at: 6)
        writeByte(UInt8(truncatingIfNeeded: h.opcode), at: 7)
        let sha = h.senderHWAddr.addr
        writeByte(sha.0, at: 8); writeByte(sha.1, at: 9); writeByte(sha.2, at: 10)
        writeByte(sha.3, at: 11); writeByte(sha.4, at: 12); writeByte(sha.5, at: 13)
        let s = h.senderIPAddr.addr
        writeByte(UInt8(truncatingIfNeeded: s), at: 14)
        writeByte(UInt8(truncatingIfNeeded: s >> 8), at: 15)
        writeByte(UInt8(truncatingIfNeeded: s >> 16), at: 16)
        writeByte(UInt8(truncatingIfNeeded: s >> 24), at: 17)
        let dha = h.targetHWAddr.addr
        writeByte(dha.0, at: 18); writeByte(dha.1, at: 19); writeByte(dha.2, at: 20)
        writeByte(dha.3, at: 21); writeByte(dha.4, at: 22); writeByte(dha.5, at: 23)
        let d = h.targetIPAddr.addr
        writeByte(UInt8(truncatingIfNeeded: d), at: 24)
        writeByte(UInt8(truncatingIfNeeded: d >> 8), at: 25)
        writeByte(UInt8(truncatingIfNeeded: d >> 16), at: 26)
        writeByte(UInt8(truncatingIfNeeded: d >> 24), at: 27)
    }

    // MARK: - Reassembly Helper

    /// Reassembly helper stored as associated-object-like pattern.
    /// In a real embedded system this would be stored in-place in the IP header area.
    private static var reassHelpers = [ObjectIdentifier: ReassemblyHelper]()

    /// Get or create a reassembly helper for this pbuf.
    public var reassHelper: ReassemblyHelper {
        get {
            let key = ObjectIdentifier(self)
            if let existing = Pbuf.reassHelpers[key] {
                return existing
            }
            let h = ReassemblyHelper()
            Pbuf.reassHelpers[key] = h
            return h
        }
        set {
            Pbuf.reassHelpers[ObjectIdentifier(self)] = newValue
        }
    }
}


// MARK: - NetworkInterface IPv4 Extensions

extension NetworkInterface {
    /// IGMP group list head.
    public var igmpData: IGMPGroup? {
        get { ipv4IgmpData as? IGMPGroup }
        set { ipv4IgmpData = newValue }
    }

    /// DHCP client data.
    public var dhcpData: DHCPClient? {
        get { ipv4DhcpData as? DHCPClient }
        set { ipv4DhcpData = newValue }
    }

    /// AutoIP data.
    public var autoipData: AutoIPData? {
        get { ipv4AutoipData as? AutoIPData }
        set { ipv4AutoipData = newValue }
    }

    /// ACD linked list.
    public var acdList: AddressConflictDetection? {
        get { ipv4AcdList as? AddressConflictDetection }
        set { ipv4AcdList = newValue }
    }

    /// Hardware address as an EthAddr.
    public var hwAddrAsEth: EthAddr {
        EthAddr(
            hwAddr.count > 0 ? hwAddr[0] : 0,
            hwAddr.count > 1 ? hwAddr[1] : 0,
            hwAddr.count > 2 ? hwAddr[2] : 0,
            hwAddr.count > 3 ? hwAddr[3] : 0,
            hwAddr.count > 4 ? hwAddr[4] : 0,
            hwAddr.count > 5 ? hwAddr[5] : 0
        )
    }

    /// UDP input callback (set by the UDP module).
    public var udpInput: ((_ p: Pbuf, _ netif: NetworkInterface) -> Void)? {
        get { ipv4UdpInput }
        set { ipv4UdpInput = newValue }
    }

    /// TCP input callback (set by the TCP module).
    public var tcpInput: ((_ p: Pbuf, _ netif: NetworkInterface) -> Void)? {
        get { ipv4TcpInput }
        set { ipv4TcpInput = newValue }
    }

    /// Loopback output function.
    public var loopOutput: ((_ netif: NetworkInterface, _ p: Pbuf) -> LWIPError)? {
        get { ipv4LoopOutput }
        set { ipv4LoopOutput = newValue }
    }

}
