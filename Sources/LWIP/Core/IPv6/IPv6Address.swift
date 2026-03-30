//
//  IPv6Address.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IPv6 Address State

/// IPv6 address lifecycle states (matching IP6_ADDR_* defines).
public struct IPv6AddressState: RawRepresentable, Equatable, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let invalid     = IPv6AddressState(rawValue: 0x00)
    public static let tentative   = IPv6AddressState(rawValue: 0x08)
    public static let tentative1  = IPv6AddressState(rawValue: 0x09)
    public static let tentative2  = IPv6AddressState(rawValue: 0x0A)
    public static let tentative3  = IPv6AddressState(rawValue: 0x0B)
    public static let tentative4  = IPv6AddressState(rawValue: 0x0C)
    public static let tentative5  = IPv6AddressState(rawValue: 0x0D)
    public static let tentative6  = IPv6AddressState(rawValue: 0x0E)
    public static let tentative7  = IPv6AddressState(rawValue: 0x0F)
    public static let valid       = IPv6AddressState(rawValue: 0x10)
    public static let preferred   = IPv6AddressState(rawValue: 0x30)
    public static let deprecated  = IPv6AddressState(rawValue: 0x10) // same as valid
    public static let duplicated  = IPv6AddressState(rawValue: 0x40)

    public static let tentativeCountMask = IPv6AddressState(rawValue: 0x07)

    @inlinable public var isInvalid: Bool    { rawValue == IPv6AddressState.invalid.rawValue }
    @inlinable public var isTentative: Bool  { (rawValue & IPv6AddressState.tentative.rawValue) != 0 && !isValid }
    @inlinable public var isValid: Bool      { (rawValue & IPv6AddressState.valid.rawValue) != 0 }
    @inlinable public var isPreferred: Bool  { rawValue == IPv6AddressState.preferred.rawValue }
    @inlinable public var isDeprecated: Bool { rawValue == IPv6AddressState.deprecated.rawValue }
    @inlinable public var isDuplicated: Bool { rawValue == IPv6AddressState.duplicated.rawValue }
}

// MARK: - IPv6 Address Lifetime

/// IPv6 address lifetime constants.
public enum IPv6AddressLifetime {
    /// Static address - never expires.
    public static let `static`: UInt32 = 0
    /// Infinite lifetime.
    public static let infinite: UInt32 = 0xFFFF_FFFF

    @inlinable
    public static func isStatic(_ life: UInt32) -> Bool { life == `static` }
    @inlinable
    public static func isInfinite(_ life: UInt32) -> Bool { life == infinite }
}

// MARK: - IPv6 Scope Type

/// IPv6 address scope type for zone assignment decisions.
public enum IPv6ScopeType: UInt8, Sendable {
    case unknown   = 0
    case unicast   = 1
    case multicast = 2
}

// MARK: - IPv6 Multicast Scope

/// IPv6 multicast scope values (RFC 4007).
public enum IPv6MulticastScope: UInt8, Sendable {
    case reserved          = 0x0
    case interfaceLocal    = 0x1
    case linkLocal         = 0x2
    case reserved3         = 0x3
    case adminLocal        = 0x4
    case siteLocal         = 0x5
    case organizationLocal = 0x8
    case global            = 0xE
    case reservedF         = 0xF
}

// MARK: - Zone index

/// Namespace for IPv6 zone constants.
public enum IPv6ZoneConstants {
    /// No zone assigned.
    public static let noZone: UInt8 = 0
}

// MARK: - IPv6Address

/// An IPv6 address stored as four UInt32 words in network byte order, with an optional zone index.
@frozen
public struct IPv6Address: Sendable {

    /// The four 32-bit words of the address, in network byte order.
    public var addr: (UInt32, UInt32, UInt32, UInt32)

    /// Zone index (for scoped/link-local addresses). 0 means "no zone".
    public var zone: UInt8

    // MARK: Initialization

    /// Create an IPv6 address from four 32-bit words in network byte order.
    @inlinable
    public init(_ w0: UInt32, _ w1: UInt32, _ w2: UInt32, _ w3: UInt32, zone: UInt8 = IPv6ZoneConstants.noZone) {
        self.addr = (w0, w1, w2, w3)
        self.zone = zone
    }

    /// Create a zero (any) address.
    @inlinable
    public init() {
        self.addr = (0, 0, 0, 0)
        self.zone = IPv6ZoneConstants.noZone
    }

    /// Create an IPv6 address from byte parts (each group of 4 bytes forms one word).
    @inlinable
    public init(
        _ a0: UInt8, _ b0: UInt8, _ c0: UInt8, _ d0: UInt8,
        _ a1: UInt8, _ b1: UInt8, _ c1: UInt8, _ d1: UInt8,
        _ a2: UInt8, _ b2: UInt8, _ c2: UInt8, _ d2: UInt8,
        _ a3: UInt8, _ b3: UInt8, _ c3: UInt8, _ d3: UInt8,
        zone: UInt8 = IPv6ZoneConstants.noZone
    ) {
        self.addr = (
            ByteOrder.hostToNetwork(ByteOrder.makeUInt32(a0, b0, c0, d0)),
            ByteOrder.hostToNetwork(ByteOrder.makeUInt32(a1, b1, c1, d1)),
            ByteOrder.hostToNetwork(ByteOrder.makeUInt32(a2, b2, c2, d2)),
            ByteOrder.hostToNetwork(ByteOrder.makeUInt32(a3, b3, c3, d3))
        )
        self.zone = zone
    }

    // MARK: Well-known addresses

    /// The all-zeros / "any" address (::).
    public static let any = IPv6Address()

    /// The loopback address (::1).
    public static let loopback = IPv6Address(0, 0, 0, ByteOrder.hostToNetwork(0x0000_0001))

    // MARK: - 16-bit block access

    /// Access one of the eight 16-bit blocks (index 0..7) in host byte order.
    @inlinable
    public func block(_ index: Int) -> UInt16 {
        guard index >= 0 && index < 8 else { return 0 }
        let wordIndex = index / 2
        let hostWord: UInt32
        switch wordIndex {
        case 0: hostWord = ByteOrder.networkToHost(addr.0)
        case 1: hostWord = ByteOrder.networkToHost(addr.1)
        case 2: hostWord = ByteOrder.networkToHost(addr.2)
        case 3: hostWord = ByteOrder.networkToHost(addr.3)
        default: hostWord = 0
        }
        if (index & 1) == 0 {
            return UInt16((hostWord >> 16) & 0xFFFF)
        } else {
            return UInt16(hostWord & 0xFFFF)
        }
    }

    /// Access a 32-bit word by index (0..3).
    @inlinable
    public func word(_ index: Int) -> UInt32 {
        switch index {
        case 0: return addr.0
        case 1: return addr.1
        case 2: return addr.2
        case 3: return addr.3
        default: return 0
        }
    }

    /// Set a 32-bit word by index (0..3).
    @inlinable
    public mutating func setWord(_ index: Int, _ value: UInt32) {
        switch index {
        case 0: addr.0 = value
        case 1: addr.1 = value
        case 2: addr.2 = value
        case 3: addr.3 = value
        default: return
        }
    }

    // MARK: - Mutators

    /// Set this address to the zero/any address.
    @inlinable
    public mutating func setZero() {
        addr = (0, 0, 0, 0)
        zone = IPv6ZoneConstants.noZone
    }

    /// Set this address to the loopback address (::1).
    @inlinable
    public mutating func setLoopback() {
        addr = (0, 0, 0, ByteOrder.hostToNetwork(0x0000_0001))
        zone = IPv6ZoneConstants.noZone
    }

    /// Set the all-nodes link-local multicast address (ff02::1).
    @inlinable
    public mutating func setAllNodesLinkLocal() {
        addr = (ByteOrder.hostToNetwork(0xFF02_0000), 0, 0, ByteOrder.hostToNetwork(0x0000_0001))
        zone = IPv6ZoneConstants.noZone
    }

    /// Set the all-routers link-local multicast address (ff02::2).
    @inlinable
    public mutating func setAllRoutersLinkLocal() {
        addr = (ByteOrder.hostToNetwork(0xFF02_0000), 0, 0, ByteOrder.hostToNetwork(0x0000_0002))
        zone = IPv6ZoneConstants.noZone
    }

    /// Set a solicited-node multicast address for the given interface ID.
    @inlinable
    public mutating func setSolicitedNode(interfaceID: UInt32) {
        addr = (ByteOrder.hostToNetwork(0xFF02_0000), 0, ByteOrder.hostToNetwork(0x0000_0001), ByteOrder.hostToNetwork(0xFF00_0000) | interfaceID)
        zone = IPv6ZoneConstants.noZone
    }

    // MARK: - Zone operations

    /// Clear the zone, setting it to "no zone".
    @inlinable
    public mutating func clearZone() {
        zone = IPv6ZoneConstants.noZone
    }

    /// Check if this address has a zone assigned.
    @inlinable
    public var hasZone: Bool { zone != IPv6ZoneConstants.noZone }

    /// Check if this address's zone matches a given index.
    @inlinable
    public func zoneEquals(_ zoneIndex: UInt8) -> Bool { zone == zoneIndex }

    // MARK: - Classification

    /// True if all words are zero (the "any" / unspecified address).
    @inlinable
    public var isAny: Bool {
        addr.0 == 0 && addr.1 == 0 && addr.2 == 0 && addr.3 == 0
    }

    /// True if this is the loopback address (::1).
    @inlinable
    public var isLoopback: Bool {
        addr.0 == 0 && addr.1 == 0 && addr.2 == 0 && addr.3 == ByteOrder.hostToNetwork(0x0000_0001)
    }

    /// True if this is a global unicast address (2000::/3).
    @inlinable
    public var isGlobal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xE000_0000)) == ByteOrder.hostToNetwork(0x2000_0000)
    }

    /// True if this is a link-local unicast address (fe80::/10).
    @inlinable
    public var isLinkLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFFC0_0000)) == ByteOrder.hostToNetwork(0xFE80_0000)
    }

    /// True if this is a site-local unicast address (fec0::/10).
    @inlinable
    public var isSiteLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFFC0_0000)) == ByteOrder.hostToNetwork(0xFEC0_0000)
    }

    /// True if this is a unique-local address (fc00::/7).
    @inlinable
    public var isUniqueLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFE00_0000)) == ByteOrder.hostToNetwork(0xFC00_0000)
    }

    /// True if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
    @inlinable
    public var isIPv4Mapped: Bool {
        addr.0 == 0 && addr.1 == 0 && addr.2 == ByteOrder.hostToNetwork(0x0000_FFFF)
    }

    /// True if this is an IPv4-compatible IPv6 address (::x.x.x.x where x > 1).
    @inlinable
    public var isIPv4Compatible: Bool {
        addr.0 == 0 && addr.1 == 0 && addr.2 == 0 && ByteOrder.networkToHost(addr.3) > 1
    }

    /// True if this is a multicast address (ff00::/8).
    @inlinable
    public var isMulticast: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF00_0000)) == ByteOrder.hostToNetwork(0xFF00_0000)
    }

    /// Multicast scope for multicast addresses.
    @inlinable
    public var multicastScope: UInt8 {
        UInt8((ByteOrder.networkToHost(addr.0) >> 16) & 0xF)
    }

    /// True if this is an interface-local multicast address.
    @inlinable
    public var isMulticastInterfaceLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF01_0000)
    }

    /// True if this is a link-local multicast address.
    @inlinable
    public var isMulticastLinkLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF02_0000)
    }

    /// True if this is an admin-local multicast address.
    @inlinable
    public var isMulticastAdminLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF04_0000)
    }

    /// True if this is a site-local multicast address.
    @inlinable
    public var isMulticastSiteLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF05_0000)
    }

    /// True if this is an organization-local multicast address.
    @inlinable
    public var isMulticastOrgLocal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF08_0000)
    }

    /// True if this is a global multicast address.
    @inlinable
    public var isMulticastGlobal: Bool {
        (addr.0 & ByteOrder.hostToNetwork(0xFF8F_0000)) == ByteOrder.hostToNetwork(0xFF0E_0000)
    }

    /// True if this is the all-nodes interface-local address (ff01::1).
    @inlinable
    public var isAllNodesInterfaceLocal: Bool {
        addr.0 == ByteOrder.hostToNetwork(0xFF01_0000) && addr.1 == 0 && addr.2 == 0 && addr.3 == ByteOrder.hostToNetwork(0x0000_0001)
    }

    /// True if this is the all-nodes link-local address (ff02::1).
    @inlinable
    public var isAllNodesLinkLocal: Bool {
        addr.0 == ByteOrder.hostToNetwork(0xFF02_0000) && addr.1 == 0 && addr.2 == 0 && addr.3 == ByteOrder.hostToNetwork(0x0000_0001)
    }

    /// True if this is the all-routers link-local address (ff02::2).
    @inlinable
    public var isAllRoutersLinkLocal: Bool {
        addr.0 == ByteOrder.hostToNetwork(0xFF02_0000) && addr.1 == 0 && addr.2 == 0 && addr.3 == ByteOrder.hostToNetwork(0x0000_0002)
    }

    /// True if this is a solicited-node multicast address (ff02::1:ffxx:xxxx).
    @inlinable
    public var isSolicitedNode: Bool {
        addr.0 == ByteOrder.hostToNetwork(0xFF02_0000)
            && addr.2 == ByteOrder.hostToNetwork(0x0000_0001)
            && (addr.3 & ByteOrder.hostToNetwork(0xFF00_0000)) == ByteOrder.hostToNetwork(0xFF00_0000)
    }

    /// Get the subnet ID (lower 16 bits of word 2, in host order).
    @inlinable
    public var subnetID: UInt32 {
        ByteOrder.networkToHost(addr.2) & 0x0000_FFFF
    }

    // MARK: - Scoping

    /// Check if this address has a constrained scope (link-local unicast, or
    /// interface/link-local multicast).
    @inlinable
    public func hasScope(type: IPv6ScopeType = .unknown) -> Bool {
        isLinkLocal
            || (type != .unicast && (isMulticastInterfaceLocal || isMulticastLinkLocal))
    }

    /// Check if this address needs a zone but doesn't have one.
    @inlinable
    public func lacksZone(type: IPv6ScopeType = .unknown) -> Bool {
        !hasZone && hasScope(type: type)
    }

    // MARK: - Comparison

    /// Compare two addresses ignoring zone information.
    @inlinable
    public func equalsZoneless(_ other: IPv6Address) -> Bool {
        addr.0 == other.addr.0
            && addr.1 == other.addr.1
            && addr.2 == other.addr.2
            && addr.3 == other.addr.3
    }

    /// Compare network prefix (first 64 bits) ignoring zones.
    @inlinable
    public func networkEqualsZoneless(_ other: IPv6Address) -> Bool {
        addr.0 == other.addr.0 && addr.1 == other.addr.1
    }

    /// Compare network prefix (first 64 bits) including zone check.
    @inlinable
    public func networkEquals(_ other: IPv6Address) -> Bool {
        networkEqualsZoneless(other) && zone == other.zone
    }

    /// Compare host part (last 64 bits) after networkEquals succeeded.
    @inlinable
    public func hostEquals(_ other: IPv6Address) -> Bool {
        addr.2 == other.addr.2 && addr.3 == other.addr.3
    }
}

// MARK: - Equatable & Hashable

extension IPv6Address: Equatable {
    /// Two IPv6 addresses are equal if both the address bits and zone match.
    @inlinable
    public static func == (lhs: IPv6Address, rhs: IPv6Address) -> Bool {
        lhs.equalsZoneless(rhs) && lhs.zone == rhs.zone
    }
}

extension IPv6Address: Hashable {
    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(addr.0)
        hasher.combine(addr.1)
        hasher.combine(addr.2)
        hasher.combine(addr.3)
        hasher.combine(zone)
    }
}

// MARK: - Parsing (ip6addr_aton)

extension IPv6Address {

    /// Parse a standard IPv6 text representation (e.g. "2001:db8::1").
    /// Returns `nil` on failure.
    public init?(_ string: String) {
        guard let result = IPv6Address.parse(string) else { return nil }
        self = result
    }

    /// Parse an IPv6 address string. Returns `nil` on failure.
    public static func parse(_ cp: String) -> IPv6Address? {
        var bytes = Array(cp.utf8)
        bytes.append(0)
        return bytes.withUnsafeBufferPointer { buf in
            parseBytes(buf.baseAddress!)
        }
    }

    /// Low-level parser operating on NUL-terminated UTF-8 bytes.
    internal static func parseBytes(_ cp: UnsafePointer<UInt8>) -> IPv6Address? {
        var addrWords: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
        var addrIndex: Int = 0
        var currentBlockIndex: UInt32 = 0
        var currentBlockValue: UInt32 = 0

        // Count colons to determine zero_blocks
        var zeroBlocks: UInt32 = 8
        var checkIPv4Mapped = false
        var s = cp
        while s.pointee != 0 {
            if s.pointee == UInt8(ascii: ":") {
                zeroBlocks -= 1
            } else if s.pointee == UInt8(ascii: ".") {
                if zeroBlocks == 5 || zeroBlocks == 2 {
                    checkIPv4Mapped = true
                    zeroBlocks -= 1
                } else {
                    return nil
                }
                break
            } else if !s.pointee.isASCIIHexDigit {
                break
            }
            s += 1
        }

        // Parse each block
        s = cp
        while s.pointee != 0 {
            let c = s.pointee
            if c == UInt8(ascii: ":") {
                if (currentBlockIndex & 0x1) != 0 {
                    setAddrWord(&addrWords, addrIndex, addrWords[keyPath: wordKeyPath(addrIndex)] | currentBlockValue)
                    addrIndex += 1
                } else {
                    setAddrWord(&addrWords, addrIndex, currentBlockValue << 16)
                }
                currentBlockIndex += 1

                if checkIPv4Mapped && currentBlockIndex == 6 {
                    if let ip4 = IPv4Address.parseBytes(s + 1) {
                        setAddrWord(&addrWords, 3, ByteOrder.hostToNetwork(ip4.addr))
                        currentBlockIndex += 1
                        // Convert to network byte order
                        for i in 0..<4 {
                            setAddrWord(&addrWords, i, ByteOrder.hostToNetwork(readAddrWord(addrWords, i)))
                        }
                        return IPv6Address(addrWords.0, addrWords.1, addrWords.2, addrWords.3)
                    }
                }

                currentBlockValue = 0
                if currentBlockIndex > 7 { return nil }

                if (s + 1).pointee == UInt8(ascii: ":") {
                    if (s + 2).pointee == UInt8(ascii: ":") { return nil } // :::
                    s += 1
                    // Insert zero blocks
                    while zeroBlocks > 0 {
                        zeroBlocks -= 1
                        if (currentBlockIndex & 0x1) != 0 {
                            addrIndex += 1
                        } else {
                            setAddrWord(&addrWords, addrIndex, 0)
                        }
                        currentBlockIndex += 1
                        if currentBlockIndex > 7 { return nil }
                    }
                }
            } else if c.isASCIIHexDigit {
                let digit: UInt32
                if c.isASCIIDigit {
                    digit = UInt32(c - UInt8(ascii: "0"))
                } else if c.isASCIILowercase {
                    digit = UInt32(c - UInt8(ascii: "a")) + 10
                } else {
                    digit = UInt32(c - UInt8(ascii: "A")) + 10
                }
                currentBlockValue = (currentBlockValue << 4) + digit
            } else {
                break
            }
            s += 1
        }

        // Final block
        if (currentBlockIndex & 0x1) != 0 {
            setAddrWord(&addrWords, addrIndex, readAddrWord(addrWords, addrIndex) | currentBlockValue)
            addrIndex += 1
        } else {
            setAddrWord(&addrWords, addrIndex, currentBlockValue << 16)
        }

        // Convert all words to network byte order
        for i in 0..<4 {
            setAddrWord(&addrWords, i, ByteOrder.hostToNetwork(readAddrWord(addrWords, i)))
        }

        var result = IPv6Address(addrWords.0, addrWords.1, addrWords.2, addrWords.3)
        result.zone = IPv6ZoneConstants.noZone

        // Parse zone ID (%xxx) -- we store the zone as a simple number if parseable
        if s.pointee == UInt8(ascii: "%") {
            s += 1
            var zoneVal: UInt8 = 0
            while s.pointee != 0 && s.pointee.isASCIIDigit {
                zoneVal = zoneVal &* 10 &+ (s.pointee - UInt8(ascii: "0"))
                s += 1
            }
            result.zone = zoneVal
        }

        if currentBlockIndex != 7 { return nil }

        return result
    }

    // Helpers for tuple access by index
    @usableFromInline
    internal static func readAddrWord(_ t: (UInt32, UInt32, UInt32, UInt32), _ i: Int) -> UInt32 {
        switch i {
        case 0: return t.0
        case 1: return t.1
        case 2: return t.2
        case 3: return t.3
        default: return 0
        }
    }

    @usableFromInline
    internal static func setAddrWord(_ t: inout (UInt32, UInt32, UInt32, UInt32), _ i: Int, _ v: UInt32) {
        switch i {
        case 0: t.0 = v
        case 1: t.1 = v
        case 2: t.2 = v
        case 3: t.3 = v
        default: break
        }
    }

    @usableFromInline
    internal static func wordKeyPath(_ i: Int) -> WritableKeyPath<(UInt32, UInt32, UInt32, UInt32), UInt32> {
        switch i {
        case 0: return \.0
        case 1: return \.1
        case 2: return \.2
        case 3: return \.3
        default: return \.0
        }
    }
}

// MARK: - Formatting (ip6addr_ntoa / ip6addr_ntoa_r)

extension IPv6Address: CustomStringConvertible {

    /// Maximum string length for an IPv6 address representation.
    public static let maxStringLength = 46

    /// The colon-hex string representation (e.g. "2001:DB8::1").
    /// Uses RFC 5952 recommendations for :: compression.
    /// IPv4-mapped addresses are rendered as "::FFFF:a.b.c.d".
    public var description: String {
        // Handle IPv4-mapped addresses specially
        if isIPv4Mapped {
            let ip4 = IPv4Address(networkOrder: addr.3)
            return "::FFFF:\(ip4)"
        }

        var result = ""
        result.reserveCapacity(39)

        var emptyBlockFlag: UInt8 = 0 // 0=not started, 1=in empty run, 2=done

        for blockIdx in 0..<8 {
            let hostWord = ByteOrder.networkToHost(word(blockIdx >> 1))
            var blockValue: UInt32
            if (blockIdx & 1) == 0 {
                blockValue = (hostWord >> 16) & 0xFFFF
            } else {
                blockValue = hostWord & 0xFFFF
            }

            // Check for zero block compression
            if blockValue == 0 {
                if blockIdx == 7 && emptyBlockFlag == 1 {
                    result.append(":")
                    break
                }
                if emptyBlockFlag == 0 {
                    // Look ahead: only compress if at least two consecutive zeros
                    let nextHostWord = ByteOrder.networkToHost(word((blockIdx + 1) >> 1))
                    var nextBlockValue: UInt32
                    if ((blockIdx + 1) & 1) == 0 {
                        nextBlockValue = (nextHostWord >> 16) & 0xFFFF
                    } else {
                        nextBlockValue = nextHostWord & 0xFFFF
                    }
                    if blockIdx < 7 && nextBlockValue == 0 {
                        emptyBlockFlag = 1
                        result.append(":")
                        continue
                    }
                } else if emptyBlockFlag == 1 {
                    continue
                }
            } else if emptyBlockFlag == 1 {
                emptyBlockFlag = 2
            }

            if blockIdx > 0 {
                result.append(":")
            }

            // Format the 16-bit block as hex, suppressing leading zeros
            var zeroFlag = true
            let nibble3 = (blockValue & 0xF000) >> 12
            if nibble3 != 0 {
                result.append(hexChar(nibble3))
                zeroFlag = false
            }
            let nibble2 = (blockValue & 0x0F00) >> 8
            if nibble2 != 0 || !zeroFlag {
                result.append(hexChar(nibble2))
                zeroFlag = false
            }
            let nibble1 = (blockValue & 0x00F0) >> 4
            if nibble1 != 0 || !zeroFlag {
                result.append(hexChar(nibble1))
            }
            result.append(hexChar(blockValue & 0x000F))
        }

        return result
    }

    /// Write the string representation into a pre-allocated buffer.
    /// Returns the number of bytes written (not including NUL), or `nil` if buffer too small.
    public func writeTo(buffer: UnsafeMutableBufferPointer<UInt8>) -> Int? {
        let s = self.description
        let utf8 = Array(s.utf8)
        guard utf8.count < buffer.count else { return nil }
        for (i, b) in utf8.enumerated() {
            buffer[i] = b
        }
        buffer[utf8.count] = 0
        return utf8.count
    }
}

/// Convert a nibble value (0-15) to its uppercase hex character.
@inlinable
internal func hexChar(_ v: UInt32) -> Character {
    let i = Int(v & 0xF)
    if i < 10 {
        return Character(Unicode.Scalar(UInt8(ascii: "0") + UInt8(i)))
    } else {
        return Character(Unicode.Scalar(UInt8(ascii: "A") + UInt8(i - 10)))
    }
}

// MARK: - IPv4-mapped conversion helpers

extension IPv6Address {

    /// Create an IPv4-mapped IPv6 address from an IPv4 address.
    /// Result: `::FFFF:<ipv4>`.
    @inlinable
    public static func ipv4Mapped(_ ipv4: IPv4Address) -> IPv6Address {
        IPv6Address(0, 0, ByteOrder.hostToNetwork(0x0000_FFFF), ipv4.addr)
    }

    /// Extract the embedded IPv4 address from an IPv4-mapped IPv6 address.
    /// Assumes `isIPv4Mapped` is true.
    @inlinable
    public var mappedIPv4: IPv4Address {
        IPv4Address(networkOrder: addr.3)
    }
}

// MARK: - Extensions for IPv6 protocol modules

extension IPv6Address {

    /// The fourth 32-bit word in host byte order (used for multicast MAC mapping).
    @inlinable
    public var addr3: UInt32 { ByteOrder.networkToHost(addr.3) }

    /// Well-known all-nodes link-local multicast address (ff02::1).
    public static let allNodesLinkLocal = IPv6Address(ByteOrder.hostToNetwork(0xFF02_0000), 0, 0, ByteOrder.hostToNetwork(0x0000_0001))

    /// Well-known all-routers link-local multicast address (ff02::2).
    public static let allRoutersLinkLocal = IPv6Address(ByteOrder.hostToNetwork(0xFF02_0000), 0, 0, ByteOrder.hostToNetwork(0x0000_0002))

    /// Create a solicited-node multicast address for a given unicast address.
    @inlinable
    public static func solicitedNodeMulticast(for addr: IPv6Address) -> IPv6Address {
        IPv6Address(ByteOrder.hostToNetwork(0xFF02_0000), 0, ByteOrder.hostToNetwork(0x0000_0001),
                    ByteOrder.hostToNetwork(0xFF00_0000) | (addr.addr.3 & ByteOrder.hostToNetwork(0x00FF_FFFF)))
    }

    /// Check if the zone of this address matches a network interface.
    @inlinable
    public func testZone(on netif: NetworkInterface) -> Bool {
        zone == netif.num &+ 1
    }

    /// Return a copy of this address with the zone set for the given interface.
    @inlinable
    public func withZone(for netif: NetworkInterface) -> IPv6Address {
        var copy = self
        copy.zone = netif.num &+ 1
        return copy
    }

    /// Whether this address needs a zone assignment (has scope but no zone).
    @inlinable
    public var needsZone: Bool {
        hasScope(type: .unknown)
    }

    /// Compare two addresses ignoring zone.
    @inlinable
    public func equalsIgnoringZone(_ other: IPv6Address) -> Bool {
        equalsZoneless(other)
    }

    /// Check if two addresses share the same /64 prefix (subnet match).
    @inlinable
    public func matchesSubnet(of other: IPv6Address) -> Bool {
        networkEqualsZoneless(other)
    }

    /// Write the address bytes in network order to a raw pointer (16 bytes).
    @inlinable
    public func writeNetworkBytes(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: addr.0, toByteOffset: 0, as: UInt32.self)
        p.storeBytes(of: addr.1, toByteOffset: 4, as: UInt32.self)
        p.storeBytes(of: addr.2, toByteOffset: 8, as: UInt32.self)
        p.storeBytes(of: addr.3, toByteOffset: 12, as: UInt32.self)
    }

    /// Address scope value (for source address selection, RFC 6724).
    @inlinable
    public var addressScope: Int8 {
        if isGlobal { return Int8(IPv6MulticastScope.global.rawValue) }
        if isLinkLocal || isLoopback { return Int8(IPv6MulticastScope.linkLocal.rawValue) }
        if isUniqueLocal { return Int8(IPv6MulticastScope.organizationLocal.rawValue) }
        if isMulticast { return Int8(multicastScope) }
        if isSiteLocal { return Int8(IPv6MulticastScope.siteLocal.rawValue) }
        return Int8(IPv6MulticastScope.global.rawValue)
    }
}

// MARK: - Codable

extension IPv6Address: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let str = try container.decode(String.self)
        guard let parsed = IPv6Address(str) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid IPv6 address string: \(str)"
            )
        }
        self = parsed
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
