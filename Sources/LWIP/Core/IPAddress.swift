//
//  IPAddress.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IPAddress

/// A unified IP address that can hold either an IPv4 or IPv6 address.
public enum IPAddress: Sendable {
    /// An IPv4 address.
    case v4(IPv4Address)
    /// An IPv6 address.
    case v6(IPv6Address)
    /// A dual-stack "any" type (binds to both IPv4 and IPv6).
    case any

    // MARK: - Type queries

    /// True if this is an IPv4 address.
    @inlinable
    public var isV4: Bool {
        if case .v4 = self { return true }
        return false
    }

    /// True if this is an IPv6 address.
    @inlinable
    public var isV6: Bool {
        if case .v6 = self { return true }
        return false
    }

    /// True if this is the dual-stack "any" type.
    @inlinable
    public var isAnyType: Bool {
        if case .any = self { return true }
        return false
    }

    // MARK: - Extractors

    /// Extract the IPv4 address, or `nil` if this is not an IPv4 address.
    @inlinable
    public var ipv4: IPv4Address? {
        if case .v4(let a) = self { return a }
        return nil
    }

    /// Extract the IPv6 address, or `nil` if this is not an IPv6 address.
    @inlinable
    public var ipv6: IPv6Address? {
        if case .v6(let a) = self { return a }
        return nil
    }

    // MARK: - Well-known addresses

    /// The IPv4 "any" address (0.0.0.0).
    public static let ipv4Any = IPAddress.v4(.any)
    /// The IPv4 broadcast address (255.255.255.255).
    public static let ipv4Broadcast = IPAddress.v4(.broadcast)
    /// The IPv6 "any" address (::).
    public static let ipv6Any = IPAddress.v6(.any)

    // MARK: - Classification

    /// Check if this address is the "any" / wildcard address for its type.
    @inlinable
    public var isAnyAddress: Bool {
        switch self {
        case .v4(let a): return a.isAny
        case .v6(let a): return a.isAny
        case .any: return true
        }
    }

    /// Check if this address is a loopback address.
    @inlinable
    public var isLoopback: Bool {
        switch self {
        case .v4(let a): return a.isLoopback
        case .v6(let a): return a.isLoopback
        case .any: return false
        }
    }

    /// Check if this address is a multicast address.
    @inlinable
    public var isMulticast: Bool {
        switch self {
        case .v4(let a): return a.isMulticast
        case .v6(let a): return a.isMulticast
        case .any: return false
        }
    }

    /// Check if this address is a link-local address.
    @inlinable
    public var isLinkLocal: Bool {
        switch self {
        case .v4(let a): return a.isLinkLocal
        case .v6(let a): return a.isLinkLocal
        case .any: return false
        }
    }

    // MARK: - Raw size

    /// The byte size of the raw address (4 for IPv4, 16+ for IPv6).
    @inlinable
    public var rawSize: Int {
        switch self {
        case .v4: return 4
        case .v6: return MemoryLayout<IPv6Address>.size
        case .any: return MemoryLayout<IPv6Address>.size
        }
    }

    // MARK: - Conversion helpers

    /// Create an IPAddress from an IPv4 raw UInt32 in network order.
    @inlinable
    public static func fromIPv4(_ rawNetworkOrder: UInt32) -> IPAddress {
        .v4(IPv4Address(networkOrder: rawNetworkOrder))
    }

    /// Get the IPv4 raw UInt32 in network order (returns 0 if not IPv4).
    @inlinable
    public var ipv4RawNetworkOrder: UInt32 {
        if case .v4(let a) = self { return a.addr }
        return 0
    }

    /// Create an IPAddress wrapping an IPv6 address.
    @inlinable
    public static func fromIPv6(_ addr: IPv6Address) -> IPAddress {
        .v6(addr)
    }

    /// Create an IPv4-mapped IPv6 address from an IPv4 address, wrapped as IPAddress.v6.
    @inlinable
    public static func ipv4MappedToIPv6(_ ipv4: IPv4Address) -> IPAddress {
        .v6(IPv6Address.ipv4Mapped(ipv4))
    }

    /// Extract the IPv4 address from an IPv4-mapped IPv6, if applicable.
    @inlinable
    public var unmappedIPv4: IPv4Address? {
        if case .v6(let a) = self, a.isIPv4Mapped {
            return a.mappedIPv4
        }
        return nil
    }

    // MARK: - Set operations

    /// Set to the zero/"any" address for the given protocol version.
    @inlinable
    public static func zero(ipv6: Bool) -> IPAddress {
        ipv6 ? .v6(.any) : .v4(.any)
    }

    /// Set to the loopback address for the given protocol version.
    @inlinable
    public static func loopback(ipv6: Bool) -> IPAddress {
        ipv6 ? .v6(.loopback) : .v4(.loopback)
    }
}

// MARK: - Equatable

extension IPAddress: Equatable {
    /// Two IP addresses are equal if they are the same type and have the same value.
    /// The `.any` type is only equal to another `.any`.
    @inlinable
    public static func == (lhs: IPAddress, rhs: IPAddress) -> Bool {
        switch (lhs, rhs) {
        case (.v4(let a), .v4(let b)):
            return a == b
        case (.v6(let a), .v6(let b)):
            return a == b
        case (.any, .any):
            return true
        default:
            return false
        }
    }
}

// MARK: - Hashable

extension IPAddress: Hashable {
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .v4(let a):
            hasher.combine(0 as UInt8)
            hasher.combine(a)
        case .v6(let a):
            hasher.combine(1 as UInt8)
            hasher.combine(a)
        case .any:
            hasher.combine(2 as UInt8)
        }
    }
}

// MARK: - Comparison ignoring zone

extension IPAddress {
    /// Compare two addresses ignoring IPv6 zone information.
    @inlinable
    public func equalsZoneless(_ other: IPAddress) -> Bool {
        switch (self, other) {
        case (.v4(let a), .v4(let b)):
            return a == b
        case (.v6(let a), .v6(let b)):
            return a.equalsZoneless(b)
        case (.any, .any):
            return true
        default:
            return false
        }
    }
}

// MARK: - Parsing (ipaddr_aton)

extension IPAddress {

    /// Parse an IP address string. Tries IPv6 first (if it contains ':'),
    /// otherwise falls back to IPv4. Returns `nil` on failure.
    public init?(_ string: String) {
        if string.contains(":") {
            if let v6 = IPv6Address(string) {
                self = .v6(v6)
                return
            }
            return nil
        }
        if let v4 = IPv4Address(string) {
            self = .v4(v4)
            return
        }
        return nil
    }
}

// MARK: - Formatting

extension IPAddress: CustomStringConvertible {

    /// The string representation of this address.
    public var description: String {
        switch self {
        case .v4(let a): return a.description
        case .v6(let a): return a.description
        case .any: return "*"
        }
    }

    /// Maximum string length for any IP address representation.
    public static let maxStringLength = IPv6Address.maxStringLength
}
