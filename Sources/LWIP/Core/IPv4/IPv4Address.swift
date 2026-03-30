//
//  IPv4Address.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IPv4Address

/// An IPv4 address stored as a UInt32 in network byte order.
@frozen
public struct IPv4Address: Equatable, Hashable, Sendable {

    /// The raw address in **network** byte order.
    public var addr: UInt32

    /// Create an IPv4Address from a raw value already in network byte order.
    @inlinable
    public init(networkOrder addr: UInt32) {
        self.addr = addr
    }

    /// Create an IPv4Address from four decimal octets (e.g. 192, 168, 1, 1).
    @inlinable
    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        self.addr = ByteOrder.hostToNetwork(ByteOrder.makeUInt32(a, b, c, d))
    }

    /// Create a zero / "any" address.
    @inlinable
    public init() {
        self.addr = 0
    }

    // MARK: Well-known addresses

    /// 0.0.0.0
    public static let any       = IPv4Address(networkOrder: IPv4Address.rawAny)
    /// 255.255.255.255
    public static let broadcast = IPv4Address(networkOrder: IPv4Address.rawBroadcast)
    /// 127.0.0.1
    public static let loopback  = IPv4Address(networkOrder: ByteOrder.hostToNetwork(IPv4Address.rawLoopback))
    /// 255.255.255.255 (same value as broadcast, used as "none"/error sentinel)
    public static let none      = IPv4Address(networkOrder: IPv4Address.rawNone)

    // Raw constants in host byte order
    public static let rawNone:      UInt32 = 0xFFFF_FFFF
    public static let rawLoopback:  UInt32 = 0x7F00_0001
    public static let rawAny:       UInt32 = 0x0000_0000
    public static let rawBroadcast: UInt32 = 0xFFFF_FFFF

    // MARK: - Byte access

    /// Get one byte from the 4-byte address (index 0..3, in network/wire order).
    @inlinable
    public func byte(at index: Int) -> UInt8 {
        precondition(index >= 0 && index < 4)
        return UInt8(truncatingIfNeeded: addr >> (index * 8))
    }

    /// Octet 1 (network order byte 0).
    @inlinable public var octet1: UInt8 { byte(at: 0) }
    /// Octet 2 (network order byte 1).
    @inlinable public var octet2: UInt8 { byte(at: 1) }
    /// Octet 3 (network order byte 2).
    @inlinable public var octet3: UInt8 { byte(at: 2) }
    /// Octet 4 (network order byte 3).
    @inlinable public var octet4: UInt8 { byte(at: 3) }

    // MARK: - Classification

    /// True if the address is 0.0.0.0 (any / wildcard).
    @inlinable
    public var isAny: Bool { addr == IPv4Address.rawAny }

    /// True if the address is in the loopback range (127.x.x.x).
    @inlinable
    public var isLoopback: Bool {
        (addr & ByteOrder.hostToNetwork(0xFF00_0000)) == ByteOrder.hostToNetwork(UInt32(127) << 24)
    }

    /// True if the address is a class D multicast address (224.0.0.0 - 239.255.255.255).
    @inlinable
    public var isMulticast: Bool {
        (addr & ByteOrder.hostToNetwork(0xF000_0000)) == ByteOrder.hostToNetwork(0xE000_0000)
    }

    /// True if the address is link-local (169.254.x.x).
    @inlinable
    public var isLinkLocal: Bool {
        (addr & ByteOrder.hostToNetwork(0xFFFF_0000)) == ByteOrder.hostToNetwork(0xA9FE_0000)
    }

    /// True if the address is a broadcast address (255.255.255.255).
    @inlinable
    public var isBroadcast: Bool {
        addr == IPv4Address.rawBroadcast
    }

    // MARK: - IP address class helpers

    /// Class A: 0.0.0.0 - 127.255.255.255
    @inlinable
    public var isClassA: Bool {
        (ByteOrder.networkToHost(addr) & 0x8000_0000) == 0
    }

    /// Class B: 128.0.0.0 - 191.255.255.255
    @inlinable
    public var isClassB: Bool {
        (ByteOrder.networkToHost(addr) & 0xC000_0000) == 0x8000_0000
    }

    /// Class C: 192.0.0.0 - 223.255.255.255
    @inlinable
    public var isClassC: Bool {
        (ByteOrder.networkToHost(addr) & 0xE000_0000) == 0xC000_0000
    }

    /// Class D (multicast): 224.0.0.0 - 239.255.255.255
    @inlinable
    public var isClassD: Bool {
        (ByteOrder.networkToHost(addr) & 0xF000_0000) == 0xE000_0000
    }

    // MARK: - Network operations

    /// Return the network address by combining this host address with a netmask.
    @inlinable
    public func network(mask: IPv4Address) -> IPv4Address {
        IPv4Address(networkOrder: addr & mask.addr)
    }

    /// Check whether two addresses are on the same network.
    @inlinable
    public func isOnSameNetwork(as other: IPv4Address, mask: IPv4Address) -> Bool {
        (addr & mask.addr) == (other.addr & mask.addr)
    }

    /// Check whether a given netmask is valid (contiguous 1-bits then 0-bits).
    @inlinable
    public static func isValidNetmask(_ netmask: UInt32) -> Bool {
        let hostOrder = ByteOrder.networkToHost(netmask)
        var mask: UInt32 = 1 << 31
        // Find the first zero bit
        while mask != 0 {
            if (hostOrder & mask) == 0 { break }
            mask >>= 1
        }
        // Then verify no one-bits after that
        while mask != 0 {
            if (hostOrder & mask) != 0 { return false }
            mask >>= 1
        }
        return true
    }

    /// Set this address to the host-to-network-order version of another address.
    @inlinable
    public mutating func setHton(from source: IPv4Address) {
        addr = ByteOrder.hostToNetwork(source.addr)
    }
}

// MARK: - Parsing (ip4addr_aton)

extension IPv4Address {

    /// Parse a dotted-decimal IPv4 string (e.g. "192.168.1.1") into an IPv4Address.
    ///
    /// Supports the full BSD `inet_aton` syntax:
    /// - `a.b.c.d`  (8.8.8.8 bits)
    /// - `a.b.c`    (8.8.16 bits)
    /// - `a.b`      (8.24 bits)
    /// - `a`        (32 bits)
    ///
    /// Hex (`0x`) and octal (`0`) prefixes are supported per component.
    /// Returns `nil` on parse failure.
    public init?(_ string: String) {
        guard let result = IPv4Address.parse(string) else { return nil }
        self = result
    }

    /// Parse a dotted-decimal IPv4 string. Returns `nil` on failure.
    /// This is the Swift equivalent of `ip4addr_aton`.
    public static func parse(_ cp: String) -> IPv4Address? {
        var bytes = Array(cp.utf8)
        bytes.append(0) // NUL terminator
        return bytes.withUnsafeBufferPointer { buf in
            parseBytes(buf.baseAddress!)
        }
    }

    /// Low-level parser operating on a NUL-terminated UTF-8 buffer.
    internal static func parseBytes(_ cp: UnsafePointer<UInt8>) -> IPv4Address? {
        var p = cp
        var parts: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
        var partCount = 0
        var val: UInt32 = 0

        var c = p.pointee

        while true {
            // Each part must start with a digit
            guard c.isASCIIDigit else { return nil }

            val = 0
            var base: UInt32 = 10

            if c == UInt8(ascii: "0") {
                p += 1; c = p.pointee
                if c == UInt8(ascii: "x") || c == UInt8(ascii: "X") {
                    base = 16
                    p += 1; c = p.pointee
                } else {
                    base = 8
                }
            }

            while true {
                if c.isASCIIDigit {
                    if base == 8 && UInt32(c - UInt8(ascii: "0")) >= 8 { break }
                    val = val &* base &+ UInt32(c - UInt8(ascii: "0"))
                    p += 1; c = p.pointee
                } else if base == 16 && c.isASCIIHexDigit {
                    let hexVal: UInt32
                    if c.isASCIILowercase {
                        hexVal = UInt32(c) + 10 - UInt32(UInt8(ascii: "a"))
                    } else {
                        hexVal = UInt32(c) + 10 - UInt32(UInt8(ascii: "A"))
                    }
                    val = (val << 4) | hexVal
                    p += 1; c = p.pointee
                } else {
                    break
                }
            }

            if c == UInt8(ascii: ".") {
                if partCount >= 3 { return nil }
                switch partCount {
                case 0: parts.0 = val
                case 1: parts.1 = val
                case 2: parts.2 = val
                default: return nil
                }
                partCount += 1
                p += 1; c = p.pointee
            } else {
                break
            }
        }

        // Check for trailing characters
        if c != 0 && !c.isASCIIWhitespace { return nil }

        // Assemble the address based on number of parts
        switch partCount + 1 {
        case 0:
            return nil
        case 1: // a -- 32 bits
            break
        case 2: // a.b -- 8.24 bits
            if val > 0x00FF_FFFF { return nil }
            if parts.0 > 0xFF { return nil }
            val |= parts.0 << 24
        case 3: // a.b.c -- 8.8.16 bits
            if val > 0xFFFF { return nil }
            if parts.0 > 0xFF || parts.1 > 0xFF { return nil }
            val |= (parts.0 << 24) | (parts.1 << 16)
        case 4: // a.b.c.d -- 8.8.8.8 bits
            if val > 0xFF { return nil }
            if parts.0 > 0xFF || parts.1 > 0xFF || parts.2 > 0xFF { return nil }
            val |= (parts.0 << 24) | (parts.1 << 16) | (parts.2 << 8)
        default:
            return nil
        }

        return IPv4Address(networkOrder: ByteOrder.hostToNetwork(val))
    }
}

// MARK: - Formatting (ip4addr_ntoa / ip4addr_ntoa_r)

extension IPv4Address: CustomStringConvertible {

    /// The dotted-decimal string representation (e.g. "192.168.1.1").
    public var description: String {
        let b0 = octet1
        let b1 = octet2
        let b2 = octet3
        let b3 = octet4
        return "\(b0).\(b1).\(b2).\(b3)"
    }

    /// Maximum string length for an IPv4 address (including NUL terminator).
    public static let maxStringLength = 16

    /// Write the dotted-decimal representation into a pre-allocated buffer.
    /// Returns the number of bytes written (not including NUL terminator),
    /// or `nil` if the buffer is too small.
    ///
    public func writeTo(buffer: UnsafeMutableBufferPointer<UInt8>) -> Int? {
        let s = self.description
        let utf8 = Array(s.utf8)
        guard utf8.count < buffer.count else { return nil }
        for (i, byte) in utf8.enumerated() {
            buffer[i] = byte
        }
        buffer[utf8.count] = 0
        return utf8.count
    }
}

// MARK: - ipaddr_addr convenience

extension IPv4Address {
    /// Parse a dotted-decimal string and return the raw UInt32 in network order.
    /// Returns `IPADDR_NONE` (0xFFFFFFFF) on failure.
    @inlinable
    public static func fromString(_ cp: String) -> UInt32 {
        if let addr = IPv4Address(cp) {
            return addr.addr
        }
        return IPv4Address.rawNone
    }
}

// MARK: - Class constants

extension IPv4Address {

    /// Namespace for IPv4 address class constants.
    public enum ClassConstants {
        // Class A
        public static let classANet: UInt32     = 0xFF00_0000
        public static let classAShift: Int      = 24
        public static let classAHost: UInt32    = 0x00FF_FFFF
        public static let classAMax: Int        = 128

        // Class B
        public static let classBNet: UInt32     = 0xFFFF_0000
        public static let classBShift: Int      = 16
        public static let classBHost: UInt32    = 0x0000_FFFF
        public static let classBMax: Int        = 65536

        // Class C
        public static let classCNet: UInt32     = 0xFFFF_FF00
        public static let classCShift: Int      = 8
        public static let classCHost: UInt32    = 0x0000_00FF

        // Class D (multicast)
        public static let classDNet: UInt32     = 0xF000_0000
        public static let classDShift: Int      = 28
        public static let classDHost: UInt32    = 0x0FFF_FFFF

        public static let loopbackNet: UInt32   = 127
    }

}

// MARK: - Codable

extension IPv4Address: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let str = try container.decode(String.self)
        guard let parsed = IPv4Address(str) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid IPv4 address string: \(str)"
            )
        }
        self = parsed
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
