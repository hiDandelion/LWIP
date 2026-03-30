//
//  Arch.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Byte order constants

/// Byte order marker values used for compile-time endianness detection.
public enum ByteOrderMarker {
    /// Little-endian byte order marker.
    public static let littleEndian: UInt32 = 1234
    /// Big-endian byte order marker.
    public static let bigEndian: UInt32 = 4321
}

// MARK: - Memory alignment

/// Memory alignment configuration and utilities.
public enum MemoryAlignment {
    /// Default memory alignment in bytes.
    public static let defaultAlignment: Int = 4

    /// Round `size` up to the next multiple of `defaultAlignment`.
    @inlinable
    public static func alignedSize(_ size: Int) -> Int {
        (size + defaultAlignment - 1) & ~(defaultAlignment - 1)
    }
}

// MARK: - Character classification (UInt8 extensions)

extension UInt8 {
    /// Returns `true` if this byte is an ASCII decimal digit ('0'...'9').
    @inlinable
    public var isASCIIDigit: Bool {
        self >= UInt8(ascii: "0") && self <= UInt8(ascii: "9")
    }

    /// Returns `true` if this byte is an ASCII hexadecimal digit.
    @inlinable
    public var isASCIIHexDigit: Bool {
        isASCIIDigit
            || (self >= UInt8(ascii: "a") && self <= UInt8(ascii: "f"))
            || (self >= UInt8(ascii: "A") && self <= UInt8(ascii: "F"))
    }

    /// Returns `true` if this byte is an ASCII lowercase letter ('a'...'z').
    @inlinable
    public var isASCIILowercase: Bool {
        self >= UInt8(ascii: "a") && self <= UInt8(ascii: "z")
    }

    /// Returns `true` if this byte is an ASCII uppercase letter ('A'...'Z').
    @inlinable
    public var isASCIIUppercase: Bool {
        self >= UInt8(ascii: "A") && self <= UInt8(ascii: "Z")
    }

    /// Returns `true` if this byte is an ASCII whitespace character.
    @inlinable
    public var isASCIIWhitespace: Bool {
        self == UInt8(ascii: " ")
            || self == 0x0C // \f
            || self == 0x0A // \n
            || self == 0x0D // \r
            || self == 0x09 // \t
            || self == 0x0B // \v
    }

    /// Returns the ASCII-lowercased version of this byte, or the byte unchanged
    /// if it is not an uppercase ASCII letter.
    @inlinable
    public var asciiLowercased: UInt8 {
        isASCIIUppercase ? self &- UInt8(ascii: "A") &+ UInt8(ascii: "a") : self
    }

    /// Returns the ASCII-uppercased version of this byte, or the byte unchanged
    /// if it is not a lowercase ASCII letter.
    @inlinable
    public var asciiUppercased: UInt8 {
        isASCIILowercase ? self &- UInt8(ascii: "a") &+ UInt8(ascii: "A") : self
    }
}

