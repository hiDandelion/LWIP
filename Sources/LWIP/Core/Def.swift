//
//  Def.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Byte Order

/// Byte-order conversion utilities.
///
/// On Swift platforms, `UInt16.bigEndian` / `UInt32.bigEndian` handle
/// byte swapping natively. These static methods provide lwIP-named
/// entry points that compile down to the same single-instruction
/// byte-swap or no-op depending on the host endianness.
public enum ByteOrder {

    /// Convert a UInt16 from host byte order to network byte order (big-endian).
    @inlinable
    public static func hostToNetwork(_ x: UInt16) -> UInt16 {
        x.bigEndian
    }

    /// Convert a UInt16 from network byte order (big-endian) to host byte order.
    @inlinable
    public static func networkToHost(_ x: UInt16) -> UInt16 {
        UInt16(bigEndian: x)
    }

    /// Convert a UInt32 from host byte order to network byte order (big-endian).
    @inlinable
    public static func hostToNetwork(_ x: UInt32) -> UInt32 {
        x.bigEndian
    }

    /// Convert a UInt32 from network byte order (big-endian) to host byte order.
    @inlinable
    public static func networkToHost(_ x: UInt32) -> UInt32 {
        UInt32(bigEndian: x)
    }

    // MARK: - UInt32 construction from bytes

    /// Create a UInt32 from four bytes (a is MSB, d is LSB).
    @inlinable
    public static func makeUInt32(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> UInt32 {
        (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
    }

    // MARK: - Constant-time memory comparison

    /// Constant-time memory comparison to prevent timing attacks.
    /// Returns 0 if the buffers are equal, non-zero otherwise.
    @inlinable
    public static func constantTimeCompare(_ s1: UnsafeRawBufferPointer, _ s2: UnsafeRawBufferPointer) -> Int {
        precondition(s1.count == s2.count, "Buffers must be the same length for constant-time comparison")
        var result: UInt8 = 0
        for i in 0..<s1.count {
            result |= s1[i] ^ s2[i]
        }
        return Int(result)
    }

    /// Constant-time memory comparison for raw pointers and explicit length.
    @inlinable
    public static func constantTimeCompare(
        _ s1: UnsafeRawPointer,
        _ s2: UnsafeRawPointer,
        length: Int
    ) -> Int {
        let a = s1.assumingMemoryBound(to: UInt8.self)
        let b = s2.assumingMemoryBound(to: UInt8.self)
        var result: UInt8 = 0
        for i in 0..<length {
            result |= a[i] ^ b[i]
        }
        return Int(result)
    }
}

// MARK: - String Utilities

extension String {
    /// Case-insensitive comparison. Returns `true` if equal.
    public func caseInsensitiveEquals(_ other: String) -> Bool {
        self.utf8.withContiguousStorageIfAvailable { buffer1 in
            other.utf8.withContiguousStorageIfAvailable { buffer2 in
                caseInsensitiveCompareBytes(
                    buffer1.baseAddress!, buffer1.count,
                    buffer2.baseAddress!, buffer2.count
                ) == 0
            } ?? false
        } ?? (self.lowercased() == other.lowercased())
    }

    /// Case-insensitive, length-limited comparison. Returns `true` if equal
    /// up to `maxLength` characters.
    public func caseInsensitiveEquals(_ other: String, maxLength: Int) -> Bool {
        self.utf8.withContiguousStorageIfAvailable { buffer1 in
            other.utf8.withContiguousStorageIfAvailable { buffer2 in
                caseInsensitivePrefixCompareBytes(
                    buffer1.baseAddress!, buffer2.baseAddress!, maxLength
                ) == 0
            } ?? false
        } ?? false
    }

    /// Initialize a String from an integer's decimal ASCII representation.
    @inlinable
    public init(fromInteger number: Int) {
        self = String(number)
    }
}

/// Byte-level case-insensitive comparison (full strings).
@usableFromInline
internal func caseInsensitiveCompareBytes(
    _ s1: UnsafePointer<UInt8>, _ length1: Int,
    _ s2: UnsafePointer<UInt8>, _ length2: Int
) -> Int {
    var i1 = 0, i2 = 0
    while i1 < length1 && i2 < length2 {
        let c1 = s1[i1]
        let c2 = s2[i2]
        if c1 != c2 {
            let c1Low = c1 | 0x20
            if c1Low >= UInt8(ascii: "a") && c1Low <= UInt8(ascii: "z") {
                let c2Low = c2 | 0x20
                if c1Low != c2Low { return 1 }
            } else {
                return 1
            }
        }
        i1 += 1
        i2 += 1
    }
    // Both must have ended at the same length
    if i1 < length1 || i2 < length2 { return 1 }
    return 0
}

/// Byte-level case-insensitive comparison (length-limited).
@usableFromInline
internal func caseInsensitivePrefixCompareBytes(
    _ s1: UnsafePointer<UInt8>,
    _ s2: UnsafePointer<UInt8>,
    _ maxLength: Int
) -> Int {
    var remaining = maxLength
    var p1 = s1
    var p2 = s2
    while remaining > 0 {
        let c1 = p1.pointee
        let c2 = p2.pointee
        if c1 == 0 && c2 == 0 { return 0 }
        if c1 != c2 {
            let c1Low = c1 | 0x20
            if c1Low >= UInt8(ascii: "a") && c1Low <= UInt8(ascii: "z") {
                let c2Low = c2 | 0x20
                if c1Low != c2Low { return 1 }
            } else {
                return 1
            }
        }
        if c1 == 0 { return 0 }
        p1 += 1
        p2 += 1
        remaining -= 1
    }
    return 0
}


