//
//  Compat.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - UnsafeMutableRawPointer Subscript

extension UnsafeMutableRawPointer {
    @inlinable
    public subscript(offset: Int) -> UInt8 {
        get { load(fromByteOffset: offset, as: UInt8.self) }
        nonmutating set { storeBytes(of: newValue, toByteOffset: offset, as: UInt8.self) }
    }
}

extension UnsafeRawPointer {
    @inlinable
    public subscript(offset: Int) -> UInt8 {
        load(fromByteOffset: offset, as: UInt8.self)
    }
}

// MARK: - Pbuf Convenience

extension Pbuf {
    /// Read a single byte at Int offset
    @inlinable
    public func readByte(at offset: Int) -> UInt8 {
        byte(at: UInt16(offset))
    }

    /// Write a single byte at Int offset
    @inlinable
    public func writeByte(_ value: UInt8, at offset: Int) {
        setByte(at: UInt16(offset), to: value)
    }

    /// Read UInt16 in network byte order at Int offset
    @inlinable
    public func readUInt16(at offset: Int) -> UInt16 {
        let hi = UInt16(readByte(at: offset))
        let lo = UInt16(readByte(at: offset + 1))
        return (hi << 8) | lo
    }

    /// Read UInt32 at Int offset (raw bytes, no byte-order conversion)
    @inlinable
    public func readUInt32(at offset: Int) -> UInt32 {
        let b0 = UInt32(readByte(at: offset))
        let b1 = UInt32(readByte(at: offset + 1))
        let b2 = UInt32(readByte(at: offset + 2))
        let b3 = UInt32(readByte(at: offset + 3))
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Write UInt32 at Int offset
    public func writeUInt32(_ value: UInt32, at offset: Int) {
        writeByte(UInt8(truncatingIfNeeded: value), at: offset)
        writeByte(UInt8(truncatingIfNeeded: value >> 8), at: offset + 1)
        writeByte(UInt8(truncatingIfNeeded: value >> 16), at: offset + 2)
        writeByte(UInt8(truncatingIfNeeded: value >> 24), at: offset + 3)
    }

    /// Zero fill a region
    public func zeroFill(at offset: Int, count: Int) {
        for i in 0..<count {
            writeByte(0, at: offset + i)
        }
    }

    /// Write raw bytes at offset
    public func writeBytes(_ bytes: [UInt8], at offset: Int) {
        for (i, b) in bytes.enumerated() {
            writeByte(b, at: offset + i)
        }
    }
}

// MARK: - IPv4Address Byte Access

extension IPv4Address {
    public var bytes: (UInt8, UInt8, UInt8, UInt8) {
        (UInt8(truncatingIfNeeded: addr),
         UInt8(truncatingIfNeeded: addr >> 8),
         UInt8(truncatingIfNeeded: addr >> 16),
         UInt8(truncatingIfNeeded: addr >> 24))
    }
}
