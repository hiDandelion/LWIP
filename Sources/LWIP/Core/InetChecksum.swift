//
//  InetChecksum.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - InetChecksum

/// Internet checksum computation (RFC 1071).
///
/// All public entry points produce the final ones-complement checksum
/// ready to be stored directly in protocol headers.
public enum InetChecksum {

    // MARK: - Helper Functions

    /// Swap bytes in a 16-bit word stored in a UInt32 accumulator.
    @inlinable @inline(__always)
    public static func swapBytesInWord(_ word: UInt32) -> UInt32 {
        ((word & 0xFF) << 8) | ((word & 0xFF00) >> 8)
    }

    /// Fold a 32-bit accumulator to 16 bits by adding high and low halves.
    @inlinable @inline(__always)
    public static func foldUInt32(_ accumulator: UInt32) -> UInt32 {
        (accumulator >> 16) &+ (accumulator & 0x0000_FFFF)
    }

    // MARK: - Core Checksum (algorithm #2, optimized for unaligned buffers)

    /// Compute the raw (non-inverted) Internet checksum over a contiguous buffer.
    ///
    /// This is equivalent to lwIP's `lwip_standard_chksum` (algorithm #2).
    /// Works for any alignment and lengths up to 128KB.
    ///
    /// - Parameters:
    ///   - dataptr: Pointer to the data.
    ///   - len: Number of bytes.
    /// - Returns: Non-inverted checksum in host byte order.
    @inlinable
    public static func rawChecksum(_ dataptr: UnsafeRawPointer, len: Int) -> UInt16 {
        var pb = dataptr
        var remaining = len
        var t: UInt16 = 0
        var sum: UInt32 = 0
        let odd = (Int(bitPattern: pb) & 1) != 0

        // Align to UInt16 boundary.
        if odd && remaining > 0 {
            // Place the byte in the high byte of t (network order).
            var tBytes = (UInt8(0), UInt8(0))
            tBytes.1 = pb.load(as: UInt8.self)
            withUnsafeBytes(of: &tBytes) { t = $0.load(as: UInt16.self) }
            pb += 1
            remaining -= 1
        }

        // Sum 16-bit words.
        // Use 32-bit accumulation for speed.
        let ps = pb.assumingMemoryBound(to: UInt8.self)
        var idx = 0

        // Process 4 bytes at a time for speed.
        while remaining > 3 {
            let b0 = UInt32(ps[idx])
            let b1 = UInt32(ps[idx + 1])
            let b2 = UInt32(ps[idx + 2])
            let b3 = UInt32(ps[idx + 3])
            sum &+= (b0 << 8) | b1
            sum &+= (b2 << 8) | b3
            idx += 4
            remaining -= 4
        }

        // Process remaining 16-bit word.
        while remaining > 1 {
            let b0 = UInt32(ps[idx])
            let b1 = UInt32(ps[idx + 1])
            sum &+= (b0 << 8) | b1
            idx += 2
            remaining -= 2
        }

        // Handle trailing byte.
        if remaining > 0 {
            var tBytes2 = (UInt8(0), UInt8(0))
            tBytes2.0 = ps[idx]
            var t2: UInt16 = 0
            withUnsafeBytes(of: &tBytes2) { t2 = $0.load(as: UInt16.self) }
            sum &+= UInt32(t2)
        }

        // Add the initial misaligned byte.
        sum &+= UInt32(t)

        // Fold to 16 bits.
        sum = foldUInt32(sum)
        sum = foldUInt32(sum)

        // Swap if the buffer was at an odd address.
        if odd {
            sum = swapBytesInWord(sum)
        }

        return UInt16(sum & 0xFFFF)
    }

    // MARK: - Standard checksum (inverted, ready for headers)

    /// Calculate the Internet checksum over a contiguous memory buffer.
    /// The result is the ones-complement inverted checksum, ready for
    /// direct insertion into protocol headers.
    ///
    /// - Parameters:
    ///   - dataptr: Pointer to data.
    ///   - len: Length in bytes.
    /// - Returns: Checksum value.
    @inlinable
    public static func checksum(_ dataptr: UnsafeRawPointer, len: UInt16) -> UInt16 {
        return ~rawChecksum(dataptr, len: Int(len))
    }

    // MARK: - Pbuf chain checksum (no pseudo header)

    /// Calculate checksum over a pbuf chain (without pseudo-header).
    ///
    /// - Parameter p: The pbuf chain.
    /// - Returns: Checksum ready for protocol headers.
    @inlinable
    public static func checksumPbuf(_ p: Pbuf) -> UInt16 {
        var acc: UInt32 = 0
        var swapped = false
        var q: Pbuf? = p

        while let current = q {
            acc &+= UInt32(rawChecksum(current.payload, len: Int(current.len)))
            acc = foldUInt32(acc)
            if current.len % 2 != 0 {
                swapped = !swapped
                acc = swapBytesInWord(acc)
            }
            q = current.next
        }

        if swapped {
            acc = swapBytesInWord(acc)
        }
        return UInt16(~acc & 0xFFFF)
    }

    // MARK: - Pseudo-header checksum base

    /// Common pseudo-header checksum logic shared by IPv4 and IPv6.
    @usableFromInline
    internal static func pseudoBase(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        initialAcc: UInt32
    ) -> UInt16 {
        var acc = initialAcc
        var swapped = false
        var q: Pbuf? = p

        while let current = q {
            acc &+= UInt32(rawChecksum(current.payload, len: Int(current.len)))
            acc = foldUInt32(acc)
            if current.len % 2 != 0 {
                swapped = !swapped
                acc = swapBytesInWord(acc)
            }
            q = current.next
        }

        if swapped {
            acc = swapBytesInWord(acc)
        }

        acc &+= UInt32(protoLen.bigEndian)
        acc &+= UInt32(UInt16(proto).bigEndian)

        acc = foldUInt32(acc)
        acc = foldUInt32(acc)

        return UInt16(~acc & 0xFFFF)
    }

    /// Common partial pseudo-header checksum (checksums only `chksumLen` bytes of payload).
    @usableFromInline
    internal static func pseudoPartialBase(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        chksumLen: UInt16,
        initialAcc: UInt32
    ) -> UInt16 {
        var acc = initialAcc
        var swapped = false
        var q: Pbuf? = p
        var remaining = chksumLen

        while let current = q, remaining > 0 {
            let chklen = min(current.len, remaining)
            acc &+= UInt32(rawChecksum(current.payload, len: Int(chklen)))
            remaining -= chklen
            acc = foldUInt32(acc)
            if chklen % 2 != 0 {
                swapped = !swapped
                acc = swapBytesInWord(acc)
            }
            q = current.next
        }

        if swapped {
            acc = swapBytesInWord(acc)
        }

        acc &+= UInt32(protoLen.bigEndian)
        acc &+= UInt32(UInt16(proto).bigEndian)

        acc = foldUInt32(acc)
        acc = foldUInt32(acc)

        return UInt16(~acc & 0xFFFF)
    }

    // MARK: - IPv4 Pseudo-header Checksum

    /// Calculate TCP/UDP checksum with IPv4 pseudo-header.
    ///
    /// - Parameters:
    ///   - p: Pbuf chain containing the transport data.
    ///   - proto: IP protocol number (e.g. 6 for TCP, 17 for UDP).
    ///   - protoLen: Length of the transport segment.
    ///   - src: Source IPv4 address (network byte order).
    ///   - dest: Destination IPv4 address (network byte order).
    /// - Returns: Checksum ready for the protocol header.
    @inlinable
    public static func checksumPseudoIPv4(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        src: IPv4Address,
        dest: IPv4Address
    ) -> UInt16 {
        var acc: UInt32 = 0
        let srcAddr = src.addr
        acc &+= srcAddr & 0xFFFF
        acc &+= (srcAddr >> 16) & 0xFFFF
        let dstAddr = dest.addr
        acc &+= dstAddr & 0xFFFF
        acc &+= (dstAddr >> 16) & 0xFFFF
        acc = foldUInt32(acc)
        acc = foldUInt32(acc)
        return pseudoBase(p, proto: proto, protoLen: protoLen, initialAcc: acc)
    }

    /// Partial checksum with IPv4 pseudo-header (checksums only `chksumLen` bytes).
    @inlinable
    public static func checksumPseudoPartialIPv4(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        chksumLen: UInt16,
        src: IPv4Address,
        dest: IPv4Address
    ) -> UInt16 {
        var acc: UInt32 = 0
        let srcAddr = src.addr
        acc &+= srcAddr & 0xFFFF
        acc &+= (srcAddr >> 16) & 0xFFFF
        let dstAddr = dest.addr
        acc &+= dstAddr & 0xFFFF
        acc &+= (dstAddr >> 16) & 0xFFFF
        acc = foldUInt32(acc)
        acc = foldUInt32(acc)
        return pseudoPartialBase(p, proto: proto, protoLen: protoLen, chksumLen: chksumLen, initialAcc: acc)
    }

    // MARK: - IPv6 Pseudo-header Checksum

    /// Calculate TCP/UDP checksum with IPv6 pseudo-header.
    ///
    /// - Parameters:
    ///   - p: Pbuf chain containing the transport data.
    ///   - proto: Next header / protocol number.
    ///   - protoLen: Length of the transport segment.
    ///   - src: Source IPv6 address (network byte order).
    ///   - dest: Destination IPv6 address (network byte order).
    /// - Returns: Checksum ready for the protocol header.
    @inlinable
    public static func checksumPseudoIPv6(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        src: IPv6Address,
        dest: IPv6Address
    ) -> UInt16 {
        var acc: UInt32 = 0
        let srcParts = [src.addr.0, src.addr.1, src.addr.2, src.addr.3]
        let dstParts = [dest.addr.0, dest.addr.1, dest.addr.2, dest.addr.3]

        for i in 0..<4 {
            acc &+= srcParts[i] & 0xFFFF
            acc &+= (srcParts[i] >> 16) & 0xFFFF
            acc &+= dstParts[i] & 0xFFFF
            acc &+= (dstParts[i] >> 16) & 0xFFFF
        }
        acc = foldUInt32(acc)
        acc = foldUInt32(acc)
        return pseudoBase(p, proto: proto, protoLen: protoLen, initialAcc: acc)
    }

    /// Partial checksum with IPv6 pseudo-header.
    @inlinable
    public static func checksumPseudoPartialIPv6(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        chksumLen: UInt16,
        src: IPv6Address,
        dest: IPv6Address
    ) -> UInt16 {
        var acc: UInt32 = 0
        let srcParts = [src.addr.0, src.addr.1, src.addr.2, src.addr.3]
        let dstParts = [dest.addr.0, dest.addr.1, dest.addr.2, dest.addr.3]

        for i in 0..<4 {
            acc &+= srcParts[i] & 0xFFFF
            acc &+= (srcParts[i] >> 16) & 0xFFFF
            acc &+= dstParts[i] & 0xFFFF
            acc &+= (dstParts[i] >> 16) & 0xFFFF
        }
        acc = foldUInt32(acc)
        acc = foldUInt32(acc)
        return pseudoPartialBase(p, proto: proto, protoLen: protoLen, chksumLen: chksumLen, initialAcc: acc)
    }

    // MARK: - Generic IP (v4/v6) Pseudo-header Checksum

    /// Calculate TCP/UDP checksum with either IPv4 or IPv6 pseudo-header,
    /// dispatching based on the `IPAddress` type.
    ///
    /// - Parameters:
    ///   - p: Pbuf chain.
    ///   - proto: Protocol number.
    ///   - protoLen: Transport segment length.
    ///   - src: Source IP address.
    ///   - dest: Destination IP address.
    /// - Returns: Checksum for the protocol header.
    @inlinable
    public static func checksumPseudo(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        src: IPAddress,
        dest: IPAddress
    ) -> UInt16 {
        switch dest {
        case .v6(let dstV6):
            guard case .v6(let srcV6) = src else {
                // Mismatched address families -- should not happen.
                return 0
            }
            return checksumPseudoIPv6(p, proto: proto, protoLen: protoLen, src: srcV6, dest: dstV6)
        case .v4(let dstV4):
            guard case .v4(let srcV4) = src else {
                return 0
            }
            return checksumPseudoIPv4(p, proto: proto, protoLen: protoLen, src: srcV4, dest: dstV4)
        case .any:
            // "Any" address cannot compute a pseudo-header checksum.
            return 0
        }
    }

    /// Partial checksum with either IPv4 or IPv6 pseudo-header.
    @inlinable
    public static func checksumPseudoPartial(
        _ p: Pbuf,
        proto: UInt8,
        protoLen: UInt16,
        chksumLen: UInt16,
        src: IPAddress,
        dest: IPAddress
    ) -> UInt16 {
        switch dest {
        case .v6(let dstV6):
            guard case .v6(let srcV6) = src else { return 0 }
            return checksumPseudoPartialIPv6(
                p, proto: proto, protoLen: protoLen, chksumLen: chksumLen, src: srcV6, dest: dstV6
            )
        case .v4(let dstV4):
            guard case .v4(let srcV4) = src else { return 0 }
            return checksumPseudoPartialIPv4(
                p, proto: proto, protoLen: protoLen, chksumLen: chksumLen, src: srcV4, dest: dstV4
            )
        case .any:
            return 0
        }
    }

    // MARK: - Checksum Copy

    /// Copy data from `src` to `dst` and return the raw checksum of the copied data.
    ///
    /// - Parameters:
    ///   - dst: Destination buffer.
    ///   - src: Source buffer.
    ///   - len: Number of bytes to copy.
    /// - Returns: Raw (non-inverted) checksum of the data.
    @inlinable
    public static func checksumCopy(
        dst: UnsafeMutableRawPointer,
        src: UnsafeRawPointer,
        len: UInt16
    ) -> UInt16 {
        memcpy(dst, src, Int(len))
        return rawChecksum(dst, len: Int(len))
    }
}
