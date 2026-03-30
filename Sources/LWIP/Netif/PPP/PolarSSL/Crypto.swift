//
//  Crypto.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Byte Manipulation Helpers

/// Read a little-endian UInt32 from a byte buffer at the given offset.
@inline(__always)
private func getUInt32LE(_ b: [UInt8], _ i: Int) -> UInt32 {
    return UInt32(b[i])
        | (UInt32(b[i + 1]) << 8)
        | (UInt32(b[i + 2]) << 16)
        | (UInt32(b[i + 3]) << 24)
}

/// Write a little-endian UInt32 to a byte buffer at the given offset.
@inline(__always)
private func putUInt32LE(_ n: UInt32, _ b: inout [UInt8], _ i: Int) {
    b[i]     = UInt8(truncatingIfNeeded: n)
    b[i + 1] = UInt8(truncatingIfNeeded: n >> 8)
    b[i + 2] = UInt8(truncatingIfNeeded: n >> 16)
    b[i + 3] = UInt8(truncatingIfNeeded: n >> 24)
}

/// Read a big-endian UInt32 from a byte buffer at the given offset.
@inline(__always)
private func getUInt32BE(_ b: [UInt8], _ i: Int) -> UInt32 {
    return (UInt32(b[i]) << 24)
        | (UInt32(b[i + 1]) << 16)
        | (UInt32(b[i + 2]) << 8)
        | UInt32(b[i + 3])
}

/// Write a big-endian UInt32 to a byte buffer at the given offset.
@inline(__always)
private func putUInt32BE(_ n: UInt32, _ b: inout [UInt8], _ i: Int) {
    b[i]     = UInt8(truncatingIfNeeded: n >> 24)
    b[i + 1] = UInt8(truncatingIfNeeded: n >> 16)
    b[i + 2] = UInt8(truncatingIfNeeded: n >> 8)
    b[i + 3] = UInt8(truncatingIfNeeded: n)
}

/// Left-rotate a 32-bit value.
@inline(__always)
private func rotateLeft(_ x: UInt32, _ n: UInt32) -> UInt32 {
    return (x << n) | (x >> (32 - n))
}

// MARK: - MD5 (RFC 1321)

/// MD5 hash context, implementing the RFC 1321 algorithm.
public struct MD5Context {
    public var total: (UInt32, UInt32) = (0, 0)
    public var state: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
    public var buffer = [UInt8](repeating: 0, count: 64)

    public init() {
        starts()
    }

    /// Initialize/reset the MD5 context.
    public mutating func starts() {
        total = (0, 0)
        state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    }

    /// Process a single 64-byte block.
    private mutating func process(_ data: [UInt8], offset: Int = 0) {
        var X = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            X[i] = getUInt32LE(data, offset + i * 4)
        }

        var A = state.0
        var B = state.1
        var C = state.2
        var D = state.3

        // Round 1: F(x,y,z) = z ^ (x & (y ^ z))
        func F1(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { z ^ (x & (y ^ z)) }
        func P1(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ k: Int, _ s: UInt32, _ t: UInt32) {
            a = a &+ F1(b, c, d) &+ X[k] &+ t
            a = rotateLeft(a, s) &+ b
        }

        P1(&A, B, C, D,  0,  7, 0xD76AA478); P1(&D, A, B, C,  1, 12, 0xE8C7B756)
        P1(&C, D, A, B,  2, 17, 0x242070DB); P1(&B, C, D, A,  3, 22, 0xC1BDCEEE)
        P1(&A, B, C, D,  4,  7, 0xF57C0FAF); P1(&D, A, B, C,  5, 12, 0x4787C62A)
        P1(&C, D, A, B,  6, 17, 0xA8304613); P1(&B, C, D, A,  7, 22, 0xFD469501)
        P1(&A, B, C, D,  8,  7, 0x698098D8); P1(&D, A, B, C,  9, 12, 0x8B44F7AF)
        P1(&C, D, A, B, 10, 17, 0xFFFF5BB1); P1(&B, C, D, A, 11, 22, 0x895CD7BE)
        P1(&A, B, C, D, 12,  7, 0x6B901122); P1(&D, A, B, C, 13, 12, 0xFD987193)
        P1(&C, D, A, B, 14, 17, 0xA679438E); P1(&B, C, D, A, 15, 22, 0x49B40821)

        // Round 2: F(x,y,z) = y ^ (z & (x ^ y))
        func F2(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { y ^ (z & (x ^ y)) }
        func P2(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ k: Int, _ s: UInt32, _ t: UInt32) {
            a = a &+ F2(b, c, d) &+ X[k] &+ t
            a = rotateLeft(a, s) &+ b
        }

        P2(&A, B, C, D,  1,  5, 0xF61E2562); P2(&D, A, B, C,  6,  9, 0xC040B340)
        P2(&C, D, A, B, 11, 14, 0x265E5A51); P2(&B, C, D, A,  0, 20, 0xE9B6C7AA)
        P2(&A, B, C, D,  5,  5, 0xD62F105D); P2(&D, A, B, C, 10,  9, 0x02441453)
        P2(&C, D, A, B, 15, 14, 0xD8A1E681); P2(&B, C, D, A,  4, 20, 0xE7D3FBC8)
        P2(&A, B, C, D,  9,  5, 0x21E1CDE6); P2(&D, A, B, C, 14,  9, 0xC33707D6)
        P2(&C, D, A, B,  3, 14, 0xF4D50D87); P2(&B, C, D, A,  8, 20, 0x455A14ED)
        P2(&A, B, C, D, 13,  5, 0xA9E3E905); P2(&D, A, B, C,  2,  9, 0xFCEFA3F8)
        P2(&C, D, A, B,  7, 14, 0x676F02D9); P2(&B, C, D, A, 12, 20, 0x8D2A4C8A)

        // Round 3: F(x,y,z) = x ^ y ^ z
        func F3(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }
        func P3(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ k: Int, _ s: UInt32, _ t: UInt32) {
            a = a &+ F3(b, c, d) &+ X[k] &+ t
            a = rotateLeft(a, s) &+ b
        }

        P3(&A, B, C, D,  5,  4, 0xFFFA3942); P3(&D, A, B, C,  8, 11, 0x8771F681)
        P3(&C, D, A, B, 11, 16, 0x6D9D6122); P3(&B, C, D, A, 14, 23, 0xFDE5380C)
        P3(&A, B, C, D,  1,  4, 0xA4BEEA44); P3(&D, A, B, C,  4, 11, 0x4BDECFA9)
        P3(&C, D, A, B,  7, 16, 0xF6BB4B60); P3(&B, C, D, A, 10, 23, 0xBEBFBC70)
        P3(&A, B, C, D, 13,  4, 0x289B7EC6); P3(&D, A, B, C,  0, 11, 0xEAA127FA)
        P3(&C, D, A, B,  3, 16, 0xD4EF3085); P3(&B, C, D, A,  6, 23, 0x04881D05)
        P3(&A, B, C, D,  9,  4, 0xD9D4D039); P3(&D, A, B, C, 12, 11, 0xE6DB99E5)
        P3(&C, D, A, B, 15, 16, 0x1FA27CF8); P3(&B, C, D, A,  2, 23, 0xC4AC5665)

        // Round 4: F(x,y,z) = y ^ (x | ~z)
        func F4(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { y ^ (x | ~z) }
        func P4(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ k: Int, _ s: UInt32, _ t: UInt32) {
            a = a &+ F4(b, c, d) &+ X[k] &+ t
            a = rotateLeft(a, s) &+ b
        }

        P4(&A, B, C, D,  0,  6, 0xF4292244); P4(&D, A, B, C,  7, 10, 0x432AFF97)
        P4(&C, D, A, B, 14, 15, 0xAB9423A7); P4(&B, C, D, A,  5, 21, 0xFC93A039)
        P4(&A, B, C, D, 12,  6, 0x655B59C3); P4(&D, A, B, C,  3, 10, 0x8F0CCC92)
        P4(&C, D, A, B, 10, 15, 0xFFEFF47D); P4(&B, C, D, A,  1, 21, 0x85845DD1)
        P4(&A, B, C, D,  8,  6, 0x6FA87E4F); P4(&D, A, B, C, 15, 10, 0xFE2CE6E0)
        P4(&C, D, A, B,  6, 15, 0xA3014314); P4(&B, C, D, A, 13, 21, 0x4E0811A1)
        P4(&A, B, C, D,  4,  6, 0xF7537E82); P4(&D, A, B, C, 11, 10, 0xBD3AF235)
        P4(&C, D, A, B,  2, 15, 0x2AD7D2BB); P4(&B, C, D, A,  9, 21, 0xEB86D391)

        state.0 = state.0 &+ A
        state.1 = state.1 &+ B
        state.2 = state.2 &+ C
        state.3 = state.3 &+ D
    }

    /// Update the hash with additional input data.
    public mutating func update(_ input: [UInt8]) {
        var ilen = input.count
        if ilen <= 0 { return }

        var inputOffset = 0
        var left = Int(total.0 & 0x3F)
        let fill = 64 - left

        total.0 = total.0 &+ UInt32(ilen)
        if total.0 < UInt32(ilen) {
            total.1 = total.1 &+ 1
        }

        if left > 0 && ilen >= fill {
            buffer.replaceSubrange(left..<left + fill, with: input[inputOffset..<inputOffset + fill])
            process(buffer)
            inputOffset += fill
            ilen -= fill
            left = 0
        }

        while ilen >= 64 {
            process(input, offset: inputOffset)
            inputOffset += 64
            ilen -= 64
        }

        if ilen > 0 {
            buffer.replaceSubrange(left..<left + ilen, with: input[inputOffset..<inputOffset + ilen])
        }
    }

    /// Finalize the hash and produce the 16-byte digest.
    public mutating func finish() -> [UInt8] {
        let high = (total.0 >> 29) | (total.1 << 3)
        let low = total.0 << 3

        var msglen = [UInt8](repeating: 0, count: 8)
        putUInt32LE(low, &msglen, 0)
        putUInt32LE(high, &msglen, 4)

        let last = Int(total.0 & 0x3F)
        let padn = (last < 56) ? (56 - last) : (120 - last)

        var padding = [UInt8](repeating: 0, count: padn)
        padding[0] = 0x80
        update(padding)
        update(msglen)

        var output = [UInt8](repeating: 0, count: 16)
        putUInt32LE(state.0, &output, 0)
        putUInt32LE(state.1, &output, 4)
        putUInt32LE(state.2, &output, 8)
        putUInt32LE(state.3, &output, 12)
        return output
    }

    /// Compute MD5 hash of input buffer in one shot.
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        var ctx = MD5Context()
        ctx.starts()
        ctx.update(input)
        return ctx.finish()
    }
}

// MARK: - MD4 (RFC 1186/1320)

/// MD4 hash context, implementing the RFC 1186/1320 algorithm.
/// Used by MS-CHAPv2 authentication.
public struct MD4Context {
    public var total: (UInt32, UInt32) = (0, 0)
    public var state: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
    public var buffer = [UInt8](repeating: 0, count: 64)

    public init() {
        starts()
    }

    /// Initialize/reset the MD4 context.
    public mutating func starts() {
        total = (0, 0)
        state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    }

    /// Process a single 64-byte block.
    private mutating func process(_ data: [UInt8], offset: Int = 0) {
        var X = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            X[i] = getUInt32LE(data, offset + i * 4)
        }

        var A = state.0
        var B = state.1
        var C = state.2
        var D = state.3

        // Round 1: F(x,y,z) = (x & y) | ((~x) & z)
        func F1(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | ((~x) & z) }
        func P1(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
            a = rotateLeft(a &+ F1(b, c, d) &+ x, s)
        }

        P1(&A, B, C, D, X[ 0],  3); P1(&D, A, B, C, X[ 1],  7)
        P1(&C, D, A, B, X[ 2], 11); P1(&B, C, D, A, X[ 3], 19)
        P1(&A, B, C, D, X[ 4],  3); P1(&D, A, B, C, X[ 5],  7)
        P1(&C, D, A, B, X[ 6], 11); P1(&B, C, D, A, X[ 7], 19)
        P1(&A, B, C, D, X[ 8],  3); P1(&D, A, B, C, X[ 9],  7)
        P1(&C, D, A, B, X[10], 11); P1(&B, C, D, A, X[11], 19)
        P1(&A, B, C, D, X[12],  3); P1(&D, A, B, C, X[13],  7)
        P1(&C, D, A, B, X[14], 11); P1(&B, C, D, A, X[15], 19)

        // Round 2: F(x,y,z) = (x & y) | (x & z) | (y & z)
        func F2(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }
        func P2(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
            a = rotateLeft(a &+ F2(b, c, d) &+ x &+ 0x5A827999, s)
        }

        P2(&A, B, C, D, X[ 0],  3); P2(&D, A, B, C, X[ 4],  5)
        P2(&C, D, A, B, X[ 8],  9); P2(&B, C, D, A, X[12], 13)
        P2(&A, B, C, D, X[ 1],  3); P2(&D, A, B, C, X[ 5],  5)
        P2(&C, D, A, B, X[ 9],  9); P2(&B, C, D, A, X[13], 13)
        P2(&A, B, C, D, X[ 2],  3); P2(&D, A, B, C, X[ 6],  5)
        P2(&C, D, A, B, X[10],  9); P2(&B, C, D, A, X[14], 13)
        P2(&A, B, C, D, X[ 3],  3); P2(&D, A, B, C, X[ 7],  5)
        P2(&C, D, A, B, X[11],  9); P2(&B, C, D, A, X[15], 13)

        // Round 3: F(x,y,z) = x ^ y ^ z
        func F3(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }
        func P3(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
            a = rotateLeft(a &+ F3(b, c, d) &+ x &+ 0x6ED9EBA1, s)
        }

        P3(&A, B, C, D, X[ 0],  3); P3(&D, A, B, C, X[ 8],  9)
        P3(&C, D, A, B, X[ 4], 11); P3(&B, C, D, A, X[12], 15)
        P3(&A, B, C, D, X[ 2],  3); P3(&D, A, B, C, X[10],  9)
        P3(&C, D, A, B, X[ 6], 11); P3(&B, C, D, A, X[14], 15)
        P3(&A, B, C, D, X[ 1],  3); P3(&D, A, B, C, X[ 9],  9)
        P3(&C, D, A, B, X[ 5], 11); P3(&B, C, D, A, X[13], 15)
        P3(&A, B, C, D, X[ 3],  3); P3(&D, A, B, C, X[11],  9)
        P3(&C, D, A, B, X[ 7], 11); P3(&B, C, D, A, X[15], 15)

        state.0 = state.0 &+ A
        state.1 = state.1 &+ B
        state.2 = state.2 &+ C
        state.3 = state.3 &+ D
    }

    /// Update the hash with additional input data.
    public mutating func update(_ input: [UInt8]) {
        var ilen = input.count
        if ilen <= 0 { return }

        var inputOffset = 0
        var left = Int(total.0 & 0x3F)
        let fill = 64 - left

        total.0 = total.0 &+ UInt32(ilen)
        if total.0 < UInt32(ilen) {
            total.1 = total.1 &+ 1
        }

        if left > 0 && ilen >= fill {
            buffer.replaceSubrange(left..<left + fill, with: input[inputOffset..<inputOffset + fill])
            process(buffer)
            inputOffset += fill
            ilen -= fill
            left = 0
        }

        while ilen >= 64 {
            process(input, offset: inputOffset)
            inputOffset += 64
            ilen -= 64
        }

        if ilen > 0 {
            buffer.replaceSubrange(left..<left + ilen, with: input[inputOffset..<inputOffset + ilen])
        }
    }

    /// Finalize the hash and produce the 16-byte digest.
    public mutating func finish() -> [UInt8] {
        let high = (total.0 >> 29) | (total.1 << 3)
        let low = total.0 << 3

        var msglen = [UInt8](repeating: 0, count: 8)
        putUInt32LE(low, &msglen, 0)
        putUInt32LE(high, &msglen, 4)

        let last = Int(total.0 & 0x3F)
        let padn = (last < 56) ? (56 - last) : (120 - last)

        var padding = [UInt8](repeating: 0, count: padn)
        padding[0] = 0x80
        update(padding)
        update(msglen)

        var output = [UInt8](repeating: 0, count: 16)
        putUInt32LE(state.0, &output, 0)
        putUInt32LE(state.1, &output, 4)
        putUInt32LE(state.2, &output, 8)
        putUInt32LE(state.3, &output, 12)
        return output
    }

    /// Compute MD4 hash of input buffer in one shot.
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        var ctx = MD4Context()
        ctx.starts()
        ctx.update(input)
        return ctx.finish()
    }
}

// MARK: - SHA-1 (FIPS 180-1)

/// SHA-1 hash context, implementing the FIPS 180-1 algorithm.
/// Used by EAP-TLS and MPPE key derivation.
public struct SHA1Context {
    public var total: (UInt32, UInt32) = (0, 0)
    public var state: (UInt32, UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0, 0)
    public var buffer = [UInt8](repeating: 0, count: 64)

    public init() {
        starts()
    }

    /// Initialize/reset the SHA-1 context.
    public mutating func starts() {
        total = (0, 0)
        state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    }

    /// Process a single 64-byte block.
    private mutating func process(_ data: [UInt8], offset: Int = 0) {
        var W = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            W[i] = getUInt32BE(data, offset + i * 4)
        }

        var A = state.0
        var B = state.1
        var C = state.2
        var D = state.3
        var E = state.4

        // Message schedule expansion (in-place, circular buffer of 16 words)
        func R(_ t: Int) -> UInt32 {
            let temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ W[(t - 14) & 0x0F] ^ W[t & 0x0F]
            W[t & 0x0F] = rotateLeft(temp, 1)
            return W[t & 0x0F]
        }

        // Rounds 0-19: F(x,y,z) = z ^ (x & (y ^ z)), K = 0x5A827999
        func P0(_ a: inout UInt32, _ b: inout UInt32, _ c: UInt32, _ d: UInt32, _ e: inout UInt32, _ x: UInt32) {
            e = e &+ rotateLeft(a, 5) &+ (d ^ (b & (c ^ d))) &+ 0x5A827999 &+ x
            b = rotateLeft(b, 30)
        }

        P0(&A, &B, C, D, &E, W[0]);  P0(&E, &A, B, C, &D, W[1])
        P0(&D, &E, A, B, &C, W[2]);  P0(&C, &D, E, A, &B, W[3])
        P0(&B, &C, D, E, &A, W[4]);  P0(&A, &B, C, D, &E, W[5])
        P0(&E, &A, B, C, &D, W[6]);  P0(&D, &E, A, B, &C, W[7])
        P0(&C, &D, E, A, &B, W[8]);  P0(&B, &C, D, E, &A, W[9])
        P0(&A, &B, C, D, &E, W[10]); P0(&E, &A, B, C, &D, W[11])
        P0(&D, &E, A, B, &C, W[12]); P0(&C, &D, E, A, &B, W[13])
        P0(&B, &C, D, E, &A, W[14]); P0(&A, &B, C, D, &E, W[15])
        P0(&E, &A, B, C, &D, R(16)); P0(&D, &E, A, B, &C, R(17))
        P0(&C, &D, E, A, &B, R(18)); P0(&B, &C, D, E, &A, R(19))

        // Rounds 20-39: F(x,y,z) = x ^ y ^ z, K = 0x6ED9EBA1
        func P1(_ a: inout UInt32, _ b: inout UInt32, _ c: UInt32, _ d: UInt32, _ e: inout UInt32, _ x: UInt32) {
            e = e &+ rotateLeft(a, 5) &+ (b ^ c ^ d) &+ 0x6ED9EBA1 &+ x
            b = rotateLeft(b, 30)
        }

        P1(&A, &B, C, D, &E, R(20)); P1(&E, &A, B, C, &D, R(21))
        P1(&D, &E, A, B, &C, R(22)); P1(&C, &D, E, A, &B, R(23))
        P1(&B, &C, D, E, &A, R(24)); P1(&A, &B, C, D, &E, R(25))
        P1(&E, &A, B, C, &D, R(26)); P1(&D, &E, A, B, &C, R(27))
        P1(&C, &D, E, A, &B, R(28)); P1(&B, &C, D, E, &A, R(29))
        P1(&A, &B, C, D, &E, R(30)); P1(&E, &A, B, C, &D, R(31))
        P1(&D, &E, A, B, &C, R(32)); P1(&C, &D, E, A, &B, R(33))
        P1(&B, &C, D, E, &A, R(34)); P1(&A, &B, C, D, &E, R(35))
        P1(&E, &A, B, C, &D, R(36)); P1(&D, &E, A, B, &C, R(37))
        P1(&C, &D, E, A, &B, R(38)); P1(&B, &C, D, E, &A, R(39))

        // Rounds 40-59: F(x,y,z) = (x & y) | (z & (x | y)), K = 0x8F1BBCDC
        func P2(_ a: inout UInt32, _ b: inout UInt32, _ c: UInt32, _ d: UInt32, _ e: inout UInt32, _ x: UInt32) {
            e = e &+ rotateLeft(a, 5) &+ ((b & c) | (d & (b | c))) &+ 0x8F1BBCDC &+ x
            b = rotateLeft(b, 30)
        }

        P2(&A, &B, C, D, &E, R(40)); P2(&E, &A, B, C, &D, R(41))
        P2(&D, &E, A, B, &C, R(42)); P2(&C, &D, E, A, &B, R(43))
        P2(&B, &C, D, E, &A, R(44)); P2(&A, &B, C, D, &E, R(45))
        P2(&E, &A, B, C, &D, R(46)); P2(&D, &E, A, B, &C, R(47))
        P2(&C, &D, E, A, &B, R(48)); P2(&B, &C, D, E, &A, R(49))
        P2(&A, &B, C, D, &E, R(50)); P2(&E, &A, B, C, &D, R(51))
        P2(&D, &E, A, B, &C, R(52)); P2(&C, &D, E, A, &B, R(53))
        P2(&B, &C, D, E, &A, R(54)); P2(&A, &B, C, D, &E, R(55))
        P2(&E, &A, B, C, &D, R(56)); P2(&D, &E, A, B, &C, R(57))
        P2(&C, &D, E, A, &B, R(58)); P2(&B, &C, D, E, &A, R(59))

        // Rounds 60-79: F(x,y,z) = x ^ y ^ z, K = 0xCA62C1D6
        func P3(_ a: inout UInt32, _ b: inout UInt32, _ c: UInt32, _ d: UInt32, _ e: inout UInt32, _ x: UInt32) {
            e = e &+ rotateLeft(a, 5) &+ (b ^ c ^ d) &+ 0xCA62C1D6 &+ x
            b = rotateLeft(b, 30)
        }

        P3(&A, &B, C, D, &E, R(60)); P3(&E, &A, B, C, &D, R(61))
        P3(&D, &E, A, B, &C, R(62)); P3(&C, &D, E, A, &B, R(63))
        P3(&B, &C, D, E, &A, R(64)); P3(&A, &B, C, D, &E, R(65))
        P3(&E, &A, B, C, &D, R(66)); P3(&D, &E, A, B, &C, R(67))
        P3(&C, &D, E, A, &B, R(68)); P3(&B, &C, D, E, &A, R(69))
        P3(&A, &B, C, D, &E, R(70)); P3(&E, &A, B, C, &D, R(71))
        P3(&D, &E, A, B, &C, R(72)); P3(&C, &D, E, A, &B, R(73))
        P3(&B, &C, D, E, &A, R(74)); P3(&A, &B, C, D, &E, R(75))
        P3(&E, &A, B, C, &D, R(76)); P3(&D, &E, A, B, &C, R(77))
        P3(&C, &D, E, A, &B, R(78)); P3(&B, &C, D, E, &A, R(79))

        state.0 = state.0 &+ A
        state.1 = state.1 &+ B
        state.2 = state.2 &+ C
        state.3 = state.3 &+ D
        state.4 = state.4 &+ E
    }

    /// Update the hash with additional input data.
    public mutating func update(_ input: [UInt8]) {
        var ilen = input.count
        if ilen <= 0 { return }

        var inputOffset = 0
        var left = Int(total.0 & 0x3F)
        let fill = 64 - left

        total.0 = total.0 &+ UInt32(ilen)
        if total.0 < UInt32(ilen) {
            total.1 = total.1 &+ 1
        }

        if left > 0 && ilen >= fill {
            buffer.replaceSubrange(left..<left + fill, with: input[inputOffset..<inputOffset + fill])
            process(buffer)
            inputOffset += fill
            ilen -= fill
            left = 0
        }

        while ilen >= 64 {
            process(input, offset: inputOffset)
            inputOffset += 64
            ilen -= 64
        }

        if ilen > 0 {
            buffer.replaceSubrange(left..<left + ilen, with: input[inputOffset..<inputOffset + ilen])
        }
    }

    /// Finalize the hash and produce the 20-byte digest.
    public mutating func finish() -> [UInt8] {
        let high = (total.0 >> 29) | (total.1 << 3)
        let low = total.0 << 3

        var msglen = [UInt8](repeating: 0, count: 8)
        putUInt32BE(high, &msglen, 0)
        putUInt32BE(low, &msglen, 4)

        let last = Int(total.0 & 0x3F)
        let padn = (last < 56) ? (56 - last) : (120 - last)

        var padding = [UInt8](repeating: 0, count: padn)
        padding[0] = 0x80
        update(padding)
        update(msglen)

        var output = [UInt8](repeating: 0, count: 20)
        putUInt32BE(state.0, &output, 0)
        putUInt32BE(state.1, &output, 4)
        putUInt32BE(state.2, &output, 8)
        putUInt32BE(state.3, &output, 12)
        putUInt32BE(state.4, &output, 16)
        return output
    }

    /// Compute SHA-1 hash of input buffer in one shot.
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        var ctx = SHA1Context()
        ctx.starts()
        ctx.update(input)
        return ctx.finish()
    }
}

// MARK: - DES (FIPS 46-3)

/// DES block cipher context.
/// Used by MS-CHAP for challenge-response computation.
public struct DESContext {

    /// 32 subkeys used during encryption/decryption.
    public var sk = [UInt32](repeating: 0, count: 32)

    public init() {}

    // MARK: - S-boxes

    private static let SB1: [UInt32] = [
        0x01010400, 0x00000000, 0x00010000, 0x01010404,
        0x01010004, 0x00010404, 0x00000004, 0x00010000,
        0x00000400, 0x01010400, 0x01010404, 0x00000400,
        0x01000404, 0x01010004, 0x01000000, 0x00000004,
        0x00000404, 0x01000400, 0x01000400, 0x00010400,
        0x00010400, 0x01010000, 0x01010000, 0x01000404,
        0x00010004, 0x01000004, 0x01000004, 0x00010004,
        0x00000000, 0x00000404, 0x00010404, 0x01000000,
        0x00010000, 0x01010404, 0x00000004, 0x01010000,
        0x01010400, 0x01000000, 0x01000000, 0x00000400,
        0x01010004, 0x00010000, 0x00010400, 0x01000004,
        0x00000400, 0x00000004, 0x01000404, 0x00010404,
        0x01010404, 0x00010004, 0x01010000, 0x01000404,
        0x01000004, 0x00000404, 0x00010404, 0x01010400,
        0x00000404, 0x01000400, 0x01000400, 0x00000000,
        0x00010004, 0x00010400, 0x00000000, 0x01010004
    ]

    private static let SB2: [UInt32] = [
        0x80108020, 0x80008000, 0x00008000, 0x00108020,
        0x00100000, 0x00000020, 0x80100020, 0x80008020,
        0x80000020, 0x80108020, 0x80108000, 0x80000000,
        0x80008000, 0x00100000, 0x00000020, 0x80100020,
        0x00108000, 0x00100020, 0x80008020, 0x00000000,
        0x80000000, 0x00008000, 0x00108020, 0x80100000,
        0x00100020, 0x80000020, 0x00000000, 0x00108000,
        0x00008020, 0x80108000, 0x80100000, 0x00008020,
        0x00000000, 0x00108020, 0x80100020, 0x00100000,
        0x80008020, 0x80100000, 0x80108000, 0x00008000,
        0x80100000, 0x80008000, 0x00000020, 0x80108020,
        0x00108020, 0x00000020, 0x00008000, 0x80000000,
        0x00008020, 0x80108000, 0x00100000, 0x80000020,
        0x00100020, 0x80008020, 0x80000020, 0x00100020,
        0x00108000, 0x00000000, 0x80008000, 0x00008020,
        0x80000000, 0x80100020, 0x80108020, 0x00108000
    ]

    private static let SB3: [UInt32] = [
        0x00000208, 0x08020200, 0x00000000, 0x08020008,
        0x08000200, 0x00000000, 0x00020208, 0x08000200,
        0x00020008, 0x08000008, 0x08000008, 0x00020000,
        0x08020208, 0x00020008, 0x08020000, 0x00000208,
        0x08000000, 0x00000008, 0x08020200, 0x00000200,
        0x00020200, 0x08020000, 0x08020008, 0x00020208,
        0x08000208, 0x00020200, 0x00020000, 0x08000208,
        0x00000008, 0x08020208, 0x00000200, 0x08000000,
        0x08020200, 0x08000000, 0x00020008, 0x00000208,
        0x00020000, 0x08020200, 0x08000200, 0x00000000,
        0x00000200, 0x00020008, 0x08020208, 0x08000200,
        0x08000008, 0x00000200, 0x00000000, 0x08020008,
        0x08000208, 0x00020000, 0x08000000, 0x08020208,
        0x00000008, 0x00020208, 0x00020200, 0x08000008,
        0x08020000, 0x08000208, 0x00000208, 0x08020000,
        0x00020208, 0x00000008, 0x08020008, 0x00020200
    ]

    private static let SB4: [UInt32] = [
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802080, 0x00800081, 0x00800001, 0x00002001,
        0x00000000, 0x00802000, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00800080, 0x00800001,
        0x00000001, 0x00002000, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002001, 0x00002080,
        0x00800081, 0x00000001, 0x00002080, 0x00800080,
        0x00002000, 0x00802080, 0x00802081, 0x00000081,
        0x00800080, 0x00800001, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00000000, 0x00802000,
        0x00002080, 0x00800080, 0x00800081, 0x00000001,
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802081, 0x00000081, 0x00000001, 0x00002000,
        0x00800001, 0x00002001, 0x00802080, 0x00800081,
        0x00002001, 0x00002080, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002000, 0x00802080
    ]

    private static let SB5: [UInt32] = [
        0x00000100, 0x02080100, 0x02080000, 0x42000100,
        0x00080000, 0x00000100, 0x40000000, 0x02080000,
        0x40080100, 0x00080000, 0x02000100, 0x40080100,
        0x42000100, 0x42080000, 0x00080100, 0x40000000,
        0x02000000, 0x40080000, 0x40080000, 0x00000000,
        0x40000100, 0x42080100, 0x42080100, 0x02000100,
        0x42080000, 0x40000100, 0x00000000, 0x42000000,
        0x02080100, 0x02000000, 0x42000000, 0x00080100,
        0x00080000, 0x42000100, 0x00000100, 0x02000000,
        0x40000000, 0x02080000, 0x42000100, 0x40080100,
        0x02000100, 0x40000000, 0x42080000, 0x02080100,
        0x40080100, 0x00000100, 0x02000000, 0x42080000,
        0x42080100, 0x00080100, 0x42000000, 0x42080100,
        0x02080000, 0x00000000, 0x40080000, 0x42000000,
        0x00080100, 0x02000100, 0x40000100, 0x00080000,
        0x00000000, 0x40080000, 0x02080100, 0x40000100
    ]

    private static let SB6: [UInt32] = [
        0x20000010, 0x20400000, 0x00004000, 0x20404010,
        0x20400000, 0x00000010, 0x20404010, 0x00400000,
        0x20004000, 0x00404010, 0x00400000, 0x20000010,
        0x00400010, 0x20004000, 0x20000000, 0x00004010,
        0x00000000, 0x00400010, 0x20004010, 0x00004000,
        0x00404000, 0x20004010, 0x00000010, 0x20400010,
        0x20400010, 0x00000000, 0x00404010, 0x20404000,
        0x00004010, 0x00404000, 0x20404000, 0x20000000,
        0x20004000, 0x00000010, 0x20400010, 0x00404000,
        0x20404010, 0x00400000, 0x00004010, 0x20000010,
        0x00400000, 0x20004000, 0x20000000, 0x00004010,
        0x20000010, 0x20404010, 0x00404000, 0x20400000,
        0x00404010, 0x20404000, 0x00000000, 0x20400010,
        0x00000010, 0x00004000, 0x20400000, 0x00404010,
        0x00004000, 0x00400010, 0x20004010, 0x00000000,
        0x20404000, 0x20000000, 0x00400010, 0x20004010
    ]

    private static let SB7: [UInt32] = [
        0x00200000, 0x04200002, 0x04000802, 0x00000000,
        0x00000800, 0x04000802, 0x00200802, 0x04200800,
        0x04200802, 0x00200000, 0x00000000, 0x04000002,
        0x00000002, 0x04000000, 0x04200002, 0x00000802,
        0x04000800, 0x00200802, 0x00200002, 0x04000800,
        0x04000002, 0x04200000, 0x04200800, 0x00200002,
        0x04200000, 0x00000800, 0x00000802, 0x04200802,
        0x00200800, 0x00000002, 0x04000000, 0x00200800,
        0x04000000, 0x00200800, 0x00200000, 0x04000802,
        0x04000802, 0x04200002, 0x04200002, 0x00000002,
        0x00200002, 0x04000000, 0x04000800, 0x00200000,
        0x04200800, 0x00000802, 0x00200802, 0x04200800,
        0x00000802, 0x04000002, 0x04200802, 0x04200000,
        0x00200800, 0x00000000, 0x00000002, 0x04200802,
        0x00000000, 0x00200802, 0x04200000, 0x00000800,
        0x04000002, 0x04000800, 0x00000800, 0x00200002
    ]

    private static let SB8: [UInt32] = [
        0x10001040, 0x00001000, 0x00040000, 0x10041040,
        0x10000000, 0x10001040, 0x00000040, 0x10000000,
        0x00040040, 0x10040000, 0x10041040, 0x00041000,
        0x10041000, 0x00041040, 0x00001000, 0x00000040,
        0x10040000, 0x10000040, 0x10001000, 0x00001040,
        0x00041000, 0x00040040, 0x10040040, 0x10041000,
        0x00001040, 0x00000000, 0x00000000, 0x10040040,
        0x10000040, 0x10001000, 0x00041040, 0x00040000,
        0x00041040, 0x00040000, 0x10041000, 0x00001000,
        0x00000040, 0x10040040, 0x00001000, 0x00041040,
        0x10001000, 0x00000040, 0x10000040, 0x10040000,
        0x10040040, 0x10000000, 0x00040000, 0x10001040,
        0x00000000, 0x10041040, 0x00040040, 0x10000040,
        0x10040000, 0x10001000, 0x10001040, 0x00000000,
        0x10041040, 0x00041000, 0x00041000, 0x00001040,
        0x00001040, 0x00040040, 0x10000000, 0x10041000
    ]

    /// PC1: left half bit-swap table.
    private static let LHs: [UInt32] = [
        0x00000000, 0x00000001, 0x00000100, 0x00000101,
        0x00010000, 0x00010001, 0x00010100, 0x00010101,
        0x01000000, 0x01000001, 0x01000100, 0x01000101,
        0x01010000, 0x01010001, 0x01010100, 0x01010101
    ]

    /// PC1: right half bit-swap table.
    private static let RHs: [UInt32] = [
        0x00000000, 0x01000000, 0x00010000, 0x01010000,
        0x00000100, 0x01000100, 0x00010100, 0x01010100,
        0x00000001, 0x01000001, 0x00010001, 0x01010001,
        0x00000101, 0x01000101, 0x00010101, 0x01010101
    ]

    @inline(__always)
    private static func permutedChoice1Left(_ value: UInt32) -> UInt32 {
        let part0 = LHs[Int(value & 0xF)] << 3
        let part1 = LHs[Int((value >> 8) & 0xF)] << 2
        let part2 = LHs[Int((value >> 16) & 0xF)] << 1
        let part3 = LHs[Int((value >> 24) & 0xF)]
        let part4 = LHs[Int((value >> 5) & 0xF)] << 7
        let part5 = LHs[Int((value >> 13) & 0xF)] << 6
        let part6 = LHs[Int((value >> 21) & 0xF)] << 5
        let part7 = LHs[Int((value >> 29) & 0xF)] << 4
        return part0 | part1 | part2 | part3 | part4 | part5 | part6 | part7
    }

    @inline(__always)
    private static func permutedChoice1Right(_ value: UInt32) -> UInt32 {
        let part0 = RHs[Int((value >> 1) & 0xF)] << 3
        let part1 = RHs[Int((value >> 9) & 0xF)] << 2
        let part2 = RHs[Int((value >> 17) & 0xF)] << 1
        let part3 = RHs[Int((value >> 25) & 0xF)]
        let part4 = RHs[Int((value >> 4) & 0xF)] << 7
        let part5 = RHs[Int((value >> 12) & 0xF)] << 6
        let part6 = RHs[Int((value >> 20) & 0xF)] << 5
        let part7 = RHs[Int((value >> 28) & 0xF)] << 4
        return part0 | part1 | part2 | part3 | part4 | part5 | part6 | part7
    }

    @inline(__always)
    private static func roundSubkeyLeft(_ x: UInt32, _ y: UInt32) -> UInt32 {
        let xPart0 = ((x << 4) & 0x24000000)
        let xPart1 = ((x << 28) & 0x10000000)
        let xPart2 = ((x << 14) & 0x08000000)
        let xPart3 = ((x << 18) & 0x02080000)
        let xPart4 = ((x << 6) & 0x01000000)
        let xPart5 = ((x << 9) & 0x00200000)
        let xPart6 = ((x >> 1) & 0x00100000)
        let xPart7 = ((x << 10) & 0x00040000)
        let xPart8 = ((x << 2) & 0x00020000)
        let xPart9 = ((x >> 10) & 0x00010000)
        let yPart0 = ((y >> 13) & 0x00002000)
        let yPart1 = ((y >> 4) & 0x00001000)
        let yPart2 = ((y << 6) & 0x00000800)
        let yPart3 = ((y >> 1) & 0x00000400)
        let yPart4 = ((y >> 14) & 0x00000200)
        let yPart5 = (y & 0x00000100)
        let yPart6 = ((y >> 5) & 0x00000020)
        let yPart7 = ((y >> 10) & 0x00000010)
        let yPart8 = ((y >> 3) & 0x00000008)
        let yPart9 = ((y >> 18) & 0x00000004)
        let yPart10 = ((y >> 26) & 0x00000002)
        let yPart11 = ((y >> 24) & 0x00000001)

        return xPart0 | xPart1 | xPart2 | xPart3 | xPart4 | xPart5 | xPart6 | xPart7 | xPart8 | xPart9 |
            yPart0 | yPart1 | yPart2 | yPart3 | yPart4 | yPart5 | yPart6 | yPart7 | yPart8 | yPart9 | yPart10 | yPart11
    }

    @inline(__always)
    private static func roundSubkeyRight(_ x: UInt32, _ y: UInt32) -> UInt32 {
        let xPart0 = ((x << 15) & 0x20000000)
        let xPart1 = ((x << 17) & 0x10000000)
        let xPart2 = ((x << 10) & 0x08000000)
        let xPart3 = ((x << 22) & 0x04000000)
        let xPart4 = ((x >> 2) & 0x02000000)
        let xPart5 = ((x << 1) & 0x01000000)
        let xPart6 = ((x << 16) & 0x00200000)
        let xPart7 = ((x << 11) & 0x00100000)
        let xPart8 = ((x << 3) & 0x00080000)
        let xPart9 = ((x >> 6) & 0x00040000)
        let xPart10 = ((x << 15) & 0x00020000)
        let xPart11 = ((x >> 4) & 0x00010000)
        let yPart0 = ((y >> 2) & 0x00002000)
        let yPart1 = ((y << 8) & 0x00001000)
        let yPart2 = ((y >> 14) & 0x00000808)
        let yPart3 = ((y >> 9) & 0x00000400)
        let yPart4 = (y & 0x00000200)
        let yPart5 = ((y << 7) & 0x00000100)
        let yPart6 = ((y >> 7) & 0x00000020)
        let yPart7 = ((y >> 3) & 0x00000011)
        let yPart8 = ((y << 2) & 0x00000004)
        let yPart9 = ((y >> 21) & 0x00000002)

        return xPart0 | xPart1 | xPart2 | xPart3 | xPart4 | xPart5 | xPart6 | xPart7 | xPart8 | xPart9 | xPart10 | xPart11 |
            yPart0 | yPart1 | yPart2 | yPart3 | yPart4 | yPart5 | yPart6 | yPart7 | yPart8 | yPart9
    }

    // MARK: - Key Schedule

    /// Internal key setup producing 32 subkeys.
    private static func computeSubkeys(_ key: [UInt8]) -> [UInt32] {
        var SK = [UInt32](repeating: 0, count: 32)
        var X = getUInt32BE(key, 0)
        var Y = getUInt32BE(key, 4)

        // Permuted Choice 1
        var T = ((Y >> 4) ^ X) & 0x0F0F0F0F; X ^= T; Y ^= (T << 4)
        T = (Y ^ X) & 0x10101010; X ^= T; Y ^= T

        X = permutedChoice1Left(X)
        Y = permutedChoice1Right(Y)

        X &= 0x0FFFFFFF
        Y &= 0x0FFFFFFF

        var skIdx = 0
        for i in 0..<16 {
            if i < 2 || i == 8 || i == 15 {
                X = ((X << 1) | (X >> 27)) & 0x0FFFFFFF
                Y = ((Y << 1) | (Y >> 27)) & 0x0FFFFFFF
            } else {
                X = ((X << 2) | (X >> 26)) & 0x0FFFFFFF
                Y = ((Y << 2) | (Y >> 26)) & 0x0FFFFFFF
            }

            SK[skIdx] = roundSubkeyLeft(X, Y)
            skIdx += 1

            SK[skIdx] = roundSubkeyRight(X, Y)
            skIdx += 1
        }

        return SK
    }

    /// Set key for encryption.
    public mutating func setKeyEncrypt(_ key: [UInt8]) {
        sk = DESContext.computeSubkeys(key)
    }

    /// Set key for decryption (reversed subkeys).
    public mutating func setKeyDecrypt(_ key: [UInt8]) {
        sk = DESContext.computeSubkeys(key)
        for i in stride(from: 0, to: 16, by: 2) {
            sk.swapAt(i, 30 - i)
            sk.swapAt(i + 1, 31 - i)
        }
    }

    /// Encrypt or decrypt a single 8-byte block (ECB mode).
    public func cryptECB(input: [UInt8]) -> [UInt8] {
        var X = getUInt32BE(input, 0)
        var Y = getUInt32BE(input, 4)
        var T: UInt32

        // Initial Permutation
        T = ((X >> 4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T << 4)
        T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16)
        T = ((Y >> 2) ^ X) & 0x33333333; X ^= T; Y ^= (T << 2)
        T = ((Y >> 8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T << 8)
        Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF
        T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T
        X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF

        // 16 Feistel rounds
        var skIdx = 0
        for _ in 0..<8 {
            // DES_ROUND(Y, X)
            T = sk[skIdx] ^ Y; skIdx += 1
            X ^= DESContext.SB8[Int(T       & 0x3F)]
               ^ DESContext.SB6[Int((T >> 8) & 0x3F)]
               ^ DESContext.SB4[Int((T >> 16) & 0x3F)]
               ^ DESContext.SB2[Int((T >> 24) & 0x3F)]
            T = sk[skIdx] ^ ((Y << 28) | (Y >> 4)); skIdx += 1
            X ^= DESContext.SB7[Int(T       & 0x3F)]
               ^ DESContext.SB5[Int((T >> 8) & 0x3F)]
               ^ DESContext.SB3[Int((T >> 16) & 0x3F)]
               ^ DESContext.SB1[Int((T >> 24) & 0x3F)]

            // DES_ROUND(X, Y)
            T = sk[skIdx] ^ X; skIdx += 1
            Y ^= DESContext.SB8[Int(T       & 0x3F)]
               ^ DESContext.SB6[Int((T >> 8) & 0x3F)]
               ^ DESContext.SB4[Int((T >> 16) & 0x3F)]
               ^ DESContext.SB2[Int((T >> 24) & 0x3F)]
            T = sk[skIdx] ^ ((X << 28) | (X >> 4)); skIdx += 1
            Y ^= DESContext.SB7[Int(T       & 0x3F)]
               ^ DESContext.SB5[Int((T >> 8) & 0x3F)]
               ^ DESContext.SB3[Int((T >> 16) & 0x3F)]
               ^ DESContext.SB1[Int((T >> 24) & 0x3F)]
        }

        // Final Permutation
        X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF
        T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T
        Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF
        T = ((Y >> 8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T << 8)
        T = ((Y >> 2) ^ X) & 0x33333333; X ^= T; Y ^= (T << 2)
        T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16)
        T = ((X >> 4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T << 4)

        var output = [UInt8](repeating: 0, count: 8)
        putUInt32BE(Y, &output, 0)
        putUInt32BE(X, &output, 4)
        return output
    }
}

// MARK: - ARC4/RC4 Stream Cipher

/// ARC4 (RC4) stream cipher context.
/// Used by MPPE for PPP data encryption.
public struct ARC4Context {
    public var x: Int = 0
    public var y: Int = 0
    public var m = [UInt8](repeating: 0, count: 256)

    public init() {}

    /// Initialize the ARC4 cipher with the given key.
    public mutating func setup(key: [UInt8]) {
        x = 0
        y = 0

        for i in 0..<256 {
            m[i] = UInt8(i)
        }

        var j = 0
        var k = 0
        for i in 0..<256 {
            if k >= key.count { k = 0 }
            let a = Int(m[i])
            j = (j + a + Int(key[k])) & 0xFF
            m[i] = m[j]
            m[j] = UInt8(a)
            k += 1
        }
    }

    /// Encrypt or decrypt (XOR) the buffer in-place.
    public mutating func crypt(_ buf: inout [UInt8]) {
        var lx = x
        var ly = y

        for i in 0..<buf.count {
            lx = (lx + 1) & 0xFF
            let a = Int(m[lx])
            ly = (ly + a) & 0xFF
            let b = Int(m[ly])

            m[lx] = UInt8(b)
            m[ly] = UInt8(a)

            buf[i] ^= m[(a + b) & 0xFF]
        }

        x = lx
        y = ly
    }

    /// Encrypt or decrypt (XOR) a slice of bytes, returning the result.
    public mutating func crypt(_ input: [UInt8]) -> [UInt8] {
        var buf = input
        crypt(&buf)
        return buf
    }
}
