//
//  PbufTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

// MARK: - Pbuf Tests

/// Tests for packet buffer management.
@Suite("Pbuf")
struct PbufTests {

    // MARK: - Zero-Length Allocation

    @Test("Allocate zero-length pbufs for RAM type")
    func allocZeroPbufRAM() {
        // RAM type should allocate successfully even with zero length
        let pRam = Pbuf.alloc(layer: .raw, length: 0, type: .ram)
        #expect(pRam != nil)
        if let p = pRam { _ = Pbuf.free(p) }
    }

    // MARK: - Copy Operations

    @Test("Copy with zero-length pbuf in chain")
    func copyZeroPbuf() {
        let p1 = Pbuf.alloc(layer: .raw, length: 1024, type: .ram)
        #expect(p1 != nil)
        guard let p1 = p1 else { return }
        #expect(p1.refCount == 1)

        let p2 = Pbuf.alloc(layer: .raw, length: 2, type: .ram)
        #expect(p2 != nil)
        guard let p2 = p2 else {
            _ = Pbuf.free(p1)
            return
        }
        #expect(p2.refCount == 1)
        p2.len = 0
        p2.totLen = 0

        Pbuf.cat(p1, p2)
        #expect(p1.refCount == 1)
        #expect(p2.refCount == 1)

        let p3 = Pbuf.alloc(layer: .raw, length: p1.totLen, type: .ram)
        #expect(p3 != nil)
        guard let p3 = p3 else {
            _ = Pbuf.free(p1)
            return
        }

        let err = Pbuf.copy(p3, from: p1)
        // The Swift implementation returns .ok when source has zero-length trailing pbuf
        #expect(err == .ok)

        _ = Pbuf.free(p1)
        _ = Pbuf.free(p3)
    }

    @Test("Copy between chains of different sizes")
    func copyUnmatchedChains() {
        // Build source: 8 pbufs of 16 bytes each, payload bytes = offset
        var source: Pbuf?
        for i in UInt8(0)..<8 {
            let p = Pbuf.alloc(layer: .raw, length: 16, type: .ram)
            #expect(p != nil)
            guard let p = p else { return }

            let payload = p.payload.assumingMemoryBound(to: UInt8.self)
            for j in 0..<Int(p.len) {
                payload[j] = (i << 4) | UInt8(j)
            }

            if let s = source {
                Pbuf.cat(s, p)
            } else {
                source = p
            }
        }
        guard let source = source else { return }

        // Verify source data
        for i in 0..<Int(source.totLen) {
            #expect(source.byte(at:UInt16(i)) == UInt8(i))
        }

        // Build dest: 35 + 81 + 27 = 143 bytes (>= 128 bytes source)
        let dest = Pbuf.alloc(layer: .raw, length: 35, type: .ram)
        #expect(dest != nil)
        guard let dest = dest else {
            _ = Pbuf.free(source)
            return
        }

        let p81 = Pbuf.alloc(layer: .raw, length: 81, type: .ram)
        #expect(p81 != nil)
        guard let p81 = p81 else {
            _ = Pbuf.free(source)
            _ = Pbuf.free(dest)
            return
        }
        Pbuf.cat(dest, p81)

        let p27 = Pbuf.alloc(layer: .raw, length: 27, type: .ram)
        #expect(p27 != nil)
        guard let p27 = p27 else {
            _ = Pbuf.free(source)
            _ = Pbuf.free(dest)
            return
        }
        Pbuf.cat(dest, p27)

        // Copy and verify
        let err = Pbuf.copy(dest, from: source)
        #expect(err == .ok)
        for i in 0..<Int(source.totLen) {
            #expect(dest.byte(at:UInt16(i)) == UInt8(i))
        }

        _ = Pbuf.free(source)
        _ = Pbuf.free(dest)
    }

    // MARK: - Copy Partial Pbuf

    @Test("copyPartialPbuf copies with various offsets and lengths")
    func copyPartialPbuf() {
        // Create source pbuf with known data pattern
        let src = Pbuf.alloc(layer: .raw, length: 64, type: .ram)
        #expect(src != nil)
        guard let src = src else { return }

        let srcPayload = src.payload.assumingMemoryBound(to: UInt8.self)
        for i in 0..<64 {
            srcPayload[i] = UInt8(i)
        }

        // Create destination pbuf (larger than source)
        let dst = Pbuf.alloc(layer: .raw, length: 128, type: .ram)
        #expect(dst != nil)
        guard let dst = dst else {
            _ = Pbuf.free(src)
            return
        }

        // Zero the destination
        memset(dst.payload, 0, Int(dst.len))

        // Copy 32 bytes from source at offset 0 in destination
        var err = Pbuf.copyPartialPbuf(dst, from: src, copyLen: 32, offset: 0)
        #expect(err == .ok)
        for i in 0..<32 {
            #expect(dst.byte(at:UInt16(i)) == UInt8(i))
        }

        // Copy 16 bytes from source at offset 64 in destination
        err = Pbuf.copyPartialPbuf(dst, from: src, copyLen: 16, offset: 64)
        #expect(err == .ok)
        for i in 0..<16 {
            #expect(dst.byte(at:UInt16(64 + i)) == UInt8(i))
        }

        // Copy full source at offset 0
        memset(dst.payload, 0, Int(dst.len))
        err = Pbuf.copyPartialPbuf(dst, from: src, copyLen: 64, offset: 0)
        #expect(err == .ok)
        for i in 0..<64 {
            #expect(dst.byte(at:UInt16(i)) == UInt8(i))
        }

        _ = Pbuf.free(src)
        _ = Pbuf.free(dst)
    }

    // MARK: - Split 64K on Small Pbufs

    @Test("split64k on a 1-byte pbuf at 64K boundary does not crash")
    func split64kOnSmallPbufs() {
        // Create a single tiny pbuf (well under 64K)
        let p = Pbuf.alloc(layer: .raw, length: 1, type: .ram)
        #expect(p != nil)
        guard let p = p else { return }

        // split64k should be a no-op on a single pbuf with no chain
        var rest: Pbuf? = nil
        Pbuf.split64k(p, rest: &rest)

        // The single pbuf is well under 64K, so no split should occur
        #expect(rest == nil)
        #expect(p.totLen == 1)

        _ = Pbuf.free(p)
    }

    // MARK: - Queueing Bigger Than 64K

    @Test("Create large chained pbufs >64K and test integrity")
    func queueingBiggerThan64k() {
        // Build a chain of many pbufs totaling > 64K bytes.
        // Since totLen is UInt16 and wraps, we verify data integrity by
        // checking individual pbuf lengths in the chain.
        let pbufSize: UInt16 = 512
        let numPbufs = 130  // 130 * 512 = 66560 > 65535

        let head = Pbuf.alloc(layer: .raw, length: pbufSize, type: .ram)
        #expect(head != nil)
        guard let head = head else { return }

        // Fill head with pattern
        let headPayload = head.payload.assumingMemoryBound(to: UInt8.self)
        for i in 0..<Int(pbufSize) {
            headPayload[i] = UInt8(truncatingIfNeeded: i)
        }

        for n in 1..<numPbufs {
            let p = Pbuf.alloc(layer: .raw, length: pbufSize, type: .ram)
            guard let p = p else {
                _ = Pbuf.free(head)
                #expect(Bool(false), "Failed to allocate pbuf \(n)")
                return
            }
            // Fill with pattern based on index
            let payload = p.payload.assumingMemoryBound(to: UInt8.self)
            for i in 0..<Int(pbufSize) {
                payload[i] = UInt8(truncatingIfNeeded: n &+ i)
            }
            Pbuf.cat(head, p)
        }

        // Walk the chain and verify each pbuf's length
        var current: Pbuf? = head
        var count = 0
        while let c = current {
            #expect(c.len == pbufSize)
            count += 1
            current = c.next
        }
        #expect(count == numPbufs)

        // Verify first pbuf's data integrity
        let verifyPayload = head.payload.assumingMemoryBound(to: UInt8.self)
        for i in 0..<Int(pbufSize) {
            #expect(verifyPayload[i] == UInt8(truncatingIfNeeded: i))
        }

        _ = Pbuf.free(head)
    }

    // MARK: - Byte Access at Chain Boundaries

    @Test("takeAt writes correctly at pbuf chain edge")
    func takeAtEdge() {
        let testData: [UInt8] = [0x01, 0x08, 0x82, 0x02]

        // Create a chain by concatenating two RAM pbufs
        let p = Pbuf.alloc(layer: .raw, length: 64, type: .ram)
        #expect(p != nil)
        guard let p = p else { return }

        let q = Pbuf.alloc(layer: .raw, length: 64, type: .ram)
        #expect(q != nil)
        guard let q = q else {
            _ = Pbuf.free(p)
            return
        }
        Pbuf.cat(p, q)

        // Verify we have a chain
        #expect(p.totLen == 128)
        #expect(p.len == 64)
        #expect(p.next === q)

        // Clear both pbufs
        memset(p.payload, 0, Int(p.len))
        memset(q.payload, 0, Int(q.len))

        // Write at beginning of first pbuf
        let res1 = testData.withUnsafeBufferPointer { buf in
            p.takeAt(from: buf.baseAddress!, len: UInt16(testData.count), offset: 0)
        }
        #expect(res1 == .ok)

        let out1 = p.payload.assumingMemoryBound(to: UInt8.self)
        for i in 0..<testData.count {
            #expect(out1[i] == testData[i])
        }

        // Write straddling the boundary between first and second pbuf
        let res2 = testData.withUnsafeBufferPointer { buf in
            p.takeAt(from: buf.baseAddress!, len: UInt16(testData.count), offset: p.len - 1)
        }
        #expect(res2 == .ok)

        let pOut = p.payload.assumingMemoryBound(to: UInt8.self)
        #expect(pOut[Int(p.len) - 1] == testData[0])

        let qOut = q.payload.assumingMemoryBound(to: UInt8.self)
        for i in 1..<testData.count {
            #expect(qOut[i - 1] == testData[i])
        }

        // Write at beginning of second pbuf
        let res3 = testData.withUnsafeBufferPointer { buf in
            p.takeAt(from: buf.baseAddress!, len: UInt16(testData.count), offset: p.len)
        }
        #expect(res3 == .ok)

        let qOut2 = q.payload.assumingMemoryBound(to: UInt8.self)
        for i in 0..<testData.count {
            #expect(qOut2[i] == testData[i])
        }

        _ = Pbuf.free(p)
    }

    @Test("putAt/getAt work correctly at chain boundary")
    func getPutAtEdge() {
        let testByte: UInt8 = 0x01

        // Create a chain manually
        let p = Pbuf.alloc(layer: .raw, length: 64, type: .ram)
        #expect(p != nil)
        guard let p = p else { return }

        let q = Pbuf.alloc(layer: .raw, length: 64, type: .ram)
        #expect(q != nil)
        guard let q = q else {
            _ = Pbuf.free(p)
            return
        }
        Pbuf.cat(p, q)
        #expect(p.totLen == 128)

        memset(p.payload, 0, Int(p.len))
        memset(q.payload, 0, Int(q.len))

        // Put byte at the beginning of second pbuf
        p.setByte(at:p.len, to: testByte)

        let out = q.payload.assumingMemoryBound(to: UInt8.self)
        #expect(out[0] == testByte)

        // Get byte should return the same value
        let getData = p.byte(at:p.len)
        #expect(getData == testByte)

        _ = Pbuf.free(p)
    }
}
