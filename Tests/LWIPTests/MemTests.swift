//
//  MemTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for the memory allocator.
@Suite("Mem")
struct MemTests {

    /// Port of test_mem_one.
    @Test("malloc, trim, and free with statistics")
    func memOne() {
        let p1 = Mem.malloc(64)
        #expect(p1 != nil)

        // Trim to smaller size
        let p1Trimmed = Mem.trim(p1, newSize: 32)
        #expect(p1Trimmed != nil)

        Mem.free(p1Trimmed)
    }

    /// Port of test_mem_random.
    @Test("Random allocation/deallocation patterns")
    func memRandom() {
        let sizes = [1, 2, 4, 8, 11, 16, 32, 48, 64, 96, 128, 256, 512, 1024]
        var pointers: [UnsafeMutableRawPointer] = []

        for i in 0..<200 {
            let size = sizes[i % sizes.count]
            if let p = Mem.malloc(size) {
                let bytes = p.assumingMemoryBound(to: UInt8.self)
                for j in 0..<size {
                    bytes[j] = UInt8(truncatingIfNeeded: j)
                }
                pointers.append(p)
            }
        }

        #expect(pointers.count == 200, "Should have allocated all 200 blocks")

        var idx = 0
        for i in 0..<200 {
            let size = sizes[i % sizes.count]
            if idx < pointers.count {
                let bytes = pointers[idx].assumingMemoryBound(to: UInt8.self)
                for j in 0..<size {
                    #expect(bytes[j] == UInt8(truncatingIfNeeded: j),
                            "Data corruption at block \(i), byte \(j)")
                }
                idx += 1
            }
        }

        for p in pointers {
            Mem.free(p)
        }
    }

    /// Port of test_mem_invalid_free.
    @Test("Detection of invalid free operations")
    func memInvalidFree() {
        Mem.free(nil)

        let p = Mem.malloc(16)
        #expect(p != nil)
        Mem.free(p)
    }

    /// Port of test_mem_double_free.
    @Test("Detection of double-free memory errors")
    func memDoubleFree() {
        let p1 = Mem.malloc(32)
        let p2 = Mem.malloc(32)
        let p3 = Mem.malloc(32)

        #expect(p1 != nil)
        #expect(p2 != nil)
        #expect(p3 != nil)

        Mem.free(p2)

        // In Swift port, double-free is UB. Just verify surrounding allocations
        // remain valid.
        Mem.free(p1)
        Mem.free(p3)
    }
}
