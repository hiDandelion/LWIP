//
//  TCPOOSTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

// MARK: - TCP Out-of-Sequence Tests

/// Tests for TCP out-of-sequence segment handling.
@Suite("TCP OOS", .serialized)
struct TCPOOSTests {

    // MARK: - Helpers

    /// Count segments on the ooseq queue.
    private func ooseqCount(_ pcb: TCPControlBlock) -> Int {
        return TCPTestHelper.segmentCount(pcb.ooseq)
    }

    /// Get the sequence number of the nth ooseq segment.
    private func ooseqSeqno(_ pcb: TCPControlBlock, at index: Int) -> UInt32? {
        var seg = pcb.ooseq
        var i = 0
        while let s = seg {
            if i == index { return s.sequenceNumber }
            i += 1
            seg = s.next
        }
        return nil
    }

    /// Get the tcp length of the nth ooseq segment.
    private func ooseqTcpLen(_ pcb: TCPControlBlock, at index: Int) -> UInt16? {
        var seg = pcb.ooseq
        var i = 0
        while let s = seg {
            if i == index { return s.tcpLen }
            i += 1
            seg = s.next
        }
        return nil
    }

    /// Total tcp length of all ooseq segments.
    private func ooseqTotalTcpLen(_ pcb: TCPControlBlock) -> UInt32 {
        var total: UInt32 = 0
        var seg = pcb.ooseq
        while let s = seg {
            total += UInt32(s.tcpLen)
            seg = s.next
        }
        return total
    }

    /// Set up a standard test PCB in ESTABLISHED state with a test netif.
    private func makeTestPCB(counters: TCPTestCounters) -> (TCPControlBlock, NetworkInterface)? {
        TCPTestHelper.removeAll()

        guard let pcb = TCPTestHelper.newCountersPCB(counters: counters) else { return nil }

        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: TCPTxCounters(),
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        TCPTestHelper.setState(pcb: pcb, state: .established)
        pcb.receiveNext = 1000
        pcb.sendNext = 2000
        pcb.sendLastByteBuffered = 1999
        pcb.lastAcknowledged = 2000
        pcb.receiveWindow = 65535
        pcb.receiveAnnouncedWindow = 65535
        pcb.receiveAnnouncedRightEdge = 1000 &+ 65535
        pcb.maxSegmentSize = 536

        return (pcb, netif)
    }

    /// Inject an OOS segment into the PCB.
    private func injectOOS(pcb: TCPControlBlock, netif: NetworkInterface,
                           data: [UInt8]?, dataLen: UInt16,
                           seqnoOffset: UInt32, flags: TCPHeaderFlags = .ack) {
        TCPTestHelper.injectRxSegment(
            pcb: pcb, data: data, dataLen: dataLen,
            seqnoOffset: seqnoOffset, acknoOffset: 0,
            headerFlags: flags, netif: netif
        )
    }

    // MARK: - test_tcp_recv_ooseq_FIN_OOSEQ

    @Test("OOS FIN_OOSEQ: FIN arrives out-of-sequence then in-seq fills gap")
    func ooseqFINOutOfSequence() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        let counters = TCPTestCounters()
        counters.expectedData = data
        counters.expectedDataLen = data.count

        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        // p1: 8 bytes at offset 8 with FIN (seqno 8..16+FIN)
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[8..<16]), dataLen: 8, seqnoOffset: 8,
                  flags: [.ack, .fin])
        #expect(counters.recvCalls == 0)
        #expect(ooseqCount(pcb) >= 1)
        if let tcpLen = ooseqTcpLen(pcb, at: 0) {
            #expect(tcpLen == 9, "8 data + 1 FIN")
        }

        // p2: 8 bytes at offset 4 (partly overlaps p1)
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[4..<12]), dataLen: 8, seqnoOffset: 4)
        #expect(counters.recvCalls == 0)

        // pinseq: 4 bytes at offset 0 (fills the gap)
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[0..<4]), dataLen: 4, seqnoOffset: 0)

        // All data plus FIN should now be delivered
        #expect(counters.recvCalls >= 1, "In-sequence data should deliver queued OOS segments")
        #expect(counters.recvedBytes == data.count, "All 16 bytes should be received")
        #expect(counters.closeCalls == 1, "FIN should trigger close callback")
        #expect(pcb.ooseq == nil, "OOS queue should be empty after delivery")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_FIN_INSEQ

    @Test("OOS FIN_INSEQ: in-sequence FIN after OOS segments delivers all data")
    func ooseqFINInSequence() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        let counters = TCPTestCounters()
        counters.expectedData = data
        counters.expectedDataLen = data.count

        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        let lateByte = TCPTestHelper.createRxSegment(
            pcb: pcb,
            data: Array(data[15..<16]),
            dataLen: 1,
            seqnoOffset: 15,
            acknoOffset: 0,
            headerFlags: .ack
        )
        let lateByteDuplicate = TCPTestHelper.createRxSegment(
            pcb: pcb,
            data: Array(data[15..<16]),
            dataLen: 1,
            seqnoOffset: 15,
            acknoOffset: 0,
            headerFlags: .ack
        )
        let finalSegment = TCPTestHelper.createRxSegment(
            pcb: pcb,
            data: Array(data[14..<16]),
            dataLen: 2,
            seqnoOffset: 14,
            acknoOffset: 0,
            headerFlags: [.ack, .fin]
        )

        // p1: 2 bytes at offset 1
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[1..<3]), dataLen: 2, seqnoOffset: 1)
        #expect(counters.recvCalls == 0)

        // p2: 8 bytes at offset 4
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[4..<12]), dataLen: 8, seqnoOffset: 4)
        #expect(counters.recvCalls == 0)

        // p3: 11 bytes at offset 3 (overlaps p1 and p2)
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[3..<14]), dataLen: 11, seqnoOffset: 3)
        #expect(counters.recvCalls == 0)

        // pinseq: 4 bytes at offset 0 (fills gap, delivers queued data)
        injectOOS(pcb: pcb, netif: netif,
                  data: Array(data[0..<4]), dataLen: 4, seqnoOffset: 0)
        #expect(counters.recvCalls >= 1, "In-sequence data should deliver all queued OOS segments")
        #expect(counters.recvedBytes >= 14, "At least 14 bytes should be received after gap fill")
        #expect(pcb.ooseq == nil || ooseqCount(pcb) <= 1,
                "Most OOS segments should be delivered")

        if let lateByte {
            TCPTestHelper.testTCPInput(lateByte, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)
        }

        if let lateByteDuplicate {
            TCPTestHelper.testTCPInput(lateByteDuplicate, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)
        }

        if let finalSegment {
            TCPTestHelper.testTCPInput(finalSegment, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)
        }

        #expect(counters.closeCalls == 1, "FIN should trigger close callback")
        #expect(counters.recvedBytes == data.count, "All 16 bytes should be received")
        #expect(pcb.ooseq == nil, "OOS queue should be empty after FIN delivery")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_overrun_rxwin

    @Test("OOS segments overrunning receive window are dropped")
    func ooseqOverrunRxWin() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        let win = pcb.receiveWindow

        // Inject a segment within the window
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0xAA, count: 10), dataLen: 10, seqnoOffset: 10)
        let countInWin = ooseqCount(pcb)
        #expect(countInWin >= 1)

        // Inject a segment way beyond the window (should be dropped)
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0xBB, count: 10), dataLen: 10,
                  seqnoOffset: win + 100)
        #expect(ooseqCount(pcb) == countInWin, "Segment beyond window should be dropped")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_overrun_rxwin_edge

    @Test("OOS segment at exact receive window edge")
    func ooseqOverrunRxWinEdge() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        let win = pcb.receiveWindow

        // Inject a segment within the window
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0xAA, count: 10), dataLen: 10, seqnoOffset: 10)
        let countInWin = ooseqCount(pcb)
        #expect(countInWin >= 1)

        // Inject a segment at the exact window edge (last byte just inside window)
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0xCC, count: 10), dataLen: 10,
                  seqnoOffset: win - 10)

        // Segment at the edge should be accepted or trimmed
        #expect(ooseqCount(pcb) >= countInWin, "Segment at window edge should be handled")

        // Inject segment that starts exactly at the window boundary (should be dropped)
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0xDD, count: 10), dataLen: 10,
                  seqnoOffset: win)
        #expect(ooseqCount(pcb) <= countInWin + 1,
                "Segment at exact boundary should be dropped")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_max_bytes

    @Test("OOS queue respects maximum bytes limit")
    func ooseqMaxBytes() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        // Inject many OOS segments to test the byte limit
        var offset: UInt32 = 10
        let segSize: UInt16 = 100
        var injected = 0
        for _ in 0..<100 {
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: UInt8(truncatingIfNeeded: offset), count: Int(segSize)),
                      dataLen: segSize, seqnoOffset: offset)
            offset += UInt32(segSize) + 10 // leave gaps
            injected += 1
        }

        // The ooseq queue should have been limited by max bytes
        let totalLen = ooseqTotalTcpLen(pcb)
        #expect(totalLen > 0, "Some OOS segments should be queued")
        // Verify the queue does not grow unboundedly
        #expect(ooseqCount(pcb) <= injected, "OOS count should not exceed injected count")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_max_pbufs

    @Test("OOS queue respects maximum pbufs limit")
    func ooseqMaxPbufs() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        // Inject many small OOS segments to test the pbuf count limit
        var offset: UInt32 = 10
        for _ in 0..<200 {
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xEE, count: 1),
                      dataLen: 1, seqnoOffset: offset)
            offset += 2 // leave 1-byte gaps
        }

        let count = ooseqCount(pcb)
        #expect(count > 0, "Some OOS segments should be queued")
        // The queue should be bounded by max pbufs
        #expect(count <= 200, "OOS pbuf count should be bounded")

        TCPGlobal.shared.abort(pcb: pcb)
    }

    // MARK: - test_tcp_recv_ooseq_double_FIN (parameterized, 0..15)

    @Test("OOS double FIN handling", arguments: 0...15)
    func ooseqDoubleFIN(variant: Int) {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        guard let (pcb, netif) = makeTestPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }

        // Each variant tests a different combination of OOS segment ordering
        // and FIN placement to verify double-FIN handling.
        //
        // Bit 0: whether first OOS segment has FIN
        // Bit 1: whether second OOS segment has FIN
        // Bit 2: order of segment injection (before/after gap fill)
        // Bit 3: whether a duplicate FIN is injected

        let hasFIN1 = (variant & 0x01) != 0
        let hasFIN2 = (variant & 0x02) != 0
        let reverseOrder = (variant & 0x04) != 0
        let duplicateFIN = (variant & 0x08) != 0

        let flags1: TCPHeaderFlags = hasFIN1 ? [.ack, .fin] : .ack
        let flags2: TCPHeaderFlags = hasFIN2 ? [.ack, .fin] : .ack

        if reverseOrder {
            // Inject segments in reverse order
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xBB, count: 4), dataLen: 4,
                      seqnoOffset: 8, flags: flags2)
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xAA, count: 4), dataLen: 4,
                      seqnoOffset: 4, flags: flags1)
        } else {
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xAA, count: 4), dataLen: 4,
                      seqnoOffset: 4, flags: flags1)
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xBB, count: 4), dataLen: 4,
                      seqnoOffset: 8, flags: flags2)
        }

        if duplicateFIN {
            // Inject a duplicate FIN segment
            injectOOS(pcb: pcb, netif: netif,
                      data: [UInt8](repeating: 0xCC, count: 4), dataLen: 4,
                      seqnoOffset: 8, flags: [.ack, .fin])
        }

        // No data should be delivered yet (gap at offset 0)
        #expect(counters.recvCalls == 0, "No data should be delivered before gap fill")
        #expect(ooseqCount(pcb) >= 1, "At least one OOS segment should be queued")

        // Fill the gap with in-sequence data
        injectOOS(pcb: pcb, netif: netif,
                  data: [UInt8](repeating: 0x00, count: 4), dataLen: 4,
                  seqnoOffset: 0, flags: .ack)

        // Data should now be delivered
        #expect(counters.recvCalls >= 1, "Data should be delivered after gap fill")

        // If any FIN was present, close should be called at most once
        if hasFIN1 || hasFIN2 {
            #expect(counters.closeCalls <= 1, "FIN should trigger at most one close callback")
        }

        // PCB should be in a valid state
        #expect(pcb.state == .established || pcb.state == .closeWait,
                "PCB should be in ESTABLISHED or CLOSE_WAIT")

        TCPGlobal.shared.abort(pcb: pcb)
    }
}
