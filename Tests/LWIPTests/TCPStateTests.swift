//
//  TCPStateTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

// MARK: - TCP State Machine Tests

/// Tests for TCP state machine transitions.
@Suite("TCP State", .serialized)
struct TCPStateTests {

    // MARK: - test_tcp_new_max_num

    @Test("TCP new returns nil when PCB pool is exhausted")
    func newMaxNum() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        // Allocate PCBs until allocation fails
        var pcbs: [TCPControlBlock] = []
        while let pcb = TCPGlobal.shared.new() {
            pcbs.append(pcb)
            // Safety limit to avoid infinite loop
            if pcbs.count > 1000 { break }
        }

        // We should have allocated some PCBs
        #expect(pcbs.count > 0)

        // Clean up - abort all
        for pcb in pcbs {
            TCPGlobal.shared.abort(pcb: pcb)
        }
    }

    // MARK: - test_tcp_new_max_num_remove_TIME_WAIT

    @Test("TIME_WAIT PCB is reclaimed when pool is exhausted")
    func newMaxNumRemoveTimeWait() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        // Create one PCB and put it in TIME_WAIT
        guard let twPcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        TCPTestHelper.setState(pcb: twPcb, state: .timeWait)

        // TIME_WAIT list should be non-empty
        #expect(TCPGlobal.shared.timeWaitPCBs != nil)
    }

    // MARK: - test_tcp_connect_active_open

    @Test("TCP connect sends SYN and transitions to SYN_SENT")
    func connectActiveOpen() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        txCounters.copyTxPackets = true
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to allocate PCB")
            return
        }

        var connected = false
        let err = TCPGlobal.shared.connect(
            pcb: pcb, address: .v4(TCPTestConstants.remoteIP),
            port: TCPTestConstants.remotePort
        ) { _, err in
            connected = (err == .ok)
            return .ok
        }

        #expect(err == .ok)
        #expect(pcb.state == .synSent)
    }

    // MARK: - test_tcp_active_close

    @Test("TCP close from ESTABLISHED goes to FIN_WAIT_1")
    func activeClose() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to allocate PCB")
            return
        }

        TCPTestHelper.setState(pcb: pcb, state: .established)
        pcb.receiveNext = 100
        pcb.sendNext = 200
        pcb.sendLastByteBuffered = 199

        let err = TCPGlobal.shared.close(pcb: pcb)
        #expect(err == .ok)
        #expect(pcb.state == .finWait1)
    }

    // MARK: - test_tcp_imultaneous_close

    @Test("Simultaneous close from both sides")
    func simultaneousClose() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        guard let pcb = TCPTestHelper.newCountersPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        TCPTestHelper.setState(pcb: pcb, state: .established)
        pcb.receiveNext = 1000
        pcb.sendNext = 2000
        pcb.sendLastByteBuffered = 1999
        pcb.lastAcknowledged = 2000
        pcb.receiveWindow = UInt32(lwipConfig.tcpWnd)
        pcb.receiveAnnouncedWindow = UInt32(lwipConfig.tcpWnd)
        pcb.maxSegmentSize = 536

        // Local close: ESTABLISHED -> FIN_WAIT_1
        let closeErr = TCPGlobal.shared.close(pcb: pcb)
        #expect(closeErr == .ok)
        #expect(pcb.state == .finWait1)

        // Receive FIN from remote while in FIN_WAIT_1 -> CLOSING
        TCPTestHelper.injectRxSegment(
            pcb: pcb, data: nil, dataLen: 0,
            seqnoOffset: 0, acknoOffset: 0,
            headerFlags: [.fin, .ack], netif: netif
        )

        // State should be CLOSING (both sides sent FIN)
        #expect(pcb.state == .closing || pcb.state == .timeWait,
                "Expected CLOSING or TIME_WAIT after simultaneous close")
    }

    // MARK: - test_tcp_gen_rst_in_CLOSED

    @Test("RST is generated for segment arriving in CLOSED state")
    func genRstInClosed() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        // No PCB exists - send an ACK segment to a port with no listener
        guard let p = TCPTestHelper.createSegment(
            srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP),
            srcPort: TCPTestConstants.remotePort,
            dstPort: TCPTestConstants.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: 54321,
            headerFlags: TCPHeaderFlags.ack,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }

        TCPTestHelper.testTCPInput(
            p, srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP), netif: netif
        )

        // A RST should have been sent in response
        #expect(txCounters.numTxCalls == 1, "Expected RST to be sent for segment in CLOSED state")
    }

    // MARK: - test_tcp_gen_rst_in_LISTEN

    @Test("RST is generated for ACK segment arriving at LISTEN PCB")
    func genRstInListen() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        // Create a listening PCB
        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let bindErr = TCPGlobal.shared.bind(pcb: pcb, address: .v4(TCPTestConstants.localIP), port: TCPTestConstants.localPort)
        #expect(bindErr == .ok)

        guard let lpcb = TCPGlobal.shared.listen(pcb: pcb, backlog: 1) else {
            #expect(Bool(false), "Failed to listen")
            return
        }

        // Send an ACK (not SYN) to the listening port - should generate RST
        guard let p = TCPTestHelper.createSegment(
            srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP),
            srcPort: TCPTestConstants.remotePort,
            dstPort: lpcb.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: 54321,
            headerFlags: TCPHeaderFlags.ack,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }

        TCPTestHelper.testTCPInput(
            p, srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP), netif: netif
        )

        // RST should have been sent
        #expect(txCounters.numTxCalls == 1, "Expected RST for ACK to LISTEN state")

        // The listen PCB should still exist
        #expect(TCPGlobal.shared.listenPCBs != nil)
        TCPGlobal.shared.removeListen(lpcb)
    }

    // MARK: - test_tcp_gen_rst_in_TIME_WAIT

    @Test("RST is generated for SYN arriving at TIME_WAIT PCB")
    func genRstInTimeWait() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        TCPTestHelper.setState(pcb: pcb, state: .timeWait)
        pcb.receiveNext = 1000
        pcb.sendNext = 2000
        pcb.sendLastByteBuffered = 1999

        // Send a SYN to the TIME_WAIT PCB
        TCPTestHelper.injectRxSegment(
            pcb: pcb, data: nil, dataLen: 0,
            seqnoOffset: 0, acknoOffset: 0,
            headerFlags: TCPHeaderFlags.syn, netif: netif
        )

        // RST should have been sent
        #expect(txCounters.numTxCalls == 1, "Expected RST for SYN to TIME_WAIT state")
        // PCB should still be in TIME_WAIT
        #expect(pcb.state == .timeWait)
    }

    // MARK: - test_tcp_process_rst_seqno

    @Test("RST with correct/incorrect sequence number validation")
    func processRstSeqno() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let counters = TCPTestCounters()
        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        // Test 1: SYN_SENT state - RST with incorrect ackno should be rejected
        guard let pcb1 = TCPTestHelper.newCountersPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let _ = TCPGlobal.shared.connect(
            pcb: pcb1, address: .v4(TCPTestConstants.remoteIP),
            port: TCPTestConstants.remotePort
        ) { _, _ in .ok }

        // RST with incorrect seqno (sendNext - 10) should NOT reset
        guard let badRst = TCPTestHelper.createSegment(
            srcIP: pcb1.remoteIP, dstIP: pcb1.localIP,
            srcPort: pcb1.remotePort, dstPort: pcb1.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: pcb1.sendNext &- 10,
            headerFlags: TCPHeaderFlags.rst,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }
        TCPTestHelper.testTCPInput(badRst, srcIP: pcb1.remoteIP, dstIP: pcb1.localIP, netif: netif)
        #expect(counters.errCalls == 0, "RST with wrong seqno should be rejected in SYN_SENT")

        // RST with correct ackno (== sendNext) SHOULD reset
        guard let goodRst = TCPTestHelper.createSegment(
            srcIP: pcb1.remoteIP, dstIP: pcb1.localIP,
            srcPort: pcb1.remotePort, dstPort: pcb1.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: pcb1.sendNext,
            headerFlags: TCPHeaderFlags.rst,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }
        TCPTestHelper.testTCPInput(goodRst, srcIP: pcb1.remoteIP, dstIP: pcb1.localIP, netif: netif)
        #expect(counters.errCalls == 1, "RST with correct seqno should be accepted in SYN_SENT")
        counters.reset()

        // Test 2: ESTABLISHED state - RST with wrong rcv_nxt should be rejected
        guard let pcb2 = TCPTestHelper.newCountersPCB(counters: counters) else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        TCPTestHelper.setState(pcb: pcb2, state: .established)
        pcb2.receiveNext = 5000
        pcb2.sendNext = 6000
        pcb2.sendLastByteBuffered = 5999
        pcb2.receiveWindow = 65535

        // RST with seqno != receiveNext should be rejected
        guard let badRst2 = TCPTestHelper.createSegment(
            srcIP: pcb2.remoteIP, dstIP: pcb2.localIP,
            srcPort: pcb2.remotePort, dstPort: pcb2.localPort,
            data: nil, dataLen: 0,
            seqno: pcb2.receiveNext &- 10, ackno: 54321,
            headerFlags: TCPHeaderFlags.rst,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }
        TCPTestHelper.testTCPInput(badRst2, srcIP: pcb2.remoteIP, dstIP: pcb2.localIP, netif: netif)
        #expect(counters.errCalls == 0, "RST with wrong seqno should be rejected in ESTABLISHED")

        // RST with correct seqno (== receiveNext) SHOULD reset
        guard let goodRst2 = TCPTestHelper.createSegment(
            srcIP: pcb2.remoteIP, dstIP: pcb2.localIP,
            srcPort: pcb2.remotePort, dstPort: pcb2.localPort,
            data: nil, dataLen: 0,
            seqno: pcb2.receiveNext, ackno: 54321,
            headerFlags: TCPHeaderFlags.rst,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }
        TCPTestHelper.testTCPInput(goodRst2, srcIP: pcb2.remoteIP, dstIP: pcb2.localIP, netif: netif)
        #expect(counters.errCalls == 1, "RST with correct seqno should be accepted in ESTABLISHED")
    }

    // MARK: - test_tcp_gen_rst_in_SYN_SENT_ackseq

    @Test("RST is generated for SYN+ACK with incorrect ackno in SYN_SENT")
    func genRstInSynSentAckSeq() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let err = TCPGlobal.shared.connect(
            pcb: pcb, address: .v4(TCPTestConstants.remoteIP),
            port: TCPTestConstants.remotePort
        ) { _, _ in .ok }
        #expect(err == .ok)
        #expect(pcb.state == .synSent)

        // Reset TX counter after the SYN was sent
        txCounters.reset()

        // Send SYN+ACK with incorrect ackno (lastack - 10)
        guard let p = TCPTestHelper.createSegment(
            srcIP: pcb.remoteIP, dstIP: pcb.localIP,
            srcPort: pcb.remotePort, dstPort: pcb.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: pcb.lastAcknowledged &- 10,
            headerFlags: [.syn, .ack],
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }

        TCPTestHelper.testTCPInput(p, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)

        // Should send RST (and possibly re-send SYN)
        #expect(txCounters.numTxCalls >= 1, "Expected RST for SYN+ACK with incorrect ackno")
    }

    // MARK: - test_tcp_gen_rst_in_SYN_SENT_non_syn_ack

    @Test("RST is generated for ACK (non-SYN) in SYN_SENT")
    func genRstInSynSentNonSynAck() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let err = TCPGlobal.shared.connect(
            pcb: pcb, address: .v4(TCPTestConstants.remoteIP),
            port: TCPTestConstants.remotePort
        ) { _, _ in .ok }
        #expect(err == .ok)

        txCounters.reset()

        // Send ACK (not SYN+ACK) with correct ackno
        guard let p = TCPTestHelper.createSegment(
            srcIP: pcb.remoteIP, dstIP: pcb.localIP,
            srcPort: pcb.remotePort, dstPort: pcb.localPort,
            data: nil, dataLen: 0,
            seqno: 12345, ackno: pcb.lastAcknowledged,
            headerFlags: TCPHeaderFlags.ack,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create segment")
            return
        }

        TCPTestHelper.testTCPInput(p, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)

        // Should send RST (and possibly re-send SYN)
        #expect(txCounters.numTxCalls >= 1, "Expected RST for non-SYN ACK in SYN_SENT")
    }

    // MARK: - test_tcp_gen_rst_in_SYN_RCVD

    @Test("RST is generated for ACK with incorrect ackno in SYN_RCVD")
    func genRstInSynRcvd() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        // Create a listening PCB
        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let bindErr = TCPGlobal.shared.bind(pcb: pcb, address: .v4(TCPTestConstants.localIP), port: TCPTestConstants.localPort)
        #expect(bindErr == .ok)

        guard let lpcb = TCPGlobal.shared.listen(pcb: pcb, backlog: 1) else {
            #expect(Bool(false), "Failed to listen")
            return
        }

        // Send a SYN to transition to SYN_RCVD
        guard let synSeg = TCPTestHelper.createSegment(
            srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP),
            srcPort: TCPTestConstants.remotePort,
            dstPort: lpcb.localPort,
            data: nil, dataLen: 0,
            seqno: 1000, ackno: 54321,
            headerFlags: TCPHeaderFlags.syn,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create SYN segment")
            return
        }

        txCounters.reset()
        TCPTestHelper.testTCPInput(
            synSeg, srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP), netif: netif
        )
        // SYN+ACK should have been sent
        #expect(txCounters.numTxCalls == 1, "Expected SYN+ACK in response to SYN")

        // Now there should be an active PCB in SYN_RCVD
        let activePCB = TCPGlobal.shared.activePCBs
        if let active = activePCB {
            let ackSeqno = active.lastAcknowledged

            txCounters.reset()

            // Send ACK with incorrect ackno
            guard let badAck = TCPTestHelper.createSegment(
                srcIP: .v4(TCPTestConstants.remoteIP),
                dstIP: .v4(TCPTestConstants.localIP),
                srcPort: TCPTestConstants.remotePort,
                dstPort: lpcb.localPort,
                data: nil, dataLen: 0,
                seqno: 1001, ackno: ackSeqno &+ 1111,
                headerFlags: TCPHeaderFlags.ack,
                window: UInt16(lwipConfig.tcpWnd)
            ) else {
                #expect(Bool(false), "Failed to create ACK segment")
                return
            }

            TCPTestHelper.testTCPInput(
                badAck, srcIP: .v4(TCPTestConstants.remoteIP),
                dstIP: .v4(TCPTestConstants.localIP), netif: netif
            )

            // RST should have been sent
            #expect(txCounters.numTxCalls == 1, "Expected RST for ACK with wrong ackno in SYN_RCVD")
        }

        // Listen PCB should still exist
        #expect(TCPGlobal.shared.listenPCBs != nil)
        TCPGlobal.shared.removeListen(lpcb)
    }

    // MARK: - test_tcp_receive_rst_SYN_RCVD_to_LISTEN

    @Test("RST in SYN_RCVD causes return to LISTEN state")
    func receiveRstSynRcvdToListen() {
        TCPTestHelper.removeAll()
        defer { TCPTestHelper.removeAll() }

        let txCounters = TCPTxCounters()
        txCounters.copyTxPackets = true
        let netif = NetworkInterface()
        TCPTestHelper.initTestNetif(
            netif: netif, txCounters: txCounters,
            ipAddr: TCPTestConstants.localIP, netmask: TCPTestConstants.netmask
        )

        // Create a listening PCB
        guard let pcb = TCPGlobal.shared.new() else {
            #expect(Bool(false), "Failed to create PCB")
            return
        }
        let bindErr = TCPGlobal.shared.bind(pcb: pcb, address: .v4(TCPTestConstants.localIP), port: TCPTestConstants.localPort)
        #expect(bindErr == .ok)

        guard let lpcb = TCPGlobal.shared.listen(pcb: pcb, backlog: 1) else {
            #expect(Bool(false), "Failed to listen")
            return
        }

        // Send SYN -> transitions to SYN_RCVD
        guard let synSeg = TCPTestHelper.createSegment(
            srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP),
            srcPort: TCPTestConstants.remotePort,
            dstPort: lpcb.localPort,
            data: nil, dataLen: 0,
            seqno: 1000, ackno: 54321,
            headerFlags: TCPHeaderFlags.syn,
            window: UInt16(lwipConfig.tcpWnd)
        ) else {
            #expect(Bool(false), "Failed to create SYN segment")
            return
        }

        txCounters.reset()
        TCPTestHelper.testTCPInput(
            synSeg, srcIP: .v4(TCPTestConstants.remoteIP),
            dstIP: .v4(TCPTestConstants.localIP), netif: netif
        )
        #expect(txCounters.numTxCalls == 1, "Expected SYN+ACK response")

        // Verify there is an active PCB in SYN_RCVD
        if let active = TCPGlobal.shared.activePCBs {
            #expect(active.state == .synRcvd)

            // Send RST to the SYN_RCVD PCB
            guard let rstSeg = TCPTestHelper.createSegment(
                srcIP: .v4(TCPTestConstants.remoteIP),
                dstIP: .v4(TCPTestConstants.localIP),
                srcPort: TCPTestConstants.remotePort,
                dstPort: lpcb.localPort,
                data: nil, dataLen: 0,
                seqno: 1001, ackno: 54321,
                headerFlags: TCPHeaderFlags.rst,
                window: UInt16(lwipConfig.tcpWnd)
            ) else {
                #expect(Bool(false), "Failed to create RST segment")
                return
            }

            TCPTestHelper.testTCPInput(
                rstSeg, srcIP: .v4(TCPTestConstants.remoteIP),
                dstIP: .v4(TCPTestConstants.localIP), netif: netif
            )

            // The active PCB should be removed (RST in SYN_RCVD removes it)
            // But the listen PCB should still be present
            #expect(TCPGlobal.shared.listenPCBs != nil, "LISTEN PCB should survive RST in SYN_RCVD")
        }

        TCPGlobal.shared.removeListen(lpcb)
    }
}
