//
//  TCPInput.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Input Processing Flags

/// Flags set during input processing (not stored on PCB).
public struct TCPRecvFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let reset  = TCPRecvFlags(rawValue: 0x08)
    public static let closed = TCPRecvFlags(rawValue: 0x10)
    public static let gotFin = TCPRecvFlags(rawValue: 0x20)
}

// MARK: - TCP Input Processor

/// Handles all incoming TCP segment processing.
public final class TCPInput {
    public static let shared = TCPInput()

    // Input processing state (global within a single tcp_input call)
    private var insegPbuf: Pbuf?
    private var insegLen: UInt16 = 0
    private var insegSeqno: UInt32 = 0
    private var insegFlags: TCPHeaderFlags = []

    private var seqno: UInt32 = 0
    private var ackno: UInt32 = 0
    private var tcplen: UInt16 = 0
    private var flags: TCPHeaderFlags = []

    private var recvFlags: TCPRecvFlags = []
    private var recvData: Pbuf?
    private var recvAcked: UInt32 = 0

    // TCP header fields (parsed from incoming segment)
    private var srcPort: UInt16 = 0
    private var destPort: UInt16 = 0
    private var wnd: UInt16 = 0
    private var urgentPointer: UInt16 = 0

    // Option parsing state
    private var optLen: UInt16 = 0
    private var optBytes: [UInt8] = []

    private init() {}

    // MARK: - Main Input Entry Point

    /// Process an incoming TCP segment.
    /// Called by the IP layer when a TCP packet arrives.
    ///
    /// - Parameters:
    ///   - pbuf: The received packet with payload pointing to TCP header.
    ///   - netif: The network interface on which the segment was received.
    ///   - srcIP: Source IP address from IP header.
    ///   - dstIP: Destination IP address from IP header.
    public func input(pbuf: Pbuf, netif: NetworkInterface, srcIP: IPAddress, dstIP: IPAddress) {
        let global = TCPGlobal.shared

        guard pbuf.len >= TCPConstants.headerLength else {
            // Too short
            return
        }

        // Don't process broadcasts/multicasts
        let isBroadcastDst: Bool
        if case .v4(let v4) = dstIP { isBroadcastDst = v4.isBroadcast } else { isBroadcastDst = false }
        if isBroadcastDst || dstIP.isMulticast {
            return
        }

        // Verify TCP checksum (matching C lwIP tcp_input CHECKSUM_CHECK_TCP)
        if lwipConfig.checksumCheckTCP && netif.isChecksumEnabled(.checkTCP) {
            let chksum = InetChecksum.checksumPseudo(
                pbuf, proto: IPProtocolNumber.tcp,
                protoLen: pbuf.totLen,
                src: srcIP, dest: dstIP
            )
            if chksum != 0 {
                LWIPStats.shared.tcp.checksumErrors += 1
                LWIPStats.shared.tcp.dropped += 1
                LWIPStats.shared.mib2.tcpInErrs += 1
                pbuf.free()
                return
            }
        }

        // Parse TCP header
        let payload = pbuf.payload
        let hdr = payload.assumingMemoryBound(to: UInt16.self)

        srcPort = UInt16(bigEndian: hdr[0])
        destPort = UInt16(bigEndian: hdr[1])

        let seqnoRaw = payload.load(fromByteOffset: 4, as: UInt32.self)
        let acknoRaw = payload.load(fromByteOffset: 8, as: UInt32.self)
        seqno = UInt32(bigEndian: seqnoRaw)
        ackno = UInt32(bigEndian: acknoRaw)

        let hdrlenFlags = UInt16(bigEndian: hdr[6])
        let hdrLenWords = (hdrlenFlags >> 12) & 0x0F
        let hdrLenBytes = UInt16(hdrLenWords) * 4
        flags = TCPHeaderFlags(rawValue: UInt8(hdrlenFlags & UInt16(TCPHeaderFlags.standardMask.rawValue)))
        wnd = UInt16(bigEndian: hdr[7])

        // Process urgent pointer (bytes 18-19 of TCP header, hdr[9]).
        // Reset first so a non-URG segment does not carry a stale value.
        urgentPointer = 0
        if flags.contains(.urg) {
            let urgentPtr = UInt16(bigEndian: hdr[9])
            if urgentPtr > 0 {
                urgentPointer = urgentPtr
            }
        }

        guard hdrLenBytes >= TCPConstants.headerLength && hdrLenBytes <= pbuf.totLen else {
            return
        }

        // Parse options
        optLen = hdrLenBytes - TCPConstants.headerLength
        if optLen > 0 && pbuf.len >= hdrLenBytes {
            optBytes = Array(repeating: 0, count: Int(optLen))
            let optSrc = payload.advanced(by: Int(TCPConstants.headerLength))
            optBytes.withUnsafeMutableBufferPointer { buf in
                buf.baseAddress?.update(from: optSrc.assumingMemoryBound(to: UInt8.self),
                                        count: Int(optLen))
            }
        } else {
            optBytes = []
        }

        // Calculate TCP length (payload + SYN/FIN)
        let payloadLen = pbuf.totLen - hdrLenBytes
        tcplen = payloadLen
        if !flags.isDisjoint(with: [.fin, .syn]) {
            tcplen &+= 1
        }

        // Demultiplex: search active PCBs
        var pcb: TCPControlBlock? = nil
        var prev: TCPControlBlock? = nil
        var current = global.activePCBs

        while let c = current {
            if c.remotePort == srcPort &&
               c.localPort == destPort &&
               c.remoteIP == srcIP &&
               c.localIP == dstIP {
                // Found matching active PCB; move to front for cache
                if let p = prev {
                    p.next = c.next
                    c.next = global.activePCBs
                    global.activePCBs = c
                }
                pcb = c
                break
            }
            prev = c
            current = c.next
        }

        // If no active PCB, check TIME-WAIT
        if pcb == nil {
            current = global.timeWaitPCBs
            while let c = current {
                if c.remotePort == srcPort &&
                   c.localPort == destPort &&
                   c.remoteIP == srcIP &&
                   c.localIP == dstIP {
                    timewaitInput(pcb: c)
                    return
                }
                current = c.next
            }
        }

        // If still no match, check LISTENing PCBs
        if pcb == nil {
            var lpcb = global.listenPCBs
            while let l = lpcb {
                // Wildcard port: localPort == 0 matches any destination port.
                // This allows a single catch-all listener (bound to port 0) to
                // accept connections on every port — used by TUN-based proxies
                // that intercept all TCP traffic from the network interface.
                if l.localPort == destPort || l.localPort == 0 {
                    if l.localIP == .any || l.localIP == dstIP {
                        listenInput(lpcb: l, srcIP: srcIP, dstIP: dstIP)
                        return
                    }
                }
                lpcb = l.next
            }
        }

        if let pcb = pcb {
            // Set up input segment
            insegPbuf = Pbuf.freeHeader(pbuf, size: hdrLenBytes)
            if payloadLen > 0 && insegPbuf == nil {
                return
            }
            insegLen = payloadLen
            insegSeqno = seqno
            insegFlags = flags

            recvData = nil
            recvFlags = []
            recvAcked = 0

            // Process refused data first
            if pcb.refusedData != nil {
                let refErr = global.processRefusedData(pcb: pcb)
                if refErr == .aborted || (pcb.refusedData != nil && tcplen > 0) {
                    if pcb.receiveAnnouncedWindow == 0 {
                        _ = TCPOutput.shared.sendEmptyAck(pcb: pcb)
                    }
                    insegPbuf = nil
                    return
                }
            }

            global.inputPCB = pcb
            let err = process(pcb: pcb)

            if err != .aborted {
                if recvFlags.contains(.reset) {
                    // Connection reset
                    pcb.errorHandler?(.reset)
                    global.pcbRemove(pcb, list: &global.activePCBs)
                } else {
                    // Notify sent callback
                    if recvAcked > 0 {
                        var remaining = recvAcked
                        while remaining > 0 {
                            let chunk = UInt16(min(remaining, UInt32(UInt16.max)))
                            remaining -= UInt32(chunk)
                            let sentErr = pcb.sentHandler?(pcb, chunk) ?? .ok
                            if sentErr == .aborted {
                                global.inputPCB = nil
                                insegPbuf = nil
                                return
                            }
                        }
                        recvAcked = 0
                    }

                    // Check for delayed close
                    if inputDelayedClose(pcb: pcb) {
                        global.inputPCB = nil
                        insegPbuf = nil
                        return
                    }

                    // Deliver received data
                    if let data = recvData {
                        if pcb.flags.contains(.rxClosed) {
                            // Data received after rx closed: abort
                            global.abort(pcb: pcb)
                            global.inputPCB = nil
                            insegPbuf = nil
                            return
                        }

                        let recvErr = pcb.receiveHandler?(pcb, data, .ok) ?? .ok
                        if recvErr == .aborted {
                            global.inputPCB = nil
                            insegPbuf = nil
                            return
                        }
                        if recvErr != .ok {
                            pcb.refusedData = data
                        }
                        recvData = nil
                    }

                    // FIN received
                    if recvFlags.contains(.gotFin) {
                        if pcb.refusedData != nil {
                            pcb.refusedData?.flags.insert(.tcpFin)
                        } else {
                            if pcb.receiveWindow != pcb.receiveWindowMax {
                                pcb.receiveWindow += 1
                            }
                            let closedErr = pcb.receiveHandler?(pcb, nil, .ok) ?? .ok
                            if closedErr == .aborted {
                                global.inputPCB = nil
                                insegPbuf = nil
                                return
                            }
                        }
                    }

                    global.inputPCB = nil

                    // Check for delayed close again
                    if inputDelayedClose(pcb: pcb) {
                        insegPbuf = nil
                        return
                    }

                    // Try to send queued data
                    _ = TCPOutput.shared.output(pcb: pcb)
                }
            }

            global.inputPCB = nil
            recvData = nil
            insegPbuf = nil
        } else {
            // No matching PCB: send RST
            if !flags.contains(.rst) {
                TCPOutput.shared.rst(seqno: ackno, ackno: seqno &+ UInt32(tcplen),
                                     localIP: dstIP, remoteIP: srcIP,
                                     localPort: destPort, remotePort: srcPort)
            }
        }
    }

    // MARK: - Listen Input

    /// Handle a segment arriving for a listening connection.
    private func listenInput(lpcb: TCPListenControlBlock, srcIP: IPAddress, dstIP: IPAddress) {
        let global = TCPGlobal.shared

        // Ignore RST
        if flags.contains(.rst) { return }

        // ACK in LISTEN: send RST
        if flags.contains(.ack) {
            TCPOutput.shared.rst(seqno: ackno, ackno: seqno &+ UInt32(tcplen),
                                 localIP: dstIP, remoteIP: srcIP,
                                 localPort: destPort, remotePort: srcPort)
            return
        }

        // SYN: create new connection
        if flags.contains(.syn) {
            // Check backlog
            if lpcb.acceptsPending >= lpcb.backlog {
                return
            }

            guard let npcb = global.alloc(priority: lpcb.priority) else {
                _ = lpcb.acceptHandler?(lpcb, nil, .outOfMemory)
                return
            }

            lpcb.acceptsPending += 1
            npcb.flags.insert(.backlogPending)

            npcb.localIP = dstIP
            npcb.remoteIP = srcIP
            // When the listener uses wildcard port 0, assign the actual
            // destination port from the SYN so the new PCB matches
            // subsequent packets for this connection in activePCBs.
            npcb.localPort = lpcb.localPort == 0 ? destPort : lpcb.localPort
            npcb.remotePort = srcPort
            npcb.state = .synRcvd
            npcb.receiveNext = seqno &+ 1
            npcb.receiveAnnouncedRightEdge = npcb.receiveNext

            let iss = global.nextISS(pcb: npcb)
            npcb.sendWindowUpdateAck = iss
            npcb.sendNext = iss
            npcb.lastAcknowledged = iss
            npcb.sendLastByteBuffered = iss
            npcb.sendWindowUpdateSequence = seqno &- 1
            npcb.callbackArg = lpcb.callbackArg
            npcb.listener = lpcb
            npcb.socketOptions = lpcb.socketOptions & 0x0F // SOF_INHERITED
            npcb.netifIdx = lpcb.netifIdx

            global.registerActive(npcb)

            // Parse SYN options
            parseOptions(pcb: npcb)
            npcb.sendWindow = UInt32(wnd)
            npcb.sendWindowMax = npcb.sendWindow

            // Send SYN|ACK
            let rc = TCPOutput.shared.enqueueFlags(pcb: npcb, flags: [.syn, .ack])
            if rc != .ok {
                global.abandon(pcb: npcb, sendReset: false)
                return
            }
            _ = TCPOutput.shared.output(pcb: npcb)
        }
    }

    // MARK: - TIME-WAIT Input

    /// Handle a segment arriving for a TIME-WAIT connection.
    private func timewaitInput(pcb: TCPControlBlock) {
        // Ignore RST in TIME-WAIT (RFC 1337)
        if flags.contains(.rst) { return }

        // SYN in window: send RST
        if flags.contains(.syn) {
            if TCPSequence.isBetween(seqno, pcb.receiveNext, pcb.receiveNext &+ pcb.receiveWindow) {
                TCPOutput.shared.rst(seqno: ackno, ackno: seqno &+ UInt32(tcplen),
                                     localIP: pcb.localIP, remoteIP: pcb.remoteIP,
                                     localPort: pcb.localPort, remotePort: pcb.remotePort)
                return
            }
        } else if flags.contains(.fin) {
            // FIN: restart 2 MSL timeout
            pcb.timer = TCPGlobal.shared.ticks
        }

        if tcplen > 0 {
            pcb.acknowledgeNow()
            _ = TCPOutput.shared.output(pcb: pcb)
        }
    }

    // MARK: - TCP State Machine (tcp_process)

    /// Implements the TCP state machine.
    private func process(pcb: TCPControlBlock) -> LWIPError {
        let global = TCPGlobal.shared

        // Process RST
        if flags.contains(.rst) {
            var acceptable = false
            if pcb.state == .synSent {
                if ackno == pcb.sendNext { acceptable = true }
            } else {
                if seqno == pcb.receiveNext {
                    acceptable = true
                } else if TCPSequence.isBetween(seqno, pcb.receiveNext, pcb.receiveNext &+ pcb.receiveWindow) {
                    // Challenge ACK (RFC 5961)
                    pcb.acknowledgeNow()
                }
            }

            if acceptable {
                recvFlags.insert(.reset)
                pcb.flags.remove(.ackDelay)
                return .reset
            }
            return .ok
        }

        // SYN in established state: challenge ACK
        if flags.contains(.syn) && pcb.state != .synSent && pcb.state != .synRcvd {
            pcb.acknowledgeNow()
            return .ok
        }

        // Update activity timer (unless rx is closed)
        if !pcb.flags.contains(.rxClosed) {
            pcb.timer = global.ticks
        }
        pcb.keepaliveCountSent = 0
        pcb.persistProbe = 0

        // Parse options
        parseOptions(pcb: pcb)

        // Store urgent pointer on the PCB if the URG flag was set.
        if flags.contains(.urg) && urgentPointer > 0 {
            pcb.urgentPointerReceived = urgentPointer
        }

        // State machine
        switch pcb.state {
        case .synSent:
            return processSynSent(pcb: pcb)
        case .synRcvd:
            return processSynRcvd(pcb: pcb)
        case .established, .closeWait:
            receive(pcb: pcb)
            if recvFlags.contains(.gotFin) {
                pcb.acknowledgeNow()
                pcb.state = .closeWait
            }
            return .ok
        case .finWait1:
            receive(pcb: pcb)
            if recvFlags.contains(.gotFin) {
                if flags.contains(.ack) && ackno == pcb.sendNext && pcb.unsent == nil {
                    pcb.acknowledgeNow()
                    global.pcbPurge(pcb)
                    global.removeActive(pcb)
                    pcb.state = .timeWait
                    global.register(pcb, list: &global.timeWaitPCBs)
                } else {
                    pcb.acknowledgeNow()
                    pcb.state = .closing
                }
            } else if flags.contains(.ack) && ackno == pcb.sendNext && pcb.unsent == nil {
                pcb.state = .finWait2
            }
            return .ok
        case .finWait2:
            receive(pcb: pcb)
            if recvFlags.contains(.gotFin) {
                pcb.acknowledgeNow()
                global.pcbPurge(pcb)
                global.removeActive(pcb)
                pcb.state = .timeWait
                global.register(pcb, list: &global.timeWaitPCBs)
            }
            return .ok
        case .closing:
            receive(pcb: pcb)
            if flags.contains(.ack) && ackno == pcb.sendNext && pcb.unsent == nil {
                global.pcbPurge(pcb)
                global.removeActive(pcb)
                pcb.state = .timeWait
                global.register(pcb, list: &global.timeWaitPCBs)
            }
            return .ok
        case .lastAck:
            receive(pcb: pcb)
            if flags.contains(.ack) && ackno == pcb.sendNext && pcb.unsent == nil {
                recvFlags.insert(.closed)
            }
            return .ok
        default:
            return .ok
        }
    }

    // MARK: - SYN_SENT processing

    private func processSynSent(pcb: TCPControlBlock) -> LWIPError {
        if flags.contains(.ack) && flags.contains(.syn) && ackno == pcb.lastAcknowledged &+ 1 {
            pcb.receiveNext = seqno &+ 1
            pcb.receiveAnnouncedRightEdge = pcb.receiveNext
            pcb.lastAcknowledged = ackno
            pcb.sendWindow = UInt32(wnd)
            pcb.sendWindowMax = pcb.sendWindow
            pcb.sendWindowUpdateSequence = seqno &- 1
            pcb.state = .established

            // Initial CWND: RFC 2581
            let mss32 = UInt32(pcb.maxSegmentSize)
            pcb.congestionWindow = min(4 * mss32, max(2 * mss32, 4380))

            // Free the SYN segment from unacked queue
            if pcb.sendQueueLength > 0 {
                pcb.sendQueueLength -= 1
            }
            if let rseg = pcb.unacked {
                pcb.unacked = rseg.next
                rseg.free()
            } else if let rseg = pcb.unsent {
                pcb.unsent = rseg.next
                rseg.free()
            }

            if pcb.unacked == nil {
                pcb.retransmissionTime = -1
            } else {
                pcb.retransmissionTime = 0
                pcb.retransmissionCount = 0
            }

            let err = pcb.connectedHandler?(pcb, .ok) ?? .ok
            if err == .aborted { return .aborted }
            pcb.acknowledgeNow()
        } else if flags.contains(.ack) {
            // Half-open: send RST + resend SYN
            TCPOutput.shared.rst(seqno: ackno, ackno: seqno &+ UInt32(tcplen),
                                 localIP: pcb.localIP, remoteIP: pcb.remoteIP,
                                 localPort: pcb.localPort, remotePort: pcb.remotePort)
            if pcb.retransmissionCount < TCPConstants.synMaxRetransmissions {
                pcb.retransmissionTime = 0
                TCPOutput.shared.rexmitRto(pcb: pcb)
            }
        }
        return .ok
    }

    // MARK: - SYN_RCVD processing

    private func processSynRcvd(pcb: TCPControlBlock) -> LWIPError {
        let global = TCPGlobal.shared

        if flags.contains(.syn) {
            if seqno == pcb.receiveNext &- 1 {
                // Retransmitted SYN: retransmit our SYN-ACK
                _ = TCPOutput.shared.rexmit(pcb: pcb)
            }
        } else if flags.contains(.ack) {
            if TCPSequence.isBetween(ackno, pcb.lastAcknowledged &+ 1, pcb.sendNext) {
                pcb.state = .established

                // Accept callback
                if let listener = pcb.listener {
                    let err = listener.acceptHandler?(listener, pcb, .ok) ?? .ok
                    if err != .ok {
                        if err != .aborted {
                            global.abort(pcb: pcb)
                        }
                        return .aborted
                    }
                }

                receive(pcb: pcb)

                // Prevent ACK for SYN from generating a sent event
                if recvAcked != 0 { recvAcked -= 1 }

                let mss32 = UInt32(pcb.maxSegmentSize)
                pcb.congestionWindow = min(4 * mss32, max(2 * mss32, 4380))

                if recvFlags.contains(.gotFin) {
                    pcb.acknowledgeNow()
                    pcb.state = .closeWait
                }
            } else {
                // Incorrect ACK: send RST
                TCPOutput.shared.rst(seqno: ackno, ackno: seqno &+ UInt32(tcplen),
                                     localIP: pcb.localIP, remoteIP: pcb.remoteIP,
                                     localPort: pcb.localPort, remotePort: pcb.remotePort)
            }
        }
        return .ok
    }

    // MARK: - Delayed Close (tcp_input_delayed_close)

    /// Handle the case where a FIN was received and the connection state
    /// has transitioned to "closed", but we could not deallocate the PCB
    /// immediately (for example because we were still delivering data to
    /// the application).
    ///
    /// When `recvFlags` contains `.closed` the PCB is removed from the
    /// active list and freed.  If the application had only shut down the
    /// transmit side (i.e. `TF_RXCLOSED` is *not* set), the PCB's error
    /// callback is invoked with `.closed` so the application knows the
    /// connection is gone.
    ///
    /// - Parameter pcb: The TCP control block to check.
    /// - Returns: `true` if the PCB was deallocated (caller must not
    ///   touch `pcb` afterwards), `false` otherwise.
    private func inputDelayedClose(pcb: TCPControlBlock) -> Bool {
        guard recvFlags.contains(.closed) else {
            return false
        }

        let global = TCPGlobal.shared

        // Connection closed although the application has only shut down the
        // tx side: call the PCB's error callback and indicate the closure to
        // ensure the application doesn't continue using the PCB.
        if !pcb.flags.contains(.rxClosed) {
            pcb.errorHandler?(.closed)
        }

        global.pcbRemove(pcb, list: &global.activePCBs)
        return true
    }

    // MARK: - SACK Management (tcp_add_sack / tcp_remove_sacks)

    /// Add a SACK block (`left` edge, `right` edge) to the pcb's SACK array.
    ///
    /// Overlapping or adjacent blocks are removed before the new block is
    /// inserted at index 0 (most-recently-received first).  If SACK
    /// support is not negotiated on this connection the call is a no-op.
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block.
    ///   - left: Left (lower) sequence-number edge of the SACK block.
    ///   - right: Right (upper, exclusive) sequence-number edge.
    private func addSACK(pcb: TCPControlBlock, left: UInt32, right: UInt32) {
        pcb.addSACK(left, right)
    }

    /// Remove all SACK blocks with `left` edge >= `seq`.
    ///
    /// Blocks whose left edge is before `seq` but whose right edge
    /// extends past `seq` are trimmed so their right edge becomes `seq`.
    /// This is used when we need to discard out-of-order data above a
    /// certain sequence number (e.g. OOS queue byte/pbuf limit
    /// enforcement).
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block.
    ///   - seq: The sequence number threshold.
    private func removeSACKsAbove(pcb: TCPControlBlock, seq: UInt32) {
        pcb.removeSACKsAfter(seq)
    }

    /// Remove all SACK blocks with `right` edge <= `seq`.
    ///
    /// Blocks whose right edge is past `seq` but whose left edge is
    /// before `seq` are trimmed so their left edge becomes `seq`.
    /// This is called when in-sequence data is consumed from the OOS
    /// queue, so SACK ranges that have been subsumed by `rcv_nxt`
    /// advancing are no longer needed.
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block.
    ///   - seq: The sequence number threshold.
    private func removeSACKsBelow(pcb: TCPControlBlock, seq: UInt32) {
        pcb.removeSACKsBefore(seq)
    }

    // MARK: - Data Reception (tcp_receive)

    /// Process ACKs and incoming data.
    private func receive(pcb: TCPControlBlock) {
        guard flags.contains(.ack) else {
            receiveData(pcb: pcb)
            return
        }

        let rightWndEdge = pcb.sendWindow &+ pcb.sendWindowUpdateAck

        // Window update
        if TCPSequence.isLessThan(pcb.sendWindowUpdateSequence, seqno) ||
           (pcb.sendWindowUpdateSequence == seqno && TCPSequence.isLessThan(pcb.sendWindowUpdateAck, ackno)) ||
           (pcb.sendWindowUpdateAck == ackno && UInt32(wnd) > pcb.sendWindow) {
            pcb.sendWindow = UInt32(wnd)
            if pcb.sendWindowMax < pcb.sendWindow {
                pcb.sendWindowMax = pcb.sendWindow
            }
            pcb.sendWindowUpdateSequence = seqno
            pcb.sendWindowUpdateAck = ackno

            // Reset persist timer when the window opens so that queued data
            // can be sent immediately via the normal output path rather than
            // waiting for the next slow-timer tick.
            if pcb.sendWindow > 0 && pcb.persistBackoff > 0 {
                pcb.persistBackoff = 0
                pcb.persistCnt = 0
            }
        }

        // Duplicate ACK detection (Stevens TCP/IP Illustrated Vol II)
        if TCPSequence.isLessThanOrEqual(ackno, pcb.lastAcknowledged) {
            if tcplen == 0 {
                if pcb.sendWindowUpdateAck &+ pcb.sendWindow == rightWndEdge {
                    if pcb.retransmissionTime >= 0 {
                        if pcb.lastAcknowledged == ackno {
                            if pcb.duplicateAckCount < 255 { pcb.duplicateAckCount += 1 }
                            if pcb.duplicateAckCount > 3 {
                                // Inflate congestion window
                                let newCwnd = pcb.congestionWindow &+ UInt32(pcb.maxSegmentSize)
                                if newCwnd >= pcb.congestionWindow { pcb.congestionWindow = newCwnd }
                            }
                            if pcb.duplicateAckCount >= 3 {
                                TCPOutput.shared.rexmitFast(pcb: pcb)
                            }
                        }
                    }
                }
            }
        } else if TCPSequence.isBetween(ackno, pcb.lastAcknowledged &+ 1, pcb.sendNext) {
            // ACK for new data
            let acked = ackno &- pcb.lastAcknowledged

            // Exit fast recovery
            if pcb.flags.contains(.inFastRecovery) {
                pcb.flags.remove(.inFastRecovery)
                pcb.congestionWindow = pcb.slowStartThreshold
                pcb.acknowledgedBytes = 0
            }

            pcb.retransmissionCount = 0
            // Reset RTO from smoothed estimators, clamped to [2, 120] ticks
            let resetRto = Int16((Int(pcb.smoothedRoundTripTime) >> 3) + Int(pcb.roundTripTimeDeviation))
            pcb.retransmissionTimeout = max(2, min(resetRto, 120))
            pcb.duplicateAckCount = 0
            pcb.lastAcknowledged = ackno

            // Congestion control
            if pcb.state.rawValue >= TCPState.established.rawValue {
                if pcb.congestionWindow < pcb.slowStartThreshold {
                    // Slow start
                    let numSeg: UInt32 = pcb.flags.contains(.rto) ? 1 : 2
                    let increase = min(acked, numSeg * UInt32(pcb.maxSegmentSize))
                    let newCwnd = pcb.congestionWindow &+ increase
                    if newCwnd >= pcb.congestionWindow { pcb.congestionWindow = newCwnd }
                } else {
                    // Congestion avoidance
                    let newBytesAcked = pcb.acknowledgedBytes &+ acked
                    if newBytesAcked >= pcb.acknowledgedBytes { pcb.acknowledgedBytes = newBytesAcked }
                    if pcb.acknowledgedBytes >= pcb.congestionWindow {
                        pcb.acknowledgedBytes = pcb.acknowledgedBytes &- pcb.congestionWindow
                        let newCwnd = pcb.congestionWindow &+ UInt32(pcb.maxSegmentSize)
                        if newCwnd >= pcb.congestionWindow { pcb.congestionWindow = newCwnd }
                    }
                }
            }

            // Free acknowledged segments from unacked queue
            freeAckedSegments(pcb: pcb, queue: &pcb.unacked)
            freeAckedSegments(pcb: pcb, queue: &pcb.unsent)

            // Update retransmission timer
            if pcb.unacked == nil {
                pcb.retransmissionTime = -1
            } else {
                pcb.retransmissionTime = 0
            }

            pcb.pollTimer = 0

            if pcb.unsent == nil {
                pcb.unsentOversize = 0
            }

            // Update send buffer
            pcb.sendBufferSpace = pcb.sendBufferSpace &+ acked

            // Check if RTO is done
            if pcb.flags.contains(.rto) {
                if pcb.unacked == nil {
                    if pcb.unsent == nil || TCPSequence.isLessThanOrEqual(pcb.retransmissionTimeoutEnd, pcb.unsent!.sequenceNumber) {
                        pcb.flags.remove(.rto)
                    }
                } else if TCPSequence.isLessThanOrEqual(pcb.retransmissionTimeoutEnd, pcb.unacked!.sequenceNumber) {
                    pcb.flags.remove(.rto)
                }
            }
        } else {
            // Out of sequence ACK
            _ = TCPOutput.shared.sendEmptyAck(pcb: pcb)
        }

        // RTT estimation (Van Jacobson, RFC 6298)
        //
        // When an ACK acknowledges the segment we are timing (roundTripTimeTest),
        // compute the smoothed RTT and deviation, then derive the RTO.
        //
        // The scaled fixed-point representation follows VJ's original paper:
        //   smoothedRoundTripTime is SRTT * 8  (i.e. sa = srtt << 3)
        //   roundTripTimeDeviation is RTTVAR * 4  (i.e. sv = rttvar << 2)
        //   retransmissionTimeout = sa/8 + sv  = SRTT + 4*RTTVAR
        if pcb.roundTripTimeTest != 0 && TCPSequence.isLessThan(pcb.roundTripTimeSequence, ackno) {
            let rawRTT = Int16(truncatingIfNeeded: TCPGlobal.shared.ticks &- pcb.roundTripTimeTest)

            if pcb.smoothedRoundTripTime == 0 {
                // First RTT measurement (RFC 6298 Section 2.2):
                //   SRTT = R  =>  sa = R * 8
                //   RTTVAR = R/2  =>  sv = (R/2) * 4 = R * 2
                pcb.smoothedRoundTripTime = Int16(Int(rawRTT) * 8)
                pcb.roundTripTimeDeviation = Int16(Int(rawRTT) * 2)
            } else {
                // Subsequent measurements (VJ algorithm, RFC 6298 Section 2.3):
                //   err = m - sa/8
                //   sa  = sa + err         (sa += m - sa/8)
                //   dev = |err| - sv/4
                //   sv  = sv + dev         (sv += |err| - sv/4)
                var m = Int16(Int(rawRTT) - (Int(pcb.smoothedRoundTripTime) >> 3))
                pcb.smoothedRoundTripTime = Int16(Int(pcb.smoothedRoundTripTime) + Int(m))
                if m < 0 { m = -m }
                m = Int16(Int(m) - (Int(pcb.roundTripTimeDeviation) >> 2))
                pcb.roundTripTimeDeviation = Int16(Int(pcb.roundTripTimeDeviation) + Int(m))
            }

            // RTO = SRTT + 4 * RTTVAR = sa/8 + sv
            var rto = Int16((Int(pcb.smoothedRoundTripTime) >> 3) + Int(pcb.roundTripTimeDeviation))
            // Clamp RTO: minimum 2 ticks (1 second at 500ms interval),
            // maximum 120 ticks (60 seconds at 500ms interval)
            rto = max(2, min(rto, 120))
            pcb.retransmissionTimeout = rto

            pcb.roundTripTimeTest = 0
        }

        // Process incoming data
        receiveData(pcb: pcb)
    }

    // MARK: - Data segment processing

    /// Process the data portion of an incoming segment.
    private func receiveData(pcb: TCPControlBlock) {
        guard tcplen > 0 && pcb.state.rawValue < TCPState.closeWait.rawValue else {
            // No data or ignoring text in CLOSE_WAIT+
            if tcplen == 0 && !TCPSequence.isBetween(seqno, pcb.receiveNext, pcb.receiveNext &+ pcb.receiveWindow &- 1) {
                pcb.acknowledgeNow()
            }
            return
        }

        // Trim leading edge if needed
        if TCPSequence.isBetween(pcb.receiveNext, seqno &+ 1, seqno &+ UInt32(tcplen) &- 1) {
            let trim = pcb.receiveNext &- seqno
            guard trimIncomingLeadingBytes(trim) else {
                pcb.acknowledgeNow()
                return
            }
        } else if TCPSequence.isLessThan(seqno, pcb.receiveNext) {
            // Entire segment is a duplicate
            pcb.acknowledgeNow()
            return
        }

        // Check if within window
        guard TCPSequence.isBetween(seqno, pcb.receiveNext, pcb.receiveNext &+ pcb.receiveWindow &- 1) else {
            _ = TCPOutput.shared.sendEmptyAck(pcb: pcb)
            return
        }

        if pcb.receiveNext == seqno {
            // In-sequence data
            var segTcpLen = incomingTCPLength

            // Trim to fit window
            if UInt32(segTcpLen) > pcb.receiveWindow {
                var effectiveLen = UInt16(truncatingIfNeeded: pcb.receiveWindow)
                if insegFlags.contains(.syn) { effectiveLen -= 1 }
                trimIncomingTail(to: effectiveLen)
                segTcpLen = incomingTCPLength
            }

            if pcb.ooseq != nil {
                if insegFlags.contains(.fin) {
                    TCPSegment.freeChain(pcb.ooseq)
                    pcb.ooseq = nil
                } else {
                    var next = pcb.ooseq
                    while let candidate = next,
                          TCPSequence.isGreaterThanOrEqual(seqno &+ UInt32(segTcpLen),
                                                           candidate.sequenceNumber &+ UInt32(candidate.len)) {
                        if candidate.headerFlags.contains(.fin) && !insegFlags.contains(.syn) {
                            insegFlags.insert(.fin)
                            segTcpLen = incomingTCPLength
                        }
                        next = candidate.next
                        candidate.next = nil
                        candidate.free()
                    }

                    if let candidate = next,
                       TCPSequence.isGreaterThan(seqno &+ UInt32(segTcpLen), candidate.sequenceNumber) {
                        trimIncomingTail(to: UInt16(truncatingIfNeeded: candidate.sequenceNumber &- seqno))
                        segTcpLen = incomingTCPLength
                    }

                    pcb.ooseq = next
                }
            }

            // Update rcv_nxt
            pcb.receiveNext = seqno &+ UInt32(segTcpLen)
            pcb.receiveWindow -= UInt32(segTcpLen)
            pcb.updateRcvAnnWnd()

            // Pass data to application
            if insegLen > 0 {
                recvData = insegPbuf
                insegPbuf = nil
            }

            // FIN processing
            if insegFlags.contains(.fin) {
                recvFlags.insert(.gotFin)
            }

            // Process out-of-sequence queue
            processOoseq(pcb: pcb)

            // ACK the segment
            pcb.acknowledge()
        } else {
            // Out-of-sequence: queue and send immediate ACK
            queueOoseq(pcb: pcb)
            trimOoseqIfOverLimit(pcb: pcb)
            _ = TCPOutput.shared.sendEmptyAck(pcb: pcb)
        }
    }

    // MARK: - Out-of-order queue

    private var incomingTCPLength: UInt16 {
        insegLen &+ (!insegFlags.isDisjoint(with: [.fin, .syn]) ? 1 : 0)
    }

    @discardableResult
    private func trimIncomingLeadingBytes(_ trim: UInt32) -> Bool {
        guard trim > 0 else { return true }
        let trimLen = UInt16(truncatingIfNeeded: trim)
        guard trimLen <= insegLen else { return false }

        if let pbuf = insegPbuf {
            insegPbuf = Pbuf.freeHeader(pbuf, size: trimLen)
            if insegLen > trimLen && insegPbuf == nil {
                return false
            }
        }

        insegLen -= trimLen
        insegSeqno &+= trim
        seqno &+= trim
        tcplen = incomingTCPLength
        return true
    }

    private func trimIncomingTail(to newLen: UInt16) {
        guard newLen <= insegLen else { return }
        if newLen < insegLen {
            insegPbuf?.realloc(to: newLen)
            insegLen = newLen
            insegFlags.remove(.fin)
        } else if insegFlags.contains(.fin) {
            insegFlags.remove(.fin)
        }
        tcplen = incomingTCPLength
    }

    private func copyIncomingSegment() -> TCPSegment {
        let cseg = TCPSegment()
        cseg.len = insegLen
        cseg.sequenceNumber = seqno
        cseg.headerFlags = insegFlags
        if let p = insegPbuf {
            cseg.pbuf = p
            p.ref()
        }
        return cseg
    }

    private func segmentDataEnd(_ segment: TCPSegment) -> UInt32 {
        segment.sequenceNumber &+ UInt32(segment.len)
    }

    private func trimSegmentTail(_ segment: TCPSegment, to newLen: UInt16) {
        guard newLen <= segment.len else { return }
        if newLen < segment.len {
            segment.pbuf?.realloc(to: newLen)
            segment.len = newLen
            segment.headerFlags.remove(.fin)
        } else if segment.headerFlags.contains(.fin) {
            segment.headerFlags.remove(.fin)
        }
    }

    private func insertOoseqSegment(_ cseg: TCPSegment, next: TCPSegment?) {
        var nextSegment = next

        if cseg.headerFlags.contains(.fin) {
            TCPSegment.freeChain(nextSegment)
            nextSegment = nil
        } else {
            while let candidate = nextSegment,
                  TCPSequence.isGreaterThanOrEqual(segmentDataEnd(cseg), candidate.sequenceNumber &+ UInt32(candidate.len)) {
                if candidate.headerFlags.contains(.fin) {
                    cseg.headerFlags.insert(.fin)
                }
                nextSegment = candidate.next
                candidate.next = nil
                candidate.free()
            }

            if let candidate = nextSegment,
               TCPSequence.isGreaterThan(segmentDataEnd(cseg), candidate.sequenceNumber) {
                trimSegmentTail(cseg, to: UInt16(truncatingIfNeeded: candidate.sequenceNumber &- cseg.sequenceNumber))
            }
        }

        cseg.next = nextSegment
    }

    private func addSACKForInsertedOoseqSegment(_ pcb: TCPControlBlock, segment: TCPSegment) {
        guard segment.len > 0 else { return }

        var sackEnd = segment.sequenceNumber
        var next: TCPSegment? = segment
        while let candidate = next, sackEnd == candidate.sequenceNumber, candidate.len > 0 {
            sackEnd = candidate.sequenceNumber &+ UInt32(candidate.len)
            next = candidate.next
        }
        addSACK(pcb: pcb, left: segment.sequenceNumber, right: sackEnd)
    }

    /// Insert a received out-of-order segment into the correct position in
    /// the pcb's OOS (out-of-order segments) queue.
    ///
    /// The queue is kept sorted by sequence number.  Overlapping segments
    /// are trimmed or discarded entirely to avoid storing duplicate data.
    /// If the new segment carries a FIN, all subsequent segments in the
    /// queue are freed (the FIN implies there is no more data).
    ///
    /// After insertion the pcb's SACK state is updated so the peer can be
    /// informed about the gaps via the next ACK.
    ///
    /// - Parameters:
    ///   - seg: The new segment to insert.  Its `sequenceNumber`, `len`,
    ///     `headerFlags` and `pbuf` must already be set.
    ///   - pcb: The TCP control block whose `ooseq` list is being managed.
    private func oosInsertSegment(seg: TCPSegment, pcb: TCPControlBlock) {
        // Phase 1 -- Find the insertion point and splice the segment in.
        //
        // The invariant is that `pcb.ooseq` is sorted in ascending sequence
        // number order and no two segments overlap.

        if pcb.ooseq == nil {
            // Empty queue -- the new segment becomes the sole entry.
            pcb.ooseq = seg
        } else {
            var prev: TCPSegment? = nil
            var next = pcb.ooseq
            var inserted = false

            while let candidate = next {
                // Exact match on sequence number.
                if seg.sequenceNumber == candidate.sequenceNumber {
                    if seg.len > candidate.len {
                        // The new segment is larger -- replace the old one.
                        if candidate.next == nil {
                            // Last segment; cannot safely replace -- discard new.
                            seg.free()
                            return
                        }
                        if let p = prev {
                            p.next = seg
                        } else {
                            pcb.ooseq = seg
                        }
                        insertOoseqSegment(seg, next: candidate)
                        candidate.next = nil
                        candidate.free()
                    } else {
                        // Old segment is already at least as large -- discard new.
                        seg.free()
                        return
                    }
                    inserted = true
                    break
                }

                // Before the first element?
                if prev == nil {
                    if TCPSequence.isLessThan(seg.sequenceNumber, candidate.sequenceNumber) {
                        pcb.ooseq = seg
                        insertOoseqSegment(seg, next: candidate)
                        inserted = true
                        break
                    }
                } else if let p = prev,
                          TCPSequence.isBetween(seg.sequenceNumber,
                                                p.sequenceNumber &+ 1,
                                                candidate.sequenceNumber &- 1) {
                    // Between `prev` and `candidate` -- trim prev's tail if it
                    // overlaps, then insert.
                    if TCPSequence.isGreaterThan(segmentDataEnd(p), seg.sequenceNumber) {
                        trimSegmentTail(p, to: UInt16(truncatingIfNeeded: seg.sequenceNumber &- p.sequenceNumber))
                    }
                    p.next = seg
                    insertOoseqSegment(seg, next: candidate)
                    inserted = true
                    break
                }

                prev = candidate

                // Append after the last element?
                if candidate.next == nil &&
                   TCPSequence.isGreaterThan(seg.sequenceNumber, candidate.sequenceNumber) {
                    if candidate.headerFlags.contains(.fin) {
                        // The queue already has a FIN; no more data expected.
                        seg.free()
                        return
                    }
                    candidate.next = seg
                    if TCPSequence.isGreaterThan(segmentDataEnd(candidate), seg.sequenceNumber) {
                        trimSegmentTail(candidate, to: UInt16(truncatingIfNeeded: seg.sequenceNumber &- candidate.sequenceNumber))
                    }
                    inserted = true
                    break
                }

                next = candidate.next
            }

            if !inserted {
                seg.free()
                return
            }
        }

        // Phase 2 -- Update SACK state for the newly inserted segment.
        addSACKForInsertedOoseqSegment(pcb, segment: seg)
    }

    /// Queue an out-of-order segment.
    ///
    /// Trims the incoming segment to fit within the receive window,
    /// copies it, and delegates to `oosInsertSegment(seg:pcb:)` for the
    /// actual sorted insertion and SACK bookkeeping.
    private func queueOoseq(pcb: TCPControlBlock) {
        let rightEdge = pcb.receiveNext &+ pcb.receiveWindow
        let maxSegLen = UInt16(min(rightEdge &- seqno, UInt32(UInt16.max)))
        if incomingTCPLength > maxSegLen {
            var effectiveLen = maxSegLen
            if insegFlags.contains(.syn) {
                effectiveLen -= 1
            }
            trimIncomingTail(to: effectiveLen)
        }

        guard incomingTCPLength > 0 else { return }

        let cseg = copyIncomingSegment()
        oosInsertSegment(seg: cseg, pcb: pcb)
    }

    /// Enforce ``LWIPConfig/tcpOoseqBytesLimit`` and
    /// ``LWIPConfig/tcpOoseqPbufsLimit`` on the out-of-order queue.
    ///
    /// Walks `pcb.ooseq` front-to-back accumulating total bytes
    /// (`pbuf.totLen`) and total pbuf chain length.  As soon as either
    /// limit is exceeded the current segment and everything after it is
    /// freed, and the corresponding SACK entries are removed.
    private func trimOoseqIfOverLimit(pcb: TCPControlBlock) {
        let maxBytes = lwipConfig.tcpOoseqBytesLimit
        let maxPbufs = lwipConfig.tcpOoseqPbufsLimit
        guard maxBytes > 0 || maxPbufs > 0 else { return }

        var ooseqBytes: Int = 0
        var ooseqPbufs: UInt16 = 0
        var prev: TCPSegment? = nil
        var next = pcb.ooseq

        while let seg = next {
            var stopHere = false
            if let p = seg.pbuf {
                if maxBytes > 0 {
                    ooseqBytes += Int(p.totLen)
                    if ooseqBytes > maxBytes {
                        stopHere = true
                    }
                }
                if maxPbufs > 0 {
                    ooseqPbufs += p.chainLength
                    if ooseqPbufs > UInt16(maxPbufs) {
                        stopHere = true
                    }
                }
            }

            if stopHere {
                // Remove SACK entries that cover the discarded segments.
                if pcb.flags.contains(.sack) {
                    removeSACKsAbove(pcb: pcb, seq: seg.sequenceNumber)
                }
                // Free this segment and everything after it.
                TCPSegment.freeChain(seg)
                if let p = prev {
                    p.next = nil
                } else {
                    // First segment already exceeds the limit.
                    pcb.ooseq = nil
                }
                break
            }

            prev = seg
            next = seg.next
        }
    }

    /// Deliver data from the ooseq queue that is now in-sequence.
    private func processOoseq(pcb: TCPControlBlock) {
        while let cseg = pcb.ooseq, cseg.sequenceNumber == pcb.receiveNext {
            let segTcpLen = cseg.tcpLen

            pcb.receiveNext &+= UInt32(segTcpLen)
            if pcb.receiveWindow >= UInt32(segTcpLen) {
                pcb.receiveWindow -= UInt32(segTcpLen)
            } else {
                pcb.receiveWindow = 0
            }
            pcb.updateRcvAnnWnd()

            if cseg.len > 0 {
                if let existing = recvData {
                    if let pbuf = cseg.pbuf {
                        Pbuf.cat(existing, pbuf)
                    }
                } else {
                    recvData = cseg.pbuf
                }
                cseg.pbuf = nil
            }

            if cseg.headerFlags.contains(.fin) {
                recvFlags.insert(.gotFin)
                if pcb.state == .established {
                    pcb.state = .closeWait
                }
            }

            pcb.ooseq = cseg.next
            cseg.next = nil
            cseg.free()
        }

        // Update SACK state after absorbing in-sequence data
        if pcb.flags.contains(.sack) {
            if let firstOoseq = pcb.ooseq {
                removeSACKsBelow(pcb: pcb, seq: firstOoseq.sequenceNumber)
            } else {
                pcb.rcvSacks = Array(repeating: TCPSACKRange(), count: TCPControlBlock.maxSACKNum)
            }
        }
    }

    // MARK: - Free acknowledged segments

    /// Remove segments from a queue whose sequence numbers have been fully
    /// acknowledged (seqno + tcpLen <= `acknowledgedTo`).
    ///
    /// For each freed segment the pcb's `sendQueueLength` is decremented and
    /// the running `recvAcked` total is accumulated so that the sent-callback
    /// can be issued later.
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block owning the segment queue.
    ///   - acknowledgedTo: The acknowledgement number from the remote peer.
    ///     Segments whose `sequenceNumber + tcpLen` is less-than-or-equal to
    ///     this value are considered acknowledged and will be freed.
    ///   - queue: An `inout` reference to the head of the segment list
    ///     (typically `pcb.unacked` or `pcb.unsent`).
    private func freeAckedSegments(pcb: TCPControlBlock,
                                   acknowledgedTo: UInt32,
                                   queue: inout TCPSegment?) {
        while let seg = queue {
            guard TCPSequence.isLessThanOrEqual(
                seg.sequenceNumber &+ UInt32(seg.tcpLen),
                acknowledgedTo
            ) else {
                break
            }

            queue = seg.next

            let clen = seg.pbuf?.chainLength ?? 1
            if pcb.sendQueueLength >= clen {
                pcb.sendQueueLength -= clen
            }
            recvAcked &+= UInt32(seg.len)
            seg.free()
        }
    }

    /// Convenience overload that uses the current input `ackno`.
    private func freeAckedSegments(pcb: TCPControlBlock, queue: inout TCPSegment?) {
        freeAckedSegments(pcb: pcb, acknowledgedTo: ackno, queue: &queue)
    }

    // MARK: - Option Parsing

    /// Parse TCP options from the incoming segment.
    ///
    /// Handles the standard TLV (Type-Length-Value) option encoding.
    /// Recognised options:
    ///  - End Of List (0) — terminates parsing
    ///  - NOP (1) — single-byte pad, no length field
    ///  - MSS (2) — 4 bytes: caps remote MSS to configured ``tcpMSS``
    ///  - Window Scale (3) — 3 bytes: only applied during SYN exchange
    ///  - SACK Permitted (4) — 2 bytes: only accepted during SYN
    ///  - Timestamps (8) — 10 bytes: TSval is stored; TSecr is skipped
    private func parseOptions(pcb: TCPControlBlock) {
        let optCount = optBytes.count
        guard optCount > 0 else { return }

        var idx = 0
        while idx < optCount {
            let kind = optBytes[idx]

            switch kind {
            // ── End of Options List ─────────────────────────────────
            case TCPOptionConstants.endOfList:
                return

            // ── No-Operation (padding) ──────────────────────────────
            case TCPOptionConstants.noOperation:
                idx += 1

            // ── Maximum Segment Size (4 bytes) ──────────────────────
            case TCPOptionConstants.maxSegmentSize:
                let optLen = Int(TCPOptionConstants.maxSegmentSizeLength)  // 4
                // Need at least `optLen` bytes remaining from idx
                guard idx + optLen <= optCount else { return }
                // Validate the length field
                guard optBytes[idx + 1] == TCPOptionConstants.maxSegmentSizeLength else { return }
                // Read 16-bit MSS value (network byte order)
                let mss = (UInt16(optBytes[idx + 2]) << 8) | UInt16(optBytes[idx + 3])
                // Cap to configured TCP_MSS; treat 0 as invalid
                let configuredMSS = UInt16(lwipConfig.tcpMSS)
                pcb.maxSegmentSize = (mss == 0 || mss > configuredMSS) ? configuredMSS : mss
                idx += optLen

            // ── Window Scale (3 bytes) ──────────────────────────────
            case TCPOptionConstants.windowScale:
                let optLen = Int(TCPOptionConstants.windowScaleLength)  // 3
                guard idx + optLen <= optCount else { return }
                guard optBytes[idx + 1] == TCPOptionConstants.windowScaleLength else { return }
                let shiftCount = optBytes[idx + 2]
                // Only apply during SYN exchange, and only once (not on retransmission)
                if flags.contains(.syn) && !pcb.flags.contains(.wndScale) {
                    // RFC 7323: shift count MUST be capped at 14
                    pcb.sendScale = min(shiftCount, 14)
                    pcb.receiveScale = lwipConfig.tcpReceiveWindowScale
                    pcb.flags.insert(.wndScale)
                    // With window scaling enabled we can advertise the full receive window
                    pcb.receiveWindow = UInt32(lwipConfig.tcpWnd)
                    pcb.receiveAnnouncedWindow = UInt32(lwipConfig.tcpWnd)
                }
                idx += optLen

            // ── Timestamps (10 bytes) ───────────────────────────────
            case TCPOptionConstants.timestamps:
                let optLen = Int(TCPOptionConstants.timestampsLength)  // 10
                guard idx + optLen <= optCount else { return }
                guard optBytes[idx + 1] == TCPOptionConstants.timestampsLength else { return }
                // Read TSval (4 bytes, network byte order) at offset +2
                let tsval = (UInt32(optBytes[idx + 2]) << 24) |
                            (UInt32(optBytes[idx + 3]) << 16) |
                            (UInt32(optBytes[idx + 4]) << 8)  |
                             UInt32(optBytes[idx + 5])
                // TSecr is at idx+6..idx+9 but we don't need to store it
                // (the outgoing timestamp echo uses tsRecent which we set here)
                if flags.contains(.syn) {
                    pcb.tsRecent = tsval
                    // Enable timestamps for all future segments on this connection
                    pcb.flags.insert(.timestamp)
                } else if TCPSequence.isBetween(pcb.tsLastAckSent, seqno, seqno &+ UInt32(tcplen)) {
                    pcb.tsRecent = tsval
                }
                idx += optLen

            // ── SACK Permitted (2 bytes) ────────────────────────────
            case TCPOptionConstants.sackPermitted:
                let optLen = Int(TCPOptionConstants.sackPermittedLength)  // 2
                guard idx + optLen <= optCount else { return }
                guard optBytes[idx + 1] == TCPOptionConstants.sackPermittedLength else { return }
                // Only accept during SYN exchange (SYN or SYN+ACK)
                if flags.contains(.syn) {
                    pcb.flags.insert(.sack)
                }
                idx += optLen

            // ── Unknown option ──────────────────────────────────────
            default:
                // All other options carry a length byte at offset +1.
                guard idx + 1 < optCount else { return }
                let len = optBytes[idx + 1]
                // Length < 2 is malformed (kind + length are already 2 bytes)
                guard len >= 2 else { return }
                idx += Int(len)
            }
        }
    }
}
