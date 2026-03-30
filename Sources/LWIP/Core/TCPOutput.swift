//
//  TCPOutput.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - TCP Output Processor

/// Handles all outgoing TCP segment creation and transmission.
public final class TCPOutput {
    public static let shared = TCPOutput()

    private init() {}

    // MARK: - Segment Creation

    /// Create a TCP segment with prefilled header.
    private func createSegment(pcb: TCPControlBlock, pbuf: Pbuf, hdrFlags: TCPHeaderFlags,
                               seqno: UInt32, optFlags: TCPSegOptFlags) -> TCPSegment? {
        let seg = TCPSegment()
        let optLen = UInt16(TCPOptionConstants.optionLength(for:optFlags))

        seg.optionFlags = optFlags
        seg.next = nil
        seg.pbuf = pbuf
        seg.len = pbuf.totLen >= optLen ? pbuf.totLen - optLen : 0
        seg.headerFlags = hdrFlags
        seg.sequenceNumber = seqno
        seg.sourcePort = pcb.localPort
        seg.destinationPort = pcb.remotePort
        seg.headerLengthWords = 5 + UInt8(optLen / 4)
        seg.checksum = 0
        seg.checksumSwapped = false

        return seg
    }

    // MARK: - tcp_write

    /// Write data for sending (does not send immediately).
    /// The data is enqueued and will be sent when tcp_output is called.
    ///
    /// - Parameters:
    ///   - pcb: The TCP PCB to write to.
    ///   - data: Pointer to the data.
    ///   - len: Length of data in bytes.
    ///   - apiFlags: TCPConstants.writeFlagCopy and/or TCPConstants.writeFlagMore.
    /// - Returns: .ok if enqueued successfully, error otherwise.
    public func write(pcb: TCPControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError {
        // Validate state
        guard pcb.state == .established || pcb.state == .closeWait ||
              pcb.state == .synSent || pcb.state == .synRcvd else {
            return .notConnected
        }
        guard len > 0 else { return .ok }

        // Check send buffer space
        guard UInt32(len) <= pcb.sendBufferSpace else {
            pcb.flags.insert(.nagleMemErr)
            return .outOfMemory
        }

        // Check queue length
        guard pcb.sendQueueLength < UInt16(lwipConfig.tcpSndQueueLen) else {
            pcb.flags.insert(.nagleMemErr)
            return .outOfMemory
        }

        // Determine MSS for segmentation
        var mssLocal = min(pcb.maxSegmentSize, UInt16(truncatingIfNeeded: pcb.sendWindowMax / 2))
        if mssLocal == 0 { mssLocal = pcb.maxSegmentSize }

        var optFlags: TCPSegOptFlags = []
        var optLen: UInt16 = 0
        if pcb.flags.contains(.timestamp) {
            optFlags.insert(.timestamp)
            optLen = UInt16(TCPOptionConstants.optionLength(for:.timestamp))
            mssLocal = max(mssLocal, UInt16(TCPOptionConstants.timestampsOutputLength) + 1)
        }

        var pos: UInt16 = 0
        var queue: TCPSegment? = nil
        var lastSeg: TCPSegment? = nil
        var queueLen = pcb.sendQueueLength

        // Phase 1: Try to append to last unsent segment
        if let lastUnsent = findLastUnsent(pcb: pcb) {
            let unsentOptLen = UInt16(TCPOptionConstants.optionLength(for:lastUnsent.optionFlags))
            let space = mssLocal - (lastUnsent.len + unsentOptLen)
            if space > 0 && pos < len {
                let seglen = min(space, len - pos)
                // In a real implementation, we'd append data to the pbuf chain
                // For now, we create a new segment for remaining data
                pos += seglen
                lastUnsent.len += seglen
                queueLen += 1
            }
        }

        // Phase 2: Create new segments for remaining data
        while pos < len {
            let left = len - pos
            let maxLen = mssLocal - optLen
            let seglen = min(left, maxLen)

            // Allocate pbuf for this segment
            guard let p = Pbuf.alloc(layer: .transport, length: seglen + optLen, type: .ram) else {
                pcb.flags.insert(.nagleMemErr)
                return .outOfMemory
            }

            // Copy data into pbuf
            if (apiFlags & TCPConstants.writeFlagCopy) != 0 {
                let dst = p.payload
                memcpy(dst.advanced(by: Int(optLen)),
                       data.advanced(by: Int(pos)),
                       Int(seglen))
            }

            queueLen += p.chainLength

            // Check queue overflow
            guard queueLen <= UInt16(lwipConfig.tcpSndQueueLen) else {
                pcb.flags.insert(.nagleMemErr)
                _ = Pbuf.free(p)
                return .outOfMemory
            }

            // Create segment
            guard let seg = createSegment(pcb: pcb, pbuf: p, hdrFlags: [],
                                          seqno: pcb.sendLastByteBuffered &+ UInt32(pos),
                                          optFlags: optFlags) else {
                pcb.flags.insert(.nagleMemErr)
                _ = Pbuf.free(p)
                return .outOfMemory
            }

            if queue == nil {
                queue = seg
            } else {
                lastSeg?.next = seg
            }
            lastSeg = seg

            pos += seglen
        }

        // Commit: append queue to unsent list
        if let lastUnsent = findLastUnsent(pcb: pcb) {
            lastUnsent.next = queue
        } else {
            pcb.unsent = queue
        }

        // Update PCB state
        pcb.sendLastByteBuffered &+= UInt32(len)
        pcb.sendBufferSpace -= UInt32(len)
        pcb.sendQueueLength = queueLen

        // Set PSH flag on last segment if not TCPConstants.writeFlagMore
        if let seg = lastSeg, (apiFlags & TCPConstants.writeFlagMore) == 0 {
            seg.headerFlags.insert(.psh)
        }

        return .ok
    }

    // MARK: - tcp_enqueue_flags

    /// Enqueue a SYN or FIN segment.
    public func enqueueFlags(pcb: TCPControlBlock, flags: TCPHeaderFlags) -> LWIPError {
        var optFlags: TCPSegOptFlags = []

        // SYN options
        if flags.contains(.syn) {
            optFlags.insert(.mss)
            if pcb.state != .synRcvd || pcb.flags.contains(.wndScale) {
                optFlags.insert(.wndScale)
            }
            if pcb.state != .synRcvd || pcb.flags.contains(.sack) {
                optFlags.insert(.sackPerm)
            }
        }

        // Timestamp option
        if pcb.flags.contains(.timestamp) || (flags.contains(.syn) && pcb.state != .synRcvd) {
            optFlags.insert(.timestamp)
        }

        let optLen = UInt16(TCPOptionConstants.optionLength(for:optFlags))

        // Allocate pbuf for options only
        guard let p = Pbuf.alloc(layer: .transport, length: optLen, type: .ram) else {
            pcb.flags.insert(.nagleMemErr)
            return .outOfMemory
        }

        guard let seg = createSegment(pcb: pcb, pbuf: p, hdrFlags: flags,
                                      seqno: pcb.sendLastByteBuffered, optFlags: optFlags) else {
            pcb.flags.insert(.nagleMemErr)
            _ = Pbuf.free(p)
            return .outOfMemory
        }

        // Append to unsent queue
        if let lastUnsent = findLastUnsent(pcb: pcb) {
            lastUnsent.next = seg
        } else {
            pcb.unsent = seg
        }

        pcb.unsentOversize = 0

        // SYN and FIN consume sequence numbers
        if !flags.isDisjoint(with: [.syn, .fin]) {
            pcb.sendLastByteBuffered &+= 1
        }
        if flags.contains(.fin) {
            pcb.flags.insert(.fin)
        }

        pcb.sendQueueLength += p.chainLength

        return .ok
    }

    // MARK: - tcp_send_fin

    /// Send a FIN segment, either by appending to the last unsent or creating new.
    public func sendFin(pcb: TCPControlBlock) -> LWIPError {
        // Try to add FIN to last unsent segment
        if let lastUnsent = findLastUnsent(pcb: pcb) {
            if lastUnsent.headerFlags.isDisjoint(with: [.syn, .fin, .rst]) {
                lastUnsent.headerFlags.insert(.fin)
                pcb.flags.insert(.fin)
                return .ok
            }
        }
        return enqueueFlags(pcb: pcb, flags: .fin)
    }

    // MARK: - tcp_output

    /// Find what can be sent and send it.
    public func output(pcb: TCPControlBlock) -> LWIPError {
        let global = TCPGlobal.shared

        guard pcb.state != .listen else { return .ok }

        // Don't output during input processing
        if global.inputPCB === pcb { return .ok }

        let wnd = min(pcb.sendWindow, pcb.congestionWindow)

        guard var seg = pcb.unsent else {
            // Nothing to send; maybe send empty ACK
            if pcb.flags.contains(.ackNow) {
                return sendEmptyAck(pcb: pcb)
            }
            // Force ACK when SACK blocks are pending to ensure timely SACK feedback
            if pcb.flags.contains(.sack) && pcb.flags.contains(.ackDelay) && pcb.rcvSacks[0].isValid {
                return sendEmptyAck(pcb: pcb)
            }
            pcb.flags.remove(.nagleMemErr)
            return .ok
        }

        // Check if first segment fits in window
        if seg.sequenceNumber &- pcb.lastAcknowledged &+ UInt32(seg.len) > wnd {
            // Segment doesn't fit in window
            if wnd == pcb.sendWindow && pcb.unacked == nil && pcb.persistBackoff == 0 {
                pcb.persistCnt = 0
                pcb.persistBackoff = 1
                pcb.persistProbe = 0
            }
            if pcb.flags.contains(.ackNow) {
                return sendEmptyAck(pcb: pcb)
            }
            pcb.flags.remove(.nagleMemErr)
            return .ok
        }

        // Stop persist timer
        pcb.persistBackoff = 0

        // Find last segment on unacked queue
        var useg = pcb.unacked
        if let u = useg {
            var cursor = u
            while let nextSeg = cursor.next {
                cursor = nextSeg
            }
            useg = cursor
        }

        // Send segments that fit in the window
        while let currentSeg = pcb.unsent {
            seg = currentSeg

            if seg.sequenceNumber &- pcb.lastAcknowledged &+ UInt32(seg.len) > wnd {
                break
            }

            // Nagle algorithm check
            if !pcb.nagleCanSend && !pcb.flags.contains(.nagleMemErr) && !pcb.flags.contains(.fin) {
                break
            }

            // Add ACK flag (except in SYN_SENT)
            if pcb.state != .synSent {
                seg.headerFlags.insert(.ack)
            }

            // Send the segment
            let err = outputSegment(seg: seg, pcb: pcb)
            if err != .ok {
                pcb.flags.insert(.nagleMemErr)
                return err
            }

            // Move to unacked
            pcb.unsent = seg.next
            if pcb.state != .synSent {
                pcb.flags.remove(.ackDelay)
                pcb.flags.remove(.ackNow)
            }

            // Update snd_nxt
            let sndNxt = seg.sequenceNumber &+ UInt32(seg.tcpLen)
            if TCPSequence.isLessThan(pcb.sendNext, sndNxt) {
                pcb.sendNext = sndNxt
            }

            // Put on unacked list if it has length
            if seg.tcpLen > 0 {
                seg.next = nil
                if pcb.unacked == nil {
                    pcb.unacked = seg
                    useg = seg
                } else {
                    // Keep unacked list sorted
                    if let u = useg, TCPSequence.isLessThan(seg.sequenceNumber, u.sequenceNumber) {
                        // Insert before useg (sorted insert)
                        var cur: TCPSegment? = pcb.unacked
                        var prevSeg: TCPSegment? = nil
                        while let c = cur, TCPSequence.isLessThan(c.sequenceNumber, seg.sequenceNumber) {
                            prevSeg = c
                            cur = c.next
                        }
                        seg.next = cur
                        if let p = prevSeg {
                            p.next = seg
                        } else {
                            pcb.unacked = seg
                        }
                    } else {
                        useg?.next = seg
                        useg = seg
                    }
                }
            } else {
                seg.free()
            }
        }

        if pcb.unsent == nil {
            pcb.unsentOversize = 0
        }

        pcb.flags.remove(.nagleMemErr)
        return .ok
    }

    // MARK: - Output a Single Segment

    /// Finalize and send a single TCP segment.
    ///
    /// If the segment is still being transmitted from a previous send (the
    /// network driver holds a pbuf reference), the retransmission is silently
    /// deferred and `.ok` is returned without modifying the segment.
    private func outputSegment(seg: TCPSegment, pcb: TCPControlBlock) -> LWIPError {
        guard let p = seg.pbuf else { return .invalidValue }

        // Check if a previous transmission is still in progress.  Retransmit
        // functions should have already checked this, but since this function
        // modifies pbuf lengths we must not proceed on a busy segment.
        if outputSegmentBusy(seg) {
            return .ok
        }

        // Fill in ackno and window
        seg.acknowledgmentNumber = pcb.receiveNext

        // Advertise receive window
        if seg.optionFlags.contains(.wndScale) {
            // SYN segment: window field is not scaled
            seg.windowSize = UInt16(min(pcb.receiveAnnouncedWindow, UInt32(UInt16.max)))
        } else {
            let scaledWnd = pcb.receiveAnnouncedWindow >> UInt32(pcb.receiveScale)
            seg.windowSize = UInt16(min(scaledWnd, UInt32(UInt16.max)))
        }

        pcb.receiveAnnouncedRightEdge = pcb.receiveNext &+ pcb.receiveAnnouncedWindow

        // Build the TCP header at the front of the pbuf.
        // The pbuf was allocated with transport layer reservation, so we need to
        // prepend the TCP header space.
        let hdrLenBytes = Int(seg.headerLengthWords) * 4
        guard p.addHeader(hdrLenBytes) else { return .outOfMemory }

        // Write the TCP header into the pbuf payload
        let hdr = p.payload.assumingMemoryBound(to: TCPHeader.self)
        hdr.pointee.sourcePort = seg.sourcePort.bigEndian
        hdr.pointee.destinationPort = seg.destinationPort.bigEndian
        hdr.pointee.sequenceNumber = seg.sequenceNumber.bigEndian
        hdr.pointee.acknowledgmentNumber = seg.acknowledgmentNumber.bigEndian
        hdr.pointee.setHeaderLenAndFlags(len: seg.headerLengthWords, flags: seg.headerFlags)
        hdr.pointee.headerLengthReservedFlags = hdr.pointee.headerLengthReservedFlags.bigEndian
        hdr.pointee.windowSize = seg.windowSize.bigEndian
        hdr.pointee.checksum = 0
        hdr.pointee.urgentPointer = 0

        // Write TCP options after the base header (20 bytes)
        let optsBase = p.payload.advanced(by: MemoryLayout<TCPHeader>.size)
        var optsPtr = optsBase.assumingMemoryBound(to: UInt32.self)

        // MSS option is only set on SYN packets.
        if seg.optionFlags.contains(.mss) {
            let mss = pcb.maxSegmentSize
            // TCP_BUILD_MSS_OPTION: kind=2, len=4, then MSS value
            optsPtr.pointee = UInt32(0x0204_0000 | UInt32(mss)).bigEndian
            optsPtr = optsPtr.advanced(by: 1)
        }

        // Record that this ACK carries our latest rcv_nxt for timestamp echo.
        pcb.tsLastAckSent = pcb.receiveNext

        // Fill remaining options via the individual option builders.
        fillOptions(pcb: pcb, options: &optsPtr, optFlags: seg.optionFlags)

        // Set retransmission timer running if it is not currently enabled
        if pcb.retransmissionTime < 0 {
            pcb.retransmissionTime = 0
        }

        // Start RTT measurement if not already running.
        // Use ticks + 1 so that a zero value reliably means "no measurement in progress"
        // (ticks could be zero at startup).
        if pcb.roundTripTimeTest == 0 {
            pcb.roundTripTimeTest = TCPGlobal.shared.ticks + 1
            pcb.roundTripTimeSequence = seg.sequenceNumber
        }

        // Compute TCP checksum over pseudo-header + full segment
        hdr.pointee.checksum = 0
        let chksum = InetChecksum.checksumPseudo(
            p,
            proto: IPProto.tcp.rawValue,
            protoLen: p.totLen,
            src: pcb.localIP,
            dest: pcb.remoteIP
        )
        hdr.pointee.checksum = chksum

        // Route and send via IP
        guard let netif = IPDispatch.route(src: pcb.localIP, dest: pcb.remoteIP) else {
            // Remove header so the segment can be retried later
            p.removeHeader(hdrLenBytes)
            return .routingError
        }

        let err = IPDispatch.outputVia(p, src: pcb.localIP, dest: pcb.remoteIP,
                             ttl: pcb.ttl, tos: pcb.tos,
                             proto: .tcp, netif: netif)

        // Remove the TCP header from the pbuf so that retransmissions can
        // re-add it (the header fields may change on retransmit).
        p.removeHeader(hdrLenBytes)

        return err
    }

    // MARK: - Send Empty ACK

    /// Send an ACK segment with no data.
    @discardableResult
    public func sendEmptyAck(pcb: TCPControlBlock) -> LWIPError {
        var optFlags: TCPSegOptFlags = []
        if pcb.flags.contains(.timestamp) {
            optFlags.insert(.timestamp)
        }

        // Calculate how many SACK ranges fit in the remaining option space
        let numSacks = getNumSacks(pcb: pcb, currentOptLen: UInt8(TCPOptionConstants.optionLength(for:optFlags)))

        let sackOptLen: UInt16 = numSacks > 0 ? UInt16(12 + (numSacks - 1) * 8) : 0
        let optLen = UInt16(TCPOptionConstants.optionLength(for:optFlags)) + sackOptLen
        let hdrLen = TCPConstants.headerLength + optLen

        // Allocate header-only pbuf at IP layer (we build the TCP header as payload)
        guard let p = Pbuf.alloc(layer: .ip, length: hdrLen, type: .ram) else {
            pcb.flags.insert(.ackDelay)
            pcb.flags.insert(.ackNow)
            return .outOfMemory
        }

        // Compute the advertised window (with scaling)
        let scaledWnd = pcb.receiveAnnouncedWindow >> UInt32(pcb.receiveScale)
        let wnd = UInt16(min(scaledWnd, UInt32(UInt16.max)))

        // Fill TCP header
        let hdr = p.payload.assumingMemoryBound(to: TCPHeader.self)
        hdr.pointee.sourcePort = pcb.localPort.bigEndian
        hdr.pointee.destinationPort = pcb.remotePort.bigEndian
        hdr.pointee.sequenceNumber = pcb.sendNext.bigEndian
        hdr.pointee.acknowledgmentNumber = pcb.receiveNext.bigEndian
        let hdrLenWords = UInt8(5 + optLen / 4)
        hdr.pointee.setHeaderLenAndFlags(len: hdrLenWords, flags: .ack)
        hdr.pointee.headerLengthReservedFlags = hdr.pointee.headerLengthReservedFlags.bigEndian
        hdr.pointee.windowSize = wnd.bigEndian
        hdr.pointee.checksum = 0
        hdr.pointee.urgentPointer = 0

        // Fill in options via builder functions
        let optsBase = p.payload.advanced(by: MemoryLayout<TCPHeader>.size)
        var optsPtr = optsBase.assumingMemoryBound(to: UInt32.self)

        pcb.tsLastAckSent = pcb.receiveNext
        fillOptions(pcb: pcb, options: &optsPtr, optFlags: optFlags)

        // Write SACK ranges into options
        if numSacks > 0 {
            buildSACKOption(pcb: pcb, options: &optsPtr, numSacks: numSacks)
        }

        // Update announced window
        pcb.receiveAnnouncedRightEdge = pcb.receiveNext &+ pcb.receiveAnnouncedWindow

        // Compute checksum
        hdr.pointee.checksum = InetChecksum.checksumPseudo(
            p,
            proto: IPProto.tcp.rawValue,
            protoLen: p.totLen,
            src: pcb.localIP,
            dest: pcb.remoteIP
        )

        // Route and send
        let err: LWIPError
        if let netif = IPDispatch.route(src: pcb.localIP, dest: pcb.remoteIP) {
            err = IPDispatch.outputVia(p, src: pcb.localIP, dest: pcb.remoteIP,
                             ttl: pcb.ttl, tos: pcb.tos,
                             proto: .tcp, netif: netif)
        } else {
            err = .routingError
        }

        if err != .ok {
            pcb.flags.insert(.ackDelay)
            pcb.flags.insert(.ackNow)
        } else {
            pcb.flags.remove(.ackDelay)
            pcb.flags.remove(.ackNow)
        }

        // Free the pbuf after sending (or attempting to send)
        _ = Pbuf.free(p)

        return err
    }

    // MARK: - RST

    /// Send a TCP RST (reset) segment.
    public func rst(seqno: UInt32, ackno: UInt32,
                    localIP: IPAddress, remoteIP: IPAddress,
                    localPort: UInt16, remotePort: UInt16) {
        let hdrLen = TCPConstants.headerLength

        guard let p = Pbuf.alloc(layer: .ip, length: hdrLen, type: .ram) else {
            return
        }

        // Build RST+ACK header
        let hdr = p.payload.assumingMemoryBound(to: TCPHeader.self)
        hdr.pointee.sourcePort = localPort.bigEndian
        hdr.pointee.destinationPort = remotePort.bigEndian
        hdr.pointee.sequenceNumber = seqno.bigEndian
        hdr.pointee.acknowledgmentNumber = ackno.bigEndian
        hdr.pointee.setHeaderLenAndFlags(len: 5, flags: [.rst, .ack])
        hdr.pointee.headerLengthReservedFlags = hdr.pointee.headerLengthReservedFlags.bigEndian
        hdr.pointee.windowSize = 0
        hdr.pointee.checksum = 0
        hdr.pointee.urgentPointer = 0

        // Compute checksum
        hdr.pointee.checksum = InetChecksum.checksumPseudo(
            p,
            proto: IPProto.tcp.rawValue,
            protoLen: p.totLen,
            src: localIP,
            dest: remoteIP
        )

        // Route and send
        if let netif = IPDispatch.route(src: localIP, dest: remoteIP) {
            _ = IPDispatch.outputVia(p, src: localIP, dest: remoteIP,
                           ttl: 255, tos: 0,
                           proto: .tcp, netif: netif)
        }

        _ = Pbuf.free(p)
    }

    // MARK: - Keepalive

    /// Send a keepalive probe.
    @discardableResult
    public func keepalive(pcb: TCPControlBlock) -> LWIPError {
        let hdrLen = TCPConstants.headerLength

        guard let p = Pbuf.alloc(layer: .ip, length: hdrLen, type: .ram) else {
            return .outOfMemory
        }

        // Compute the advertised window (with scaling)
        let scaledWnd = pcb.receiveAnnouncedWindow >> UInt32(pcb.receiveScale)
        let wnd = UInt16(min(scaledWnd, UInt32(UInt16.max)))

        // Build header with seqno = snd_nxt - 1 to elicit a response
        let hdr = p.payload.assumingMemoryBound(to: TCPHeader.self)
        hdr.pointee.sourcePort = pcb.localPort.bigEndian
        hdr.pointee.destinationPort = pcb.remotePort.bigEndian
        hdr.pointee.sequenceNumber = (pcb.sendNext &- 1).bigEndian
        hdr.pointee.acknowledgmentNumber = pcb.receiveNext.bigEndian
        hdr.pointee.setHeaderLenAndFlags(len: 5, flags: .ack)
        hdr.pointee.headerLengthReservedFlags = hdr.pointee.headerLengthReservedFlags.bigEndian
        hdr.pointee.windowSize = wnd.bigEndian
        hdr.pointee.checksum = 0
        hdr.pointee.urgentPointer = 0

        // Update announced window
        pcb.receiveAnnouncedRightEdge = pcb.receiveNext &+ pcb.receiveAnnouncedWindow

        // Compute checksum
        hdr.pointee.checksum = InetChecksum.checksumPseudo(
            p,
            proto: IPProto.tcp.rawValue,
            protoLen: p.totLen,
            src: pcb.localIP,
            dest: pcb.remoteIP
        )

        // Route and send
        let err: LWIPError
        if let netif = IPDispatch.route(src: pcb.localIP, dest: pcb.remoteIP) {
            err = IPDispatch.outputVia(p, src: pcb.localIP, dest: pcb.remoteIP,
                             ttl: pcb.ttl, tos: pcb.tos,
                             proto: .tcp, netif: netif)
        } else {
            err = .routingError
        }

        _ = Pbuf.free(p)
        return err
    }

    // MARK: - Zero Window Probe

    /// Send a zero-window probe.
    @discardableResult
    public func zeroWindowProbe(pcb: TCPControlBlock) -> LWIPError {
        guard let seg = pcb.unsent, let segPbuf = seg.pbuf else { return .ok }

        // Increment probe count (even if send fails, to prevent indefinite zombies)
        if pcb.persistProbe < 0xFF {
            pcb.persistProbe += 1
        }

        // Check if this is a FIN-only segment (no data)
        let isFin = seg.headerFlags.contains(.fin) && seg.len == 0
        let dataLen: UInt16 = isFin ? 0 : 1
        let hdrLen = TCPConstants.headerLength

        guard let p = Pbuf.alloc(layer: .ip, length: hdrLen + dataLen, type: .ram) else {
            return .outOfMemory
        }

        // Compute the advertised window (with scaling)
        let scaledWnd = pcb.receiveAnnouncedWindow >> UInt32(pcb.receiveScale)
        let wnd = UInt16(min(scaledWnd, UInt32(UInt16.max)))

        // Build TCP header
        let hdr = p.payload.assumingMemoryBound(to: TCPHeader.self)
        hdr.pointee.sourcePort = pcb.localPort.bigEndian
        hdr.pointee.destinationPort = pcb.remotePort.bigEndian
        hdr.pointee.sequenceNumber = seg.sequenceNumber.bigEndian
        hdr.pointee.acknowledgmentNumber = pcb.receiveNext.bigEndian
        let flags: TCPHeaderFlags = isFin ? [.ack, .fin] : .ack
        hdr.pointee.setHeaderLenAndFlags(len: 5, flags: flags)
        hdr.pointee.headerLengthReservedFlags = hdr.pointee.headerLengthReservedFlags.bigEndian
        hdr.pointee.windowSize = wnd.bigEndian
        hdr.pointee.checksum = 0
        hdr.pointee.urgentPointer = 0

        if !isFin {
            // Copy 1 byte of data from the segment's payload (after options)
            let dataOffset = segPbuf.totLen - seg.len
            let dst = p.payload.advanced(by: Int(hdrLen))
            _ = segPbuf.copyPartial(to: dst, len: 1, offset: dataOffset)
        }

        // Update snd_nxt if needed
        let sndNxt = seg.sequenceNumber &+ 1
        if TCPSequence.isLessThan(pcb.sendNext, sndNxt) {
            pcb.sendNext = sndNxt
        }

        // Update announced window
        pcb.receiveAnnouncedRightEdge = pcb.receiveNext &+ pcb.receiveAnnouncedWindow

        // Compute checksum
        hdr.pointee.checksum = InetChecksum.checksumPseudo(
            p,
            proto: IPProto.tcp.rawValue,
            protoLen: p.totLen,
            src: pcb.localIP,
            dest: pcb.remoteIP
        )

        // Route and send
        let err: LWIPError
        if let netif = IPDispatch.route(src: pcb.localIP, dest: pcb.remoteIP) {
            err = IPDispatch.outputVia(p, src: pcb.localIP, dest: pcb.remoteIP,
                             ttl: pcb.ttl, tos: pcb.tos,
                             proto: .tcp, netif: netif)
        } else {
            err = .routingError
        }

        _ = Pbuf.free(p)
        return err
    }

    // MARK: - Retransmission

    /// Prepare for RTO retransmission: move all unacked segments back to the
    /// head of the unsent list.
    ///
    /// This is the first phase of a two-phase RTO retransmission.  The caller
    /// may inspect or modify the unsent list between `rexmitRTOPrepare` and
    /// `rexmitRTOCommit`.
    ///
    /// If any segment on the unacked list is still being transmitted (its pbuf
    /// has a reference count > 1, meaning a network driver still holds a
    /// reference), the prepare is aborted and `.invalidValue` is returned.
    @discardableResult
    public func rexmitRTOPrepare(pcb: TCPControlBlock) -> LWIPError {
        guard pcb.unacked != nil else { return .invalidValue }

        // Walk the entire unacked list and bail out if any segment is still
        // referenced by the network driver (deferred transmission).
        var seg = pcb.unacked
        while let s = seg {
            if outputSegmentBusy(s) {
                return .invalidValue
            }
            if s.next == nil { break }
            seg = s.next
        }
        // `seg` now points to the tail of the unacked list.

        // Concatenate: unacked tail -> unsent head
        seg?.next = pcb.unsent

        // The unsent list is now the old unacked list followed by the old unsent list.
        pcb.unsent = pcb.unacked
        pcb.unacked = nil

        // Mark RTO in progress and record the end sequence for RTO tracking.
        pcb.flags.insert(.rto)
        if let lastSeg = seg {
            pcb.retransmissionTimeoutEnd = lastSeg.sequenceNumber &+ UInt32(lastSeg.tcpLen)
        }

        // Don't take any RTT measurements after retransmitting.
        pcb.roundTripTimeTest = 0

        return .ok
    }

    /// Commit RTO retransmission: increment the retransmission counter and
    /// trigger `output` to actually send the segments.
    ///
    /// This is the second phase of a two-phase RTO retransmission.
    public func rexmitRTOCommit(pcb: TCPControlBlock) {
        if pcb.retransmissionCount < 0xFF {
            pcb.retransmissionCount += 1
        }
        _ = output(pcb: pcb)
    }

    /// Full RTO retransmission (prepare + commit).
    ///
    /// Used when no intermediate inspection is needed between the two phases.
    public func rexmitRto(pcb: TCPControlBlock) {
        if rexmitRTOPrepare(pcb: pcb) == .ok {
            rexmitRTOCommit(pcb: pcb)
        }
    }

    /// Backward-compatible alias for `rexmitRTOPrepare`.
    @discardableResult
    public func rexmitRtoPrepare(pcb: TCPControlBlock) -> LWIPError {
        rexmitRTOPrepare(pcb: pcb)
    }

    /// Backward-compatible alias for `rexmitRTOCommit`.
    public func rexmitRtoCommit(pcb: TCPControlBlock) {
        rexmitRTOCommit(pcb: pcb)
    }

    /// Retransmit the first unacked segment by moving it back into the unsent
    /// list (kept sorted by sequence number).
    ///
    /// If the segment is still being transmitted (pbuf ref > 1), the
    /// retransmission is aborted.
    @discardableResult
    public func rexmit(pcb: TCPControlBlock) -> LWIPError {
        guard let seg = pcb.unacked else { return .invalidValue }

        // Give up if the segment is still held by a network driver.
        if outputSegmentBusy(seg) {
            return .invalidValue
        }

        // Move first unacked to unsent (sorted)
        pcb.unacked = seg.next

        // Insert in sorted position in unsent
        var cur = pcb.unsent
        var prev: TCPSegment? = nil
        while let c = cur, TCPSequence.isLessThan(c.sequenceNumber, seg.sequenceNumber) {
            prev = c
            cur = c.next
        }
        seg.next = cur
        if let p = prev {
            p.next = seg
        } else {
            pcb.unsent = seg
        }

        if seg.next == nil {
            pcb.unsentOversize = 0
        }

        if pcb.retransmissionCount < 0xFF { pcb.retransmissionCount += 1 }
        pcb.roundTripTimeTest = 0

        return .ok
    }

    /// Fast retransmit: retransmit first unacked and enter fast recovery.
    public func rexmitFast(pcb: TCPControlBlock) {
        guard pcb.unacked != nil && !pcb.flags.contains(.inFastRecovery) else { return }

        if rexmit(pcb: pcb) == .ok {
            // Set ssthresh to half of min(cwnd, snd_wnd)
            pcb.slowStartThreshold = min(pcb.congestionWindow, pcb.sendWindow) / 2
            if pcb.slowStartThreshold < UInt32(pcb.maxSegmentSize) * 2 {
                pcb.slowStartThreshold = UInt32(pcb.maxSegmentSize) * 2
            }

            pcb.congestionWindow = pcb.slowStartThreshold + 3 * UInt32(pcb.maxSegmentSize)
            pcb.flags.insert(.inFastRecovery)

            // Reset retransmission timer
            pcb.retransmissionTime = 0
        }
    }

    // MARK: - Split Unsent Segment

    /// Split the head of the unsent queue so that the first segment contains
    /// exactly `split` bytes of payload data, and a new second segment holds
    /// the remainder.
    ///
    /// This is used for path MTU discovery and the Nagle algorithm when the
    /// head segment is larger than the current effective MSS / window.
    ///
    /// The new remainder segment inherits PSH and FIN flags from the original
    /// (which are removed from the original). SYN stays on the original.
    @discardableResult
    public func splitUnsentSegment(pcb: TCPControlBlock, split: UInt16) -> LWIPError {
        guard let useg = pcb.unsent else { return .outOfMemory }
        guard split > 0 else { return .invalidValue }
        guard useg.len > split else { return .ok }
        guard let usegPbuf = useg.pbuf else { return .outOfMemory }

        let remainder = useg.len - split

        // Preserve option flags but strip the data-checksummed flag (it will be
        // re-established after tcp_create_segment fills it in).
        var optFlags = useg.optionFlags
        optFlags.remove(.dataChecksummed)
        let optLen = UInt16(TCPOptionConstants.optionLength(for: optFlags))

        // Allocate a new pbuf for the remainder data plus options header space.
        guard let p = Pbuf.alloc(layer: .transport, length: remainder + optLen, type: .ram) else {
            return .outOfMemory
        }

        // Copy remainder data from the original segment's pbuf into the new pbuf.
        // The offset into the original pbuf is past all headers/options plus the
        // split amount of payload we are keeping.
        let offset = usegPbuf.totLen - useg.len + split
        let copied = usegPbuf.copyPartial(
            to: p.payload.advanced(by: Int(optLen)),
            len: remainder,
            offset: offset
        )
        guard copied == remainder else {
            _ = Pbuf.free(p)
            return .outOfMemory
        }

        // Migrate PSH and FIN flags to the remainder; SYN stays on the original.
        var remainderFlags: TCPHeaderFlags = []

        if useg.headerFlags.contains(.psh) {
            useg.headerFlags.remove(.psh)
            remainderFlags.insert(.psh)
        }
        if useg.headerFlags.contains(.fin) {
            useg.headerFlags.remove(.fin)
            remainderFlags.insert(.fin)
        }

        // Create the new segment for the remainder.
        guard let seg = createSegment(pcb: pcb, pbuf: p, hdrFlags: remainderFlags,
                                      seqno: useg.sequenceNumber &+ UInt32(split),
                                      optFlags: optFlags) else {
            // createSegment frees `p` on failure
            return .outOfMemory
        }

        // Adjust queue length: remove old pbuf chain count, trim, re-add.
        pcb.sendQueueLength -= usegPbuf.chainLength

        // Trim the original segment's pbuf to discard the remainder data.
        // This may free trailing pbufs in the chain.
        usegPbuf.realloc(to: usegPbuf.totLen - remainder)
        useg.len -= remainder

        // Re-add the (possibly shorter) original pbuf chain count.
        pcb.sendQueueLength += usegPbuf.chainLength

        // Add the new remainder segment's pbuf chain count.
        pcb.sendQueueLength += p.chainLength

        // Insert the remainder segment right after the split segment.
        seg.next = useg.next
        useg.next = seg

        // If the remainder is now the last segment, clear oversize tracking.
        if seg.next == nil {
            pcb.unsentOversize = 0
        }

        return .ok
    }

    /// Compatibility alias matching the original lwIP helper name.
    @discardableResult
    public func splitUnsentSeg(pcb: TCPControlBlock, split: UInt16) -> LWIPError {
        splitUnsentSegment(pcb: pcb, split: split)
    }

    // MARK: - Helpers

    /// Find the last segment on the unsent queue.
    private func findLastUnsent(pcb: TCPControlBlock) -> TCPSegment? {
        guard var seg = pcb.unsent else { return nil }
        while let next = seg.next { seg = next }
        return seg
    }

    // MARK: - Segment Busy Check

    /// Check whether a segment's pbuf is still referenced by a network driver
    /// from a previous transmission (deferred send).
    ///
    /// When a driver calls `pbuf_ref()` on the first pbuf of a segment, the
    /// reference count rises above 1.  In that case the segment must not be
    /// retransmitted because `outputSegment` would modify `p->len`.
    ///
    /// - Parameter seg: The segment to check.
    /// - Returns: `true` if the segment is busy (ref count > 1).
    private func outputSegmentBusy(_ seg: TCPSegment) -> Bool {
        // Only the first pbuf needs to be checked: drivers call pbuf_ref()
        // on the head of the chain.
        guard let p = seg.pbuf else { return false }
        return p.refCount != 1
    }

    // MARK: - TCP Option Builders

    /// Write the TCP timestamp option into the options area.
    ///
    /// Layout (12 bytes = 3 x UInt32 words):
    /// ```
    /// NOP  NOP  Kind=8  Len=10   (0x0101_080A)
    /// TSval (current system time in ms)
    /// TSecr (echo of peer's timestamp)
    /// ```
    ///
    /// - Parameters:
    ///   - options: Pointer to the current position in the options buffer;
    ///     advanced by 3 words on return.
    ///   - pcb: The TCP control block (provides `tsRecent`).
    private func buildTimestampOption(options: inout UnsafeMutablePointer<UInt32>,
                                      pcb: TCPControlBlock) {
        // Two NOP padding bytes + kind 8 + length 10
        options.pointee = UInt32(0x0101_080A).bigEndian
        options = options.advanced(by: 1)
        // TSval: current timestamp
        options.pointee = Timeouts.shared.systemTimeMilliseconds().bigEndian
        options = options.advanced(by: 1)
        // TSecr: echo of peer's most recent timestamp
        options.pointee = pcb.tsRecent.bigEndian
        options = options.advanced(by: 1)
    }

    /// Write the SACK-permitted option into the options area.
    ///
    /// Layout (4 bytes = 1 x UInt32 word):
    /// ```
    /// NOP  NOP  Kind=4  Len=2    (0x0101_0402)
    /// ```
    ///
    /// - Parameter options: Pointer to the current position in the options
    ///   buffer; advanced by 1 word on return.
    private func buildSACKPermittedOption(options: inout UnsafeMutablePointer<UInt32>) {
        options.pointee = UInt32(0x0101_0402).bigEndian
        options = options.advanced(by: 1)
    }

    /// Write SACK blocks from the pcb's receiver SACK state into the options
    /// area.
    ///
    /// Layout: 1 header word + 2 words per SACK range.
    /// ```
    /// NOP  NOP  Kind=5  Len=(2 + numSacks*8)
    /// left_edge_1   right_edge_1
    /// left_edge_2   right_edge_2
    /// ...
    /// ```
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block (provides `rcvSacks`).
    ///   - options: Pointer to the current position in the options buffer;
    ///     advanced by (1 + 2*numSacks) words on return.
    ///   - numSacks: Number of SACK ranges to write.
    private func buildSACKOption(pcb: TCPControlBlock,
                                 options: inout UnsafeMutablePointer<UInt32>,
                                 numSacks: UInt8) {
        // Header: NOP NOP SACK_KIND(5) LENGTH
        // Length = 2 (kind + len bytes) + numSacks * 8
        let sackLen = 2 + UInt32(numSacks) * 8
        options.pointee = (0x0101_0500 + sackLen).bigEndian
        options = options.advanced(by: 1)

        for i in 0..<Int(numSacks) {
            options.pointee = pcb.rcvSacks[i].left.bigEndian
            options = options.advanced(by: 1)
            options.pointee = pcb.rcvSacks[i].right.bigEndian
            options = options.advanced(by: 1)
        }
    }

    /// Write the window scale option into the options area.
    ///
    /// Layout (4 bytes = 1 x UInt32 word):
    /// ```
    /// NOP  Kind=3  Len=3  ShiftCount
    /// ```
    ///
    /// - Parameters:
    ///   - options: Pointer to the current position in the options buffer;
    ///     advanced by 1 word on return.
    ///   - scale: The receive window scale shift count.
    private func buildWindowScaleOption(options: inout UnsafeMutablePointer<UInt32>,
                                        scale: UInt8) {
        // NOP + WS kind=3 len=3 value
        options.pointee = UInt32(0x0103_0300 | UInt32(scale)).bigEndian
        options = options.advanced(by: 1)
    }

    /// Orchestrator that calls the individual option builders based on the
    /// segment's option flags.
    ///
    /// MSS is intentionally **not** handled here because it is only sent on SYN
    /// segments and is written inline by the caller before invoking this method.
    ///
    /// - Parameters:
    ///   - pcb: The TCP control block.
    ///   - options: Pointer to the current position in the options buffer;
    ///     advanced past all written options on return.
    ///   - optFlags: Which options to write.
    private func fillOptions(pcb: TCPControlBlock,
                             options: inout UnsafeMutablePointer<UInt32>,
                             optFlags: TCPSegOptFlags) {
        if optFlags.contains(.timestamp) {
            buildTimestampOption(options: &options, pcb: pcb)
        }

        if optFlags.contains(.wndScale) {
            buildWindowScaleOption(options: &options, scale: pcb.receiveScale)
        }

        if optFlags.contains(.sackPerm) {
            buildSACKPermittedOption(options: &options)
        }
    }

    // MARK: - SACK Output Helpers

    /// Calculate how many SACK ranges can fit in remaining option space.
    ///
    /// The first SACK takes 12 bytes (2 NOP + kind + length + 1 range of 8
    /// bytes).  Each additional range adds 8 bytes.  The total options area
    /// is capped at `TCPConstants.maxOptionBytes` (40).
    private func getNumSacks(pcb: TCPControlBlock, currentOptLen: UInt8) -> UInt8 {
        guard pcb.flags.contains(.sack) else { return 0 }
        var numSacks: UInt8 = 0
        var optLen = currentOptLen + 12  // First SACK takes 12 bytes

        for i in 0..<TCPControlBlock.maxSACKNum {
            guard optLen <= UInt8(TCPConstants.maxOptionBytes),
                  pcb.sackIsValid(i) else { break }
            numSacks += 1
            optLen += 8
        }
        return numSacks
    }
}
