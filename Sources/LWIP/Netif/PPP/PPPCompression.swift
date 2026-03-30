//
//  PPPCompression.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Van Jacobson Compression (RFC 1144)

/// VJ compression packet types.
public enum VJPacketType: UInt8, Sendable {
    /// Normal uncompressed IP packet.
    case ip             = 0
    /// Uncompressed TCP (with connection ID in protocol field).
    case uncompressedTCP = 1
    /// Compressed TCP header.
    case compressedTCP   = 2
}

/// VJ compression change flags.
public struct VJChangeFlags {
    /// New urgent pointer
    public static let newU: UInt8        = 0x01
    /// New window size
    public static let newW: UInt8        = 0x02
    /// New acknowledgement number
    public static let newA: UInt8        = 0x04
    /// New sequence number
    public static let newS: UInt8        = 0x08
    /// New IP ID
    public static let newI: UInt8        = 0x10
    /// New connection ID present
    public static let newC: UInt8        = 0x40
    /// TCP PUSH flag
    public static let pushBit: UInt8     = 0x20
    /// Special case: echoed interactive traffic
    public static let specialI: UInt8    = 0x08 | 0x04  // NEW_S | NEW_A
    /// Special case: unidirectional data transfer
    public static let specialD: UInt8    = 0x08          // NEW_S
    /// Mask for special cases
    public static let specialsMask: UInt8 = 0x0C
    /// Toss flag: indicates error/desync
    public static let toss: UInt8        = 0x80
}

/// Connection state for VJ compression, storing the last TCP/IP header.
public struct VJConnectionState {
    /// Connection ID (slot index).
    public var id: UInt8 = 0
    /// Cached header data (IP + TCP headers).
    public var headerData = [UInt8](repeating: 0, count: 128)
    /// Length of cached header.
    public var headerLength: UInt16 = 0

    public init() {}
}

/// Van Jacobson TCP/IP header compression state.
///
/// Implements RFC 1144 for compressing TCP/IP headers over serial links.
/// Maintains a ring of connection states for recently-seen TCP connections.
public struct VJCompressionState {

    /// Maximum number of compression slots.
    public static let maxSlots: Int = 16
    /// Maximum header size we cache.
    public static let maxHeader: Int = 128

    /// Transmit connection states (ring).
    public var transmitStates: [VJConnectionState]
    /// Receive connection states.
    public var receiveStates: [VJConnectionState]

    /// Index of last used transmit state.
    public var lastTransmitIndex: Int = 0
    /// Transmit LRU ordering (indices into transmitStates).
    public var transmitLRU: [Int]

    /// Index of most recently used slot for compression.
    public var lastXmitSlot: UInt8 = 255
    /// Index of most recently received slot.
    public var lastRecvSlot: UInt8 = 255

    /// Whether to compress the connection/slot ID.
    public var compressSlot: Bool = false
    /// Maximum slot index in use.
    public var maxSlotIndex: UInt8
    /// Flags (e.g., toss).
    public var flags: UInt8 = VJChangeFlags.toss

    /// Statistics.
    public var stats = VJStats()

    /// Initialize VJ compression state with the given maximum number of slots.
    public init(maxSlots: Int = VJCompressionState.maxSlots) {
        let count = min(maxSlots, VJCompressionState.maxSlots)
        self.maxSlotIndex = UInt8(count - 1)

        transmitStates = (0..<count).map { i in
            var s = VJConnectionState()
            s.id = UInt8(i)
            return s
        }
        receiveStates = (0..<count).map { i in
            var s = VJConnectionState()
            s.id = UInt8(i)
            return s
        }

        // Build LRU chain: each entry points to the previous (circular)
        transmitLRU = (0..<count).map { i in (i > 0) ? i - 1 : count - 1 }

        lastTransmitIndex = 0
        lastXmitSlot = 255
        lastRecvSlot = 255
        compressSlot = false
        flags = VJChangeFlags.toss
    }

    /// Called when we may have missed a packet -- sets toss flag.
    public mutating func uncompressError() {
        flags |= VJChangeFlags.toss
        stats.errorIn += 1
    }

    /// Attempt to compress a TCP/IP packet using VJ header compression.
    ///
    /// - Parameter packet: The full IP packet data.
    /// - Returns: A tuple of (type, compressedData). The type indicates whether
    ///   the packet was compressed, left uncompressed, or passed through as-is.
    public mutating func compress(packet: [UInt8]) -> (VJPacketType, [UInt8]) {
        guard packet.count >= 40 else { return (.ip, packet) }

        // Check IP protocol == TCP (6)
        let ipProto = packet[9]
        guard ipProto == 6 else { return (.ip, packet) }

        // Check for IP fragments
        let fragOffset = (UInt16(packet[6]) << 8) | UInt16(packet[7])
        guard (fragOffset & 0x3FFF) == 0 else { return (.ip, packet) }

        // IP header length in bytes
        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20 && packet.count >= ihl + 20 else { return (.ip, packet) }

        // TCP header offset
        let tcpOffset = ihl
        let tcpFlags = packet[tcpOffset + 13]

        // Only compress if ACK is set and SYN/FIN/RST are clear
        guard (tcpFlags & 0x17) == 0x10 else { return (.ip, packet) }

        // TCP header length
        let tcpHdrLen = Int((packet[tcpOffset + 12] >> 4)) * 4
        let totalHdrLen = ihl + tcpHdrLen
        guard packet.count >= totalHdrLen else { return (.ip, packet) }

        stats.packets += 1

        // Try to find matching connection state (by src/dst IP and src/dst port)
        let srcIP = Array(packet[12..<16])
        let dstIP = Array(packet[16..<20])
        let srcPort = Array(packet[tcpOffset..<tcpOffset + 2])
        let dstPort = Array(packet[tcpOffset + 2..<tcpOffset + 4])

        var foundSlot: Int? = nil
        for i in 0..<transmitStates.count {
            let cs = transmitStates[i]
            guard cs.headerLength >= UInt16(totalHdrLen) else { continue }
            let hdr = cs.headerData
            if hdr[12..<16].elementsEqual(srcIP)
                && hdr[16..<20].elementsEqual(dstIP) {
                let csIHL = Int(hdr[0] & 0x0F) * 4
                if hdr[csIHL..<csIHL + 2].elementsEqual(srcPort)
                    && hdr[csIHL + 2..<csIHL + 4].elementsEqual(dstPort) {
                    foundSlot = i
                    break
                }
            }
        }

        guard let slot = foundSlot else {
            // No match found -- use the oldest slot, send uncompressed
            stats.misses += 1
            let useSlot = Int(maxSlotIndex)
            var state = transmitStates[useSlot]
            let headerSlice = Array(packet[0..<totalHdrLen])
            state.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
            state.headerLength = UInt16(totalHdrLen)
            transmitStates[useSlot] = state

            var result = packet
            result[9] = state.id  // Store connection ID in protocol field
            lastXmitSlot = state.id
            return (.uncompressedTCP, result)
        }

        stats.searches += 1

        // Found matching connection -- check for changes
        let cs = transmitStates[slot]
        let prevHdr = Array(cs.headerData[0..<Int(cs.headerLength)])
        let prevIHL = Int(prevHdr[0] & 0x0F) * 4
        let prevTcpHdrLen = Int((prevHdr[prevIHL + 12] >> 4)) * 4

        // Verify constant fields haven't changed
        guard packet[0] == prevHdr[0],  // version + IHL
              packet[6] == prevHdr[6],  // flags
              packet[8] == prevHdr[8],  // TTL
              packet[9] == prevHdr[9],  // protocol
              tcpHdrLen == prevTcpHdrLen else {
            // Too many differences -- send uncompressed
            var state = transmitStates[slot]
            let headerSlice = Array(packet[0..<totalHdrLen])
            state.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
            state.headerLength = UInt16(totalHdrLen)
            transmitStates[slot] = state

            var result = packet
            result[9] = state.id
            lastXmitSlot = state.id
            return (.uncompressedTCP, result)
        }

        // Compute deltas for sequence number, ack number, window, urgent, IP ID
        var changes: UInt8 = 0
        var encoded = [UInt8]()

        // Helper: encode a 16-bit nonzero delta
        func encode(_ delta: UInt16) {
            if delta >= 256 {
                encoded.append(0)
                encoded.append(UInt8(delta >> 8))
                encoded.append(UInt8(delta & 0xFF))
            } else {
                encoded.append(UInt8(delta))
            }
        }

        // Helper: encode a 16-bit delta that may be zero
        func encodeZ(_ delta: UInt16) {
            if delta >= 256 || delta == 0 {
                encoded.append(0)
                encoded.append(UInt8(delta >> 8))
                encoded.append(UInt8(delta & 0xFF))
            } else {
                encoded.append(UInt8(delta))
            }
        }

        // Check urgent
        if (tcpFlags & 0x20) != 0 {
            let urgp = (UInt16(packet[tcpOffset + 18]) << 8) | UInt16(packet[tcpOffset + 19])
            encodeZ(urgp)
            changes |= VJChangeFlags.newU
        }

        // Check window change
        let curWnd = (UInt16(packet[tcpOffset + 14]) << 8) | UInt16(packet[tcpOffset + 15])
        let prevWnd = (UInt16(prevHdr[prevIHL + 14]) << 8) | UInt16(prevHdr[prevIHL + 15])
        if curWnd != prevWnd {
            let deltaW = curWnd &- prevWnd
            encode(deltaW)
            changes |= VJChangeFlags.newW
        }

        // Check ack change
        let curAck = (UInt32(packet[tcpOffset + 8]) << 24) | (UInt32(packet[tcpOffset + 9]) << 16)
                   | (UInt32(packet[tcpOffset + 10]) << 8) | UInt32(packet[tcpOffset + 11])
        let prevAck = (UInt32(prevHdr[prevIHL + 8]) << 24) | (UInt32(prevHdr[prevIHL + 9]) << 16)
                    | (UInt32(prevHdr[prevIHL + 10]) << 8) | UInt32(prevHdr[prevIHL + 11])
        let deltaAck = curAck &- prevAck
        if deltaAck != 0 {
            guard deltaAck <= 0xFFFF else {
                // Delta too large -- send uncompressed
                var st = transmitStates[slot]
                let headerSlice = Array(packet[0..<totalHdrLen])
                st.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
                st.headerLength = UInt16(totalHdrLen)
                transmitStates[slot] = st
                var result = packet
                result[9] = st.id
                lastXmitSlot = st.id
                return (.uncompressedTCP, result)
            }
            encode(UInt16(deltaAck))
            changes |= VJChangeFlags.newA
        }

        // Check seq change
        let curSeq = (UInt32(packet[tcpOffset + 4]) << 24) | (UInt32(packet[tcpOffset + 5]) << 16)
                   | (UInt32(packet[tcpOffset + 6]) << 8) | UInt32(packet[tcpOffset + 7])
        let prevSeq = (UInt32(prevHdr[prevIHL + 4]) << 24) | (UInt32(prevHdr[prevIHL + 5]) << 16)
                    | (UInt32(prevHdr[prevIHL + 6]) << 8) | UInt32(prevHdr[prevIHL + 7])
        let deltaSeq = curSeq &- prevSeq
        if deltaSeq != 0 {
            guard deltaSeq <= 0xFFFF else {
                var st = transmitStates[slot]
                let headerSlice = Array(packet[0..<totalHdrLen])
                st.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
                st.headerLength = UInt16(totalHdrLen)
                transmitStates[slot] = st
                var result = packet
                result[9] = st.id
                lastXmitSlot = st.id
                return (.uncompressedTCP, result)
            }
            encode(UInt16(deltaSeq))
            changes |= VJChangeFlags.newS
        }

        // Handle special cases
        let prevTotalLen = (UInt16(prevHdr[2]) << 8) | UInt16(prevHdr[3])

        switch changes {
        case 0:
            let curTotalLen = (UInt16(packet[2]) << 8) | UInt16(packet[3])
            if curTotalLen != prevTotalLen && prevTotalLen == UInt16(totalHdrLen) {
                break // Data following an ACK
            }
            // Probably retransmit -- send uncompressed
            var st = transmitStates[slot]
            let headerSlice = Array(packet[0..<totalHdrLen])
            st.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
            st.headerLength = UInt16(totalHdrLen)
            transmitStates[slot] = st
            var result = packet
            result[9] = st.id
            lastXmitSlot = st.id
            return (.uncompressedTCP, result)

        case VJChangeFlags.specialI, VJChangeFlags.specialD:
            // Actual changes match special encodings -- send uncompressed
            var st = transmitStates[slot]
            let headerSlice = Array(packet[0..<totalHdrLen])
            st.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
            st.headerLength = UInt16(totalHdrLen)
            transmitStates[slot] = st
            var result = packet
            result[9] = st.id
            lastXmitSlot = st.id
            return (.uncompressedTCP, result)

        case VJChangeFlags.newS | VJChangeFlags.newA:
            if UInt16(deltaSeq) == UInt16(deltaAck) && UInt16(deltaSeq) == prevTotalLen &- UInt16(totalHdrLen) {
                changes = VJChangeFlags.specialI
                encoded.removeAll()
            }

        case VJChangeFlags.newS:
            if UInt16(deltaSeq) == prevTotalLen &- UInt16(totalHdrLen) {
                changes = VJChangeFlags.specialD
                encoded.removeAll()
            }

        default:
            break
        }

        // Check IP ID change
        let curID = (UInt16(packet[4]) << 8) | UInt16(packet[5])
        let prevID = (UInt16(prevHdr[4]) << 8) | UInt16(prevHdr[5])
        let deltaID = curID &- prevID
        if deltaID != 1 {
            encodeZ(deltaID)
            changes |= VJChangeFlags.newI
        }

        if (tcpFlags & 0x08) != 0 {
            changes |= VJChangeFlags.pushBit
        }

        // Grab the TCP checksum before updating state
        let tcpChecksum = (UInt16(packet[tcpOffset + 16]) << 8) | UInt16(packet[tcpOffset + 17])

        // Update state
        var st = transmitStates[slot]
        let headerSlice = Array(packet[0..<totalHdrLen])
        st.headerData.replaceSubrange(0..<totalHdrLen, with: headerSlice)
        st.headerLength = UInt16(totalHdrLen)
        transmitStates[slot] = st

        // Build compressed packet
        var compressed = [UInt8]()

        if !compressSlot || lastXmitSlot != st.id {
            lastXmitSlot = st.id
            compressed.append(changes | VJChangeFlags.newC)
            compressed.append(st.id)
        } else {
            compressed.append(changes)
        }

        // TCP checksum
        compressed.append(UInt8(tcpChecksum >> 8))
        compressed.append(UInt8(tcpChecksum & 0xFF))

        // Encoded deltas
        compressed.append(contentsOf: encoded)

        // Payload (everything after the original headers)
        if packet.count > totalHdrLen {
            compressed.append(contentsOf: packet[totalHdrLen...])
        }

        stats.compressed += 1
        return (.compressedTCP, compressed)
    }

    /// Process a received uncompressed TCP packet (TYPE_UNCOMPRESSED_TCP).
    ///
    /// The protocol field contains the connection ID. This restores it to TCP (6)
    /// and updates the receive state.
    ///
    /// - Parameter packet: The received IP packet (modified in-place).
    /// - Returns: The corrected packet, or nil on error.
    public mutating func uncompressUncomp(_ packet: [UInt8]) -> [UInt8]? {
        guard packet.count >= 40 else {
            uncompressError()
            return nil
        }

        let slotID = packet[9]  // connection ID stored in protocol field
        guard slotID <= maxSlotIndex else {
            uncompressError()
            return nil
        }

        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20 && packet.count >= ihl + 20 else {
            uncompressError()
            return nil
        }

        let tcpHdrLen = Int((packet[ihl + 12] >> 4)) * 4
        let totalHdrLen = ihl + tcpHdrLen
        guard packet.count >= totalHdrLen && totalHdrLen <= VJCompressionState.maxHeader else {
            uncompressError()
            return nil
        }

        lastRecvSlot = slotID
        flags &= ~VJChangeFlags.toss

        var result = packet
        result[9] = 6  // Restore TCP protocol number

        receiveStates[Int(slotID)].headerData.replaceSubrange(0..<totalHdrLen, with: result[0..<totalHdrLen])
        receiveStates[Int(slotID)].headerLength = UInt16(totalHdrLen)

        stats.uncompressedIn += 1
        return result
    }

    /// Decompress a TYPE_COMPRESSED_TCP packet.
    ///
    /// - Parameter data: The compressed packet data.
    /// - Returns: The decompressed full IP packet, or nil on error.
    public mutating func uncompressTCP(_ data: [UInt8]) -> [UInt8]? {
        guard data.count >= 3 else {
            uncompressError()
            return nil
        }

        stats.compressedIn += 1

        var offset = 0
        let changes = data[offset]; offset += 1

        // Get connection ID
        if (changes & VJChangeFlags.newC) != 0 {
            guard data.count > offset else {
                uncompressError()
                return nil
            }
            let slotID = data[offset]; offset += 1
            guard slotID <= maxSlotIndex else {
                uncompressError()
                return nil
            }
            flags &= ~VJChangeFlags.toss
            lastRecvSlot = slotID
        } else {
            if (flags & VJChangeFlags.toss) != 0 {
                stats.tossed += 1
                return nil
            }
        }

        var cs = receiveStates[Int(lastRecvSlot)]
        guard cs.headerLength > 0 else {
            uncompressError()
            return nil
        }

        var hdr = Array(cs.headerData[0..<Int(cs.headerLength)])
        let ihl = Int(hdr[0] & 0x0F) * 4
        let tcpOff = ihl

        // Read TCP checksum
        guard data.count >= offset + 2 else {
            uncompressError()
            return nil
        }
        hdr[tcpOff + 16] = data[offset]; offset += 1
        hdr[tcpOff + 17] = data[offset]; offset += 1

        // Handle PUSH flag
        if (changes & VJChangeFlags.pushBit) != 0 {
            hdr[tcpOff + 13] |= 0x08
        } else {
            hdr[tcpOff + 13] &= ~0x08
        }

        // Decode changes
        let specials = changes & VJChangeFlags.specialsMask
        switch specials {
        case VJChangeFlags.specialI:
            // Echoed interactive traffic
            let prevLen = (UInt16(hdr[2]) << 8) | UInt16(hdr[3])
            let dataLen = UInt32(prevLen) - UInt32(cs.headerLength)
            // ack += dataLen
            var ack = readUInt32BE(hdr, tcpOff + 8)
            ack = ack &+ dataLen
            writeUInt32BE(ack, &hdr, tcpOff + 8)
            // seq += dataLen
            var seq = readUInt32BE(hdr, tcpOff + 4)
            seq = seq &+ dataLen
            writeUInt32BE(seq, &hdr, tcpOff + 4)

        case VJChangeFlags.specialD:
            // Unidirectional data transfer
            let prevLen = (UInt16(hdr[2]) << 8) | UInt16(hdr[3])
            let dataLen = UInt32(prevLen) - UInt32(cs.headerLength)
            var seq = readUInt32BE(hdr, tcpOff + 4)
            seq = seq &+ dataLen
            writeUInt32BE(seq, &hdr, tcpOff + 4)

        default:
            // Decode individual fields
            if (changes & VJChangeFlags.newU) != 0 {
                hdr[tcpOff + 13] |= 0x20  // Set URG
                let (val, adv) = decodeU(data, offset)
                offset += adv
                hdr[tcpOff + 18] = UInt8(val >> 8)
                hdr[tcpOff + 19] = UInt8(val & 0xFF)
            } else {
                hdr[tcpOff + 13] &= ~0x20  // Clear URG
            }
            if (changes & VJChangeFlags.newW) != 0 {
                let (delta, adv) = decodeS(data, offset)
                offset += adv
                var wnd = (UInt16(hdr[tcpOff + 14]) << 8) | UInt16(hdr[tcpOff + 15])
                wnd = wnd &+ delta
                hdr[tcpOff + 14] = UInt8(wnd >> 8)
                hdr[tcpOff + 15] = UInt8(wnd & 0xFF)
            }
            if (changes & VJChangeFlags.newA) != 0 {
                let (delta, adv) = decodeL(data, offset)
                offset += adv
                var ack = readUInt32BE(hdr, tcpOff + 8)
                ack = ack &+ UInt32(delta)
                writeUInt32BE(ack, &hdr, tcpOff + 8)
            }
            if (changes & VJChangeFlags.newS) != 0 {
                let (delta, adv) = decodeL(data, offset)
                offset += adv
                var seq = readUInt32BE(hdr, tcpOff + 4)
                seq = seq &+ UInt32(delta)
                writeUInt32BE(seq, &hdr, tcpOff + 4)
            }
        }

        // Decode IP ID
        if (changes & VJChangeFlags.newI) != 0 {
            let (delta, adv) = decodeS(data, offset)
            offset += adv
            var ipID = (UInt16(hdr[4]) << 8) | UInt16(hdr[5])
            ipID = ipID &+ delta
            hdr[4] = UInt8(ipID >> 8)
            hdr[5] = UInt8(ipID & 0xFF)
        } else {
            var ipID = (UInt16(hdr[4]) << 8) | UInt16(hdr[5])
            ipID = ipID &+ 1
            hdr[4] = UInt8(ipID >> 8)
            hdr[5] = UInt8(ipID & 0xFF)
        }

        // Compute new total length
        let payloadLength = data.count - offset
        let newTotalLen = UInt16(cs.headerLength) + UInt16(payloadLength)
        hdr[2] = UInt8(newTotalLen >> 8)
        hdr[3] = UInt8(newTotalLen & 0xFF)

        // Recompute IP header checksum
        hdr[10] = 0
        hdr[11] = 0
        var cksum: UInt32 = 0
        for i in stride(from: 0, to: ihl, by: 2) {
            cksum += UInt32(hdr[i]) << 8 | UInt32(hdr[i + 1])
        }
        cksum = (cksum & 0xFFFF) + (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16)
        let finalCksum = ~UInt16(cksum & 0xFFFF)
        hdr[10] = UInt8(finalCksum >> 8)
        hdr[11] = UInt8(finalCksum & 0xFF)

        // Update receive state
        cs.headerData.replaceSubrange(0..<hdr.count, with: hdr)
        cs.headerLength = UInt16(hdr.count)
        receiveStates[Int(lastRecvSlot)] = cs

        // Build decompressed packet: header + payload
        var result = hdr
        if offset < data.count {
            result.append(contentsOf: data[offset...])
        }

        return result
    }

    // MARK: - VJ Decode Helpers

    /// Decode a 16-bit delta for sequence/ack (long form).
    private func decodeL(_ data: [UInt8], _ offset: Int) -> (UInt16, Int) {
        guard offset < data.count else { return (0, 0) }
        if data[offset] == 0 {
            guard offset + 2 < data.count else { return (0, 1) }
            let val = (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2])
            return (val, 3)
        } else {
            return (UInt16(data[offset]), 1)
        }
    }

    /// Decode a 16-bit delta (short form, for window/IP ID).
    private func decodeS(_ data: [UInt8], _ offset: Int) -> (UInt16, Int) {
        return decodeL(data, offset)
    }

    /// Decode an unsigned 16-bit value (for urgent pointer).
    private func decodeU(_ data: [UInt8], _ offset: Int) -> (UInt16, Int) {
        guard offset < data.count else { return (0, 0) }
        if data[offset] == 0 {
            guard offset + 2 < data.count else { return (0, 1) }
            let val = (UInt16(data[offset + 1]) << 8) | UInt16(data[offset + 2])
            return (val, 3)
        } else {
            return (UInt16(data[offset]), 1)
        }
    }

    /// Read a big-endian UInt32 from a byte array.
    private func readUInt32BE(_ data: [UInt8], _ offset: Int) -> UInt32 {
        return (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16)
             | (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
    }

    /// Write a big-endian UInt32 to a byte array.
    private func writeUInt32BE(_ value: UInt32, _ data: inout [UInt8], _ offset: Int) {
        data[offset]     = UInt8(truncatingIfNeeded: value >> 24)
        data[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        data[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        data[offset + 3] = UInt8(truncatingIfNeeded: value)
    }
}

/// VJ compression statistics.
public struct VJStats {
    /// Total packets considered for compression.
    public var packets: UInt32 = 0
    /// Packets that were compressed.
    public var compressed: UInt32 = 0
    /// Connection state searches performed.
    public var searches: UInt32 = 0
    /// Connection state misses (no matching state found).
    public var misses: UInt32 = 0
    /// Received uncompressed TCP packets.
    public var uncompressedIn: UInt32 = 0
    /// Received compressed TCP packets.
    public var compressedIn: UInt32 = 0
    /// Packets tossed due to desync.
    public var tossed: UInt32 = 0
    /// Error count.
    public var errorIn: UInt32 = 0

    public init() {}
}

// MARK: - MPPE (Microsoft Point-to-Point Encryption, RFC 3078)

/// MPPE bit flags in the coherency count header.
public struct MPPEBits {
    /// Encryption table (re)initialized.
    public static let flushed: UInt8    = 0x80
    /// Frame is encrypted.
    public static let encrypted: UInt8  = 0x10
}

/// MPPE option flags for CCP negotiation.
public struct MPPEOption {
    /// 40-bit encryption.
    public static let opt40: UInt8     = 0x01
    /// 128-bit encryption.
    public static let opt128: UInt8    = 0x02
    /// Stateful mode.
    public static let stateful: UInt8  = 0x04
}

/// MPPE encryption/decryption state.
///
/// Implements the MPPE protocol (RFC 3078) using ARC4 stream cipher
/// for PPP data encryption. Used with MS-CHAP authentication.
public final class MPPEState {

    /// MPPE overhead per packet (2 bytes of coherency count).
    public static let overhead: Int = 2
    /// Maximum sanity errors before closing the link.
    public static let sanityMax: Int = 1600
    /// SHA1 padding constants used in MPPE key derivation.
    public static let sha1Pad1: [UInt8] = [UInt8](repeating: 0x00, count: 40)
    public static let sha1Pad2: [UInt8] = [UInt8](repeating: 0xF2, count: 40)
    /// Maximum MPPE key length (128-bit).
    public static let maxKeyLength: Int = 16
    /// Coherency count space (12-bit counter wraps at 4096).
    public static let coherencyCountSpace: UInt16 = 0x1000

    /// Master key (derived from MS-CHAP authentication).
    public var masterKey = [UInt8](repeating: 0, count: MPPEState.maxKeyLength)
    /// Current session key.
    public var sessionKey = [UInt8](repeating: 0, count: MPPEState.maxKeyLength)
    /// Key length in bytes (8 for 40-bit, 16 for 128-bit).
    public var keyLen: Int = 0
    /// ARC4 cipher context.
    public var arc4 = ARC4Context()

    /// Coherency count (12-bit rolling counter).
    public var ccount: UInt16 = 0
    /// Current MPPE header bits.
    public var bits: UInt8 = 0
    /// Whether stateful mode is enabled.
    var isStateful: Bool = false
    /// Whether we are in discard state (stateful mode).
    var shouldDiscard: Bool = false
    /// Sanity error counter.
    public var sanityErrors: Int = 0

    public init() {}

    /// Set the master key (called by MS-CHAP before `initialize`).
    public func setKey(_ key: [UInt8]) {
        let count = min(key.count, MPPEState.maxKeyLength)
        for i in 0..<count {
            masterKey[i] = key[i]
        }
    }

    /// Initialize the MPPE state with the given options.
    ///
    /// - Parameter options: MPPE option flags (opt40, opt128, stateful).
    public func initialize(options: UInt8) {
        // Copy master key to session key
        for i in 0..<MPPEState.maxKeyLength {
            sessionKey[i] = masterKey[i]
        }

        if (options & MPPEOption.opt128) != 0 {
            keyLen = 16
        } else if (options & MPPEOption.opt40) != 0 {
            keyLen = 8
        } else {
            keyLen = 0
            return
        }

        if (options & MPPEOption.stateful) != 0 {
            isStateful = true
        }

        // Generate initial session key
        rekey(initial: true)

        // Initialize coherency count
        ccount = MPPEState.coherencyCountSpace - 1
        bits = MPPEBits.encrypted
    }

    /// Perform the MPPE rekey algorithm (RFC 3078, sec. 7.3).
    public func rekey(initial: Bool = false) {
        // SHA1(masterKey + pad1 + sessionKey + pad2)
        var sha1 = SHA1Context()
        sha1.starts()
        sha1.update(Array(masterKey[0..<keyLen]))
        sha1.update(MPPEState.sha1Pad1)
        sha1.update(Array(sessionKey[0..<keyLen]))
        sha1.update(MPPEState.sha1Pad2)
        let digest = sha1.finish()

        for i in 0..<keyLen {
            sessionKey[i] = digest[i]
        }

        if !initial {
            // Encrypt session key with itself
            var tempARC4 = ARC4Context()
            tempARC4.setup(key: Array(digest[0..<keyLen]))
            var keySlice = Array(sessionKey[0..<keyLen])
            tempARC4.crypt(&keySlice)
            for i in 0..<keyLen {
                sessionKey[i] = keySlice[i]
            }
        }

        // For 40-bit encryption, fix the first 3 bytes per RFC 3078
        if keyLen == 8 {
            sessionKey[0] = 0xD1
            sessionKey[1] = 0x26
            sessionKey[2] = 0x9E
        }

        // Setup ARC4 with the new session key
        arc4.setup(key: Array(sessionKey[0..<keyLen]))
    }

    /// Signal that the compressor should rekey on the next transmitted packet.
    public func compressReset() {
        bits |= MPPEBits.flushed
    }

    /// Encrypt a packet.
    ///
    /// - Parameters:
    ///   - payload: The payload data to encrypt.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The MPPE-encapsulated encrypted packet, or nil on error.
    public func encrypt(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        ccount = (ccount + 1) % MPPEState.coherencyCountSpace

        // Build MPPE header
        var header = [UInt8](repeating: 0, count: 2)
        header[0] = UInt8(ccount >> 8)
        header[1] = UInt8(ccount & 0xFF)

        // Determine if rekeying is needed
        if !isStateful || ((ccount & 0xFF) == 0xFF) || (bits & MPPEBits.flushed) != 0 {
            rekey()
            bits |= MPPEBits.flushed
        }

        header[0] |= bits
        bits &= ~MPPEBits.flushed

        // Protocol field + payload
        var plaintext = [UInt8]()
        plaintext.append(UInt8(proto >> 8))
        plaintext.append(UInt8(proto & 0xFF))
        plaintext.append(contentsOf: payload)

        // Encrypt
        let ciphertext = arc4.crypt(plaintext)
        _ = ciphertext  // consume return

        var result = header
        result.append(contentsOf: ciphertext)
        return result
    }

    /// Decrypt an MPPE packet.
    ///
    /// - Parameter data: The received MPPE-encapsulated data.
    /// - Returns: The decrypted payload (including protocol field), or nil on error.
    public func decrypt(data: [UInt8]) -> [UInt8]? {
        guard data.count >= MPPEState.overhead else {
            sanityErrors += 100
            return nil
        }

        let flushed = (data[0] & 0xF0) & MPPEBits.flushed
        let receivedCCount = ((UInt16(data[0] & 0x0F) << 8) | UInt16(data[1]))

        // Sanity checks
        guard (data[0] & 0xF0) & MPPEBits.encrypted != 0 else {
            sanityErrors += 100
            return nil
        }

        if !isStateful && flushed == 0 {
            sanityErrors += 100
            return nil
        }

        if isStateful && ((receivedCCount & 0xFF) == 0xFF) && flushed == 0 {
            sanityErrors += 100
            return nil
        }

        // Coherency count handling
        if !isStateful {
            // Stateless: discard late packets
            let diff = (receivedCCount &- ccount) % MPPEState.coherencyCountSpace
            if diff > MPPEState.coherencyCountSpace / 2 {
                sanityErrors += 1
                return checkSanity()
            }
            // Rekey for every missed packet
            while ccount != receivedCCount {
                rekey()
                ccount = (ccount + 1) % MPPEState.coherencyCountSpace
            }
        } else {
            // Stateful mode
            if !shouldDiscard {
                ccount = (ccount + 1) % MPPEState.coherencyCountSpace
                if receivedCCount != ccount {
                    shouldDiscard = true
                    return nil  // Signal CCP to send Reset-Request
                }
            } else {
                if flushed == 0 {
                    return nil
                }
                // Rekey for missed flag packets
                while (receivedCCount & 0xFF00) != (ccount & 0xFF00) {
                    rekey()
                    ccount = (ccount &+ 256) % MPPEState.coherencyCountSpace
                }
                shouldDiscard = false
                ccount = receivedCCount
            }
            if flushed != 0 {
                rekey()
            }
        }

        // Decrypt payload
        let encrypted = Array(data[MPPEState.overhead...])
        let decrypted = arc4.crypt(encrypted)

        // Credit for good packet
        sanityErrors >>= 1

        return decrypted
    }

    private func checkSanity() -> [UInt8]? {
        if sanityErrors >= MPPEState.sanityMax {
            // Too many errors -- signal to close the link
            return nil
        }
        return nil
    }
}

// MARK: - CCP (Compression Control Protocol, RFC 1962)

/// CCP configuration option types.
public enum CCPOptionType: UInt8, Sendable {
    /// MPPE encryption option.
    case mppe          = 18
    /// BSD Compress.
    case bsdCompression   = 21
    /// Deflate compression (RFC 1979).
    case deflate       = 26
    /// Deflate draft (old type value used by some implementations).
    case deflateDraft  = 24
    /// Predictor-1.
    case predictor1    = 1
    /// Predictor-2.
    case predictor2    = 2
}

/// CCP configuration item lengths.
private enum CCPOptionLength {
    static let mppe: Int          = 6  // type(1) + len(1) + 4 bytes MPPE opts
    static let deflate: Int       = 4  // type(1) + len(1) + window(1) + check(1)
    static let bsdCompression: Int   = 3  // type(1) + len(1) + version/bits(1)
    static let predictor1: Int    = 2  // type(1) + len(1)
    static let predictor2: Int    = 2  // type(1) + len(1)
}

/// Deflate constants for CCP negotiation (RFC 1979).
private enum DeflateConst {
    /// Method value (always 8 for zlib deflate).
    static let methodValue: UInt8 = 8
    /// Check-sequence type (always 0 for sequence number).
    static let checkSequence: UInt8 = 0
    /// Minimum window size that works.
    static let minWorks: Int = 9

    /// Make the deflate option byte: method in low 4 bits, window in high 4 bits.
    static func makeOpt(size: Int) -> UInt8 {
        return UInt8((size << 4) | Int(methodValue))
    }
    /// Extract window size from deflate option byte.
    static func size(from opt: UInt8) -> Int {
        return Int(opt >> 4)
    }
    /// Extract method from deflate option byte.
    static func method(from opt: UInt8) -> UInt8 {
        return opt & 0x0F
    }
}

/// CCP negotiation options.
public struct CCPOptions {
    /// MPPE options bitmask (0 = disabled).
    public var mppe: UInt8 = 0
    /// Deflate compression enabled.
    var isDeflate: Bool = false
    /// Deflate window size (8..15).
    public var deflateSize: Int = 15
    /// Deflate correct format (CI_DEFLATE = 26).
    public var deflateCorrect: Bool = true
    /// Deflate draft format (CI_DEFLATE_DRAFT = 24).
    public var deflateDraft: Bool = true
    /// BSD Compress enabled.
    public var bsdCompression: Bool = false
    /// BSD Compress bits.
    public var bsdBits: Int = 0
    /// Predictor-1 enabled.
    public var predictor1: Bool = false
    /// Predictor-2 enabled.
    public var predictor2: Bool = false
    /// The primary compression method (first option type in our ConfReq).
    public var method: UInt8 = 0

    public init() {}

    /// Whether any compression method is configured.
    public var anyCompression: Bool {
        return mppe != 0 || isDeflate || bsdCompression || predictor1 || predictor2
    }
}

/// CCP local state flags.
public struct CCPStateFlags {
    /// Waiting for Reset-Ack.
    public static let rackPending: UInt8  = 1
    /// Send another Reset-Req if no Reset-Ack.
    public static let rreqRepeat: UInt8   = 2
}

/// Compression Control Protocol (CCP).
///
/// Negotiates compression/encryption options between PPP peers
/// using the FSM (Finite State Machine) framework.
/// Implements the full addCI/ackCI/nakCI/rejCI/reqCI cycle to
/// properly negotiate DEFLATE, BSD Compress, Predictor, and MPPE
/// with peer PPP implementations.
public final class CCP: @unchecked Sendable, FSMCallbacks {
    public let protocolName = "CCP"

    /// The CCP FSM instance.
    public var fsm: FSM

    /// Our desired options.
    public var wantOptions = CCPOptions()
    /// Options we will actually request (adjusted through NAK/REJ).
    public var goOptions = CCPOptions()
    /// Options we allow the peer to request.
    public var allowOptions = CCPOptions()
    /// Options the peer agreed to use.
    public var hisOptions = CCPOptions()

    /// Local CCP state flags (Reset-Req/Ack handling).
    public var localFlags: UInt8 = 0
    /// Reset-Ack timeout (seconds).
    public var rackTimeout: UInt32 = 1
    /// Whether all CCP options have been rejected.
    public var allRejected: Bool = false

    /// MPPE compressor state (if MPPE negotiated).
    public var mppeCompressor: MPPEState?
    /// MPPE decompressor state (if MPPE negotiated).
    public var mppeDecompressor: MPPEState?

    /// Parent PPP connection.
    public weak var pcb: PPPControlBlock?

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
        self.fsm = FSM(pcb: pcb)
        self.fsm.protocolNumber = PPPProtocol.ccp
        self.fsm.callbacks = self
    }

    /// Initialize CCP with default options.
    public func initialize() {
        fsm.initialize()
        wantOptions = CCPOptions()
        goOptions = CCPOptions()
        allowOptions = CCPOptions()
        hisOptions = CCPOptions()
        allRejected = false
    }

    /// Open the CCP negotiation.
    public func open() {
        fsm.open()
    }

    /// Close the CCP negotiation.
    public func close(reason: String? = nil) {
        fsm.close(reason: reason)
    }

    /// Lower layer is up -- start CCP negotiation.
    public func lowerUp() {
        fsm.lowerUp()
    }

    /// Lower layer is down -- abort CCP.
    public func lowerDown() {
        fsm.lowerDown()
    }

    /// Handle incoming CCP packet.
    public func input(data: [UInt8]) {
        guard data.count >= 4 else { return }
        let code = data[0]
        let id = data[1]

        // Handle Reset-Request (code 14) and Reset-Ack (code 15) specially
        if code == 14 {
            // Reset-Request: send Reset-Ack and reset decompressor
            pcb?.sendProtocolPacket(protocol: PPPProtocol.ccp, code: 15, id: id, data: [])
            return
        }
        if code == 15 {
            // Reset-Ack: clear pending flag
            resetAck()
            return
        }

        let payload = data.count > 4 ? Array(data[4...]) : []
        fsm.input(code: code, id: id, data: payload)
    }

    /// Handle CCP protocol rejection from peer.
    public func protocolReject() {
        fsm.lowerDown()
        fsm.lowerUp()
    }

    /// Send a CCP Reset-Request to the peer.
    public func resetRequest() {
        fsm.id = fsm.id &+ 1
        localFlags |= CCPStateFlags.rackPending
        pcb?.sendProtocolPacket(protocol: PPPProtocol.ccp, code: 14, id: fsm.id, data: [])
    }

    /// Process a received CCP Reset-Ack.
    public func resetAck() {
        localFlags &= ~CCPStateFlags.rackPending
    }

    // MARK: - FSMCallbacks

    public func resetCI(_ fsm: FSM) {
        goOptions = wantOptions
        allRejected = false
    }

    /// Build our CCP Configure-Request options.
    public func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        let go = goOptions
        var offset = 0

        // MPPE (type 18, length 6)
        if go.mppe != 0 {
            buffer[offset] = CCPOptionType.mppe.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.mppe); offset += 1
            // MPPE options: 4 bytes, flags in the last byte
            buffer[offset] = 0; offset += 1
            buffer[offset] = 0; offset += 1
            buffer[offset] = 0; offset += 1
            buffer[offset] = go.mppe; offset += 1
        }

        // Deflate correct (type 26, length 4)
        if go.isDeflate && go.deflateCorrect {
            buffer[offset] = CCPOptionType.deflate.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.deflate); offset += 1
            buffer[offset] = DeflateConst.makeOpt(size: go.deflateSize); offset += 1
            buffer[offset] = DeflateConst.checkSequence; offset += 1
        }

        // Deflate draft (type 24, length 4)
        if go.isDeflate && go.deflateDraft {
            buffer[offset] = CCPOptionType.deflateDraft.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.deflate); offset += 1
            buffer[offset] = DeflateConst.makeOpt(size: go.deflateSize); offset += 1
            buffer[offset] = DeflateConst.checkSequence; offset += 1
        }

        // BSD Compress (type 21, length 3)
        if go.bsdCompression {
            buffer[offset] = CCPOptionType.bsdCompression.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.bsdCompression); offset += 1
            // Version (1) in high 3 bits, bits in low 5 bits
            buffer[offset] = UInt8((1 << 5) | (go.bsdBits & 0x1F)); offset += 1
        }

        // Predictor-1 (type 1, length 2)
        if go.predictor1 {
            buffer[offset] = CCPOptionType.predictor1.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.predictor1); offset += 1
        }

        // Predictor-2 (type 2, length 2)
        if go.predictor2 {
            buffer[offset] = CCPOptionType.predictor2.rawValue; offset += 1
            buffer[offset] = UInt8(CCPOptionLength.predictor2); offset += 1
        }

        // Record the primary method
        if offset > 0 {
            goOptions.method = buffer[0]
        } else {
            goOptions.method = 0
        }

        return offset
    }

    /// Validate that peer's Configure-Ack matches what we sent.
    public func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = goOptions
        var p = 0
        let len = data.count

        // MPPE
        if go.mppe != 0 {
            guard p + CCPOptionLength.mppe <= len else { return false }
            guard data[p] == CCPOptionType.mppe.rawValue,
                  data[p+1] == UInt8(CCPOptionLength.mppe) else { return false }
            // Verify MPPE option bytes match
            guard data[p+5] == go.mppe else { return false }
            p += CCPOptionLength.mppe
            if p == len { return true } // Fast ack
        }

        // Deflate
        if go.isDeflate {
            let expectedType: UInt8 = go.deflateCorrect
                ? CCPOptionType.deflate.rawValue : CCPOptionType.deflateDraft.rawValue
            guard p + CCPOptionLength.deflate <= len else { return false }
            guard data[p] == expectedType,
                  data[p+1] == UInt8(CCPOptionLength.deflate),
                  data[p+2] == DeflateConst.makeOpt(size: go.deflateSize),
                  data[p+3] == DeflateConst.checkSequence else { return false }
            p += CCPOptionLength.deflate
            if p == len { return true }

            // Draft variant if both are set
            if go.deflateCorrect && go.deflateDraft {
                guard p + CCPOptionLength.deflate <= len else { return false }
                guard data[p] == CCPOptionType.deflateDraft.rawValue,
                      data[p+1] == UInt8(CCPOptionLength.deflate),
                      data[p+2] == DeflateConst.makeOpt(size: go.deflateSize),
                      data[p+3] == DeflateConst.checkSequence else { return false }
                p += CCPOptionLength.deflate
            }
        }

        // BSD Compress
        if go.bsdCompression {
            guard p + CCPOptionLength.bsdCompression <= len else { return false }
            guard data[p] == CCPOptionType.bsdCompression.rawValue,
                  data[p+1] == UInt8(CCPOptionLength.bsdCompression),
                  data[p+2] == UInt8((1 << 5) | (go.bsdBits & 0x1F)) else { return false }
            p += CCPOptionLength.bsdCompression
            if p == len { return true }
        }

        // Predictor-1
        if go.predictor1 {
            guard p + CCPOptionLength.predictor1 <= len else { return false }
            guard data[p] == CCPOptionType.predictor1.rawValue,
                  data[p+1] == UInt8(CCPOptionLength.predictor1) else { return false }
            p += CCPOptionLength.predictor1
            if p == len { return true }
        }

        // Predictor-2
        if go.predictor2 {
            guard p + CCPOptionLength.predictor2 <= len else { return false }
            guard data[p] == CCPOptionType.predictor2.rawValue,
                  data[p+1] == UInt8(CCPOptionLength.predictor2) else { return false }
            p += CCPOptionLength.predictor2
        }

        return p == len
    }

    /// Process a Configure-Nak from the peer.
    public func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        let go = goOptions
        var proposedOptions = go
        var p = 0
        let len = data.count

        // MPPE
        if go.mppe != 0 && p + CCPOptionLength.mppe <= len
            && data[p] == CCPOptionType.mppe.rawValue
            && data[p+1] == UInt8(CCPOptionLength.mppe) {
            // Peer suggests different MPPE options
            let suggestedMPPE = data[p+5]
            proposedOptions.mppe = suggestedMPPE & go.mppe // Only accept bits we support
            if proposedOptions.mppe == 0 {
                // No common ground -- MPPE negotiation failed
                proposedOptions.mppe = 0
            }
            p += CCPOptionLength.mppe
        }

        // Deflate
        if go.isDeflate && p + CCPOptionLength.deflate <= len {
            let expectedType: UInt8 = go.deflateCorrect
                ? CCPOptionType.deflate.rawValue : CCPOptionType.deflateDraft.rawValue
            if data[p] == expectedType && data[p+1] == UInt8(CCPOptionLength.deflate) {
                let sugOpt = data[p+2]
                let sugCheck = data[p+3]
                if DeflateConst.method(from: sugOpt) != DeflateConst.methodValue
                    || DeflateConst.size(from: sugOpt) < DeflateConst.minWorks
                    || sugCheck != DeflateConst.checkSequence {
                    proposedOptions.isDeflate = false
                } else if DeflateConst.size(from: sugOpt) < go.deflateSize {
                    proposedOptions.deflateSize = DeflateConst.size(from: sugOpt)
                }
                p += CCPOptionLength.deflate

                // Skip draft variant if present
                if go.deflateCorrect && go.deflateDraft
                    && p + CCPOptionLength.deflate <= len
                    && data[p] == CCPOptionType.deflateDraft.rawValue
                    && data[p+1] == UInt8(CCPOptionLength.deflate) {
                    p += CCPOptionLength.deflate
                }
            }
        }

        // BSD Compress
        if go.bsdCompression && p + CCPOptionLength.bsdCompression <= len
            && data[p] == CCPOptionType.bsdCompression.rawValue
            && data[p+1] == UInt8(CCPOptionLength.bsdCompression) {
            let optByte = data[p+2]
            let version = Int(optByte >> 5)
            let bits = Int(optByte & 0x1F)
            if version != 1 {
                proposedOptions.bsdCompression = false
            } else if bits < go.bsdBits {
                proposedOptions.bsdBits = bits
            }
            p += CCPOptionLength.bsdCompression
        }

        // Predictor-1 and Predictor-2 have no options; they can't be NAK'd

        if fsm.state != .opened {
            goOptions = proposedOptions
        }
        return true
    }

    /// Process a Configure-Reject -- remove rejected options.
    public func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = goOptions
        var proposedOptions = go
        var p = 0
        let len = data.count

        // Handle empty reject (all previously rejected)
        if len == 0 && allRejected {
            return false // Signal to stop negotiating
        }

        // MPPE
        if go.mppe != 0 && p + CCPOptionLength.mppe <= len
            && data[p] == CCPOptionType.mppe.rawValue
            && data[p+1] == UInt8(CCPOptionLength.mppe) {
            proposedOptions.mppe = 0
            p += CCPOptionLength.mppe
        }

        // Deflate correct
        if go.deflateCorrect && p + CCPOptionLength.deflate <= len
            && data[p] == CCPOptionType.deflate.rawValue
            && data[p+1] == UInt8(CCPOptionLength.deflate) {
            guard data[p+2] == DeflateConst.makeOpt(size: go.deflateSize),
                  data[p+3] == DeflateConst.checkSequence else { return false }
            proposedOptions.deflateCorrect = false
            p += CCPOptionLength.deflate
        }

        // Deflate draft
        if go.deflateDraft && p + CCPOptionLength.deflate <= len
            && data[p] == CCPOptionType.deflateDraft.rawValue
            && data[p+1] == UInt8(CCPOptionLength.deflate) {
            guard data[p+2] == DeflateConst.makeOpt(size: go.deflateSize),
                  data[p+3] == DeflateConst.checkSequence else { return false }
            proposedOptions.deflateDraft = false
            p += CCPOptionLength.deflate
        }

        if !proposedOptions.deflateCorrect && !proposedOptions.deflateDraft {
            proposedOptions.isDeflate = false
        }

        // BSD Compress
        if go.bsdCompression && p + CCPOptionLength.bsdCompression <= len
            && data[p] == CCPOptionType.bsdCompression.rawValue
            && data[p+1] == UInt8(CCPOptionLength.bsdCompression) {
            guard data[p+2] == UInt8((1 << 5) | (go.bsdBits & 0x1F)) else { return false }
            proposedOptions.bsdCompression = false
            p += CCPOptionLength.bsdCompression
        }

        // Predictor-1
        if go.predictor1 && p + CCPOptionLength.predictor1 <= len
            && data[p] == CCPOptionType.predictor1.rawValue
            && data[p+1] == UInt8(CCPOptionLength.predictor1) {
            proposedOptions.predictor1 = false
            p += CCPOptionLength.predictor1
        }

        // Predictor-2
        if go.predictor2 && p + CCPOptionLength.predictor2 <= len
            && data[p] == CCPOptionType.predictor2.rawValue
            && data[p+1] == UInt8(CCPOptionLength.predictor2) {
            proposedOptions.predictor2 = false
            p += CCPOptionLength.predictor2
        }

        guard p == len else { return false }

        if fsm.state != .opened {
            goOptions = proposedOptions
        }

        // Track whether everything was rejected
        if !proposedOptions.anyCompression && proposedOptions.mppe == 0 {
            allRejected = true
        }

        return true
    }

    /// Process the peer's Configure-Request for CCP options.
    /// Examines each option and returns ACK/NAK/REJ.
    public func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        let ao = allowOptions
        var ho = CCPOptions()
        var rc: FSMCode = .configureAcknowledgment
        var nakBuffer = [UInt8]()
        var rejBuffer = [UInt8]()

        var p = 0
        let totalLen = data.count
        ho.method = (totalLen > 0) ? data[0] : 0

        while p < totalLen {
            guard p + 2 <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject; break
            }

            let citype = data[p]
            let cilen = Int(data[p+1])
            guard cilen >= 2 && p + cilen <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject; break
            }

            let ciStart = p
            let ciEnd = p + cilen
            let ciData = Array(data[ciStart..<ciEnd])
            var orc: FSMCode = .configureAcknowledgment

            switch citype {

            case CCPOptionType.mppe.rawValue:
                guard ao.mppe != 0 && cilen == CCPOptionLength.mppe else {
                    orc = .configureReject; break
                }
                let peerMPPE = data[p + 5]
                // Check if peer's flags are compatible with what we allow
                let commonBits = peerMPPE & ao.mppe
                if commonBits == 0 {
                    orc = .configureReject
                } else if commonBits != peerMPPE {
                    // NAK with only the bits we support
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(CCPOptionType.mppe.rawValue)
                    nakBuffer.append(UInt8(CCPOptionLength.mppe))
                    nakBuffer.append(0); nakBuffer.append(0); nakBuffer.append(0)
                    nakBuffer.append(commonBits)
                } else {
                    ho.mppe = peerMPPE
                }

            case CCPOptionType.deflate.rawValue, CCPOptionType.deflateDraft.rawValue:
                let isCorrect = (citype == CCPOptionType.deflate.rawValue)
                guard ao.isDeflate && cilen == CCPOptionLength.deflate else {
                    orc = .configureReject; break
                }
                if (isCorrect && !ao.deflateCorrect) || (!isCorrect && !ao.deflateDraft) {
                    orc = .configureReject; break
                }

                let optByte = data[p + 2]
                let checkByte = data[p + 3]
                let winSize = DeflateConst.size(from: optByte)
                let method = DeflateConst.method(from: optByte)

                if method != DeflateConst.methodValue
                    || checkByte != DeflateConst.checkSequence
                    || winSize > ao.deflateSize
                    || winSize < DeflateConst.minWorks {
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(citype)
                    nakBuffer.append(UInt8(CCPOptionLength.deflate))
                    nakBuffer.append(DeflateConst.makeOpt(size: ao.deflateSize))
                    nakBuffer.append(DeflateConst.checkSequence)
                } else {
                    ho.isDeflate = true
                    ho.deflateSize = winSize
                }

            case CCPOptionType.bsdCompression.rawValue:
                guard ao.bsdCompression && cilen == CCPOptionLength.bsdCompression else {
                    orc = .configureReject; break
                }
                let optByte = data[p + 2]
                let version = Int(optByte >> 5)
                let bits = Int(optByte & 0x1F)
                if version != 1 || bits > ao.bsdBits || bits < 9 {
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(CCPOptionType.bsdCompression.rawValue)
                    nakBuffer.append(UInt8(CCPOptionLength.bsdCompression))
                    nakBuffer.append(UInt8((1 << 5) | (ao.bsdBits & 0x1F)))
                } else {
                    ho.bsdCompression = true
                    ho.bsdBits = bits
                }

            case CCPOptionType.predictor1.rawValue:
                guard ao.predictor1 && cilen == CCPOptionLength.predictor1 else {
                    orc = .configureReject; break
                }
                ho.predictor1 = true

            case CCPOptionType.predictor2.rawValue:
                guard ao.predictor2 && cilen == CCPOptionLength.predictor2 else {
                    orc = .configureReject; break
                }
                ho.predictor2 = true

            default:
                orc = .configureReject
            }

            p = ciEnd

            // Combine results
            if orc == .configureAcknowledgment && rc != .configureAcknowledgment { continue }
            if orc == .configureNegativeAcknowledgment {
                if rc == .configureReject { continue }
                rc = .configureNegativeAcknowledgment
            }
            if orc == .configureReject {
                rc = .configureReject
                rejBuffer.append(contentsOf: ciData)
            }
        }

        switch rc {
        case .configureAcknowledgment:
            reject = data
        case .configureNegativeAcknowledgment:
            reject = nakBuffer
        case .configureReject:
            reject = rejBuffer
        default:
            reject = data
        }

        hisOptions = ho
        return rc
    }

    /// Deflate compressor (if deflate negotiated).
    public var deflateCompressor: DEFLATECompressor?
    /// Deflate decompressor (if deflate negotiated).
    public var deflateDecompressor: DEFLATECompressor?

    /// Compress a PPP packet using the negotiated CCP method.
    ///
    /// - Parameters:
    ///   - payload: The raw payload data.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The compressed/encrypted packet data, or nil if passthrough.
    public func compressPacket(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        // Try MPPE encryption first
        if let comp = mppeCompressor {
            return comp.encrypt(payload: payload, protocol: proto)
        }
        // Try Deflate compression
        if let comp = deflateCompressor {
            return comp.compress(payload: payload, protocol: proto)
        }
        return nil
    }

    /// Decompress a received CCP-compressed packet.
    ///
    /// - Parameter data: The received compressed/encrypted data.
    /// - Returns: The decompressed data (protocol + payload), or nil on error.
    public func decompressPacket(_ data: [UInt8]) -> [UInt8]? {
        // Try MPPE decryption first
        if let decomp = mppeDecompressor {
            return decomp.decrypt(data: data)
        }
        // Try Deflate decompression
        if let decomp = deflateDecompressor {
            return decomp.decompress(data)
        }
        return nil
    }

    /// Handle a CCP Reset-Request by resetting the compressor state.
    public func handleCompressorReset() {
        mppeCompressor?.compressReset()
        deflateCompressor?.resetCompressor()
    }

    /// Handle a CCP Reset-Ack by resetting the decompressor state.
    public func handleDecompressorReset() {
        deflateDecompressor?.resetDecompressor()
    }

    public func up(_ fsm: FSM) {
        // CCP negotiation succeeded -- compression is active
        // Initialize MPPE if negotiated
        if hisOptions.mppe != 0 {
            let comp = MPPEState()
            comp.initialize(options: hisOptions.mppe)
            mppeCompressor = comp
        }
        if goOptions.mppe != 0 {
            let decomp = MPPEState()
            decomp.initialize(options: goOptions.mppe)
            mppeDecompressor = decomp
        }

        // Initialize Deflate if negotiated
        if hisOptions.isDeflate {
            let comp = DEFLATECompressor(windowBits: hisOptions.deflateSize)
            deflateCompressor = comp
        }
        if goOptions.isDeflate {
            let decomp = DEFLATECompressor(windowBits: goOptions.deflateSize)
            deflateDecompressor = decomp
        }

        PPP.debugLog(.info, "CCP up: compression/encryption negotiated")
    }

    public func down(_ fsm: FSM) {
        mppeCompressor = nil
        mppeDecompressor = nil
        deflateCompressor = nil
        deflateDecompressor = nil
    }

    public func starting(_ fsm: FSM) {}
    public func finished(_ fsm: FSM) {}

    public func extCode(_ fsm: FSM, code: UInt8, id: UInt8, data: [UInt8]) -> Bool {
        // Handle Reset-Request (14) and Reset-Ack (15) as extended codes
        if code == 14 {
            // Reset-Request from peer -- send Reset-Ack
            pcb?.sendProtocolPacket(protocol: PPPProtocol.ccp, code: 15, id: id, data: [])
            return true
        }
        if code == 15 {
            // Reset-Ack from peer
            resetAck()
            return true
        }
        return false
    }
}

// MARK: - ECP (Encryption Control Protocol, RFC 1968)

/// ECP configuration option types (RFC 1968, RFC 2419, RFC 3162).
public enum ECPOptionType: UInt8, Sendable {
    /// DES-EDE3 CBC encryption with explicit IV (RFC 2420).
    case tripleDesDese = 2
    /// DES encryption with explicit IV (DESE, RFC 2419).
    case dese          = 3
    /// AES-CBC encryption.
    case aesCBC        = 4
}

/// ECP configuration item lengths.
private enum ECPOptionLength {
    /// DESE: type(1) + len(1) + initial nonce(8) = 10
    static let dese: Int          = 10
    /// 3DES-DESE: type(1) + len(1) + initial nonce(8) = 10
    static let tripleDesDese: Int = 10
    /// AES-CBC: type(1) + len(1) + initial IV(16) = 18
    static let aesCBC: Int        = 18
}

/// ECP negotiation options.
public struct ECPOptions {
    /// Whether ECP is enabled.
    var isEnabled: Bool = false
    /// DESE (DES with explicit IV, RFC 2419) enabled.
    public var dese: Bool = false
    /// DESE initial nonce (8 bytes).
    public var deseNonce: [UInt8] = [UInt8](repeating: 0, count: 8)
    /// 3DES-DESE (Triple-DES with explicit IV, RFC 2420) enabled.
    public var tripleDesDese: Bool = false
    /// 3DES-DESE initial nonce (8 bytes).
    public var tripleDesDeseNonce: [UInt8] = [UInt8](repeating: 0, count: 8)
    /// AES-CBC encryption enabled.
    public var aesCBC: Bool = false
    /// AES-CBC initial IV (16 bytes).
    public var aesCBCIV: [UInt8] = [UInt8](repeating: 0, count: 16)
    /// The primary encryption method (first option type in our ConfReq).
    public var method: UInt8 = 0

    public init() {}

    /// Whether any encryption method is configured.
    public var anyEncryption: Bool {
        return dese || tripleDesDese || aesCBC
    }
}

/// ECP local state flags.
public struct ECPStateFlags {
    /// Waiting for Reset-Ack.
    public static let rackPending: UInt8 = 1
    /// Send another Reset-Req if no Reset-Ack.
    public static let rreqRepeat: UInt8  = 2
}

/// Encryption Control Protocol (ECP, RFC 1968).
///
/// Negotiates encryption options between PPP peers using the FSM framework.
/// Implements the full addCI/ackCI/nakCI/rejCI/reqCI cycle to negotiate
/// DESE (RFC 2419), 3DES-DESE (RFC 2420), and AES-CBC encryption methods.
public final class ECP: @unchecked Sendable, FSMCallbacks {
    public let protocolName = "ECP"

    /// The ECP FSM instance.
    public var fsm: FSM

    /// Our desired options.
    public var wantOptions = ECPOptions()
    /// Options we will actually request (adjusted through NAK/REJ).
    public var goOptions = ECPOptions()
    /// Options we allow the peer to request.
    public var allowOptions = ECPOptions()
    /// Options the peer agreed to use.
    public var hisOptions = ECPOptions()

    /// Local ECP state flags (Reset-Req/Ack handling).
    public var localFlags: UInt8 = 0
    /// Whether all ECP options have been rejected.
    public var allRejected: Bool = false

    /// DES encryptor (if DESE negotiated).
    public var desEncryptor: DESEncryptor?
    /// Triple DES encryptor (if 3DES-DESE negotiated).
    public var tripleDesEncryptor: TripleDESEncryptor?
    /// AES-CBC encryptor (if AES-CBC negotiated).
    internal var aesCBCEncryptor: AESCBCEncryptor?

    /// The pre-shared encryption key (set before ECP negotiation begins).
    public var encryptionKey: [UInt8] = []

    /// Parent PPP connection.
    public weak var pcb: PPPControlBlock?

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
        self.fsm = FSM(pcb: pcb)
        self.fsm.protocolNumber = PPPProtocol.ecp
        self.fsm.callbacks = self
    }

    /// Initialize ECP with default options.
    public func initialize() {
        fsm.initialize()
        wantOptions = ECPOptions()
        goOptions = ECPOptions()
        allowOptions = ECPOptions()
        hisOptions = ECPOptions()
        allRejected = false
    }

    /// Open the ECP negotiation.
    public func open() {
        fsm.open()
    }

    /// Close the ECP negotiation.
    public func close(reason: String? = nil) {
        fsm.close(reason: reason)
    }

    /// Lower layer is up -- start ECP negotiation.
    public func lowerUp() {
        fsm.lowerUp()
    }

    /// Lower layer is down -- abort ECP.
    public func lowerDown() {
        fsm.lowerDown()
    }

    /// Handle incoming ECP packet.
    public func input(data: [UInt8]) {
        guard data.count >= 4 else { return }
        let code = data[0]
        let id = data[1]

        // Handle Reset-Request (code 14) and Reset-Ack (code 15) specially
        if code == 14 {
            pcb?.sendProtocolPacket(protocol: PPPProtocol.ecp, code: 15, id: id, data: [])
            return
        }
        if code == 15 {
            resetAck()
            return
        }

        let payload = data.count > 4 ? Array(data[4...]) : []
        fsm.input(code: code, id: id, data: payload)
    }

    /// Handle ECP protocol rejection.
    public func protocolReject() {
        fsm.lowerDown()
        fsm.lowerUp()
    }

    /// Send an ECP Reset-Request to the peer.
    public func resetRequest() {
        fsm.id = fsm.id &+ 1
        localFlags |= ECPStateFlags.rackPending
        pcb?.sendProtocolPacket(protocol: PPPProtocol.ecp, code: 14, id: fsm.id, data: [])
    }

    /// Process a received ECP Reset-Ack.
    public func resetAck() {
        localFlags &= ~ECPStateFlags.rackPending
    }

    // MARK: - FSMCallbacks

    public func resetCI(_ fsm: FSM) {
        goOptions = wantOptions
        allRejected = false

        // Generate random nonces/IVs for our options
        if goOptions.dese {
            PPPMagic.shared.randomBytes(&goOptions.deseNonce)
        }
        if goOptions.tripleDesDese {
            PPPMagic.shared.randomBytes(&goOptions.tripleDesDeseNonce)
        }
        if goOptions.aesCBC {
            PPPMagic.shared.randomBytes(&goOptions.aesCBCIV)
        }
    }

    /// Build our ECP Configure-Request options.
    public func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        let go = goOptions
        var offset = 0

        // DESE (type 3, length 10)
        if go.dese {
            buffer[offset] = ECPOptionType.dese.rawValue; offset += 1
            buffer[offset] = UInt8(ECPOptionLength.dese); offset += 1
            for i in 0..<8 {
                buffer[offset] = go.deseNonce[i]; offset += 1
            }
        }

        // 3DES-DESE (type 2, length 10)
        if go.tripleDesDese {
            buffer[offset] = ECPOptionType.tripleDesDese.rawValue; offset += 1
            buffer[offset] = UInt8(ECPOptionLength.tripleDesDese); offset += 1
            for i in 0..<8 {
                buffer[offset] = go.tripleDesDeseNonce[i]; offset += 1
            }
        }

        // AES-CBC (type 4, length 18)
        if go.aesCBC {
            buffer[offset] = ECPOptionType.aesCBC.rawValue; offset += 1
            buffer[offset] = UInt8(ECPOptionLength.aesCBC); offset += 1
            for i in 0..<16 {
                buffer[offset] = go.aesCBCIV[i]; offset += 1
            }
        }

        // Record the primary method
        if offset > 0 {
            goOptions.method = buffer[0]
        } else {
            goOptions.method = 0
        }

        return offset
    }

    /// Validate that peer's Configure-Ack matches what we sent.
    public func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = goOptions
        var p = 0
        let len = data.count

        // DESE
        if go.dese {
            guard p + ECPOptionLength.dese <= len else { return false }
            guard data[p] == ECPOptionType.dese.rawValue,
                  data[p + 1] == UInt8(ECPOptionLength.dese) else { return false }
            // Verify nonce matches
            for i in 0..<8 {
                guard data[p + 2 + i] == go.deseNonce[i] else { return false }
            }
            p += ECPOptionLength.dese
        }

        // 3DES-DESE
        if go.tripleDesDese {
            guard p + ECPOptionLength.tripleDesDese <= len else { return false }
            guard data[p] == ECPOptionType.tripleDesDese.rawValue,
                  data[p + 1] == UInt8(ECPOptionLength.tripleDesDese) else { return false }
            for i in 0..<8 {
                guard data[p + 2 + i] == go.tripleDesDeseNonce[i] else { return false }
            }
            p += ECPOptionLength.tripleDesDese
        }

        // AES-CBC
        if go.aesCBC {
            guard p + ECPOptionLength.aesCBC <= len else { return false }
            guard data[p] == ECPOptionType.aesCBC.rawValue,
                  data[p + 1] == UInt8(ECPOptionLength.aesCBC) else { return false }
            for i in 0..<16 {
                guard data[p + 2 + i] == go.aesCBCIV[i] else { return false }
            }
            p += ECPOptionLength.aesCBC
        }

        return p == len
    }

    /// Process a Configure-Nak from the peer.
    public func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        let go = goOptions
        var proposedOptions = go
        var p = 0
        let len = data.count

        while p + 2 <= len {
            let citype = data[p]
            let cilen = Int(data[p + 1])
            guard cilen >= 2 && p + cilen <= len else { break }

            switch citype {
            case ECPOptionType.dese.rawValue:
                if go.dese && cilen == ECPOptionLength.dese {
                    // Peer suggests a different nonce -- accept it
                    if cilen >= 10 {
                        proposedOptions.deseNonce = Array(data[(p + 2)..<(p + 10)])
                    }
                }

            case ECPOptionType.tripleDesDese.rawValue:
                if go.tripleDesDese && cilen == ECPOptionLength.tripleDesDese {
                    if cilen >= 10 {
                        proposedOptions.tripleDesDeseNonce = Array(data[(p + 2)..<(p + 10)])
                    }
                }

            case ECPOptionType.aesCBC.rawValue:
                if go.aesCBC && cilen == ECPOptionLength.aesCBC {
                    if cilen >= 18 {
                        proposedOptions.aesCBCIV = Array(data[(p + 2)..<(p + 18)])
                    }
                }

            default:
                break
            }

            p += cilen
        }

        if fsm.state != .opened {
            goOptions = proposedOptions
        }
        return true
    }

    /// Process a Configure-Reject -- remove rejected options.
    public func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = goOptions
        var proposedOptions = go
        var p = 0
        let len = data.count

        if len == 0 && allRejected {
            return false
        }

        while p + 2 <= len {
            let citype = data[p]
            let cilen = Int(data[p + 1])
            guard cilen >= 2 && p + cilen <= len else { return false }

            switch citype {
            case ECPOptionType.dese.rawValue:
                guard go.dese && cilen == ECPOptionLength.dese else { return false }
                proposedOptions.dese = false

            case ECPOptionType.tripleDesDese.rawValue:
                guard go.tripleDesDese && cilen == ECPOptionLength.tripleDesDese else { return false }
                proposedOptions.tripleDesDese = false

            case ECPOptionType.aesCBC.rawValue:
                guard go.aesCBC && cilen == ECPOptionLength.aesCBC else { return false }
                proposedOptions.aesCBC = false

            default:
                return false
            }

            p += cilen
        }

        guard p == len else { return false }

        if fsm.state != .opened {
            goOptions = proposedOptions
        }

        if !proposedOptions.anyEncryption {
            allRejected = true
        }

        return true
    }

    /// Process the peer's Configure-Request for ECP options.
    public func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        let ao = allowOptions
        var ho = ECPOptions()
        var rc: FSMCode = .configureAcknowledgment
        let nakBuffer = [UInt8]()
        var rejBuffer = [UInt8]()

        var p = 0
        let totalLen = data.count
        ho.method = (totalLen > 0) ? data[0] : 0

        while p < totalLen {
            guard p + 2 <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject; break
            }

            let citype = data[p]
            let cilen = Int(data[p + 1])
            guard cilen >= 2 && p + cilen <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject; break
            }

            let ciStart = p
            let ciEnd = p + cilen
            let ciData = Array(data[ciStart..<ciEnd])
            var orc: FSMCode = .configureAcknowledgment

            switch citype {

            case ECPOptionType.dese.rawValue:
                guard ao.dese && cilen == ECPOptionLength.dese else {
                    orc = .configureReject; break
                }
                ho.dese = true
                ho.deseNonce = Array(data[(p + 2)..<(p + 10)])

            case ECPOptionType.tripleDesDese.rawValue:
                guard ao.tripleDesDese && cilen == ECPOptionLength.tripleDesDese else {
                    orc = .configureReject; break
                }
                ho.tripleDesDese = true
                ho.tripleDesDeseNonce = Array(data[(p + 2)..<(p + 10)])

            case ECPOptionType.aesCBC.rawValue:
                guard ao.aesCBC && cilen == ECPOptionLength.aesCBC else {
                    orc = .configureReject; break
                }
                ho.aesCBC = true
                ho.aesCBCIV = Array(data[(p + 2)..<(p + 18)])

            default:
                orc = .configureReject
            }

            p = ciEnd

            if orc == .configureAcknowledgment && rc != .configureAcknowledgment { continue }
            if orc == .configureNegativeAcknowledgment {
                if rc == .configureReject { continue }
                rc = .configureNegativeAcknowledgment
            }
            if orc == .configureReject {
                rc = .configureReject
                rejBuffer.append(contentsOf: ciData)
            }
        }

        switch rc {
        case .configureAcknowledgment:
            reject = data
        case .configureNegativeAcknowledgment:
            reject = nakBuffer
        case .configureReject:
            reject = rejBuffer
        default:
            reject = data
        }

        hisOptions = ho
        return rc
    }

    public func up(_ fsm: FSM) {
        // ECP negotiation succeeded -- create encryptors based on negotiated options.
        let his = hisOptions
        let go = goOptions

        if his.dese || go.dese {
            let nonce = his.dese ? his.deseNonce : go.deseNonce
            desEncryptor = DESEncryptor(key: encryptionKey, initialNonce: nonce)
        }
        if his.tripleDesDese || go.tripleDesDese {
            let nonce = his.tripleDesDese ? his.tripleDesDeseNonce : go.tripleDesDeseNonce
            // Split the encryption key into three 8-byte DES keys.
            let k1 = Array(encryptionKey.prefix(8))
            let k2 = encryptionKey.count > 8 ? Array(encryptionKey[8..<min(16, encryptionKey.count)]) : k1
            let k3 = encryptionKey.count > 16 ? Array(encryptionKey[16..<min(24, encryptionKey.count)]) : k1
            tripleDesEncryptor = TripleDESEncryptor(key1: k1, key2: k2, key3: k3, initialNonce: nonce)
        }
        if his.aesCBC || go.aesCBC {
            let iv = his.aesCBC ? his.aesCBCIV : go.aesCBCIV
            aesCBCEncryptor = AESCBCEncryptor(key: encryptionKey, iv: iv)
        }

        PPP.debugLog(.info, "ECP up: encryption negotiated")
    }

    public func down(_ fsm: FSM) {
        desEncryptor = nil
        tripleDesEncryptor = nil
        aesCBCEncryptor = nil
        PPP.debugLog(.info, "ECP down")
    }

    public func starting(_ fsm: FSM) {}
    public func finished(_ fsm: FSM) {}

    public func extCode(_ fsm: FSM, code: UInt8, id: UInt8, data: [UInt8]) -> Bool {
        if code == 14 {
            // Reset-Request from peer -- send Reset-Ack
            pcb?.sendProtocolPacket(protocol: PPPProtocol.ecp, code: 15, id: id, data: [])
            return true
        }
        if code == 15 {
            // Reset-Ack from peer
            resetAck()
            return true
        }
        return false
    }
}

// MARK: - DEFLATE Compression (RFC 1979)

import Compression

/// DEFLATE compression state for PPP CCP.
///
/// Implements RFC 1979 PPP Deflate Protocol using Foundation's Compression
/// framework with COMPRESSION_ZLIB. Provides packet-by-packet compression
/// with sequence number tracking and reset handling.
public final class DEFLATECompressor {

    /// Negotiated window size in bits (8..15).
    public var windowBits: Int

    /// Transmit sequence number (16-bit, wrapping).
    public var txSequence: UInt16 = 0

    /// Receive sequence number (16-bit, wrapping).
    public var rxSequence: UInt16 = 0

    /// Compression statistics.
    public var compressedOut: UInt32 = 0
    public var uncompressedOut: UInt32 = 0
    public var compressedIn: UInt32 = 0
    public var uncompressedIn: UInt32 = 0
    public var incompressibleCount: UInt32 = 0

    /// Compression output buffer (reused across calls).
    private var outputBuffer: [UInt8]

    /// Maximum output size before we declare a packet incompressible.
    private let maxOutputSize: Int

    /// Whether the compressor has been reset and needs a fresh dictionary.
    private var compressorReset: Bool = true

    /// Whether the decompressor has been reset and needs a fresh dictionary.
    private var decompressorReset: Bool = true

    /// Compression history buffer for maintaining deflate dictionary state.
    /// Accumulates raw data across packets so the next compression can use
    /// prior context (until a reset clears it).
    private var compressHistory: [UInt8] = []

    /// Decompression history buffer for maintaining inflate dictionary state.
    private var decompressHistory: [UInt8] = []

    /// Maximum history size based on window bits.
    private var maxHistorySize: Int

    /// Initialize a DEFLATE compressor with the given window size.
    ///
    /// - Parameter windowBits: Window size in bits (8..15). Default is 15.
    public init(windowBits: Int = 15) {
        let clamped = min(max(windowBits, 8), 15)
        self.windowBits = clamped
        self.maxHistorySize = 1 << clamped
        self.maxOutputSize = 1500 + 4  // MRU + overhead
        self.outputBuffer = [UInt8](repeating: 0, count: maxOutputSize)
    }

    /// Reset the compressor state.
    ///
    /// Called when CCP sends a Reset-Request or receives a Reset-Ack,
    /// indicating the peer cannot decompress and needs a fresh start.
    public func resetCompressor() {
        txSequence = 0
        compressorReset = true
        compressHistory.removeAll(keepingCapacity: true)
    }

    /// Reset the decompressor state.
    ///
    /// Called when we cannot decompress a received packet and need to
    /// send a Reset-Request, or when we receive a Reset-Ack from the peer.
    public func resetDecompressor() {
        rxSequence = 0
        decompressorReset = true
        decompressHistory.removeAll(keepingCapacity: true)
    }

    /// Compress a PPP packet payload using DEFLATE.
    ///
    /// The compressed format per RFC 1979 is:
    ///   - 2 bytes: sequence number (big-endian)
    ///   - N bytes: zlib-compressed data (protocol + payload)
    ///
    /// - Parameters:
    ///   - payload: The raw payload data to compress.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The compressed packet data, or nil if the data is incompressible
    ///   (compressed output would be larger than the input).
    public func compress(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        // Build the uncompressed input: protocol field + payload
        var input = [UInt8]()
        if proto > 0xFF {
            input.append(UInt8(proto >> 8))
        }
        input.append(UInt8(proto & 0xFF))
        input.append(contentsOf: payload)

        // Compress using zlib
        let sourceData = input
        let destinationCapacity = sourceData.count + 64  // Allow overhead for zlib framing
        var destinationBuffer = [UInt8](repeating: 0, count: destinationCapacity)
        let compressedSize: Int = sourceData.withUnsafeBufferPointer { srcBuf in
            destinationBuffer.withUnsafeMutableBufferPointer { dstBuf in
                let result = compression_encode_buffer(
                    dstBuf.baseAddress!, destinationCapacity,
                    srcBuf.baseAddress!, sourceData.count,
                    nil,
                    COMPRESSION_ZLIB
                )
                return result
            }
        }

        guard compressedSize > 0 else {
            incompressibleCount += 1
            return nil
        }

        // Check if compressed output is actually smaller
        if compressedSize >= input.count {
            incompressibleCount += 1
            return nil
        }

        // Build output: sequence number + compressed data
        var result = [UInt8]()
        result.reserveCapacity(2 + compressedSize)
        result.append(UInt8(txSequence >> 8))
        result.append(UInt8(txSequence & 0xFF))
        result.append(contentsOf: destinationBuffer[0..<compressedSize])

        // Update history for context
        if compressHistory.count + input.count > maxHistorySize {
            let excess = compressHistory.count + input.count - maxHistorySize
            if excess < compressHistory.count {
                compressHistory.removeFirst(excess)
            } else {
                compressHistory.removeAll(keepingCapacity: true)
            }
        }
        compressHistory.append(contentsOf: input)

        txSequence &+= 1
        compressedOut += 1
        uncompressedOut += UInt32(input.count)

        return result
    }

    /// Decompress a received DEFLATE-compressed PPP packet.
    ///
    /// - Parameter data: The received compressed data (sequence number + compressed payload).
    /// - Returns: The decompressed data (protocol + payload), or nil on error.
    ///   On error, the caller should send a CCP Reset-Request.
    public func decompress(_ data: [UInt8]) -> [UInt8]? {
        guard data.count >= 4 else { return nil }  // Need at least seq(2) + some data

        // Extract and verify sequence number
        let receivedSeq = (UInt16(data[0]) << 8) | UInt16(data[1])
        if receivedSeq != rxSequence {
            // Sequence mismatch -- need reset
            PPP.debugLog(.warning, "DEFLATE: sequence mismatch: expected \(rxSequence), got \(receivedSeq)")
            return nil
        }

        // Decompress the payload
        let compressedData = Array(data[2...])
        let destinationCapacity = 1500 + 128  // MRU + generous headroom
        var destinationBuffer = [UInt8](repeating: 0, count: destinationCapacity)
        let decompressedSize: Int = compressedData.withUnsafeBufferPointer { srcBuf in
            destinationBuffer.withUnsafeMutableBufferPointer { dstBuf in
                let result = compression_decode_buffer(
                    dstBuf.baseAddress!, destinationCapacity,
                    srcBuf.baseAddress!, compressedData.count,
                    nil,
                    COMPRESSION_ZLIB
                )
                return result
            }
        }

        guard decompressedSize > 0 else {
            PPP.debugLog(.warning, "DEFLATE: decompression failed")
            return nil
        }

        let result = Array(destinationBuffer[0..<decompressedSize])

        // Update history
        if decompressHistory.count + result.count > maxHistorySize {
            let excess = decompressHistory.count + result.count - maxHistorySize
            if excess < decompressHistory.count {
                decompressHistory.removeFirst(excess)
            } else {
                decompressHistory.removeAll(keepingCapacity: true)
            }
        }
        decompressHistory.append(contentsOf: result)

        rxSequence &+= 1
        compressedIn += UInt32(compressedData.count)
        uncompressedIn += UInt32(decompressedSize)

        return result
    }

    /// Signal that the last packet was incompressible.
    ///
    /// Called by CCP when the peer indicates it received a packet that
    /// it could not decompress (typically after a CCP Reset-Request).
    public func incompressible() {
        incompressibleCount += 1
    }

    /// Negotiate the window size with the peer.
    ///
    /// Returns the effective window size that both sides can agree on.
    /// Per RFC 1979, we accept any window size >= 8, but may reduce it
    /// to what we support.
    ///
    /// - Parameter peerWindowBits: The peer's proposed window size in bits.
    /// - Returns: The agreed window size in bits.
    public func negotiateWindowSize(peerWindowBits: Int) -> Int {
        let peerClamped = min(max(peerWindowBits, 8), 15)
        let agreed = min(windowBits, peerClamped)
        windowBits = agreed
        maxHistorySize = 1 << agreed
        return agreed
    }
}

// MARK: - DES Encryptor for ECP (RFC 1969 / RFC 2419)

/// DES-based encryption for ECP DESE (DES Encryption Protocol).
///
/// Implements RFC 2419 (PPP DES Encryption Protocol, Version 2) using
/// the existing DES implementation in PolarSSL/Crypto.swift.
/// Provides CBC-mode DES encryption/decryption with explicit IV management
/// for PPP ECP.
public final class DESEncryptor {

    /// DES context for encryption.
    private var encryptContext = DESContext()
    /// DES context for decryption.
    private var decryptContext = DESContext()

    /// Current IV for encryption (8 bytes). Initially set from ECP negotiation.
    public var encryptIV: [UInt8]

    /// Current IV for decryption (8 bytes). Initially set from ECP negotiation.
    public var decryptIV: [UInt8]

    /// The 8-byte DES key.
    private var key: [UInt8]

    /// Whether the encryptor has been initialized.
    private var isInitialized: Bool = false

    /// Packet counter for statistics.
    public var encryptedPackets: UInt32 = 0
    public var decryptedPackets: UInt32 = 0

    /// Initialize a DES encryptor with the given key and initial nonce.
    ///
    /// - Parameters:
    ///   - key: The 8-byte DES key.
    ///   - initialNonce: The 8-byte initial nonce from ECP negotiation.
    public init(key: [UInt8], initialNonce: [UInt8]) {
        var effectiveKey = key
        while effectiveKey.count < 8 { effectiveKey.append(0) }
        self.key = Array(effectiveKey.prefix(8))
        self.encryptIV = Array(initialNonce.prefix(8))
        while self.encryptIV.count < 8 { self.encryptIV.append(0) }
        self.decryptIV = self.encryptIV
        setup()
    }

    /// Set up the DES contexts with the key.
    private func setup() {
        encryptContext.setKeyEncrypt(key)
        decryptContext.setKeyDecrypt(key)
        isInitialized = true
    }

    /// Encrypt a PPP packet payload using DES in CBC mode (RFC 2419).
    ///
    /// The encrypted format is:
    ///   - 8 bytes: explicit IV (the IV used for this packet)
    ///   - N bytes: CBC-encrypted data (padded to 8-byte boundary)
    ///
    /// The plaintext includes the protocol field and payload.
    ///
    /// - Parameters:
    ///   - payload: The raw payload data.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The encrypted packet (IV + ciphertext), or nil on error.
    public func encrypt(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        guard isInitialized else { return nil }

        // Build plaintext: protocol + payload
        var plaintext = [UInt8]()
        plaintext.append(UInt8(proto >> 8))
        plaintext.append(UInt8(proto & 0xFF))
        plaintext.append(contentsOf: payload)

        // Pad to 8-byte boundary (PKCS-style: pad byte = number of padding bytes)
        let remainder = plaintext.count % 8
        if remainder != 0 {
            let padLen = 8 - remainder
            for _ in 0..<padLen {
                plaintext.append(UInt8(padLen))
            }
        }

        // The explicit IV for this packet is our current encryptIV
        var result = [UInt8]()
        result.reserveCapacity(8 + plaintext.count)
        result.append(contentsOf: encryptIV)

        // CBC encryption: for each 8-byte block, XOR with IV then encrypt
        var currentIV = encryptIV
        var offset = 0
        while offset + 8 <= plaintext.count {
            var block = [UInt8](repeating: 0, count: 8)
            for i in 0..<8 {
                block[i] = plaintext[offset + i] ^ currentIV[i]
            }
            let encrypted = encryptContext.cryptECB(input: block)
            result.append(contentsOf: encrypted)
            currentIV = encrypted
            offset += 8
        }

        // Update IV for next packet: last ciphertext block
        encryptIV = currentIV
        encryptedPackets += 1

        return result
    }

    /// Decrypt a received DES-encrypted PPP packet (RFC 2419).
    ///
    /// - Parameter data: The received encrypted data (explicit IV + ciphertext).
    /// - Returns: The decrypted data (protocol + payload), or nil on error.
    public func decrypt(_ data: [UInt8]) -> [UInt8]? {
        guard isInitialized else { return nil }
        guard data.count >= 16 else { return nil }  // Need at least IV(8) + one block(8)
        guard (data.count - 8) % 8 == 0 else { return nil }  // Ciphertext must be block-aligned

        // Extract explicit IV
        let packetIV = Array(data[0..<8])

        // CBC decryption
        var plaintext = [UInt8]()
        plaintext.reserveCapacity(data.count - 8)
        var currentIV = packetIV
        var offset = 8
        while offset + 8 <= data.count {
            let cipherBlock = Array(data[offset..<(offset + 8)])
            let decrypted = decryptContext.cryptECB(input: cipherBlock)
            for i in 0..<8 {
                plaintext.append(decrypted[i] ^ currentIV[i])
            }
            currentIV = cipherBlock
            offset += 8
        }

        // Update IV for next packet: last ciphertext block
        decryptIV = currentIV

        // Remove padding (PKCS-style)
        if let lastByte = plaintext.last {
            let padLen = Int(lastByte)
            if padLen >= 1 && padLen <= 8 && plaintext.count >= padLen {
                // Verify all padding bytes match
                var validPadding = true
                for i in (plaintext.count - padLen)..<plaintext.count {
                    if plaintext[i] != lastByte {
                        validPadding = false
                        break
                    }
                }
                if validPadding {
                    plaintext.removeLast(padLen)
                }
            }
        }

        decryptedPackets += 1
        return plaintext
    }

    /// Reset the encryption state (e.g., after ECP Reset-Request).
    ///
    /// - Parameter nonce: The new initial nonce/IV.
    public func reset(nonce: [UInt8]) {
        var newNonce = nonce
        while newNonce.count < 8 { newNonce.append(0) }
        encryptIV = Array(newNonce.prefix(8))
        decryptIV = encryptIV
    }
}

// MARK: - Triple DES Encryptor for ECP (RFC 2420)

/// Triple DES (3DES-DESE) encryption for ECP.
///
/// Implements RFC 2420 (PPP Triple-DES Encryption Protocol) using
/// three-key Triple DES in CBC mode. Uses the existing DES implementation
/// in PolarSSL/Crypto.swift to perform EDE (Encrypt-Decrypt-Encrypt)
/// operations.
public final class TripleDESEncryptor {

    /// Three DES contexts for encryption (EDE: encrypt, decrypt, encrypt).
    private var encContext1 = DESContext()
    private var encContext2 = DESContext()
    private var encContext3 = DESContext()

    /// Three DES contexts for decryption (DED: decrypt, encrypt, decrypt).
    private var decContext1 = DESContext()
    private var decContext2 = DESContext()
    private var decContext3 = DESContext()

    /// Current IV for encryption (8 bytes).
    public var encryptIV: [UInt8]

    /// Current IV for decryption (8 bytes).
    public var decryptIV: [UInt8]

    /// The three 8-byte keys.
    private var key1: [UInt8]
    private var key2: [UInt8]
    private var key3: [UInt8]

    /// Whether the encryptor has been initialized.
    private var isInitialized: Bool = false

    /// Packet counter for statistics.
    public var encryptedPackets: UInt32 = 0
    public var decryptedPackets: UInt32 = 0

    /// Initialize a Triple DES encryptor with three 8-byte keys and an initial nonce.
    ///
    /// - Parameters:
    ///   - key1: First 8-byte DES key (used for outer encrypt).
    ///   - key2: Second 8-byte DES key (used for middle decrypt).
    ///   - key3: Third 8-byte DES key (used for inner encrypt).
    ///   - initialNonce: The 8-byte initial nonce from ECP negotiation.
    public init(key1: [UInt8], key2: [UInt8], key3: [UInt8], initialNonce: [UInt8]) {
        func padKey(_ k: [UInt8]) -> [UInt8] {
            var padded = k
            while padded.count < 8 { padded.append(0) }
            return Array(padded.prefix(8))
        }
        self.key1 = padKey(key1)
        self.key2 = padKey(key2)
        self.key3 = padKey(key3)
        self.encryptIV = Array(initialNonce.prefix(8))
        while self.encryptIV.count < 8 { self.encryptIV.append(0) }
        self.decryptIV = self.encryptIV
        setup()
    }

    /// Set up the DES contexts with the three keys.
    private func setup() {
        // For 3DES encryption (EDE): K1 encrypt, K2 decrypt, K3 encrypt
        encContext1.setKeyEncrypt(key1)
        encContext2.setKeyDecrypt(key2)
        encContext3.setKeyEncrypt(key3)

        // For 3DES decryption (DED): K3 decrypt, K2 encrypt, K1 decrypt
        decContext1.setKeyDecrypt(key3)
        decContext2.setKeyEncrypt(key2)
        decContext3.setKeyDecrypt(key1)

        isInitialized = true
    }

    /// Perform 3DES EDE encryption on a single 8-byte block.
    private func encryptBlock(_ input: [UInt8]) -> [UInt8] {
        let step1 = encContext1.cryptECB(input: input)
        let step2 = encContext2.cryptECB(input: step1)
        return encContext3.cryptECB(input: step2)
    }

    /// Perform 3DES DED decryption on a single 8-byte block.
    private func decryptBlock(_ input: [UInt8]) -> [UInt8] {
        let step1 = decContext1.cryptECB(input: input)
        let step2 = decContext2.cryptECB(input: step1)
        return decContext3.cryptECB(input: step2)
    }

    /// Encrypt a PPP packet payload using Triple DES in CBC mode (RFC 2420).
    ///
    /// The encrypted format is:
    ///   - 8 bytes: explicit IV
    ///   - N bytes: CBC-encrypted data (padded to 8-byte boundary)
    ///
    /// - Parameters:
    ///   - payload: The raw payload data.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The encrypted packet (IV + ciphertext), or nil on error.
    public func encrypt(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        guard isInitialized else { return nil }

        // Build plaintext: protocol + payload
        var plaintext = [UInt8]()
        plaintext.append(UInt8(proto >> 8))
        plaintext.append(UInt8(proto & 0xFF))
        plaintext.append(contentsOf: payload)

        // Pad to 8-byte boundary
        let remainder = plaintext.count % 8
        if remainder != 0 {
            let padLen = 8 - remainder
            for _ in 0..<padLen {
                plaintext.append(UInt8(padLen))
            }
        }

        // Build output with explicit IV
        var result = [UInt8]()
        result.reserveCapacity(8 + plaintext.count)
        result.append(contentsOf: encryptIV)

        // CBC encryption using 3DES EDE
        var currentIV = encryptIV
        var offset = 0
        while offset + 8 <= plaintext.count {
            var block = [UInt8](repeating: 0, count: 8)
            for i in 0..<8 {
                block[i] = plaintext[offset + i] ^ currentIV[i]
            }
            let encrypted = encryptBlock(block)
            result.append(contentsOf: encrypted)
            currentIV = encrypted
            offset += 8
        }

        encryptIV = currentIV
        encryptedPackets += 1

        return result
    }

    /// Decrypt a received Triple DES-encrypted PPP packet (RFC 2420).
    ///
    /// - Parameter data: The received encrypted data (explicit IV + ciphertext).
    /// - Returns: The decrypted data (protocol + payload), or nil on error.
    public func decrypt(_ data: [UInt8]) -> [UInt8]? {
        guard isInitialized else { return nil }
        guard data.count >= 16 else { return nil }
        guard (data.count - 8) % 8 == 0 else { return nil }

        let packetIV = Array(data[0..<8])

        // CBC decryption using 3DES DED
        var plaintext = [UInt8]()
        plaintext.reserveCapacity(data.count - 8)
        var currentIV = packetIV
        var offset = 8
        while offset + 8 <= data.count {
            let cipherBlock = Array(data[offset..<(offset + 8)])
            let decrypted = decryptBlock(cipherBlock)
            for i in 0..<8 {
                plaintext.append(decrypted[i] ^ currentIV[i])
            }
            currentIV = cipherBlock
            offset += 8
        }

        decryptIV = currentIV

        // Remove padding
        if let lastByte = plaintext.last {
            let padLen = Int(lastByte)
            if padLen >= 1 && padLen <= 8 && plaintext.count >= padLen {
                var validPadding = true
                for i in (plaintext.count - padLen)..<plaintext.count {
                    if plaintext[i] != lastByte {
                        validPadding = false
                        break
                    }
                }
                if validPadding {
                    plaintext.removeLast(padLen)
                }
            }
        }

        decryptedPackets += 1
        return plaintext
    }

    /// Reset the encryption state (e.g., after ECP Reset-Request).
    ///
    /// - Parameter nonce: The new initial nonce/IV.
    public func reset(nonce: [UInt8]) {
        var newNonce = nonce
        while newNonce.count < 8 { newNonce.append(0) }
        encryptIV = Array(newNonce.prefix(8))
        decryptIV = encryptIV
    }
}

// MARK: - AES-CBC Encryptor for ECP

import CommonCrypto

/// AES-CBC encryption for ECP.
///
/// Implements AES-128/192/256 CBC-mode encryption for PPP ECP using
/// CommonCrypto (CCCrypt). Provides packet-by-packet encryption with
/// explicit IV management, following the same pattern as `DESEncryptor`
/// and `TripleDESEncryptor`.
internal final class AESCBCEncryptor {

    /// The AES key (16, 24, or 32 bytes for AES-128/192/256).
    private var key: [UInt8]

    /// Current IV for encryption (16 bytes).
    private var encryptIV: [UInt8]

    /// Current IV for decryption (16 bytes).
    private var decryptIV: [UInt8]

    /// AES block size.
    private let blockSize = 16

    /// Whether the encryptor has been initialized.
    private var isInitialized: Bool = false

    /// Packet counter for statistics.
    public var encryptedPackets: UInt32 = 0
    public var decryptedPackets: UInt32 = 0

    /// Initialize an AES-CBC encryptor with the given key and initial IV.
    ///
    /// - Parameters:
    ///   - key: The AES key (16, 24, or 32 bytes).
    ///   - iv: The 16-byte initial IV from ECP negotiation.
    init(key: [UInt8], iv: [UInt8]) {
        // Pad or truncate key to a valid AES key length (default to 16).
        var effectiveKey = key
        if effectiveKey.count < 16 {
            while effectiveKey.count < 16 { effectiveKey.append(0) }
        } else if effectiveKey.count > 16 && effectiveKey.count < 24 {
            effectiveKey = Array(effectiveKey.prefix(16))
        } else if effectiveKey.count > 24 && effectiveKey.count < 32 {
            effectiveKey = Array(effectiveKey.prefix(24))
        } else if effectiveKey.count > 32 {
            effectiveKey = Array(effectiveKey.prefix(32))
        }
        self.key = effectiveKey

        var effectiveIV = iv
        while effectiveIV.count < 16 { effectiveIV.append(0) }
        self.encryptIV = Array(effectiveIV.prefix(16))
        self.decryptIV = self.encryptIV
        self.isInitialized = true
    }

    /// Encrypt a PPP packet payload using AES in CBC mode.
    ///
    /// The encrypted format is:
    ///   - 16 bytes: explicit IV (the IV used for this packet)
    ///   - N bytes: CBC-encrypted data (padded to 16-byte boundary)
    ///
    /// - Parameters:
    ///   - payload: The raw payload data.
    ///   - protocol: The PPP protocol number.
    /// - Returns: The encrypted packet (IV + ciphertext), or nil on error.
    func encrypt(payload: [UInt8], protocol proto: UInt16) -> [UInt8]? {
        guard isInitialized else { return nil }

        // Build plaintext: protocol + payload
        var plaintext = [UInt8]()
        plaintext.append(UInt8(proto >> 8))
        plaintext.append(UInt8(proto & 0xFF))
        plaintext.append(contentsOf: payload)

        // PKCS7 padding to block boundary
        let remainder = plaintext.count % blockSize
        let padLen = (remainder == 0) ? blockSize : blockSize - remainder
        for _ in 0..<padLen {
            plaintext.append(UInt8(padLen))
        }

        // Output: explicit IV + ciphertext
        var result = [UInt8]()
        result.reserveCapacity(blockSize + plaintext.count)
        result.append(contentsOf: encryptIV)

        let ciphertextSize = plaintext.count
        var ciphertext = [UInt8](repeating: 0, count: ciphertextSize)
        var numBytesEncrypted = 0

        let status = key.withUnsafeBufferPointer { keyPtr in
            encryptIV.withUnsafeBufferPointer { ivPtr in
                plaintext.withUnsafeBufferPointer { dataPtr in
                    ciphertext.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,  // No padding (we handle PKCS7 manually)
                            keyPtr.baseAddress!, key.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, plaintext.count,
                            outPtr.baseAddress!, ciphertextSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }

        result.append(contentsOf: ciphertext[0..<numBytesEncrypted])

        // Update IV for next packet: last ciphertext block
        if numBytesEncrypted >= blockSize {
            encryptIV = Array(ciphertext[(numBytesEncrypted - blockSize)..<numBytesEncrypted])
        }
        encryptedPackets += 1

        return result
    }

    /// Decrypt a received AES-CBC-encrypted PPP packet.
    ///
    /// - Parameter data: The received encrypted data (explicit IV + ciphertext).
    /// - Returns: The decrypted data (protocol + payload), or nil on error.
    func decrypt(data: [UInt8]) -> [UInt8]? {
        guard isInitialized else { return nil }
        guard data.count >= blockSize * 2 else { return nil }  // Need at least IV(16) + one block(16)
        guard (data.count - blockSize) % blockSize == 0 else { return nil }

        // Extract explicit IV
        let packetIV = Array(data[0..<blockSize])
        let ciphertextData = Array(data[blockSize...])

        let plaintextSize = ciphertextData.count
        var plaintext = [UInt8](repeating: 0, count: plaintextSize)
        var numBytesDecrypted = 0

        let status = key.withUnsafeBufferPointer { keyPtr in
            packetIV.withUnsafeBufferPointer { ivPtr in
                ciphertextData.withUnsafeBufferPointer { dataPtr in
                    plaintext.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            0,  // No padding (we handle PKCS7 manually)
                            keyPtr.baseAddress!, key.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, ciphertextData.count,
                            outPtr.baseAddress!, plaintextSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }

        plaintext = Array(plaintext[0..<numBytesDecrypted])

        // Update IV for next packet: last ciphertext block
        if ciphertextData.count >= blockSize {
            decryptIV = Array(ciphertextData[(ciphertextData.count - blockSize)...])
        }

        // Remove PKCS7 padding
        if let lastByte = plaintext.last {
            let padLen = Int(lastByte)
            if padLen >= 1 && padLen <= blockSize && plaintext.count >= padLen {
                var validPadding = true
                for i in (plaintext.count - padLen)..<plaintext.count {
                    if plaintext[i] != lastByte {
                        validPadding = false
                        break
                    }
                }
                if validPadding {
                    plaintext.removeLast(padLen)
                }
            }
        }

        decryptedPackets += 1
        return plaintext
    }

    /// Reset the encryption state (e.g., after ECP Reset-Request).
    ///
    /// - Parameter iv: The new initial IV.
    func reset(iv: [UInt8]) {
        var newIV = iv
        while newIV.count < 16 { newIV.append(0) }
        encryptIV = Array(newIV.prefix(16))
        decryptIV = encryptIV
    }
}
