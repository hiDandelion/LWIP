//
//  LowPAN6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// 6LoWPAN constants.
public enum LowPAN6Constants {
    /// Maximum IEEE 802.15.4 payload (127 bytes minus 2-byte CRC).
    public static let maxPayload: UInt16 = 125
    /// Maximum number of compression contexts.
    public static let maxContexts: Int = 10
    /// Reassembly timer interval in milliseconds.
    public static let timerInterval: UInt32 = 1000
    /// Maximum datagram size for fragmentation (11-bit field).
    public static let maxDatagramSize: UInt16 = 0x7FF
}

/// IEEE 802.15.4 frame control field constants
public struct IEEE802154FC {
    public static let frameTypeData: UInt16     = 0x0001
    public static let ackReq: UInt16            = 0x0020
    public static let panIDCompress: UInt16     = 0x0040
    public static let seqnoSuppress: UInt16     = 0x0100
    public static let dstAddrModeShort: UInt16  = 0x0800
    public static let dstAddrModeExt: UInt16    = 0x0C00
    public static let dstAddrModeMask: UInt16   = 0x0C00
    public static let srcAddrModeShort: UInt16  = 0x8000
    public static let srcAddrModeExt: UInt16    = 0xC000
    public static let srcAddrModeMask: UInt16   = 0xC000
}

// MARK: - Link-Layer Address

/// 6LoWPAN link-layer address (2 or 8 bytes)
public struct LowPAN6LinkAddr: Equatable, Sendable {
    /// Address length (2 for short, 8 for extended)
    public var addrLen: UInt8
    /// Address bytes (up to 8)
    public var addr: [UInt8]

    public init(addrLen: UInt8 = 0, addr: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]) {
        self.addrLen = addrLen
        self.addr = addr
    }

    /// The IEEE 802.15.4 broadcast address (short, 0xFFFF)
    public static let broadcast = LowPAN6LinkAddr(addrLen: 2, addr: [0xFF, 0xFF, 0, 0, 0, 0, 0, 0])
}

// MARK: - Reassembly Helper

/// Tracks a single datagram being reassembled from fragments
public final class LowPAN6ReassemblyHelper {
    public var next: LowPAN6ReassemblyHelper?
    /// Reassembled full datagram buffer
    public var reassembled: Pbuf?
    /// Linked list of received fragment pbufs
    public var fragments: Pbuf?
    /// Timeout timer (decremented each tick)
    public var timer: UInt8 = 0
    /// Sender address for matching fragments
    public var senderAddr: LowPAN6LinkAddr = LowPAN6LinkAddr()
    /// Total datagram size from fragmentation header
    public var datagramSize: UInt16 = 0
    /// Datagram tag for matching fragments
    public var datagramTag: UInt16 = 0

    public init() {}
}

// MARK: - Address Compression Mode

/// IPHC unicast address compression mode (RFC 6282).
/// Indicates how much of the address can be elided.
public enum IPHCAddressMode: UInt8, Sendable {
    /// 64-bit inline (IID carried in-line)
    case inline64 = 1
    /// 16-bit inline (last 16 bits carried)
    case inline16 = 2
    /// Fully elided (derived from link-layer)
    case elided = 3
}

/// IPHC multicast address compression mode (RFC 6282).
public enum IPHCMulticastMode: UInt8, Sendable {
    /// Full 128-bit multicast address inline
    case inline128 = 0
    /// 48-bit: flags + 1-byte prefix + 4-byte group
    case inline48 = 1
    /// 32-bit: flags + 3-byte group
    case inline32 = 2
    /// 8-bit: last byte only (ff02::xx)
    case inline8 = 3
}

// MARK: - LowPAN6 Namespace

/// Namespace for 6LoWPAN utility functions (header compression, CRC, etc.)
public enum LowPAN6 {

    /// Helper to build an IPv6Address from 16 raw bytes
    public static func ipv6AddressFromBytes(_ b: [UInt8]) -> IPv6Address {
        guard b.count >= 16 else { return .any }
        return IPv6Address(
            b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11],
            b[12], b[13], b[14], b[15]
        )
    }

    /// Determine IPHC address compression mode for a unicast address.
    public static func getAddressMode(ip6addr: IPv6Address, macAddr: LowPAN6LinkAddr) -> IPHCAddressMode {
        let w2 = ip6addr.word(2)
        let w3 = ip6addr.word(3)

        if macAddr.addrLen == 2 {
            if w2 == 0x000000FF {
                let upper16 = (w3 >> 16) & 0xFFFF
                if upper16 == 0xFE00 {
                    let lower16 = w3 & 0xFFFF
                    let macVal = UInt32(macAddr.addr[0]) << 8 | UInt32(macAddr.addr[1])
                    if lower16 == macVal {
                        return .elided
                    }
                }
            }
        } else if macAddr.addrLen == 8 {
            let expectedW2 = UInt32(macAddr.addr[0] ^ 2) << 24 | UInt32(macAddr.addr[1]) << 16 |
                              UInt32(macAddr.addr[2]) << 8 | UInt32(macAddr.addr[3])
            let expectedW3 = UInt32(macAddr.addr[4]) << 24 | UInt32(macAddr.addr[5]) << 16 |
                              UInt32(macAddr.addr[6]) << 8 | UInt32(macAddr.addr[7])
            if w2 == expectedW2 && w3 == expectedW3 {
                return .elided
            }
        }

        if w2 == 0x000000FF {
            let upper16 = (w3 >> 16) & 0xFFFF
            if upper16 == 0xFE00 {
                return .inline16
            }
        }
        return .inline64
    }

    /// Determine IPHC compression mode for multicast addresses
    public static func getMulticastAddressMode(ip6addr: IPv6Address) -> IPHCMulticastMode {
        let w0 = ip6addr.word(0)
        let w1 = ip6addr.word(1)
        let w2 = ip6addr.word(2)
        let w3 = ip6addr.word(3)

        if w0 == 0xFF020000 && w1 == 0 && w2 == 0 && (w3 & 0xFFFFFF00) == 0 {
            return .inline8
        } else if (w0 & 0xFF00FFFF) == 0xFF000000 && w1 == 0 {
            if w2 == 0 && (w3 & 0xFF000000) == 0 {
                return .inline32
            } else if (w2 & 0xFFFFFF00) == 0 {
                return .inline48
            }
        }
        return .inline128
    }

    /// Write the IEEE 802.15.4 header for a 6LoWPAN frame.
    public static func writeIEEE802154Header(
        into buffer: inout [UInt8],
        src: LowPAN6LinkAddr,
        dst: LowPAN6LinkAddr,
        data: LowPAN6IEEE802154Data
    ) -> UInt8 {
        var fc: UInt16 = IEEE802154FC.frameTypeData
        fc |= IEEE802154FC.panIDCompress

        if dst != LowPAN6LinkAddr.broadcast {
            fc |= IEEE802154FC.ackReq
        }

        if dst.addrLen == 2 {
            fc |= IEEE802154FC.dstAddrModeShort
        } else {
            fc |= IEEE802154FC.dstAddrModeExt
        }

        if src.addrLen == 2 {
            fc |= IEEE802154FC.srcAddrModeShort
        } else {
            fc |= IEEE802154FC.srcAddrModeExt
        }

        var offset = 0
        buffer[offset] = UInt8(fc & 0xFF)
        buffer[offset + 1] = UInt8(fc >> 8)
        offset += 2

        buffer[offset] = data.nextSeqNum()
        offset += 1

        buffer[offset] = UInt8(data.panID & 0xFF)
        buffer[offset + 1] = UInt8(data.panID >> 8)
        offset += 2

        // Reverse memcpy of dst addr
        for i in stride(from: Int(dst.addrLen) - 1, through: 0, by: -1) {
            buffer[offset] = dst.addr[i]
            offset += 1
        }

        // Source PAN ID skipped (PAN ID compression)
        // Reverse memcpy of src addr
        for i in stride(from: Int(src.addrLen) - 1, through: 0, by: -1) {
            buffer[offset] = src.addr[i]
            offset += 1
        }

        return UInt8(offset)
    }

    /// Parse the IEEE 802.15.4 header from raw data.
    public static func parseIEEE802154Header(
        _ data: [UInt8],
        src: inout LowPAN6LinkAddr,
        dst: inout LowPAN6LinkAddr
    ) -> Int {
        guard data.count >= 5 else { return 0 }

        let fc = UInt16(data[0]) | (UInt16(data[1]) << 8)
        var offset = 2

        // Sequence number
        if (fc & IEEE802154FC.seqnoSuppress) != 0 {
            return 0
        } else {
            offset += 1
        }

        // Skip destination PAN ID
        offset += 2

        // Destination address
        let dstMode = fc & IEEE802154FC.dstAddrModeMask
        if dstMode == IEEE802154FC.dstAddrModeExt {
            dst.addrLen = 8
            guard offset + 8 <= data.count else { return 0 }
            for i in 0..<8 {
                dst.addr[i] = data[offset + 7 - i]
            }
            offset += 8
        } else if dstMode == IEEE802154FC.dstAddrModeShort {
            dst.addrLen = 2
            guard offset + 2 <= data.count else { return 0 }
            dst.addr[0] = data[offset + 1]
            dst.addr[1] = data[offset]
            offset += 2
        } else {
            return 0
        }

        // Skip source PAN ID if no compression
        if (fc & IEEE802154FC.panIDCompress) == 0 {
            offset += 2
        }

        // Source address
        let srcMode = fc & IEEE802154FC.srcAddrModeMask
        if srcMode == IEEE802154FC.srcAddrModeExt {
            src.addrLen = 8
            guard offset + 8 <= data.count else { return 0 }
            for i in 0..<8 {
                src.addr[i] = data[offset + 7 - i]
            }
            offset += 8
        } else if srcMode == IEEE802154FC.srcAddrModeShort {
            src.addrLen = 2
            guard offset + 2 <= data.count else { return 0 }
            src.addr[0] = data[offset + 1]
            src.addr[1] = data[offset]
            offset += 2
        } else {
            return 0
        }

        return offset
    }

    /// Calculate the 16-bit CRC as required by IEEE 802.15.4 (CCITT CRC-16)
    public static func calculateCRC(_ data: [UInt8], length: Int) -> UInt16 {
        let ccittPoly: UInt16 = 0x8408
        var crc: UInt16 = 0

        for i in 0..<length {
            var byte = data[i]
            for _ in 0..<8 {
                if ((byte ^ UInt8(crc & 0xFF)) & 1) != 0 {
                    crc = (crc >> 1) ^ ccittPoly
                } else {
                    crc >>= 1
                }
                byte >>= 1
            }
        }
        return crc
    }

    /// Compress IPv6 (and optionally UDP) headers using IPHC (RFC 6282).
    public static func compressHeaders(
        inbuf: [UInt8],
        outbuf: inout [UInt8],
        contextTable: LowPAN6ContextTable?,
        src: LowPAN6LinkAddr,
        dst: LowPAN6LinkAddr
    ) -> (compressedLen: Int, hiddenLen: Int)? {
        guard inbuf.count >= 40 else { return nil } // IPConstants.ipv6HeaderLength
        guard outbuf.count >= 40 else { return nil }

        var lowpan6HeaderLen = 2
        var hiddenHeaderLen = 0

        // IPHC dispatch
        outbuf[0] = 0x60
        outbuf[1] = 0

        // Extract IPv6 header fields
        let versionTC = UInt32(inbuf[0]) << 24 | UInt32(inbuf[1]) << 16 |
                        UInt32(inbuf[2]) << 8 | UInt32(inbuf[3])
        let trafficClass = UInt8((versionTC >> 20) & 0xFF)
        let flowLabel = versionTC & 0xFFFFF
        let nextHeader = inbuf[6]
        let hopLimit = inbuf[7]

        // Context Identifier Extension
        if let ctx = contextTable {
            var cid: UInt8 = 0
            let srcIP6 = LowPAN6.ipv6AddressFromBytes(Array(inbuf[8..<24]))
            let dstIP6 = LowPAN6.ipv6AddressFromBytes(Array(inbuf[24..<40]))

            if let srcCtx = ctx.lookup(srcIP6) {
                outbuf[1] |= 0x40
                cid |= UInt8(srcCtx & 0x0F) << 4
            }

            if let dstCtx = ctx.lookup(dstIP6) {
                outbuf[1] |= 0x04
                cid |= UInt8(dstCtx & 0x0F)
            }

            if cid != 0 {
                outbuf[1] |= 0x80
                outbuf[2] = cid
                lowpan6HeaderLen += 1
            }
        }

        // Traffic Class / Flow Label compression
        if flowLabel == 0 {
            outbuf[0] |= 0x10
            if trafficClass == 0 {
                outbuf[0] |= 0x08
            } else {
                outbuf[lowpan6HeaderLen] = trafficClass
                lowpan6HeaderLen += 1
            }
        } else {
            if (trafficClass & 0x3F) == 0 {
                outbuf[0] |= 0x08
                outbuf[lowpan6HeaderLen] = (trafficClass & 0xC0) | UInt8((flowLabel >> 16) & 0x0F)
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = UInt8((flowLabel >> 8) & 0xFF)
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = UInt8(flowLabel & 0xFF)
                lowpan6HeaderLen += 1
            } else {
                outbuf[lowpan6HeaderLen] = trafficClass
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = UInt8((flowLabel >> 16) & 0x0F)
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = UInt8((flowLabel >> 8) & 0xFF)
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = UInt8(flowLabel & 0xFF)
                lowpan6HeaderLen += 1
            }
        }

        // Next Header compression (only UDP for now)
        if nextHeader == 17 { // IP6_NEXTH_UDP
            outbuf[0] |= 0x04
        } else {
            outbuf[lowpan6HeaderLen] = nextHeader
            lowpan6HeaderLen += 1
        }

        // Hop Limit compression
        switch hopLimit {
        case 255: outbuf[0] |= 0x03
        case 64:  outbuf[0] |= 0x02
        case 1:   outbuf[0] |= 0x01
        default:
            outbuf[lowpan6HeaderLen] = hopLimit
            lowpan6HeaderLen += 1
        }

        // Source address compression
        let srcAddr = LowPAN6.ipv6AddressFromBytes(Array(inbuf[8..<24]))
        if (outbuf[1] & 0x40) != 0 || srcAddr.isLinkLocal {
            let mode = LowPAN6.getAddressMode(ip6addr: srcAddr, macAddr: src)
            outbuf[1] |= (mode.rawValue & 0x03) << 4
            switch mode {
            case .inline64:
                for i in 0..<8 { outbuf[lowpan6HeaderLen + i] = inbuf[16 + i] }
                lowpan6HeaderLen += 8
            case .inline16:
                outbuf[lowpan6HeaderLen] = inbuf[22]
                outbuf[lowpan6HeaderLen + 1] = inbuf[23]
                lowpan6HeaderLen += 2
            case .elided:
                break
            }
        } else if srcAddr.isAny {
            outbuf[1] |= 0x40
        } else {
            for i in 0..<16 { outbuf[lowpan6HeaderLen + i] = inbuf[8 + i] }
            lowpan6HeaderLen += 16
        }

        // Destination address compression
        let dstAddr = LowPAN6.ipv6AddressFromBytes(Array(inbuf[24..<40]))
        if dstAddr.isMulticast {
            outbuf[1] |= 0x08
            let mode = LowPAN6.getMulticastAddressMode(ip6addr: dstAddr)
            outbuf[1] |= mode.rawValue & 0x03
            switch mode {
            case .inline128:
                for i in 0..<16 { outbuf[lowpan6HeaderLen + i] = inbuf[24 + i] }
                lowpan6HeaderLen += 16
            case .inline48:
                outbuf[lowpan6HeaderLen] = inbuf[25]
                lowpan6HeaderLen += 1
                for i in 0..<5 { outbuf[lowpan6HeaderLen + i] = inbuf[35 + i] }
                lowpan6HeaderLen += 5
            case .inline32:
                outbuf[lowpan6HeaderLen] = inbuf[25]
                lowpan6HeaderLen += 1
                for i in 0..<3 { outbuf[lowpan6HeaderLen + i] = inbuf[37 + i] }
                lowpan6HeaderLen += 3
            case .inline8:
                outbuf[lowpan6HeaderLen] = inbuf[39]
                lowpan6HeaderLen += 1
            }
        } else if (outbuf[1] & 0x04) != 0 || dstAddr.isLinkLocal {
            let mode = LowPAN6.getAddressMode(ip6addr: dstAddr, macAddr: dst)
            outbuf[1] |= mode.rawValue & 0x03
            switch mode {
            case .inline64:
                for i in 0..<8 { outbuf[lowpan6HeaderLen + i] = inbuf[32 + i] }
                lowpan6HeaderLen += 8
            case .inline16:
                outbuf[lowpan6HeaderLen] = inbuf[38]
                outbuf[lowpan6HeaderLen + 1] = inbuf[39]
                lowpan6HeaderLen += 2
            case .elided:
                break
            }
        } else {
            for i in 0..<16 { outbuf[lowpan6HeaderLen + i] = inbuf[24 + i] }
            lowpan6HeaderLen += 16
        }

        hiddenHeaderLen += 40 // IPConstants.ipv6HeaderLength

        // UDP header compression
        if nextHeader == 17 && inbuf.count >= 48 {
            outbuf[lowpan6HeaderLen] = 0xF0

            let srcPort0 = inbuf[40], srcPort1 = inbuf[41]
            let dstPort0 = inbuf[42], dstPort1 = inbuf[43]

            if srcPort0 == 0xF0 && (srcPort1 & 0xF0) == 0xB0 &&
               dstPort0 == 0xF0 && (dstPort1 & 0xF0) == 0xB0 {
                outbuf[lowpan6HeaderLen] |= 0x03
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = ((srcPort1 & 0x0F) << 4) | (dstPort1 & 0x0F)
                lowpan6HeaderLen += 1
            } else if srcPort0 == 0xF0 {
                outbuf[lowpan6HeaderLen] |= 0x02
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = srcPort1
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = dstPort0
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = dstPort1
                lowpan6HeaderLen += 1
            } else if dstPort0 == 0xF0 {
                outbuf[lowpan6HeaderLen] |= 0x01
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = srcPort0
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = srcPort1
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = dstPort1
                lowpan6HeaderLen += 1
            } else {
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = srcPort0
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = srcPort1
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = dstPort0
                lowpan6HeaderLen += 1
                outbuf[lowpan6HeaderLen] = dstPort1
                lowpan6HeaderLen += 1
            }

            // Elide length, copy checksum
            outbuf[lowpan6HeaderLen] = inbuf[46]
            lowpan6HeaderLen += 1
            outbuf[lowpan6HeaderLen] = inbuf[47]
            lowpan6HeaderLen += 1

            hiddenHeaderLen += 8 // UDPConstants.headerLength
        }

        return (lowpan6HeaderLen, hiddenHeaderLen)
    }

    /// Periodic timer function for 6LoWPAN.
    public static func timerTick(data: LowPAN6IEEE802154Data) {
        var prev: LowPAN6ReassemblyHelper?
        var current = data.reassList

        while let lrh = current {
            let next = lrh.next
            lrh.timer = lrh.timer &- 1
            if lrh.timer == 0 {
                // Remove from list
                if prev == nil {
                    data.reassList = next
                } else {
                    prev?.next = next
                }
                lrh.reassembled = nil
                lrh.fragments = nil
            } else {
                prev = lrh
            }
            current = next
        }
    }
}

// MARK: - Context Management

/// Context table for stateful header compression
public final class LowPAN6ContextTable: @unchecked Sendable {
    public var contexts: [IPv6Address]
    private let lock = NSLock()

    public init() {
        self.contexts = Array(repeating: IPv6Address.any, count: LowPAN6Constants.maxContexts)
    }

    /// Look up a context matching the given IPv6 address prefix
    public func lookup(_ addr: IPv6Address) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        for i in 0..<LowPAN6Constants.maxContexts {
            if contexts[i].networkEquals(addr) {
                return i
            }
        }
        return nil
    }

    /// Set a context at a given index
    public func set(index: UInt8, context: IPv6Address) -> LWIPError {
        guard Int(index) < LowPAN6Constants.maxContexts else { return .invalidArgument }
        lock.lock()
        contexts[Int(index)] = context
        lock.unlock()
        return .ok
    }

    /// Read a configured context by index.
    public func context(at index: Int) -> IPv6Address? {
        guard index >= 0, index < LowPAN6Constants.maxContexts else { return nil }
        lock.lock()
        let context = contexts[index]
        lock.unlock()
        return context
    }
}

// MARK: - IEEE 802.15.4 Header

/// IEEE 802.15.4 MAC header structure
public struct IEEE802154Header {
    public var frameControl: UInt16 = 0
    public var sequenceNumber: UInt8 = 0
    public var destinationPANID: UInt16 = 0
    public var destinationAddr: LowPAN6LinkAddr = LowPAN6LinkAddr()
    public var sourceAddr: LowPAN6LinkAddr = LowPAN6LinkAddr()

    public init() {}

    /// Serialized header length
    public var length: Int {
        var len = 5 // FC(2) + SeqNo(1) + DstPAN(2)
        len += Int(destinationAddr.addrLen)
        // Source PAN ID skipped due to PAN ID compression
        len += Int(sourceAddr.addrLen)
        return len
    }
}

// MARK: - LowPAN6 Per-Netif Data

/// Per-network-interface state for IEEE 802.15.4 6LoWPAN
public final class LowPAN6IEEE802154Data: @unchecked Sendable {
    /// Reassembly list head
    public var reassList: LowPAN6ReassemblyHelper?
    /// Compression contexts
    public let contextTable = LowPAN6ContextTable()
    /// Datagram tag for TX fragmentation
    public var txDatagramTag: UInt16 = 0
    /// Local PAN ID
    public var panID: UInt16 = 0xFFFF
    /// TX frame sequence number
    public var txFrameSeqNum: UInt8 = 0
    /// Lock for concurrent access
    private let lock = NSLock()

    public init() {}

    /// Set the PAN ID for outgoing frames
    public func setPanID(_ id: UInt16) {
        lock.lock()
        panID = id
        lock.unlock()
    }

    /// Get the next datagram tag and increment
    public func nextDatagramTag() -> UInt16 {
        lock.lock()
        let tag = txDatagramTag
        txDatagramTag &+= 1
        lock.unlock()
        return tag
    }

    /// Get the next sequence number and increment
    public func nextSeqNum() -> UInt8 {
        lock.lock()
        let seq = txFrameSeqNum
        txFrameSeqNum &+= 1
        lock.unlock()
        return seq
    }
}

private struct LowPAN6DecompressionResult {
    let ipv6Header: IPv6Header
    let transportHeader: [UInt8]
    let compressedHeaderLength: Int
}

private func lowpan6IPv6Bytes(_ address: IPv6Address) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 16)
    bytes.withUnsafeMutableBytes { rawBuffer in
        guard let baseAddress = rawBuffer.baseAddress else { return }
        address.writeNetworkBytes(to: baseAddress)
    }
    return bytes
}

private func lowpan6LinkLayerSuffix(_ addr: LowPAN6LinkAddr) -> [UInt8]? {
    switch addr.addrLen {
    case 2:
        return [0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, addr.addr[0], addr.addr[1]]
    case 8:
        return [
            addr.addr[0] ^ 0x02, addr.addr[1], addr.addr[2], addr.addr[3],
            addr.addr[4], addr.addr[5], addr.addr[6], addr.addr[7]
        ]
    default:
        return nil
    }
}

private func lowpan6ContextPrefix(
    _ index: Int,
    contextTable: LowPAN6ContextTable?
) -> [UInt8]? {
    guard let context = contextTable?.context(at: index) else {
        return nil
    }
    return Array(lowpan6IPv6Bytes(context).prefix(8))
}

private func lowpan6IPv6Address(prefix: [UInt8], suffix: [UInt8]) -> IPv6Address {
    var bytes = prefix
    bytes.append(contentsOf: suffix)
    if bytes.count < 16 {
        bytes.append(contentsOf: repeatElement(0, count: 16 - bytes.count))
    }
    return LowPAN6.ipv6AddressFromBytes(bytes)
}

private func lowpan6BuildFrame(_ payload: [UInt8]) -> [UInt8] {
    let crc = LowPAN6.calculateCRC(payload, length: payload.count)
    var frame = payload
    frame.append(UInt8(crc & 0xFF))
    frame.append(UInt8(crc >> 8))
    return frame
}

private func lowpan6SendRawFrame(_ frame: [UInt8], via netif: NetworkInterface) -> LWIPError {
    guard let linkOutput = netif.linkOutput else {
        return .interfaceError
    }
    guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(frame.count), type: .ram) else {
        return .outOfMemory
    }
    frame.withUnsafeBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return }
        _ = pbuf.take(from: baseAddress, len: UInt16(frame.count))
    }
    return linkOutput(netif, pbuf)
}

private func lowpan6DecompressHeaders(
    compressed: [UInt8],
    datagramSize: UInt16,
    contextTable: LowPAN6ContextTable?,
    src: LowPAN6LinkAddr,
    dst: LowPAN6LinkAddr
) -> LowPAN6DecompressionResult? {
    guard compressed.count >= 2 else { return nil }

    let header1 = compressed[0]
    let header2 = compressed[1]
    let hasContextIdentifier = (header2 & 0x80) != 0
    var lowpanOffset = 2
    if hasContextIdentifier {
        guard compressed.count >= 3 else { return nil }
        lowpanOffset += 1
    }

    func requireBytes(_ count: Int) -> ArraySlice<UInt8>? {
        guard lowpanOffset + count <= compressed.count else { return nil }
        let bytes = compressed[lowpanOffset..<(lowpanOffset + count)]
        lowpanOffset += count
        return bytes
    }

    let trafficClass: UInt8
    let flowLabel: UInt32
    switch header1 & 0x18 {
    case 0x00:
        guard let bytes = requireBytes(4) else { return nil }
        let array = Array(bytes)
        trafficClass = array[0]
        flowLabel = (UInt32(array[1] & 0x0F) << 16) | (UInt32(array[2]) << 8) | UInt32(array[3])
    case 0x08:
        guard let bytes = requireBytes(3) else { return nil }
        let array = Array(bytes)
        trafficClass = array[0] & 0xC0
        flowLabel = (UInt32(array[0] & 0x0F) << 16) | (UInt32(array[1]) << 8) | UInt32(array[2])
    case 0x10:
        guard let bytes = requireBytes(1) else { return nil }
        trafficClass = bytes[bytes.startIndex]
        flowLabel = 0
    case 0x18:
        trafficClass = 0
        flowLabel = 0
    default:
        return nil
    }

    var nextHeader: UInt8 = 0
    if (header1 & 0x04) == 0 {
        guard let bytes = requireBytes(1) else { return nil }
        nextHeader = bytes[bytes.startIndex]
    }

    let hopLimit: UInt8
    switch header1 & 0x03 {
    case 0x00:
        guard let bytes = requireBytes(1) else { return nil }
        hopLimit = bytes[bytes.startIndex]
    case 0x01:
        hopLimit = 1
    case 0x02:
        hopLimit = 64
    case 0x03:
        hopLimit = 255
    default:
        return nil
    }

    let sourceAddress: IPv6Address
    if (header2 & 0x40) == 0 {
        switch header2 & 0x30 {
        case 0x00:
            guard let bytes = requireBytes(16) else { return nil }
            sourceAddress = LowPAN6.ipv6AddressFromBytes(Array(bytes))
        case 0x10:
            guard let bytes = requireBytes(8) else { return nil }
            sourceAddress = lowpan6IPv6Address(
                prefix: [0xFE, 0x80, 0, 0, 0, 0, 0, 0],
                suffix: Array(bytes)
            )
        case 0x20:
            guard let bytes = requireBytes(2) else { return nil }
            sourceAddress = lowpan6IPv6Address(
                prefix: [0xFE, 0x80, 0, 0, 0, 0, 0, 0],
                suffix: [0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, bytes[bytes.startIndex], bytes[bytes.startIndex + 1]]
            )
        case 0x30:
            guard let suffix = lowpan6LinkLayerSuffix(src) else { return nil }
            sourceAddress = lowpan6IPv6Address(
                prefix: [0xFE, 0x80, 0, 0, 0, 0, 0, 0],
                suffix: suffix
            )
        default:
            return nil
        }
    } else {
        switch header2 & 0x30 {
        case 0x00:
            sourceAddress = .any
        case 0x10, 0x20, 0x30:
            let contextIndex = hasContextIdentifier ? Int((compressed[2] >> 4) & 0x0F) : 0
            guard let prefix = lowpan6ContextPrefix(contextIndex, contextTable: contextTable) else {
                return nil
            }
            switch header2 & 0x30 {
            case 0x10:
                guard let bytes = requireBytes(8) else { return nil }
                sourceAddress = lowpan6IPv6Address(prefix: prefix, suffix: Array(bytes))
            case 0x20:
                guard let bytes = requireBytes(2) else { return nil }
                sourceAddress = lowpan6IPv6Address(
                    prefix: prefix,
                    suffix: [0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, bytes[bytes.startIndex], bytes[bytes.startIndex + 1]]
                )
            case 0x30:
                guard let suffix = lowpan6LinkLayerSuffix(src) else { return nil }
                sourceAddress = lowpan6IPv6Address(prefix: prefix, suffix: suffix)
            default:
                return nil
            }
        default:
            return nil
        }
    }

    let destinationAddress: IPv6Address
    if (header2 & 0x08) != 0 {
        if (header2 & 0x04) != 0 {
            return nil
        }
        switch header2 & 0x03 {
        case 0x00:
            guard let bytes = requireBytes(16) else { return nil }
            destinationAddress = LowPAN6.ipv6AddressFromBytes(Array(bytes))
        case 0x01:
            guard let bytes = requireBytes(6) else { return nil }
            let array = Array(bytes)
            destinationAddress = LowPAN6.ipv6AddressFromBytes([
                0xFF, array[0], 0, 0,
                0, 0, 0, 0,
                0, 0, 0, array[1],
                array[2], array[3], array[4], array[5]
            ])
        case 0x02:
            guard let bytes = requireBytes(4) else { return nil }
            let array = Array(bytes)
            destinationAddress = LowPAN6.ipv6AddressFromBytes([
                0xFF, array[0], 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, array[1], array[2], array[3]
            ])
        case 0x03:
            guard let bytes = requireBytes(1) else { return nil }
            destinationAddress = LowPAN6.ipv6AddressFromBytes([
                0xFF, 0x02, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, bytes[bytes.startIndex]
            ])
        default:
            return nil
        }
    } else {
        let prefix: [UInt8]
        if (header2 & 0x04) != 0 {
            let contextIndex = hasContextIdentifier ? Int(compressed[2] & 0x0F) : 0
            guard let contextPrefix = lowpan6ContextPrefix(contextIndex, contextTable: contextTable) else {
                return nil
            }
            prefix = contextPrefix
        } else {
            prefix = [0xFE, 0x80, 0, 0, 0, 0, 0, 0]
        }

        switch header2 & 0x03 {
        case 0x00:
            guard let bytes = requireBytes(16) else { return nil }
            destinationAddress = LowPAN6.ipv6AddressFromBytes(Array(bytes))
        case 0x01:
            guard let bytes = requireBytes(8) else { return nil }
            destinationAddress = lowpan6IPv6Address(prefix: prefix, suffix: Array(bytes))
        case 0x02:
            guard let bytes = requireBytes(2) else { return nil }
            destinationAddress = lowpan6IPv6Address(
                prefix: prefix,
                suffix: [0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, bytes[bytes.startIndex], bytes[bytes.startIndex + 1]]
            )
        case 0x03:
            guard let suffix = lowpan6LinkLayerSuffix(dst) else { return nil }
            destinationAddress = lowpan6IPv6Address(prefix: prefix, suffix: suffix)
        default:
            return nil
        }
    }

    var transportHeader = [UInt8]()
    if (header1 & 0x04) != 0 {
        guard lowpanOffset < compressed.count else { return nil }
        let nhc = compressed[lowpanOffset]
        guard (nhc & 0xF8) == 0xF0 else { return nil }
        guard (nhc & 0x04) == 0 else { return nil }
        lowpanOffset += 1

        let sourcePort: UInt16
        let destinationPort: UInt16
        switch nhc & 0x03 {
        case 0x00:
            guard let bytes = requireBytes(4) else { return nil }
            let array = Array(bytes)
            sourcePort = (UInt16(array[0]) << 8) | UInt16(array[1])
            destinationPort = (UInt16(array[2]) << 8) | UInt16(array[3])
        case 0x01:
            guard let bytes = requireBytes(3) else { return nil }
            let array = Array(bytes)
            sourcePort = (UInt16(array[0]) << 8) | UInt16(array[1])
            destinationPort = 0xF000 | UInt16(array[2])
        case 0x02:
            guard let bytes = requireBytes(3) else { return nil }
            let array = Array(bytes)
            sourcePort = 0xF000 | UInt16(array[0])
            destinationPort = (UInt16(array[1]) << 8) | UInt16(array[2])
        case 0x03:
            guard let bytes = requireBytes(1) else { return nil }
            let value = bytes[bytes.startIndex]
            sourcePort = 0xF0B0 | UInt16((value >> 4) & 0x0F)
            destinationPort = 0xF0B0 | UInt16(value & 0x0F)
        default:
            return nil
        }

        guard let checksumBytes = requireBytes(2) else { return nil }
        let checksum = (UInt16(checksumBytes[checksumBytes.startIndex]) << 8)
            | UInt16(checksumBytes[checksumBytes.startIndex + 1])

        let totalDatagramSize = datagramSize == 0
            ? compressed.count - lowpanOffset + IPv6HeaderConstants.length + Int(UDPConstants.headerLength)
            : Int(datagramSize)
        guard totalDatagramSize >= IPv6HeaderConstants.length + Int(UDPConstants.headerLength) else {
            return nil
        }

        nextHeader = IPv6NextHeader.udp.rawValue
        let udpLength = UInt16(totalDatagramSize - IPv6HeaderConstants.length)
        transportHeader = [
            UInt8(sourcePort >> 8), UInt8(sourcePort & 0xFF),
            UInt8(destinationPort >> 8), UInt8(destinationPort & 0xFF),
            UInt8(udpLength >> 8), UInt8(udpLength & 0xFF),
            UInt8(checksum >> 8), UInt8(checksum & 0xFF)
        ]
    }

    let totalDatagramSize = datagramSize == 0
        ? compressed.count - lowpanOffset + IPv6HeaderConstants.length + transportHeader.count
        : Int(datagramSize)
    guard totalDatagramSize >= IPv6HeaderConstants.length + transportHeader.count else {
        return nil
    }

    let ipv6Header = IPv6Header(
        trafficClass: trafficClass,
        flowLabel: flowLabel,
        payloadLength: UInt16(totalDatagramSize - IPv6HeaderConstants.length),
        nextHeader: nextHeader,
        hopLimit: hopLimit,
        src: sourceAddress,
        dest: destinationAddress
    )

    return LowPAN6DecompressionResult(
        ipv6Header: ipv6Header,
        transportHeader: transportHeader,
        compressedHeaderLength: lowpanOffset
    )
}

private func lowpan6Decompress(
    pbuf: Pbuf,
    datagramSize: UInt16,
    contextTable: LowPAN6ContextTable?,
    src: LowPAN6LinkAddr,
    dst: LowPAN6LinkAddr
) -> Pbuf? {
    var compressed = [UInt8](repeating: 0, count: Int(pbuf.totLen))
    compressed.withUnsafeMutableBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return }
        _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
    }

    guard let result = lowpan6DecompressHeaders(
        compressed: compressed,
        datagramSize: datagramSize,
        contextTable: contextTable,
        src: src,
        dst: dst
    ) else {
        _ = Pbuf.free(pbuf)
        return nil
    }

    let payloadOffset = result.compressedHeaderLength
    let payloadBytes = payloadOffset < compressed.count ? Array(compressed[payloadOffset...]) : []
    let outputLength = IPv6HeaderConstants.length + result.transportHeader.count + payloadBytes.count
    guard let decompressed = Pbuf.alloc(layer: .ip, length: UInt16(outputLength), type: .ram) else {
        _ = Pbuf.free(pbuf)
        return nil
    }

    result.ipv6Header.write(to: decompressed)
    decompressed.writeBytes(result.transportHeader, at: IPv6HeaderConstants.length)
    decompressed.writeBytes(payloadBytes, at: IPv6HeaderConstants.length + result.transportHeader.count)

    _ = Pbuf.free(pbuf)
    return decompressed
}

// MARK: - 6LoWPAN Interface

/// 6LoWPAN network interface for IEEE 802.15.4
public final class LowPAN6Interface: @unchecked Sendable {
    public let data = LowPAN6IEEE802154Data()
    public var netif: NetworkInterface?

    public init() {}

    private func hwAddrToLinkAddr(_ netif: NetworkInterface) -> LowPAN6LinkAddr? {
        var addr = LowPAN6LinkAddr()
        switch netif.hwAddrLen {
        case 8:
            addr.addrLen = 8
            for index in 0..<8 {
                addr.addr[index] = netif.hwAddr[index]
            }
            return addr
        case 6:
            addr.addrLen = 8
            addr.addr[0] = netif.hwAddr[0]
            addr.addr[1] = netif.hwAddr[1]
            addr.addr[2] = netif.hwAddr[2]
            addr.addr[3] = 0xFF
            addr.addr[4] = 0xFF
            addr.addr[5] = netif.hwAddr[3]
            addr.addr[6] = netif.hwAddr[4]
            addr.addr[7] = netif.hwAddr[5]
            return addr
        default:
            return nil
        }
    }

    private func fragmentAndSend(
        netif: NetworkInterface,
        pbuf: Pbuf,
        src: LowPAN6LinkAddr,
        dst: LowPAN6LinkAddr
    ) -> LWIPError {
        guard pbuf.totLen > 0, Int(pbuf.totLen) <= Int(LowPAN6Constants.maxDatagramSize) else {
            return .invalidValue
        }

        var packet = [UInt8](repeating: 0, count: Int(pbuf.totLen))
        packet.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
        }

        var ieeeHeaderBuffer = [UInt8](repeating: 0, count: 127)
        let ieeeHeaderLength = Int(LowPAN6.writeIEEE802154Header(
            into: &ieeeHeaderBuffer,
            src: src,
            dst: dst,
            data: data
        ))
        let ieeeHeader = Array(ieeeHeaderBuffer.prefix(ieeeHeaderLength))

        var lowpanHeaderBuffer = [UInt8](repeating: 0, count: max(IPv6HeaderConstants.length, 127 - ieeeHeaderLength))
        guard let compression = LowPAN6.compressHeaders(
            inbuf: packet,
            outbuf: &lowpanHeaderBuffer,
            contextTable: data.contextTable,
            src: src,
            dst: dst
        ) else {
            return .invalidValue
        }

        guard compression.hiddenLen <= packet.count else {
            return .invalidValue
        }

        let lowpanHeader = Array(lowpanHeaderBuffer.prefix(compression.compressedLen))
        let payloadBytes = Array(packet.dropFirst(compression.hiddenLen))
        let maxDataLength = Int(LowPAN6Constants.maxPayload) - ieeeHeaderLength - lowpanHeader.count
        guard maxDataLength > 0 else {
            return .outOfMemory
        }

        if payloadBytes.count > maxDataLength {
            let datagramTag = data.nextDatagramTag()
            let firstPayloadLength = min(((maxDataLength - 4) & ~0x7), payloadBytes.count)
            guard firstPayloadLength > 0 else {
                return .outOfMemory
            }

            var firstFrame = ieeeHeader
            firstFrame.append(0xC0 | UInt8((packet.count >> 8) & 0x07))
            firstFrame.append(UInt8(packet.count & 0xFF))
            firstFrame.append(UInt8(datagramTag >> 8))
            firstFrame.append(UInt8(datagramTag & 0xFF))
            firstFrame.append(contentsOf: lowpanHeader)
            firstFrame.append(contentsOf: payloadBytes.prefix(firstPayloadLength))

            var err = lowpan6SendRawFrame(lowpan6BuildFrame(firstFrame), via: netif)
            guard err == .ok else {
                return err
            }

            var datagramOffset = compression.hiddenLen + firstPayloadLength
            var payloadOffset = firstPayloadLength
            let nextFragmentMax = (127 - ieeeHeaderLength - 5 - 2) & ~0x7

            while payloadOffset < payloadBytes.count {
                let fragmentLength = min(nextFragmentMax, payloadBytes.count - payloadOffset)
                guard fragmentLength > 0 else {
                    return .outOfMemory
                }

                var fragmentHeaderBuffer = [UInt8](repeating: 0, count: 127)
                let fragmentHeaderLength = Int(LowPAN6.writeIEEE802154Header(
                    into: &fragmentHeaderBuffer,
                    src: src,
                    dst: dst,
                    data: data
                ))

                var fragmentFrame = Array(fragmentHeaderBuffer.prefix(fragmentHeaderLength))
                fragmentFrame.append(0xE0 | UInt8((packet.count >> 8) & 0x07))
                fragmentFrame.append(UInt8(packet.count & 0xFF))
                fragmentFrame.append(UInt8(datagramTag >> 8))
                fragmentFrame.append(UInt8(datagramTag & 0xFF))
                fragmentFrame.append(UInt8(datagramOffset >> 3))
                fragmentFrame.append(contentsOf: payloadBytes[payloadOffset..<(payloadOffset + fragmentLength)])

                err = lowpan6SendRawFrame(lowpan6BuildFrame(fragmentFrame), via: netif)
                guard err == .ok else {
                    return err
                }

                datagramOffset += fragmentLength
                payloadOffset += fragmentLength
            }

            return .ok
        }

        var frame = ieeeHeader
        frame.append(contentsOf: lowpanHeader)
        frame.append(contentsOf: payloadBytes)
        return lowpan6SendRawFrame(lowpan6BuildFrame(frame), via: netif)
    }

    public func outputIPv6(netif: NetworkInterface, pbuf: Pbuf, dest: IPv6Address) -> LWIPError {
        guard let srcAddr = hwAddrToLinkAddr(netif) else {
            return .invalidValue
        }

        if dest.isMulticast {
            return fragmentAndSend(netif: netif, pbuf: pbuf, src: srcAddr, dst: .broadcast)
        }

        let (result, nextHopAddress) = ND6.getNextHopAddrOrQueue(on: netif, pbuf: pbuf, dest: dest)
        guard result == .ok else {
            return result
        }
        guard let nextHopAddress else {
            return .ok
        }

        let addrLen = Int(netif.hwAddrLen)
        guard addrLen > 0, addrLen <= 8 else {
            return .invalidValue
        }

        var destAddr = LowPAN6LinkAddr(addrLen: UInt8(addrLen))
        for index in 0..<addrLen {
            destAddr.addr[index] = nextHopAddress[index]
        }
        return fragmentAndSend(netif: netif, pbuf: pbuf, src: srcAddr, dst: destAddr)
    }

    /// Initialize the 6LoWPAN netif
    public func setupNetif(_ netif: NetworkInterface) {
        self.netif = netif
        netif.name = (UInt8(ascii: "L"), UInt8(ascii: "6"))
        netif.mtu = 1280
        netif.hwAddrLen = 8
        netif.outputIP6 = { [weak self] outputNetif, pbuf, dest in
            self?.outputIPv6(netif: outputNetif, pbuf: pbuf, dest: dest) ?? .interfaceError
        }
        netif.flags.insert(.broadcast)
    }

    /// Set the PAN ID for this interface
    public func setPanID(_ id: UInt16) {
        data.setPanID(id)
    }

    /// Set a compression context
    public func setContext(index: UInt8, context: IPv6Address) -> LWIPError {
        return data.contextTable.set(index: index, context: context)
    }

    // MARK: - Fragment Reassembly

    /// Remove a reassembly helper from the reassembly list.
    private func dequeueReassembly(_ lrh: LowPAN6ReassemblyHelper, prev: LowPAN6ReassemblyHelper?) {
        if data.reassList === lrh {
            data.reassList = lrh.next
        } else {
            prev?.next = lrh.next
        }
    }

    /// Free all buffers held by a reassembly helper.
    private func freeReassemblyDatagram(_ lrh: LowPAN6ReassemblyHelper) {
        if let reass = lrh.reassembled {
            _ = Pbuf.free(reass)
            lrh.reassembled = nil
        }
        if let frags = lrh.fragments {
            _ = Pbuf.free(frags)
            lrh.fragments = nil
        }
    }

    /// Check whether all fragments have been received for a reassembly context
    /// and, if so, combine them into a single contiguous datagram.
    ///
    /// - Parameters:
    ///   - lrh: The reassembly helper being checked.
    ///   - lrhPrev: The previous element in the reassembly list (for dequeue).
    ///   - netif: The network interface on which the packet was received.
    /// - Returns: `.ok` on success (whether complete or still waiting), or the
    ///   result of passing the completed datagram to the IP layer.
    private func checkReassemblyComplete(
        _ lrh: LowPAN6ReassemblyHelper,
        prev lrhPrev: LowPAN6ReassemblyHelper?,
        netif: NetworkInterface
    ) -> LWIPError {
        guard let reass = lrh.reassembled else {
            // FRAG1 not yet received; wait.
            return .ok
        }

        // Walk the fragment list and verify contiguous coverage starting
        // from the end of the decompressed first-fragment data.
        var offset = reass.len
        var frag = lrh.fragments
        while let f = frag {
            let fragDatagramOffset = UInt16(f.byte(at: 0)) << 3
            if fragDatagramOffset != offset {
                // Gap in coverage -- not yet complete.
                return .ok
            }
            offset += f.len - 1 // subtract the 1-byte datagram-offset field
            frag = f.next
        }

        guard offset == lrh.datagramSize else {
            // Not all bytes accounted for yet.
            return .ok
        }

        // All fragments received. Combine the pbuf chain.
        var datagramLeft = lrh.datagramSize - reass.len
        frag = lrh.fragments
        while let f = frag {
            // Hide the leading datagram-offset byte in each FRAGN pbuf.
            _ = f.removeHeader(1)
            f.totLen = datagramLeft
            datagramLeft -= f.len
            frag = f.next
        }

        // Chain the fragment list onto the reassembled first fragment.
        reass.totLen = lrh.datagramSize
        reass.next = lrh.fragments
        lrh.fragments = nil
        lrh.reassembled = nil

        dequeueReassembly(lrh, prev: lrhPrev)

        return netif.input?(reass, netif) ?? .invalidValue
    }

    /// Process a received IEEE 802.15.4 frame, handling fragment reassembly and
    /// IPHC header decompression.
    ///
    /// - Parameters:
    ///   - pbuf: The received packet buffer (payload starts at the IEEE 802.15.4 header).
    ///   - netif: The network interface that received the frame.
    /// - Returns: `.ok` on success (always `.ok` to prevent the caller from freeing
    ///   the pbuf a second time).
    public func input(pbuf: Pbuf, netif: NetworkInterface) -> LWIPError {
        guard pbuf.totLen > 0 else {
            _ = Pbuf.free(pbuf)
            return .ok
        }

        // Require a contiguous buffer for the frame.
        guard pbuf.len == pbuf.totLen else {
            _ = Pbuf.free(pbuf)
            return .ok
        }

        // Parse the IEEE 802.15.4 MAC header.
        var rawData = [UInt8](repeating: 0, count: Int(pbuf.totLen))
        rawData.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = pbuf.copyPartial(to: base, len: pbuf.totLen, offset: 0)
        }

        var src = LowPAN6LinkAddr()
        var dst = LowPAN6LinkAddr()
        let ieeeHeaderLen = LowPAN6.parseIEEE802154Header(rawData, src: &src, dst: &dst)
        guard ieeeHeaderLen > 0, ieeeHeaderLen < rawData.count else {
            _ = Pbuf.free(pbuf)
            return .ok
        }

        // Advance past the IEEE 802.15.4 header.
        guard pbuf.removeHeader(ieeeHeaderLen) else {
            _ = Pbuf.free(pbuf)
            return .ok
        }

        let dispatch = pbuf.byte(at: 0)

        // ---------------------------------------------------------------
        // FRAG1 -- first fragment (dispatch 0b11000xxx)
        // ---------------------------------------------------------------
        if (dispatch & 0xF8) == 0xC0 {
            let datagramSize = (UInt16(pbuf.byte(at: 0) & 0x07) << 8) | UInt16(pbuf.byte(at: 1))
            let datagramTag  = (UInt16(pbuf.byte(at: 2)) << 8) | UInt16(pbuf.byte(at: 3))

            // Check for duplicate or superseding datagram from the same sender.
            var lrh = data.reassList
            var lrhPrev: LowPAN6ReassemblyHelper?
            while let entry = lrh {
                let lrhNext = entry.next
                var discard = false

                if entry.senderAddr.addrLen == src.addrLen &&
                   entry.senderAddr.addr.prefix(Int(src.addrLen)) == src.addr.prefix(Int(src.addrLen)) {
                    if datagramTag == entry.datagramTag && datagramSize == entry.datagramSize {
                        // Duplicate FRAG1 -- discard the incoming frame.
                        _ = Pbuf.free(pbuf)
                        return .ok
                    } else {
                        // New datagram from same sender -- discard the old incomplete one.
                        discard = true
                    }
                }

                if discard {
                    dequeueReassembly(entry, prev: lrhPrev)
                    freeReassemblyDatagram(entry)
                } else {
                    lrhPrev = entry
                }
                lrh = lrhNext
            }

            // Hide the 4-byte FRAG1 header.
            guard pbuf.removeHeader(4) else {
                _ = Pbuf.free(pbuf)
                return .ok
            }

            let newLRH = LowPAN6ReassemblyHelper()
            newLRH.senderAddr = src
            newLRH.datagramSize = datagramSize
            newLRH.datagramTag = datagramTag
            newLRH.fragments = nil
            newLRH.timer = 2

            let firstByte = pbuf.byte(at: 0)
            if firstByte == 0x41 {
                // Uncompressed IPv6, skip dispatch byte.
                guard pbuf.removeHeader(1) else {
                    _ = Pbuf.free(pbuf)
                    return .ok
                }
                newLRH.reassembled = pbuf
            } else if (firstByte & 0xE0) == 0x60 {
                // IPHC compressed header -- decompress.
                guard let decompressed = lowpan6Decompress(
                    pbuf: pbuf,
                    datagramSize: datagramSize,
                    contextTable: data.contextTable,
                    src: src,
                    dst: dst
                ) else {
                    return .ok
                }
                newLRH.reassembled = decompressed
            } else {
                // Unknown dispatch after FRAG1 header.
                _ = Pbuf.free(pbuf)
                return .ok
            }

            // Prepend to the reassembly list.
            newLRH.next = data.reassList
            data.reassList = newLRH

            return .ok
        }

        // ---------------------------------------------------------------
        // FRAGN -- subsequent fragment (dispatch 0b11100xxx)
        // ---------------------------------------------------------------
        if (dispatch & 0xF8) == 0xE0 {
            let datagramSize   = (UInt16(pbuf.byte(at: 0) & 0x07) << 8) | UInt16(pbuf.byte(at: 1))
            let datagramTag    = (UInt16(pbuf.byte(at: 2)) << 8) | UInt16(pbuf.byte(at: 3))
            let datagramOffset = UInt16(pbuf.byte(at: 4)) << 3

            // Hide the 4-byte fragment dispatch (keep the datagram_offset byte for reassembly).
            guard pbuf.removeHeader(4) else {
                _ = Pbuf.free(pbuf)
                return .ok
            }

            // Find the matching reassembly entry.
            var lrhPrev: LowPAN6ReassemblyHelper?
            var matchedLRH: LowPAN6ReassemblyHelper?
            var entry = data.reassList
            while let e = entry {
                if e.senderAddr.addrLen == src.addrLen &&
                   e.senderAddr.addr.prefix(Int(src.addrLen)) == src.addr.prefix(Int(src.addrLen)) &&
                   datagramTag == e.datagramTag &&
                   datagramSize == e.datagramSize {
                    matchedLRH = e
                    break
                }
                lrhPrev = e
                entry = e.next
            }

            guard let lrhEntry = matchedLRH else {
                // Rogue fragment -- no matching FRAG1 received.
                _ = Pbuf.free(pbuf)
                return .ok
            }

            // If FRAG1 was already decompressed, verify no overlap with the first fragment.
            if let reass = lrhEntry.reassembled {
                if datagramOffset < reass.len {
                    // Fragment overlaps with the decompressed first fragment.
                    dequeueReassembly(lrhEntry, prev: lrhPrev)
                    freeReassemblyDatagram(lrhEntry)
                    _ = Pbuf.free(pbuf)
                    return .ok
                }
            }

            let newFragLen = pbuf.len - 1 // pbuf payload: [datagram_offset_byte | fragment_data]

            if lrhEntry.fragments == nil {
                // First subsequent fragment received.
                lrhEntry.fragments = pbuf
            } else {
                // Insert in sorted order by datagram offset. Detect overlaps and duplicates.
                var q = lrhEntry.fragments
                var last: Pbuf?
                var inserted = false

                while let currentFrag = q {
                    let qDatagramOffset = UInt16(currentFrag.byte(at: 0)) << 3
                    let qFragLen = currentFrag.len - 1

                    if datagramOffset < qDatagramOffset {
                        // Check for overlap with this later fragment.
                        if datagramOffset + newFragLen > qDatagramOffset {
                            dequeueReassembly(lrhEntry, prev: lrhPrev)
                            freeReassemblyDatagram(lrhEntry)
                            _ = Pbuf.free(pbuf)
                            return .ok
                        }
                        // Insert before currentFrag.
                        if let lastFrag = last {
                            lastFrag.next = pbuf
                        } else {
                            lrhEntry.fragments = pbuf
                        }
                        pbuf.next = currentFrag
                        inserted = true
                        break
                    } else if datagramOffset == qDatagramOffset {
                        if qFragLen != newFragLen {
                            // Same offset but different length -- mismatch.
                            dequeueReassembly(lrhEntry, prev: lrhPrev)
                            freeReassemblyDatagram(lrhEntry)
                            _ = Pbuf.free(pbuf)
                            return .ok
                        }
                        // Duplicate fragment -- silently ignore.
                        _ = Pbuf.free(pbuf)
                        return .ok
                    }

                    last = currentFrag
                    q = currentFrag.next
                }

                if !inserted {
                    // Append at end.
                    last?.next = pbuf
                    pbuf.next = nil
                }
            }

            // Check if all fragments have been received.
            return checkReassemblyComplete(lrhEntry, prev: lrhPrev, netif: netif)
        }

        // ---------------------------------------------------------------
        // Unfragmented packet
        // ---------------------------------------------------------------
        if dispatch == 0x41 {
            // Uncompressed IPv6, skip dispatch byte.
            _ = pbuf.removeHeader(1)
            return netif.input?(pbuf, netif) ?? .invalidValue
        } else if (dispatch & 0xE0) == 0x60 {
            // IPHC compressed.
            guard let decompressed = lowpan6Decompress(
                pbuf: pbuf,
                datagramSize: 0,
                contextTable: data.contextTable,
                src: src,
                dst: dst
            ) else {
                return .ok
            }
            return netif.input?(decompressed, netif) ?? .invalidValue
        }

        // Unknown dispatch.
        _ = Pbuf.free(pbuf)
        return .ok
    }
}

// MARK: - 6LoWPAN over BLE (RFC 7668)

/// 6LoWPAN over Bluetooth Low Energy interface.
public final class RFC7668Interface: @unchecked Sendable {
    public let contextTable = LowPAN6ContextTable()
    public var localAddr = LowPAN6LinkAddr()
    public var peerAddr = LowPAN6LinkAddr()
    public var netif: NetworkInterface?

    public init() {}

    /// Convert BLE MAC address (6 bytes) to EUI-64 address (8 bytes)
    public static func bleAddrToEUI64(src: [UInt8], isPublicAddr: Bool = false) -> [UInt8] {
        var dst = [UInt8](repeating: 0, count: 8)
        guard src.count >= 6 else { return dst }
        dst[0] = src[0]
        dst[1] = src[1]
        dst[2] = src[2]
        dst[3] = 0xFF
        dst[4] = 0xFE
        dst[5] = src[3]
        dst[6] = src[4]
        dst[7] = src[5]
        if isPublicAddr {
            dst[0] &= ~0x02
        } else {
            dst[0] |= 0x02
        }
        return dst
    }

    /// Convert EUI-64 address to BLE MAC address
    public static func eui64ToBLEAddr(src: [UInt8]) -> [UInt8] {
        var dst = [UInt8](repeating: 0, count: 6)
        guard src.count >= 8 else { return dst }
        dst[0] = src[0]
        dst[1] = src[1]
        dst[2] = src[2]
        dst[3] = src[5]
        dst[4] = src[6]
        dst[5] = src[7]
        return dst
    }

    /// Set the local EUI-64 address (8 bytes)
    public func setLocalAddrEUI64(_ addr: [UInt8]) -> LWIPError {
        guard addr.count == 8 else { return .invalidValue }
        localAddr.addrLen = 8
        localAddr.addr = Array(addr[0..<8])
        return .ok
    }

    /// Set the local address from a BLE MAC-48 (6 bytes)
    public func setLocalAddrMAC48(_ addr: [UInt8], isPublicAddr: Bool = false) -> LWIPError {
        guard addr.count == 6 else { return .invalidValue }
        localAddr.addrLen = 8
        localAddr.addr = RFC7668Interface.bleAddrToEUI64(src: addr, isPublicAddr: isPublicAddr)
        return .ok
    }

    /// Set the peer EUI-64 address (8 bytes)
    public func setPeerAddrEUI64(_ addr: [UInt8]) -> LWIPError {
        guard addr.count == 8 else { return .invalidValue }
        peerAddr.addrLen = 8
        peerAddr.addr = Array(addr[0..<8])
        return .ok
    }

    /// Set the peer address from a BLE MAC-48 (6 bytes)
    public func setPeerAddrMAC48(_ addr: [UInt8], isPublicAddr: Bool = false) -> LWIPError {
        guard addr.count == 6 else { return .invalidValue }
        peerAddr.addrLen = 8
        peerAddr.addr = RFC7668Interface.bleAddrToEUI64(src: addr, isPublicAddr: isPublicAddr)
        return .ok
    }

    /// Set a compression context for this interface
    public func setContext(index: UInt8, context: IPv6Address) -> LWIPError {
        return contextTable.set(index: index, context: context)
    }

    /// Compress and send an IPv6 packet over BLE
    public func compress(netif: NetworkInterface, pbuf: Pbuf) -> LWIPError {
        guard let linkout = netif.linkOutput else { return .interfaceError }
        guard pbuf.totLen > 0 else { return .invalidValue }

        let payloadPtr = pbuf.payload
        var inbuf = [UInt8](repeating: 0, count: Int(pbuf.totLen))
        for i in 0..<Int(pbuf.totLen) {
            inbuf[i] = payloadPtr[i]
        }

        var outbuf = [UInt8](repeating: 0, count: Int(pbuf.totLen))

        guard let result = LowPAN6.compressHeaders(
            inbuf: inbuf,
            outbuf: &outbuf,
            contextTable: contextTable,
            src: localAddr,
            dst: peerAddr
        ) else {
            return .invalidValue
        }

        // Build output: compressed header + remaining payload
        let remainingLen = Int(pbuf.totLen) - result.hiddenLen
        var fragData = Array(outbuf[0..<result.compressedLen])
        if remainingLen > 0 && result.hiddenLen < inbuf.count {
            fragData.append(contentsOf: inbuf[result.hiddenLen..<min(inbuf.count, result.hiddenLen + remainingLen)])
        }

        guard let pFrag = Pbuf.alloc(layer: .raw, length: UInt16(fragData.count), type: .ram) else {
            return .outOfMemory
        }
        fragData.withUnsafeBufferPointer { buf in
            _ = pFrag.take(from: buf.baseAddress!, len: UInt16(fragData.count))
        }
        return linkout(netif, pFrag)
    }

    /// Process a received raw payload from an L2CAP channel
    public func input(pbuf: Pbuf, netif: NetworkInterface) -> LWIPError {
        guard pbuf.totLen > 0 else {
            return .invalidValue
        }

        let dispatch = pbuf.byte(at: 0)
        let deliveredPbuf: Pbuf

        if dispatch == 0x41 {
            // Uncompressed IPv6, skip dispatch byte
            _ = pbuf.removeHeader(1)
            deliveredPbuf = pbuf
        } else if (dispatch & 0xE0) == 0x60 {
            // IPHC compressed
            guard let decompressed = lowpan6Decompress(
                pbuf: pbuf,
                datagramSize: 0,
                contextTable: contextTable,
                src: peerAddr,
                dst: localAddr
            ) else {
                return .ok
            }
            deliveredPbuf = decompressed
        } else {
            // Invalid dispatch
            _ = Pbuf.free(pbuf)
            return .ok
        }

        // Pass to IP6 input
        return netif.input?(deliveredPbuf, netif) ?? .invalidValue
    }

    /// Initialize the RFC 7668 BLE netif
    public func setupNetif(_ netif: NetworkInterface) {
        self.netif = netif
        netif.name = (UInt8(ascii: "b"), UInt8(ascii: "t"))
        netif.mtu = 1280 // IP6_MIN_MTU_LENGTH
        netif.flags = []
        netif.outputIP6 = { [weak self] outputNetif, pbuf, _ in
            self?.compress(netif: outputNetif, pbuf: pbuf) ?? .interfaceError
        }
    }
}
