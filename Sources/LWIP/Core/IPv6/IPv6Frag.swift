//
//  IPv6Frag.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for IPv6 reassembly constants.
public enum IPv6ReassemblyConstants {
    /// Timer interval in milliseconds.
    public static let timerInterval: UInt32 = 1000
}

/// Maximum time (in seconds) a fragment set can be pending.
private let ipv6ReassMaxAge: UInt8 = 60

/// Maximum number of pbufs in the reassembly queue.
private let ip6ReassMaxPbufs: UInt16 = 64

// MARK: - Reassembly Data

/// Per-datagram reassembly tracking structure.
final class IPv6ReassData: @unchecked Sendable {
    var next: IPv6ReassData?
    var firstFragment: Pbuf?
    var srcAddress: IPv6Address = .any
    var destAddress: IPv6Address = .any
    var identification: UInt32 = 0
    var datagramLength: UInt16 = 0
    var nextHeader: UInt8 = 0
    var timer: UInt8 = 0
    /// Track total length of received fragments.
    var totalReceived: UInt16 = 0
    /// Whether we have received the last fragment.
    var haveLastFragment: Bool = false

    init() {}
}

/// Fragment list node embedded in the fragment pbuf payload.
///
/// For each fragment, we track the start offset, end offset, and
/// a reference to the next fragment pbuf.
public final class IPv6FragmentNode: @unchecked Sendable {
    public var nextPbuf: Pbuf?
    public var start: UInt16
    public var end: UInt16

    public init(start: UInt16, end: UInt16) {
        self.start = start
        self.end = end
    }
}

// MARK: - IPv6Frag Module

/// IPv6 fragmentation and reassembly.
public enum IPv6Frag {

    /// Linked list of pending reassembly datagrams.
    private static var reassDatagrams: IPv6ReassData? = nil

    /// Current count of pbufs in the reassembly queue.
    private static var reassPbufCount: UInt16 = 0

    // MARK: - Reassembly Timer

    /// Periodic reassembly timer. Must be called every `IPv6ReassemblyConstants.timerInterval` ms.
    ///
    /// Walks the reassembly list, decrements each entry's timer, and frees
    /// timed-out entries (sending ICMPv6 Time Exceeded if the first fragment
    /// was received).
    public static func reassemblyTimer() {
        var current = reassDatagrams
        while let r = current {
            if r.timer > 0 {
                r.timer -= 1
                current = r.next
            } else {
                // Timed out - save next before freeing
                let next = r.next
                freeCompleteDatagram(r)
                current = next
            }
        }
    }

    // MARK: - Reassembly

    /// Reassemble an incoming IPv6 fragment.
    ///
    /// - Parameter pbuf: The fragment packet (payload at fragment header).
    /// - Returns: The fully reassembled packet (payload at IPv6 header),
    ///            or `nil` if reassembly is not yet complete.
    public static func reassemble(_ pbuf: Pbuf) -> Pbuf? {
        // Parse the fragment header
        guard let fragHdr = IPv6FragmentHeader(reading: pbuf) else {
            pbuf.free()
            return nil
        }

        let ctx = IPv6.currentContext

        // Calculate fragment offsets
        let fragOffset = fragHdr.offset
        let fragId = fragHdr.identification

        // Calculate fragment data length from the IPv6 payload length,
        // adjusting for extension headers before the Fragment header and the
        // Fragment header itself.
        guard let currentHdr = ctx.currentHeader else {
            pbuf.free()
            return nil
        }
        let plen = Int(currentHdr.payloadLength)
        let headersBefore = Int(ctx.headerTotalLength) - IPv6HeaderConstants.length
        let fragDataLen = plen - headersBefore - IPv6FragmentHeader.length
        guard fragDataLen > 0 && fragDataLen <= 0xFFFF else {
            pbuf.free()
            return nil
        }

        let start = fragOffset
        // Check for UInt16 overflow
        guard start <= 0xFFFF - UInt16(fragDataLen) else {
            pbuf.free()
            return nil
        }
        let end = start + UInt16(fragDataLen)

        let clen = pbuf.chainLength

        // Find existing reassembly entry
        var ipr = reassDatagrams
        while let r = ipr {
            if r.identification == fragId &&
               r.srcAddress == ctx.currentSrc &&
               r.destAddress == ctx.currentDest {
                break
            }
            ipr = r.next
        }

        // Create new entry if needed
        if ipr == nil {
            let r = IPv6ReassData()
            r.timer = ipv6ReassMaxAge
            r.identification = fragId
            r.srcAddress = ctx.currentSrc
            r.destAddress = ctx.currentDest
            r.nextHeader = fragHdr.nextHeader
            r.next = reassDatagrams
            reassDatagrams = r
            ipr = r
        }

        guard let reassEntry = ipr else {
            pbuf.free()
            return nil
        }

        // Check pbuf count limits; if exceeded, try to free the oldest
        // datagram to make room.
        if reassPbufCount + clen > ip6ReassMaxPbufs {
            freeOldestDatagram(excluding: reassEntry, pbufsNeeded: Int(clen))
            if reassPbufCount + clen > ip6ReassMaxPbufs {
                // Still not enough room - drop this fragment
                pbuf.free()
                return nil
            }
        }

        // Remove the fragment header from the data and skip to payload
        pbuf.removeHeader(IPv6FragmentHeader.length)

        // Create fragment node
        let fragNode = IPv6FragmentNode(start: start, end: end)

        // Track whether this is the last fragment
        if !fragHdr.moreFragments {
            reassEntry.haveLastFragment = true
            reassEntry.datagramLength = end
        }

        // Track the fragment in the reassembly queue
        reassPbufCount += clen
        pbuf.fragmentNode = fragNode

        // Insert in sorted order by start offset, checking for overlaps and
        // duplicates along the way.
        var valid = true
        if reassEntry.firstFragment == nil {
            // First fragment ever received for this datagram
            reassEntry.firstFragment = pbuf
        } else {
            var prev: Pbuf? = nil
            var cur = reassEntry.firstFragment
            var inserted = false

            while let c = cur {
                guard let curNode = c.fragmentNode else {
                    cur = c.fragmentNext
                    continue
                }

                if start < curNode.start {
                    // Insert before this node

                    // Check for overlap with the following fragment
                    if end > curNode.start {
                        // Overlaps with following fragment - reject
                        reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
                        pbuf.free()
                        return nil
                    }

                    // Check for overlap with the previous fragment
                    if let p = prev, let prevNode = p.fragmentNode {
                        if start < prevNode.end {
                            // Overlaps with previous fragment - reject
                            reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
                            pbuf.free()
                            return nil
                        }
                        // Check for gap between previous and current
                        if prevNode.end != start {
                            valid = false
                        }
                    }

                    // Check for gap between current insert and the following fragment
                    if end != curNode.start {
                        valid = false
                    }

                    // Insert before cur
                    if let p = prev {
                        pbuf.fragmentNext = p.fragmentNext
                        p.fragmentNext = pbuf
                    } else {
                        pbuf.fragmentNext = reassEntry.firstFragment
                        reassEntry.firstFragment = pbuf
                    }
                    inserted = true
                    break

                } else if start == curNode.start {
                    // Duplicate fragment - drop
                    reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
                    pbuf.free()
                    return nil

                } else if start < curNode.end {
                    // Overlaps with an existing fragment - drop
                    reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
                    pbuf.free()
                    return nil

                } else {
                    // start >= curNode.end, continue walking
                    // Check for gap between previous and current
                    if let p = prev, let prevNode = p.fragmentNode {
                        if prevNode.end != curNode.start {
                            valid = false
                        }
                    }
                }

                prev = c
                cur = c.fragmentNext
            }

            if !inserted {
                // Append at end
                if let p = prev, let prevNode = p.fragmentNode {
                    // Check for overlap with the last fragment in the list
                    if prevNode.end > start {
                        reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
                        pbuf.free()
                        return nil
                    }
                    p.fragmentNext = pbuf
                    if prevNode.end != start {
                        valid = false
                    }
                } else {
                    reassEntry.firstFragment = pbuf
                }
            }
        }

        reassEntry.totalReceived += UInt16(fragDataLen)

        // Additional validity tests: we need the first fragment (offset 0) and
        // the last fragment (moreFragments == false) to be complete.
        if let firstFrag = reassEntry.firstFragment,
           let firstNode = firstFrag.fragmentNode {
            if firstNode.start != 0 {
                valid = false
            }
        } else {
            valid = false
        }

        if reassEntry.datagramLength == 0 {
            valid = false
        }

        // Verify contiguous coverage from this fragment forward
        if valid {
            var prevNode = fragNode
            var nextFrag = pbuf.fragmentNext
            while let nf = nextFrag {
                guard let nn = nf.fragmentNode else {
                    valid = false
                    break
                }
                if prevNode.end != nn.start {
                    valid = false
                    break
                }
                prevNode = nn
                nextFrag = nf.fragmentNext
            }
        }

        // Check if reassembly is complete
        guard valid && reassEntry.haveLastFragment else {
            return nil
        }

        // Final complete check: verify contiguous coverage from 0 to datagramLength
        var expectedStart: UInt16 = 0
        var complete = true
        var frag = reassEntry.firstFragment
        while let f = frag {
            guard let node = f.fragmentNode else {
                complete = false
                break
            }
            if node.start != expectedStart {
                complete = false
                break
            }
            expectedStart = node.end
            frag = f.fragmentNext
        }
        if !complete || expectedStart != reassEntry.datagramLength {
            return nil
        }

        // Reassembly complete - build final packet
        // Allocate a new pbuf with the full IPv6 header + reassembled data
        let totalLen = IPv6HeaderConstants.length + Int(reassEntry.datagramLength)
        guard let result = Pbuf.alloc(layer: .raw, length: UInt16(totalLen), type: .ram) else {
            freeCompleteDatagram(reassEntry)
            return nil
        }

        // Write IPv6 header with the next-header field from the Fragment
        // header (i.e. the protocol that follows the fragment header),
        // and the payload length set to the total reassembled data length.
        let hdr = IPv6Header(
            trafficClass: currentHdr.trafficClass,
            flowLabel: currentHdr.flowLabel,
            payloadLength: reassEntry.datagramLength,
            nextHeader: reassEntry.nextHeader,
            hopLimit: currentHdr.hopLimit,
            src: reassEntry.srcAddress,
            dest: reassEntry.destAddress
        )
        hdr.write(to: result)

        // Copy fragment data into the result buffer in order
        var offset = IPv6HeaderConstants.length
        frag = reassEntry.firstFragment
        while let f = frag {
            let dataLen = f.totalLength
            result.copyPartialFrom(f, length: dataLen, destOffset: offset)
            offset += dataLen
            frag = f.fragmentNext
        }

        // Clean up reassembly entry and adjust pbuf count
        let reassClen = countReassFragmentPbufs(reassEntry)
        removeReassData(reassEntry)
        freeReassFragments(reassEntry)
        reassPbufCount = reassPbufCount >= reassClen ? reassPbufCount - reassClen : 0

        return result
    }

    // MARK: - Fragmentation

    /// Fragment an outgoing IPv6 packet.
    ///
    /// - Parameters:
    ///   - pbuf: The packet to fragment (payload at IPv6 header).
    ///   - netif: The output network interface.
    ///   - dest: Destination address.
    /// - Returns: `.ok` on success, error otherwise.
    @discardableResult
    public static func fragment(_ pbuf: Pbuf, on netif: NetworkInterface,
                                to dest: IPv6Address) -> LWIPError {
        let mtu = Int(ND6.getDestinationMTU(for: dest, on: netif))
        guard mtu >= Int(IPv6HeaderConstants.minimumMTU) else { return .invalidValue }

        // Maximum fragment payload size (must be multiple of 8)
        let maxFragPayload = (mtu - IPv6HeaderConstants.length - IPv6FragmentHeader.length) & ~7
        guard maxFragPayload > 0 else { return .invalidValue }

        // Read original header
        guard let origHdr = IPv6Header(reading: pbuf) else { return .invalidValue }
        let totalPayload = Int(origHdr.payloadLength)

        // Generate identification
        let identification = generateFragId()

        var offset = 0
        while offset < totalPayload {
            let remaining = totalPayload - offset
            let fragPayload = min(remaining, maxFragPayload)
            let isLast = (offset + fragPayload >= totalPayload)

            // Fragment size: IPv6 header + Fragment header + data
            let fragTotalLen = IPv6HeaderConstants.length + IPv6FragmentHeader.length + fragPayload
            guard let frag = Pbuf.alloc(layer: .raw, length: UInt16(fragTotalLen), type: .ram) else {
                return .outOfMemory
            }

            // Write IPv6 header with next-header set to Fragment
            let fragHdr = IPv6Header(
                trafficClass: origHdr.trafficClass,
                flowLabel: origHdr.flowLabel,
                payloadLength: UInt16(IPv6FragmentHeader.length + fragPayload),
                nextHeader: IPv6NextHeader.fragment.rawValue,
                hopLimit: origHdr.hopLimit,
                src: origHdr.src,
                dest: origHdr.dest
            )
            fragHdr.write(to: frag)

            // Write fragment extension header (8 bytes)
            let fragHdrP = frag.payload.advanced(by: IPv6HeaderConstants.length)
            // Byte 0: Next Header (protocol that follows the fragment header)
            fragHdrP.storeBytes(of: origHdr.nextHeader, toByteOffset: 0, as: UInt8.self)
            // Byte 1: Reserved
            fragHdrP.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
            // Bytes 2-3: Fragment Offset (13 bits) | Res (2 bits) | M flag (1 bit)
            var fragOffsetField = UInt16(offset) & IPv6FragmentHeader.offsetMask
            if !isLast { fragOffsetField |= IPv6FragmentHeader.moreFlag }
            fragHdrP.storeBytes(of: fragOffsetField.bigEndian, toByteOffset: 2, as: UInt16.self)
            // Bytes 4-7: Identification
            fragHdrP.storeBytes(of: identification.bigEndian, toByteOffset: 4, as: UInt32.self)

            // Copy payload data from original pbuf
            let srcOffset = IPv6HeaderConstants.length + offset
            frag.copyPartialFrom(pbuf, length: fragPayload,
                                 srcOffset: srcOffset,
                                 destOffset: IPv6HeaderConstants.length + IPv6FragmentHeader.length)

            // Send fragment
            let err = netif.outputIPv6(frag, to: dest)
            frag.free()
            if err != .ok { return err }

            offset += fragPayload
        }

        return .ok
    }

    // MARK: - Private Helpers

    /// Monotonically increasing fragment identification counter.
    private static var fragIdCounter: UInt32 = 0

    /// Generate a unique identification value for outgoing fragments.
    private static func generateFragId() -> UInt32 {
        fragIdCounter += 1
        return fragIdCounter
    }

    /// Free all fragments and the reassembly entry, sending ICMPv6 Time
    /// Exceeded (fragment reassembly time exceeded) if the first fragment
    /// (offset 0) was received.
    private static func freeCompleteDatagram(_ r: IPv6ReassData) {
        var pbufsFreed: UInt16 = 0

        // If the first fragment (offset 0) was received, send ICMPv6
        // Time Exceeded before freeing.
        if let firstPbuf = r.firstFragment,
           let firstNode = firstPbuf.fragmentNode,
           firstNode.start == 0 {
            // Dequeue the first fragment so we can send ICMP with it
            let p = firstPbuf
            r.firstFragment = p.fragmentNext
            p.fragmentNext = nil

            // Build a packet suitable for sending ICMPv6:
            // We need the IPv6 header + fragment header + some data.
            // Allocate a new pbuf with room for the IPv6 header, fragment
            // header, and the fragment data, then send the ICMP response.
            let dataLen = p.totalLength
            let icmpPktLen = IPv6HeaderConstants.length + IPv6FragmentHeader.length + dataLen
            if let icmpPbuf = Pbuf.alloc(layer: .raw, length: UInt16(icmpPktLen), type: .ram) {
                // Write IPv6 header
                let ipHdr = IPv6Header(
                    payloadLength: UInt16(IPv6FragmentHeader.length + dataLen),
                    nextHeader: IPv6NextHeader.fragment.rawValue,
                    hopLimit: 64,
                    src: r.srcAddress,
                    dest: r.destAddress
                )
                ipHdr.write(to: icmpPbuf)

                // Write a placeholder fragment header
                let fhPtr = icmpPbuf.payload.advanced(by: IPv6HeaderConstants.length)
                fhPtr.storeBytes(of: r.nextHeader, toByteOffset: 0, as: UInt8.self)
                fhPtr.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
                fhPtr.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self)
                fhPtr.storeBytes(of: r.identification.bigEndian, toByteOffset: 4, as: UInt32.self)

                // Copy fragment data
                icmpPbuf.copyPartialFrom(p, length: dataLen,
                                         destOffset: IPv6HeaderConstants.length + IPv6FragmentHeader.length)

                ICMPv6.sendTimeExceededWithAddrs(icmpPbuf,
                                                 code: .fragmentReassembly,
                                                 srcAddr: r.srcAddress,
                                                 destAddr: r.destAddress)
                icmpPbuf.free()
            }

            let clen = p.chainLength
            pbufsFreed += clen
            p.free()
        }

        // Free remaining fragment pbufs
        var frag = r.firstFragment
        while let f = frag {
            let next = f.fragmentNext
            let clen = f.chainLength
            pbufsFreed += clen
            f.fragmentNext = nil
            f.free()
            frag = next
        }
        r.firstFragment = nil

        // Remove from linked list
        removeReassData(r)

        // Update global pbuf count
        reassPbufCount = reassPbufCount >= pbufsFreed ? reassPbufCount - pbufsFreed : 0
    }

    /// Free the oldest incomplete datagram to make room for new fragments.
    /// The datagram `excluding` is not freed.
    private static func freeOldestDatagram(excluding current: IPv6ReassData,
                                           pbufsNeeded: Int) {
        while (Int(reassPbufCount) + pbufsNeeded > Int(ip6ReassMaxPbufs)) &&
              reassDatagrams != nil {
            var r = reassDatagrams
            var oldest: IPv6ReassData? = reassDatagrams
            while let entry = r {
                if entry !== current {
                    if let o = oldest {
                        if entry.timer <= o.timer {
                            oldest = entry
                        }
                    } else {
                        oldest = entry
                    }
                }
                r = entry.next
            }
            // If the only entry is the current one, nothing to free
            if oldest === current {
                return
            }
            if let o = oldest {
                freeCompleteDatagram(o)
            } else {
                return
            }
        }
    }

    /// Free all fragment pbufs in a reassembly entry without sending ICMP.
    /// Used during successful reassembly cleanup.
    private static func freeReassFragments(_ r: IPv6ReassData) {
        var frag = r.firstFragment
        while let f = frag {
            let next = f.fragmentNext
            f.fragmentNext = nil
            f.free()
            frag = next
        }
        r.firstFragment = nil
    }

    /// Count the total number of pbufs across all fragments in a reassembly entry.
    private static func countReassFragmentPbufs(_ r: IPv6ReassData) -> UInt16 {
        var count: UInt16 = 0
        var frag = r.firstFragment
        while let f = frag {
            count += f.chainLength
            frag = f.fragmentNext
        }
        return count
    }

    /// Simple helper that frees all fragment pbufs and removes the entry
    /// from the list (no ICMP). Used for legacy callers.
    private static func freeReassData(_ r: IPv6ReassData) {
        // Free all fragment pbufs
        var frag = r.firstFragment
        while let f = frag {
            let next = f.fragmentNext
            let clen = f.chainLength
            reassPbufCount = reassPbufCount >= clen ? reassPbufCount - clen : 0
            f.fragmentNext = nil
            f.free()
            frag = next
        }
        r.firstFragment = nil

        // Remove from list
        removeReassData(r)
    }

    /// Remove a reassembly entry from the linked list.
    private static func removeReassData(_ r: IPv6ReassData) {
        if reassDatagrams === r {
            reassDatagrams = r.next
        } else {
            var prev = reassDatagrams
            while let p = prev {
                if p.next === r {
                    p.next = r.next
                    break
                }
                prev = p.next
            }
        }
        r.next = nil
    }
}
