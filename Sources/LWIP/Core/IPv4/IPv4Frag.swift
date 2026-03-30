//
//  IPv4Frag.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for IPv4 reassembly constants.
public enum IPv4ReassemblyConstants {
    /// Timer interval in milliseconds.
    public static let timerInterval: Int = 1000
}

/// Flag indicating the last fragment has been received.
private let reassemblyFlagLastFragment: UInt8 = 0x01

/// Validation return codes.
private enum ReassemblyValidation {
    static let telegramFinished: Int = 1
    static let pbufQueued: Int = 0
    static let pbufDropped: Int = -1
}

// MARK: - Reassembly Helper

/// Helper structure stored in place of the IP header in fragment pbufs
/// to chain fragments during reassembly.
public final class ReassemblyHelper {
    /// Next fragment pbuf in the chain.
    public var nextPbuf: Pbuf?
    /// Start offset of this fragment's data.
    public var start: UInt16
    /// End offset of this fragment's data.
    public var end: UInt16

    public init() {
        nextPbuf = nil
        start = 0
        end = 0
    }
}

// MARK: - Reassembly Data

/// Holds state for one datagram being reassembled.
public final class IPv4ReassemblyData {
    /// Next datagram in the reassembly queue.
    public var next: IPv4ReassemblyData?
    /// First fragment pbuf (with helper structs in payloads).
    public var p: Pbuf?
    /// Saved copy of the original IP header.
    public var iphdr: IPv4Header
    /// Total datagram length (set when last fragment arrives).
    public var datagramLen: UInt16
    /// Flags (reassemblyFlagLastFragment).
    public var flags: UInt8
    /// Time-to-live countdown (in seconds).
    public var timer: UInt8

    public init() {
        next = nil
        p = nil
        iphdr = IPv4Header()
        datagramLen = 0
        flags = 0
        timer = UInt8(lwipConfig.ipReassMaxAge)
    }
}

// MARK: - IPv4 Fragmentation / Reassembly Module

/// IPv4 fragmentation and reassembly implementation.
public enum IPv4Frag {

    /// Linked list of datagrams currently being reassembled.
    private static var reassDatagrams: IPv4ReassemblyData?

    /// Count of pbufs currently enqueued for reassembly.
    private static var reassPbufCount: UInt16 = 0

    // MARK: - Reassembly Init

    /// Initialize the reassembly module.
    public static func initialize() {
        reassDatagrams = nil
        reassPbufCount = 0
    }

    // MARK: - Reassembly Timer

    /// Reassembly timer. Call every IP_REASS_TMR_INTERVAL (1000ms).
    /// Decrements timers and frees timed-out datagrams.
    public static func reassTimer() {
        var r = reassDatagrams
        var prev: IPv4ReassemblyData? = nil

        while let datagram = r {
            if datagram.timer > 0 {
                datagram.timer -= 1
                prev = datagram
                r = datagram.next
            } else {
                // Timed out
                let tmp = datagram
                r = datagram.next
                freeCompleteDatagram(tmp, prev: prev)
            }
        }
    }

    // MARK: - Free Datagram

    /// Free a complete datagram and all its fragment pbufs.
    /// Sends ICMP time exceeded for the first fragment if available.
    @discardableResult
    private static func freeCompleteDatagram(_ ipr: IPv4ReassemblyData,
                                              prev: IPv4ReassemblyData?) -> Int {
        var pbufFreed: UInt16 = 0

        LWIPStats.shared.mib2.ipReasmFails += 1

        // Send ICMP time exceeded if first fragment present
        if lwipConfig.icmp, let firstPbuf = ipr.p {
            let helper = firstPbuf.reassHelper
            if helper.start == 0 {
                // First fragment: dequeue and send ICMP
                let p = firstPbuf
                ipr.p = helper.nextPbuf

                // Restore original IP header
                p.writeIPv4Header(ipr.iphdr)
                ICMP.sendTimeExceeded(p, type: .fragmentReassembly)

                let clen = p.chainLength
                pbufFreed &+= UInt16(clen)
                p.free()
            }
        }

        // Free remaining fragment pbufs
        var p = ipr.p
        while let current = p {
            let helper = current.reassHelper
            p = helper.nextPbuf
            let clen = current.chainLength
            pbufFreed &+= UInt16(clen)
            current.free()
        }

        // Dequeue from list
        dequeueDatagram(ipr, prev: prev)

        if reassPbufCount >= pbufFreed {
            reassPbufCount &-= pbufFreed
        } else {
            reassPbufCount = 0
        }

        return Int(pbufFreed)
    }

    /// Remove oldest datagram to make room for new fragments.
    private static func removeOldestDatagram(fraghdr: IPv4Header, needed: Int) -> Int {
        var freed = 0

        repeat {
            var oldest: IPv4ReassemblyData? = nil
            var oldestPrev: IPv4ReassemblyData? = nil
            var prev: IPv4ReassemblyData? = nil
            var otherDatagrams = 0

            var r = reassDatagrams
            while let datagram = r {
                if datagram.iphdr.src != fraghdr.src || datagram.iphdr.dest != fraghdr.dest ||
                   datagram.iphdr.identification != fraghdr.identification {
                    otherDatagrams += 1
                    if oldest == nil || datagram.timer <= oldest!.timer {
                        oldest = datagram
                        oldestPrev = prev
                    }
                }
                prev = datagram
                r = datagram.next
            }

            if let old = oldest {
                freed += freeCompleteDatagram(old, prev: oldestPrev)
            } else {
                break
            }
        } while freed < needed && true

        return freed
    }

    // MARK: - Enqueue / Dequeue

    /// Create a new reassembly entry and add it to the front of the list.
    private static func enqueueNewDatagram(_ fraghdr: IPv4Header, clen: Int) -> IPv4ReassemblyData? {
        var ipr = IPv4ReassemblyData()

        // Try to make room if needed
        // (simplified: just allocate)
        ipr.timer = UInt8(lwipConfig.ipReassMaxAge)
        ipr.next = reassDatagrams
        reassDatagrams = ipr
        ipr.iphdr = fraghdr
        return ipr
    }

    /// Remove a datagram from the reassembly list.
    private static func dequeueDatagram(_ ipr: IPv4ReassemblyData, prev: IPv4ReassemblyData?) {
        if reassDatagrams === ipr {
            reassDatagrams = ipr.next
        } else {
            prev?.next = ipr.next
        }
    }

    // MARK: - Chain Fragment

    /// Insert a new fragment pbuf into the correct position in the datagram chain.
    /// Checks for overlapping/duplicate fragments.
    ///
    /// - Returns: A validation code indicating the reassembly state.
    private static func chainFragIntoDatagram(_ ipr: IPv4ReassemblyData,
                                               newP: Pbuf, isLast: Bool) -> Int {
        let fraghdr = newP.readIPv4Header()
        let hlen = fraghdr.headerLengthBytes
        var len = fraghdr.totalLengthHost
        guard hlen <= len else { return ReassemblyValidation.pbufDropped }
        len -= hlen
        let offset = fraghdr.fragmentOffsetBytes

        // Set up the helper
        let newHelper = ReassemblyHelper()
        newHelper.start = offset
        newHelper.end = offset &+ len
        guard newHelper.end >= offset else { return ReassemblyValidation.pbufDropped }

        newP.reassHelper = newHelper

        // Find insertion point
        var q = ipr.p
        var prevHelper: ReassemblyHelper? = nil
        var valid = true

        while let current = q {
            let curHelper = current.reassHelper
            if newHelper.start < curHelper.start {
                // Insert before current
                newHelper.nextPbuf = current
                if let ph = prevHelper {
                    // Check overlap
                    if newHelper.start < ph.end || newHelper.end > curHelper.start {
                        return ReassemblyValidation.pbufDropped
                    }
                    ph.nextPbuf = newP
                    if ph.end != newHelper.start {
                        valid = false
                    }
                } else {
                    if newHelper.end > curHelper.start {
                        return ReassemblyValidation.pbufDropped
                    }
                    ipr.p = newP
                }
                break
            } else if newHelper.start == curHelper.start {
                // Duplicate
                return ReassemblyValidation.pbufDropped
            } else if newHelper.start < curHelper.end {
                // Overlap
                return ReassemblyValidation.pbufDropped
            } else {
                if let ph = prevHelper, ph.end != curHelper.start {
                    valid = false
                }
            }

            let nextP = curHelper.nextPbuf
            prevHelper = curHelper
            q = nextP
        }

        // If we reached end of list, append
        if q == nil {
            if let ph = prevHelper {
                ph.nextPbuf = newP
                if ph.end != newHelper.start {
                    valid = false
                }
            } else {
                ipr.p = newP
            }
        }

        // Validation
        if isLast || (ipr.flags & reassemblyFlagLastFragment) != 0 {
            if valid {
                // Check completeness
                guard let first = ipr.p, first.reassHelper.start == 0 else {
                    return ReassemblyValidation.pbufQueued
                }

                var checkHelper: ReassemblyHelper? = newHelper
                var checkQ = newHelper.nextPbuf
                while let cq = checkQ {
                    let ch = cq.reassHelper
                    if checkHelper!.end != ch.start {
                        valid = false
                        break
                    }
                    checkHelper = ch
                    checkQ = ch.nextPbuf
                }

                return valid ? ReassemblyValidation.telegramFinished : ReassemblyValidation.pbufQueued
            }
            return ReassemblyValidation.pbufQueued
        }

        return ReassemblyValidation.pbufQueued
    }

    // MARK: - Reassemble

    /// Reassemble incoming IP fragments into a complete datagram.
    ///
    /// - Parameter p: An incoming fragment.
    /// - Returns: The complete reassembled pbuf, or `nil` if reassembly is not yet complete.
    public static func reassemble(_ p: Pbuf) -> Pbuf? {
        LWIPStats.shared.ipFrag.received += 1
        LWIPStats.shared.mib2.ipReasmReqds += 1

        let fraghdr = p.readIPv4Header()

        // We only support standard IP header (no options) for reassembly
        guard fraghdr.headerLengthBytes == IPv4HeaderConstants.standardLength else {
            LWIPStats.shared.ipFrag.errors += 1
            LWIPStats.shared.ipFrag.dropped += 1
            p.free()
            return nil
        }

        let offset = fraghdr.fragmentOffsetBytes
        var len = fraghdr.totalLengthHost
        let hlen = fraghdr.headerLengthBytes
        guard hlen <= len else {
            LWIPStats.shared.ipFrag.dropped += 1
            p.free()
            return nil
        }
        len -= hlen

        // Check pbuf count limit
        let clen = p.chainLength
        if reassPbufCount &+ UInt16(clen) > UInt16(lwipConfig.ipReassMaxPbufs) {
            let needed = Int(clen)
            if removeOldestDatagram(fraghdr: fraghdr, needed: needed) < needed {
                if reassPbufCount &+ UInt16(clen) > UInt16(lwipConfig.ipReassMaxPbufs) {
                    LWIPStats.shared.ipFrag.memoryErrors += 1
                    LWIPStats.shared.ipFrag.dropped += 1
                    p.free()
                    return nil
                }
            }
        }

        // Find existing datagram or create new one
        var ipr = reassDatagrams
        while let datagram = ipr {
            if datagram.iphdr.src == fraghdr.src &&
               datagram.iphdr.dest == fraghdr.dest &&
               datagram.iphdr.identification == fraghdr.identification {
                LWIPStats.shared.ipFrag.cacheHits += 1
                break
            }
            ipr = datagram.next
        }

        if ipr == nil {
            guard let newIpr = enqueueNewDatagram(fraghdr, clen: Int(clen)) else {
                LWIPStats.shared.ipFrag.memoryErrors += 1
                LWIPStats.shared.ipFrag.dropped += 1
                p.free()
                return nil
            }
            ipr = newIpr
        } else {
            // If this is the first fragment (offset 0) and the stored one isn't,
            // update the stored header
            if fraghdr.fragmentOffsetBytes == 0 && ipr!.iphdr.fragmentOffsetBytes != 0 {
                ipr!.iphdr = fraghdr
            }
        }

        guard let datagram = ipr else {
            LWIPStats.shared.ipFrag.dropped += 1
            p.free()
            return nil
        }

        let isLast = !fraghdr.hasMoreFragments
        if isLast {
            let dgLen = offset &+ len
            guard dgLen >= offset, dgLen <= 0xFFFF - IPv4HeaderConstants.standardLength else {
                // Overflow
                if datagram.p == nil {
                    dequeueDatagram(datagram, prev: nil)
                }
                LWIPStats.shared.ipFrag.dropped += 1
                p.free()
                return nil
            }
        }

        // Insert fragment
        let valid = chainFragIntoDatagram(datagram, newP: p, isLast: isLast)
        if valid == ReassemblyValidation.pbufDropped {
            if datagram.p == nil {
                dequeueDatagram(datagram, prev: nil)
            }
            LWIPStats.shared.ipFrag.dropped += 1
            p.free()
            return nil
        }

        // Track pbuf count
        reassPbufCount &+= UInt16(clen)

        if isLast {
            datagram.datagramLen = offset &+ len
            datagram.flags |= reassemblyFlagLastFragment
        }

        if valid == ReassemblyValidation.telegramFinished {
            // Reassembly complete
            let totalLen = datagram.datagramLen &+ IPv4HeaderConstants.standardLength

            guard let firstPbuf = datagram.p else {
                p.free()
                return nil
            }

            // Save next before overwriting payload with IP header
            let secondHelper = firstPbuf.reassHelper
            let secondPbuf = secondHelper.nextPbuf

            // Restore original IP header into first pbuf
            var finalHdr = datagram.iphdr
            finalHdr.totalLength = totalLen.bigEndian
            finalHdr.flagsFragOffset = 0
            finalHdr.checksum = 0
            firstPbuf.writeIPv4Header(finalHdr)
            if lwipConfig.checksumGenIP {
                finalHdr.checksum = InetChecksum.checksum(UnsafeRawPointer(firstPbuf.payload), len: UInt16(IPv4HeaderConstants.standardLength))
                firstPbuf.writeIPv4Header(finalHdr)
            }

            // Chain all fragment pbufs together
            var r = secondPbuf
            var result = firstPbuf
            while let frag = r {
                let fragHelper = frag.reassHelper
                let next = fragHelper.nextPbuf

                // Remove IP header from subsequent fragments
                frag.removeHeader(Int(IPv4HeaderConstants.standardLength))
                Pbuf.cat(result, frag)
                r = next
            }

            // Remove from reassembly list
            var iprPrev: IPv4ReassemblyData? = nil
            if datagram === reassDatagrams {
                iprPrev = nil
            } else {
                var search = reassDatagrams
                while let s = search {
                    if s.next === datagram {
                        iprPrev = s
                        break
                    }
                    search = s.next
                }
            }
            dequeueDatagram(datagram, prev: iprPrev)

            // Update pbuf count
            let resultClen = result.chainLength
            if reassPbufCount >= UInt16(resultClen) {
                reassPbufCount -= UInt16(resultClen)
            } else {
                reassPbufCount = 0
            }

            LWIPStats.shared.mib2.ipReasmOks += 1
            return result
        }

        // Not yet complete
        return nil
    }

    // MARK: - Fragmentation

    /// Fragment an IP datagram that exceeds the interface MTU.
    ///
    /// Splits the packet into MTU-sized fragments and sends each one.
    ///
    /// - Parameters:
    ///   - p: The original IP packet (payload at IP header).
    ///   - netif: The output network interface.
    ///   - dest: The destination IP address.
    /// - Returns: `.ok` on success, `.outOfMemory` on allocation failure.
    @discardableResult
    public static func fragment(_ p: Pbuf, netif: NetworkInterface, dest: IPv4Address) -> LWIPError {
        let iphdr = p.readIPv4Header()
        guard iphdr.headerLengthBytes == IPv4HeaderConstants.standardLength else { return .invalidValue }
        guard p.len >= IPv4HeaderConstants.standardLength else { return .invalidValue }

        let nfb = (netif.mtu - IPv4HeaderConstants.standardLength) / 8
        guard nfb > 0 else { return .invalidValue }

        // Original fragment offset and MF flag
        let origOffset = iphdr.offsetHost
        var ofo = origOffset & IPv4FragmentFlag.offsetMask
        let mfSet = (origOffset & IPv4FragmentFlag.moreFragments) != 0

        var left = p.totLen - IPv4HeaderConstants.standardLength
        var poff: UInt16 = IPv4HeaderConstants.standardLength

        while left > 0 {
            let fragSize = min(left, nfb * 8)

            // Allocate fragment pbuf with IP header space
            guard let rambuf = Pbuf.alloc(layer: .ip, length: fragSize, type: .ram) else {
                LWIPStats.shared.mib2.ipFragFails += 1
                return .outOfMemory
            }

            // Copy fragment data from original
            p.copyPartialTo(rambuf.payload, length: Int(fragSize), srcOffset: Int(poff))
            poff += fragSize

            // Prepend IP header
            guard rambuf.addHeader(Int(IPv4HeaderConstants.standardLength)) else {
                rambuf.free()
                LWIPStats.shared.mib2.ipFragFails += 1
                return .outOfMemory
            }

            // Copy original IP header
            var fragHdr = iphdr
            let isLast = left <= netif.mtu - IPv4HeaderConstants.standardLength

            // Set offset and MF flag
            var tmp = IPv4FragmentFlag.offsetMask & ofo
            if !isLast || mfSet {
                tmp |= IPv4FragmentFlag.moreFragments
            }
            fragHdr.flagsFragOffset = tmp.bigEndian
            fragHdr.totalLength = (fragSize + IPv4HeaderConstants.standardLength).bigEndian
            fragHdr.checksum = 0
            rambuf.writeIPv4Header(fragHdr)

            // Calculate checksum (respects per-netif offload flags)
            if lwipConfig.checksumGenIP && netif.isChecksumEnabled(.genIP) {
                fragHdr.checksum = InetChecksum.checksum(UnsafeRawPointer(rambuf.payload), len: UInt16(IPv4HeaderConstants.standardLength))
                rambuf.writeIPv4Header(fragHdr)
            }

            // Send fragment
            netif.output?(netif, rambuf, dest)
            LWIPStats.shared.ipFrag.transmitted += 1

            rambuf.free()
            left -= fragSize
            ofo += nfb
        }

        LWIPStats.shared.mib2.ipFragOks += 1
        return .ok
    }
}
