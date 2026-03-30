//
//  ICMP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - ICMP Type Codes

/// ICMP message type codes.
public enum ICMPType: UInt8, Sendable {
    case echoReply          = 0
    case destUnreachable    = 3
    case sourceQuench       = 4
    case redirect           = 5
    case echo               = 8
    case timeExceeded       = 11
    case parameterProblem   = 12
    case timestamp          = 13
    case timestampReply     = 14
    case infoRequest        = 15
    case infoReply          = 16
    case addressMask        = 17
    case addressMaskReply   = 18
}

/// ICMP destination unreachable codes.
public enum ICMPDestUnreachCode: UInt8, Sendable {
    case netUnreachable         = 0
    case hostUnreachable        = 1
    case protocolUnreachable    = 2
    case portUnreachable        = 3
    case fragmentationNeeded    = 4
    case sourceRouteFailed      = 5
}

/// ICMP time exceeded codes.
public enum ICMPTimeExceededCode: UInt8, Sendable {
    case ttlExceeded            = 0
    case fragmentReassembly     = 1
}

// MARK: - ICMP Header

/// Standard ICMP header (8 bytes).
public struct ICMPHeader {
    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    /// Generic 32-bit data field (used as id+seq for echo).
    public var data: UInt32

    public init() {
        type = 0
        code = 0
        checksum = 0
        data = 0
    }

    public static let size: Int = 8
}

/// ICMP echo header (8 bytes, same layout but with named identifier/sequenceNumber).
public struct ICMPEchoHeader {
    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    public var identifier: UInt16
    public var sequenceNumber: UInt16

    public init() {
        type = 0
        code = 0
        checksum = 0
        identifier = 0
        sequenceNumber = 0
    }

    public static let size: Int = 8
}

// MARK: - ICMP Module

/// Maximum amount of original data to include in error responses.
private let icmpDestUnreachableDataSize: UInt16 = 8

/// ICMP processing module.
public enum ICMP {

    // MARK: - Input

    /// Process an incoming ICMP packet.
    ///
    /// - Parameters:
    ///   - p: The received packet with payload pointing to the ICMP header.
    ///   - netif: The network interface on which the packet was received.
    public static func input(_ p: Pbuf, netif: NetworkInterface) {
        guard let iphdrIn = IPv4.inputContext.currentIPv4Header else {
            p.free()
            return
        }

        let hlen = iphdrIn.headerLengthBytes
        guard hlen >= IPv4HeaderConstants.standardLength else {
            p.free()
            return
        }

        // Need at least 4 bytes for type + code + checksum
        guard p.len >= 4 else {
            p.free()
            return
        }

        let icmpType = p.readByte(at: 0)

        LWIPStats.shared.mib2.icmpInMsgs += 1

        switch icmpType {
        case ICMPType.echoReply.rawValue:
            LWIPStats.shared.mib2.icmpInEchoReps += 1

        case ICMPType.echo.rawValue:
            LWIPStats.shared.mib2.icmpInEchos += 1
            handleEchoRequest(p, netif: netif, iphdr: iphdrIn, hlen: hlen)
            return  // handleEchoRequest frees p

        case ICMPType.destUnreachable.rawValue:
            LWIPStats.shared.mib2.icmpInDestUnreachs += 1

        case ICMPType.timeExceeded.rawValue:
            LWIPStats.shared.mib2.icmpInTimeExcds += 1

        case ICMPType.parameterProblem.rawValue:
            LWIPStats.shared.mib2.icmpInParmProbs += 1

        case ICMPType.sourceQuench.rawValue:
            LWIPStats.shared.mib2.icmpInSrcQuenchs += 1

        case ICMPType.redirect.rawValue:
            LWIPStats.shared.mib2.icmpInRedirects += 1

        case ICMPType.timestamp.rawValue:
            LWIPStats.shared.mib2.icmpInTimestamps += 1

        case ICMPType.timestampReply.rawValue:
            LWIPStats.shared.mib2.icmpInTimestampReps += 1

        case ICMPType.addressMask.rawValue:
            LWIPStats.shared.mib2.icmpInAddrMasks += 1

        case ICMPType.addressMaskReply.rawValue:
            LWIPStats.shared.mib2.icmpInAddrMaskReps += 1

        default:
            break
        }

        p.free()
    }

    // MARK: - Echo Request Handling

    /// Handle an ICMP echo request (ping).
    private static func handleEchoRequest(_ p: Pbuf, netif: NetworkInterface,
                                           iphdr: IPv4Header, hlen: UInt16) {
        var src = IPv4.inputContext.currentDest

        // Multicast destination?
        if src.isMulticast {
            if lwipConfig.multicastPing {
                src = netif.ipAddr
            } else {
                p.free()
                return
            }
        }

        // Broadcast destination?
        if src.isBroadcast(on: netif) {
            if lwipConfig.broadcastPing {
                src = netif.ipAddr
            } else {
                p.free()
                return
            }
        }

        // Validate minimum echo header size
        guard p.totLen >= UInt16(ICMPEchoHeader.size) else {
            p.free()
            return
        }

        // Verify checksum (respects per-netif offload flags)
        if lwipConfig.checksumCheckICMP && netif.isChecksumEnabled(.checkICMP) {
            if InetChecksum.checksumPbuf(p) != 0 {
                p.free()
                return
            }
        }

        // We need space for the link layer header. Try to expand p.
        // If that fails, allocate a new pbuf and copy.
        let linkHdrSize = UInt16(lwipConfig.pbufLinkHlen + lwipConfig.pbufLinkEncapsulationHlen)
        if !p.addHeader(Int(hlen + linkHdrSize)) {
            // Allocate a new pbuf with space for link headers
            let allocLen = p.totLen + hlen
            guard allocLen >= p.totLen else { // overflow check
                p.free()
                return
            }

            guard let r = Pbuf.alloc(layer: .link, length: allocLen, type: .ram) else {
                p.free()
                return
            }

            guard r.len >= hlen + UInt16(ICMPEchoHeader.size) else {
                r.free()
                p.free()
                return
            }

            // Copy the IP header
            r.copyFromPayload(iphdr, offset: 0, length: Int(hlen))

            // Skip IP header in r
            r.removeHeader(Int(hlen))

            // Copy the rest (ICMP data) from p to r
            r.copyPartialFrom(p, length: Int(p.totLen), destOffset: 0)

            p.free()

            // Now modify r
            modifyEchoReply(r, src: src, hlen: hlen, netif: netif)
        } else {
            // Restore payload to ICMP header
            p.removeHeader(Int(hlen + linkHdrSize))
            modifyEchoReply(p, src: src, hlen: hlen, netif: netif)
        }
    }

    /// Modify an echo request into an echo reply and send it.
    private static func modifyEchoReply(_ p: Pbuf, src: IPv4Address,
                                         hlen: UInt16, netif: NetworkInterface) {
        // Read and modify ICMP header
        var echoHdr = p.readICMPEchoHeader()
        let origType = echoHdr.type

        // Change type to echo reply
        echoHdr.type = ICMPType.echoReply.rawValue

        // Adjust checksum incrementally (respects per-netif offload flags)
        if lwipConfig.checksumGenICMP && netif.isChecksumEnabled(.genICMP) {
            let diff = UInt16(origType) << 8
            let maxVal: UInt16 = 0xFFFF &- diff
            if echoHdr.checksum > maxVal.bigEndian {
                echoHdr.checksum = echoHdr.checksum &+ diff.bigEndian &+ 1
            } else {
                echoHdr.checksum = echoHdr.checksum &+ diff.bigEndian
            }
        } else {
            echoHdr.checksum = 0
        }
        p.writeICMPEchoHeader(echoHdr)

        // Prepend IP header
        guard p.addHeader(Int(hlen)) else { p.free(); return }

        var iphdr = p.readIPv4Header()
        iphdr.src = src
        iphdr.dest = IPv4.inputContext.currentSrc
        iphdr.timeToLive = UInt8(lwipConfig.icmpTTL)
        iphdr.checksum = 0
        if lwipConfig.checksumGenIP {
            p.writeIPv4Header(iphdr)
            iphdr.checksum = InetChecksum.checksum(UnsafeRawPointer(p.payload), len: UInt16(hlen))
        }
        p.writeIPv4Header(iphdr)

        // Interface index is reset implicitly when reusing the pbuf

        LWIPStats.shared.mib2.icmpOutMsgs += 1
        LWIPStats.shared.mib2.icmpOutEchoReps += 1

        // Send using HDRINCL (header already included)
        let _ = IPv4.outputIf(p, src: src, dest: IPv4.inputContext.currentSrc,
                              ttl: UInt8(lwipConfig.icmpTTL), tos: 0,
                              proto: IPProtocolNumber.icmp, netif: netif)
        p.free()
    }

    // MARK: - Error Messages

    /// Send an ICMP destination unreachable message.
    ///
    /// - Parameters:
    ///   - p: The original packet (payload points to IP header).
    ///   - type: The specific unreachable code.
    public static func sendDestUnreachable(_ p: Pbuf, type: ICMPDestUnreachCode) {
        sendResponse(p, type: .destUnreachable, code: type.rawValue)
    }

    /// Send an ICMP time exceeded message.
    ///
    /// - Parameters:
    ///   - p: The original packet (payload points to IP header).
    ///   - type: The specific time exceeded code.
    public static func sendTimeExceeded(_ p: Pbuf, type: ICMPTimeExceededCode) {
        sendResponse(p, type: .timeExceeded, code: type.rawValue)
    }

    /// Send an ICMP error response packet.
    ///
    /// - Parameters:
    ///   - p: The original packet that triggered the error.
    ///   - type: ICMP message type.
    ///   - code: ICMP message code.
    private static func sendResponse(_ p: Pbuf, type: ICMPType, code: UInt8) {
        // Keep IP header + up to 8 bytes of original data
        var responsePktLen = IPv4HeaderConstants.standardLength + icmpDestUnreachableDataSize
        if p.totLen < responsePktLen {
            responsePktLen = p.totLen
        }

        // Allocate ICMP header + original data
        let totalLen = UInt16(ICMPHeader.size) + responsePktLen
        guard let q = Pbuf.alloc(layer: .ip, length: totalLen, type: .ram) else {
            return
        }

        guard q.len >= totalLen else {
            q.free()
            return
        }

        // Read the original IP header for source address
        let origIphdr = p.readIPv4Header()

        // Build ICMP header
        var icmpHdr = ICMPHeader()
        icmpHdr.type = type.rawValue
        icmpHdr.code = code
        icmpHdr.data = 0
        q.writeICMPHeader(icmpHdr)

        // Copy original IP header + data
        q.copyPartialFrom(p, length: Int(responsePktLen), destOffset: ICMPHeader.size)

        // Route to sender
        let srcAddr = origIphdr.src
        guard let netif = IPv4.route(dest: srcAddr) else {
            q.free()
            return
        }

        // Calculate checksum (respects per-netif offload flags)
        var hdr = q.readICMPHeader()
        hdr.checksum = 0
        q.writeICMPHeader(hdr)
        if lwipConfig.checksumGenICMP && netif.isChecksumEnabled(.genICMP) {
            hdr.checksum = InetChecksum.checksum(UnsafeRawPointer(q.payload), len: q.len)
            q.writeICMPHeader(hdr)
        }

        LWIPStats.shared.mib2.icmpOutMsgs += 1
        switch type {
        case .destUnreachable: LWIPStats.shared.mib2.icmpOutDestUnreachs += 1
        case .timeExceeded:    LWIPStats.shared.mib2.icmpOutTimeExcds += 1
        default:               break
        }

        // Send
        let _ = IPv4.outputIf(q, src: nil, dest: srcAddr,
                              ttl: UInt8(lwipConfig.icmpTTL), tos: 0,
                              proto: IPProtocolNumber.icmp, netif: netif)
        q.free()
    }
}
