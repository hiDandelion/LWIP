//
//  ICMPv6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - ICMPv6 Types

/// ICMPv6 message types.
public enum ICMPv6Type: UInt8, Sendable {
    // Error messages (0-127)
    case destinationUnreachable = 1
    case packetTooBig           = 2
    case timeExceeded           = 3
    case parameterProblem       = 4
    case privateExperimentation1 = 100
    case privateExperimentation2 = 101
    case reservedError          = 127
    // Informational messages (128-255)
    case echoRequest            = 128
    case echoReply              = 129
    case multicastListenerQuery = 130
    case multicastListenerReport = 131
    case multicastListenerDone  = 132
    case routerSolicitation     = 133
    case multicastListenerV2Report = 143
    case routerAdvertisement    = 134
    case neighborSolicitation   = 135
    case neighborAdvertisement  = 136
    case redirect               = 137
    case multicastRouterAdvert  = 151
    case multicastRouterSolicit = 152
    case multicastRouterTermination = 153
    case privateExperimentation3 = 200
    case privateExperimentation4 = 201
    case reservedInformational  = 255
}

/// ICMPv6 Destination Unreachable codes.
public enum ICMPv6DestUnreachableCode: UInt8, Sendable {
    case noRoute       = 0
    case prohibited    = 1
    case beyondScope   = 2
    case addressUnreachable = 3
    case portUnreachable    = 4
    case ingressEgressPolicy = 5
    case rejectRoute   = 6
}

/// ICMPv6 Time Exceeded codes.
public enum ICMPv6TimeExceededCode: UInt8, Sendable {
    case hopLimitExceeded    = 0
    case fragmentReassembly  = 1
}

/// ICMPv6 Parameter Problem codes.
public enum ICMPv6ParameterProblemCode: UInt8, Sendable {
    case erroneousField       = 0
    case unrecognizedNextHeader = 1
    case unrecognizedOption   = 2
}

// MARK: - ICMPv6 Header

/// Standard ICMPv6 header (8 bytes).
public struct ICMPv6Header: Sendable {
    public static let length: Int = 8

    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    /// Additional 32-bit data field (e.g., MTU for PTB, pointer for PP).
    public var data: UInt32

    @inlinable
    public init(type: UInt8 = 0, code: UInt8 = 0, checksum: UInt16 = 0, data: UInt32 = 0) {
        self.type = type
        self.code = code
        self.checksum = checksum
        self.data = data
    }

    @inlinable
    public init?(reading pbuf: Pbuf, offset: Int = 0) {
        guard pbuf.length >= offset + Self.length else { return nil }
        let p = pbuf.payload.advanced(by: offset)
        self.type = p.load(fromByteOffset: 0, as: UInt8.self)
        self.code = p.load(fromByteOffset: 1, as: UInt8.self)
        self.checksum = p.loadUnaligned(fromByteOffset: 2, as: UInt16.self).bigEndian
        self.data = p.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
    }

    @inlinable
    public func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: type, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: code, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: checksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: data.bigEndian, toByteOffset: 4, as: UInt32.self)
    }
}

/// ICMPv6 Echo header (8 bytes, same size but different layout for id/seqno).
public struct ICMPv6EchoHeader: Sendable {
    public static let length: Int = 8

    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    public var identifier: UInt16
    public var sequenceNumber: UInt16

    @inlinable
    public init?(reading p: UnsafeMutableRawPointer, length: Int) {
        guard length >= Self.length else { return nil }
        self.type = p.load(fromByteOffset: 0, as: UInt8.self)
        self.code = p.load(fromByteOffset: 1, as: UInt8.self)
        self.checksum = p.loadUnaligned(fromByteOffset: 2, as: UInt16.self).bigEndian
        self.identifier = p.loadUnaligned(fromByteOffset: 4, as: UInt16.self).bigEndian
        self.sequenceNumber = p.loadUnaligned(fromByteOffset: 6, as: UInt16.self).bigEndian
    }
}

// MARK: - ICMPv6 Module

/// ICMPv6 protocol processing.
public enum ICMPv6 {

    /// Default hop limit for ICMPv6 packets.
    public static let defaultHopLimit: UInt8 = 255

    /// Maximum data from original packet included in ICMPv6 error messages.
    public static var maxErrorDataSize: Int {
        Int(IPv6HeaderConstants.minimumMTU) - IPv6HeaderConstants.length - ICMPv6Header.length
    }

    // MARK: - Input

    /// Process an incoming ICMPv6 message.
    ///
    /// Dispatches to ND6 for neighbor discovery messages, MLD6 for multicast
    /// listener messages, and generates echo replies for echo requests.
    ///
    /// - Parameters:
    ///   - pbuf: The ICMPv6 packet (payload at ICMPv6 header).
    ///   - inputNetif: The receiving network interface.
    public static func input(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        guard let icmpHdr = ICMPv6Header(reading: pbuf) else {
            pbuf.free()
            return
        }

        // Checksum verification (respects per-netif offload flags)
        if LWIPConfig.checksumCheckICMPv6 && inputNetif.isChecksumEnabled(.checkICMP6) {
            let ctx = IPv6.currentContext
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf,
                proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.totalLength),
                src: ctx.currentSrc,
                dest: ctx.currentDest
            )
            if cksum != 0 {
                pbuf.free()
                return
            }
        }

        switch icmpHdr.type {
        case ICMPv6Type.neighborAdvertisement.rawValue,
             ICMPv6Type.neighborSolicitation.rawValue,
             ICMPv6Type.routerAdvertisement.rawValue,
             ICMPv6Type.redirect.rawValue,
             ICMPv6Type.packetTooBig.rawValue:
            ND6.input(pbuf, on: inputNetif)
            return

        case ICMPv6Type.routerSolicitation.rawValue:
            // Router functionality not implemented
            break

        case ICMPv6Type.multicastListenerQuery.rawValue,
             ICMPv6Type.multicastListenerReport.rawValue,
             ICMPv6Type.multicastListenerDone.rawValue,
             ICMPv6Type.multicastListenerV2Report.rawValue:
            if LWIPConfig.ipv6MLD {
                MLD6.input(pbuf, on: inputNetif)
                return
            }

        case ICMPv6Type.echoRequest.rawValue:
            processEchoRequest(pbuf, on: inputNetif)
            return

        default:
            break
        }

        pbuf.free()
    }

    // MARK: - Echo Request / Reply

    /// Handle an echo request by generating an echo reply.
    private static func processEchoRequest(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        let ctx = IPv6.currentContext

        // Don't respond to multicast pings unless configured
        if !LWIPConfig.multicastPing && ctx.currentDest.isMulticast {
            pbuf.free()
            return
        }

        // Allocate reply
        guard let reply = Pbuf.alloc(layer: .ip, length: UInt16(pbuf.totalLength), type: .ram) else {
            pbuf.free()
            return
        }

        // Copy echo request data
        guard reply.copy(from: pbuf) == .ok else {
            pbuf.free()
            reply.free()
            return
        }

        // Determine source address for reply
        let replySrc: IPv6Address
        if LWIPConfig.multicastPing && ctx.currentDest.isMulticast {
            guard let selected = IPv6.selectSourceAddress(on: inputNetif, for: ctx.currentSrc) else {
                pbuf.free()
                reply.free()
                return
            }
            replySrc = selected
        } else {
            replySrc = ctx.currentDest
        }

        // Set echo reply type
        reply.payload.storeBytes(of: ICMPv6Type.echoReply.rawValue, toByteOffset: 0, as: UInt8.self)

        // Calculate checksum (respects per-netif offload flags)
        reply.payload.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self)
        if LWIPConfig.checksumGenICMPv6 && inputNetif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                reply,
                proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(reply.totalLength),
                src: replySrc,
                dest: ctx.currentSrc
            )
            reply.payload.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        // Send reply
        IPv6.outputIf(reply, src: replySrc, dest: ctx.currentSrc,
                      hopLimit: Self.defaultHopLimit, trafficClass: 0,
                      nextHeader: IPv6NextHeader.icmpv6.rawValue, netif: inputNetif)
        reply.free()
        pbuf.free()
    }

    // MARK: - Error Messages

    /// Send an ICMPv6 Destination Unreachable message.
    public static func sendDestUnreachable(_ pbuf: Pbuf, code: ICMPv6DestUnreachableCode) {
        sendResponse(pbuf, code: code.rawValue, data: 0,
                     type: ICMPv6Type.destinationUnreachable.rawValue)
    }

    /// Send an ICMPv6 Packet Too Big message.
    public static func sendPacketTooBig(_ pbuf: Pbuf, mtu: UInt32) {
        sendResponse(pbuf, code: 0, data: mtu,
                     type: ICMPv6Type.packetTooBig.rawValue)
    }

    /// Send an ICMPv6 Time Exceeded message.
    public static func sendTimeExceeded(_ pbuf: Pbuf, code: ICMPv6TimeExceededCode) {
        sendResponse(pbuf, code: code.rawValue, data: 0,
                     type: ICMPv6Type.timeExceeded.rawValue)
    }

    /// Send an ICMPv6 Time Exceeded with explicit source/destination addresses.
    public static func sendTimeExceededWithAddrs(_ pbuf: Pbuf,
                                                  code: ICMPv6TimeExceededCode,
                                                  srcAddr: IPv6Address,
                                                  destAddr: IPv6Address) {
        sendResponseWithAddrs(pbuf, code: code.rawValue, data: 0,
                              type: ICMPv6Type.timeExceeded.rawValue,
                              srcAddr: srcAddr, destAddr: destAddr)
    }

    /// Send an ICMPv6 Parameter Problem message.
    public static func sendParameterProblem(_ pbuf: Pbuf,
                                            code: ICMPv6ParameterProblemCode,
                                            offset: UInt32) {
        sendResponse(pbuf, code: code.rawValue, data: offset,
                     type: ICMPv6Type.parameterProblem.rawValue)
    }

    // MARK: - Internal Response Helpers

    /// Send an ICMPv6 error response using the current packet context.
    private static func sendResponse(_ pbuf: Pbuf, code: UInt8, data: UInt32, type: UInt8) {
        let ctx = IPv6.currentContext
        guard let netif = ctx.currentNetif else { return }
        let replyDest = ctx.currentSrc

        guard let replySrc = IPv6.selectSourceAddress(on: netif, for: replyDest) else {
            return
        }
        sendResponseFull(pbuf, code: code, data: data, type: type,
                         replySrc: replySrc, replyDest: replyDest, netif: netif)
    }

    /// Send an ICMPv6 error response with explicit addresses.
    private static func sendResponseWithAddrs(_ pbuf: Pbuf, code: UInt8, data: UInt32,
                                              type: UInt8,
                                              srcAddr: IPv6Address,
                                              destAddr: IPv6Address) {
        // Swap src/dest for reply
        let replyDest = srcAddr
        let replySrc = destAddr
        guard let netif = IPv6.route(src: replySrc, dest: replyDest) else {
            return
        }
        sendResponseFull(pbuf, code: code, data: data, type: type,
                         replySrc: replySrc, replyDest: replyDest, netif: netif)
    }

    /// Core ICMPv6 error response builder.
    private static func sendResponseFull(_ pbuf: Pbuf, code: UInt8, data: UInt32,
                                         type: UInt8,
                                         replySrc: IPv6Address, replyDest: IPv6Address,
                                         netif: NetworkInterface) {
        let dataLen = min(pbuf.totalLength, maxErrorDataSize)
        let totalLen = ICMPv6Header.length + dataLen

        guard let q = Pbuf.alloc(layer: .ip, length: UInt16(totalLen), type: .ram) else {
            return
        }

        // Fill ICMPv6 header
        var hdr = ICMPv6Header(type: type, code: code, checksum: 0, data: data)
        hdr.write(to: q.payload)

        // Copy offending packet data
        q.copyPartialFrom(pbuf, length: dataLen, destOffset: ICMPv6Header.length)

        // Calculate checksum (respects per-netif offload flags)
        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                q,
                proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(q.totalLength),
                src: replySrc,
                dest: replyDest
            )
            q.payload.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        IPv6.outputIf(q, src: replySrc, dest: replyDest,
                      hopLimit: Self.defaultHopLimit, trafficClass: 0,
                      nextHeader: IPv6NextHeader.icmpv6.rawValue, netif: netif)
        q.free()
    }
}
