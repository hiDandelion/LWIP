//
//  UDP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - UDP Constants

/// Namespace for UDP protocol constants.
public enum UDPConstants {
    /// UDP header length (8 bytes).
    public static let headerLength: UInt16 = 8

    /// Start of ephemeral port range.
    public static let localPortRangeStart: UInt16 = 0xC000
    /// End of ephemeral port range.
    public static let localPortRangeEnd: UInt16 = 0xFFFF
}

// MARK: - UDP Flags

/// Flags stored on a UDP PCB.
public struct UDPFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Don't generate checksums on transmit.
    public static let noChecksum    = UDPFlags(rawValue: 0x01)
    /// UDP-Lite (RFC 3828) mode.
    public static let udpLite       = UDPFlags(rawValue: 0x02)
    /// PCB is connected to a remote address/port.
    public static let connected     = UDPFlags(rawValue: 0x04)
    /// Loopback multicast packets to local delivery.
    public static let multicastLoop = UDPFlags(rawValue: 0x08)
}

// MARK: - UDP Header

/// In-memory representation of a UDP header.
public struct UDPHeader {
    public var sourcePort: UInt16 = 0
    public var destinationPort: UInt16 = 0
    public var length: UInt16 = 0
    public var checksum: UInt16 = 0

    public init() {}
}

// MARK: - UDP PCB

/// UDP protocol control block.
public final class UDPControlBlock {
    // Common PCB members
    public var localIP: IPAddress = .any
    public var remoteIP: IPAddress = .any
    public var netifIdx: UInt8 = 0
    public var ttl: UInt8 = 255
    public var tos: UInt8 = 0
    public var soOptions: UInt8 = 0

    // Linked list
    public var next: UDPControlBlock?

    // Flags
    public var flags: UDPFlags = []

    // Ports (host byte order)
    public var localPort: UInt16 = 0
    public var remotePort: UInt16 = 0

    // Multicast options
    public var multicastIPv4: UInt32 = 0
    public var multicastInterfaceIndex: UInt8 = 0
    public var multicastTTL: UInt8 = 1

    // UDP-Lite checksum coverage
    public var checksumLengthReceive: UInt16 = 0
    public var checksumLengthTransmit: UInt16 = 0

    // Receive callback
    public var receiveHandler: ((UDPControlBlock, Pbuf, IPAddress, UInt16) -> Void)?
    var receiveMetadataHandler: ((UDPControlBlock, Pbuf, IPAddress, UInt16, IPAddress) -> Void)?
    public var receiveArgument: AnyObject?

    public init() {}
}

// MARK: - UDP Global State

/// Manages all UDP PCBs and provides the UDP API.
public final class UDPGlobal {
    public static let shared = UDPGlobal()

    /// Head of the global UDP PCB list.
    public var pcbs: UDPControlBlock?

    /// Last allocated ephemeral port.
    private var nextPort: UInt16 = UDPConstants.localPortRangeStart

    private init() {}

    // MARK: - Initialization

    /// Initialize the UDP module.
    public func initialize() {
        pcbs = nil
        #if DEBUG
        nextPort = UDPConstants.localPortRangeStart
        #else
        nextPort = UDPConstants.localPortRangeStart &+ UInt16(truncatingIfNeeded: arc4random())
        if nextPort < UDPConstants.localPortRangeStart || nextPort >= UDPConstants.localPortRangeEnd {
            nextPort = UDPConstants.localPortRangeStart
        }
        #endif
    }

    // MARK: - Port Allocation

    /// Allocate a new ephemeral local UDP port.
    ///
    /// Scans forward from the last allocated port through the ephemeral range
    /// (`localPortRangeStart ..< localPortRangeEnd`), wrapping around if needed,
    /// until a port is found that is not in use by any existing UDP PCB.
    ///
    /// - Returns: A free port number, or 0 if no port is available.
    public func allocatePort() -> UInt16 {
        return newPort()
    }

    /// Internal port allocation used by `bind` and `allocatePort`.
    private func newPort() -> UInt16 {
        var attempts: UInt16 = 0
        let range = UDPConstants.localPortRangeEnd - UDPConstants.localPortRangeStart

        while true {
            nextPort &+= 1
            if nextPort >= UDPConstants.localPortRangeEnd || nextPort < UDPConstants.localPortRangeStart {
                nextPort = UDPConstants.localPortRangeStart
            }

            var inUse = false
            var pcb = pcbs
            while let p = pcb {
                if p.localPort == nextPort {
                    inUse = true
                    break
                }
                pcb = p.next
            }

            if !inUse { return nextPort }

            attempts += 1
            if attempts > range { return 0 }
        }
    }

    // MARK: - PCB Creation / Removal

    /// Create a new UDP PCB.
    public func new() -> UDPControlBlock {
        let pcb = UDPControlBlock()
        pcb.ttl = UInt8(lwipConfig.udpTTL)
        pcb.multicastTTL = 1
        return pcb
    }

    /// Remove a UDP PCB from the global list and release it.
    public func remove(_ pcb: UDPControlBlock) {
        if pcbs === pcb {
            pcbs = pcb.next
        } else {
            var prev = pcbs
            while let p = prev {
                if p.next === pcb {
                    p.next = pcb.next
                    break
                }
                prev = p.next
            }
        }
        pcb.next = nil
    }

    // MARK: - Bind

    /// Bind a UDP PCB to a local address and port.
    ///
    /// - Parameters:
    ///   - pcb: The PCB to bind.
    ///   - address: Local IP address (.any to bind to all interfaces).
    ///   - port: Local port (0 for automatic allocation).
    /// - Returns: .ok on success, .addressInUse if port is already bound.
    public func bind(_ pcb: UDPControlBlock, address: IPAddress = .any, port: UInt16 = 0) -> LWIPError {
        // Check if already on the list
        var rebind = false
        var ipcb = pcbs
        while let p = ipcb {
            if p === pcb { rebind = true; break }
            ipcb = p.next
        }

        var bindPort = port
        if bindPort == 0 {
            bindPort = newPort()
            if bindPort == 0 { return .addressInUse }
        } else {
            // Check for conflicts
            let requestedOptions = SocketOptions(rawValue: pcb.soOptions)
            ipcb = pcbs
            while let p = ipcb {
                if p !== pcb && p.localPort == bindPort {
                    let existingOptions = SocketOptions(rawValue: p.soOptions)
                    if (!requestedOptions.contains(.reuseAddr) || !existingOptions.contains(.reuseAddr)) &&
                        bindAddressesOverlap(existing: p.localIP, requested: address) {
                        return .addressInUse
                    }
                }
                ipcb = p.next
            }
        }

        if address != .any {
            pcb.localIP = address
        }
        pcb.localPort = bindPort

        // Add to list if not already on it
        if !rebind {
            pcb.next = pcbs
            pcbs = pcb
        }

        return .ok
    }

    /// Bind a UDP PCB to a specific network interface.
    public func bindNetif(_ pcb: UDPControlBlock, netif: NetworkInterface?) {
        pcb.netifIdx = netif?.index ?? 0
    }

    // MARK: - Connect / Disconnect

    /// Set the remote address and port of a UDP PCB.
    ///
    /// - Parameters:
    ///   - pcb: The PCB to connect.
    ///   - address: Remote IP address.
    ///   - port: Remote port.
    /// - Returns: .ok on success.
    public func connect(_ pcb: UDPControlBlock, address: IPAddress, port: UInt16) -> LWIPError {
        pcb.remoteIP = address
        pcb.remotePort = port
        pcb.flags.insert(.connected)

        // If not yet on the list, add it
        var onList = false
        var ipcb = pcbs
        while let p = ipcb {
            if p === pcb { onList = true; break }
            ipcb = p.next
        }
        if !onList {
            pcb.next = pcbs
            pcbs = pcb
        }

        return .ok
    }

    /// Remove the remote address/port association from a UDP PCB.
    public func disconnect(_ pcb: UDPControlBlock) {
        pcb.remoteIP = .any
        pcb.remotePort = 0
        pcb.flags.remove(.connected)
    }

    // MARK: - Set Receive Callback

    /// Set the receive callback for a UDP PCB.
    ///
    /// - Parameters:
    ///   - pcb: The PCB.
    ///   - callback: The callback to invoke when data is received.
    public func recv(_ pcb: UDPControlBlock, callback: ((UDPControlBlock, Pbuf, IPAddress, UInt16) -> Void)?) {
        pcb.receiveMetadataHandler = nil
        pcb.receiveHandler = callback
    }

    /// Set an extended receive callback that also receives the destination IP.
    func recvExtended(
        _ pcb: UDPControlBlock,
        callback: ((UDPControlBlock, Pbuf, IPAddress, UInt16, IPAddress) -> Void)?
    ) {
        pcb.receiveHandler = nil
        pcb.receiveMetadataHandler = callback
    }

    // MARK: - Send

    /// Send data using a connected UDP PCB.
    public func send(_ pcb: UDPControlBlock, pbuf: Pbuf) -> LWIPError {
        guard !pcb.remoteIP.isAnyAddress else { return .invalidValue }
        return sendTo(pcb, pbuf: pbuf, dstIP: pcb.remoteIP, dstPort: pcb.remotePort)
    }

    /// Send data using a connected UDP PCB, with a pre-computed partial checksum.
    ///
    /// Like `send()` but with a pre-computed partial checksum. Used when the
    /// application has already computed part of the checksum (e.g., for checksum
    /// offloading).
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB (must be connected).
    ///   - pbuf: The payload data to send.
    ///   - haveChecksum: If true, `checksum` contains a valid pre-computed partial checksum.
    ///   - checksum: Pre-computed partial checksum over the payload.
    /// - Returns: `.ok` on success, or an error code.
    public func sendWithChecksum(_ pcb: UDPControlBlock, pbuf: Pbuf,
                                 haveChecksum: Bool, checksum: UInt16) -> LWIPError {
        guard !pcb.remoteIP.isAnyAddress else { return .invalidValue }
        return sendToWithChecksum(pcb, pbuf: pbuf, dstIP: pcb.remoteIP,
                                  dstPort: pcb.remotePort,
                                  haveChecksum: haveChecksum, checksum: checksum)
    }

    /// Send data to a specific destination, with a pre-computed partial checksum.
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB.
    ///   - pbuf: The payload data to send.
    ///   - dstIP: Destination IP address.
    ///   - dstPort: Destination port.
    ///   - haveChecksum: If true, `checksum` contains a valid pre-computed partial checksum.
    ///   - checksum: Pre-computed partial checksum over the payload.
    /// - Returns: `.ok` on success, or an error code.
    public func sendToWithChecksum(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress,
                                   dstPort: UInt16, haveChecksum: Bool,
                                   checksum: UInt16) -> LWIPError {
        var netif: NetworkInterface?

        // If bound to a specific interface, use it directly.
        if pcb.netifIdx != 0 {
            netif = NetworkInterface.getByIndex(pcb.netifIdx)
        } else {
            // For multicast, use the designated multicast interface if set.
            if dstIP.isMulticast {
                if pcb.multicastInterfaceIndex != 0 {
                    netif = NetworkInterface.getByIndex(pcb.multicastInterfaceIndex)
                }
            }

            // Otherwise, find the outgoing interface via routing.
            if netif == nil {
                netif = IPDispatch.route(src: pcb.localIP, dest: dstIP)
            }
        }

        guard let outNetif = netif else {
            LWIPStats.shared.udp.routingErrors += 1
            return .routingError
        }

        return sendToIfWithChecksum(pcb, pbuf: pbuf, dstIP: dstIP, dstPort: dstPort,
                                    netif: outNetif, haveChecksum: haveChecksum,
                                    checksum: checksum)
    }

    /// Send data to a specific destination.
    public func sendTo(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress, dstPort: UInt16) -> LWIPError {
        var netif: NetworkInterface?

        // For multicast, use the designated multicast interface if set.
        if dstIP.isMulticast, pcb.multicastInterfaceIndex != 0 {
            netif = NetworkInterface.getByIndex(pcb.multicastInterfaceIndex)
        }

        // Otherwise, find the outgoing interface via routing.
        if netif == nil {
            netif = IPDispatch.route(src: pcb.localIP, dest: dstIP)
        }

        guard let outNetif = netif else {
            LWIPStats.shared.udp.routingErrors += 1
            return .routingError
        }

        // Determine source IP address.
        let srcIP: IPAddress
        if pcb.localIP.isAnyAddress || pcb.localIP.isMulticast {
            // Use the outgoing interface's address as the source.
            if let localAddr = IPDispatch.netifGetLocalIP(outNetif, dest: dstIP) {
                srcIP = localAddr
            } else {
                return .routingError
            }
        } else {
            srcIP = pcb.localIP
        }

        return sendToIf(pcb, pbuf: pbuf, dstIP: dstIP, dstPort: dstPort,
                        netif: outNetif, srcIP: srcIP)
    }

    /// Send data to a specific destination via a specific interface.
    public func sendToIf(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress, dstPort: UInt16,
                         netif: NetworkInterface?, srcIP: IPAddress) -> LWIPError {
        return sendToIfSrcChksum(pcb, pbuf: pbuf, dstIP: dstIP, dstPort: dstPort,
                                 netif: netif, srcIP: srcIP, haveChecksum: false, checksum: 0)
    }

    /// Send data to a specific destination via a specific interface, with a pre-computed
    /// partial checksum.
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB.
    ///   - pbuf: The payload data to send.
    ///   - dstIP: Destination IP address.
    ///   - dstPort: Destination port.
    ///   - netif: The outgoing network interface (or nil).
    ///   - haveChecksum: If true, `checksum` contains a pre-computed partial checksum over the payload.
    ///   - checksum: Pre-computed partial checksum (only used when `haveChecksum` is true).
    /// - Returns: `.ok` on success, or an error code.
    public func sendToIfWithChecksum(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress,
                                     dstPort: UInt16, netif: NetworkInterface?,
                                     haveChecksum: Bool, checksum: UInt16) -> LWIPError {
        var srcIP: IPAddress

        // Determine source IP address (same logic as sendToIf in C: udp_sendto_if / udp_sendto_if_chksum)
        if pcb.localIP.isAnyAddress || pcb.localIP.isMulticast {
            if let nif = netif, let localAddr = IPDispatch.netifGetLocalIP(nif, dest: dstIP) {
                srcIP = localAddr
            } else {
                return .routingError
            }
        } else {
            srcIP = pcb.localIP
        }

        return sendToIfSrcChksum(pcb, pbuf: pbuf, dstIP: dstIP, dstPort: dstPort,
                                 netif: netif, srcIP: srcIP,
                                 haveChecksum: haveChecksum, checksum: checksum)
    }

    // MARK: - Send with Source IP

    /// Send a UDP datagram via a specific network interface with a specific source IP address.
    ///
    /// This is the most flexible send variant. It prepends the UDP header (source port,
    /// dest port, length, checksum), calculates the UDP checksum (or sets to 0 for
    /// no-checksum mode), and passes to the IP layer for transmission via the specified
    /// netif with the specified source address.
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB.
    ///   - pbuf: The payload data to send.
    ///   - dstIP: Destination IP address.
    ///   - dstPort: Destination port.
    ///   - netif: The outgoing network interface.
    ///   - srcIP: Source IP address to use.
    /// - Returns: `.ok` on success, or an error code.
    public func sendToIfSrc(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress, dstPort: UInt16,
                            netif: NetworkInterface, srcIP: IPAddress) -> LWIPError {
        return sendToIfSrcChksum(pcb, pbuf: pbuf, dstIP: dstIP, dstPort: dstPort,
                                 netif: netif, srcIP: srcIP, haveChecksum: false, checksum: 0)
    }

    /// Send a UDP datagram via a specific network interface with a specific source IP address
    /// and a pre-computed partial checksum.
    ///
    /// This is the most flexible send variant with checksum-on-copy support. When the
    /// application has already computed the checksum over the payload (e.g., for checksum
    /// offloading), it can pass that partial result here to avoid recomputing it.
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB.
    ///   - pbuf: The payload data to send.
    ///   - dstIP: Destination IP address.
    ///   - dstPort: Destination port.
    ///   - netif: The outgoing network interface (or nil).
    ///   - srcIP: Source IP address to use.
    ///   - haveChecksum: If true, `checksum` contains a pre-computed partial checksum over the payload.
    ///   - checksum: Pre-computed partial checksum (only used when `haveChecksum` is true).
    /// - Returns: `.ok` on success, or an error code.
    public func sendToIfSrcChksum(_ pcb: UDPControlBlock, pbuf: Pbuf, dstIP: IPAddress,
                                  dstPort: UInt16, netif: NetworkInterface?, srcIP: IPAddress,
                                  haveChecksum: Bool, checksum: UInt16) -> LWIPError {
        // Broadcast permission check: if SOF_BROADCAST is not set, reject broadcasts.
        if dstIP.isV4 {
            if let nif = netif, IPDispatch.isBroadcast(dstIP, nif) {
                let opts = SocketOptions(rawValue: pcb.soOptions)
                if !opts.contains(.broadcast) {
                    return .invalidValue
                }
            }
        }

        // Auto-bind if not yet bound
        if pcb.localPort == 0 {
            let err = bind(pcb, address: pcb.localIP, port: 0)
            if err != .ok { return err }
        }

        // Check for overflow when adding UDP header
        guard UInt32(pbuf.totLen) + UInt32(UDPConstants.headerLength) <= UInt32(UInt16.max) else {
            return .outOfMemory
        }

        // Try to prepend UDP header in-place within the existing pbuf
        let q: Pbuf
        let separateHeader: Bool
        if pbuf.addHeader(Int(UDPConstants.headerLength)) {
            // Header space was available in the pbuf itself
            q = pbuf
            separateHeader = false
        } else {
            // Allocate a separate header pbuf and chain it in front
            guard let headerPbuf = Pbuf.alloc(layer: .ip, length: UDPConstants.headerLength, type: .ram) else {
                return .outOfMemory
            }
            if pbuf.totLen != 0 {
                Pbuf.chain(headerPbuf, pbuf)
            }
            q = headerPbuf
            separateHeader = true
        }

        // Fill in the UDP header
        let hdr = q.payload.assumingMemoryBound(to: UInt16.self)
        hdr[0] = pcb.localPort.bigEndian        // source port
        hdr[1] = dstPort.bigEndian               // destination port
        hdr[3] = 0                               // checksum placeholder

        // Determine the IP protocol number
        let ipProto: IPProto

        if pcb.flags.contains(.udpLite) {
            // UDP-Lite: the length field carries the checksum coverage, not the datagram length
            var chksumLen = pcb.checksumLengthTransmit
            var chksumLenHeader: UInt16
            if chksumLen < UDPConstants.headerLength || chksumLen > q.totLen {
                if chksumLen != 0 {
                    // Illegal coverage length; fall back to full coverage
                }
                chksumLenHeader = 0
                chksumLen = q.totLen
            } else {
                chksumLenHeader = chksumLen
            }
            hdr[2] = chksumLenHeader.bigEndian   // coverage length (0 means full)

            // UDP-Lite checksum is mandatory (partial coverage).
            // When a pre-computed checksum is provided, compute only over the
            // UDP header and then fold in the caller's partial checksum.
            if haveChecksum {
                var udpChksum = InetChecksum.checksumPseudoPartial(
                    q, proto: IPProto.udpLite.rawValue,
                    protoLen: q.totLen, chksumLen: UDPConstants.headerLength,
                    src: srcIP, dest: dstIP
                )
                let acc = UInt32(udpChksum) &+ UInt32(~checksum)
                udpChksum = UInt16(truncatingIfNeeded: InetChecksum.foldUInt32(acc))
                hdr[3] = (udpChksum == 0) ? 0xFFFF : udpChksum
            } else {
                let chksum = InetChecksum.checksumPseudoPartial(
                    q, proto: IPProto.udpLite.rawValue,
                    protoLen: q.totLen, chksumLen: chksumLen,
                    src: srcIP, dest: dstIP
                )
                hdr[3] = (chksum == 0) ? 0xFFFF : chksum
            }

            ipProto = .udpLite
        } else {
            // Standard UDP
            hdr[2] = q.totLen.bigEndian          // total UDP datagram length

            // Checksum is mandatory for IPv6, optional for IPv4
            if dstIP.isV6 || !pcb.flags.contains(.noChecksum) {
                if haveChecksum {
                    // Compute checksum over only the UDP header (pseudo-header + 8 bytes),
                    // then fold in the caller's pre-computed payload checksum.
                    var udpChksum = InetChecksum.checksumPseudoPartial(
                        q, proto: IPProto.udp.rawValue,
                        protoLen: q.totLen, chksumLen: UDPConstants.headerLength,
                        src: srcIP, dest: dstIP
                    )
                    let acc = UInt32(udpChksum) &+ UInt32(~checksum)
                    udpChksum = UInt16(truncatingIfNeeded: InetChecksum.foldUInt32(acc))
                    hdr[3] = (udpChksum == 0) ? 0xFFFF : udpChksum
                } else {
                    let chksum = InetChecksum.checksumPseudo(
                        q, proto: IPProto.udp.rawValue,
                        protoLen: q.totLen,
                        src: srcIP, dest: dstIP
                    )
                    // In UDP, checksum 0x0000 means "no checksum", so use 0xFFFF instead (RFC 768)
                    hdr[3] = (chksum == 0) ? 0xFFFF : chksum
                }
            }

            ipProto = .udp
        }

        // Determine TTL: use multicast TTL for multicast destinations
        let ttl: UInt8 = dstIP.isMulticast ? pcb.multicastTTL : pcb.ttl

        // Send the datagram via the IP layer
        let err: LWIPError
        if let nif = netif {
            err = IPDispatch.outputVia(q, src: srcIP, dest: dstIP, ttl: ttl, tos: pcb.tos,
                             proto: ipProto, netif: nif)
        } else {
            err = IPDispatch.output(q, src: srcIP, dest: dstIP, ttl: ttl, tos: pcb.tos,
                           proto: ipProto)
        }

        // Update MIB2 statistics
        LWIPStats.shared.mib2.udpOutDatagrams += 1

        // If we allocated a separate header pbuf, free it now.
        // The caller still owns the original data pbuf.
        if separateHeader {
            // Dechain and free only the header pbuf.
            // chain() incremented pbuf's refcount, so freeing q will
            // just release the header portion, not the data.
            let _ = Pbuf.free(q)
        } else {
            // We prepended the header in-place; remove it so the caller's
            // pbuf is restored to its original state.
            pbuf.removeHeader(Int(UDPConstants.headerLength))
        }

        LWIPStats.shared.udp.transmitted += 1
        return err
    }

    // MARK: - Input

    /// Process an incoming UDP datagram.
    ///
    /// - Parameters:
    ///   - pbuf: The received packet (payload pointing to UDP header).
    ///   - netif: The receiving network interface.
    ///   - srcIP: Source IP address from IP layer.
    ///   - dstIP: Destination IP address from IP layer.
    public func input(pbuf: Pbuf, netif: NetworkInterface, srcIP: IPAddress, dstIP: IPAddress) {
        // Minimum length check
        guard pbuf.len >= UDPConstants.headerLength else {
            pbuf.free()
            return
        }

        // Parse UDP header
        let payload = pbuf.payload
        let hdr = payload.assumingMemoryBound(to: UInt16.self)
        let srcPort = UInt16(bigEndian: hdr[0])
        let destPort = UInt16(bigEndian: hdr[1])
        let udpLen = UInt16(bigEndian: hdr[2])
        let chksum = UInt16(bigEndian: hdr[3])

        let isBroadcast = IPDispatch.isBroadcast(dstIP, netif)

        // Demultiplex: find matching PCB
        var matchedPCB: UDPControlBlock? = nil
        var unconnectedMatch: UDPControlBlock? = nil
        var prev: UDPControlBlock? = nil

        var pcb = pcbs
        while let p = pcb {
            // Wildcard port: localPort == 0 matches any destination port.
            // This allows a single catch-all PCB (bound to port 0) to receive
            // datagrams on every port — used by TUN-based proxies that
            // intercept all UDP traffic from the network interface.
            if p.localPort == destPort || p.localPort == 0 {
                if inputLocalMatch(pcb: p, netif: netif, dstIP: dstIP, isBroadcast: isBroadcast) {
                    // Check for connected match
                    if p.flags.contains(.connected) {
                        if p.remotePort == srcPort &&
                           (p.remoteIP == .any || p.remoteIP == srcIP) {
                            // Perfect match: move to front
                            if let pr = prev {
                                pr.next = p.next
                                p.next = pcbs
                                pcbs = p
                            }
                            matchedPCB = p
                            break
                        }
                    } else if let currentMatch = unconnectedMatch {
                        if shouldPreferUnconnectedMatch(candidate: p,
                                                        over: currentMatch,
                                                        netif: netif,
                                                        dstIP: dstIP,
                                                        isBroadcast: isBroadcast) {
                            unconnectedMatch = p
                        }
                    } else {
                        unconnectedMatch = p
                    }
                }
            }
            prev = p
            pcb = p.next
        }

        if matchedPCB == nil {
            matchedPCB = unconnectedMatch
        }

        // Validate UDP datagram length
        guard udpLen >= UDPConstants.headerLength, udpLen <= pbuf.totLen else {
            LWIPStats.shared.udp.lengthErrors += 1
            LWIPStats.shared.udp.dropped += 1
            LWIPStats.shared.mib2.udpInErrors += 1
            pbuf.free()
            return
        }

        // Verify checksum (if present; respects per-netif offload flags)
        if chksum != 0 && netif.isChecksumEnabled(.checkUDP) {
            // A correct checksum will yield 0 when computed over the
            // pseudo-header + entire UDP datagram (including the checksum field).
            let isUDPLite = (matchedPCB?.flags.contains(.udpLite) ?? false)
            let proto: UInt8 = isUDPLite ? IPProto.udpLite.rawValue : IPProto.udp.rawValue

            let verified: UInt16
            if isUDPLite, matchedPCB != nil {
                // UDP-Lite: verify only over the coverage length
                var coverageLen = udpLen  // the "len" field is coverage for UDP-Lite
                if coverageLen == 0 {
                    coverageLen = pbuf.totLen  // 0 means full coverage
                }
                if coverageLen < UDPConstants.headerLength || coverageLen > pbuf.totLen {
                    LWIPStats.shared.udp.checksumErrors += 1
                    LWIPStats.shared.udp.dropped += 1
                    pbuf.free()
                    return
                }
                verified = InetChecksum.checksumPseudoPartial(
                    pbuf, proto: proto,
                    protoLen: pbuf.totLen,
                    chksumLen: coverageLen,
                    src: srcIP, dest: dstIP
                )
            } else {
                verified = InetChecksum.checksumPseudo(
                    pbuf, proto: proto,
                    protoLen: udpLen,
                    src: srcIP, dest: dstIP
                )
            }

            if verified != 0 {
                LWIPStats.shared.udp.checksumErrors += 1
                LWIPStats.shared.udp.dropped += 1
                LWIPStats.shared.mib2.udpInErrors += 1
                pbuf.free()
                return
            }
        } else if matchedPCB?.flags.contains(.udpLite) == true {
            // UDP-Lite requires a checksum; drop if missing
            LWIPStats.shared.udp.checksumErrors += 1
            LWIPStats.shared.udp.dropped += 1
            pbuf.free()
            return
        }

        if let pcb = matchedPCB {
            LWIPStats.shared.udp.received += 1
            LWIPStats.shared.mib2.udpInDatagrams += 1

            // Remove UDP header from pbuf
            _ = pbuf.removeHeader(Int(UDPConstants.headerLength))

            // Deliver to application
            if let receiveMetadataHandler = pcb.receiveMetadataHandler {
                receiveMetadataHandler(pcb, pbuf, srcIP, srcPort, dstIP)
            } else {
                pcb.receiveHandler?(pcb, pbuf, srcIP, srcPort)
            }
        } else {
            // No match found
            LWIPStats.shared.udp.dropped += 1
            LWIPStats.shared.mib2.udpNoPorts += 1

            // Send ICMP port unreachable for unicast packets only
            if !isBroadcast && !dstIP.isMulticast {
                // The pbuf payload currently points to the UDP header.
                // ICMP needs the payload pointing to the IP header, so we
                // re-add the IP header that was stripped before calling us.
                pbuf.addHeaderForce(Int(IPGlobals.shared.currentIPHeaderTotLen))

                if dstIP.isV6 {
                    ICMPv6.sendDestUnreachable(pbuf, code: .portUnreachable)
                } else {
                    ICMP.sendDestUnreachable(pbuf, type: .portUnreachable)
                }
            }
            pbuf.free()
        }
    }

    // MARK: - Address Changed

    /// Handle IP address changes on network interfaces.
    public func netifIPAddrChanged(oldAddr: IPAddress, newAddr: IPAddress?) {
        guard !oldAddr.isAnyAddress else { return }

        var pcb = pcbs
        while let p = pcb {
            let next = p.next
            if p.localIP == oldAddr {
                if let newAddr = newAddr {
                    p.localIP = newAddr
                } else {
                    remove(p)
                }
            }
            pcb = next
        }
    }

    // MARK: - Internal Helpers

    /// Check if a PCB's local address matches the incoming packet.
    private func inputLocalMatch(
        pcb: UDPControlBlock,
        netif: NetworkInterface,
        dstIP: IPAddress,
        isBroadcast: Bool
    ) -> Bool {
        // Check netif binding
        if pcb.netifIdx != 0 && pcb.netifIdx != netif.index {
            return false
        }

        // Dual-stack ANY type matches both IPv4 and IPv6.
        if pcb.localIP == .any {
            return true
        }

        guard addressVersionsMatchExactly(pcb.localIP, dstIP) else {
            return false
        }

        if isBroadcast {
            guard let pcbV4 = pcb.localIP.ipv4,
                  let dstV4 = dstIP.ipv4 else {
                return false
            }

            if pcbV4.isAny || dstV4 == .broadcast {
                return true
            }

            return pcbV4.isOnSameNetwork(as: dstV4, mask: netif.netmask)
        }

        return pcb.localIP.isAnyAddress || pcb.localIP == dstIP
    }

    /// Check if a received UDP datagram matches a specific PCB.
    ///
    /// Compares the destination port, local IP binding, and interface binding
    /// to determine if the incoming datagram should be delivered to this PCB.
    /// Used during UDP demultiplexing when given explicit local IP and port
    /// parameters rather than relying on parsed packet fields.
    ///
    /// Exposed with explicit parameters for use by higher-level demultiplexing
    /// logic.
    ///
    /// - Parameters:
    ///   - pcb: The UDP PCB to check against.
    ///   - netif: The network interface the datagram was received on.
    ///   - localIP: The destination IP address from the received datagram.
    ///   - destPort: The destination port from the received datagram.
    /// - Returns: `true` if the datagram matches this PCB.
    public func inputLocalMatch(pcb: UDPControlBlock, netif: NetworkInterface,
                                localIP: IPAddress, destPort: UInt16) -> Bool {
        // Port must match
        guard pcb.localPort == destPort else {
            return false
        }
        return inputLocalMatch(pcb: pcb,
                               netif: netif,
                               dstIP: localIP,
                               isBroadcast: IPDispatch.isBroadcast(localIP, netif))
    }

    private func bindAddressesOverlap(existing: IPAddress, requested: IPAddress) -> Bool {
        guard addressTypesOverlap(existing, requested) else {
            return false
        }

        return existing == requested || existing.isAnyAddress || requested.isAnyAddress
    }

    private func addressTypesOverlap(_ lhs: IPAddress, _ rhs: IPAddress) -> Bool {
        if lhs.isAnyType || rhs.isAnyType {
            return true
        }
        return addressVersionsMatchExactly(lhs, rhs)
    }

    private func addressVersionsMatchExactly(_ lhs: IPAddress, _ rhs: IPAddress) -> Bool {
        switch (lhs, rhs) {
        case (.v4, .v4), (.v6, .v6):
            return true
        default:
            return false
        }
    }

    private func shouldPreferUnconnectedMatch(
        candidate: UDPControlBlock,
        over current: UDPControlBlock,
        netif: NetworkInterface,
        dstIP: IPAddress,
        isBroadcast: Bool
    ) -> Bool {
        if isBroadcast,
           case .v4(let dstV4) = dstIP,
           dstV4 == .broadcast {
            let netifAddress = IPAddress.v4(netif.ipAddr)
            if current.localIP != netifAddress && candidate.localIP == netifAddress {
                return true
            }
        }

        return current.localIP.isAnyAddress && !candidate.localIP.isAnyAddress
    }

    /// Compute UDP checksum over header + data using pseudo-header.
    ///
    /// For standard UDP, computes the checksum over the entire datagram
    /// (pseudo-header + UDP header + payload) per RFC 768.
    ///
    /// For UDP-Lite, computes the checksum over only the coverage length
    /// (pseudo-header + first `coverageLen` bytes of the datagram) per RFC 3828.
    ///
    /// - Parameters:
    ///   - pbuf: The pbuf chain starting at the UDP header (header + payload already chained).
    ///   - proto: The IP protocol number (17 for UDP, 136 for UDP-Lite).
    ///   - totalLen: The total length of the UDP datagram (header + payload).
    ///   - coverageLen: For UDP-Lite, the number of bytes covered by the checksum.
    ///                  For standard UDP, pass `totalLen` (full coverage).
    ///   - srcIP: Source IP address for the pseudo-header.
    ///   - dstIP: Destination IP address for the pseudo-header.
    /// - Returns: The computed checksum. If the result is 0, the caller must
    ///            substitute 0xFFFF (since 0 means "no checksum" in UDP).
    private func computeUDPChecksum(pbuf: Pbuf, proto: UInt8,
                                    totalLen: UInt16, coverageLen: UInt16,
                                    srcIP: IPAddress, dstIP: IPAddress) -> UInt16 {
        if coverageLen < totalLen {
            // Partial coverage (UDP-Lite)
            return InetChecksum.checksumPseudoPartial(
                pbuf, proto: proto,
                protoLen: totalLen,
                chksumLen: coverageLen,
                src: srcIP, dest: dstIP
            )
        } else {
            // Full coverage (standard UDP or UDP-Lite with full coverage)
            return InetChecksum.checksumPseudo(
                pbuf, proto: proto,
                protoLen: totalLen,
                src: srcIP, dest: dstIP
            )
        }
    }
}
