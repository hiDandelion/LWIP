//
//  Raw.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Raw PCB flags

/// Flags for `RawControlBlock.flags`.
public struct RawFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// PCB is connected to a remote address.
    public static let connected     = RawFlags(rawValue: 0x01)
    /// PCB includes its own IP header in outgoing packets.
    public static let hdrIncl       = RawFlags(rawValue: 0x02)
    /// PCB wants multicast loopback.
    public static let multicastLoop = RawFlags(rawValue: 0x04)
}

// MARK: - Raw input result

/// Result of `RawControlBlock.handleInput` processing.
public enum RawInputState: Sendable, Equatable {
    /// No PCB matched the packet.
    case none
    /// Packet was delivered to at least one PCB, but not consumed.
    case delivered
    /// Packet was consumed (freed) by a PCB callback.
    case eaten
}

// MARK: - Raw receive callback

extension RawControlBlock {
    /// Callback invoked when a raw PCB receives a matching packet.
    ///
    /// - Parameters:
    ///   - arg: User-supplied argument (from `setReceiveHandler`).
    ///   - pcb: The PCB that matched.
    ///   - p: The received packet buffer.
    ///   - addr: The source IP address.
    /// - Returns: Non-zero if the callback consumed (freed) the packet;
    ///            zero if the packet should continue to be matched.
    public typealias ReceiveHandler = (
        _ arg: UnsafeMutableRawPointer?,
        _ pcb: RawControlBlock,
        _ p: Pbuf,
        _ addr: IPAddress
    ) -> UInt8
}

// MARK: - RawControlBlock

/// A Raw IP Protocol Control Block, allowing direct access to IP protocols
/// that may not have dedicated lwIP support (or overriding those that do).
///
/// This is a class (reference type) because PCBs live in a global linked list
/// and are referenced by multiple subsystems.
public final class RawControlBlock: IPPCBFields {

    // MARK: IP_PCB fields

    public var localIP: IPAddress = .v4(.any)
    public var remoteIP: IPAddress = .v4(.any)
    public var netifIdx: UInt8 = NetworkInterfaceConstants.noIndex
    public var soOptions: SocketOptions = []
    public var tos: UInt8 = 0
    public var ttl: UInt8 = NetworkInterfaceConstants.defaultTTL

    // MARK: Linked-list

    /// Next PCB in the global `pcbList`.
    public var next: RawControlBlock?

    // MARK: Protocol

    /// IP protocol number this PCB is bound to.
    public var protocolNumber: UInt8 = 0
    /// PCB flags.
    public var flags: RawFlags = []

    // MARK: Multicast TX options

    /// Outgoing interface for multicast (by index, 0 = unset).
    public var multicastInterfaceIndex: UInt8 = 0
    /// TTL for outgoing multicast packets.
    public var multicastTTL: UInt8 = 1

    // MARK: Receive callback

    /// The receive callback function.
    public var receiveHandler: ReceiveHandler?
    /// User-supplied argument passed to the receive callback.
    public var receiveArgument: UnsafeMutableRawPointer?

    // MARK: IPv6 checksum

    /// Offset within the payload where the checksum should be written.
    public var checksumOffset: UInt16 = 0
    /// Whether the checksum computation is requested (per RFC 3542).
    public var checksumRequired: Bool = false

    // MARK: Init

    public init() {}
}

// MARK: - Global PCB list

extension RawControlBlock {
    /// The global linked list of raw PCBs.
    /// Access is protected by the lwIP core lock (single-threaded TCPIP thread).
    static nonisolated(unsafe) var pcbList: RawControlBlock?
}

// MARK: - Static methods

extension RawControlBlock {

    /// Initialize the raw IP subsystem.
    public static func initialize() {
        pcbList = nil
    }

    // MARK: - create (raw_new)

    /// Create a new Raw PCB for the given IP protocol number.
    ///
    /// The PCB is automatically inserted at the head of the global list.
    ///
    /// - Parameter proto: IP protocol number (e.g. `IPProto.icmp.rawValue`).
    /// - Returns: A new `RawControlBlock`.
    public static func create(protocol proto: UInt8) -> RawControlBlock {
        let pcb = RawControlBlock()
        pcb.protocolNumber = proto
        pcb.ttl = NetworkInterfaceConstants.defaultTTL
        pcb.multicastTTL = NetworkInterfaceConstants.defaultTTL

        // Prepend to global list
        pcb.next = pcbList
        pcbList = pcb
        return pcb
    }

    /// Create a Raw PCB for a specific IP address type (IPv4, IPv6, or dual-stack).
    ///
    /// - Parameters:
    ///   - type: The address type (`.v4`, `.v6`, or `.any`).
    ///   - proto: IP protocol number.
    /// - Returns: A new `RawControlBlock`.
    public static func create(type: IPAddressType, protocol proto: UInt8) -> RawControlBlock {
        let pcb = create(protocol: proto)
        switch type {
        case .v4:
            pcb.localIP = .v4(.any)
            pcb.remoteIP = .v4(.any)
        case .v6:
            pcb.localIP = .v6(.any)
            pcb.remoteIP = .v6(.any)
        case .any:
            pcb.localIP = .v4(.any)
            pcb.remoteIP = .v4(.any)
        }
        return pcb
    }

    // MARK: - handleInput (raw_input)

    /// Deliver an incoming IP packet to matching Raw PCBs.
    ///
    /// Called by the IPv4/IPv6 input functions. Iterates the global PCB list
    /// and invokes receive callbacks for matching PCBs.
    ///
    /// - Parameters:
    ///   - p: The received packet (payload points to the IP header).
    ///   - inp: The interface the packet was received on.
    /// - Returns: `.none` if no PCB matched, `.delivered` if at least one
    ///            callback was invoked, `.eaten` if a callback consumed the packet.
    public static func handleInput(_ p: Pbuf, _ inp: NetworkInterface) -> RawInputState {
        var result: RawInputState = .none

        // Determine the protocol number from the IP header
        let payload = p.payload
        let version = payload.load(as: UInt8.self) >> 4
        let proto: UInt8
        if version == 6 {
            // IPv6: next header is at byte offset 6
            proto = payload.load(fromByteOffset: 6, as: UInt8.self)
        } else {
            // IPv4: protocol is at byte offset 9
            proto = payload.load(fromByteOffset: 9, as: UInt8.self)
        }

        let broadcast = IPDispatch.isBroadcast(IPGlobals.shared.currentDestAddr, IPGlobals.shared.currentNetif)

        var prev: RawControlBlock? = nil
        var pcb = pcbList

        while let current = pcb {
            let nextPCB = current.next

            // Match protocol
            guard current.protocolNumber == proto else {
                prev = current
                pcb = nextPCB
                continue
            }

            // Match local address
            guard handleInputLocalMatch(current, broadcast: broadcast) else {
                prev = current
                pcb = nextPCB
                continue
            }

            // Match connected remote address (if connected)
            if current.flags.contains(.connected) {
                guard current.remoteIP == IPGlobals.shared.currentSrcAddr else {
                    prev = current
                    pcb = nextPCB
                    continue
                }
            }

            // Invoke callback
            if let recvFn = current.receiveHandler {
                result = .delivered
                let eaten = recvFn(current.receiveArgument, current, p, IPGlobals.shared.currentSrcAddr)

                if eaten != 0 {
                    // Callback consumed the packet. Move this PCB to the front
                    // for faster matching next time.
                    if let p = prev {
                        p.next = current.next
                        current.next = pcbList
                        pcbList = current
                    }
                    return .eaten
                }
            }

            prev = current
            pcb = nextPCB
        }

        return result
    }

    /// Check if a packet matches a Raw PCB's local address binding.
    private static func handleInputLocalMatch(_ pcb: RawControlBlock, broadcast: Bool) -> Bool {
        // Check if PCB is bound to a specific interface
        if pcb.netifIdx != NetworkInterfaceConstants.noIndex {
            if let inputNetif = IPGlobals.shared.currentInputNetif {
                if pcb.netifIdx != inputNetif.index {
                    return false
                }
            } else {
                return false
            }
        }

        // Broadcast packets require the SOF_BROADCAST option (IPv4 only)
        if broadcast && !pcb.soOptions.contains(.broadcast) {
            return false
        }

        // Any-address PCB matches everything (including broadcast when permitted)
        if pcb.localIP.isAnyAddress {
            return true
        }

        // Exact match
        if pcb.localIP == IPGlobals.shared.currentDestAddr {
            return true
        }

        return false
    }

    // MARK: - handleIPAddressChange (raw_netif_ip_addr_changed)

    /// Notify all Raw PCBs that an interface's IP address has changed.
    ///
    /// PCBs bound to the old address are rebound to the new address.
    public static func handleIPAddressChange(old oldAddr: IPAddress?, new newAddr: IPAddress?) {
        guard let oldAddr = oldAddr, let newAddr = newAddr else { return }
        guard !oldAddr.isAnyAddress, !newAddr.isAnyAddress else { return }

        var pcb = pcbList
        while let current = pcb {
            if current.localIP == oldAddr {
                current.localIP = newAddr
            }
            pcb = current.next
        }
    }
}

/// The type of an IP address for `RawControlBlock.create(type:protocol:)`.
public enum IPAddressType: Sendable {
    case v4
    case v6
    case any
}

// MARK: - Instance methods

extension RawControlBlock {

    // MARK: - remove (raw_remove)

    /// Remove this Raw PCB from the global list and release it.
    public func remove() {
        if RawControlBlock.pcbList === self {
            RawControlBlock.pcbList = RawControlBlock.pcbList?.next
        } else {
            var cur = RawControlBlock.pcbList
            while let c = cur {
                if c.next === self {
                    c.next = self.next
                    break
                }
                cur = c.next
            }
        }
        self.next = nil
    }

    // MARK: - bind (raw_bind)

    /// Bind this Raw PCB to a local IP address.
    ///
    /// - Parameter address: The local address. Use `.any` to receive on all interfaces.
    /// - Returns: `.ok` on success, `.invalidValue` on invalid arguments.
    public func bind(to address: IPAddress) -> LWIPError {
        self.localIP = address
        return .ok
    }

    // MARK: - bindNetif (raw_bind_netif)

    /// Bind this Raw PCB to a specific network interface.
    ///
    /// After calling this, all packets received via this PCB are guaranteed
    /// to have arrived on the specified interface, and all outgoing packets
    /// will be sent via it.
    ///
    /// - Parameter netif: The interface, or `nil` to unbind.
    public func bindNetif(_ netif: NetworkInterface?) {
        if let n = netif {
            self.netifIdx = n.index
        } else {
            self.netifIdx = NetworkInterfaceConstants.noIndex
        }
    }

    // MARK: - connect (raw_connect)

    /// Connect this Raw PCB to a remote IP address.
    ///
    /// After connecting, `send` will use this address as the destination.
    ///
    /// - Parameter address: The remote address.
    /// - Returns: `.ok` on success.
    public func connect(to address: IPAddress) -> LWIPError {
        self.remoteIP = address
        self.flags.insert(.connected)
        return .ok
    }

    // MARK: - disconnect (raw_disconnect)

    /// Disconnect this Raw PCB, resetting the remote address.
    public func disconnect() {
        switch self.localIP {
        case .v4:
            self.remoteIP = .v4(.any)
        case .v6:
            self.remoteIP = .v6(.any)
        case .any:
            self.remoteIP = .any
        }
        self.netifIdx = NetworkInterfaceConstants.noIndex
        self.flags.remove(.connected)
    }

    // MARK: - setReceiveHandler (raw_recv)

    /// Set the receive callback and user argument for this Raw PCB.
    ///
    /// The callback is invoked for every packet that matches the PCB's
    /// protocol and address bindings.
    public func setReceiveHandler(_ recv: ReceiveHandler?, arg: UnsafeMutableRawPointer?) {
        self.receiveHandler = recv
        self.receiveArgument = arg
    }

    // MARK: - sendTo (raw_sendto)

    /// Send a raw IP packet to a specific destination address.
    ///
    /// An IP header is prepended unless `RawFlags.hdrIncl` is set.
    ///
    /// - Parameters:
    ///   - p: The payload to send.
    ///   - address: The destination IP address.
    /// - Returns: `.ok` on success, or an error code.
    public func sendTo(_ p: Pbuf, address: IPAddress) -> LWIPError {
        // Validate address version match
        guard self.localIP.versionMatches(address) else {
            return .invalidValue
        }

        // Find the outgoing interface
        var netif: NetworkInterface?

        if self.netifIdx != NetworkInterfaceConstants.noIndex {
            netif = NetworkInterface.getByIndex(self.netifIdx)
        } else {
            // Multicast: try mcast_ifindex first
            if address.isMulticast && self.multicastInterfaceIndex != 0 {
                netif = NetworkInterface.getByIndex(self.multicastInterfaceIndex)
            }
            if netif == nil {
                netif = IPDispatch.route(src: self.localIP, dest: address)
            }
        }

        guard let outNetif = netif else {
            return .routingError
        }

        // Determine source address
        let srcIP: IPAddress
        if self.localIP.isAnyAddress || self.localIP.isMulticast {
            if let localIP = IPDispatch.netifGetLocalIP(outNetif, dest: address) {
                srcIP = localIP
            } else {
                return .routingError
            }
        } else {
            srcIP = self.localIP
        }

        return sendToInterfaceSource(p, dest: address, netif: outNetif, src: srcIP)
    }

    // MARK: - sendToInterfaceSource (raw_sendto_if_src)

    /// Send a raw IP packet to a destination via a specific interface and source address.
    ///
    /// - Parameters:
    ///   - p: The payload.
    ///   - dest: Destination IP address.
    ///   - netif: The outgoing interface.
    ///   - src: Source IP address.
    /// - Returns: `.ok` on success.
    public func sendToInterfaceSource(
        _ p: Pbuf,
        dest: IPAddress,
        netif: NetworkInterface,
        src: IPAddress
    ) -> LWIPError {
        // Determine header size
        let headerSize: UInt16
        switch dest {
        case .v6: headerSize = IPConstants.ipv6HeaderLength
        case .v4: headerSize = IPv4HeaderConstants.standardLength
        case .any: headerSize = IPv4HeaderConstants.standardLength
        }

        // Handle HDRINCL: the packet already contains a full IP header
        if self.flags.contains(.hdrIncl) {
            guard p.len >= headerSize else { return .invalidValue }
            return IPDispatch.outputViaHdrIncl(p, src: src, dest: dest, netif: netif)
        }

        // Check for overflow
        guard UInt32(p.totLen) + UInt32(headerSize) <= UInt32(UInt16.max) else {
            return .outOfMemory
        }

        // Try to prepend the IP header into the existing pbuf
        var q: Pbuf
        if p.addHeader(Int(headerSize)) {
            q = p
            // Remove the header we just added -- ip_output_if will re-add it
            let _ = q.removeHeader(Int(headerSize))
        } else {
            // Need a separate header pbuf
            guard let hdrPbuf = Pbuf.alloc(layer: .ip, length: 0, type: .ram) else {
                return .outOfMemory
            }
            if p.totLen != 0 {
                Pbuf.chain(hdrPbuf, p)
            }
            q = hdrPbuf
        }

        // Multicast loop flag
        if self.flags.contains(.multicastLoop) && dest.isMulticast {
            q.flags.insert(.mcastLoop)
        }

        // Determine TTL
        let ttl: UInt8
        if dest.isMulticast {
            ttl = self.multicastTTL
        } else {
            ttl = self.ttl
        }

        let proto = IPProto(rawValue: self.protocolNumber) ?? .hopByHop
        let err = IPDispatch.outputVia(q, src: src, dest: dest, ttl: ttl, tos: self.tos, proto: proto, netif: netif)

        // Free the header pbuf if we allocated one
        if q !== p {
            let _ = Pbuf.free(q)
        }
        return err
    }

    // MARK: - send (raw_send)

    /// Send a raw IP packet to the connected remote address.
    ///
    /// The PCB must have been connected via `connect(to:)` first.
    public func send(_ p: Pbuf) -> LWIPError {
        return sendTo(p, address: self.remoteIP)
    }
}

// MARK: - Address helper extensions

extension IPAddress {
    /// True if this address version-matches another address.
    @inlinable
    public func versionMatches(_ other: IPAddress) -> Bool {
        switch (self, other) {
        case (.v4, .v4), (.v6, .v6), (.any, _), (_, .any): return true
        default: return false
        }
    }
}
