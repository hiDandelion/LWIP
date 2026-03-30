//
//  IP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - IP protocol numbers

/// Well-known IP protocol numbers (the "protocol" field in IPv4,
/// "next header" in IPv6). Named `IPProto` to avoid collision with the
/// sockets-level `IPProtocol` enum.
public enum IPProto: UInt8, Sendable, Equatable, Hashable {
    case hopByHop   = 0
    case icmp       = 1
    case igmp       = 2
    case tcp        = 6
    case udp        = 17
    case encaps     = 41   // IPv6 encapsulation
    case routing    = 43
    case fragment   = 44
    case icmpv6     = 58
    case noNextHdr  = 59
    case destOpts   = 60
    case udpLite    = 136

    /// Construct from a raw byte, returning `nil` for unknown values.
    @inlinable
    public init?(rawByte: UInt8) {
        self.init(rawValue: rawByte)
    }
}

// MARK: - Socket options (SOF_ flags)

/// Per-PCB socket option flags, matching SOF_XXX in lwIP.
public struct SocketOptions: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Allow local address reuse.
    public static let reuseAddr  = SocketOptions(rawValue: 0x04)
    /// Keep connections alive.
    public static let keepAlive  = SocketOptions(rawValue: 0x08)
    /// Permit sending/receiving broadcast messages.
    public static let broadcast  = SocketOptions(rawValue: 0x20)

    /// Flags inherited from a listen-PCB to a connection-PCB.
    public static let inherited: SocketOptions = [.reuseAddr, .keepAlive]
}

// MARK: - IP_PCB (base protocol control block)

/// The common base fields shared by all protocol control blocks (TCP, UDP, RAW).
///
/// In C lwIP this is an `IP_PCB` macro that gets pasted into each PCB struct.
/// In Swift we model it as a protocol with stored-property requirements,
/// and also provide a concrete `IPControlBlock` struct for lightweight use.
public protocol IPPCBFields: AnyObject {
    /// Local IP address (network byte order).
    var localIP: IPAddress { get set }
    /// Remote IP address (network byte order).
    var remoteIP: IPAddress { get set }
    /// Index of the bound network interface (0 = any).
    var netifIdx: UInt8 { get set }
    /// Socket option flags (SOF_*).
    var soOptions: SocketOptions { get set }
    /// Type Of Service / Traffic Class.
    var tos: UInt8 { get set }
    /// Time To Live / Hop Limit.
    var ttl: UInt8 { get set }
}

extension IPPCBFields {
    /// Check whether a specific socket option is set.
    @inlinable
    public func hasOption(_ opt: SocketOptions) -> Bool {
        soOptions.contains(opt)
    }

    /// Set a socket option.
    @inlinable
    public func setOption(_ opt: SocketOptions) {
        soOptions.insert(opt)
    }

    /// Clear a socket option.
    @inlinable
    public func resetOption(_ opt: SocketOptions) {
        soOptions.remove(opt)
    }
}

/// A minimal concrete IP PCB for cases that only need the base fields.
public final class IPControlBlock: IPPCBFields {
    public var localIP: IPAddress = .v4(.any)
    public var remoteIP: IPAddress = .v4(.any)
    public var netifIdx: UInt8 = NetworkInterfaceConstants.noIndex
    public var soOptions: SocketOptions = []
    public var tos: UInt8 = 0
    public var ttl: UInt8 = NetworkInterfaceConstants.defaultTTL

    public init() {}
}

// MARK: - IP global state

/// Global state for the IP layer, corresponding to `struct ip_globals` in C.
///
/// During input processing, these fields record which interface received the
/// current packet, the IP header pointers, and the source/destination addresses.
/// They are set by `ip4_input`/`ip6_input` and read by transport-layer callbacks.
public final class IPGlobals {
    /// The interface that accepted the packet for the current callback.
    public var currentNetif: NetworkInterface?
    /// The interface that actually received the packet (may differ from currentNetif).
    public var currentInputNetif: NetworkInterface?
    /// Total header length of the current IP header (after this, transport header starts).
    public var currentIPHeaderTotLen: UInt16 = 0
    /// Source IP address from the current packet header.
    public var currentSrcAddr: IPAddress = .v4(.any)
    /// Destination IP address from the current packet header.
    public var currentDestAddr: IPAddress = .v4(.any)

    /// True when the current packet is IPv6.
    @inlinable
    public var currentIsV6: Bool {
        if case .v6 = currentDestAddr { return true }
        return false
    }

    /// The transport-layer protocol number from the current IP header.
    public var currentHeaderProto: UInt8 = 0

    public init() {}
}

extension IPGlobals {
    /// The singleton IP global state.
    /// Access is protected by the lwIP core lock (single-threaded TCPIP thread).
    public static nonisolated(unsafe) let shared = IPGlobals()
}

// MARK: - IP header version extraction

/// IP layer utility functions.
extension IPConstants {
    /// Extract the IP version (4 or 6) from the first nibble of a raw header.
    @inlinable
    public static func headerVersion(from payload: UnsafeRawPointer) -> UInt8 {
        payload.load(as: UInt8.self) >> 4
    }
}

// MARK: - IP Header Constants

/// Namespace for IP layer constants.
public enum IPConstants {
    /// Size of an IPv6 header in bytes.
    public static let ipv6HeaderLength: UInt16 = 40
}

// MARK: - IPv4Protocol namespace

/// Namespace for IPv4-specific free functions, converted to static methods.
public enum IPv4Protocol {
    /// IPv4 input processing.
    public static func input(_ p: Pbuf, _ inp: NetworkInterface) -> LWIPError {
        IPv4.input(p, inp: inp)
    }

    /// IPv4 output -- find the route and forward to outputVia.
    public static func output(_ p: Pbuf, src: IPv4Address?, dest: IPv4Address, ttl: UInt8, tos: UInt8, proto: IPProto) -> LWIPError {
        guard let netif = IPv4Protocol.route(src: src, dest: dest) else { return .routingError }
        return IPv4Protocol.outputVia(p, src: src, dest: dest, ttl: ttl, tos: tos, proto: proto, netif: netif)
    }

    /// IPv4 output on a specific interface.
    public static func outputVia(_ p: Pbuf, src: IPv4Address?, dest: IPv4Address?, ttl: UInt8, tos: UInt8, proto: IPProto, netif: NetworkInterface) -> LWIPError {
        guard let dest else {
            let header = p.readIPv4Header()
            return netif.output?(netif, p, header.dest) ?? .interfaceError
        }
        return IPv4.outputIf(p, src: src, dest: dest, ttl: ttl, tos: tos, proto: proto.rawValue, netif: netif)
    }

    /// IPv4 routing -- find the outgoing interface for a destination.
    public static func route(src: IPv4Address?, dest: IPv4Address) -> NetworkInterface? {
        if let source = src, !source.isAny {
            var current = NetworkInterface.list
            while let netif = current {
                if netif.isUp && netif.isLinkUp && netif.ipAddr == source {
                    if dest.isOnSameNetwork(as: netif.ipAddr, mask: netif.netmask) {
                        return netif
                    }
                    if !netif.flags.contains(.broadcast) && dest == netif.gateway {
                        return netif
                    }
                    if dest.isLoopback {
                        return netif
                    }
                }
                current = netif.next
            }
        }

        if dest.isMulticast, let multicastNetif = IPv4.defaultMulticastNetif {
            return multicastNetif
        }

        var current = NetworkInterface.list
        while let netif = current {
            if netif.isUp && netif.isLinkUp && !netif.ipAddr.isAny {
                if dest.isOnSameNetwork(as: netif.ipAddr, mask: netif.netmask) {
                    return netif
                }
                if !netif.flags.contains(.broadcast) && dest == netif.gateway {
                    return netif
                }
            }
            current = netif.next
        }

        if dest.isLoopback {
            if let defaultNetif = NetworkInterface.defaultInterface, defaultNetif.isUp {
                return defaultNetif
            }
            current = NetworkInterface.list
            while let netif = current {
                if netif.isUp {
                    return netif
                }
                current = netif.next
            }
            return nil
        }

        guard let defaultNetif = NetworkInterface.defaultInterface,
              defaultNetif.isUp,
              defaultNetif.isLinkUp,
              !defaultNetif.ipAddr.isAny else {
            return nil
        }
        return defaultNetif
    }
}

// MARK: - IPv6Protocol namespace

/// Namespace for IPv6-specific free functions, converted to static methods.
public enum IPv6Protocol {
    /// IPv6 input processing.
    public static func input(_ p: Pbuf, _ inp: NetworkInterface) -> LWIPError {
        IPv6.input(p, on: inp)
    }

    /// IPv6 output -- find the route and forward to outputVia.
    public static func output(_ p: Pbuf, src: IPv6Address?, dest: IPv6Address, ttl: UInt8, tos: UInt8, proto: IPProto) -> LWIPError {
        guard let netif = IPv6Protocol.route(src: src, dest: dest) else { return .routingError }
        return IPv6Protocol.outputVia(p, src: src, dest: dest, ttl: ttl, tos: tos, proto: proto, netif: netif)
    }

    /// IPv6 output on a specific interface.
    public static func outputVia(_ p: Pbuf, src: IPv6Address?, dest: IPv6Address, ttl: UInt8, tos: UInt8, proto: IPProto, netif: NetworkInterface) -> LWIPError {
        IPv6.outputIf(p, src: src, dest: dest, hopLimit: ttl, trafficClass: tos, nextHeader: proto.rawValue, netif: netif)
    }

    /// IPv6 routing.
    public static func route(src: IPv6Address?, dest: IPv6Address) -> NetworkInterface? {
        IPv6.route(src: src ?? .any, dest: dest)
    }

    /// Get the local IPv6 address to use when sending to `dest` via `netif`.
    public static func netifGetLocalIP(_ netif: NetworkInterface, dest: IPAddress) -> IPAddress? {
        guard case .v6(let dest6) = dest else { return nil }
        guard let source = IPv6.selectSourceAddress(on: netif, for: dest6) else {
            return nil
        }
        return .v6(source)
    }
}

// MARK: - IPDispatch namespace (dual-stack dispatcher)

/// Dual-stack IP dispatcher. Routes calls to IPv4Protocol or IPv6Protocol
/// based on the address type.
public enum IPDispatch {
    /// Dual-stack IP input dispatcher. Examines the version nibble
    /// and forwards to `IPv4Protocol.input` or `IPv6Protocol.input`.
    ///
    /// This is the function typically passed to `NetworkInterface.add` as the input callback
    /// when the interface is not Ethernet-based (no ARP layer).
    @inlinable
    public static func input(_ p: Pbuf, _ inp: NetworkInterface) -> LWIPError {
        let payload = p.payload

        let version = payload.load(as: UInt8.self) >> 4
        if version == 6 {
            return IPv6Protocol.input(p, inp)
        }
        return IPv4Protocol.input(p, inp)
    }

    /// Output an IP packet, selecting the outgoing interface by the destination address.
    ///
    /// Dispatches to `IPv4Protocol.output` or `IPv6Protocol.output` based on the destination address type.
    @inlinable
    public static func output(
        _ p: Pbuf,
        src: IPAddress?,
        dest: IPAddress,
        ttl: UInt8,
        tos: UInt8,
        proto: IPProto
    ) -> LWIPError {
        switch dest {
        case .v6(let dst6):
            let src6: IPv6Address?
            if case .v6(let s) = src { src6 = s } else { src6 = nil }
            return IPv6Protocol.output(p, src: src6, dest: dst6, ttl: ttl, tos: tos, proto: proto)
        case .v4(let dst4):
            let src4: IPv4Address?
            if case .v4(let s) = src { src4 = s } else { src4 = nil }
            return IPv4Protocol.output(p, src: src4, dest: dst4, ttl: ttl, tos: tos, proto: proto)
        case .any:
            return .invalidValue
        }
    }

    /// Output an IP packet on a specific interface.
    @inlinable
    public static func outputVia(
        _ p: Pbuf,
        src: IPAddress?,
        dest: IPAddress,
        ttl: UInt8,
        tos: UInt8,
        proto: IPProto,
        netif: NetworkInterface
    ) -> LWIPError {
        switch dest {
        case .v6(let dst6):
            let src6: IPv6Address?
            if case .v6(let s) = src { src6 = s } else { src6 = nil }
            return IPv6Protocol.outputVia(p, src: src6, dest: dst6, ttl: ttl, tos: tos, proto: proto, netif: netif)
        case .v4(let dst4):
            let src4: IPv4Address?
            if case .v4(let s) = src { src4 = s } else { src4 = nil }
            return IPv4Protocol.outputVia(p, src: src4, dest: dst4, ttl: ttl, tos: tos, proto: proto, netif: netif)
        case .any:
            return .invalidValue
        }
    }

    /// Output an IP packet that already contains a complete IP header.
    @inlinable
    public static func outputViaHdrIncl(
        _ p: Pbuf,
        src: IPAddress?,
        dest: IPAddress,
        netif: NetworkInterface
    ) -> LWIPError {
        switch dest {
        case .v6(let dst6):
            return netif.outputIPv6(p, to: dst6)
        case .v4:
            return IPv4Protocol.outputVia(p, src: nil, dest: nil, ttl: 0, tos: 0, proto: .hopByHop, netif: netif)
        case .any:
            return .invalidValue
        }
    }

    /// Find the outgoing interface for a given source/destination pair.
    /// Dispatches to `IPv4Protocol.route` or `IPv6Protocol.route` based on the destination type.
    @inlinable
    public static func route(src: IPAddress, dest: IPAddress) -> NetworkInterface? {
        switch dest {
        case .v6(let dst6):
            let src6: IPv6Address?
            if case .v6(let s) = src { src6 = s } else { src6 = nil }
            return IPv6Protocol.route(src: src6, dest: dst6)
        case .v4(let dst4):
            let src4: IPv4Address?
            if case .v4(let s) = src { src4 = s } else { src4 = nil }
            return IPv4Protocol.route(src: src4, dest: dst4)
        case .any:
            return NetworkInterface.defaultInterface
        }
    }

    /// Get the local IP address that should be used as source when sending
    /// to `dest` via `netif`.
    @inlinable
    public static func netifGetLocalIP(_ netif: NetworkInterface, dest: IPAddress) -> IPAddress? {
        switch dest {
        case .v6:
            return IPv6Protocol.netifGetLocalIP(netif, dest: dest)
        case .v4:
            return .v4(netif.ipAddr)
        case .any:
            return .v4(netif.ipAddr)
        }
    }

    /// Convert an IP address to its string representation.
    public static func addressToString(_ addr: IPAddress) -> String {
        switch addr {
        case .v4(let v4):
            return v4.description
        case .v6(let v6):
            return v6.description
        case .any:
            return "0.0.0.0"
        }
    }

    /// Parse an IP address from a string, auto-detecting the version.
    public static func addressFromString(_ str: String) -> IPAddress? {
        if str.contains(":") {
            // IPv6
            if let v6 = IPv6Address(str) {
                return .v6(v6)
            }
            return nil
        } else {
            if let v4 = IPv4Address(str) {
                return .v4(v4)
            }
            return nil
        }
    }

    /// Check if an IP address is a broadcast address on the given interface.
    @inlinable
    public static func isBroadcast(_ addr: IPAddress, _ netif: NetworkInterface?) -> Bool {
        switch addr {
        case .v4(let v4):
            if v4.addr == 0xFFFF_FFFF { return true }
            guard let n = netif else { return false }
            if n.netmask.addr == 0 { return false }
            // directed broadcast: (addr & ~mask) == (~mask)
            let hostPart = v4.addr & ~n.netmask.addr
            let allOnes = ~n.netmask.addr
            return hostPart == allOnes
        case .v6:
            return false // IPv6 does not have broadcast
        case .any:
            return false
        }
    }
}
