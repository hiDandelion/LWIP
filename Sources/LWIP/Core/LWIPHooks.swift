//
//  LWIPHooks.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

/// Collection of optional hook functions for the lwIP stack.
///
/// Each hook defaults to `nil`, which means the stack uses its built-in
/// default behaviour.  Override individual hooks by assigning closures to
/// the global ``lwipHooks`` instance before initialising the stack.
public struct LWIPHooks: @unchecked Sendable {

    public init() {}

    // MARK: - TCP Hooks

    /// Custom TCP Initial Sequence Number generator (RFC 6528).
    ///
    /// Called when a new TCP connection is created. For RFC 6528
    /// compliance, hash the connection 4-tuple with a secret key
    /// and a monotonic counter.
    /// - Parameters: (localIP, localPort, remoteIP, remotePort)
    /// - Returns: The 32-bit ISN.
    public var tcpISN: (@Sendable (IPAddress, UInt16, IPAddress, UInt16) -> UInt32)?

    /// Inspect or modify an incoming TCP packet after PCB lookup.
    ///
    /// Called for every incoming segment that matched a PCB.
    /// Return a non-`.ok` error to drop the segment.
    /// - Parameters: (pcb, optionBytes, optionLength, pbuf)
    public var tcpInPacketPCB: (@Sendable (TCPControlBlock, [UInt8], UInt16, Pbuf) -> LWIPError)?

    /// Report additional TCP option space needed in outgoing segments.
    ///
    /// Return the *total* desired option length (including the
    /// `internalLength` already reserved by the stack).
    /// - Parameters: (pcb, internalOptionLength)
    public var tcpOutOptionLength: (@Sendable (TCPControlBlock, UInt8) -> UInt8)?

    /// Write custom TCP options into an outgoing segment.
    ///
    /// Called after the stack has written its own options.
    /// `optionOffset` is the byte offset where writing should begin.
    /// Return the new offset after writing.
    /// - Parameters: (pbuf, pcb, optionOffset)
    public var tcpOutAddOptions: (@Sendable (Pbuf, TCPControlBlock, Int) -> Int)?

    // MARK: - IPv4 Hooks

    /// Intercept or filter an incoming IPv4 packet.
    ///
    /// Return `true` to indicate the packet was consumed (the stack
    /// will not process it further). Return `false` for normal processing.
    /// - Parameters: (pbuf, inputNetif)
    public var ip4Input: (@Sendable (Pbuf, NetworkInterface) -> Bool)?

    /// Custom IPv4 routing lookup.
    ///
    /// Return a `NetworkInterface` to override the default routing
    /// decision, or `nil` to fall through to the built-in route table.
    /// - Parameter: destination address
    public var ip4Route: (@Sendable (IPv4Address) -> NetworkInterface?)?

    /// Custom IPv4 source-based routing.
    ///
    /// Like ``ip4Route`` but also receives the source address.
    /// - Parameters: (source, destination)
    public var ip4RouteSrc: (@Sendable (IPv4Address, IPv4Address) -> NetworkInterface?)?

    /// Control whether an IPv4 packet may be forwarded.
    ///
    /// Return `true` to allow forwarding, `false` to drop.
    /// Only consulted when IP forwarding is enabled.
    /// - Parameters: (source, destination)
    public var ip4CanForward: (@Sendable (IPv4Address, IPv4Address) -> Bool)?

    // MARK: - IPv6 Hooks

    /// Intercept or filter an incoming IPv6 packet.
    ///
    /// Return `true` if consumed, `false` for normal processing.
    /// - Parameters: (pbuf, inputNetif)
    public var ip6Input: (@Sendable (Pbuf, NetworkInterface) -> Bool)?

    /// Custom IPv6 routing lookup.
    ///
    /// - Parameters: (source, destination)
    public var ip6Route: (@Sendable (IPv6Address, IPv6Address) -> NetworkInterface?)?

    // MARK: - ARP / Neighbor Discovery Hooks

    /// Custom ARP gateway resolution for IPv4.
    ///
    /// Return an alternate gateway address for the given destination,
    /// or `nil` to use the default gateway.
    /// - Parameters: (netif, destination)
    public var etharpGetGateway: (@Sendable (NetworkInterface, IPv4Address) -> IPv4Address?)?

    /// Custom ND6 gateway resolution for IPv6.
    ///
    /// - Parameters: (netif, destination)
    public var nd6GetGateway: (@Sendable (NetworkInterface, IPv6Address) -> IPv6Address?)?

    // MARK: - VLAN Hooks

    /// Check whether an incoming VLAN-tagged frame should be accepted.
    ///
    /// Return `true` to accept the frame, `false` to drop it.
    /// - Parameters: (netif, ethernetHeaderBytes, vlanHeaderBytes)
    public var vlanCheck: (@Sendable (NetworkInterface, [UInt8], [UInt8]) -> Bool)?

    /// Set a VLAN tag on an outgoing Ethernet frame.
    ///
    /// Return the 16-bit VLAN TCI to insert, or a negative value to
    /// send the frame untagged.
    /// - Parameters: (netif, pbuf, srcMAC, dstMAC, etherType)
    public var vlanSet: (@Sendable (NetworkInterface, Pbuf, [UInt8], [UInt8], UInt16) -> Int32)?

    // MARK: - Memory Hooks

    /// Notification that a memory pool has free entries again.
    ///
    /// Called when a previously exhausted pool type gains capacity.
    /// - Parameter: pool type index
    public var mempAvailable: (@Sendable (Int) -> Void)?

    // MARK: - Ethernet Hooks

    /// Handle an Ethernet frame with an unknown EtherType.
    ///
    /// Return `.ok` if handled, or an error to drop the frame.
    /// - Parameters: (pbuf, netif)
    public var unknownEthProtocol: (@Sendable (Pbuf, NetworkInterface) -> LWIPError)?

    // MARK: - DHCP Hooks

    /// Append custom options to an outgoing DHCP message.
    ///
    /// Called after the stack has written its standard options.
    /// Write additional options directly into the pbuf.
    /// - Parameters: (netif, dhcpStateRawValue, messageTypeRawValue, pbuf)
    public var dhcpAppendOptions: (@Sendable (NetworkInterface, UInt8, UInt8, Pbuf) -> Void)?
}

/// Global hooks instance.
///
/// Assign custom hooks before calling ``LWIPStack/initialize(config:)``.
nonisolated(unsafe) public var lwipHooks = LWIPHooks()

// MARK: - Convenience Helpers

extension LWIPHooks {
    /// Generate a TCP ISN, falling back to random if no hook is set.
    public func generateTCPISN(localIP: IPAddress, localPort: UInt16,
                                remoteIP: IPAddress, remotePort: UInt16) -> UInt32 {
        if let hook = tcpISN {
            return hook(localIP, localPort, remoteIP, remotePort)
        }
        return UInt32.random(in: 0...UInt32.max)
    }

    /// Resolve an IPv4 route via hook, returning `nil` when no hook is set.
    public func routeIPv4(dest: IPv4Address) -> NetworkInterface? {
        return ip4Route?(dest)
    }

    /// Resolve an IPv4 route with source address via hook.
    public func routeIPv4(src: IPv4Address, dest: IPv4Address) -> NetworkInterface? {
        return ip4RouteSrc?(src, dest)
    }

    /// Resolve an IPv6 route via hook, returning `nil` when no hook is set.
    public func routeIPv6(src: IPv6Address, dest: IPv6Address) -> NetworkInterface? {
        return ip6Route?(src, dest)
    }

    /// Check if IPv4 forwarding is allowed via hook.  Returns `true` when no hook is set.
    public func canForwardIPv4(src: IPv4Address, dest: IPv4Address) -> Bool {
        return ip4CanForward?(src, dest) ?? true
    }

    /// Resolve an ARP gateway via hook.
    public func resolveARPGateway(netif: NetworkInterface, dest: IPv4Address) -> IPv4Address? {
        return etharpGetGateway?(netif, dest)
    }

    /// Resolve an ND6 gateway via hook.
    public func resolveND6Gateway(netif: NetworkInterface, dest: IPv6Address) -> IPv6Address? {
        return nd6GetGateway?(netif, dest)
    }
}
