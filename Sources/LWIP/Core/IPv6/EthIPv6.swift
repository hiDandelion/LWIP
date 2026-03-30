//
//  EthIPv6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - EthIPv6 Module

/// Ethernet output for IPv6 packets.
public enum EthIPv6 {

    /// Ethernet type for IPv6.
    public static let etherTypeIPv6: UInt16 = 0x86DD

    /// Resolve the Ethernet destination address and output an IPv6 packet.
    ///
    /// For IPv6 multicast destinations, the corresponding Ethernet multicast
    /// address is computed directly (33:33:xx:xx:xx:xx). For unicast destinations,
    /// the ND6 module is consulted to either provide the link-layer address
    /// immediately or queue the packet for later resolution.
    ///
    /// - Parameters:
    ///   - netif: The output network interface.
    ///   - pbuf: The packet buffer containing the IPv6 packet.
    ///   - dest: The IPv6 destination address (must be properly zoned).
    /// - Returns: `.ok` on success, or the error from ND6/ethernet output.
    @inlinable
    @discardableResult
    public static func output(on netif: NetworkInterface,
                              pbuf: Pbuf,
                              dest: IPv6Address) -> LWIPError {
        // Multicast destination?
        if dest.isMulticast {
            // Map IPv6 multicast to Ethernet multicast: 33:33:xx:xx:xx:xx
            // where xx:xx:xx:xx are the last 4 bytes of the IPv6 address.
            var ethDest = EthernetAddress()
            ethDest.addr.0 = 0x33
            ethDest.addr.1 = 0x33

            let lastWord = dest.addr3 // last 32 bits of the address (network order in our struct)
            ethDest.addr.2 = UInt8((lastWord >> 24) & 0xFF)
            ethDest.addr.3 = UInt8((lastWord >> 16) & 0xFF)
            ethDest.addr.4 = UInt8((lastWord >> 8) & 0xFF)
            ethDest.addr.5 = UInt8(lastWord & 0xFF)

            return netif.ethernetOutput(pbuf, dest: ethDest, etherType: Self.etherTypeIPv6)
        }

        // Unicast: ask ND6 for the next-hop hardware address.
        let (result, hwAddrPtr) = ND6.getNextHopAddrOrQueue(on: netif, pbuf: pbuf, dest: dest)
        if result != .ok {
            return result
        }

        // If hwAddrPtr is nil, ND6 has queued the packet for later.
        guard let hwAddr = hwAddrPtr else {
            return .ok
        }

        // Build Ethernet destination address from resolved hardware address.
        var ethDest = EthernetAddress()
        ethDest.addr.0 = hwAddr[0]
        ethDest.addr.1 = hwAddr[1]
        ethDest.addr.2 = hwAddr[2]
        ethDest.addr.3 = hwAddr[3]
        ethDest.addr.4 = hwAddr[4]
        ethDest.addr.5 = hwAddr[5]

        return netif.ethernetOutput(pbuf, dest: ethDest, etherType: Self.etherTypeIPv6)
    }
}

// MARK: - Ethernet Address

/// A 6-byte Ethernet (MAC) address.
public struct EthernetAddress: Sendable {
    public var addr: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    @inlinable
    public init() {
        addr = (0, 0, 0, 0, 0, 0)
    }

    @inlinable
    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8,
                _ d: UInt8, _ e: UInt8, _ f: UInt8) {
        addr = (a, b, c, d, e, f)
    }
}
