//
//  Ethernet.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Ethernet protocol constants (frame sizes).
public extension EthernetConstants {
    /// Size of an Ethernet header in bytes (without padding).
    static let frameHeaderSize: UInt16 = 14
    /// Size of a VLAN tag in bytes.
    static let vlanHeaderSize: UInt16 = 4
}

// MARK: - Link-Layer Multicast Prefixes

/// Link-layer multicast address constants.
public enum LinkLayerMulticast {
    /// IPv4 multicast OUI bytes (01:00:5E).
    public static let ipv4Byte0: UInt8 = 0x01
    public static let ipv4Byte1: UInt8 = 0x00
    public static let ipv4Byte2: UInt8 = 0x5E

    /// IPv6 multicast prefix bytes (33:33).
    public static let ipv6Byte0: UInt8 = 0x33
    public static let ipv6Byte1: UInt8 = 0x33
}

// MARK: - EthAddr (MAC address)

/// A 6-byte Ethernet MAC address.
public struct EthAddr: Equatable, Hashable, Sendable, CustomStringConvertible {
    /// Broadcast MAC address (FF:FF:FF:FF:FF:FF).
    public static let broadcast = EthAddr(addr: (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    /// Zero MAC address (00:00:00:00:00:00).
    public static let zero = EthAddr(addr: (0, 0, 0, 0, 0, 0))

    /// The six address bytes.
    public var addr: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    @inlinable
    public init(addr: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)) {
        self.addr = addr
    }

    @inlinable
    public init(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8, _ b4: UInt8, _ b5: UInt8) {
        self.addr = (b0, b1, b2, b3, b4, b5)
    }

    /// Create from a byte array (must have at least 6 elements).
    public init(bytes: [UInt8]) {
        precondition(bytes.count >= EthernetConstants.hardwareAddressLength, "Need at least 6 bytes for a MAC address")
        self.addr = (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }

    /// Access bytes as an array (convenience).
    @inlinable
    public subscript(index: Int) -> UInt8 {
        get {
            guard (0..<EthernetConstants.hardwareAddressLength).contains(index) else { return 0 }
            switch index {
            case 0: return addr.0
            case 1: return addr.1
            case 2: return addr.2
            case 3: return addr.3
            case 4: return addr.4
            case 5: return addr.5
            default: return 0
            }
        }
        set {
            guard (0..<EthernetConstants.hardwareAddressLength).contains(index) else { return }
            switch index {
            case 0: addr.0 = newValue
            case 1: addr.1 = newValue
            case 2: addr.2 = newValue
            case 3: addr.3 = newValue
            case 4: addr.4 = newValue
            case 5: addr.5 = newValue
            default: return
            }
        }
    }

    /// Convert to a byte array.
    @inlinable
    public var bytes: [UInt8] {
        [addr.0, addr.1, addr.2, addr.3, addr.4, addr.5]
    }

    public var description: String {
        String(format: "%02x:%02x:%02x:%02x:%02x:%02x",
               addr.0, addr.1, addr.2, addr.3, addr.4, addr.5)
    }

    public static func == (lhs: EthAddr, rhs: EthAddr) -> Bool {
        lhs.addr.0 == rhs.addr.0 && lhs.addr.1 == rhs.addr.1 &&
        lhs.addr.2 == rhs.addr.2 && lhs.addr.3 == rhs.addr.3 &&
        lhs.addr.4 == rhs.addr.4 && lhs.addr.5 == rhs.addr.5
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(addr.0)
        hasher.combine(addr.1)
        hasher.combine(addr.2)
        hasher.combine(addr.3)
        hasher.combine(addr.4)
        hasher.combine(addr.5)
    }
}

// MARK: - EtherType

/// IEEE 802 EtherType values.
public enum EtherType: UInt16, Sendable, Equatable, Hashable {
    case ipv4       = 0x0800
    case arp        = 0x0806
    case wol        = 0x0842   // Wake-on-LAN
    case rarp       = 0x8035
    case vlan       = 0x8100   // 802.1Q
    case ipv6       = 0x86DD
    case pppoeDiscovery = 0x8863   // PPPoE Discovery
    case pppoeSession   = 0x8864   // PPPoE Session
    case jumbo      = 0x8870   // Jumbo Frames
    case profinet   = 0x8892
    case etherCat   = 0x88A4
    case lldp       = 0x88CC
    case serviceTag = 0x88A8   // 802.1ad Service VLAN
    case ptp        = 0x88F7   // Precision Time Protocol
    case qinq       = 0x9100   // Q-in-Q

    /// The big-endian (network byte order) representation.
    @inlinable
    public var networkByteOrder: UInt16 {
        rawValue.bigEndian
    }

    /// Construct from a network-byte-order value.
    @inlinable
    public init?(networkByteOrder value: UInt16) {
        self.init(rawValue: UInt16(bigEndian: value))
    }
}

// MARK: - EthernetHeader

/// An Ethernet frame header (14 bytes, no VLAN tag).
public struct EthernetHeader {
    /// Destination MAC address.
    public var dest: EthAddr
    /// Source MAC address.
    public var src: EthAddr
    /// EtherType / length field (in network byte order).
    public var type: UInt16

    public init(dest: EthAddr, src: EthAddr, type: UInt16) {
        self.dest = dest
        self.src = src
        self.type = type
    }

    /// The EtherType as a host-byte-order enum value.
    @inlinable
    public var etherType: EtherType? {
        EtherType(rawValue: UInt16(bigEndian: type))
    }

    /// Size of this header in bytes.
    public static let size: Int = 14
}

// MARK: - VLANHeader

/// VLAN tag header (4 bytes), inserted between the Ethernet header
/// and the payload when `etherType == .vlan`.
public struct VLANHeader {
    /// Priority + VLAN ID (in network byte order).
    public var prioVID: UInt16
    /// The "real" EtherType (in network byte order).
    public var tpid: UInt16

    /// Extract the 12-bit VLAN ID.
    @inlinable
    public var vlanID: UInt16 {
        UInt16(bigEndian: prioVID) & 0x0FFF
    }

    public static let size: Int = 4
}

// MARK: - Parsing helpers

extension EthernetHeader {
    /// Read an Ethernet header from a raw payload pointer.
    @inlinable
    public static func read(from payload: UnsafeRawPointer) -> EthernetHeader {
        let bytes = payload.assumingMemoryBound(to: UInt8.self)
        let dest = EthAddr(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
        let src = EthAddr(bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11])
        let type = UInt16(bytes[12]) << 8 | UInt16(bytes[13])  // already network order
        return EthernetHeader(dest: dest, src: src, type: type.bigEndian)
    }

    /// Write this header into a raw payload buffer.
    @inlinable
    public func write(to payload: UnsafeMutableRawPointer) {
        let bytes = payload.assumingMemoryBound(to: UInt8.self)
        bytes[0]  = dest.addr.0; bytes[1]  = dest.addr.1
        bytes[2]  = dest.addr.2; bytes[3]  = dest.addr.3
        bytes[4]  = dest.addr.4; bytes[5]  = dest.addr.5
        bytes[6]  = src.addr.0;  bytes[7]  = src.addr.1
        bytes[8]  = src.addr.2;  bytes[9]  = src.addr.3
        bytes[10] = src.addr.4;  bytes[11] = src.addr.5

        let typeBE = type.bigEndian
        bytes[12] = UInt8(typeBE >> 8)
        bytes[13] = UInt8(typeBE & 0xFF)
    }
}

// MARK: - Ethernet Processing

/// Ethernet frame processing functions.
public enum Ethernet {

    /// Process a received Ethernet frame.
    public static func input(_ p: Pbuf, _ netif: NetworkInterface) -> LWIPError {
    // Need at least a full Ethernet header
    guard p.len >= EthernetConstants.frameHeaderSize else {
        _ = p.free()
        return .ok
    }
    let payloadPtr: UnsafeMutableRawPointer = p.payload

    // Parse the Ethernet header
    let ethHdr = EthernetHeader.read(from: payloadPtr)
    var type = ethHdr.type  // network byte order
    var nextHdrOffset = EthernetConstants.frameHeaderSize

    // VLAN support
    if type == EtherType.vlan.networkByteOrder {
        nextHdrOffset = EthernetConstants.frameHeaderSize + EthernetConstants.vlanHeaderSize
        guard p.len >= nextHdrOffset else {
            _ = p.free()
            return .ok
        }
        // Read the "real" EtherType from the VLAN header
        let vlanPayload = payloadPtr.advanced(by: Int(EthernetConstants.frameHeaderSize))
        let vlanBytes = vlanPayload.assumingMemoryBound(to: UInt8.self)
        // tpid is at offset 2-3 in the VLAN header
        type = UInt16(vlanBytes[2]) << 8 | UInt16(vlanBytes[3])
        type = type.bigEndian  // store as network byte order
    }

    // Record the receiving interface index
    if p.ifIndex == NetworkInterfaceConstants.noIndex {
        p.ifIndex = netif.index
    }

    // Detect multicast / broadcast in destination MAC
    if ethHdr.dest[0] & 1 != 0 {
        // Bit 0 of first byte set -> group address
        if ethHdr.dest[0] == LinkLayerMulticast.ipv4Byte0 {
            if ethHdr.dest[1] == LinkLayerMulticast.ipv4Byte1 &&
               ethHdr.dest[2] == LinkLayerMulticast.ipv4Byte2 {
                p.flags.insert(.llMulticast)
            }
        } else if ethHdr.dest[0] == LinkLayerMulticast.ipv6Byte0 &&
                  ethHdr.dest[1] == LinkLayerMulticast.ipv6Byte1 {
            p.flags.insert(.llMulticast)
        } else if ethHdr.dest == EthAddr.broadcast {
            p.flags.insert(.llBroadcast)
        }
    }

    // Dispatch on EtherType (network byte order comparison)
    switch type {
    case EtherType.ipv4.networkByteOrder:
        // IPv4 packet
        guard netif.flags.contains(.ethArp) else {
            _ = p.free()
            return .ok
        }
        guard p.removeHeader(Int(nextHdrOffset)) else {
            _ = p.free()
            return .ok
        }
        return IPv4Protocol.input(p, netif)

    case EtherType.arp.networkByteOrder:
        // ARP packet
        guard netif.flags.contains(.ethArp) else {
            _ = p.free()
            return .ok
        }
        guard p.removeHeader(Int(nextHdrOffset)) else {
            _ = p.free()
            return .ok
        }
        return EthARP.handleInput(p, netif)

    case EtherType.ipv6.networkByteOrder:
        // IPv6 packet
        guard p.len >= nextHdrOffset else {
            _ = p.free()
            return .ok
        }
        guard p.removeHeader(Int(nextHdrOffset)) else {
            _ = p.free()
            return .ok
        }
        return IPv6Protocol.input(p, netif)

    default:
        // Unknown protocol
        _ = p.free()
        return .ok
    }
    }

    // MARK: - ethernet_output

    /// Send an Ethernet frame via `netif.linkOutput`.
    public static func output(
        _ netif: NetworkInterface,
        _ p: Pbuf,
        src: EthAddr,
        dst: EthAddr,
        ethType: EtherType
    ) -> LWIPError {
    // Add space for the Ethernet header
    guard p.addHeader(Int(EthernetConstants.frameHeaderSize)) else {
        return .bufferError
    }

    let payloadPtr: UnsafeMutableRawPointer = p.payload

    // Fill in the header
    let hdr = EthernetHeader(dest: dst, src: src, type: ethType.networkByteOrder)
    hdr.write(to: payloadPtr)

    // Send via the link output function
    guard let linkOut = netif.linkOutput else {
        return .interfaceError
    }
        return linkOut(netif, p)
    }

    /// Convenience overload that uses the interface's own hardware address as source.
    @inlinable
    public static func output(
        _ netif: NetworkInterface,
        _ p: Pbuf,
        dst: EthAddr,
        ethType: EtherType
    ) -> LWIPError {
        let hw = netif.hwAddr
        let src = EthAddr(hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
        return Ethernet.output(netif, p, src: src, dst: dst, ethType: ethType)
    }
}

// MARK: - Stub for etharp_input

extension EthARP {
    /// ARP input stub -- the real implementation lives in the EthARP module.
    public static func handleInput(_ p: Pbuf, _ netif: NetworkInterface) -> LWIPError {
        EthARP.input(p, netif: netif)
        return .ok
    }
}
