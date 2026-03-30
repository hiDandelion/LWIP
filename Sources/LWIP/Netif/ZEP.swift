//
//  ZEP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// ZEP interface constants.
public extension ZEPInterface {
    /// Default UDP port for ZEP.
    static let defaultUdpPort: UInt16 = 17754
}

/// Maximum IEEE 802.15.4 data length
/// Maximum IEEE 802.15.4 data length
private let zepMaxDataLength: Int = 127

// MARK: - ZEP Header

/// ZEP (ZigBee Encapsulation Protocol) header.
/// Total size: 32 bytes.
public struct ZEPHeader {
    /// Protocol ID ("EX")
    public var protocolID: (UInt8, UInt8) = (0x45, 0x58) // 'E', 'X'
    /// Protocol version (2)
    public var protocolVersion: UInt8 = 2
    /// Packet type (1 = data, 2 = ack)
    public var type: UInt8 = 1
    /// Channel ID
    public var channelID: UInt8 = 0
    /// Device ID (network byte order)
    public var deviceID: UInt16 = 1
    /// CRC mode (1 = CRC included)
    public var crcMode: UInt8 = 1
    /// Reserved
    public var reserved1: UInt8 = 0xFF
    /// Timestamp (two 32-bit words)
    public var timestamp: (UInt32, UInt32) = (0, 0)
    /// Sequence number (network byte order)
    public var sequenceNumber: UInt32 = 0
    /// Reserved
    public var reserved2: [UInt8] = [UInt8](repeating: 0, count: 10)
    /// Length of IEEE 802.15.4 data
    public var dataLength: UInt8 = 0

    public init() {}

    /// Total header size in bytes
    public static let size: Int = 32

    /// Serialize to bytes
    public func serialize() -> [UInt8] {
        var data = [UInt8](repeating: 0, count: ZEPHeader.size)
        data[0] = protocolID.0
        data[1] = protocolID.1
        data[2] = protocolVersion
        data[3] = type
        data[4] = channelID
        data[5] = UInt8(deviceID >> 8)
        data[6] = UInt8(deviceID & 0xFF)
        data[7] = crcMode
        data[8] = reserved1
        data[9]  = UInt8(timestamp.0 >> 24)
        data[10] = UInt8((timestamp.0 >> 16) & 0xFF)
        data[11] = UInt8((timestamp.0 >> 8) & 0xFF)
        data[12] = UInt8(timestamp.0 & 0xFF)
        data[13] = UInt8(timestamp.1 >> 24)
        data[14] = UInt8((timestamp.1 >> 16) & 0xFF)
        data[15] = UInt8((timestamp.1 >> 8) & 0xFF)
        data[16] = UInt8(timestamp.1 & 0xFF)
        data[17] = UInt8(sequenceNumber >> 24)
        data[18] = UInt8((sequenceNumber >> 16) & 0xFF)
        data[19] = UInt8((sequenceNumber >> 8) & 0xFF)
        data[20] = UInt8(sequenceNumber & 0xFF)
        for i in 0..<10 {
            data[21 + i] = reserved2[i]
        }
        data[31] = dataLength
        return data
    }

    /// Deserialize from bytes
    public static func deserialize(from data: [UInt8]) -> ZEPHeader? {
        guard data.count >= size else { return nil }
        var hdr = ZEPHeader()
        hdr.protocolID = (data[0], data[1])
        hdr.protocolVersion = data[2]
        hdr.type = data[3]
        hdr.channelID = data[4]
        hdr.deviceID = UInt16(data[5]) << 8 | UInt16(data[6])
        hdr.crcMode = data[7]
        hdr.reserved1 = data[8]
        hdr.timestamp.0 = UInt32(data[9]) << 24 | UInt32(data[10]) << 16 |
                          UInt32(data[11]) << 8 | UInt32(data[12])
        hdr.timestamp.1 = UInt32(data[13]) << 24 | UInt32(data[14]) << 16 |
                          UInt32(data[15]) << 8 | UInt32(data[16])
        hdr.sequenceNumber = UInt32(data[17]) << 24 | UInt32(data[18]) << 16 |
                             UInt32(data[19]) << 8 | UInt32(data[20])
        hdr.reserved2 = Array(data[21..<31])
        hdr.dataLength = data[31]
        return hdr
    }
}

// MARK: - ZEP Init Configuration

/// Configuration for ZEP interface initialization
public struct ZEPInitConfig: @unchecked Sendable {
    /// Source IP address for UDP (nil for any)
    public var sourceIPAddress: IPAddress?
    /// Destination IP address for UDP
    public var destinationIPAddress: IPAddress?
    /// Source UDP port (0 = default)
    public var sourceUdpPort: UInt16
    /// Destination UDP port (0 = default)
    public var destinationUdpPort: UInt16
    /// Network interface to bind to (nil = any)
    public var boundNetif: NetworkInterface?
    /// IEEE 802.15.4 MAC address (6 bytes)
    public var addr: [UInt8]

    public init(
        sourceIPAddress: IPAddress? = nil,
        destinationIPAddress: IPAddress? = nil,
        sourceUdpPort: UInt16 = 0,
        destinationUdpPort: UInt16 = 0,
        boundNetif: NetworkInterface? = nil,
        addr: [UInt8] = [0, 1, 2, 3, 4, 5]
    ) {
        self.sourceIPAddress = sourceIPAddress
        self.destinationIPAddress = destinationIPAddress
        self.sourceUdpPort = sourceUdpPort
        self.destinationUdpPort = destinationUdpPort
        self.boundNetif = boundNetif
        self.addr = addr
    }
}

// MARK: - ZEP Interface State

/// Internal state for a ZEP network interface
public final class ZEPState: @unchecked Sendable {
    public var config: ZEPInitConfig
    public var udpControlBlock: UDPControlBlock?
    public var seqno: UInt32 = 0

    public init(config: ZEPInitConfig) {
        self.config = config
    }
}

// MARK: - ZEPInterface

/// ZEP (ZigBee Encapsulation Protocol) network interface.
public final class ZEPInterface: @unchecked Sendable {

    /// Interface state
    public var state: ZEPState?
    /// The network interface
    public var netif: NetworkInterface?

    public init() {}

    // MARK: - UDP Receive Handler

    /// Handle received UDP packets containing ZEP frames.
    public func udpReceive(pbuf: Pbuf, fromAddr: IPAddress, fromPort: UInt16) {
        guard Int(pbuf.totLen) >= ZEPHeader.size else {
            return
        }

        // Read ZEP header bytes from the pbuf payload
        let payloadPtr = pbuf.payload
        var headerBytes = [UInt8](repeating: 0, count: ZEPHeader.size)
        for i in 0..<ZEPHeader.size {
            headerBytes[i] = payloadPtr[i]
        }

        // Parse and validate ZEP header
        guard let zep = ZEPHeader.deserialize(from: headerBytes) else {
            return
        }

        guard zep.protocolID == (0x45, 0x58) else { return } // 'E', 'X'
        guard zep.protocolVersion == 2 else { return }
        guard zep.type == 1 else { return }
        guard zep.crcMode == 1 else { return }

        let expectedDataLen = Int(pbuf.totLen) - ZEPHeader.size
        guard Int(zep.dataLength) == expectedDataLen else { return }

        // Remove ZEP header
        _ = pbuf.removeHeader(ZEPHeader.size)

        // Remove CRC trailer (2 bytes)
        if pbuf.totLen > 2 {
            pbuf.realloc(to: pbuf.totLen - 2)
        }

        // Forward to 6LoWPAN input
        if let netif = self.netif {
            _ = netif.input?(pbuf, netif)
        }
    }

    // MARK: - Link Output

    /// Encapsulate an IEEE 802.15.4 frame in ZEP and send via UDP.
    public func linkOutput(netif: NetworkInterface, pbuf: Pbuf) -> LWIPError {
        guard Int(pbuf.totLen) <= zepMaxDataLength else { return .invalidValue }
        guard let st = state, let udp = st.udpControlBlock else { return .invalidValue }

        // Build ZEP header
        var zep = ZEPHeader()
        zep.sequenceNumber = st.seqno
        st.seqno += 1
        zep.dataLength = UInt8(pbuf.totLen)

        // Build complete frame: ZEP header + IEEE 802.15.4 data
        var frame = zep.serialize()
        let payloadPtr = pbuf.payload
        for i in 0..<Int(pbuf.totLen) {
            frame.append(payloadPtr[i])
        }

        guard let outPbuf = Pbuf.alloc(layer: .raw, length: UInt16(frame.count), type: .ram) else {
            return .outOfMemory
        }
        frame.withUnsafeBufferPointer { buf in
            _ = outPbuf.take(from: buf.baseAddress!, len: UInt16(frame.count))
        }

        // Send via UDP
        if let dstAddr = st.config.destinationIPAddress {
            return UDPGlobal.shared.sendTo(udp, pbuf: outPbuf, dstIP: dstAddr, dstPort: st.config.destinationUdpPort)
        }
        return .routingError
    }

    // MARK: - Initialization

    /// Initialize the ZEP network interface.
    public func initialize(netif: NetworkInterface, config: ZEPInitConfig) -> LWIPError {
        self.netif = netif

        var cfg = config
        if cfg.sourceUdpPort == 0 { cfg.sourceUdpPort = ZEPInterface.defaultUdpPort }
        if cfg.destinationUdpPort == 0 { cfg.destinationUdpPort = ZEPInterface.defaultUdpPort }

        let st = ZEPState(config: cfg)
        self.state = st

        // Create UDP PCB
        let udp = UDPGlobal.shared.new()
        st.udpControlBlock = udp

        // Bind
        let bindAddr = cfg.sourceIPAddress ?? .any
        let bindErr = UDPGlobal.shared.bind(udp, address: bindAddr, port: cfg.sourceUdpPort)
        guard bindErr == .ok else {
            st.udpControlBlock = nil
            return bindErr
        }

        // Set up receive callback
        UDPGlobal.shared.recv(udp) { [weak self] _, pbuf, addr, port in
            self?.udpReceive(pbuf: pbuf, fromAddr: addr, fromPort: port)
        }

        // Set up the 6LoWPAN interface part
        netif.name = (UInt8(ascii: "z"), UInt8(ascii: "p"))
        netif.hwAddrLen = 6
        var hwAddr = Array(cfg.addr.prefix(6))
        if hwAddr.count < 6 {
            hwAddr.append(contentsOf: [UInt8](repeating: 0, count: 6 - hwAddr.count))
        }
        // Ensure locally administered, unicast address
        hwAddr[0] &= 0xFC
        netif.hwAddr = hwAddr

        netif.linkOutput = { [weak self] netif, pbuf in
            self?.linkOutput(netif: netif, pbuf: pbuf) ?? .interfaceError
        }

        return .ok
    }
}
