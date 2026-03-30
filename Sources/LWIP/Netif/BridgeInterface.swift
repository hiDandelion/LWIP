//
//  BridgeInterface.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// Bridge interface constants.
public extension BridgeInterface {
    /// Maximum number of bridge ports (bit positions in port mask).
    static let maxPortsSupported: UInt8 = 7
    /// Port mask indicating flood to all ports, including the CPU port bit.
    static let floodMask: BridgePortMask = UInt16.max
}

/// FDB aging timer interval in milliseconds
private let bridgeAgeTimerMilliseconds: UInt32 = 1000

/// FDB timeout in seconds (5 minutes)
private let bridgeFDBTimeoutSeconds: UInt32 = 60 * 5

// MARK: - STP Constants

/// STP timer defaults per IEEE 802.1D
private enum STPConstants {
    /// Hello timer interval in seconds (default 2s)
    static let defaultHelloTime: UInt16 = 2
    /// Max age for BPDU information in seconds (default 20s)
    static let defaultMaxAge: UInt16 = 20
    /// Forward delay in seconds (default 15s)
    static let defaultForwardDelay: UInt16 = 15
    /// Default bridge priority (IEEE 802.1D default is 32768 = 0x8000)
    static let defaultBridgePriority: UInt16 = 0x8000
    /// Default port path cost for 100 Mbps links
    static let defaultPortPathCost: UInt32 = 19
    /// Default port priority (upper 4 bits, IEEE 802.1D default is 128 = 0x80)
    static let defaultPortPriority: UInt8 = 0x80
    /// STP timer tick interval in milliseconds (1 second)
    static let timerTickMilliseconds: UInt32 = 1000
    /// IEEE 802.1D BPDU destination multicast address (01:80:C2:00:00:00)
    static let bpduMulticastAddr = EthAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x00)
    /// LLC header for STP: DSAP=0x42, SSAP=0x42, Control=0x03
    static let llcDSAP: UInt8 = 0x42
    static let llcSSAP: UInt8 = 0x42
    static let llcControl: UInt8 = 0x03
    /// STP protocol identifier (always 0x0000)
    static let protocolIdentifier: UInt16 = 0x0000
    /// STP protocol version (0 for 802.1D)
    static let protocolVersion: UInt8 = 0x00
    /// BPDU type: Configuration BPDU
    static let bpduTypeConfig: UInt8 = 0x00
    /// BPDU type: Topology Change Notification
    static let bpduTypeTCN: UInt8 = 0x80
    /// Size of a Configuration BPDU (from protocol ID through message age/max age/hello/fwd delay)
    /// 3 (LLC) + 4 (protocol ID, version, type) + 1 (flags) + 8 (root ID) + 4 (root path cost)
    /// + 8 (bridge ID) + 2 (port ID) + 2 (message age) + 2 (max age) + 2 (hello) + 2 (fwd delay) = 38
    static let configBPDUSize: Int = 38
    /// Size of a TCN BPDU: 3 (LLC) + 4 (protocol ID, version, type) = 7
    static let tcnBPDUSize: Int = 7
    /// Ethernet frame minimum: 14 (eth header) + LLC + BPDU
    static let minConfigFrameSize: Int = 14 + configBPDUSize
    /// BPDU flag: Topology Change
    static let flagTopologyChange: UInt8 = 0x01
    /// BPDU flag: Topology Change Acknowledgment
    static let flagTopologyChangeAck: UInt8 = 0x80
}

// MARK: - STP Port State

/// IEEE 802.1D port states for Spanning Tree Protocol.
public enum STPPortState: UInt8, Sendable, CustomStringConvertible {
    /// Port is administratively disabled.
    case disabled = 0
    /// Port is blocked to prevent loops. Receives BPDUs only.
    case blocking = 1
    /// Port is transitioning. Receives and sends BPDUs but does not learn or forward.
    case listening = 2
    /// Port is learning MAC addresses but not yet forwarding data frames.
    case learning = 3
    /// Port is fully operational: forwards data frames and learns MAC addresses.
    case forwarding = 4

    public var description: String {
        switch self {
        case .disabled:   return "Disabled"
        case .blocking:   return "Blocking"
        case .listening:  return "Listening"
        case .learning:   return "Learning"
        case .forwarding: return "Forwarding"
        }
    }

    /// Whether the port should learn MAC addresses in this state.
    public var shouldLearn: Bool {
        self == .learning || self == .forwarding
    }

    /// Whether the port should forward data frames in this state.
    public var shouldForward: Bool {
        self == .forwarding
    }
}

// MARK: - STP Port Role

/// The role assigned to a port by the STP algorithm.
public enum STPPortRole: UInt8, Sendable, CustomStringConvertible {
    /// No role assigned.
    case none = 0
    /// Root port: best path to the root bridge.
    case root = 1
    /// Designated port: best path from this segment to the root.
    case designated = 2
    /// Blocked port: redundant path, blocked to prevent loops.
    case blocked = 3

    public var description: String {
        switch self {
        case .none:       return "None"
        case .root:       return "Root"
        case .designated: return "Designated"
        case .blocked:    return "Blocked"
        }
    }
}

// MARK: - Bridge Identifier

/// IEEE 802.1D Bridge Identifier: 2-byte priority + 6-byte MAC address.
/// Lower values are better (more likely to become root bridge).
public struct BridgeID: Equatable, Hashable, Sendable, CustomStringConvertible {
    /// Bridge priority (default 0x8000)
    public var priority: UInt16
    /// Bridge MAC address
    public var addr: EthAddr

    public init(priority: UInt16, addr: EthAddr) {
        self.priority = priority
        self.addr = addr
    }

    public var description: String {
        String(format: "%04x.", priority) + addr.description
    }

    /// Compare two bridge IDs. Lower is better.
    /// Priority is compared first, then MAC address byte-by-byte.
    public static func isBetter(_ lhs: BridgeID, than rhs: BridgeID) -> Bool {
        if lhs.priority != rhs.priority {
            return lhs.priority < rhs.priority
        }
        for i in 0..<6 {
            if lhs.addr[i] != rhs.addr[i] {
                return lhs.addr[i] < rhs.addr[i]
            }
        }
        return false // equal
    }

    /// Returns true if lhs is better than or equal to rhs.
    public static func isBetterOrEqual(_ lhs: BridgeID, than rhs: BridgeID) -> Bool {
        lhs == rhs || isBetter(lhs, than: rhs)
    }
}

// MARK: - Configuration BPDU

/// Parsed IEEE 802.1D Configuration Bridge Protocol Data Unit.
public struct ConfigurationBPDU: Sendable {
    /// BPDU flags (topology change, topology change ack)
    public var flags: UInt8 = 0
    /// Root bridge identifier
    public var rootBridgeID: BridgeID
    /// Cost of the path to the root bridge
    public var rootPathCost: UInt32
    /// Bridge identifier of the bridge sending this BPDU
    public var senderBridgeID: BridgeID
    /// Port identifier of the port sending this BPDU
    public var portID: UInt16
    /// Age of the BPDU information (in 1/256 seconds, we store whole seconds)
    public var messageAge: UInt16
    /// Maximum age before BPDU information is discarded
    public var maxAge: UInt16
    /// Hello timer interval
    public var helloTime: UInt16
    /// Forward delay timer value
    public var forwardDelay: UInt16

    public init(
        flags: UInt8 = 0,
        rootBridgeID: BridgeID,
        rootPathCost: UInt32,
        senderBridgeID: BridgeID,
        portID: UInt16,
        messageAge: UInt16 = 0,
        maxAge: UInt16 = 20,
        helloTime: UInt16 = 2,
        forwardDelay: UInt16 = 15
    ) {
        self.flags = flags
        self.rootBridgeID = rootBridgeID
        self.rootPathCost = rootPathCost
        self.senderBridgeID = senderBridgeID
        self.portID = portID
        self.messageAge = messageAge
        self.maxAge = maxAge
        self.helloTime = helloTime
        self.forwardDelay = forwardDelay
    }

    /// Parse a Configuration BPDU from raw bytes starting after the Ethernet header.
    /// The pointer should point to the start of the LLC header (DSAP, SSAP, Control).
    /// Returns nil if the data is too short or the protocol fields are invalid.
    public static func parse(from ptr: UnsafeRawPointer, length: Int) -> ConfigurationBPDU? {
        // Need at least LLC(3) + protocolID(2) + version(1) + type(1) + flags(1)
        // + rootID(8) + rootPathCost(4) + bridgeID(8) + portID(2) + messageAge(2)
        // + maxAge(2) + helloTime(2) + forwardDelay(2) = 38
        guard length >= STPConstants.configBPDUSize else { return nil }

        let bytes = ptr.assumingMemoryBound(to: UInt8.self)

        // Verify LLC header
        guard bytes[0] == STPConstants.llcDSAP,
              bytes[1] == STPConstants.llcSSAP,
              bytes[2] == STPConstants.llcControl else { return nil }

        // Verify protocol identifier (bytes 3-4, network byte order)
        let protocolID = UInt16(bytes[3]) << 8 | UInt16(bytes[4])
        guard protocolID == STPConstants.protocolIdentifier else { return nil }

        // Verify protocol version
        guard bytes[5] == STPConstants.protocolVersion else { return nil }

        // Check BPDU type
        let bpduType = bytes[6]
        guard bpduType == STPConstants.bpduTypeConfig else { return nil }

        let flags = bytes[7]

        // Root Bridge ID: priority (2 bytes) + MAC (6 bytes) at offset 8
        let rootPriority = UInt16(bytes[8]) << 8 | UInt16(bytes[9])
        let rootAddr = EthAddr(bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
        let rootBridgeID = BridgeID(priority: rootPriority, addr: rootAddr)

        // Root path cost (4 bytes) at offset 16
        let rootPathCost = UInt32(bytes[16]) << 24 | UInt32(bytes[17]) << 16
                         | UInt32(bytes[18]) << 8  | UInt32(bytes[19])

        // Sender Bridge ID: priority (2 bytes) + MAC (6 bytes) at offset 20
        let senderPriority = UInt16(bytes[20]) << 8 | UInt16(bytes[21])
        let senderAddr = EthAddr(bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27])
        let senderBridgeID = BridgeID(priority: senderPriority, addr: senderAddr)

        // Port ID (2 bytes) at offset 28
        let portID = UInt16(bytes[28]) << 8 | UInt16(bytes[29])

        // Message age (2 bytes) at offset 30, in 1/256 seconds -> convert to seconds
        let messageAgeRaw = UInt16(bytes[30]) << 8 | UInt16(bytes[31])
        let messageAge = messageAgeRaw / 256

        // Max age (2 bytes) at offset 32
        let maxAgeRaw = UInt16(bytes[32]) << 8 | UInt16(bytes[33])
        let maxAge = maxAgeRaw / 256

        // Hello time (2 bytes) at offset 34
        let helloTimeRaw = UInt16(bytes[34]) << 8 | UInt16(bytes[35])
        let helloTime = helloTimeRaw / 256

        // Forward delay (2 bytes) at offset 36
        let forwardDelayRaw = UInt16(bytes[36]) << 8 | UInt16(bytes[37])
        let forwardDelay = forwardDelayRaw / 256

        return ConfigurationBPDU(
            flags: flags,
            rootBridgeID: rootBridgeID,
            rootPathCost: rootPathCost,
            senderBridgeID: senderBridgeID,
            portID: portID,
            messageAge: messageAge,
            maxAge: maxAge,
            helloTime: helloTime,
            forwardDelay: forwardDelay
        )
    }

    /// Serialize this BPDU into a raw byte buffer starting at the LLC header.
    /// The caller must ensure at least `STPConstants.configBPDUSize` bytes are available.
    public func serialize(to ptr: UnsafeMutableRawPointer) {
        let bytes = ptr.assumingMemoryBound(to: UInt8.self)

        // LLC header
        bytes[0] = STPConstants.llcDSAP
        bytes[1] = STPConstants.llcSSAP
        bytes[2] = STPConstants.llcControl

        // Protocol identifier (network byte order)
        bytes[3] = UInt8(STPConstants.protocolIdentifier >> 8)
        bytes[4] = UInt8(STPConstants.protocolIdentifier & 0xFF)

        // Protocol version
        bytes[5] = STPConstants.protocolVersion

        // BPDU type
        bytes[6] = STPConstants.bpduTypeConfig

        // Flags
        bytes[7] = flags

        // Root Bridge ID
        bytes[8]  = UInt8(rootBridgeID.priority >> 8)
        bytes[9]  = UInt8(rootBridgeID.priority & 0xFF)
        bytes[10] = rootBridgeID.addr[0]
        bytes[11] = rootBridgeID.addr[1]
        bytes[12] = rootBridgeID.addr[2]
        bytes[13] = rootBridgeID.addr[3]
        bytes[14] = rootBridgeID.addr[4]
        bytes[15] = rootBridgeID.addr[5]

        // Root path cost
        bytes[16] = UInt8((rootPathCost >> 24) & 0xFF)
        bytes[17] = UInt8((rootPathCost >> 16) & 0xFF)
        bytes[18] = UInt8((rootPathCost >> 8)  & 0xFF)
        bytes[19] = UInt8(rootPathCost & 0xFF)

        // Sender Bridge ID
        bytes[20] = UInt8(senderBridgeID.priority >> 8)
        bytes[21] = UInt8(senderBridgeID.priority & 0xFF)
        bytes[22] = senderBridgeID.addr[0]
        bytes[23] = senderBridgeID.addr[1]
        bytes[24] = senderBridgeID.addr[2]
        bytes[25] = senderBridgeID.addr[3]
        bytes[26] = senderBridgeID.addr[4]
        bytes[27] = senderBridgeID.addr[5]

        // Port ID
        bytes[28] = UInt8(portID >> 8)
        bytes[29] = UInt8(portID & 0xFF)

        // Message age (in 1/256 seconds)
        let messageAgeEncoded = messageAge * 256
        bytes[30] = UInt8(messageAgeEncoded >> 8)
        bytes[31] = UInt8(messageAgeEncoded & 0xFF)

        // Max age
        let maxAgeEncoded = maxAge * 256
        bytes[32] = UInt8(maxAgeEncoded >> 8)
        bytes[33] = UInt8(maxAgeEncoded & 0xFF)

        // Hello time
        let helloTimeEncoded = helloTime * 256
        bytes[34] = UInt8(helloTimeEncoded >> 8)
        bytes[35] = UInt8(helloTimeEncoded & 0xFF)

        // Forward delay
        let forwardDelayEncoded = forwardDelay * 256
        bytes[36] = UInt8(forwardDelayEncoded >> 8)
        bytes[37] = UInt8(forwardDelayEncoded & 0xFF)
    }
}

// MARK: - STP Port Configuration

/// Per-port STP configuration and state.
public final class STPPortInfo {
    /// Current port state
    public internal(set) var state: STPPortState = .blocking
    /// Port role assigned by the STP algorithm
    public internal(set) var role: STPPortRole = .none
    /// Port path cost (lower = preferred)
    public var pathCost: UInt32 = STPConstants.defaultPortPathCost
    /// Port priority (upper 4 bits of port ID)
    public var priority: UInt8 = STPConstants.defaultPortPriority
    /// Port identifier: priority (high byte) | port number (low byte)
    public internal(set) var portID: UInt16 = 0
    /// Timer counting up toward forward delay for listening -> learning -> forwarding
    public internal(set) var forwardDelayTimer: UInt16 = 0
    /// Timer counting the age of the best BPDU received on this port
    public internal(set) var messageAgeTimer: UInt16 = 0
    /// Whether this port holds current BPDU information
    public internal(set) var holdingBPDUInfo: Bool = false
    /// The best BPDU received on this port (used for comparison)
    public internal(set) var designatedBridgeID: BridgeID = BridgeID(priority: 0xFFFF, addr: .broadcast)
    /// The designated port ID from the best BPDU
    public internal(set) var designatedPortID: UInt16 = 0xFFFF
    /// The root bridge ID from the best BPDU on this port
    public internal(set) var designatedRootID: BridgeID = BridgeID(priority: 0xFFFF, addr: .broadcast)
    /// The root path cost from the best BPDU on this port
    public internal(set) var designatedCost: UInt32 = UInt32.max
    /// Whether topology change was detected on this port
    public internal(set) var topologyChangeDetected: Bool = false

    public init() {}

    /// Compute the port ID from priority and port number
    public func computePortID(portNum: UInt8) {
        portID = UInt16(priority) << 8 | UInt16(portNum)
    }
}

// MARK: - Types

/// Port mask type: each bit represents one port
public typealias BridgePortMask = UInt16

// MARK: - Bridge Initialization Data

/// Configuration passed to BridgeInterface.init to set up the bridge
public struct BridgeInitData: Sendable {
    /// MAC address for the bridge interface
    public var ethaddr: EthAddr
    /// Maximum number of ports this bridge supports
    public var maxPorts: UInt8
    /// Maximum number of static FDB entries
    public var maxFDBStaticEntries: UInt16
    /// Maximum number of dynamic (auto-learned) FDB entries
    public var maxFDBDynamicEntries: UInt16
    /// Whether STP is enabled (default: true)
    public var stpEnabled: Bool
    /// Bridge priority for STP (default: 0x8000)
    public var bridgePriority: UInt16

    public init(
        ethaddr: EthAddr,
        maxPorts: UInt8,
        maxFDBStaticEntries: UInt16,
        maxFDBDynamicEntries: UInt16,
        stpEnabled: Bool = true,
        bridgePriority: UInt16 = 0x8000
    ) {
        self.ethaddr = ethaddr
        self.maxPorts = maxPorts
        self.maxFDBStaticEntries = maxFDBStaticEntries
        self.maxFDBDynamicEntries = maxFDBDynamicEntries
        self.stpEnabled = stpEnabled
        self.bridgePriority = bridgePriority
    }
}

// MARK: - Dynamic FDB Entry

/// A single entry in the dynamic forwarding database
public final class DynamicFDBEntry {
    public internal(set) var isUsed: Bool = false
    public internal(set) var port: UInt8 = 0
    public internal(set) var timeToLive: UInt32 = 0
    public internal(set) var addr: EthAddr = .zero

    public init() {}
}

// MARK: - Dynamic FDB (Forwarding Database)

/// Auto-learning forwarding database for MAC address -> port mappings.
/// Entries age out after `bridgeFDBTimeoutSeconds` seconds.
public final class DynamicFDB: @unchecked Sendable {
    public let maxEntries: UInt16
    public var entries: [DynamicFDBEntry]
    private let lock = NSLock()

    public init(maxEntries: UInt16) {
        self.maxEntries = maxEntries
        self.entries = (0..<Int(maxEntries)).map { _ in DynamicFDBEntry() }
    }

    /// Update or create source address entry in the dynamic FDB
    public func updateSource(addr: EthAddr, portIndex: UInt8) {
        lock.lock()
        // Search for existing entry
        for i in 0..<Int(maxEntries) {
            let e = entries[i]
            if e.isUsed && e.timeToLive > 0 && e.addr == addr {
                e.timeToLive = bridgeFDBTimeoutSeconds
                e.port = portIndex
                lock.unlock()
                return
            }
        }
        // Not found, allocate from free
        for i in 0..<Int(maxEntries) {
            let e = entries[i]
            if !e.isUsed || e.timeToLive == 0 {
                e.addr = addr
                e.timeToLive = bridgeFDBTimeoutSeconds
                e.port = portIndex
                e.isUsed = true
                lock.unlock()
                return
            }
        }
        lock.unlock()
        // No free entry - flood will be used
    }

    /// Look up the destination port(s) for a given MAC address
    public func getDestinationPorts(addr: EthAddr) -> BridgePortMask {
        lock.lock()
        for i in 0..<Int(maxEntries) {
            let e = entries[i]
            if e.isUsed && e.timeToLive > 0 && e.addr == addr {
                let ret = BridgePortMask(1 << e.port)
                lock.unlock()
                return ret
            }
        }
        lock.unlock()
        return BridgeInterface.floodMask
    }

    /// Age all entries by one second, removing expired ones
    public func ageOneSecond() {
        lock.lock()
        for i in 0..<Int(maxEntries) {
            let e = entries[i]
            if e.isUsed && e.timeToLive > 0 {
                e.timeToLive -= 1
                if e.timeToLive == 0 {
                    e.isUsed = false
                }
            }
        }
        lock.unlock()
    }
}

// MARK: - Static FDB Entry

/// A static entry in the forwarding database
public final class StaticFDBEntry {
    public internal(set) var isUsed: Bool = false
    public internal(set) var destinationPorts: BridgePortMask = 0
    public internal(set) var addr: EthAddr = .zero

    public init() {}
}

// MARK: - Bridge Port

/// Represents a port attached to the bridge
public final class BridgePort {
    /// Reference back to the parent bridge
    public weak var bridge: BridgeInterface?
    /// The network interface for this port
    public var portNetif: NetworkInterface?
    /// Port number within the bridge
    public var portNum: UInt8 = 0
    /// STP per-port state and configuration
    public let stpInfo: STPPortInfo = STPPortInfo()

    public init() {}
}

// MARK: - BridgeInterface

/// IEEE 802.1D MAC Bridge implementation with STP support.
public final class BridgeInterface: @unchecked Sendable {

    /// The bridge's own network interface (has IP address)
    public var netif: NetworkInterface?
    /// Bridge MAC address
    public let ethaddr: EthAddr
    /// Maximum number of ports
    public let maxPorts: UInt8
    /// Current number of ports
    public private(set) var numPorts: UInt8 = 0
    /// Port array
    public var ports: [BridgePort]
    /// Static FDB entries
    public var staticFDB: [StaticFDBEntry]
    /// Maximum static FDB entries
    public let maxStaticFDBEntries: UInt16
    /// Dynamic FDB
    public let dynamicFDB: DynamicFDB
    /// Lock for thread safety
    private let lock = NSLock()

    // MARK: - STP State

    /// Whether STP is enabled on this bridge
    public var stpEnabled: Bool
    /// This bridge's identifier (priority + MAC)
    public private(set) var bridgeID: BridgeID
    /// The current root bridge identifier (initially ourselves)
    public private(set) var rootBridgeID: BridgeID
    /// Cost of the path from this bridge to the root
    public private(set) var rootPathCost: UInt32 = 0
    /// The port number that is the root port (nil if we are root)
    public private(set) var rootPort: UInt8? = nil
    /// Hello timer: seconds since last Configuration BPDU was sent
    public private(set) var helloTimer: UInt16 = 0
    /// Topology Change Notification timer
    public private(set) var tcnTimer: UInt16 = 0
    /// Topology change flag (included in BPDUs)
    public private(set) var topologyChange: Bool = false
    /// Topology change detected flag
    public private(set) var topologyChangeDetected: Bool = false
    /// Configured hello time
    public var helloTime: UInt16 = STPConstants.defaultHelloTime
    /// Configured max age
    public var maxAge: UInt16 = STPConstants.defaultMaxAge
    /// Configured forward delay
    public var forwardDelay: UInt16 = STPConstants.defaultForwardDelay

    // MARK: - Initialization

    public init?(initData: BridgeInitData) {
        guard initData.maxPorts <= BridgeInterface.maxPortsSupported else { return nil }

        self.ethaddr = initData.ethaddr
        self.maxPorts = initData.maxPorts
        self.maxStaticFDBEntries = initData.maxFDBStaticEntries
        self.ports = (0..<Int(initData.maxPorts)).map { _ in BridgePort() }
        self.staticFDB = (0..<Int(initData.maxFDBStaticEntries)).map { _ in StaticFDBEntry() }
        self.dynamicFDB = DynamicFDB(maxEntries: initData.maxFDBDynamicEntries)

        // STP initialization
        self.stpEnabled = initData.stpEnabled
        self.bridgeID = BridgeID(priority: initData.bridgePriority, addr: initData.ethaddr)
        // Initially, we consider ourselves the root bridge
        self.rootBridgeID = BridgeID(priority: initData.bridgePriority, addr: initData.ethaddr)
    }

    // MARK: - Static FDB Management

    /// Add a static entry to the forwarding database.
    public func fdbAdd(addr: EthAddr, ports: BridgePortMask) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        for i in 0..<Int(maxStaticFDBEntries) {
            if !staticFDB[i].isUsed {
                staticFDB[i].isUsed = true
                staticFDB[i].destinationPorts = ports
                staticFDB[i].addr = addr
                return .ok
            }
        }
        return .outOfMemory
    }

    /// Remove a static entry from the forwarding database.
    public func fdbRemove(addr: EthAddr) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        for i in 0..<Int(maxStaticFDBEntries) {
            if staticFDB[i].isUsed && staticFDB[i].addr == addr {
                staticFDB[i].isUsed = false
                staticFDB[i].destinationPorts = 0
                staticFDB[i].addr = .zero
                return .ok
            }
        }
        return .invalidValue
    }

    // MARK: - FDB Lookup

    /// Find the forwarding port mask for a destination MAC address.
    public func findDestinationPorts(dst: EthAddr) -> BridgePortMask {
        lock.lock()
        // Check static entries first
        for i in 0..<Int(maxStaticFDBEntries) {
            if staticFDB[i].isUsed && staticFDB[i].addr == dst {
                let ret = staticFDB[i].destinationPorts
                lock.unlock()
                return ret
            }
        }
        lock.unlock()

        if dst.isGroup {
            // Group address - flood
            return BridgeInterface.floodMask
        }

        // Check dynamic FDB or fall back to flooding
        return dynamicFDB.getDestinationPorts(addr: dst)
    }

    /// Check if a MAC address belongs to the bridge or one of its ports
    public func isLocalMAC(_ addr: EthAddr) -> Bool {
        if let netif = netif {
            let hwBytes = netif.hwAddr
            if hwBytes.count >= 6 {
                let hw = EthAddr(hwBytes[0], hwBytes[1], hwBytes[2], hwBytes[3], hwBytes[4], hwBytes[5])
                if hw == addr { return true }
            }
        }
        lock.lock()
        for i in 0..<Int(numPorts) {
            if let portif = ports[i].portNetif {
                let hwBytes = portif.hwAddr
                if hwBytes.count >= 6 {
                    let hw = EthAddr(hwBytes[0], hwBytes[1], hwBytes[2], hwBytes[3], hwBytes[4], hwBytes[5])
                    if hw == addr {
                        lock.unlock()
                        return true
                    }
                }
            }
        }
        lock.unlock()
        return false
    }

    // MARK: - Port Management

    /// Add a port to the bridge.
    public func addPort(_ portif: NetworkInterface) -> LWIPError {
        guard portif.flags.contains(.ethArp) && portif.flags.contains(.ethernet) else {
            return .invalidValue
        }
        guard numPorts < maxPorts else {
            return .invalidValue
        }

        let port = ports[Int(numPorts)]
        port.portNetif = portif
        port.portNum = numPorts
        port.bridge = self

        // Initialize STP per-port state
        port.stpInfo.computePortID(portNum: numPorts)
        if stpEnabled {
            port.stpInfo.state = .blocking
            port.stpInfo.role = .none
        } else {
            port.stpInfo.state = .forwarding
            port.stpInfo.role = .designated
        }

        numPorts += 1

        // Redirect port input to bridge
        portif.input = { [weak self] pbuf, netif in
            self?.bridgeInput(pbuf: pbuf, netif: netif) ?? .invalidValue
        }

        // Remove ETHARP flag to prevent ARP on port netif
        portif.flags.remove(.ethArp)

        // Trigger STP recalculation when a new port is added
        if stpEnabled {
            stpRecalculate()
        }

        return .ok
    }

    // MARK: - Forwarding

    /// Send a pbuf to a specific port by index.
    /// When STP is enabled, only forwards on ports in the forwarding state.
    @discardableResult
    private func sendToPort(_ pbuf: Pbuf, portIndex: UInt8) -> LWIPError {
        if portIndex < BridgeInterface.maxPortsSupported {
            if portIndex < maxPorts {
                let port = ports[Int(portIndex)]
                // STP: only forward data frames on ports in the forwarding state
                if stpEnabled && !port.stpInfo.state.shouldForward {
                    return .ok
                }
                guard let portif = port.portNetif else { return .ok }
                guard let linkout = portif.linkOutput else { return .ok }
                // Prevent sending back to the receiving port
                if portif.index != pbuf.ifIndex {
                    if portif.isLinkUp {
                        return linkout(portif, pbuf)
                    }
                }
            }
        }
        return .ok
    }

    /// Send a pbuf to all ports indicated in the port mask
    @discardableResult
    private func sendToPorts(_ pbuf: Pbuf, ports: BridgePortMask) -> LWIPError {
        var retErr: LWIPError = .ok
        var mask: BridgePortMask = 1

        lock.lock()
        for i in 0..<BridgeInterface.maxPortsSupported {
            if (ports & mask) != 0 {
                let err = sendToPort(pbuf, portIndex: i)
                if err != .ok {
                    retErr = err
                }
            }
            mask <<= 1
        }
        lock.unlock()
        return retErr
    }

    // MARK: - Output

    /// Output function for the bridge's application port.
    public func bridgeOutput(netif: NetworkInterface, pbuf: Pbuf) -> LWIPError {
        guard pbuf.totLen >= 6 else {
            return .invalidValue
        }

        let payloadPtr = pbuf.payload
        let dst = EthAddr(payloadPtr[0], payloadPtr[1], payloadPtr[2],
                          payloadPtr[3], payloadPtr[4], payloadPtr[5])
        let dstports = findDestinationPorts(dst: dst)
        let err = sendToPorts(pbuf, ports: dstports)

        return err
    }

    // MARK: - Input

    /// The bridge input function. Port netifs redirect their input here.
    /// When STP is enabled, intercepts BPDUs and enforces port state restrictions.
    public func bridgeInput(pbuf: Pbuf, netif portNetif: NetworkInterface) -> LWIPError {
        // Find the port for this netif
        var portData: BridgePort?
        for i in 0..<Int(numPorts) {
            if ports[i].portNetif === portNetif {
                portData = ports[i]
                break
            }
        }
        guard let port = portData else {
            return .invalidValue
        }

        let rxIdx = portNetif.index
        pbuf.ifIndex = rxIdx

        guard pbuf.totLen >= 14 else {
            return .invalidValue
        }

        let payloadPtr = pbuf.payload
        let dst = EthAddr(payloadPtr[0], payloadPtr[1], payloadPtr[2],
                          payloadPtr[3], payloadPtr[4], payloadPtr[5])
        let src = EthAddr(payloadPtr[6], payloadPtr[7], payloadPtr[8],
                          payloadPtr[9], payloadPtr[10], payloadPtr[11])

        // STP: Check if this is a BPDU (destination is the STP multicast address).
        // BPDUs must be processed regardless of port state (except disabled).
        if stpEnabled && dst == STPConstants.bpduMulticastAddr {
            if port.stpInfo.state != .disabled {
                stpHandleBPDU(pbuf: pbuf, port: port)
            }
            pbuf.free()
            return .ok
        }

        // STP: If the port is not in a state that allows forwarding, drop the frame.
        // Disabled and blocking ports drop all data frames.
        // Listening ports also drop data frames (they only process BPDUs).
        if stpEnabled && !port.stpInfo.state.shouldForward {
            // Learning ports learn MAC addresses but still drop data frames
            if port.stpInfo.state.shouldLearn && !src.isGroup {
                dynamicFDB.updateSource(addr: src, portIndex: port.portNum)
            }
            pbuf.free()
            return .ok
        }

        // Update source in FDB for non-group addresses (only in learning/forwarding)
        if !src.isGroup {
            if !stpEnabled || port.stpInfo.state.shouldLearn {
                dynamicFDB.updateSource(addr: src, portIndex: port.portNum)
            }
        }

        if dst.isGroup {
            // Group address -> flood + cpu?
            let dstports = findDestinationPorts(dst: dst)
            sendToPorts(pbuf, ports: dstports)
            if (dstports & (1 << BridgeInterface.maxPortsSupported)) != 0 {
                // Forward to CPU port
                if let bridgeNetif = self.netif {
                    if let input = bridgeNetif.input {
                        _ = input(pbuf, bridgeNetif)
                    } else {
                        pbuf.free()
                    }
                } else {
                    pbuf.free()
                }
            } else {
                pbuf.free()
            }
            return .ok
        } else {
            // Unicast
            if isLocalMAC(dst) {
                // Destined for the bridge itself, send to CPU only
                if let bridgeNetif = self.netif {
                    return bridgeNetif.input?(pbuf, bridgeNetif) ?? .invalidValue
                }
                return .invalidValue
            }

            // Forward to destination port(s)
            let dstports = findDestinationPorts(dst: dst)
            sendToPorts(pbuf, ports: dstports)
            pbuf.free()
            return .ok
        }
    }

    // MARK: - Setup

    /// Initialize the bridge network interface.
    public func setupNetif(_ netif: NetworkInterface) {
        self.netif = netif
        netif.name = (UInt8(ascii: "b"), UInt8(ascii: "r"))
        netif.hwAddr = ethaddr.bytes
        netif.hwAddrLen = 6
        netif.mtu = 1500
        netif.flags.insert(.broadcast)
        netif.flags.insert(.ethArp)
        netif.flags.insert(.ethernet)
        netif.flags.insert(.linkUp)

        netif.linkOutput = { [weak self] netif, pbuf in
            self?.bridgeOutput(netif: netif, pbuf: pbuf) ?? .invalidValue
        }
    }

    // MARK: - Aging Timer

    /// Start the FDB aging timer. Should be called periodically (every 1 second).
    public func ageTimerTick() {
        dynamicFDB.ageOneSecond()
    }

    // MARK: - STP: BPDU Handling

    /// Handle an incoming BPDU on the given port.
    private func stpHandleBPDU(pbuf: Pbuf, port: BridgePort) {
        // The pbuf payload points to the Ethernet header. The LLC+BPDU starts
        // after the 14-byte Ethernet header.
        let ethHeaderSize = 14
        guard pbuf.totLen >= ethHeaderSize + STPConstants.tcnBPDUSize else { return }

        let bpduPtr = pbuf.payload.advanced(by: ethHeaderSize)
        let bpduLen = Int(pbuf.totLen) - ethHeaderSize

        let bytes = bpduPtr.assumingMemoryBound(to: UInt8.self)

        // Verify LLC header
        guard bytes[0] == STPConstants.llcDSAP,
              bytes[1] == STPConstants.llcSSAP,
              bytes[2] == STPConstants.llcControl else { return }

        // Check BPDU type (at offset 6 after LLC)
        guard bpduLen >= 7 else { return }
        let bpduType = bytes[6]

        if bpduType == STPConstants.bpduTypeTCN {
            // Topology Change Notification BPDU
            stpHandleTCN(port: port)
            return
        }

        guard bpduType == STPConstants.bpduTypeConfig else { return }

        // Parse the Configuration BPDU
        guard let bpdu = ConfigurationBPDU.parse(from: bpduPtr, length: bpduLen) else {
            return
        }

        lock.lock()
        stpProcessConfigBPDU(bpdu, on: port)
        lock.unlock()
    }

    /// Process a received Configuration BPDU on the given port.
    /// Must be called with `lock` held.
    private func stpProcessConfigBPDU(_ bpdu: ConfigurationBPDU, on port: BridgePort) {
        let stp = port.stpInfo

        // Check if the received BPDU is superior to what we know on this port.
        // A BPDU is superior if:
        // 1. It advertises a better root bridge ID, OR
        // 2. Same root but lower root path cost, OR
        // 3. Same root and cost but from a better bridge, OR
        // 4. Same root, cost, and bridge but lower port ID
        let receivedCost = bpdu.rootPathCost

        let isSuperior: Bool = {
            // Compare root bridge IDs
            if BridgeID.isBetter(bpdu.rootBridgeID, than: stp.designatedRootID) {
                return true
            }
            if bpdu.rootBridgeID != stp.designatedRootID {
                return false
            }
            // Same root - compare root path cost
            if receivedCost < stp.designatedCost {
                return true
            }
            if receivedCost > stp.designatedCost {
                return false
            }
            // Same cost - compare sender bridge ID
            if BridgeID.isBetter(bpdu.senderBridgeID, than: stp.designatedBridgeID) {
                return true
            }
            if bpdu.senderBridgeID != stp.designatedBridgeID {
                return false
            }
            // Same bridge - compare port ID
            return bpdu.portID < stp.designatedPortID
        }()

        if isSuperior {
            // Record the superior BPDU information on this port
            stp.designatedRootID = bpdu.rootBridgeID
            stp.designatedCost = receivedCost
            stp.designatedBridgeID = bpdu.senderBridgeID
            stp.designatedPortID = bpdu.portID
            stp.holdingBPDUInfo = true
            stp.messageAgeTimer = bpdu.messageAge

            // Adopt the timer values from the root bridge
            if bpdu.maxAge > 0 { self.maxAge = bpdu.maxAge }
            if bpdu.helloTime > 0 { self.helloTime = bpdu.helloTime }
            if bpdu.forwardDelay > 0 { self.forwardDelay = bpdu.forwardDelay }

            // Handle topology change flags
            if (bpdu.flags & STPConstants.flagTopologyChange) != 0 {
                topologyChange = true
            }
            if (bpdu.flags & STPConstants.flagTopologyChangeAck) != 0 {
                stp.topologyChangeDetected = false
            }

            // Recalculate STP
            stpRecalculateLocked()
        }
    }

    /// Handle a Topology Change Notification BPDU on a port.
    private func stpHandleTCN(port: BridgePort) {
        lock.lock()
        // Only the root bridge processes TCN BPDUs.
        // If we are the root, acknowledge it and set TC flag.
        if isRootBridge {
            topologyChange = true
            // Send a Configuration BPDU with the TC Ack flag on the receiving port
            stpSendConfigBPDU(
                onPort: port,
                flags: STPConstants.flagTopologyChangeAck | STPConstants.flagTopologyChange
            )
        }
        lock.unlock()
    }

    // MARK: - STP: Recalculation

    /// Whether this bridge considers itself the root bridge.
    public var isRootBridge: Bool {
        rootBridgeID == bridgeID
    }

    /// Recalculate port roles and states based on current BPDU information.
    /// Public entry point; acquires the lock.
    public func stpRecalculate() {
        lock.lock()
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Recalculate port roles and states. Must be called with `lock` held.
    private func stpRecalculateLocked() {
        guard stpEnabled else { return }

        // Step 1: Determine the root bridge and root port.
        // Start by assuming we are root.
        var bestRootID = bridgeID
        var bestRootCost: UInt32 = 0
        var bestRootPort: UInt8? = nil
        var bestRootPortID: UInt16 = UInt16.max

        for i in 0..<Int(numPorts) {
            let stp = ports[i].stpInfo
            guard stp.state != .disabled else { continue }
            guard stp.holdingBPDUInfo else { continue }

            // The effective cost through this port
            let effectiveCost = stp.designatedCost + stp.pathCost

            // Check if the information on this port indicates a better root
            let isBetter: Bool = {
                if BridgeID.isBetter(stp.designatedRootID, than: bestRootID) {
                    return true
                }
                if stp.designatedRootID != bestRootID {
                    return false
                }
                // Same root - check cost
                if effectiveCost < bestRootCost {
                    return true
                }
                if effectiveCost > bestRootCost {
                    return false
                }
                // Same cost - check sender bridge ID
                if BridgeID.isBetter(stp.designatedBridgeID, than: bridgeID) {
                    // The sender is better than us, this could be root port
                    if bestRootPort == nil {
                        return true
                    }
                    // Compare port IDs for tiebreaker
                    return stp.portID < bestRootPortID
                }
                return false
            }()

            if isBetter {
                bestRootID = stp.designatedRootID
                bestRootCost = effectiveCost
                bestRootPort = UInt8(i)
                bestRootPortID = stp.portID
            }
        }

        rootBridgeID = bestRootID
        rootPathCost = bestRootCost
        rootPort = bestRootPort

        // Step 2: Assign port roles.
        for i in 0..<Int(numPorts) {
            let port = ports[i]
            let stp = port.stpInfo
            guard stp.state != .disabled else { continue }

            if let rp = rootPort, rp == UInt8(i) {
                // This is the root port
                stp.role = .root
            } else if isRootBridge {
                // We are root: all active ports are designated
                stp.role = .designated
            } else {
                // Check if this port should be a designated port for its segment.
                // A port is designated if our information is better than what any
                // other bridge on that segment can offer.
                let ourCostToRoot = rootPathCost
                if !stp.holdingBPDUInfo {
                    // No BPDU info on this port - we are designated
                    stp.role = .designated
                } else if BridgeID.isBetter(rootBridgeID, than: stp.designatedRootID) {
                    // We know a better root
                    stp.role = .designated
                } else if rootBridgeID == stp.designatedRootID {
                    if ourCostToRoot < stp.designatedCost {
                        stp.role = .designated
                    } else if ourCostToRoot == stp.designatedCost {
                        if BridgeID.isBetterOrEqual(bridgeID, than: stp.designatedBridgeID) {
                            stp.role = .designated
                        } else {
                            stp.role = .blocked
                        }
                    } else {
                        stp.role = .blocked
                    }
                } else {
                    stp.role = .blocked
                }
            }

            // Step 3: Transition port states based on role.
            stpUpdatePortState(port)
        }
    }

    /// Update a port's state based on its assigned role.
    /// Root and designated ports transition toward forwarding.
    /// Blocked ports transition to blocking.
    private func stpUpdatePortState(_ port: BridgePort) {
        let stp = port.stpInfo
        switch stp.role {
        case .root, .designated:
            // Root and designated ports should be moving toward forwarding.
            // If currently blocking, start transition to listening.
            if stp.state == .blocking {
                stp.state = .listening
                stp.forwardDelayTimer = 0
            }
            // listening and learning transitions are driven by the timer
        case .blocked:
            // Blocked ports go to blocking state
            if stp.state == .forwarding || stp.state == .learning || stp.state == .listening {
                stp.state = .blocking
                stp.forwardDelayTimer = 0
            }
        case .none:
            break
        }
    }

    // MARK: - STP: BPDU Generation

    /// Send a Configuration BPDU on a specific port.
    /// Must be called with `lock` held when called internally.
    private func stpSendConfigBPDU(onPort port: BridgePort, flags: UInt8 = 0) {
        guard let portif = port.portNetif else { return }
        guard let linkout = portif.linkOutput else { return }
        guard portif.isLinkUp else { return }
        guard port.stpInfo.state != .disabled else { return }

        // Build a BPDU frame: Ethernet header (14) + LLC (3) + BPDU (35) = 52 bytes
        let frameSize = 14 + STPConstants.configBPDUSize
        guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(frameSize), type: .ram) else {
            return
        }

        let ptr = pbuf.payload.assumingMemoryBound(to: UInt8.self)

        // Ethernet header: destination = STP multicast, source = port MAC
        let bpduDst = STPConstants.bpduMulticastAddr
        ptr[0] = bpduDst[0]; ptr[1] = bpduDst[1]; ptr[2] = bpduDst[2]
        ptr[3] = bpduDst[3]; ptr[4] = bpduDst[4]; ptr[5] = bpduDst[5]

        let hwAddr = portif.hwAddr
        ptr[6]  = hwAddr[0]; ptr[7]  = hwAddr[1]; ptr[8]  = hwAddr[2]
        ptr[9]  = hwAddr[3]; ptr[10] = hwAddr[4]; ptr[11] = hwAddr[5]

        // EtherType/Length: for 802.3 frames, this is the payload length
        let payloadLen = UInt16(STPConstants.configBPDUSize)
        ptr[12] = UInt8(payloadLen >> 8)
        ptr[13] = UInt8(payloadLen & 0xFF)

        // Build BPDU flags
        var bpduFlags = flags
        if topologyChange {
            bpduFlags |= STPConstants.flagTopologyChange
        }

        // Compute message age: for designated ports, we add 1 to the current root's
        // message age. For root bridge, message age starts at 0.
        let messageAge: UInt16
        if isRootBridge {
            messageAge = 0
        } else if let rp = rootPort {
            messageAge = ports[Int(rp)].stpInfo.messageAgeTimer + 1
        } else {
            messageAge = 0
        }

        let bpdu = ConfigurationBPDU(
            flags: bpduFlags,
            rootBridgeID: rootBridgeID,
            rootPathCost: rootPathCost,
            senderBridgeID: bridgeID,
            portID: port.stpInfo.portID,
            messageAge: messageAge,
            maxAge: maxAge,
            helloTime: helloTime,
            forwardDelay: forwardDelay
        )

        bpdu.serialize(to: pbuf.payload.advanced(by: 14))

        _ = linkout(portif, pbuf)
        pbuf.free()
    }

    /// Send Configuration BPDUs on all designated ports.
    private func stpSendConfigBPDUs() {
        for i in 0..<Int(numPorts) {
            let port = ports[i]
            if port.stpInfo.role == .designated || isRootBridge {
                if port.stpInfo.state != .disabled {
                    stpSendConfigBPDU(onPort: port)
                }
            }
        }
    }

    /// Send a Topology Change Notification BPDU on the root port.
    private func stpSendTCN() {
        guard let rp = rootPort else { return }
        let port = ports[Int(rp)]
        guard let portif = port.portNetif else { return }
        guard let linkout = portif.linkOutput else { return }
        guard portif.isLinkUp else { return }

        let frameSize = 14 + STPConstants.tcnBPDUSize
        guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(frameSize), type: .ram) else {
            return
        }

        let ptr = pbuf.payload.assumingMemoryBound(to: UInt8.self)

        // Ethernet header
        let bpduDst = STPConstants.bpduMulticastAddr
        ptr[0] = bpduDst[0]; ptr[1] = bpduDst[1]; ptr[2] = bpduDst[2]
        ptr[3] = bpduDst[3]; ptr[4] = bpduDst[4]; ptr[5] = bpduDst[5]

        let hwAddr = portif.hwAddr
        ptr[6]  = hwAddr[0]; ptr[7]  = hwAddr[1]; ptr[8]  = hwAddr[2]
        ptr[9]  = hwAddr[3]; ptr[10] = hwAddr[4]; ptr[11] = hwAddr[5]

        // Length field
        let payloadLen = UInt16(STPConstants.tcnBPDUSize)
        ptr[12] = UInt8(payloadLen >> 8)
        ptr[13] = UInt8(payloadLen & 0xFF)

        // LLC header
        ptr[14] = STPConstants.llcDSAP
        ptr[15] = STPConstants.llcSSAP
        ptr[16] = STPConstants.llcControl

        // Protocol ID
        ptr[17] = 0x00
        ptr[18] = 0x00

        // Protocol version
        ptr[19] = STPConstants.protocolVersion

        // BPDU type: TCN
        ptr[20] = STPConstants.bpduTypeTCN

        _ = linkout(portif, pbuf)
        pbuf.free()
    }

    // MARK: - STP: Timer Processing

    /// STP timer tick. Should be called once per second (alongside ageTimerTick).
    /// Drives port state transitions and periodic BPDU generation.
    public func stpTimerTick() {
        guard stpEnabled else { return }

        lock.lock()

        // Hello timer: root bridge sends BPDUs periodically
        helloTimer += 1
        if isRootBridge && helloTimer >= helloTime {
            helloTimer = 0
            stpSendConfigBPDUs()
        }

        // Process per-port timers
        for i in 0..<Int(numPorts) {
            let port = ports[i]
            let stp = port.stpInfo
            guard stp.state != .disabled else { continue }

            // Message age timer: if information ages out, recalculate
            if stp.holdingBPDUInfo {
                stp.messageAgeTimer += 1
                if stp.messageAgeTimer >= maxAge {
                    // BPDU information has expired
                    stp.holdingBPDUInfo = false
                    stp.designatedRootID = BridgeID(priority: 0xFFFF, addr: .broadcast)
                    stp.designatedCost = UInt32.max
                    stp.designatedBridgeID = BridgeID(priority: 0xFFFF, addr: .broadcast)
                    stp.designatedPortID = 0xFFFF
                    stp.messageAgeTimer = 0
                    stpRecalculateLocked()
                }
            }

            // Forward delay timer: drives listening -> learning -> forwarding transitions
            if stp.state == .listening || stp.state == .learning {
                stp.forwardDelayTimer += 1
                if stp.forwardDelayTimer >= forwardDelay {
                    stp.forwardDelayTimer = 0
                    if stp.state == .listening {
                        stp.state = .learning
                    } else if stp.state == .learning {
                        stp.state = .forwarding
                    }
                }
            }
        }

        // TCN timer: if topology change was detected and we are not root,
        // periodically send TCN BPDUs on the root port
        if topologyChangeDetected && !isRootBridge {
            tcnTimer += 1
            if tcnTimer >= helloTime {
                tcnTimer = 0
                stpSendTCN()
            }
        }

        lock.unlock()
    }

    // MARK: - STP: Configuration API

    /// Set the bridge priority and trigger STP recalculation.
    public func setBridgePriority(_ priority: UInt16) {
        lock.lock()
        bridgeID = BridgeID(priority: priority, addr: ethaddr)
        // If we were root with the old priority, we might not be anymore (or vice versa)
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Set the path cost for a specific port and trigger STP recalculation.
    public func setPortPathCost(portIndex: UInt8, cost: UInt32) {
        guard portIndex < numPorts else { return }
        lock.lock()
        ports[Int(portIndex)].stpInfo.pathCost = cost
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Set the priority for a specific port and trigger STP recalculation.
    public func setPortPriority(portIndex: UInt8, priority: UInt8) {
        guard portIndex < numPorts else { return }
        lock.lock()
        let port = ports[Int(portIndex)]
        port.stpInfo.priority = priority
        port.stpInfo.computePortID(portNum: portIndex)
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Enable or disable STP on this bridge.
    /// When disabling, all ports transition to forwarding.
    /// When enabling, all ports transition to blocking and STP begins.
    public func setStpEnabled(_ enabled: Bool) {
        lock.lock()
        stpEnabled = enabled
        if enabled {
            // Reset to initial STP state
            rootBridgeID = bridgeID
            rootPathCost = 0
            rootPort = nil
            helloTimer = 0
            for i in 0..<Int(numPorts) {
                let stp = ports[i].stpInfo
                stp.state = .blocking
                stp.role = .none
                stp.forwardDelayTimer = 0
                stp.messageAgeTimer = 0
                stp.holdingBPDUInfo = false
                stp.designatedRootID = BridgeID(priority: 0xFFFF, addr: .broadcast)
                stp.designatedCost = UInt32.max
                stp.designatedBridgeID = BridgeID(priority: 0xFFFF, addr: .broadcast)
                stp.designatedPortID = 0xFFFF
            }
            stpRecalculateLocked()
        } else {
            // All ports go to forwarding
            for i in 0..<Int(numPorts) {
                let stp = ports[i].stpInfo
                stp.state = .forwarding
                stp.role = .designated
            }
        }
        lock.unlock()
    }

    /// Set a specific port's STP state to disabled (administratively shut down).
    public func setPortDisabled(portIndex: UInt8) {
        guard portIndex < numPorts else { return }
        lock.lock()
        let stp = ports[Int(portIndex)].stpInfo
        stp.state = .disabled
        stp.role = .none
        stp.holdingBPDUInfo = false
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Re-enable a previously disabled port (starts in blocking state).
    public func setPortEnabled(portIndex: UInt8) {
        guard portIndex < numPorts else { return }
        guard stpEnabled else {
            // If STP is off, just go straight to forwarding
            ports[Int(portIndex)].stpInfo.state = .forwarding
            ports[Int(portIndex)].stpInfo.role = .designated
            return
        }
        lock.lock()
        let stp = ports[Int(portIndex)].stpInfo
        stp.state = .blocking
        stp.role = .none
        stp.forwardDelayTimer = 0
        stp.messageAgeTimer = 0
        stpRecalculateLocked()
        lock.unlock()
    }

    /// Get the current STP state for a port.
    public func portState(at portIndex: UInt8) -> STPPortState {
        guard portIndex < numPorts else { return .disabled }
        return ports[Int(portIndex)].stpInfo.state
    }

    /// Get the current STP role for a port.
    public func portRole(at portIndex: UInt8) -> STPPortRole {
        guard portIndex < numPorts else { return .none }
        return ports[Int(portIndex)].stpInfo.role
    }
}
