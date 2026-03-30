//
//  Netif.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// Namespace for network interface constants.
public enum NetworkInterfaceConstants {
    /// Maximum length of a hardware (MAC) address across all interface types.
    public static let maxHardwareAddressLength: Int = 8
    /// Size of a fully constructed netif name (2 chars + up to 3 digits + NUL).
    public static let nameSize: Int = 6
    /// Sentinel value meaning "no interface index".
    public static let noIndex: UInt8 = 0
    /// Maximum number of IPv6 addresses per interface.
    public static let ipv6AddressCount: Int = 3
    /// Default IP TTL value.
    public static let defaultTTL: UInt8 = 255
}

// MARK: - NetifFlags

/// Flags that describe the state and capabilities of a `NetworkInterface`.
/// Modeled as an `OptionSet` for bitwise composition.
public struct NetifFlags: OptionSet, Sendable, Hashable, CustomStringConvertible {
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Software flag: the interface is administratively "up".
    public static let up          = NetifFlags(rawValue: 0x01)
    /// The interface has broadcast capability.
    public static let broadcast   = NetifFlags(rawValue: 0x02)
    /// The link is physically up.
    public static let linkUp      = NetifFlags(rawValue: 0x04)
    /// The interface uses ARP (Ethernet + ARP).
    public static let ethArp      = NetifFlags(rawValue: 0x08)
    /// The interface is an Ethernet device (may not use ARP, e.g. PPPoE).
    public static let ethernet    = NetifFlags(rawValue: 0x10)
    /// The interface supports IGMP.
    public static let igmp        = NetifFlags(rawValue: 0x20)
    /// The interface supports MLDv6.
    public static let mld6        = NetifFlags(rawValue: 0x40)

    public var description: String {
        var parts: [String] = []
        if contains(.up)        { parts.append("UP") }
        if contains(.broadcast) { parts.append("BROADCAST") }
        if contains(.linkUp)    { parts.append("LINK_UP") }
        if contains(.ethArp)    { parts.append("ETHARP") }
        if contains(.ethernet)  { parts.append("ETHERNET") }
        if contains(.igmp)      { parts.append("IGMP") }
        if contains(.mld6)      { parts.append("MLD6") }
        return parts.isEmpty ? "[]" : parts.joined(separator: "|")
    }
}

// MARK: - Per-Interface Checksum Flags

/// Per-interface checksum offload flags.
/// Used to control which checksums are generated/checked in software vs. hardware.
public struct NetifChecksumFlags: OptionSet, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// Generate IP header checksum in software.
    public static let genIP      = NetifChecksumFlags(rawValue: 0x0001)
    /// Generate UDP checksum in software.
    public static let genUDP     = NetifChecksumFlags(rawValue: 0x0002)
    /// Generate TCP checksum in software.
    public static let genTCP     = NetifChecksumFlags(rawValue: 0x0004)
    /// Generate ICMP checksum in software.
    public static let genICMP    = NetifChecksumFlags(rawValue: 0x0008)
    /// Generate ICMPv6 checksum in software.
    public static let genICMP6   = NetifChecksumFlags(rawValue: 0x0010)
    /// Check IP header checksum in software.
    public static let checkIP    = NetifChecksumFlags(rawValue: 0x0100)
    /// Check UDP checksum in software.
    public static let checkUDP   = NetifChecksumFlags(rawValue: 0x0200)
    /// Check TCP checksum in software.
    public static let checkTCP   = NetifChecksumFlags(rawValue: 0x0400)
    /// Check ICMP checksum in software.
    public static let checkICMP  = NetifChecksumFlags(rawValue: 0x0800)
    /// Check ICMPv6 checksum in software.
    public static let checkICMP6 = NetifChecksumFlags(rawValue: 0x1000)
    /// Enable all checksum generation and checking in software.
    public static let enableAll  = NetifChecksumFlags(rawValue: 0xFFFF)
    /// Disable all software checksum processing (assume hardware offload).
    public static let disableAll = NetifChecksumFlags([])
}

// MARK: - MAC filter action

/// Action to pass to IGMP/MLD MAC filter callbacks.
public enum MacFilterAction: UInt8, Sendable {
    /// Delete a MAC filter entry.
    case delete = 0
    /// Add a MAC filter entry.
    case add    = 1
}


// MARK: - Callback type aliases

extension NetworkInterface {
    /// Called by the IPv4 layer when it wants to send a packet; usually `etharpOutput`.
    public typealias OutputHandler = (_ netif: NetworkInterface, _ packet: Pbuf, _ dest: IPv4Address) -> LWIPError

    /// Called by the IPv6 layer when it wants to send a packet.
    public typealias OutputIPv6Handler = (_ netif: NetworkInterface, _ packet: Pbuf, _ dest: IPv6Address) -> LWIPError

    /// Called by the Ethernet/ARP layer to send a raw Ethernet frame.
    public typealias LinkOutputHandler = (_ netif: NetworkInterface, _ packet: Pbuf) -> LWIPError

    /// Status/link change callback.
    public typealias StatusCallbackHandler = (_ netif: NetworkInterface) -> Void

    /// IGMP MAC filter callback.
    public typealias IGMPMacFilterHandler = (_ netif: NetworkInterface, _ group: IPv4Address, _ action: MacFilterAction) -> LWIPError

    /// MLD6 MAC filter callback.
    public typealias MLDMacFilterHandler = (_ netif: NetworkInterface, _ group: IPv6Address, _ action: MacFilterAction) -> LWIPError
}

// MARK: - Extended status callback

/// Reasons for extended netif status callbacks. Modeled as an OptionSet
/// so multiple reasons can be combined in a single invocation.
public struct NetifNSCReason: OptionSet, Sendable {
    public let rawValue: UInt16

    @inlinable
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let none                   = NetifNSCReason([])
    public static let netifAdded             = NetifNSCReason(rawValue: 0x0001)
    public static let netifRemoved           = NetifNSCReason(rawValue: 0x0002)
    public static let linkChanged            = NetifNSCReason(rawValue: 0x0004)
    public static let statusChanged          = NetifNSCReason(rawValue: 0x0008)
    public static let ipv4AddressChanged     = NetifNSCReason(rawValue: 0x0010)
    public static let ipv4GatewayChanged     = NetifNSCReason(rawValue: 0x0020)
    public static let ipv4NetmaskChanged     = NetifNSCReason(rawValue: 0x0040)
    public static let ipv4SettingsChanged    = NetifNSCReason(rawValue: 0x0080)
    public static let ipv6Set                = NetifNSCReason(rawValue: 0x0100)
    public static let ipv6AddrStateChanged   = NetifNSCReason(rawValue: 0x0200)
    public static let ipv4AddrValid          = NetifNSCReason(rawValue: 0x0400)
}

/// Arguments for extended status callbacks.
public enum NetifExtCallbackArgs {
    case linkChanged(state: Bool)
    case statusChanged(state: Bool)
    case ipv4Changed(oldAddress: IPAddress?, oldNetmask: IPAddress?, oldGateway: IPAddress?)
    case ipv6Set(addrIndex: Int, oldAddress: IPAddress?)
    case ipv6AddrStateChanged(addrIndex: Int, oldState: IPv6AddressState, address: IPAddress?)
    case none
}

/// Extended status callback function type.
public typealias NetworkInterfaceExtendedCallbackHandler = (_ netif: NetworkInterface, _ reason: NetifNSCReason, _ args: NetifExtCallbackArgs) -> Void

/// A node in the linked list of extended status callback listeners.
public final class NetifExtCallback {
    public var callbackFn: NetworkInterfaceExtendedCallbackHandler?
    public var next: NetifExtCallback?

    public init(callbackFn: NetworkInterfaceExtendedCallbackHandler? = nil) {
        self.callbackFn = callbackFn
    }
}

// MARK: - NetworkInterface

/// The central network interface type, corresponding to `struct netif` in lwIP.
///
/// This is a reference type (class) because:
/// - lwIP stores netifs in a singly-linked list via the `next` pointer.
/// - Many subsystems hold long-lived references to a specific netif.
/// - Callbacks capture `self` by reference.
public final class NetworkInterface {

    // MARK: Linked-list pointer

    /// Next interface in the global list. `nil` if this is the last.
    public var next: NetworkInterface?

    // MARK: IPv4 addresses

    /// IPv4 address in network byte order.
    public var ipAddr: IPv4Address = .any
    /// IPv4 netmask in network byte order.
    public var netmask: IPv4Address = .any
    /// IPv4 default gateway in network byte order.
    public var gateway: IPv4Address = .any

    // MARK: IPv6 addresses

    /// Array of IPv6 addresses for this interface.
    public var ipv6Addresses: [IPAddress]
    /// State of each IPv6 address (tentative, preferred, etc.).
    public var ipv6AddressStates: [IPv6AddressState]
    /// Remaining valid lifetime (seconds) per IPv6 address. 0 = static.
    public var ipv6AddressValidLifetime: [UInt32]
    /// Remaining preferred lifetime (seconds) per IPv6 address.
    public var ipv6AddressPreferredLifetime: [UInt32]

    // MARK: Callbacks

    /// Called by the driver to pass a received packet up the stack.
    public var input: NetifAPI.InputHandler?
    /// Called by the IPv4 layer to send a packet (usually etharp_output).
    public var output: NetworkInterface.OutputHandler?
    /// Called by the IPv6 layer to send a packet.
    public var outputIP6: NetworkInterface.OutputIPv6Handler?
    /// Called by the Ethernet layer to send a raw link-level frame.
    public var linkOutput: NetworkInterface.LinkOutputHandler?
    /// Called when the netif admin state changes (up/down).
    public var statusCallback: NetworkInterface.StatusCallbackHandler?
    /// Called when the link state changes.
    public var linkCallback: NetworkInterface.StatusCallbackHandler?
    /// Called just before the netif is removed.
    public var removeCallback: NetworkInterface.StatusCallbackHandler?

    // MARK: IGMP / MLD

    /// IGMP MAC filter function.
    public var igmpMacFilter: NetworkInterface.IGMPMacFilterHandler?

    /// MLD6 MAC filter function.
    public var mldMacFilter: NetworkInterface.MLDMacFilterHandler?

    // MARK: Driver state

    /// Opaque driver-specific state.
    public var state: UnsafeMutableRawPointer?

    // MARK: Hostname

    /// Optional hostname for this interface.
    public var hostname: String?

    // MARK: Numeric properties

    /// Maximum transfer unit (bytes).
    public var mtu: UInt16 = 0
    /// MTU for IPv6 (may be updated by Router Advertisements).
    public var mtuIPv6: UInt16 = 0
    /// Compatibility alias for `mtuIPv6`.
    public var mtu6: UInt16 {
        get { mtuIPv6 }
        set { mtuIPv6 = newValue }
    }

    /// Per-interface checksum offload flags. Controls which checksums are
    /// generated/checked in software vs. offloaded to hardware.
    public var checksumFlags: NetifChecksumFlags = .enableAll

    /// Link-level hardware address (e.g. MAC).
    public var hwAddr: [UInt8]
    /// Number of bytes actually used in `hwAddr`.
    public var hwAddrLen: UInt8 = 0

    /// Interface flags.
    public var flags: NetifFlags = []

    /// Two-character descriptive abbreviation (e.g. "en", "lo").
    public var name: (UInt8, UInt8) = (0, 0)

    /// Interface number (unique among all interfaces). Used as part of
    /// the interface index (index = num + 1) and for scope-zone IDs.
    public var num: UInt8 = 0

    /// Whether IPv6 autoconfiguration (SLAAC) is enabled.
    public var ip6AutoconfigEnabled: Bool = true

    /// Remaining Router Solicitation messages to send.
    public var routerSolicitationCount: UInt8 = 0

    // MARK: Loopback support

    /// First queued loopback packet.
    public var loopFirst: Pbuf?
    /// Last queued loopback packet.
    public var loopLast: Pbuf?
    /// Current number of pbufs on the loopback queue.
    public var loopCountCurrent: UInt16 = 0

    // MARK: SNMP / MIB-II properties

    /// Link type for SNMP ifType (RFC 1213). E.g. 6 = ethernetCsmacd.
    public var linkType: UInt8 = 6

    /// Link speed in bits/second for SNMP ifSpeed.
    public var linkSpeed: UInt32 = 0

    /// Timestamp (sysUpTime) of the last link state change.
    public var lastChange: UInt32 = 0

    /// Per-interface MIB-II traffic counters.
    public var mib2Counters: MIB2NetifCounters = MIB2NetifCounters()

    // MARK: IPv4 protocol client data (used by IPv4 modules)

    /// IGMP group list head.
    public var ipv4IgmpData: AnyObject?
    /// DHCP client state.
    public var ipv4DhcpData: AnyObject?
    /// AutoIP state.
    public var ipv4AutoipData: AnyObject?
    /// ACD linked list head.
    public var ipv4AcdList: AnyObject?

    // MARK: Transport input callbacks (set by transport modules)

    /// UDP input callback.
    public var ipv4UdpInput: ((_ p: Pbuf, _ netif: NetworkInterface) -> Void)?
    /// TCP input callback.
    public var ipv4TcpInput: ((_ p: Pbuf, _ netif: NetworkInterface) -> Void)?
    /// Loopback output callback.
    public var ipv4LoopOutput: ((_ netif: NetworkInterface, _ p: Pbuf) -> LWIPError)?
    // MARK: Init

    public init() {
        ipv6Addresses = Array(repeating: .v6(.any), count: NetworkInterfaceConstants.ipv6AddressCount)
        ipv6AddressStates = Array(repeating: .invalid, count: NetworkInterfaceConstants.ipv6AddressCount)
        ipv6AddressValidLifetime = Array(repeating: IPv6AddressLifetime.static, count: NetworkInterfaceConstants.ipv6AddressCount)
        ipv6AddressPreferredLifetime = Array(repeating: IPv6AddressLifetime.static, count: NetworkInterfaceConstants.ipv6AddressCount)
        hwAddr = Array(repeating: 0, count: NetworkInterfaceConstants.maxHardwareAddressLength)
    }
}

// MARK: - Convenience accessors

extension NetworkInterface {
    /// The interface index (1-based), matching lwIP's `netif_get_index`.
    @inlinable
    public var index: UInt8 { num &+ 1 }

    /// True when the interface is administratively up.
    @inlinable
    public var isUp: Bool { flags.contains(.up) }

    /// True when the link is physically up.
    @inlinable
    public var isLinkUp: Bool { flags.contains(.linkUp) }

    /// Check whether a specific checksum operation is enabled on this interface.
    ///
    /// Returns `true` when the corresponding flag is set in `checksumFlags`,
    /// meaning the checksum should be computed/verified in software. A `false`
    /// return means the hardware handles this checksum (offload).
    @inlinable
    public func isChecksumEnabled(_ flag: NetifChecksumFlags) -> Bool {
        checksumFlags.contains(flag)
    }

    /// Full name including the interface number (e.g. "en0").
    public var fullName: String {
        String(UnicodeScalar(name.0)) + String(UnicodeScalar(name.1)) + "\(num)"
    }

    /// Retrieve the IPv6 address at `index`.
    @inlinable
    public func ipv6Address(at index: Int) -> IPv6Address {
        guard index >= 0, index < NetworkInterfaceConstants.ipv6AddressCount else { return .any }
        if case .v6(let addr) = ipv6Addresses[index] {
            return addr
        }
        return .any
    }

    /// Retrieve the state of the IPv6 address at `index`.
    @inlinable
    public func ipv6AddressStateRaw(at index: Int) -> IPv6AddressState {
        guard index >= 0, index < NetworkInterfaceConstants.ipv6AddressCount else { return .invalid }
        return ipv6AddressStates[index]
    }
}

// MARK: - IPv6 convenience extensions for IPv6 modules

extension NetworkInterface {
    /// Number of IPv6 addresses configured on this interface.
    @inlinable
    public var ipv6AddressCount: Int { NetworkInterfaceConstants.ipv6AddressCount }

    /// Get the address state at a given index.
    @inlinable
    public func ipv6AddressState(index: Int) -> IPv6AddressState {
        ipv6AddressStateRaw(at: index)
    }

    /// Check if the address at index is valid (preferred or deprecated).
    @inlinable
    public func ipv6AddressIsValid(index: Int) -> Bool {
        ipv6AddressStateRaw(at: index).isValid
    }

    /// Check if the address at index is preferred.
    @inlinable
    public func ipv6AddressIsPreferred(index: Int) -> Bool {
        ipv6AddressStateRaw(at: index).isPreferred
    }

    /// Check if the address at index is tentative.
    @inlinable
    public func ipv6AddressIsTentative(index: Int) -> Bool {
        ipv6AddressStateRaw(at: index).isTentative
    }

    /// Check if the address at index is static.
    @inlinable
    public func ipv6AddressIsStatic(index: Int) -> Bool {
        guard index >= 0, index < NetworkInterfaceConstants.ipv6AddressCount else { return false }
        return ipv6AddressValidLifetime[index] == IPv6AddressLifetime.static
    }

    /// Set the IPv6 address state at an index.
    public func setIPv6AddressState(index: Int, state: IPv6AddressState) {
        guard index >= 0, index < NetworkInterfaceConstants.ipv6AddressCount else { return }
        ipv6AddressStates[index] = state
    }

    /// Increment the tentative count for DAD.
    public func incrementIPv6TentativeCount(index: Int) {
        guard index >= 0, index < NetworkInterfaceConstants.ipv6AddressCount else { return }
        let current = ipv6AddressStates[index]
        if current.isTentative {
            ipv6AddressStates[index] = IPv6AddressState(rawValue: current.rawValue + 1)
        }
    }

    /// Check whether this interface has a specific IPv6 address assigned.
    @inlinable
    public func hasIPv6Address(_ addr: IPv6Address) -> Bool {
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if ipv6AddressIsValid(index: i) && ipv6Address(at: i) == addr {
                return true
            }
        }
        return false
    }

    /// Output an IPv6 packet on this interface.
    @inlinable
    @discardableResult
    public func outputIPv6(_ pbuf: Pbuf, to dest: IPv6Address) -> LWIPError {
        return outputIP6?(self, pbuf, dest) ?? .interfaceError
    }

    /// Queue a packet for loopback delivery on this interface.
    ///
    /// Copies the pbuf and appends it to the loopback queue (`loopFirst`/`loopLast`).
    /// When `loopbackMaxPbufs` is configured, the enqueue is rejected if it would
    /// exceed the limit. Queued packets are later fed to `input` by `poll()`.
    @discardableResult
    public func loopOutput(_ p: Pbuf) -> LWIPError {
        let statsIf = self

        // Allocate a new pbuf large enough for the whole chain
        guard let r = Pbuf.alloc(layer: .link, length: p.totLen, type: .ram) else {
            LWIPStats.shared.link.memoryErrors += 1
            LWIPStats.shared.link.dropped += 1
            statsIf.mib2Counters.ifOutDiscards += 1
            return .outOfMemory
        }

        // Check max pbufs limit if configured
        let maxPbufs = lwipConfig.loopbackMaxPbufs
        if maxPbufs > 0 {
            let clen = r.chainLength
            let newCount = self.loopCountCurrent &+ clen
            // Overflow check or exceeds maximum
            if newCount < self.loopCountCurrent || newCount > UInt16(min(maxPbufs, 0xFFFF)) {
                let _ = Pbuf.free(r)
                LWIPStats.shared.link.memoryErrors += 1
                LWIPStats.shared.link.dropped += 1
                statsIf.mib2Counters.ifOutDiscards += 1
                return .outOfMemory
            }
            self.loopCountCurrent = newCount
        }

        // Copy the whole pbuf chain p into the single pbuf r
        let err = Pbuf.copy(r, from: p)
        guard err == .ok else {
            let _ = Pbuf.free(r)
            LWIPStats.shared.link.memoryErrors += 1
            LWIPStats.shared.link.dropped += 1
            statsIf.mib2Counters.ifOutDiscards += 1
            return err
        }

        // Find last pbuf in the copied chain r
        var last = r
        while let nxt = last.next {
            last = nxt
        }

        // Append to loopback queue
        if self.loopFirst != nil {
            assert(self.loopLast != nil, "if loopFirst != nil, loopLast must also be != nil")
            self.loopLast?.next = r
            self.loopLast = last
        } else {
            self.loopFirst = r
            self.loopLast = last
        }

        LWIPStats.shared.link.transmitted += 1
        statsIf.mib2Counters.ifOutOctets += UInt32(p.totLen)
        statsIf.mib2Counters.ifOutUcastPkts += 1

        return .ok
    }

    /// Ethernet output (for EthIPv6).
    @inlinable
    @discardableResult
    public func ethernetOutput(_ pbuf: Pbuf, dest: EthernetAddress, etherType: UInt16) -> LWIPError {
        return linkOutput?(self, pbuf) ?? .interfaceError
    }

    /// MLD MAC filter action.
    public enum MLDMacFilterAction: Sendable {
        case add
        case remove
    }

    /// MLD MAC filter convenience.
    public var mld6Groups: MLD6Group? {
        get { storedMLD6Groups }
        set { storedMLD6Groups = newValue }
    }

    /// DHCPv6 data storage.
    public var dhcp6Data: DHCPv6Data? {
        get { storedDHCP6Data }
        set { storedDHCP6Data = newValue }
    }
}

/// Thread-safe storage for per-interface extension data.
/// In a full port, this would be stored via client data indices.
internal enum NetworkInterfaceExtensionData {
    private static var mld6GroupsMap = [ObjectIdentifier: MLD6Group?]()
    private static var dhcp6DataMap = [ObjectIdentifier: DHCPv6Data?]()
    private static var mld6InterfaceStateMap = [ObjectIdentifier: MLD6InterfaceState]()

    static func mld6Groups(for netif: NetworkInterface) -> MLD6Group? {
        mld6GroupsMap[ObjectIdentifier(netif)] ?? nil
    }

    static func setMLD6Groups(_ value: MLD6Group?, for netif: NetworkInterface) {
        mld6GroupsMap[ObjectIdentifier(netif)] = value
    }

    static func dhcp6Data(for netif: NetworkInterface) -> DHCPv6Data? {
        dhcp6DataMap[ObjectIdentifier(netif)] ?? nil
    }

    static func setDHCP6Data(_ value: DHCPv6Data?, for netif: NetworkInterface) {
        dhcp6DataMap[ObjectIdentifier(netif)] = value
    }

    static func mld6InterfaceState(for netif: NetworkInterface) -> MLD6InterfaceState {
        if let state = mld6InterfaceStateMap[ObjectIdentifier(netif)] {
            return state
        }
        let state = MLD6InterfaceState()
        mld6InterfaceStateMap[ObjectIdentifier(netif)] = state
        return state
    }

    static func setMLD6InterfaceState(_ value: MLD6InterfaceState?, for netif: NetworkInterface) {
        mld6InterfaceStateMap[ObjectIdentifier(netif)] = value
    }
}

extension NetworkInterface {
    fileprivate var storedMLD6Groups: MLD6Group? {
        get { NetworkInterfaceExtensionData.mld6Groups(for: self) }
        set { NetworkInterfaceExtensionData.setMLD6Groups(newValue, for: self) }
    }
    fileprivate var storedDHCP6Data: DHCPv6Data? {
        get { NetworkInterfaceExtensionData.dhcp6Data(for: self) }
        set { NetworkInterfaceExtensionData.setDHCP6Data(newValue, for: self) }
    }

    /// Per-interface MLDv2 state (compatibility mode, robustness, query interval).
    public var mld6State: MLD6InterfaceState {
        get { NetworkInterfaceExtensionData.mld6InterfaceState(for: self) }
        set { NetworkInterfaceExtensionData.setMLD6InterfaceState(newValue, for: self) }
    }
}

// MARK: - Global state as static properties on NetworkInterface

extension NetworkInterface {
    /// The global linked list of all registered network interfaces.
    public static nonisolated(unsafe) var list: NetworkInterface?

    /// The default network interface used when no specific route matches.
    public static nonisolated(unsafe) var defaultInterface: NetworkInterface?

    /// Monotonically-increasing counter to assign unique interface numbers.
    static nonisolated(unsafe) var numCounter: UInt8 = 0

    /// Linked list head for extended status callbacks.
    static nonisolated(unsafe) var extCallbackHead: NetifExtCallback?

    /// The dedicated loopback interface, created automatically during subsystem
    /// initialization when `loopbackEnabled` is set.
    public static nonisolated(unsafe) var loopbackInterface: NetworkInterface?
}

// MARK: - netif_init

extension NetworkInterface {
    /// Initialize the network interface subsystem. Call once at startup.
    ///
    /// When `lwipConfig.loopbackEnabled` is `true` this also creates the
    /// loopback interface with 127.0.0.1 (IPv4) and ::1 (IPv6).
    public static func initializeSubsystem() {
        NetworkInterface.list = nil
        NetworkInterface.defaultInterface = nil
        NetworkInterface.numCounter = 0
        NetworkInterface.loopbackInterface = nil
        IPv4.netifList = nil
        IPv4.netifDefault = nil
        IPv4.defaultMulticastNetif = nil

        // Automatically create the loopback interface when enabled.
        if lwipConfig.loopbackEnabled {
            let loopNetif = NetworkInterface()

            // Determine the input function: in NO_SYS mode packets go
            // straight to ip_input; in threaded mode they go via tcpip_input.
            let inputFn: NetifAPI.InputHandler = lwipConfig.noSys
                ? { p, inp in IPDispatch.input(p, inp) }
                : { p, inp in TCPIP.shared.input(pbuf: p, netif: inp) }

            if lwipConfig.ipv4 {
                NetworkInterface.add(
                    loopNetif,
                    ipAddr: IPv4Address(127, 0, 0, 1),
                    netmask: IPv4Address(255, 0, 0, 0),
                    gateway: IPv4Address(127, 0, 0, 1),
                    initFn: { $0.initLoopback() },
                    inputFn: inputFn
                )
            } else {
                NetworkInterface.add(
                    loopNetif,
                    initFn: { $0.initLoopback() },
                    inputFn: inputFn
                )
            }

            if lwipConfig.ipv6 {
                loopNetif.ipv6Addresses[0] = .v6(.loopback)
                loopNetif.ipv6AddressStates[0] = .valid
            }

            loopNetif.setLinkUp()
            loopNetif.setUp()

            NetworkInterface.loopbackInterface = loopNetif
        }
    }
}

// MARK: - Default null output functions

extension NetworkInterface {
    /// No-op IPv4 output for interfaces that do not support IPv4.
    ///
    /// Used as a placeholder output function; simply returns `.interfaceError`.
    public static func nullOutputIPv4(_ netif: NetworkInterface, _ p: Pbuf, _ addr: IPv4Address) -> LWIPError {
        return .interfaceError
    }

    /// No-op IPv6 output for interfaces that do not support IPv6.
    ///
    /// Used as a placeholder output function; simply returns `.interfaceError`.
    public static func nullOutputIPv6(_ netif: NetworkInterface, _ p: Pbuf, _ addr: IPv6Address) -> LWIPError {
        return .interfaceError
    }
}

// MARK: - Static methods (add, find, setDefault, etc.)

extension NetworkInterface {

    // MARK: - netif_add

    /// Add a network interface to the global list.
    ///
    /// - Parameters:
    ///   - netif: A pre-allocated `NetworkInterface`.
    ///   - ipAddr: Initial IPv4 address (or `.any`).
    ///   - netmask: Initial IPv4 netmask (or `.any`).
    ///   - gateway: Initial default gateway (or `.any`).
    ///   - state: Opaque driver state pointer.
    ///   - initFn: Driver init callback.
    ///   - inputFn: Packet input callback (typically `NetworkInterface.input` or `tcpipInput`).
    /// - Returns: The initialised interface, or `nil` if `initFn` failed.
    @discardableResult
    public static func add(
        _ netif: NetworkInterface,
        ipAddr: IPv4Address = .any,
        netmask: IPv4Address = .any,
        gateway: IPv4Address = .any,
        state: UnsafeMutableRawPointer? = nil,
        initFn: NetifAPI.InitializationHandler,
        inputFn: @escaping NetifAPI.InputHandler
    ) -> NetworkInterface? {
        // Reset IPv4
        netif.ipAddr = .any
        netif.netmask = .any
        netif.gateway = .any
        netif.output = NetworkInterface.nullOutputIPv4

        // Reset IPv6
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            netif.ipv6Addresses[i] = .v6(.any)
            netif.ipv6AddressStates[i] = .invalid
            netif.ipv6AddressValidLifetime[i] = IPv6AddressLifetime.static
            netif.ipv6AddressPreferredLifetime[i] = IPv6AddressLifetime.static
        }
        netif.outputIP6 = NetworkInterface.nullOutputIPv6

        netif.mtu = 0
        netif.flags = []
        netif.ip6AutoconfigEnabled = true
        netif.statusCallback = nil
        netif.linkCallback = nil
        netif.removeCallback = nil
        netif.igmpMacFilter = nil
        netif.mldMacFilter = nil
        netif.state = state
        netif.num = NetworkInterface.numCounter
        netif.input = inputFn
        netif.loopFirst = nil
        netif.loopLast = nil
        netif.loopCountCurrent = 0

        // Set IPv4 addresses
        netif.setAddresses(ipAddr: ipAddr, netmask: netmask, gateway: gateway)

        // Call driver init
        if initFn(netif) != .ok {
            return nil
        }

        // Initialize mtuIPv6 from mtu
        netif.mtuIPv6 = netif.mtu

        // Assign a unique num
        assignUniqueNum(netif)

        // Prepend to global list
        netif.next = NetworkInterface.list
        NetworkInterface.list = netif
        IPv4.netifList = NetworkInterface.list

        // Notify
        NetworkInterface.invokeExtCallback(netif, reason: .netifAdded, args: .none)

        return netif
    }

    /// Add an interface without specifying IPv4 addresses.
    @discardableResult
    public static func addNoAddr(
        _ netif: NetworkInterface,
        state: UnsafeMutableRawPointer? = nil,
        initFn: NetifAPI.InitializationHandler,
        inputFn: @escaping NetifAPI.InputHandler
    ) -> NetworkInterface? {
        return NetworkInterface.add(netif, state: state, initFn: initFn, inputFn: inputFn)
    }

    /// Assign a unique interface number, avoiding collisions with existing netifs.
    private static func assignUniqueNum(_ netif: NetworkInterface) {
        // O(n^2) but fine for the small number of interfaces lwIP supports.
        var found: Bool
        repeat {
            if netif.num == 255 {
                netif.num = 0
            }
            found = false
            var cur = NetworkInterface.list
            while let c = cur {
                assert(c !== netif, "netif already in list during num assignment")
                if c.num == netif.num {
                    netif.num &+= 1
                    found = true
                    break
                }
                cur = c.next
            }
        } while found

        NetworkInterface.numCounter = (netif.num == 254) ? 0 : netif.num &+ 1
    }

    // MARK: - netif_set_default

    /// Set the default network interface.
    public static func setDefault(_ netif: NetworkInterface?) {
        NetworkInterface.defaultInterface = netif
        IPv4.netifDefault = netif
    }

    // MARK: - netif_find

    /// Find a network interface by its name string (e.g. "en0").
    public static func find(_ nameStr: String) -> NetworkInterface? {
        guard nameStr.count >= 3 else { return nil }
        let chars = Array(nameStr.utf8)
        guard chars.count >= 3 else { return nil }

        let c0 = chars[0]
        let c1 = chars[1]

        // Parse the numeric suffix
        let numStr = String(nameStr.dropFirst(2))
        guard let parsedNum = UInt8(numStr) else { return nil }

        var cur = NetworkInterface.list
        while let netif = cur {
            if netif.num == parsedNum && netif.name.0 == c0 && netif.name.1 == c1 {
                return netif
            }
            cur = netif.next
        }
        return nil
    }

    /// Find a network interface by its 1-based index.
    public static func getByIndex(_ idx: UInt8) -> NetworkInterface? {
        guard idx != NetworkInterfaceConstants.noIndex else { return nil }
        var cur = NetworkInterface.list
        while let netif = cur {
            if netif.index == idx {
                return netif
            }
            cur = netif.next
        }
        return nil
    }

    /// Convert a name string to a 1-based interface index.
    public static func nameToIndex(_ name: String) -> UInt8 {
        if let netif = NetworkInterface.find(name) {
            return netif.index
        }
        return NetworkInterfaceConstants.noIndex
    }

    /// Convert a 1-based index to the interface name string.
    public static func indexToName(_ idx: UInt8) -> String? {
        guard let netif = NetworkInterface.getByIndex(idx) else { return nil }
        return netif.fullName
    }

    // MARK: - Iterate

    /// Call `body` for every registered network interface.
    @inlinable
    public static func forEach(_ body: (NetworkInterface) -> Void) {
        var cur = NetworkInterface.list
        while let netif = cur {
            body(netif)
            cur = netif.next
        }
    }

    // MARK: - netif_input

    /// Forwards a received packet to `ethernet_input` or `ip_input` based on flags.
    ///
    /// This is the standard function to pass to `NetworkInterface.add` as the input callback
    /// when working in NO_SYS mode.
    @inlinable
    public static func input(_ p: Pbuf, _ inp: NetworkInterface) -> LWIPError {
        if inp.flags.contains(.ethArp) || inp.flags.contains(.ethernet) {
            return Ethernet.input(p, inp)
        }
        return IPDispatch.input(p, inp)
    }

    // MARK: - netif_poll_all

    /// Call `poll` for every interface in the list.
    public static func pollAll() {
        NetworkInterface.forEach { $0.poll() }
    }

    // MARK: - Extended status callbacks (static)

    /// Add an extended status callback listener.
    public static func addExtCallback(_ callback: NetifExtCallback, fn: @escaping NetworkInterfaceExtendedCallbackHandler) {
        callback.callbackFn = fn
        callback.next = NetworkInterface.extCallbackHead
        NetworkInterface.extCallbackHead = callback
    }

    /// Remove an extended status callback listener.
    public static func removeExtCallback(_ callback: NetifExtCallback) {
        if NetworkInterface.extCallbackHead === callback {
            NetworkInterface.extCallbackHead = NetworkInterface.extCallbackHead?.next
        } else {
            var last = NetworkInterface.extCallbackHead
            var iter = NetworkInterface.extCallbackHead?.next
            while let i = iter {
                if i === callback {
                    last?.next = callback.next
                    break
                }
                last = i
                iter = i.next
            }
        }
        callback.next = nil
    }

    /// Invoke all registered extended status callbacks.
    public static func invokeExtCallback(
        _ netif: NetworkInterface,
        reason: NetifNSCReason,
        args: NetifExtCallbackArgs
    ) {
        var cb = NetworkInterface.extCallbackHead
        while let current = cb {
            let next = current.next
            current.callbackFn?(netif, reason, args)
            cb = next
        }
    }
}

// MARK: - Instance methods

extension NetworkInterface {

    // MARK: - remove

    /// Remove this network interface from the global list.
    public func remove() {
        NetworkInterface.invokeExtCallback(self, reason: .netifRemoved, args: .none)

        // Notify PCBs about removed IPv4 address
        if self.ipAddr != .any {
            NetworkInterface.doIPAddrChanged(.v4(self.ipAddr), nil)
        }

        // Notify PCBs about removed IPv6 addresses
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            if self.ipv6AddressStates[i].isValid {
                NetworkInterface.doIPAddrChanged(self.ipv6Addresses[i], nil)
            }
        }

        // Bring down if up
        if self.isUp {
            self.setDown()
        }

        // Reset default
        if NetworkInterface.defaultInterface === self {
            NetworkInterface.setDefault(nil)
        }

        // Unlink from list
        if NetworkInterface.list === self {
            NetworkInterface.list = self.next
        } else {
            var cur = NetworkInterface.list
            while let c = cur {
                if c.next === self {
                    c.next = self.next
                    break
                }
                cur = c.next
            }
        }
        IPv4.netifList = NetworkInterface.list

        // Invoke remove callback
        self.removeCallback?(self)
    }

    // MARK: - IPv4 address management

    /// Change the IPv4 address of this interface.
    public func setIPAddress(_ ipaddr: IPv4Address) {
        let oldAddr = self.ipAddr
        if ipaddr != oldAddr {
            let newAddr = IPAddress.v4(ipaddr)
            NetworkInterface.doIPAddrChanged(.v4(oldAddr), newAddr)
            self.ipAddr = ipaddr
            NetworkInterface.issueReports(self, reportType: .ipv4)
            self.statusCallback?(self)

            NetworkInterface.invokeExtCallback(self, reason: .ipv4AddressChanged,
                                   args: .ipv4Changed(oldAddress: .v4(oldAddr), oldNetmask: nil, oldGateway: nil))
        }
    }

    /// Change the netmask of this interface.
    public func setNetmask(_ mask: IPv4Address) {
        let oldMask = self.netmask
        if mask != oldMask {
            self.netmask = mask
            NetworkInterface.invokeExtCallback(self, reason: .ipv4NetmaskChanged,
                                   args: .ipv4Changed(oldAddress: nil, oldNetmask: .v4(oldMask), oldGateway: nil))
        }
    }

    /// Change the default gateway of this interface.
    public func setGateway(_ gw: IPv4Address) {
        let oldGw = self.gateway
        if gw != oldGw {
            self.gateway = gw
            NetworkInterface.invokeExtCallback(self, reason: .ipv4GatewayChanged,
                                   args: .ipv4Changed(oldAddress: nil, oldNetmask: nil, oldGateway: .v4(oldGw)))
        }
    }

    /// Set IPv4 address, netmask, and gateway atomically.
    public func setAddresses(
        ipAddr: IPv4Address,
        netmask: IPv4Address,
        gateway: IPv4Address
    ) {
        var reason: NetifNSCReason = .none
        let oldAddr = self.ipAddr
        let oldMask = self.netmask
        let oldGw = self.gateway

        let removing = (ipAddr == .any)

        if removing {
            // Remove address first
            if ipAddr != oldAddr {
                NetworkInterface.doIPAddrChanged(.v4(oldAddr), .v4(ipAddr))
                self.ipAddr = ipAddr
                reason.insert(.ipv4AddressChanged)
                NetworkInterface.issueReports(self, reportType: .ipv4)
                self.statusCallback?(self)
            }
        }

        if netmask != oldMask {
            self.netmask = netmask
            reason.insert(.ipv4NetmaskChanged)
        }

        if gateway != oldGw {
            self.gateway = gateway
            reason.insert(.ipv4GatewayChanged)
        }

        if !removing {
            if ipAddr != oldAddr {
                NetworkInterface.doIPAddrChanged(.v4(oldAddr), .v4(ipAddr))
                self.ipAddr = ipAddr
                reason.insert(.ipv4AddressChanged)
                NetworkInterface.issueReports(self, reportType: .ipv4)
                self.statusCallback?(self)
            }
        }

        if reason != .none {
            reason.insert(.ipv4SettingsChanged)
        }
        if !removing {
            reason.insert(.ipv4AddrValid)
        }
        if reason != .none {
            NetworkInterface.invokeExtCallback(self, reason: reason,
                                   args: .ipv4Changed(oldAddress: .v4(oldAddr),
                                                      oldNetmask: .v4(oldMask),
                                                      oldGateway: .v4(oldGw)))
        }
    }

    // MARK: - Up / Down

    /// Bring the interface up.
    public func setUp() {
        guard !self.flags.contains(.up) else { return }
        self.flags.insert(.up)

        self.statusCallback?(self)
        NetworkInterface.invokeExtCallback(self, reason: .statusChanged, args: .statusChanged(state: true))
        NetworkInterface.issueReports(self, reportType: [.ipv4, .ipv6])
    }

    /// Bring the interface down.
    public func setDown() {
        guard self.flags.contains(.up) else { return }

        NetworkInterface.invokeExtCallback(self, reason: .statusChanged, args: .statusChanged(state: false))
        self.flags.remove(.up)

        if self.flags.contains(.ethArp) {
            EthARP.cleanupNetif(self)
        }
        ND6.cleanupNetif(self)

        self.statusCallback?(self)
    }

    // MARK: - Link Up / Down

    /// Called by the driver when the physical link comes up.
    public func setLinkUp() {
        guard !self.flags.contains(.linkUp) else { return }
        self.flags.insert(.linkUp)

        DHCP.networkChangedLinkUp(self)
        AutoIP.networkChangedLinkUp(on: self)
        NetworkInterface.issueReports(self, reportType: [.ipv4, .ipv6])
        ND6.restartNetif(self)
        self.linkCallback?(self)
        NetworkInterface.invokeExtCallback(self, reason: .linkChanged, args: .linkChanged(state: true))
    }

    /// Called by the driver when the physical link goes down.
    public func setLinkDown() {
        guard self.flags.contains(.linkUp) else { return }
        self.flags.remove(.linkUp)

        AutoIP.networkChangedLinkDown(on: self)
        ACD.networkChangedLinkDown(on: self)
        self.mtuIPv6 = self.mtu

        self.linkCallback?(self)
        NetworkInterface.invokeExtCallback(self, reason: .linkChanged, args: .linkChanged(state: false))
    }

    // MARK: - Status / Link callbacks

    /// Set the status callback (called on up/down and address changes while up).
    public func setStatusCallback(_ cb: NetworkInterface.StatusCallbackHandler?) {
        self.statusCallback = cb
    }

    /// Set the link callback (called on link up/down).
    public func setLinkCallback(_ cb: NetworkInterface.StatusCallbackHandler?) {
        self.linkCallback = cb
    }

    /// Set the remove callback (called just before the interface is removed).
    public func setRemoveCallback(_ cb: NetworkInterface.StatusCallbackHandler?) {
        self.removeCallback = cb
    }

    // MARK: - IPv6 address management (instance methods)

    /// Change an IPv6 address on this interface.
    public func setIPv6Address(_ addr: IPv6Address, at addrIndex: Int) {
        setIPv6AddressParts(at: addrIndex,
                            i0: addr.addr.0, i1: addr.addr.1,
                            i2: addr.addr.2, i3: addr.addr.3)
    }

    /// Change an IPv6 address on this interface using four 32-bit words.
    public func setIPv6AddressParts(
        at addrIndex: Int,
        i0: UInt32, i1: UInt32, i2: UInt32, i3: UInt32
    ) {
        precondition(addrIndex >= 0 && addrIndex < NetworkInterfaceConstants.ipv6AddressCount, "invalid IPv6 addr index")

        let oldAddr = self.ipv6Addresses[addrIndex]
        let oldV6: IPv6Address
        if case .v6(let a) = oldAddr { oldV6 = a } else { oldV6 = .any }

        if oldV6.addr.0 != i0 || oldV6.addr.1 != i1 || oldV6.addr.2 != i2 || oldV6.addr.3 != i3 {
            let newV6 = IPv6Address(i0, i1, i2, i3)
            let newIP = IPAddress.v6(newV6)

            if self.ipv6AddressStates[addrIndex].isValid {
                NetworkInterface.doIPAddrChanged(oldAddr, newIP)
            }

            self.ipv6Addresses[addrIndex] = newIP

            if self.ipv6AddressStates[addrIndex].isValid {
                NetworkInterface.issueReports(self, reportType: .ipv6)
                self.statusCallback?(self)
            }

            NetworkInterface.invokeExtCallback(self, reason: .ipv6Set,
                                   args: .ipv6Set(addrIndex: addrIndex, oldAddress: oldAddr))
        }
    }

    /// Change the state of an IPv6 address on this interface.
    public func setIPv6AddressState(at addrIndex: Int, state: IPv6AddressState) {
        precondition(addrIndex >= 0 && addrIndex < NetworkInterfaceConstants.ipv6AddressCount, "invalid IPv6 addr index")

        let oldState = self.ipv6AddressStates[addrIndex]
        guard oldState != state else { return }

        let oldValid = oldState.isValid
        let newValid = state.isValid

        if oldValid && !newValid {
            NetworkInterface.doIPAddrChanged(self.ipv6Addresses[addrIndex], nil)
        }

        self.ipv6AddressStates[addrIndex] = state

        if !oldValid && newValid {
            NetworkInterface.issueReports(self, reportType: .ipv6)
        }

        if (oldState.rawValue & ~IPv6AddressState.tentativeCountMask.rawValue) != (state.rawValue & ~IPv6AddressState.tentativeCountMask.rawValue) {
            self.statusCallback?(self)
        }

        NetworkInterface.invokeExtCallback(self, reason: .ipv6AddrStateChanged,
                                           args: .ipv6AddrStateChanged(addrIndex: addrIndex,
                                                                       oldState: oldState,
                                                                       address: self.ipv6Addresses[addrIndex]))
    }

    /// Find the index of a specific IPv6 address on this interface. Returns -1 if not found.
    public func getIPv6AddressMatch(_ addr: IPv6Address) -> Int {
        for i in 0..<NetworkInterfaceConstants.ipv6AddressCount {
            guard !self.ipv6AddressStates[i].isInvalid else { continue }
            if case .v6(let a) = self.ipv6Addresses[i] {
                if a == addr {
                    return i
                }
            }
        }
        return -1
    }

    /// Create a link-local IPv6 address from the hardware address and store it in slot 0.
    public func createIPv6LinkLocalAddress(fromMAC48Bit: Bool) {
        var addr = IPv6Address.any

        // Link-local prefix: fe80::
        var a0: UInt32 = 0xFE80_0000
        a0 = a0.bigEndian
        let a1: UInt32 = 0
        var a2: UInt32
        var a3: UInt32

        if fromMAC48Bit {
            // EUI-64 from 48-bit MAC: insert ff:fe in the middle, complement bit 1 of first byte
            let hw = self.hwAddr
            a2 = UInt32(hw[0] ^ 0x02) << 24
               | UInt32(hw[1]) << 16
               | UInt32(hw[2]) << 8
               | 0xFF
            a2 = a2.bigEndian

            a3 = UInt32(0xFE) << 24
               | UInt32(hw[3]) << 16
               | UInt32(hw[4]) << 8
               | UInt32(hw[5])
            a3 = a3.bigEndian
        } else {
            a2 = 0
            a3 = 0
            // Use hwAddr directly as interface ID
            var addrIndex = 3
            for i in 0..<min(8, Int(self.hwAddrLen)) {
                if i == 4 { addrIndex -= 1 }
                let shift = 8 * (i & 0x03)
                let val = UInt32(self.hwAddr[Int(self.hwAddrLen) - i - 1]) << shift
                let valBE = val.bigEndian
                if addrIndex == 3 {
                    a3 |= valBE
                } else {
                    a2 |= valBE
                }
            }
        }

        addr = IPv6Address(a0, a1, a2, a3)
        self.ipv6Addresses[0] = .v6(addr)

        // Set address state to tentative (will do DAD) or preferred
        self.setIPv6AddressState(at: 0, state: .tentative)
    }

    /// Add an IPv6 address to this interface, finding a free slot.
    /// Returns the chosen index, or -1 on failure.
    @discardableResult
    public func addIPv6Address(_ addr: IPv6Address) -> Int {
        // Check if already present
        let existing = self.getIPv6AddressMatch(addr)
        if existing >= 0 {
            return existing
        }

        // Link-local addresses go in slot 0; others start at 1
        let isLinkLocal = (addr.addr.0 & UInt32(0xFFC0_0000).bigEndian) == UInt32(0xFE80_0000).bigEndian
        let start = isLinkLocal ? 0 : 1

        for i in start..<NetworkInterfaceConstants.ipv6AddressCount {
            if self.ipv6AddressStates[i].isInvalid {
                self.ipv6Addresses[i] = .v6(addr)
                self.setIPv6AddressState(at: i, state: .tentative)
                return i
            }
        }
        return -1
    }

    // MARK: - Loopback output wrappers

    /// IPv4 wrapper that calls `loopOutput(_:)`.
    ///
    /// Intended to be used as the `output` function for loopback interfaces.
    public static func loopOutputIPv4(_ netif: NetworkInterface, _ p: Pbuf, _ addr: IPv4Address) -> LWIPError {
        return netif.loopOutput(p)
    }

    /// IPv6 wrapper that calls `loopOutput(_:)`.
    ///
    /// Intended to be used as the `outputIP6` function for loopback interfaces.
    public static func loopOutputIPv6(_ netif: NetworkInterface, _ p: Pbuf, _ addr: IPv6Address) -> LWIPError {
        return netif.loopOutput(p)
    }

    // MARK: - Loopback poll

    /// Deliver queued loopback packets to the interface's input function.
    ///
    /// Dequeues packets one at a time from the `loopFirst` linked list and
    /// feeds each back through `ip_input` as if it were received from the network.
    public func poll() {
        let statsIf = self

        while self.loopFirst != nil {
            // Detach one complete packet from the queue.
            // A "packet" may span multiple pbufs; we walk until len == totLen
            // to find the boundary of the first logical packet.
            let inPkt = self.loopFirst!
            var inEnd = inPkt
            var clen: UInt16 = 1

            while inEnd.len != inEnd.totLen {
                assert(inEnd.next != nil, "bogus pbuf: len != totLen but next == nil")
                guard let nxt = inEnd.next else { break }
                inEnd = nxt
                clen += 1
            }

            // Adjust the loopback pbuf count
            if lwipConfig.loopbackMaxPbufs > 0 {
                assert(self.loopCountCurrent >= clen, "loopCountCurrent underflow")
                self.loopCountCurrent = self.loopCountCurrent &- clen
            }

            // Advance or clear the queue
            if inEnd === self.loopLast {
                // This was the last packet in the queue
                self.loopFirst = nil
                self.loopLast = nil
            } else {
                // Pop the packet off the list
                self.loopFirst = inEnd.next
                assert(self.loopFirst != nil, "should not be nil since first != last")
            }
            // Detach the packet from its successors on the queue
            inEnd.next = nil

            inPkt.ifIndex = self.index

            LWIPStats.shared.link.received += 1
            statsIf.mib2Counters.ifInOctets += UInt32(inPkt.totLen)
            statsIf.mib2Counters.ifInUcastPkts += 1

            // Loopback packets are always IP packets
            if IPDispatch.input(inPkt, self) != .ok {
                let _ = Pbuf.free(inPkt)
            }
        }
    }

    // MARK: - Loopback interface initialization

    /// Initialize this network interface as a loopback interface.
    ///
    /// Sets the interface name to "lo", installs `loopOutputIPv4` / `loopOutputIPv6`
    /// as the output functions, and disables all software checksum processing.
    ///
    /// - Returns: `.ok` on success.
    @discardableResult
    public func initLoopback() -> LWIPError {
        // Set MIB2 interface type for loopback (softwareLoopback = 24, speed = 0)
        self.linkType = 24
        self.linkSpeed = 0

        self.name = (UInt8(ascii: "l"), UInt8(ascii: "o"))

        // Set output functions to loopback wrappers
        self.output = NetworkInterface.loopOutputIPv4
        self.outputIP6 = NetworkInterface.loopOutputIPv6

        // Disable all software checksum processing for loopback
        self.checksumFlags = .disableAll

        return .ok
    }
}

// MARK: - Report types (internal)

private struct NetifReportType: OptionSet {
    let rawValue: UInt8
    static let ipv4 = NetifReportType(rawValue: 0x01)
    static let ipv6 = NetifReportType(rawValue: 0x02)
}

extension NetworkInterface {
    private static let ipAddressChangeLock = NSLock()

    /// Send gratuitous ARPs, IGMP reports, MLD reports, etc. as appropriate.
    fileprivate static func issueReports(_ netif: NetworkInterface, reportType: NetifReportType) {
        // Only send reports when both link and admin states are up
        guard netif.flags.contains(.linkUp), netif.flags.contains(.up) else { return }

        if reportType.contains(.ipv4), !netif.ipAddr.isAny {
            if netif.flags.contains(.ethArp), netif.acdList == nil {
                _ = EthARP.request(netif: netif, ipAddr: netif.ipAddr)
            }

            if netif.flags.contains(.igmp) {
                IGMP.reportGroups(on: netif)
            }
        }

        if reportType.contains(.ipv6), netif.flags.contains(.mld6) {
            MLD6.reportGroups(on: netif)
        }
    }

    /// Notify TCP, UDP, and RAW PCBs that an IP address has changed.
    fileprivate static func doIPAddrChanged(_ oldAddr: IPAddress?, _ newAddr: IPAddress?) {
        guard let oldAddr else { return }

        ipAddressChangeLock.lock()
        defer { ipAddressChangeLock.unlock() }

        TCPGlobal.shared.netifIPAddrChanged(oldAddr: oldAddr, newAddr: newAddr)
        UDPGlobal.shared.netifIPAddrChanged(oldAddr: oldAddr, newAddr: newAddr)
        RawControlBlock.handleIPAddressChange(old: oldAddr, new: newAddr)
    }
}

// MARK: - Closure-based extended status callback convenience API

/// An opaque token returned by the closure-based `addExtCallback` that owns
/// the underlying `NetifExtCallback` node.  Passing it back to
/// `removeExtCallback` unregisters the listener.
private final class NetifExtCallbackToken {
    let node: NetifExtCallback
    init(node: NetifExtCallback) { self.node = node }
}

extension NetworkInterface {

    /// Register an extended status callback using a closure.
    ///
    /// Returns an opaque token (`AnyObject`) that must be retained for as long
    /// as the callback should remain active.  Pass the token to
    /// `removeExtCallback(_:)` to unregister.
    ///
    /// Uses a closure and token pattern instead of caller-managed linked-list nodes.
    @discardableResult
    public static func addExtCallback(
        _ callback: @escaping (NetworkInterface, NetifNSCReason, NetifExtCallbackArgs) -> Void
    ) -> AnyObject {
        let node = NetifExtCallback()
        NetworkInterface.addExtCallback(node, fn: callback)
        return NetifExtCallbackToken(node: node)
    }

    /// Remove an extended status callback previously registered via the
    /// closure-based `addExtCallback(_:)`.
    ///
    /// - Parameter token: The opaque `AnyObject` returned by `addExtCallback`.
    ///   If `token` is not a valid callback token the call is silently ignored.
    public static func removeExtCallback(_ token: AnyObject) {
        guard let t = token as? NetifExtCallbackToken else { return }
        NetworkInterface.removeExtCallback(t.node)
    }
}

// MARK: - Client data slots
//
// Well-known subsystems (DHCP, AutoIP, IGMP, MLD6, DHCPv6, ...) already
// have typed properties (e.g. `ipv4DhcpData`, `ipv4AutoipData`), but this
// generic mechanism is needed for third-party or optional subsystems that
// want to attach opaque data to a `NetworkInterface` without modifying
// the class.

extension NetworkInterface {

    /// The next client-data slot ID to hand out.  Access is **not**
    /// thread-safe; callers are expected to allocate IDs from the lwIP
    /// core thread.
    private static nonisolated(unsafe) var nextClientDataID: Int = 0

    /// Maximum number of client-data slots.
    /// Generous upper bound; the array grows lazily so no memory is wasted.
    private static let maxClientDataSlots: Int = 256

    /// Allocate a new client-data slot index.
    ///
    /// Each subsystem should call this **once** during its own initialisation
    /// and cache the returned index.  The index is then used with the
    /// `subscript(clientDataIndex:)` accessor on every `NetworkInterface`.
    ///
    /// - Returns: A unique slot index.
    public static func allocClientDataID() -> Int {
        let id = nextClientDataID
        nextClientDataID += 1
        precondition(id < maxClientDataSlots,
                     "Exceeded maximum number of netif client data slots (\(maxClientDataSlots))")
        return id
    }

    /// Access the client-data slot at `index`.
    ///
    /// Slot indices are obtained from `allocClientDataID()`.  Each slot
    /// stores an optional `AnyObject?`.
    ///
    /// - Complexity: O(1) after the internal array has grown to accommodate
    ///   the index.
    public subscript(clientDataIndex index: Int) -> AnyObject? {
        get {
            guard index >= 0, index < clientDataStorage.count else { return nil }
            return clientDataStorage[index]
        }
        set {
            if index >= clientDataStorage.count {
                clientDataStorage.append(contentsOf:
                    Array<AnyObject?>(repeating: nil, count: index - clientDataStorage.count + 1))
            }
            clientDataStorage[index] = newValue
        }
    }
}

// MARK: - Per-instance client data backing store

/// Thread-safe storage for the per-instance client-data array, keyed by
/// `ObjectIdentifier`.  Stored outside the class to avoid changing its
/// stored-property layout.
private enum ClientDataStore {
    /// Map from interface identity to its client-data array.
    static var map: [ObjectIdentifier: [AnyObject?]] = [:]
}

extension NetworkInterface {
    /// Internal accessor for the per-instance client-data array.
    internal var clientDataStorage: [AnyObject?] {
        get {
            ClientDataStore.map[ObjectIdentifier(self)] ?? []
        }
        set {
            ClientDataStore.map[ObjectIdentifier(self)] = newValue
        }
    }
}
