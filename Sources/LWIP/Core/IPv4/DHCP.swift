//
//  DHCP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - DHCP Constants

/// Namespace for DHCP protocol constants.
public enum DHCPConstants {
    /// Coarse timer period in seconds.
    public static let coarseTimerSeconds: UInt32 = 60
    /// Coarse timer period in milliseconds.
    public static let coarseTimerMilliseconds: UInt32 = coarseTimerSeconds * 1000
    /// Fine timer period in milliseconds.
    public static let fineTimerMilliseconds: UInt32 = 500

    /// Maximum boot file name length.
    public static let bootFileLength: Int = 128

    /// Client hardware address field length.
    public static let clientHardwareAddressLength: Int = 16
    /// Server name field length.
    public static let serverNameLength: Int = 64
    /// Server name field offset.
    public static let serverNameOffset: Int = 44
    /// File name field length.
    public static let fileLength: Int = 128
    /// File name field offset.
    public static let fileOffset: Int = 108
    /// Base message length.
    public static let messageLength: Int = 236
    /// Options offset in message.
    public static let optionsOffset: Int = messageLength + 4
    /// Minimum options length.
    public static let minimumOptionsLength: Int = 68
    /// Options buffer length.
    public static let optionsLength: Int = 68
    /// Minimum reply length.
    public static let minimumReplyLength: Int = 44

    /// DHCP boot request opcode.
    public static let bootRequest: UInt8 = 1
    /// DHCP boot reply opcode.
    public static let bootReply: UInt8 = 2

    /// Magic cookie value.
    public static let magicCookie: UInt32 = 0x63825363

    /// Server port.
    public static let serverPort: UInt16 = 67
    /// Client port.
    public static let clientPort: UInt16 = 68

    /// Maximum rebooting attempts before falling back to discover.
    public static let rebootTries: UInt8 = 2

    /// Minimum MTU for DHCP.
    public static let minimumMTU: UInt16 = 576

    /// Overload values for option 52.
    public static let overloadNone: UInt8 = 0
    public static let overloadFile: UInt8 = 1
    public static let overloadSName: UInt8 = 2
    public static let overloadBoth: UInt8 = 3

    /// Minimum coarse-timer ticks between adaptive timeout recalculations.
    public static let nextTimeoutThreshold: UInt16 = UInt16((60 + coarseTimerSeconds / 2) / coarseTimerSeconds)

    /// Flag indicating the subnet mask was supplied by the server.
    public static let flagSubnetMaskGiven: UInt8 = 0x01
    /// Flag indicating externally allocated memory.
    public static let flagExternalMem: UInt8 = 0x02

    /// Initial retransmit timeout in seconds (RFC 2131).
    public static let initialRetransmitTimeout: UInt16 = 4
    /// Maximum retransmit timeout in seconds.
    public static let maxRetransmitTimeout: UInt16 = 64
    /// Randomization jitter range in seconds (+/- 1).
    public static let retransmitJitter: UInt16 = 1

    /// Ethernet hardware type for IANA.
    public static let hardwareTypeEthernet: UInt8 = 1
    /// Ethernet hardware address length.
    public static let hardwareAddrLenEthernet: UInt8 = 6

    /// Vendor class identifier string.
    public static let vendorClassIdentifier = "lwIP"
}

// MARK: - DHCP Message Types

/// DHCP message type values.
public enum DHCPMessageType: UInt8, Sendable {
    case discover   = 1
    case offer      = 2
    case request    = 3
    case decline    = 4
    case ack        = 5
    case nak        = 6
    case release    = 7
    case inform     = 8
}

// MARK: - DHCP State

/// DHCP client state machine states.
public enum DHCPState: UInt8, Sendable {
    case off            = 0
    case requesting     = 1
    case initializing   = 2
    case rebooting      = 3
    case rebinding      = 4
    case renewing       = 5
    case selecting      = 6
    case informing      = 7
    case checking       = 8
    case permanent      = 9
    case bound          = 10
    case releasing      = 11
    case backingOff     = 12
}

// MARK: - DHCP Options

/// DHCP option codes.
public enum DHCPOption: UInt8, Sendable {
    case pad                    = 0
    case subnetMask             = 1
    case router                 = 3
    case dnsServer              = 6
    case hostname               = 12
    case domainName             = 15
    case ipTTL                  = 23
    case mtu                    = 26
    case broadcast              = 28
    case tcpTTL                 = 37
    case ntp                    = 42
    case requestedIP            = 50
    case leaseTime              = 51
    case overload               = 52
    case messageType            = 53
    case serverID               = 54
    case parameterRequestList   = 55
    case maxMsgSize             = 57
    case t1                     = 58
    case t2                     = 59
    case vendorClassIdentifier  = 60
    case clientID               = 61
    case tftpServerName         = 66
    case bootFile               = 67
    case end                    = 255
}

// MARK: - Parsed Options

/// Temporary storage for options parsed from a DHCP server reply.
internal struct DHCPParsedOptions {
    var messageType: DHCPMessageType?
    var subnetMask: IPv4Address?
    var router: IPv4Address?
    var leaseTime: UInt32?
    var serverID: IPv4Address?
    var t1: UInt32?
    var t2: UInt32?
    var dnsServers: [IPv4Address] = []
    var ntpServers: [IPv4Address] = []
    var offeredIP: IPv4Address = .any
    var overload: UInt8 = 0

    init() {}
}

// MARK: - DHCP Client

/// DHCP client state for one network interface.
public final class DHCPClient {
    /// Transaction identifier of last sent request.
    public var xid: UInt32 = 0
    /// Whether a PCB is allocated.
    public var pcbAllocated: Bool = false
    /// Current state.
    public var state: DHCPState = .off
    /// Retry count for current request.
    public var tries: UInt8 = 0
    /// Flags (subnet mask given, external memory, etc.).
    public var flags: UInt8 = 0

    /// Request timeout (ticks at DHCPConstants.fineTimerMilliseconds rate).
    public var requestTimeout: UInt16 = 0
    /// T1 renewal timeout (ticks at DHCPConstants.coarseTimerSeconds rate).
    public var t1Timeout: UInt16 = 0
    /// T2 rebind timeout (ticks at DHCPConstants.coarseTimerSeconds rate).
    public var t2Timeout: UInt16 = 0
    /// Time until next renew attempt.
    public var t1RenewTime: UInt16 = 0
    /// Time until next rebind attempt.
    public var t2RebindTime: UInt16 = 0
    /// Lease time used so far (coarse ticks).
    public var leaseUsed: UInt16 = 0
    /// Total lease timeout (coarse ticks).
    public var t0Timeout: UInt16 = 0

    /// DHCP server address.
    public var serverIPAddr: IPv4Address = .any
    /// Offered IP address.
    public var offeredIPAddr: IPv4Address = .any
    /// Offered subnet mask.
    public var offeredSubnetMask: IPv4Address = .any
    /// Offered gateway.
    public var offeredGateway: IPv4Address = .any

    /// Offered lease period in seconds.
    public var offeredT0Lease: UInt32 = 0
    /// Offered T1 renewal time in seconds.
    public var offeredT1Renew: UInt32 = 0
    /// Offered T2 rebind time in seconds.
    public var offeredT2Rebind: UInt32 = 0

    /// ACD instance for address conflict detection.
    public var acd: AddressConflictDetection?

    /// Current retransmit timeout in seconds (doubles on each retry, 4..64).
    public var retransmitTimeout: UInt16 = DHCPConstants.initialRetransmitTimeout

    public init() {}

    // MARK: - State Management

    /// Transition to a new DHCP state, resetting tries if the state changes.
    internal func setState(_ newState: DHCPState) {
        if state != newState {
            state = newState
            tries = 0
            requestTimeout = 0
            retransmitTimeout = DHCPConstants.initialRetransmitTimeout
        }
    }

    /// Clear all offered/lease state.
    internal func clearOffers() {
        offeredIPAddr = .any
        offeredSubnetMask = .any
        offeredGateway = .any
        offeredT0Lease = 0
        offeredT1Renew = 0
        offeredT2Rebind = 0
    }

    // MARK: - Instance Methods

    /// Start the DHCP client on a network interface.
    @discardableResult
    public func start(netif: NetworkInterface) -> LWIPError {
        guard netif.mtu >= DHCPConstants.minimumMTU else { return .outOfMemory }

        if pcbAllocated {
            pcbAllocated = false
        }

        let savedFlags = flags

        xid = 0
        state = .off
        tries = 0
        requestTimeout = 0
        t1Timeout = 0
        t2Timeout = 0
        t1RenewTime = 0
        t2RebindTime = 0
        leaseUsed = 0
        t0Timeout = 0
        serverIPAddr = .any
        clearOffers()

        flags = savedFlags
        pcbAllocated = true
        netif.ipv4DhcpData = self
        xid = UInt32.random(in: 1...UInt32.max)

        // Register ACD instance for address conflict detection if enabled.
        if lwipConfig.dhcpDoesAcdCheck {
            if acd == nil {
                acd = AddressConflictDetection()
            }
            ACD.add(to: netif, acd: acd!) { netif, state in
                DHCP.acdCallback(netif: netif, state: state)
            }
        }

        guard netif.flags.contains(.linkUp) else {
            state = .initializing
            return .ok
        }

        state = .selecting
        tries = 1
        _ = DHCP.start(on: netif)
        return .ok
    }

    /// Stop the DHCP client on a network interface.
    public func stop(netif: NetworkInterface) {
        guard state != .off else { return }

        // Remove ACD registration if it was enabled.
        if lwipConfig.dhcpDoesAcdCheck, let acdInst = acd {
            ACD.remove(from: netif, acd: acdInst)
        }

        let savedServerAddr = serverIPAddr

        serverIPAddr = .any
        clearOffers()
        t1RenewTime = 0
        t2RebindTime = 0
        leaseUsed = 0
        t0Timeout = 0

        if state == .bound || state == .renewing || state == .rebinding {
            serverIPAddr = savedServerAddr
            DHCP.release(on: netif)
            netif.ipAddr = .any
            netif.netmask = .any
            netif.gateway = .any
        }

        state = .off
        tries = 0
        requestTimeout = 0
        pcbAllocated = false
    }
}

// MARK: - DHCP Module

/// DHCP client protocol implementation.
public enum DHCP {

    /// Backoff sequence for request retries (in milliseconds).
    /// Uses the formula: (tries < 6 ? 1 << tries : 60) * 1000.
    @inlinable
    public static func requestBackoff(tries: UInt8) -> UInt16 {
        let t = Int(tries)
        return UInt16((t < 6 ? (1 << t) : 60) * 1000)
    }

    /// Compute retransmit timeout with exponential backoff and +/- 1s jitter.
    /// Initial: 4s, doubles each retry up to 64s max. Randomized +/- 1s.
    /// Returns timeout in fine-timer ticks (500ms each).
    internal static func retransmitBackoff(client: DHCPClient) -> UInt16 {
        let baseSeconds = client.retransmitTimeout
        // Apply +/- 1 second jitter.
        let jitter = Int16.random(in: -1...1)
        let withJitter = max(1, Int(baseSeconds) + Int(jitter))
        let msecs = UInt16(min(withJitter * 1000, Int(UInt16.max)))
        // Double the timeout for next retry, capped at max.
        if client.retransmitTimeout < DHCPConstants.maxRetransmitTimeout {
            client.retransmitTimeout = min(client.retransmitTimeout * 2, DHCPConstants.maxRetransmitTimeout)
        }
        // Convert milliseconds to fine timer ticks (rounding up).
        return (msecs + UInt16(DHCPConstants.fineTimerMilliseconds) - 1) / UInt16(DHCPConstants.fineTimerMilliseconds)
    }

    // MARK: - Start / Stop

    /// Start the DHCP client on an interface.
    public static func start(on netif: NetworkInterface) -> LWIPError {
        var dhcp = netif.ipv4DhcpData as? DHCPClient

        if dhcp == nil {
            dhcp = DHCPClient()
            netif.ipv4DhcpData = dhcp
        }

        guard let client = dhcp else { return .outOfMemory }

        client.state = .initializing
        client.tries = 0
        client.xid = UInt32.random(in: 0...UInt32.max)

        return discover(on: netif, client: client)
    }

    /// Stop the DHCP client on an interface.
    public static func stop(on netif: NetworkInterface) {
        guard let dhcp = netif.ipv4DhcpData as? DHCPClient else { return }
        dhcp.state = .off
        dhcp.pcbAllocated = false
    }

    /// Release the DHCP lease and stop the client.
    public static func releaseAndStop(on netif: NetworkInterface) {
        guard let dhcp = netif.ipv4DhcpData as? DHCPClient else { return }

        if dhcp.state == .bound || dhcp.state == .renewing || dhcp.state == .rebinding {
            let _ = release(on: netif)
        }

        // Remove ACD registration before stopping.
        if lwipConfig.dhcpDoesAcdCheck, let acdInst = dhcp.acd {
            ACD.remove(from: netif, acd: acdInst)
        }

        stop(on: netif)

        netif.ipAddr = .any
        netif.netmask = .any
        netif.gateway = .any
    }

    // MARK: - Discover

    /// Send a DHCP DISCOVER message.
    private static func discover(on netif: NetworkInterface, client: DHCPClient) -> LWIPError {
        // DHCP/AutoIP cooperation: start AutoIP as fallback after N failed discovers.
        if lwipConfig.autoip && lwipConfig.dhcpAutoipCoopTries > 0 &&
           client.tries >= lwipConfig.dhcpAutoipCoopTries {
            let _ = AutoIP.start(on: netif)
        }

        client.offeredIPAddr = .any
        client.setState(.selecting)
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .discover, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size.
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })

        // Option 61: Client Identifier (hardware type + MAC address).
        addOptionClientIdentifier(p, netif: netif)

        // Option 60: Vendor Class Identifier.
        addOptionVendorClassIdentifier(p)

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        let result = sendMessage(p, netif: netif)
        p.free()

        client.requestTimeout = retransmitBackoff(client: client)
        return result
    }

    // MARK: - Select (Request after Offer)

    /// Send a DHCP REQUEST in response to a server OFFER.
    private static func select(on netif: NetworkInterface, client: DHCPClient) -> LWIPError {
        client.setState(.requesting)
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .request, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size.
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })

        // MUST request the offered IP address (option 50).
        addOption(p, option: .requestedIP,
                  data: withUnsafeBytes(of: client.offeredIPAddr.addr) { Array($0) })

        // Server Identifier (option 54).
        addOption(p, option: .serverID,
                  data: withUnsafeBytes(of: client.serverIPAddr.addr) { Array($0) })

        // Option 61: Client Identifier.
        addOptionClientIdentifier(p, netif: netif)

        // Option 60: Vendor Class Identifier.
        addOptionVendorClassIdentifier(p)

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        let result = sendMessage(p, netif: netif)
        p.free()

        client.requestTimeout = retransmitBackoff(client: client)
        return result
    }

    // MARK: - Request (generic, used by renew/rebind/reboot)

    /// Send a DHCP REQUEST message (generic helper).
    private static func request(on netif: NetworkInterface, client: DHCPClient) -> LWIPError {
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .request, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size.
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        let result = sendMessage(p, netif: netif)
        p.free()

        client.requestTimeout = retransmitBackoff(client: client)
        return result
    }

    // MARK: - Reboot

    /// Send a DHCP REQUEST to verify an existing lease after link change.
    private static func reboot(on netif: NetworkInterface, client: DHCPClient) -> LWIPError {
        client.setState(.rebooting)
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .request, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size (use minimum required for reboot).
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: DHCPConstants.minimumMTU.bigEndian) { Array($0) })

        addOption(p, option: .requestedIP,
                  data: withUnsafeBytes(of: client.offeredIPAddr.addr) { Array($0) })

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        let result = sendMessage(p, netif: netif)
        p.free()

        let backoff: UInt16 = client.tries < 10
            ? UInt16(client.tries) * 1000
            : 10_000
        client.requestTimeout = (backoff + UInt16(DHCPConstants.fineTimerMilliseconds) - 1) / UInt16(DHCPConstants.fineTimerMilliseconds)
        return result
    }

    // MARK: - Bind

    /// Bind the offered address to the network interface.
    public static func bind(on netif: NetworkInterface, client: DHCPClient) {
        // DHCP/AutoIP cooperation: stop AutoIP now that DHCP succeeded.
        if lwipConfig.autoip && lwipConfig.dhcpAutoipCoopTries > 0 {
            let _ = AutoIP.stop(on: netif)
        }

        client.state = .bound
        client.leaseUsed = 0
        client.tries = 0

        // Calculate t0 (lease timeout) in coarse timer ticks.
        if client.offeredT0Lease != 0xFFFF_FFFF {
            let t0 = (client.offeredT0Lease + DHCPConstants.coarseTimerSeconds / 2) / DHCPConstants.coarseTimerSeconds
            client.t0Timeout = UInt16(min(t0, UInt32(UInt16.max)))
        }

        // Calculate t1 (renew timeout).
        if client.offeredT1Renew != 0 {
            let t1 = (client.offeredT1Renew + DHCPConstants.coarseTimerSeconds / 2) / DHCPConstants.coarseTimerSeconds
            client.t1Timeout = UInt16(min(t1, UInt32(UInt16.max)))
        } else {
            client.t1Timeout = client.t0Timeout / 2
        }

        // Calculate t2 (rebind timeout).
        if client.offeredT2Rebind != 0 {
            let t2 = (client.offeredT2Rebind + DHCPConstants.coarseTimerSeconds / 2) / DHCPConstants.coarseTimerSeconds
            client.t2Timeout = UInt16(min(t2, UInt32(UInt16.max)))
        } else {
            client.t2Timeout = UInt16(UInt32(client.t0Timeout) * 7 / 8)
        }

        // Prevent t1 >= t2 when both are set.
        if client.t1Timeout >= client.t2Timeout && client.t2Timeout > 0 {
            client.t1Timeout = 0
        }

        client.t1RenewTime = client.t1Timeout
        client.t2RebindTime = client.t2Timeout

        // Determine subnet mask if not explicitly supplied.
        var mask = client.offeredSubnetMask
        if mask == .any {
            // Infer from IP class.
            let firstOctet = client.offeredIPAddr.addr & 0xFF
            if firstOctet < 128 {
                mask = IPv4Address(255, 0, 0, 0)        // Class A
            } else if firstOctet < 192 {
                mask = IPv4Address(255, 255, 0, 0)      // Class B
            } else {
                mask = IPv4Address(255, 255, 255, 0)    // Class C
            }
        }

        netif.ipAddr = client.offeredIPAddr
        netif.netmask = mask
        netif.gateway = client.offeredGateway
    }

    // MARK: - Renew

    /// Initiate DHCP lease renewal (unicast to server).
    @discardableResult
    public static func renew(on netif: NetworkInterface) -> LWIPError {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return .invalidArgument }
        client.setState(.renewing)
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .request, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size.
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        // Renew sends unicast to the server that granted the lease.
        let result = sendMessageUnicast(p, netif: netif, serverAddr: client.serverIPAddr)
        p.free()

        let backoff: UInt16 = client.tries < 10
            ? UInt16(client.tries) * 2000
            : 20_000
        client.requestTimeout = (backoff + UInt16(DHCPConstants.fineTimerMilliseconds) - 1) / UInt16(DHCPConstants.fineTimerMilliseconds)
        return result
    }

    // MARK: - Rebind

    /// Initiate DHCP rebinding (broadcast to any server).
    /// In REBINDING state, the client broadcasts DHCPREQUEST to any server
    /// (not unicast to the original), per RFC 2131 section 4.3.6.
    @discardableResult
    public static func rebind(on netif: NetworkInterface) -> LWIPError {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return .invalidArgument }
        client.setState(.rebinding)
        client.tries &+= 1

        guard let p = createMessage(client: client, type: .request, netif: netif) else {
            return .outOfMemory
        }

        // Option 57: Maximum DHCP Message Size.
        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })

        // Option 55: Parameter Request List (expanded).
        addOption(p, option: .parameterRequestList, data: [
            DHCPOption.subnetMask.rawValue,
            DHCPOption.router.rawValue,
            DHCPOption.dnsServer.rawValue,
            DHCPOption.domainName.rawValue,
            DHCPOption.leaseTime.rawValue,
            DHCPOption.t1.rawValue,
            DHCPOption.t2.rawValue,
            DHCPOption.broadcast.rawValue
        ])
        addOptionHostname(p, netif: netif)
        addEndOption(p)

        // Rebind broadcasts to any DHCP server (not unicast to original).
        let result = sendMessage(p, netif: netif)
        p.free()

        let backoff: UInt16 = client.tries < 10
            ? UInt16(client.tries) * 1000
            : 10_000
        client.requestTimeout = (backoff + UInt16(DHCPConstants.fineTimerMilliseconds) - 1) / UInt16(DHCPConstants.fineTimerMilliseconds)
        return result
    }

    // MARK: - Release

    /// Release the DHCP lease.
    /// Sends DHCPRELEASE with server identifier and client IP, then clears the interface address.
    @discardableResult
    public static func release(on netif: NetworkInterface) -> LWIPError {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return .invalidArgument }

        // Save server address before clearing state.
        let savedServerAddr = client.serverIPAddr

        client.setState(.off)

        guard let p = createMessage(client: client, type: .release, netif: netif) else {
            return .outOfMemory
        }

        // Include server identifier (option 54) using the saved address.
        addOption(p, option: .serverID,
                  data: withUnsafeBytes(of: savedServerAddr.addr) { Array($0) })
        addEndOption(p)

        // Send unicast to the server that granted the lease.
        let result = sendMessageUnicast(p, netif: netif, serverAddr: savedServerAddr)
        p.free()

        // Clear the interface address after sending release (RFC 2131).
        netif.ipAddr = .any
        netif.netmask = .any
        netif.gateway = .any

        return result
    }

    // MARK: - Inform

    /// Send a DHCP INFORM message for a manually configured address.
    public static func inform(on netif: NetworkInterface) {
        let tmpClient = DHCPClient()
        tmpClient.xid = UInt32.random(in: 1...UInt32.max)

        guard let p = createMessage(client: tmpClient, type: .inform, netif: netif) else {
            return
        }

        addOption(p, option: .maxMsgSize, data: withUnsafeBytes(of: netif.mtu.bigEndian) { Array($0) })
        addEndOption(p)

        _ = sendMessage(p, netif: netif)
        p.free()
    }

    // MARK: - Decline

    /// Send a DHCP DECLINE message (offered address already in use).
    /// Per RFC 2131 section 4.4.4, DECLINE is broadcast.
    @discardableResult
    private static func decline(on netif: NetworkInterface, client: DHCPClient) -> LWIPError {
        client.setState(.backingOff)

        // Remove IP address from interface (prevents routing from selecting this interface).
        netif.ipAddr = .any
        netif.netmask = .any
        netif.gateway = .any

        guard let p = createMessage(client: client, type: .decline, netif: netif) else {
            return .outOfMemory
        }

        // Include requested IP (option 50).
        addOption(p, option: .requestedIP,
                  data: withUnsafeBytes(of: client.offeredIPAddr.addr) { Array($0) })

        // Include server identifier (option 54).
        addOption(p, option: .serverID,
                  data: withUnsafeBytes(of: client.serverIPAddr.addr) { Array($0) })
        addEndOption(p)

        // Broadcast DECLINE per RFC 2131 section 4.4.4.
        let result = sendMessage(p, netif: netif)
        p.free()
        return result
    }

    // MARK: - Receive

    /// Process a received DHCP message from the server.
    ///
    /// This is the core receive handler. It validates the reply, parses options,
    /// and dispatches to the appropriate
    /// handler based on message type and current client state.
    public static func recv(netif: NetworkInterface, p: Pbuf) {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return }
        guard client.state != .off else { return }

        // Validate minimum message length.
        guard p.totalLength >= DHCPConstants.minimumReplyLength else { return }

        // Validate opcode is BOOTREPLY.
        guard p.readByte(at: 0) == DHCPConstants.bootReply else { return }

        // Validate hardware address matches.
        let hlen = Int(p.readByte(at: 2))
        let hwAddr = netif.hwAddr
        if hlen == hwAddr.count {
            for i in 0..<hlen {
                guard p.readByte(at: 28 + i) == hwAddr[i] else { return }
            }
        }

        // Validate transaction ID.
        let replyXid = p.readUInt32(at: 4)
        guard replyXid == client.xid else { return }

        // Parse options.
        guard let opts = parseReply(p: p) else { return }
        guard let msgType = opts.messageType else { return }

        // Extract offered IP from yiaddr field (offset 16).
        let offeredIP = IPv4Address(networkOrder: p.readUInt32(at: 16))

        switch msgType {
        case .offer:
            if client.state == .selecting {
                handleOffer(netif: netif, client: client, opts: opts, offeredIP: offeredIP)
            }

        case .ack:
            // Validate server identifier in ACK matches expected server for
            // REQUESTING state (RFC 2131 section 4.3.2).
            if client.state == .requesting {
                if let serverID = opts.serverID {
                    guard serverID == client.serverIPAddr else { return }
                } else {
                    // No server ID in ACK during requesting -- skip.
                    return
                }
            }

            switch client.state {
            case .requesting, .rebooting:
                handleAck(netif: netif, client: client, opts: opts, offeredIP: offeredIP)
                if lwipConfig.dhcpDoesAcdCheck, let acdInst = client.acd {
                    client.setState(.checking)
                    ACD.start(on: netif, acd: acdInst, ipAddr: client.offeredIPAddr)
                } else {
                    bind(on: netif, client: client)
                }
            case .renewing, .rebinding:
                handleAck(netif: netif, client: client, opts: opts, offeredIP: offeredIP)
                if lwipConfig.dhcpDoesAcdCheck, let acdInst = client.acd {
                    client.setState(.checking)
                    ACD.start(on: netif, acd: acdInst, ipAddr: client.offeredIPAddr)
                } else {
                    bind(on: netif, client: client)
                }
            default:
                break
            }

        case .nak:
            switch client.state {
            case .rebooting, .requesting, .renewing, .rebinding:
                handleNak(netif: netif, client: client)
            default:
                break
            }

        default:
            break
        }
    }

    // MARK: - Reply Parsing

    /// Parse DHCP options from a reply message.
    ///
    /// Walks the options fields (and optionally overloaded sname/file fields)
    /// extracting known options.
    private static func parseReply(p: Pbuf) -> DHCPParsedOptions? {
        guard p.totalLength >= DHCPConstants.optionsOffset else { return nil }

        var opts = DHCPParsedOptions()

        // Parse options starting at the options offset.
        parseOptionsRegion(p: p, start: DHCPConstants.optionsOffset,
                           end: Int(p.totalLength), opts: &opts)

        // Handle overload: re-parse sname and/or file fields as options.
        if opts.overload & DHCPConstants.overloadFile != 0 {
            parseOptionsRegion(p: p, start: DHCPConstants.fileOffset,
                               end: DHCPConstants.fileOffset + DHCPConstants.fileLength, opts: &opts)
        }
        if opts.overload & DHCPConstants.overloadSName != 0 {
            parseOptionsRegion(p: p, start: DHCPConstants.serverNameOffset,
                               end: DHCPConstants.serverNameOffset + DHCPConstants.serverNameLength, opts: &opts)
        }

        return opts
    }

    /// Parse a contiguous region of DHCP options.
    private static func parseOptionsRegion(p: Pbuf, start: Int, end: Int, opts: inout DHCPParsedOptions) {
        var offset = start

        while offset < end {
            let optType = p.readByte(at: offset)

            if optType == DHCPOption.end.rawValue {
                break
            }
            if optType == DHCPOption.pad.rawValue {
                offset += 1
                continue
            }

            // Read option length.
            guard offset + 1 < end else { break }
            let optLen = Int(p.readByte(at: offset + 1))
            let dataStart = offset + 2
            guard dataStart + optLen <= end else { break }

            switch optType {
            case DHCPOption.messageType.rawValue:
                if optLen == 1 {
                    opts.messageType = DHCPMessageType(rawValue: p.readByte(at: dataStart))
                }

            case DHCPOption.subnetMask.rawValue:
                if optLen == 4 {
                    opts.subnetMask = IPv4Address(networkOrder: p.readUInt32(at: dataStart))
                }

            case DHCPOption.router.rawValue:
                if optLen >= 4 {
                    opts.router = IPv4Address(networkOrder: p.readUInt32(at: dataStart))
                }

            case DHCPOption.leaseTime.rawValue:
                if optLen == 4 {
                    opts.leaseTime = UInt32(bigEndian: p.readUInt32(at: dataStart))
                }

            case DHCPOption.serverID.rawValue:
                if optLen == 4 {
                    opts.serverID = IPv4Address(networkOrder: p.readUInt32(at: dataStart))
                }

            case DHCPOption.t1.rawValue:
                if optLen == 4 {
                    opts.t1 = UInt32(bigEndian: p.readUInt32(at: dataStart))
                }

            case DHCPOption.t2.rawValue:
                if optLen == 4 {
                    opts.t2 = UInt32(bigEndian: p.readUInt32(at: dataStart))
                }

            case DHCPOption.dnsServer.rawValue:
                let count = optLen / 4
                for i in 0..<count {
                    opts.dnsServers.append(IPv4Address(networkOrder: p.readUInt32(at: dataStart + i * 4)))
                }

            case DHCPOption.ntp.rawValue:
                let count = optLen / 4
                for i in 0..<count {
                    opts.ntpServers.append(IPv4Address(networkOrder: p.readUInt32(at: dataStart + i * 4)))
                }

            case DHCPOption.overload.rawValue:
                if optLen == 1 {
                    opts.overload = p.readByte(at: dataStart)
                }

            default:
                break
            }

            offset = dataStart + optLen
        }
    }

    // MARK: - Message Handlers

    /// Handle a DHCP OFFER from the server.
    private static func handleOffer(netif: NetworkInterface, client: DHCPClient,
                                     opts: DHCPParsedOptions, offeredIP: IPv4Address) {
        guard let serverID = opts.serverID else { return }

        client.serverIPAddr = serverID
        client.offeredIPAddr = offeredIP

        _ = select(on: netif, client: client)
    }

    /// Handle a DHCP ACK from the server. Extracts lease parameters.
    private static func handleAck(netif: NetworkInterface, client: DHCPClient,
                                   opts: DHCPParsedOptions, offeredIP: IPv4Address) {
        // Clear previous offers.
        client.clearOffers()

        // Store offered IP.
        client.offeredIPAddr = offeredIP

        // Lease time.
        if let lease = opts.leaseTime {
            client.offeredT0Lease = lease
        } else {
            client.offeredT0Lease = 7200 // Default: 2 hours
        }

        // Renewal time (T1).
        if let t1 = opts.t1 {
            client.offeredT1Renew = t1
        } else {
            client.offeredT1Renew = client.offeredT0Lease / 2
        }

        // Rebind time (T2).
        if let t2 = opts.t2 {
            client.offeredT2Rebind = t2
        } else {
            client.offeredT2Rebind = client.offeredT0Lease * 7 / 8
        }

        // Subnet mask.
        if let mask = opts.subnetMask {
            client.offeredSubnetMask = mask
            client.flags |= DHCPConstants.flagSubnetMaskGiven
        }

        // Gateway.
        if let gw = opts.router {
            client.offeredGateway = gw
        }

        // Server ID (update in case it changed during renew).
        if let sid = opts.serverID {
            client.serverIPAddr = sid
        }

        // Register DNS servers.
        for (i, dns) in opts.dnsServers.enumerated() {
            DNS.shared.setServer(index: i, address: .v4(dns))
        }
    }

    /// Handle a DHCP NAK from the server.
    private static func handleNak(netif: NetworkInterface, client: DHCPClient) {
        client.setState(.backingOff)

        // Remove address from interface.
        netif.ipAddr = .any
        netif.netmask = .any
        netif.gateway = .any

        // Restart discovery.
        _ = discover(on: netif, client: client)
    }

    // MARK: - ACD Conflict Callback

    /// Called by the ACD module when address conflict detection completes or a conflict is found.
    internal static func acdCallback(netif: NetworkInterface, state: ACDCallbackState) {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return }

        switch state {
        case .ipOK:
            // Address is confirmed unique, proceed to bind.
            bind(on: netif, client: client)

        case .restartClient:
            // Conflict detected after decline. Wait 10 seconds before restarting
            // per RFC 2131 section 3.1 point 5: "The client SHOULD wait a minimum
            // of ten seconds before restarting the configuration process to avoid
            // excessive network traffic in case of looping."
            client.setState(.backingOff)
            let msecs: UInt16 = 10 * 1000
            client.requestTimeout = (msecs + UInt16(DHCPConstants.fineTimerMilliseconds) - 1) / UInt16(DHCPConstants.fineTimerMilliseconds)

        case .decline:
            // Address is in use. Remove IP address from interface first
            // (prevents routing from selecting this interface), then send DECLINE.
            _ = decline(on: netif, client: client)
        }
    }

    // MARK: - Timers

    /// Coarse timer. Call every DHCPConstants.coarseTimerSeconds seconds.
    /// Handles lease expiry, T1 renew, and T2 rebind.
    /// t0 counts up (leaseUsed increments toward t0Timeout), while
    /// t1RenewTime and t2RebindTime count down to 1 then trigger.
    public static func coarseTimer() {
        var netif = IPv4.netifList
        while let n = netif {
            if let dhcp = n.dhcpData, dhcp.state != .off {
                // Check lease expiry (t0): leaseUsed counts up to t0Timeout.
                if dhcp.t0Timeout > 0 {
                    dhcp.leaseUsed &+= 1
                    if dhcp.leaseUsed == dhcp.t0Timeout {
                        // Lease has expired. Release and restart discovery.
                        releaseAndStop(on: n)
                        let _ = start(on: n)
                        netif = n.next
                        continue
                    }
                }

                // Check T2 rebind (countdown): when it reaches 1, trigger rebind.
                // This enters REBINDING state and broadcasts to any server.
                if dhcp.t2RebindTime > 0 {
                    let wasT2 = dhcp.t2RebindTime
                    dhcp.t2RebindTime -= 1
                    if wasT2 == 1 {
                        t2Timeout(n, client: dhcp)
                    }
                }
                // Check T1 renewal (countdown): when it reaches 1, trigger renewal.
                else if dhcp.t1RenewTime > 0 {
                    let wasT1 = dhcp.t1RenewTime
                    dhcp.t1RenewTime -= 1
                    if wasT1 == 1 {
                        t1Timeout(n, client: dhcp)
                    }
                }
            }
            netif = n.next
        }
    }

    /// Handle T1 renewal timeout.
    /// In RENEWING, unicast DHCPREQUEST to the server. The T2 timer will
    /// eventually trigger REBINDING if renew attempts fail.
    private static func t1Timeout(_ netif: NetworkInterface, client: DHCPClient) {
        let st = client.state
        guard st == .requesting || st == .bound || st == .renewing else { return }

        _ = renew(on: netif)

        // Recalculate next t1 countdown: half the remaining time until t2.
        // The C code does: t1_renew_time = (t2_timeout - lease_used) / 2
        let remaining = client.t2Timeout > client.leaseUsed
            ? client.t2Timeout - client.leaseUsed
            : 0
        let next = remaining / 2
        if next >= DHCPConstants.nextTimeoutThreshold {
            client.t1RenewTime = next
        }
    }

    /// Handle T2 rebind timeout.
    /// Enters REBINDING state and broadcasts DHCPREQUEST to any server.
    /// If no response, the lease will eventually expire via the t0 timer
    /// and discovery will restart.
    private static func t2Timeout(_ netif: NetworkInterface, client: DHCPClient) {
        let st = client.state
        guard st == .requesting || st == .bound || st == .renewing || st == .rebinding else { return }

        _ = rebind(on: netif)

        // Recalculate next t2 countdown: half the remaining time until lease expiry.
        // The C code does: t2_rebind_time = (t0_timeout - lease_used) / 2
        let remaining = client.t0Timeout > client.leaseUsed
            ? client.t0Timeout - client.leaseUsed
            : 0
        let next = remaining / 2
        if next >= DHCPConstants.nextTimeoutThreshold {
            client.t2RebindTime = next
        }
    }

    /// Fine timer. Call every DHCPConstants.fineTimerMilliseconds (500ms).
    /// Handles request timeouts and retransmissions.
    public static func fineTimer() {
        var netif = IPv4.netifList
        while let n = netif {
            if let dhcp = n.dhcpData {
                if dhcp.requestTimeout > 0 {
                    dhcp.requestTimeout -= 1
                    if dhcp.requestTimeout == 0 {
                        handleTimeout(n, client: dhcp)
                    }
                }
            }
            netif = n.next
        }
    }

    /// Handle a request timeout.
    private static func handleTimeout(_ netif: NetworkInterface, client: DHCPClient) {
        switch client.state {
        case .backingOff, .selecting:
            let _ = discover(on: netif, client: client)

        case .requesting:
            if client.tries <= 5 {
                let _ = select(on: netif, client: client)
            } else {
                releaseAndStop(on: netif)
                let _ = start(on: netif)
            }

        case .rebooting:
            if client.tries < DHCPConstants.rebootTries {
                let _ = reboot(on: netif, client: client)
            } else {
                let _ = discover(on: netif, client: client)
            }

        case .renewing:
            let _ = renew(on: netif)

        case .rebinding:
            let _ = rebind(on: netif)

        default:
            break
        }
    }

    // MARK: - Utility

    /// Check if DHCP supplied the interface address.
    public static func suppliedAddress(_ netif: NetworkInterface) -> Bool {
        guard let dhcp = netif.ipv4DhcpData as? DHCPClient else { return false }
        return dhcp.state == .bound || dhcp.state == .renewing || dhcp.state == .rebinding
    }

    /// Called when the network link comes up.
    public static func networkChangedLinkUp(_ netif: NetworkInterface) {
        guard let client = netif.ipv4DhcpData as? DHCPClient else { return }

        switch client.state {
        case .bound, .renewing, .rebinding, .rebooting:
            client.tries = 0
            let _ = reboot(on: netif, client: client)
        case .off:
            break
        default:
            client.tries = 0
            client.xid = UInt32.random(in: 1...UInt32.max)
            let _ = discover(on: netif, client: client)
        }
    }

    // MARK: - Message Construction

    /// Create a DHCP message pbuf.
    private static func createMessage(client: DHCPClient, type: DHCPMessageType,
                                       netif: NetworkInterface) -> Pbuf? {
        let msgSize = UInt16(DHCPConstants.messageLength + 4 + DHCPConstants.optionsLength)
        guard let p = Pbuf.alloc(layer: .transport, length: msgSize, type: .ram) else {
            return nil
        }

        p.zeroFill(at: 0, count: Int(msgSize))

        // Generate new xid on first try, reuse for retransmissions.
        if client.tries == 0 {
            client.xid = UInt32.random(in: 1...UInt32.max)
        }

        p.writeByte(DHCPConstants.bootRequest, at: 0)   // op
        p.writeByte(1, at: 1)                            // htype (Ethernet)
        p.writeByte(6, at: 2)                            // hlen
        p.writeByte(0, at: 3)                            // hops
        p.writeUInt32(client.xid, at: 4)                 // xid

        // Set ciaddr for certain message types.
        switch type {
        case .inform, .decline, .release:
            p.writeUInt32(netif.ipAddr.addr, at: 12)
        case .request:
            if client.state == .renewing || client.state == .rebinding {
                p.writeUInt32(netif.ipAddr.addr, at: 12)
            }
        default:
            break
        }

        // chaddr at offset 28.
        let hwAddr = netif.hwAddr
        for i in 0..<min(hwAddr.count, DHCPConstants.clientHardwareAddressLength) {
            p.writeByte(hwAddr[i], at: 28 + i)
        }

        // Magic cookie.
        p.writeUInt32(DHCPConstants.magicCookie.bigEndian, at: DHCPConstants.messageLength)

        // Message type option.
        p.writeByte(DHCPOption.messageType.rawValue, at: DHCPConstants.optionsOffset)
        p.writeByte(1, at: DHCPConstants.optionsOffset + 1)
        p.writeByte(type.rawValue, at: DHCPConstants.optionsOffset + 2)

        return p
    }

    /// Add a DHCP option to the message.
    private static func addOption(_ p: Pbuf, option: DHCPOption, data: [UInt8]) {
        var offset = DHCPConstants.optionsOffset + 3
        while offset < Int(p.len) - 1 {
            let optType = p.readByte(at: offset)
            if optType == DHCPOption.end.rawValue || optType == DHCPOption.pad.rawValue {
                break
            }
            let optLen = Int(p.readByte(at: offset + 1))
            offset += 2 + optLen
        }

        guard offset + 2 + data.count <= Int(p.len) else { return }
        p.writeByte(option.rawValue, at: offset)
        p.writeByte(UInt8(data.count), at: offset + 1)
        for (i, byte) in data.enumerated() {
            p.writeByte(byte, at: offset + 2 + i)
        }
    }

    /// Add Client Identifier option (61): hardware type (1 byte) + MAC address.
    /// Per RFC 2132 section 9.14, the client identifier consists of a
    /// hardware type byte followed by the hardware address.
    private static func addOptionClientIdentifier(_ p: Pbuf, netif: NetworkInterface) {
        let hw = netif.hwAddr
        let hwLen = min(Int(netif.hwAddrLen), hw.count, Int(DHCPConstants.hardwareAddrLenEthernet))
        var data = [UInt8](repeating: 0, count: 1 + hwLen)
        data[0] = DHCPConstants.hardwareTypeEthernet  // hardware type: Ethernet
        for i in 0..<hwLen { data[i + 1] = hw[i] }
        addOption(p, option: .clientID, data: data)
    }

    /// Add Vendor Class Identifier option (60).
    /// Per RFC 2132 section 9.13, identifies the vendor type and configuration.
    private static func addOptionVendorClassIdentifier(_ p: Pbuf) {
        addOption(p, option: .vendorClassIdentifier,
                  data: Array(DHCPConstants.vendorClassIdentifier.utf8))
    }

    /// Send a DHCP message via unicast to a specific server.
    /// Used for RENEW (unicast to original server) and RELEASE.
    private static func sendMessageUnicast(_ p: Pbuf, netif: NetworkInterface, serverAddr: IPv4Address) -> LWIPError {
        return IPv4.outputIf(p, src: netif.ipAddr, dest: serverAddr,
                             ttl: UInt8(lwipConfig.ipDefaultTTL), tos: 0,
                             proto: IPProtocolNumber.udp, netif: netif)
    }

    /// Add the hostname option if a hostname is set on the interface.
    private static func addOptionHostname(_ p: Pbuf, netif: NetworkInterface) {
        guard let hostname = netif.hostname, !hostname.isEmpty else { return }
        let bytes = Array(hostname.utf8)
        addOption(p, option: .hostname, data: bytes)
    }

    /// Add the END option marker.
    private static func addEndOption(_ p: Pbuf) {
        var offset = DHCPConstants.optionsOffset + 3
        while offset < Int(p.len) - 1 {
            let optType = p.readByte(at: offset)
            if optType == DHCPOption.end.rawValue || optType == DHCPOption.pad.rawValue {
                break
            }
            let optLen = Int(p.readByte(at: offset + 1))
            offset += 2 + optLen
        }
        if offset < Int(p.len) {
            p.writeByte(DHCPOption.end.rawValue, at: offset)
        }
    }

    /// Send a DHCP message via UDP broadcast.
    private static func sendMessage(_ p: Pbuf, netif: NetworkInterface) -> LWIPError {
        return IPv4.outputIf(p, src: .any, dest: .broadcast,
                             ttl: UInt8(lwipConfig.ipDefaultTTL), tos: 0,
                             proto: IPProtocolNumber.udp, netif: netif)
    }
}
