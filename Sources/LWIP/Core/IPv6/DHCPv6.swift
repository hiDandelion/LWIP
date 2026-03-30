//
//  DHCPv6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for DHCPv6 protocol constants.
public enum DHCPv6Constants {
    /// Timer period in milliseconds.
    public static let timerMilliseconds: UInt16 = 500
    /// Client port.
    public static let clientPort: UInt16 = 546
    /// Server port.
    public static let serverPort: UInt16 = 547
    /// Transaction ID length in bytes.
    public static let transactionIDLength: Int = 3
    /// DUID type: Link-Layer Address (DUID-LL, RFC 3315 section 9.4).
    public static let duidTypeLL: UInt16 = 3
    /// Hardware type: Ethernet (RFC 826).
    public static let hwTypeEthernet: UInt16 = 1
    /// Default SOL_MAX_RT (RFC 3315 section 5.5): 120 seconds.
    public static let solMaxRetransmitTimeout: UInt16 = 120
    /// Default SOL_TIMEOUT (RFC 3315 section 5.5): 1 second.
    public static let solTimeout: UInt16 = 1
    /// Default REQ_TIMEOUT: 1 second.
    public static let reqTimeout: UInt16 = 1
    /// Default REQ_MAX_RT: 30 seconds.
    public static let reqMaxRetransmitTimeout: UInt16 = 30
    /// Maximum request retransmissions.
    public static let reqMaxRetransmitCount: UInt8 = 10
    /// Default REN_TIMEOUT: 10 seconds.
    public static let renTimeout: UInt16 = 10
    /// Default REN_MAX_RT: 600 seconds.
    public static let renMaxRetransmitTimeout: UInt16 = 600
    /// Default REB_TIMEOUT: 10 seconds.
    public static let rebTimeout: UInt16 = 10
    /// Default REB_MAX_RT: 600 seconds.
    public static let rebMaxRetransmitTimeout: UInt16 = 600
    /// IPv6 address size in bytes.
    public static let ipv6AddressSize: Int = 16
    /// IA_NA fixed header size (IAID + T1 + T2 = 12 bytes).
    public static let iaNAHeaderSize: Int = 12
    /// IA Address option fixed size (address + preferred + valid = 24 bytes).
    public static let iaAddrFixedSize: Int = 24
    /// DHCPv6 status code: Success.
    public static let statusSuccess: UInt16 = 0
    /// IA_TA fixed header size (IAID = 4 bytes).
    public static let iaTAHeaderSize: Int = 4
    /// IA_PD fixed header size (IAID + T1 + T2 = 12 bytes).
    public static let iaPDHeaderSize: Int = 12
    /// IA Prefix sub-option fixed size (preferred + valid + prefix-len + prefix = 25 bytes).
    public static let iaPrefixFixedSize: Int = 25
    /// DUID type: Link-Layer Address plus Time (DUID-LLT, RFC 3315 section 9.2).
    public static let duidTypeLLT: UInt16 = 1
    /// Default INF_TIMEOUT (RFC 3736): 1 second.
    public static let infTimeout: UInt16 = 1
    /// Default INF_MAX_RT (RFC 3736): 120 seconds.
    public static let infMaxRetransmitTimeout: UInt16 = 120
    /// Maximum number of DNS search list domains to store.
    public static let maxDNSSearchDomains: Int = 4
    /// Maximum number of SNTP servers to store.
    public static let maxSNTPServers: Int = 4
    /// Maximum number of delegated prefixes per IA_PD.
    public static let maxDelegatedPrefixes: Int = 4
    /// Maximum number of temporary addresses per IA_TA.
    public static let maxTemporaryAddresses: Int = 2
}

// MARK: - DHCPv6 Message Types

/// DHCPv6 message types.
public enum DHCPv6MessageType: UInt8, Sendable {
    case solicit         = 1
    case advertise       = 2
    case request         = 3
    case confirm         = 4
    case renew           = 5
    case rebind          = 6
    case reply           = 7
    case release         = 8
    case decline         = 9
    case reconfigure     = 10
    case informationRequest = 11
    case relayForward    = 12
    case relayReply      = 13
}

// MARK: - DHCPv6 Options

/// DHCPv6 option codes.
public enum DHCPv6Option: UInt16, Sendable {
    case clientID       = 1
    case serverID       = 2
    case iaNA           = 3
    case iaTA           = 4
    case iaAddr         = 5
    case optionRequest  = 6
    case preference     = 7
    case elapsedTime    = 8
    case relayMsg       = 9
    case auth           = 11
    case unicast        = 12
    case statusCode     = 13
    case rapidCommit    = 14
    case userClass      = 15
    case vendorClass    = 16
    case vendorOpts     = 17
    case interfaceID    = 18
    case reconfMsg      = 19
    case reconfAccept   = 20
    case dnsServers     = 23
    case domainList     = 24
    case iaPD           = 25
    case iaPrefix       = 26
    case sntpServers    = 31
}

// MARK: - DHCPv6 State

/// DHCPv6 client states.
public enum DHCPv6State: UInt8, Sendable {
    case off                = 0
    case statelessIdle      = 1
    case requestingConfig   = 2
    // Stateful states (RFC 3315)
    case statefulIdle       = 3
    case soliciting         = 4
    case requesting         = 5
    case bound              = 6
    case renewing           = 7
    case rebinding          = 8
    case releasing          = 9
}

// MARK: - IA_NA Data

/// Identity Association for Non-temporary Addresses data.
public struct IANAData: Sendable {
    /// Identity Association Identifier.
    public var iaid: UInt32 = 0
    /// Time at which the client contacts the server to extend lifetimes (seconds).
    public var t1: UInt32 = 0
    /// Time at which the client contacts any server to extend lifetimes (seconds).
    public var t2: UInt32 = 0
    /// Assigned IPv6 address.
    public var address: IPv6Address = .any
    /// Preferred lifetime for the address in seconds.
    public var preferredLifetime: UInt32 = 0
    /// Valid lifetime for the address in seconds.
    public var validLifetime: UInt32 = 0

    public init() {}
}

// MARK: - IA_TA Data (RFC 3315 Section 22.5)

/// Identity Association for Temporary Addresses data.
public struct IATAData: Sendable {
    /// Identity Association Identifier.
    public var iaid: UInt32 = 0
    /// Assigned temporary IPv6 addresses (temporary addresses have no T1/T2).
    public var addresses: [IPv6Address] = []
    /// Preferred lifetimes for each address in seconds.
    public var preferredLifetimes: [UInt32] = []
    /// Valid lifetimes for each address in seconds.
    public var validLifetimes: [UInt32] = []

    public init() {}
}

// MARK: - IA_PD Data (RFC 3633)

/// A single delegated prefix within an IA_PD.
public struct DHCPv6IAPrefix: Sendable {
    /// Preferred lifetime for the prefix in seconds.
    public var preferredLifetime: UInt32 = 0
    /// Valid lifetime for the prefix in seconds.
    public var validLifetime: UInt32 = 0
    /// Prefix length in bits (e.g. 48, 56, 64).
    public var prefixLength: UInt8 = 0
    /// The delegated IPv6 prefix (network portion; host bits should be zero).
    public var prefix: IPv6Address = .any

    public init() {}

    public init(preferredLifetime: UInt32, validLifetime: UInt32,
                prefixLength: UInt8, prefix: IPv6Address) {
        self.preferredLifetime = preferredLifetime
        self.validLifetime = validLifetime
        self.prefixLength = prefixLength
        self.prefix = prefix
    }
}

/// Identity Association for Prefix Delegation data.
public struct DHCPv6IAPD: Sendable {
    /// Identity Association Identifier.
    public var iaid: UInt32 = 0
    /// Time at which the client contacts the server to extend prefix lifetimes (seconds).
    public var t1: UInt32 = 0
    /// Time at which the client contacts any server to extend prefix lifetimes (seconds).
    public var t2: UInt32 = 0
    /// Delegated prefixes from the server.
    public var prefixes: [DHCPv6IAPrefix] = []

    public init() {}
}

// MARK: - Prefix Delegation Callback

/// Callback invoked when prefix delegation events occur.
///
/// - Parameters:
///   - netif: The network interface associated with the event.
///   - prefix: The delegated prefix information.
///   - event: The type of prefix delegation event.
public typealias DHCPv6PrefixDelegationCallback = (
    _ netif: NetworkInterface,
    _ prefix: DHCPv6IAPrefix,
    _ event: DHCPv6PrefixEvent
) -> Void

/// Prefix delegation events.
public enum DHCPv6PrefixEvent: Sendable {
    /// A new prefix has been delegated.
    case delegated
    /// A delegated prefix has been renewed with updated lifetimes.
    case renewed
    /// A delegated prefix has expired or been released.
    case expired
}

// MARK: - DHCPv6 Client Data

/// DHCPv6 client state for a network interface.
public final class DHCPv6Data: @unchecked Sendable {
    /// Transaction identifier of last sent request.
    public var xid: UInt32 = 0
    /// Whether a PCB is allocated.
    public var pcbAllocated: Bool = false
    /// Current state.
    public var state: DHCPv6State = .off
    /// Retry counter.
    public var tries: UInt8 = 0
    /// Pending config request flag.
    public var requestConfigPending: Bool = false
    /// Request timeout in timer ticks.
    public var requestTimeout: UInt16 = 0

    // MARK: - Stateful DHCPv6 fields

    /// IA_NA (Identity Association for Non-temporary Addresses) data.
    public var iana: IANAData = IANAData()
    /// Server ID from ADVERTISE (raw bytes).
    public var serverID: [UInt8] = []
    /// Client DUID (generated from link-layer address).
    public var clientDUID: [UInt8] = []
    /// T1 timer countdown in timer ticks (triggers renew).
    public var t1Timeout: UInt32 = 0
    /// T2 timer countdown in timer ticks (triggers rebind).
    public var t2Timeout: UInt32 = 0
    /// Lease valid lifetime countdown in timer ticks.
    public var leaseTimeout: UInt32 = 0
    /// Server preference from ADVERTISE.
    public var serverPreference: UInt8 = 0
    /// Whether we have received an ADVERTISE.
    public var hasAdvertise: Bool = false
    /// Index of the assigned address in the netif's IPv6 address array (-1 = none).
    public var addressIndex: Int = -1

    // MARK: - IA_TA (Temporary Addresses) fields

    /// IA_TA (Identity Association for Temporary Addresses) data.
    public var iata: IATAData = IATAData()
    /// Whether IA_TA is requested alongside IA_NA.
    public var requestTemporaryAddresses: Bool = false
    /// Indices of temporary addresses in the netif's IPv6 address array.
    public var temporaryAddressIndices: [Int] = []
    /// Lease timeout for temporary addresses (shortest valid lifetime, in timer ticks).
    public var temporaryLeaseTimeout: UInt32 = 0

    // MARK: - IA_PD (Prefix Delegation) fields

    /// IA_PD (Identity Association for Prefix Delegation) data.
    public var iapd: DHCPv6IAPD = DHCPv6IAPD()
    /// Whether prefix delegation is requested.
    public var requestPrefixDelegation: Bool = false
    /// T1 timer countdown for prefix delegation in timer ticks.
    public var pdT1Timeout: UInt32 = 0
    /// T2 timer countdown for prefix delegation in timer ticks.
    public var pdT2Timeout: UInt32 = 0
    /// Prefix valid lifetime countdown in timer ticks.
    public var pdLeaseTimeout: UInt32 = 0
    /// Callback for prefix delegation events.
    public var prefixDelegationCallback: DHCPv6PrefixDelegationCallback?

    // MARK: - Rapid Commit fields

    /// Whether Rapid Commit is enabled (skip REQUEST phase).
    public var rapidCommitEnabled: Bool = false
    /// Whether the server confirmed Rapid Commit in its REPLY.
    public var rapidCommitConfirmed: Bool = false

    // MARK: - DNS Search List and SNTP

    /// DNS domain search list parsed from OPTION_DOMAIN_LIST (option 24).
    public var dnsSearchList: [String] = []
    /// SNTP server addresses parsed from server reply.
    public var sntpServers: [IPv6Address] = []

    public init() {}
}

/// Well-known DHCPv6 multicast addresses.
public enum DHCPv6MulticastAddress {
    /// All DHCP relay agents and servers (ff02::1:2).
    public static let allRelayAgentsAndServers = IPv6Address(
        0xFF02_0000, 0x0000_0000, 0x0000_0000, 0x0001_0002
    )
    /// All DHCP servers (ff02::1:3).
    public static let allServers = IPv6Address(
        0xFF02_0000, 0x0000_0000, 0x0000_0000, 0x0001_0003
    )
}

// MARK: - DHCPv6 Message Header

/// Minimum DHCPv6 message header (4 bytes: msgtype + 3-byte transaction ID).
public struct DHCPv6MessageHeader: Sendable {
    public static let length: Int = 4

    public var messageType: UInt8
    public var transactionID: (UInt8, UInt8, UInt8)

    @inlinable
    public init(messageType: UInt8, xid: UInt32) {
        self.messageType = messageType
        self.transactionID = (
            UInt8((xid >> 16) & 0xFF),
            UInt8((xid >> 8) & 0xFF),
            UInt8(xid & 0xFF)
        )
    }

    @inlinable
    public func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: messageType, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: transactionID.0, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: transactionID.1, toByteOffset: 2, as: UInt8.self)
        p.storeBytes(of: transactionID.2, toByteOffset: 3, as: UInt8.self)
    }
}

// MARK: - Parsed Option Info

/// Parsed DHCPv6 option location info.
struct DHCPv6OptionInfo {
    var isGiven: Bool = false
    var valueStart: UInt16 = 0
    var valueLength: UInt16 = 0
}

// MARK: - DHCPv6 Module

/// DHCPv6 protocol processing.
public enum DHCPv6 {

    // MARK: - Enable / Disable

    /// Enable stateful DHCPv6 on an interface (RFC 3315).
    ///
    /// Allocates DHCPv6 state and transitions to `statefulIdle`. The actual
    /// SOLICIT is triggered by `nd6RATrigger` when an RA with the Managed
    /// Address Configuration flag is received, or can be started immediately
    /// via `startStateful(on:)`.
    @discardableResult
    public static func enableStateful(on netif: NetworkInterface) -> LWIPError {
        guard let data = getOrCreateData(for: netif) else { return .outOfMemory }

        if isStatefulEnabled(data) {
            return .ok
        }
        if data.state != .off {
            // Switching from stateless to stateful -- stop stateless first
        }
        generateClientDUID(data: data, netif: netif)
        // Generate IAID from interface index (unique per IA type)
        let baseIAID = UInt32(netif.num) | (UInt32(netif.hwAddr[0]) << 24)
        data.iana.iaid = baseIAID
        data.iata.iaid = baseIAID &+ 1  // Different IAID for IA_TA
        data.iapd.iaid = baseIAID &+ 2  // Different IAID for IA_PD
        setState(data, to: .statefulIdle)
        return .ok
    }

    /// Begin the stateful SOLICIT process immediately.
    ///
    /// Typically called after `enableStateful(on:)` or from `nd6RATrigger`
    /// when the Managed Address Configuration flag is set.
    public static func startStateful(on netif: NetworkInterface) {
        guard let data = netif.dhcp6Data else { return }
        guard data.state == .statefulIdle else { return }
        sendSolicit(netif: netif, data: data)
    }

    /// Enable stateless DHCPv6 on an interface.
    ///
    /// When enabled, information requests are sent upon receiving an RA
    /// with the Other Configuration flag set.
    @discardableResult
    public static func enableStateless(on netif: NetworkInterface) -> LWIPError {
        let dhcp6 = getOrCreateData(for: netif)
        guard let data = dhcp6 else { return .outOfMemory }

        if isStatelessEnabled(data) {
            return .ok
        }
        if data.state != .off {
            // Switching from stateful to stateless
        }
        setState(data, to: .statelessIdle)
        return .ok
    }

    /// Disable DHCPv6 on an interface.
    ///
    /// If stateful mode was active with an assigned address, a RELEASE
    /// message is sent before shutting down.
    public static func disable(on netif: NetworkInterface) {
        guard let data = netif.dhcp6Data else { return }
        if data.state != .off {
            // If we have a bound address, release it
            if isStatefulEnabled(data) && data.addressIndex >= 0 {
                sendRelease(netif: netif, data: data)
                removeAssignedAddress(netif: netif, data: data)
            }
            // Clean up temporary addresses
            if data.requestTemporaryAddresses {
                removeTemporaryAddresses(netif: netif, data: data)
            }
            // Clean up delegated prefixes
            if data.requestPrefixDelegation {
                notifyPrefixExpiry(netif: netif, data: data)
            }
            setState(data, to: .off)
            data.pcbAllocated = false
        }
    }

    /// Set a pre-allocated DHCPv6 struct on an interface.
    public static func setStruct(on netif: NetworkInterface, data: DHCPv6Data) {
        netif.dhcp6Data = data
    }

    /// Remove and clean up DHCPv6 state from an interface.
    public static func cleanup(on netif: NetworkInterface) {
        netif.dhcp6Data = nil
    }

    // MARK: - Timer

    /// Periodic DHCPv6 timer. Must be called every `DHCPv6Constants.timerMilliseconds` ms.
    public static func timer() {
        var netif = NetworkInterface.list
        while let n = netif {
            if let data = n.dhcp6Data {
                // Request timeout (retransmission)
                if data.requestTimeout > 0 {
                    data.requestTimeout -= 1
                    if data.requestTimeout == 0 {
                        handleTimeout(on: n, data: data)
                    }
                }
                // Stateful lease timers (only when bound)
                if data.state == .bound || data.state == .renewing || data.state == .rebinding {
                    handleLeaseTimers(on: n, data: data)
                }
            }
            netif = n.next
        }
    }

    // MARK: - RA Trigger

    /// Called from ND6 when a Router Advertisement is received.
    ///
    /// Triggers DHCPv6 information requests if stateless mode is enabled
    /// and the Other Configuration flag is set in the RA. Triggers SOLICIT
    /// if stateful mode is enabled and the Managed Address Configuration
    /// flag is set.
    public static func nd6RATrigger(on netif: NetworkInterface,
                                    managedAddrConfig: Bool,
                                    otherConfig: Bool) {
        guard let data = netif.dhcp6Data else { return }

        if isStatelessEnabled(data) {
            if otherConfig {
                requestConfig(on: netif, data: data)
            } else {
                abortConfigRequest(data)
            }
        }

        if isStatefulEnabled(data) {
            if managedAddrConfig && data.state == .statefulIdle {
                sendSolicit(netif: netif, data: data)
            }
        }
    }

    // MARK: - Stateful DHCPv6 Message Sending

    /// Send a SOLICIT message to discover DHCPv6 servers.
    private static func sendSolicit(netif: NetworkInterface, data: DHCPv6Data) {
        // Client ID option: 4 header + DUID length
        let clientIDOptLen = 4 + data.clientDUID.count
        // IA_NA option: 4 header + 12 (IAID + T1 + T2)
        let iaNAOptLen = 4 + DHCPv6Constants.iaNAHeaderSize
        // Elapsed Time option: 4 header + 2
        let elapsedTimeOptLen = 4 + 2
        // Option Request: 4 header + 2 * number of requested options
        let requestedOptions: [UInt16] = [
            DHCPv6Option.dnsServers.rawValue,
            DHCPv6Option.domainList.rawValue,
        ]
        let oroOptLen = 4 + 2 * requestedOptions.count

        // IA_TA option (optional): 4 header + 4 (IAID)
        let iaTAOptLen = data.requestTemporaryAddresses ? (4 + DHCPv6Constants.iaTAHeaderSize) : 0

        // IA_PD option (optional): 4 header + 12 (IAID + T1 + T2)
        let iaPDOptLen = data.requestPrefixDelegation ? (4 + DHCPv6Constants.iaPDHeaderSize) : 0

        // Rapid Commit option (optional): 4 header + 0 data
        let rapidCommitOptLen = data.rapidCommitEnabled ? 4 : 0

        let totalOptLen = clientIDOptLen + iaNAOptLen + elapsedTimeOptLen + oroOptLen
                        + iaTAOptLen + iaPDOptLen + rapidCommitOptLen

        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        if data.tries == 0 {
            data.xid = UInt32.random(in: 0...0xFFFFFF)
            data.hasAdvertise = false
            data.serverID = []
            data.serverPreference = 0
            data.rapidCommitConfirmed = false
        }

        let p = pbuf.payload

        // Write message header
        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.solicit.rawValue, xid: data.xid)
        msgHdr.write(to: p)

        var offset = DHCPv6MessageHeader.length

        // Write Client ID option
        offset = writeClientIDOption(to: p, at: offset, data: data)

        // Write IA_NA option (no IA Address sub-option in SOLICIT)
        offset = writeIANAOption(to: p, at: offset, data: data, includeAddress: false)

        // Write IA_TA option if temporary addresses are requested
        if data.requestTemporaryAddresses {
            offset = writeIATAOption(to: p, at: offset, data: data, includeAddresses: false)
        }

        // Write IA_PD option if prefix delegation is requested
        if data.requestPrefixDelegation {
            offset = writeIAPDOption(to: p, at: offset, data: data, includePrefixes: false)
        }

        // Write Elapsed Time option
        offset = writeElapsedTimeOption(to: p, at: offset, data: data)

        // Write Option Request option
        offset = writeOptionRequestOption(to: p, at: offset, options: requestedOptions)

        // Write Rapid Commit option if enabled
        if data.rapidCommitEnabled {
            offset = writeRapidCommitOption(to: p, at: offset)
        }

        sendMessage(pbuf, netif: netif)

        setState(data, to: .soliciting)
        if data.tries < 255 {
            data.tries += 1
        }
        setRetransmitTimeout(data: data,
                             baseSeconds: DHCPv6Constants.solTimeout,
                             maxSeconds: DHCPv6Constants.solMaxRetransmitTimeout)
    }

    /// Send a REQUEST message to a specific server after receiving ADVERTISE.
    private static func sendRequest(netif: NetworkInterface, data: DHCPv6Data) {
        // Client ID + Server ID + IA_NA (with address) + Elapsed Time + ORO
        let clientIDOptLen = 4 + data.clientDUID.count
        let serverIDOptLen = 4 + data.serverID.count
        // IA_NA with IA Address sub-option
        let iaAddrSubOptLen = 4 + DHCPv6Constants.iaAddrFixedSize
        let iaNAOptLen = 4 + DHCPv6Constants.iaNAHeaderSize + iaAddrSubOptLen
        let elapsedTimeOptLen = 4 + 2
        let requestedOptions: [UInt16] = [
            DHCPv6Option.dnsServers.rawValue,
            DHCPv6Option.domainList.rawValue,
        ]
        let oroOptLen = 4 + 2 * requestedOptions.count

        // IA_TA option with addresses if available
        let iaTAOptLen: Int
        if data.requestTemporaryAddresses {
            let taAddrSubOptLen = data.iata.addresses.count * (4 + DHCPv6Constants.iaAddrFixedSize)
            iaTAOptLen = 4 + DHCPv6Constants.iaTAHeaderSize + taAddrSubOptLen
        } else {
            iaTAOptLen = 0
        }

        // IA_PD option with prefixes if available
        let iaPDOptLen: Int
        if data.requestPrefixDelegation {
            let pdPrefixSubOptLen = data.iapd.prefixes.count * (4 + DHCPv6Constants.iaPrefixFixedSize)
            iaPDOptLen = 4 + DHCPv6Constants.iaPDHeaderSize + pdPrefixSubOptLen
        } else {
            iaPDOptLen = 0
        }

        let totalOptLen = clientIDOptLen + serverIDOptLen + iaNAOptLen + elapsedTimeOptLen + oroOptLen
                        + iaTAOptLen + iaPDOptLen

        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        if data.tries == 0 {
            data.xid = UInt32.random(in: 0...0xFFFFFF)
        }

        let p = pbuf.payload

        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.request.rawValue, xid: data.xid)
        msgHdr.write(to: p)

        var offset = DHCPv6MessageHeader.length
        offset = writeClientIDOption(to: p, at: offset, data: data)
        offset = writeServerIDOption(to: p, at: offset, data: data)
        offset = writeIANAOption(to: p, at: offset, data: data, includeAddress: true)

        // Include IA_TA with addresses if requesting temporary addresses
        if data.requestTemporaryAddresses {
            offset = writeIATAOption(to: p, at: offset, data: data,
                                     includeAddresses: !data.iata.addresses.isEmpty)
        }

        // Include IA_PD with prefixes if requesting prefix delegation
        if data.requestPrefixDelegation {
            offset = writeIAPDOption(to: p, at: offset, data: data,
                                     includePrefixes: !data.iapd.prefixes.isEmpty)
        }

        offset = writeElapsedTimeOption(to: p, at: offset, data: data)
        offset = writeOptionRequestOption(to: p, at: offset, options: requestedOptions)

        sendMessage(pbuf, netif: netif)

        setState(data, to: .requesting)
        if data.tries < 255 {
            data.tries += 1
        }
        setRetransmitTimeout(data: data,
                             baseSeconds: DHCPv6Constants.reqTimeout,
                             maxSeconds: DHCPv6Constants.reqMaxRetransmitTimeout)
    }

    /// Send a RENEW message to extend lifetimes (unicast-capable, sent to server).
    private static func sendRenew(netif: NetworkInterface, data: DHCPv6Data) {
        let clientIDOptLen = 4 + data.clientDUID.count
        let serverIDOptLen = 4 + data.serverID.count
        let iaAddrSubOptLen = 4 + DHCPv6Constants.iaAddrFixedSize
        let iaNAOptLen = 4 + DHCPv6Constants.iaNAHeaderSize + iaAddrSubOptLen
        let elapsedTimeOptLen = 4 + 2

        // IA_TA with addresses
        let iaTAOptLen: Int
        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            let taAddrSubOptLen = data.iata.addresses.count * (4 + DHCPv6Constants.iaAddrFixedSize)
            iaTAOptLen = 4 + DHCPv6Constants.iaTAHeaderSize + taAddrSubOptLen
        } else {
            iaTAOptLen = 0
        }

        // IA_PD with prefixes
        let iaPDOptLen: Int
        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            let pdPrefixSubOptLen = data.iapd.prefixes.count * (4 + DHCPv6Constants.iaPrefixFixedSize)
            iaPDOptLen = 4 + DHCPv6Constants.iaPDHeaderSize + pdPrefixSubOptLen
        } else {
            iaPDOptLen = 0
        }

        let totalOptLen = clientIDOptLen + serverIDOptLen + iaNAOptLen + elapsedTimeOptLen
                        + iaTAOptLen + iaPDOptLen

        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        if data.tries == 0 {
            data.xid = UInt32.random(in: 0...0xFFFFFF)
        }

        let p = pbuf.payload

        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.renew.rawValue, xid: data.xid)
        msgHdr.write(to: p)

        var offset = DHCPv6MessageHeader.length
        offset = writeClientIDOption(to: p, at: offset, data: data)
        offset = writeServerIDOption(to: p, at: offset, data: data)
        offset = writeIANAOption(to: p, at: offset, data: data, includeAddress: true)

        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            offset = writeIATAOption(to: p, at: offset, data: data, includeAddresses: true)
        }

        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            offset = writeIAPDOption(to: p, at: offset, data: data, includePrefixes: true)
        }

        offset = writeElapsedTimeOption(to: p, at: offset, data: data)

        sendMessage(pbuf, netif: netif)

        setState(data, to: .renewing)
        if data.tries < 255 {
            data.tries += 1
        }
        setRetransmitTimeout(data: data,
                             baseSeconds: DHCPv6Constants.renTimeout,
                             maxSeconds: DHCPv6Constants.renMaxRetransmitTimeout)
    }

    /// Send a REBIND message to any server to extend lifetimes.
    private static func sendRebind(netif: NetworkInterface, data: DHCPv6Data) {
        let clientIDOptLen = 4 + data.clientDUID.count
        let iaAddrSubOptLen = 4 + DHCPv6Constants.iaAddrFixedSize
        let iaNAOptLen = 4 + DHCPv6Constants.iaNAHeaderSize + iaAddrSubOptLen
        let elapsedTimeOptLen = 4 + 2

        // IA_TA with addresses
        let iaTAOptLen: Int
        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            let taAddrSubOptLen = data.iata.addresses.count * (4 + DHCPv6Constants.iaAddrFixedSize)
            iaTAOptLen = 4 + DHCPv6Constants.iaTAHeaderSize + taAddrSubOptLen
        } else {
            iaTAOptLen = 0
        }

        // IA_PD with prefixes
        let iaPDOptLen: Int
        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            let pdPrefixSubOptLen = data.iapd.prefixes.count * (4 + DHCPv6Constants.iaPrefixFixedSize)
            iaPDOptLen = 4 + DHCPv6Constants.iaPDHeaderSize + pdPrefixSubOptLen
        } else {
            iaPDOptLen = 0
        }

        let totalOptLen = clientIDOptLen + iaNAOptLen + elapsedTimeOptLen
                        + iaTAOptLen + iaPDOptLen

        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        if data.tries == 0 {
            data.xid = UInt32.random(in: 0...0xFFFFFF)
        }

        let p = pbuf.payload

        // REBIND does not include Server ID (sent to all servers)
        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.rebind.rawValue, xid: data.xid)
        msgHdr.write(to: p)

        var offset = DHCPv6MessageHeader.length
        offset = writeClientIDOption(to: p, at: offset, data: data)
        offset = writeIANAOption(to: p, at: offset, data: data, includeAddress: true)

        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            offset = writeIATAOption(to: p, at: offset, data: data, includeAddresses: true)
        }

        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            offset = writeIAPDOption(to: p, at: offset, data: data, includePrefixes: true)
        }

        offset = writeElapsedTimeOption(to: p, at: offset, data: data)

        sendMessage(pbuf, netif: netif)

        setState(data, to: .rebinding)
        if data.tries < 255 {
            data.tries += 1
        }
        setRetransmitTimeout(data: data,
                             baseSeconds: DHCPv6Constants.rebTimeout,
                             maxSeconds: DHCPv6Constants.rebMaxRetransmitTimeout)
    }

    /// Send a RELEASE message to relinquish the assigned address.
    private static func sendRelease(netif: NetworkInterface, data: DHCPv6Data) {
        let clientIDOptLen = 4 + data.clientDUID.count
        let serverIDOptLen = 4 + data.serverID.count
        let iaAddrSubOptLen = 4 + DHCPv6Constants.iaAddrFixedSize
        let iaNAOptLen = 4 + DHCPv6Constants.iaNAHeaderSize + iaAddrSubOptLen

        // IA_TA with addresses for release
        let iaTAOptLen: Int
        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            let taAddrSubOptLen = data.iata.addresses.count * (4 + DHCPv6Constants.iaAddrFixedSize)
            iaTAOptLen = 4 + DHCPv6Constants.iaTAHeaderSize + taAddrSubOptLen
        } else {
            iaTAOptLen = 0
        }

        // IA_PD with prefixes for release
        let iaPDOptLen: Int
        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            let pdPrefixSubOptLen = data.iapd.prefixes.count * (4 + DHCPv6Constants.iaPrefixFixedSize)
            iaPDOptLen = 4 + DHCPv6Constants.iaPDHeaderSize + pdPrefixSubOptLen
        } else {
            iaPDOptLen = 0
        }

        let totalOptLen = clientIDOptLen + serverIDOptLen + iaNAOptLen + iaTAOptLen + iaPDOptLen

        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        data.xid = UInt32.random(in: 0...0xFFFFFF)

        let p = pbuf.payload

        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.release.rawValue, xid: data.xid)
        msgHdr.write(to: p)

        var offset = DHCPv6MessageHeader.length
        offset = writeClientIDOption(to: p, at: offset, data: data)
        offset = writeServerIDOption(to: p, at: offset, data: data)
        offset = writeIANAOption(to: p, at: offset, data: data, includeAddress: true)

        if data.requestTemporaryAddresses && !data.iata.addresses.isEmpty {
            offset = writeIATAOption(to: p, at: offset, data: data, includeAddresses: true)
        }

        if data.requestPrefixDelegation && !data.iapd.prefixes.isEmpty {
            offset = writeIAPDOption(to: p, at: offset, data: data, includePrefixes: true)
        }

        sendMessage(pbuf, netif: netif)

        // Notify about prefix expiry on release
        if data.requestPrefixDelegation {
            notifyPrefixExpiry(netif: netif, data: data)
        }

        setState(data, to: .releasing)
    }

    // MARK: - Stateful Response Handling

    /// Handle an ADVERTISE message received in response to SOLICIT.
    ///
    /// Selects the best server offer based on preference and transitions
    /// to REQUEST.
    private static func handleAdvertise(netif: NetworkInterface, pbuf: Pbuf,
                                        data: DHCPv6Data, parsed: DHCPv6ParsedReply) {
        guard data.state == .soliciting else { return }

        // Extract server ID
        guard let serverIDInfo = parsed.serverID else { return }
        let serverIDBytes = extractBytes(from: pbuf, info: serverIDInfo)

        // Extract preference (if present)
        let preference = parsed.preference?.isGiven == true
            ? pbuf.getByte(at: Int(parsed.preference!.valueStart))
            : UInt8(0)

        // Extract IA_NA data from the ADVERTISE
        guard let ianaResult = parseIANA(from: pbuf, info: parsed.iaNA) else { return }

        // Accept this offer if it is better than any previous one
        if !data.hasAdvertise || preference > data.serverPreference {
            data.serverID = serverIDBytes
            data.serverPreference = preference
            data.iana.address = ianaResult.address
            data.iana.t1 = ianaResult.t1
            data.iana.t2 = ianaResult.t2
            data.iana.preferredLifetime = ianaResult.preferredLifetime
            data.iana.validLifetime = ianaResult.validLifetime
            data.hasAdvertise = true

            // Parse IA_TA from ADVERTISE if present
            if data.requestTemporaryAddresses {
                if let iataResult = parseIATA(from: pbuf, info: parsed.iaTA) {
                    data.iata.iaid = iataResult.iaid
                    data.iata.addresses = iataResult.addresses
                    data.iata.preferredLifetimes = iataResult.preferredLifetimes
                    data.iata.validLifetimes = iataResult.validLifetimes
                }
            }

            // Parse IA_PD from ADVERTISE if present
            if data.requestPrefixDelegation {
                if let iapdResult = parseIAPD(from: pbuf, info: parsed.iaPD) {
                    data.iapd.iaid = iapdResult.iaid
                    data.iapd.t1 = iapdResult.t1
                    data.iapd.t2 = iapdResult.t2
                    data.iapd.prefixes = iapdResult.prefixes
                }
            }
        }

        // If preference is 255, use immediately per RFC 3315 section 17.1.2
        // Otherwise, wait for timeout to allow collecting more offers
        if preference == 255 || data.tries > 1 {
            sendRequest(netif: netif, data: data)
        }
        // Otherwise the solicitation timeout will trigger sendRequest
    }

    /// Handle a REPLY message received in response to REQUEST, RENEW, REBIND, or RELEASE.
    private static func handleReply(netif: NetworkInterface, pbuf: Pbuf,
                                    data: DHCPv6Data, parsed: DHCPv6ParsedReply) {
        // Check status code if present
        if let statusInfo = parsed.statusCode, statusInfo.isGiven {
            let statusCode = pbuf.getUInt16(at: Int(statusInfo.valueStart))
            if statusCode != DHCPv6Constants.statusSuccess {
                // Server rejected our request; go back to soliciting
                if data.state == .requesting || data.state == .soliciting {
                    setState(data, to: .statefulIdle)
                    sendSolicit(netif: netif, data: data)
                }
                return
            }
        }

        switch data.state {
        case .soliciting:
            // Rapid Commit: server replied directly to SOLICIT with a REPLY
            // This only happens if we sent Rapid Commit and the server supports it.
            guard data.rapidCommitEnabled else { return }
            guard parsed.rapidCommit != nil else { return }

            // Server confirmed Rapid Commit -- skip REQUEST, go directly to BOUND
            data.rapidCommitConfirmed = true

            // Process like a normal reply to REQUEST
            guard let ianaResult = parseIANA(from: pbuf, info: parsed.iaNA) else {
                setState(data, to: .statefulIdle)
                sendSolicit(netif: netif, data: data)
                return
            }

            if let serverIDInfo = parsed.serverID {
                data.serverID = extractBytes(from: pbuf, info: serverIDInfo)
            }

            applyIANAResult(ianaResult, netif: netif, data: data)
            applyIATAFromReply(pbuf: pbuf, parsed: parsed, netif: netif, data: data)
            applyIAPDFromReply(pbuf: pbuf, parsed: parsed, netif: netif, data: data)
            handleConfigReply(netif: netif, parsed: parsed, pbuf: pbuf)

        case .requesting, .renewing, .rebinding:
            // Extract IA_NA with address
            guard let ianaResult = parseIANA(from: pbuf, info: parsed.iaNA) else {
                // No valid IA_NA in reply -- restart
                setState(data, to: .statefulIdle)
                sendSolicit(netif: netif, data: data)
                return
            }

            // Update server ID from reply if present
            if let serverIDInfo = parsed.serverID {
                data.serverID = extractBytes(from: pbuf, info: serverIDInfo)
            }

            applyIANAResult(ianaResult, netif: netif, data: data)
            applyIATAFromReply(pbuf: pbuf, parsed: parsed, netif: netif, data: data)
            applyIAPDFromReply(pbuf: pbuf, parsed: parsed, netif: netif, data: data)

            // Also handle DNS config if present in reply
            handleConfigReply(netif: netif, parsed: parsed, pbuf: pbuf)

        case .releasing:
            // Release acknowledged -- go to idle
            if data.requestPrefixDelegation {
                notifyPrefixExpiry(netif: netif, data: data)
            }
            setState(data, to: .statefulIdle)

        default:
            break
        }
    }

    /// Apply parsed IA_NA result to client data: store address, set timers, transition to bound.
    private static func applyIANAResult(_ ianaResult: IANAParseResult,
                                         netif: NetworkInterface, data: DHCPv6Data) {
        // Store the assigned address and timers
        data.iana.address = ianaResult.address
        data.iana.t1 = ianaResult.t1
        data.iana.t2 = ianaResult.t2
        data.iana.preferredLifetime = ianaResult.preferredLifetime
        data.iana.validLifetime = ianaResult.validLifetime

        // Apply T1/T2 defaults per RFC 3315 section 22.4
        if data.iana.t1 == 0 && data.iana.t2 == 0 && data.iana.validLifetime != 0xFFFF_FFFF {
            data.iana.t1 = data.iana.preferredLifetime / 2
            data.iana.t2 = (data.iana.preferredLifetime * 4) / 5
        }

        // Assign address to network interface
        assignAddress(netif: netif, data: data)

        // Set lease timers (convert seconds to timer ticks)
        let ticksPerSecond = UInt32(1000 / DHCPv6Constants.timerMilliseconds)
        if data.iana.t1 != 0 && data.iana.t1 != 0xFFFF_FFFF {
            data.t1Timeout = data.iana.t1 * ticksPerSecond
        } else {
            data.t1Timeout = 0
        }
        if data.iana.t2 != 0 && data.iana.t2 != 0xFFFF_FFFF {
            data.t2Timeout = data.iana.t2 * ticksPerSecond
        } else {
            data.t2Timeout = 0
        }
        if data.iana.validLifetime != 0xFFFF_FFFF {
            data.leaseTimeout = data.iana.validLifetime * ticksPerSecond
        } else {
            data.leaseTimeout = 0
        }

        setState(data, to: .bound)
    }

    /// Apply IA_TA (temporary addresses) from a parsed reply.
    private static func applyIATAFromReply(pbuf: Pbuf, parsed: DHCPv6ParsedReply,
                                            netif: NetworkInterface, data: DHCPv6Data) {
        guard data.requestTemporaryAddresses else { return }
        guard let iataResult = parseIATA(from: pbuf, info: parsed.iaTA) else { return }

        let isRenewal = !data.iata.addresses.isEmpty

        data.iata.iaid = iataResult.iaid
        data.iata.addresses = iataResult.addresses
        data.iata.preferredLifetimes = iataResult.preferredLifetimes
        data.iata.validLifetimes = iataResult.validLifetimes

        // Assign temporary addresses to the interface
        assignTemporaryAddresses(netif: netif, data: data)

        // Set temporary lease timeout to the shortest valid lifetime
        let ticksPerSecond = UInt32(1000 / DHCPv6Constants.timerMilliseconds)
        var shortestValid: UInt32 = 0xFFFF_FFFF
        for vl in data.iata.validLifetimes {
            if vl < shortestValid && vl != 0 {
                shortestValid = vl
            }
        }
        if shortestValid != 0xFFFF_FFFF && shortestValid != 0 {
            data.temporaryLeaseTimeout = shortestValid * ticksPerSecond
        } else {
            data.temporaryLeaseTimeout = 0
        }

        _ = isRenewal // Renewal vs initial assignment tracked implicitly by timer reset
    }

    /// Apply IA_PD (prefix delegation) from a parsed reply.
    private static func applyIAPDFromReply(pbuf: Pbuf, parsed: DHCPv6ParsedReply,
                                            netif: NetworkInterface, data: DHCPv6Data) {
        guard data.requestPrefixDelegation else { return }
        guard let iapdResult = parseIAPD(from: pbuf, info: parsed.iaPD) else { return }

        let oldPrefixes = data.iapd.prefixes
        let isRenewal = !oldPrefixes.isEmpty

        data.iapd.iaid = iapdResult.iaid
        data.iapd.t1 = iapdResult.t1
        data.iapd.t2 = iapdResult.t2
        data.iapd.prefixes = iapdResult.prefixes

        // Apply T1/T2 defaults for IA_PD (same logic as IA_NA)
        if data.iapd.t1 == 0 && data.iapd.t2 == 0 {
            var shortestPreferred: UInt32 = 0xFFFF_FFFF
            for pfx in data.iapd.prefixes {
                if pfx.preferredLifetime < shortestPreferred && pfx.preferredLifetime != 0 {
                    shortestPreferred = pfx.preferredLifetime
                }
            }
            if shortestPreferred != 0xFFFF_FFFF {
                data.iapd.t1 = shortestPreferred / 2
                data.iapd.t2 = (shortestPreferred * 4) / 5
            }
        }

        // Set PD lease timers
        let ticksPerSecond = UInt32(1000 / DHCPv6Constants.timerMilliseconds)
        if data.iapd.t1 != 0 && data.iapd.t1 != 0xFFFF_FFFF {
            data.pdT1Timeout = data.iapd.t1 * ticksPerSecond
        } else {
            data.pdT1Timeout = 0
        }
        if data.iapd.t2 != 0 && data.iapd.t2 != 0xFFFF_FFFF {
            data.pdT2Timeout = data.iapd.t2 * ticksPerSecond
        } else {
            data.pdT2Timeout = 0
        }

        var shortestValid: UInt32 = 0xFFFF_FFFF
        for pfx in data.iapd.prefixes {
            if pfx.validLifetime < shortestValid && pfx.validLifetime != 0 {
                shortestValid = pfx.validLifetime
            }
        }
        if shortestValid != 0xFFFF_FFFF && shortestValid != 0 {
            data.pdLeaseTimeout = shortestValid * ticksPerSecond
        } else {
            data.pdLeaseTimeout = 0
        }

        // Notify application about delegated prefixes
        if let callback = data.prefixDelegationCallback {
            let event: DHCPv6PrefixEvent = isRenewal ? .renewed : .delegated
            for pfx in data.iapd.prefixes {
                callback(netif, pfx, event)
            }
        }
    }

    // MARK: - Information Request (Stateless)

    /// Send a DHCPv6 Information Request message.
    private static func requestConfig(on netif: NetworkInterface, data: DHCPv6Data) {
        guard data.state == .statelessIdle || data.state == .requestingConfig else { return }

        // Requested options
        let requestedOptions: [UInt16] = [
            DHCPv6Option.dnsServers.rawValue,
            DHCPv6Option.domainList.rawValue,
        ]

        // Calculate option length: ORO option = 4 header + 2*count
        let oroLen = 4 + 2 * requestedOptions.count
        let totalOptLen = oroLen

        // Create message
        let msgLen = DHCPv6MessageHeader.length + totalOptLen
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(msgLen), type: .ram) else {
            return
        }

        // Generate new XID on first try
        if data.tries == 0 {
            data.xid = UInt32.random(in: 0...0xFFFFFF)
        }

        let p = pbuf.payload

        // Write message header
        let msgHdr = DHCPv6MessageHeader(messageType: DHCPv6MessageType.informationRequest.rawValue,
                                          xid: data.xid)
        msgHdr.write(to: p)

        // Write Option Request option
        var optOffset = DHCPv6MessageHeader.length
        // Option code (ORO = 6)
        p.storeBytes(of: DHCPv6Option.optionRequest.rawValue.bigEndian,
                     toByteOffset: optOffset, as: UInt16.self)
        optOffset += 2
        // Option length
        p.storeBytes(of: UInt16(2 * requestedOptions.count).bigEndian,
                     toByteOffset: optOffset, as: UInt16.self)
        optOffset += 2
        // Requested options
        for opt in requestedOptions {
            p.storeBytes(of: opt.bigEndian, toByteOffset: optOffset, as: UInt16.self)
            optOffset += 2
        }

        sendMessage(pbuf, netif: netif)

        setState(data, to: .requestingConfig)
        if data.tries < 255 {
            data.tries += 1
        }
        // Exponential backoff timeout
        let msecs = UInt16(min(UInt32(data.tries < 6 ? 1 << data.tries : 60) * 1000, UInt32(UInt16.max)))
        data.requestTimeout = (msecs + DHCPv6Constants.timerMilliseconds - 1) / DHCPv6Constants.timerMilliseconds
    }

    // MARK: - Reply Processing

    /// Parsed DHCPv6 options from a received message.
    struct DHCPv6ParsedReply {
        var clientID: DHCPv6OptionInfo?
        var serverID: DHCPv6OptionInfo?
        var iaNA: DHCPv6OptionInfo?
        var iaTA: DHCPv6OptionInfo?
        var iaPD: DHCPv6OptionInfo?
        var preference: DHCPv6OptionInfo?
        var statusCode: DHCPv6OptionInfo?
        var rapidCommit: DHCPv6OptionInfo?
        var dnsServer: DHCPv6OptionInfo?
        var domainList: DHCPv6OptionInfo?
        var sntpServer: DHCPv6OptionInfo?
    }

    /// Parsed IA_NA result containing address and lifetime information.
    struct IANAParseResult {
        var iaid: UInt32
        var t1: UInt32
        var t2: UInt32
        var address: IPv6Address
        var preferredLifetime: UInt32
        var validLifetime: UInt32
    }

    /// Parsed IA_TA result containing temporary address information.
    struct IATAParseResult {
        var iaid: UInt32
        var addresses: [IPv6Address]
        var preferredLifetimes: [UInt32]
        var validLifetimes: [UInt32]
    }

    /// Parsed IA_PD result containing prefix delegation information.
    struct IAPDParseResult {
        var iaid: UInt32
        var t1: UInt32
        var t2: UInt32
        var prefixes: [DHCPv6IAPrefix]
    }

    /// Parse all options from a DHCPv6 message.
    static func parseFullReply(_ pbuf: Pbuf) -> DHCPv6ParsedReply {
        var result = DHCPv6ParsedReply()

        var offset = DHCPv6MessageHeader.length
        let maxOffset = pbuf.totalLength

        while offset + 4 <= maxOffset {
            let optCode = pbuf.getUInt16(at: offset)
            let optLen = pbuf.getUInt16(at: offset + 2)
            let valOffset = offset + 4

            guard valOffset + Int(optLen) <= maxOffset else { break }

            switch optCode {
            case DHCPv6Option.clientID.rawValue:
                result.clientID = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.serverID.rawValue:
                result.serverID = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.iaNA.rawValue:
                result.iaNA = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.preference.rawValue:
                result.preference = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.statusCode.rawValue:
                result.statusCode = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.dnsServers.rawValue:
                result.dnsServer = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.domainList.rawValue:
                result.domainList = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.iaTA.rawValue:
                result.iaTA = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.iaPD.rawValue:
                result.iaPD = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.rapidCommit.rawValue:
                result.rapidCommit = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            case DHCPv6Option.sntpServers.rawValue:
                result.sntpServer = DHCPv6OptionInfo(isGiven: true, valueStart: UInt16(valOffset), valueLength: optLen)
            default:
                break
            }

            offset = valOffset + Int(optLen)
        }

        return result
    }

    /// Parse a DHCPv6 reply message and extract options (legacy stateless interface).
    static func parseReply(_ pbuf: Pbuf, data: DHCPv6Data) -> (clientID: DHCPv6OptionInfo?,
                                                                 serverID: DHCPv6OptionInfo?,
                                                                 dnsServer: DHCPv6OptionInfo?,
                                                                 domainList: DHCPv6OptionInfo?) {
        let parsed = parseFullReply(pbuf)
        return (parsed.clientID, parsed.serverID, parsed.dnsServer, parsed.domainList)
    }

    /// Main receive handler for DHCPv6 messages.
    ///
    /// Call this from the UDP receive callback when a packet arrives on the
    /// DHCPv6 client port. Dispatches to the appropriate handler based on
    /// message type and current client state.
    public static func recv(on netif: NetworkInterface, pbuf: Pbuf) {
        guard let data = netif.dhcp6Data else { return }
        guard data.state != .off else { return }

        // Minimum message size check
        guard pbuf.totalLength >= DHCPv6MessageHeader.length else { return }

        // Match transaction ID
        let rxXid = (UInt32(pbuf.getByte(at: 1)) << 16)
                   | (UInt32(pbuf.getByte(at: 2)) << 8)
                   | UInt32(pbuf.getByte(at: 3))
        guard rxXid == data.xid else { return }

        let msgType = pbuf.getByte(at: 0)
        let parsed = parseFullReply(pbuf)

        switch msgType {
        case DHCPv6MessageType.advertise.rawValue:
            handleAdvertise(netif: netif, pbuf: pbuf, data: data, parsed: parsed)

        case DHCPv6MessageType.reply.rawValue:
            if data.state == .requestingConfig {
                // Stateless: reply to information request
                setState(data, to: .statelessIdle)
                handleConfigReply(netif: netif, parsed: parsed, pbuf: pbuf)
            } else if isStatefulEnabled(data) {
                // Stateful: reply to request/renew/rebind/release
                handleReply(netif: netif, pbuf: pbuf, data: data, parsed: parsed)
            }

        default:
            break
        }
    }

    // MARK: - Private Helpers

    private static func getOrCreateData(for netif: NetworkInterface) -> DHCPv6Data? {
        if let existing = netif.dhcp6Data {
            return existing
        }
        let data = DHCPv6Data()
        netif.dhcp6Data = data
        return data
    }

    private static func setState(_ data: DHCPv6Data, to newState: DHCPv6State) {
        if newState != data.state {
            data.state = newState
            data.tries = 0
            data.requestTimeout = 0
        }
    }

    private static func isStatelessEnabled(_ data: DHCPv6Data) -> Bool {
        data.state == .statelessIdle || data.state == .requestingConfig
    }

    private static func isStatefulEnabled(_ data: DHCPv6Data) -> Bool {
        switch data.state {
        case .off, .statelessIdle, .requestingConfig:
            return false
        default:
            return true
        }
    }

    private static func abortConfigRequest(_ data: DHCPv6Data) {
        if data.state == .requestingConfig {
            setState(data, to: .statelessIdle)
        }
    }

    // MARK: - Client DUID Generation

    /// Generate a DUID-LL (Link-Layer) from the interface hardware address.
    ///
    /// Format: DUID type (2 bytes) + hardware type (2 bytes) + link-layer address (variable).
    private static func generateClientDUID(data: DHCPv6Data, netif: NetworkInterface) {
        var duid = [UInt8]()
        // DUID type: DUID-LL = 3 (big-endian)
        duid.append(UInt8((DHCPv6Constants.duidTypeLL >> 8) & 0xFF))
        duid.append(UInt8(DHCPv6Constants.duidTypeLL & 0xFF))
        // Hardware type: Ethernet = 1 (big-endian)
        duid.append(UInt8((DHCPv6Constants.hwTypeEthernet >> 8) & 0xFF))
        duid.append(UInt8(DHCPv6Constants.hwTypeEthernet & 0xFF))
        // Link-layer address
        for i in 0..<Int(netif.hwAddrLen) {
            duid.append(netif.hwAddr[i])
        }
        data.clientDUID = duid
    }

    // MARK: - Option Writing Helpers

    /// Write a Client ID option. Returns the new offset.
    @discardableResult
    private static func writeClientIDOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                            data: DHCPv6Data) -> Int {
        var off = offset
        // Option code
        p.storeBytes(of: DHCPv6Option.clientID.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        // Option length
        p.storeBytes(of: UInt16(data.clientDUID.count).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        // DUID data
        for byte in data.clientDUID {
            p.storeBytes(of: byte, toByteOffset: off, as: UInt8.self)
            off += 1
        }
        return off
    }

    /// Write a Server ID option. Returns the new offset.
    @discardableResult
    private static func writeServerIDOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                            data: DHCPv6Data) -> Int {
        var off = offset
        p.storeBytes(of: DHCPv6Option.serverID.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(data.serverID.count).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        for byte in data.serverID {
            p.storeBytes(of: byte, toByteOffset: off, as: UInt8.self)
            off += 1
        }
        return off
    }

    /// Write an IA_NA option, optionally including an IA Address sub-option. Returns the new offset.
    @discardableResult
    private static func writeIANAOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                        data: DHCPv6Data, includeAddress: Bool) -> Int {
        var off = offset
        let iaAddrSubOptLen = includeAddress ? (4 + DHCPv6Constants.iaAddrFixedSize) : 0
        let iaNALen = DHCPv6Constants.iaNAHeaderSize + iaAddrSubOptLen

        // IA_NA option header
        p.storeBytes(of: DHCPv6Option.iaNA.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(iaNALen).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2

        // IAID (4 bytes)
        p.storeBytes(of: data.iana.iaid.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4
        // T1 (4 bytes)
        p.storeBytes(of: data.iana.t1.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4
        // T2 (4 bytes)
        p.storeBytes(of: data.iana.t2.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4

        if includeAddress {
            // IA Address sub-option
            p.storeBytes(of: DHCPv6Option.iaAddr.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
            off += 2
            p.storeBytes(of: UInt16(DHCPv6Constants.iaAddrFixedSize).bigEndian, toByteOffset: off, as: UInt16.self)
            off += 2
            // IPv6 address (16 bytes, in network order)
            p.storeBytes(of: data.iana.address.addr.0, toByteOffset: off, as: UInt32.self)
            off += 4
            p.storeBytes(of: data.iana.address.addr.1, toByteOffset: off, as: UInt32.self)
            off += 4
            p.storeBytes(of: data.iana.address.addr.2, toByteOffset: off, as: UInt32.self)
            off += 4
            p.storeBytes(of: data.iana.address.addr.3, toByteOffset: off, as: UInt32.self)
            off += 4
            // Preferred lifetime
            p.storeBytes(of: data.iana.preferredLifetime.bigEndian, toByteOffset: off, as: UInt32.self)
            off += 4
            // Valid lifetime
            p.storeBytes(of: data.iana.validLifetime.bigEndian, toByteOffset: off, as: UInt32.self)
            off += 4
        }

        return off
    }

    /// Write an Elapsed Time option. Returns the new offset.
    @discardableResult
    private static func writeElapsedTimeOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                               data: DHCPv6Data) -> Int {
        var off = offset
        p.storeBytes(of: DHCPv6Option.elapsedTime.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(2).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        // Elapsed time in hundredths of a second (simplified: report 0)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        return off
    }

    /// Write an Option Request option. Returns the new offset.
    @discardableResult
    private static func writeOptionRequestOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                                 options: [UInt16]) -> Int {
        var off = offset
        p.storeBytes(of: DHCPv6Option.optionRequest.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(2 * options.count).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        for opt in options {
            p.storeBytes(of: opt.bigEndian, toByteOffset: off, as: UInt16.self)
            off += 2
        }
        return off
    }

    /// Write an IA_TA option, optionally including IA Address sub-options. Returns the new offset.
    @discardableResult
    private static func writeIATAOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                        data: DHCPv6Data, includeAddresses: Bool) -> Int {
        var off = offset
        var iaAddrSubOptLen = 0
        if includeAddresses {
            iaAddrSubOptLen = data.iata.addresses.count * (4 + DHCPv6Constants.iaAddrFixedSize)
        }
        let iaTALen = DHCPv6Constants.iaTAHeaderSize + iaAddrSubOptLen

        // IA_TA option header
        p.storeBytes(of: DHCPv6Option.iaTA.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(iaTALen).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2

        // IAID (4 bytes)
        p.storeBytes(of: data.iata.iaid.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4

        if includeAddresses {
            for i in 0..<data.iata.addresses.count {
                let addr = data.iata.addresses[i]
                let preferred = i < data.iata.preferredLifetimes.count ? data.iata.preferredLifetimes[i] : 0
                let valid = i < data.iata.validLifetimes.count ? data.iata.validLifetimes[i] : 0

                // IA Address sub-option
                p.storeBytes(of: DHCPv6Option.iaAddr.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
                off += 2
                p.storeBytes(of: UInt16(DHCPv6Constants.iaAddrFixedSize).bigEndian, toByteOffset: off, as: UInt16.self)
                off += 2
                // IPv6 address (16 bytes)
                p.storeBytes(of: addr.addr.0, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: addr.addr.1, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: addr.addr.2, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: addr.addr.3, toByteOffset: off, as: UInt32.self)
                off += 4
                // Preferred lifetime
                p.storeBytes(of: preferred.bigEndian, toByteOffset: off, as: UInt32.self)
                off += 4
                // Valid lifetime
                p.storeBytes(of: valid.bigEndian, toByteOffset: off, as: UInt32.self)
                off += 4
            }
        }

        return off
    }

    /// Write an IA_PD option, optionally including IA Prefix sub-options. Returns the new offset.
    @discardableResult
    private static func writeIAPDOption(to p: UnsafeMutableRawPointer, at offset: Int,
                                        data: DHCPv6Data, includePrefixes: Bool) -> Int {
        var off = offset
        var iaPrefixSubOptLen = 0
        if includePrefixes {
            iaPrefixSubOptLen = data.iapd.prefixes.count * (4 + DHCPv6Constants.iaPrefixFixedSize)
        }
        let iaPDLen = DHCPv6Constants.iaPDHeaderSize + iaPrefixSubOptLen

        // IA_PD option header
        p.storeBytes(of: DHCPv6Option.iaPD.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        p.storeBytes(of: UInt16(iaPDLen).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2

        // IAID (4 bytes)
        p.storeBytes(of: data.iapd.iaid.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4
        // T1 (4 bytes)
        p.storeBytes(of: data.iapd.t1.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4
        // T2 (4 bytes)
        p.storeBytes(of: data.iapd.t2.bigEndian, toByteOffset: off, as: UInt32.self)
        off += 4

        if includePrefixes {
            for pfx in data.iapd.prefixes {
                // IA Prefix sub-option (option code 26)
                p.storeBytes(of: DHCPv6Option.iaPrefix.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
                off += 2
                p.storeBytes(of: UInt16(DHCPv6Constants.iaPrefixFixedSize).bigEndian, toByteOffset: off, as: UInt16.self)
                off += 2
                // Preferred lifetime (4 bytes)
                p.storeBytes(of: pfx.preferredLifetime.bigEndian, toByteOffset: off, as: UInt32.self)
                off += 4
                // Valid lifetime (4 bytes)
                p.storeBytes(of: pfx.validLifetime.bigEndian, toByteOffset: off, as: UInt32.self)
                off += 4
                // Prefix length (1 byte)
                p.storeBytes(of: pfx.prefixLength, toByteOffset: off, as: UInt8.self)
                off += 1
                // IPv6 prefix (16 bytes)
                p.storeBytes(of: pfx.prefix.addr.0, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: pfx.prefix.addr.1, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: pfx.prefix.addr.2, toByteOffset: off, as: UInt32.self)
                off += 4
                p.storeBytes(of: pfx.prefix.addr.3, toByteOffset: off, as: UInt32.self)
                off += 4
            }
        }

        return off
    }

    /// Write a Rapid Commit option (zero-length option, code 14). Returns the new offset.
    @discardableResult
    private static func writeRapidCommitOption(to p: UnsafeMutableRawPointer, at offset: Int) -> Int {
        var off = offset
        p.storeBytes(of: DHCPv6Option.rapidCommit.rawValue.bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        // Length = 0 (Rapid Commit has no data)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: off, as: UInt16.self)
        off += 2
        return off
    }

    // MARK: - DUID Encoding Helpers

    /// Encode a DUID-LL (Link-Layer, type 3) from a hardware address.
    ///
    /// Format: DUID type (2 bytes) + hardware type (2 bytes) + link-layer address (variable).
    ///
    /// - Parameters:
    ///   - hardwareType: The hardware type (e.g. 1 for Ethernet).
    ///   - linkLayerAddress: The link-layer (MAC) address bytes.
    /// - Returns: The encoded DUID bytes.
    public static func encodeDUIDLL(hardwareType: UInt16 = DHCPv6Constants.hwTypeEthernet,
                                    linkLayerAddress: [UInt8]) -> [UInt8] {
        var duid = [UInt8]()
        duid.reserveCapacity(4 + linkLayerAddress.count)
        // DUID type: DUID-LL = 3 (big-endian)
        duid.append(UInt8((DHCPv6Constants.duidTypeLL >> 8) & 0xFF))
        duid.append(UInt8(DHCPv6Constants.duidTypeLL & 0xFF))
        // Hardware type (big-endian)
        duid.append(UInt8((hardwareType >> 8) & 0xFF))
        duid.append(UInt8(hardwareType & 0xFF))
        // Link-layer address
        duid.append(contentsOf: linkLayerAddress)
        return duid
    }

    /// Encode a DUID-LLT (Link-Layer + Time, type 1) from a hardware address and time value.
    ///
    /// Format: DUID type (2 bytes) + hardware type (2 bytes) + time (4 bytes) + link-layer address (variable).
    /// The time value is seconds since midnight January 1, 2000 UTC.
    ///
    /// - Parameters:
    ///   - hardwareType: The hardware type (e.g. 1 for Ethernet).
    ///   - time: Seconds since midnight January 1, 2000 UTC.
    ///   - linkLayerAddress: The link-layer (MAC) address bytes.
    /// - Returns: The encoded DUID bytes.
    public static func encodeDUIDLLT(hardwareType: UInt16 = DHCPv6Constants.hwTypeEthernet,
                                     time: UInt32,
                                     linkLayerAddress: [UInt8]) -> [UInt8] {
        var duid = [UInt8]()
        duid.reserveCapacity(8 + linkLayerAddress.count)
        // DUID type: DUID-LLT = 1 (big-endian)
        duid.append(UInt8((DHCPv6Constants.duidTypeLLT >> 8) & 0xFF))
        duid.append(UInt8(DHCPv6Constants.duidTypeLLT & 0xFF))
        // Hardware type (big-endian)
        duid.append(UInt8((hardwareType >> 8) & 0xFF))
        duid.append(UInt8(hardwareType & 0xFF))
        // Time (big-endian, 4 bytes)
        duid.append(UInt8((time >> 24) & 0xFF))
        duid.append(UInt8((time >> 16) & 0xFF))
        duid.append(UInt8((time >> 8) & 0xFF))
        duid.append(UInt8(time & 0xFF))
        // Link-layer address
        duid.append(contentsOf: linkLayerAddress)
        return duid
    }

    /// Encode an IA_NA option into a byte array suitable for embedding in a DHCPv6 message.
    ///
    /// - Parameters:
    ///   - iaid: The Identity Association Identifier.
    ///   - t1: The T1 renewal time in seconds.
    ///   - t2: The T2 rebind time in seconds.
    /// - Returns: The encoded IA_NA option bytes (without the option header).
    public static func encodeIANA(iaid: UInt32, t1: UInt32, t2: UInt32) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(12)
        // IAID (4 bytes, big-endian)
        bytes.append(UInt8((iaid >> 24) & 0xFF))
        bytes.append(UInt8((iaid >> 16) & 0xFF))
        bytes.append(UInt8((iaid >> 8) & 0xFF))
        bytes.append(UInt8(iaid & 0xFF))
        // T1 (4 bytes, big-endian)
        bytes.append(UInt8((t1 >> 24) & 0xFF))
        bytes.append(UInt8((t1 >> 16) & 0xFF))
        bytes.append(UInt8((t1 >> 8) & 0xFF))
        bytes.append(UInt8(t1 & 0xFF))
        // T2 (4 bytes, big-endian)
        bytes.append(UInt8((t2 >> 24) & 0xFF))
        bytes.append(UInt8((t2 >> 16) & 0xFF))
        bytes.append(UInt8((t2 >> 8) & 0xFF))
        bytes.append(UInt8(t2 & 0xFF))
        return bytes
    }

    /// Encode an IA_TA option into a byte array suitable for embedding in a DHCPv6 message.
    ///
    /// - Parameter iaid: The Identity Association Identifier.
    /// - Returns: The encoded IA_TA option bytes (without the option header).
    public static func encodeIATA(iaid: UInt32) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(4)
        // IAID (4 bytes, big-endian)
        bytes.append(UInt8((iaid >> 24) & 0xFF))
        bytes.append(UInt8((iaid >> 16) & 0xFF))
        bytes.append(UInt8((iaid >> 8) & 0xFF))
        bytes.append(UInt8(iaid & 0xFF))
        return bytes
    }

    /// Encode an IA_PD option into a byte array suitable for embedding in a DHCPv6 message.
    ///
    /// - Parameters:
    ///   - iaid: The Identity Association Identifier.
    ///   - t1: The T1 renewal time in seconds.
    ///   - t2: The T2 rebind time in seconds.
    /// - Returns: The encoded IA_PD option bytes (without the option header).
    public static func encodeIAPD(iaid: UInt32, t1: UInt32, t2: UInt32) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(12)
        // IAID (4 bytes, big-endian)
        bytes.append(UInt8((iaid >> 24) & 0xFF))
        bytes.append(UInt8((iaid >> 16) & 0xFF))
        bytes.append(UInt8((iaid >> 8) & 0xFF))
        bytes.append(UInt8(iaid & 0xFF))
        // T1 (4 bytes, big-endian)
        bytes.append(UInt8((t1 >> 24) & 0xFF))
        bytes.append(UInt8((t1 >> 16) & 0xFF))
        bytes.append(UInt8((t1 >> 8) & 0xFF))
        bytes.append(UInt8(t1 & 0xFF))
        // T2 (4 bytes, big-endian)
        bytes.append(UInt8((t2 >> 24) & 0xFF))
        bytes.append(UInt8((t2 >> 16) & 0xFF))
        bytes.append(UInt8((t2 >> 8) & 0xFF))
        bytes.append(UInt8(t2 & 0xFF))
        return bytes
    }

    // MARK: - Message Sending

    /// Send a DHCPv6 payload through the UDP layer, then free it.
    private static func sendMessage(_ pbuf: Pbuf, netif: NetworkInterface) {
        let pcb = UDPGlobal.shared.new()
        let bindErr = UDPGlobal.shared.bind(pcb, address: .ipv6Any, port: DHCPv6Constants.clientPort)
        guard bindErr == .ok else {
            pbuf.free()
            return
        }

        defer {
            UDPGlobal.shared.remove(pcb)
            pbuf.free()
        }

        _ = UDPGlobal.shared.sendToIfWithChecksum(
            pcb,
            pbuf: pbuf,
            dstIP: IPAddress.fromIPv6(DHCPv6MulticastAddress.allRelayAgentsAndServers),
            dstPort: DHCPv6Constants.serverPort,
            netif: netif,
            haveChecksum: false,
            checksum: 0
        )
    }

    // MARK: - Timeout Handling

    /// Set retransmit timeout with exponential backoff.
    private static func setRetransmitTimeout(data: DHCPv6Data, baseSeconds: UInt16, maxSeconds: UInt16) {
        let factor: UInt32 = data.tries < 6 ? (1 << UInt32(data.tries)) : UInt32(maxSeconds)
        let seconds = min(UInt32(baseSeconds) * factor, UInt32(maxSeconds))
        let msecs = UInt16(min(seconds * 1000, UInt32(UInt16.max)))
        data.requestTimeout = (msecs + DHCPv6Constants.timerMilliseconds - 1) / DHCPv6Constants.timerMilliseconds
    }

    /// Handle retransmission timeout for all states.
    private static func handleTimeout(on netif: NetworkInterface, data: DHCPv6Data) {
        switch data.state {
        case .requestingConfig:
            // Stateless: retransmit information request
            requestConfig(on: netif, data: data)

        case .soliciting:
            if data.hasAdvertise {
                // We have an offer, transition to REQUEST
                sendRequest(netif: netif, data: data)
            } else {
                // Retransmit SOLICIT
                sendSolicit(netif: netif, data: data)
            }

        case .requesting:
            if data.tries >= DHCPv6Constants.reqMaxRetransmitCount {
                // Max retransmissions exceeded, restart from SOLICIT
                setState(data, to: .statefulIdle)
                sendSolicit(netif: netif, data: data)
            } else {
                sendRequest(netif: netif, data: data)
            }

        case .renewing:
            // Retransmit RENEW
            sendRenew(netif: netif, data: data)

        case .rebinding:
            // Retransmit REBIND
            sendRebind(netif: netif, data: data)

        default:
            break
        }
    }

    /// Handle T1/T2/lease lifetime countdown timers for IA_NA, IA_TA, and IA_PD.
    private static func handleLeaseTimers(on netif: NetworkInterface, data: DHCPv6Data) {
        // Decrement IA_NA lease timeout
        if data.leaseTimeout > 0 {
            data.leaseTimeout -= 1
            if data.leaseTimeout == 0 {
                // Lease expired -- remove addresses and restart
                removeAssignedAddress(netif: netif, data: data)
                if data.requestTemporaryAddresses {
                    removeTemporaryAddresses(netif: netif, data: data)
                }
                if data.requestPrefixDelegation {
                    notifyPrefixExpiry(netif: netif, data: data)
                }
                setState(data, to: .statefulIdle)
                sendSolicit(netif: netif, data: data)
                return
            }
        }

        // Decrement IA_TA lease timeout (temporary addresses have shorter lifetimes)
        if data.requestTemporaryAddresses && data.temporaryLeaseTimeout > 0 {
            data.temporaryLeaseTimeout -= 1
            if data.temporaryLeaseTimeout == 0 {
                // Temporary addresses expired -- remove them;
                // they will be re-requested in the next RENEW/REBIND
                removeTemporaryAddresses(netif: netif, data: data)
                data.iata.addresses = []
                data.iata.preferredLifetimes = []
                data.iata.validLifetimes = []
            }
        }

        // Decrement IA_PD lease timeout
        if data.requestPrefixDelegation && data.pdLeaseTimeout > 0 {
            data.pdLeaseTimeout -= 1
            if data.pdLeaseTimeout == 0 {
                // Delegated prefixes expired
                notifyPrefixExpiry(netif: netif, data: data)
            }
        }

        if data.state == .bound {
            // Check T1 (renew timer) -- considers both IA_NA and IA_PD T1
            var shouldRenew = false
            if data.t1Timeout > 0 {
                data.t1Timeout -= 1
                if data.t1Timeout == 0 {
                    shouldRenew = true
                }
            }
            if data.requestPrefixDelegation && data.pdT1Timeout > 0 {
                data.pdT1Timeout -= 1
                if data.pdT1Timeout == 0 {
                    shouldRenew = true
                }
            }
            if shouldRenew {
                sendRenew(netif: netif, data: data)
                return
            }

            // Check T2 (rebind timer)
            var shouldRebind = false
            if data.t2Timeout > 0 {
                data.t2Timeout -= 1
                if data.t2Timeout == 0 {
                    shouldRebind = true
                }
            }
            if data.requestPrefixDelegation && data.pdT2Timeout > 0 {
                data.pdT2Timeout -= 1
                if data.pdT2Timeout == 0 {
                    shouldRebind = true
                }
            }
            if shouldRebind {
                sendRebind(netif: netif, data: data)
                return
            }
        } else if data.state == .renewing {
            // While renewing, check T2 for rebind
            var shouldRebind = false
            if data.t2Timeout > 0 {
                data.t2Timeout -= 1
                if data.t2Timeout == 0 {
                    shouldRebind = true
                }
            }
            if data.requestPrefixDelegation && data.pdT2Timeout > 0 {
                data.pdT2Timeout -= 1
                if data.pdT2Timeout == 0 {
                    shouldRebind = true
                }
            }
            if shouldRebind {
                sendRebind(netif: netif, data: data)
                return
            }
        }
    }

    // MARK: - IA_NA Parsing

    /// Parse an IA_NA option and extract the first IA Address sub-option.
    private static func parseIANA(from pbuf: Pbuf, info: DHCPv6OptionInfo?) -> IANAParseResult? {
        guard let info = info, info.isGiven else { return nil }
        let start = Int(info.valueStart)
        let length = Int(info.valueLength)

        // IA_NA header: IAID(4) + T1(4) + T2(4) = 12 bytes minimum
        guard length >= DHCPv6Constants.iaNAHeaderSize else { return nil }

        let iaid = pbuf.getUInt32(at: start)
        let t1 = pbuf.getUInt32(at: start + 4)
        let t2 = pbuf.getUInt32(at: start + 8)

        // Parse sub-options to find IA Address
        var subOffset = start + DHCPv6Constants.iaNAHeaderSize
        let endOffset = start + length

        while subOffset + 4 <= endOffset {
            let subOptCode = pbuf.getUInt16(at: subOffset)
            let subOptLen = pbuf.getUInt16(at: subOffset + 2)
            let subValOffset = subOffset + 4

            guard subValOffset + Int(subOptLen) <= endOffset else { break }

            if subOptCode == DHCPv6Option.iaAddr.rawValue
                && subOptLen >= UInt16(DHCPv6Constants.iaAddrFixedSize) {
                // IA Address: IPv6 address (16 bytes) + preferred lifetime (4) + valid lifetime (4)
                let w0 = pbuf.getUInt32NetworkOrder(at: subValOffset)
                let w1 = pbuf.getUInt32NetworkOrder(at: subValOffset + 4)
                let w2 = pbuf.getUInt32NetworkOrder(at: subValOffset + 8)
                let w3 = pbuf.getUInt32NetworkOrder(at: subValOffset + 12)
                let addr = IPv6Address(w0, w1, w2, w3)

                let preferredLifetime = pbuf.getUInt32(at: subValOffset + 16)
                let validLifetime = pbuf.getUInt32(at: subValOffset + 20)

                return IANAParseResult(
                    iaid: iaid, t1: t1, t2: t2,
                    address: addr,
                    preferredLifetime: preferredLifetime,
                    validLifetime: validLifetime
                )
            }

            subOffset = subValOffset + Int(subOptLen)
        }

        return nil
    }

    // MARK: - IA_TA Parsing (RFC 3315 Section 22.5)

    /// Parse an IA_TA option and extract all IA Address sub-options.
    ///
    /// IA_TA has only IAID (4 bytes), no T1/T2 (temporary addresses use the
    /// lifetimes from each IA Address sub-option directly).
    private static func parseIATA(from pbuf: Pbuf, info: DHCPv6OptionInfo?) -> IATAParseResult? {
        guard let info = info, info.isGiven else { return nil }
        let start = Int(info.valueStart)
        let length = Int(info.valueLength)

        // IA_TA header: IAID(4) = 4 bytes minimum
        guard length >= DHCPv6Constants.iaTAHeaderSize else { return nil }

        let iaid = pbuf.getUInt32(at: start)

        var addresses = [IPv6Address]()
        var preferredLifetimes = [UInt32]()
        var validLifetimes = [UInt32]()

        // Parse sub-options to find IA Address entries
        var subOffset = start + DHCPv6Constants.iaTAHeaderSize
        let endOffset = start + length

        while subOffset + 4 <= endOffset {
            let subOptCode = pbuf.getUInt16(at: subOffset)
            let subOptLen = pbuf.getUInt16(at: subOffset + 2)
            let subValOffset = subOffset + 4

            guard subValOffset + Int(subOptLen) <= endOffset else { break }

            if subOptCode == DHCPv6Option.iaAddr.rawValue
                && subOptLen >= UInt16(DHCPv6Constants.iaAddrFixedSize) {
                let w0 = pbuf.getUInt32NetworkOrder(at: subValOffset)
                let w1 = pbuf.getUInt32NetworkOrder(at: subValOffset + 4)
                let w2 = pbuf.getUInt32NetworkOrder(at: subValOffset + 8)
                let w3 = pbuf.getUInt32NetworkOrder(at: subValOffset + 12)
                let addr = IPv6Address(w0, w1, w2, w3)

                let preferredLifetime = pbuf.getUInt32(at: subValOffset + 16)
                let validLifetime = pbuf.getUInt32(at: subValOffset + 20)

                addresses.append(addr)
                preferredLifetimes.append(preferredLifetime)
                validLifetimes.append(validLifetime)

                if addresses.count >= DHCPv6Constants.maxTemporaryAddresses {
                    break
                }
            }

            subOffset = subValOffset + Int(subOptLen)
        }

        guard !addresses.isEmpty else { return nil }

        return IATAParseResult(
            iaid: iaid,
            addresses: addresses,
            preferredLifetimes: preferredLifetimes,
            validLifetimes: validLifetimes
        )
    }

    // MARK: - IA_PD Parsing (RFC 3633)

    /// Parse an IA_PD option and extract all IA Prefix sub-options.
    ///
    /// IA_PD has IAID(4) + T1(4) + T2(4) = 12 bytes header, followed by
    /// IA Prefix sub-options (option code 26).
    private static func parseIAPD(from pbuf: Pbuf, info: DHCPv6OptionInfo?) -> IAPDParseResult? {
        guard let info = info, info.isGiven else { return nil }
        let start = Int(info.valueStart)
        let length = Int(info.valueLength)

        // IA_PD header: IAID(4) + T1(4) + T2(4) = 12 bytes minimum
        guard length >= DHCPv6Constants.iaPDHeaderSize else { return nil }

        let iaid = pbuf.getUInt32(at: start)
        let t1 = pbuf.getUInt32(at: start + 4)
        let t2 = pbuf.getUInt32(at: start + 8)

        var prefixes = [DHCPv6IAPrefix]()

        // Parse sub-options to find IA Prefix entries
        var subOffset = start + DHCPv6Constants.iaPDHeaderSize
        let endOffset = start + length

        while subOffset + 4 <= endOffset {
            let subOptCode = pbuf.getUInt16(at: subOffset)
            let subOptLen = pbuf.getUInt16(at: subOffset + 2)
            let subValOffset = subOffset + 4

            guard subValOffset + Int(subOptLen) <= endOffset else { break }

            if subOptCode == DHCPv6Option.iaPrefix.rawValue
                && subOptLen >= UInt16(DHCPv6Constants.iaPrefixFixedSize) {
                // IA Prefix: preferred-lifetime(4) + valid-lifetime(4) + prefix-length(1) + prefix(16)
                let preferredLifetime = pbuf.getUInt32(at: subValOffset)
                let validLifetime = pbuf.getUInt32(at: subValOffset + 4)
                let prefixLength = pbuf.getByte(at: subValOffset + 8)

                let pw0 = pbuf.getUInt32NetworkOrder(at: subValOffset + 9)
                let pw1 = pbuf.getUInt32NetworkOrder(at: subValOffset + 13)
                let pw2 = pbuf.getUInt32NetworkOrder(at: subValOffset + 17)
                let pw3 = pbuf.getUInt32NetworkOrder(at: subValOffset + 21)
                let prefix = IPv6Address(pw0, pw1, pw2, pw3)

                prefixes.append(DHCPv6IAPrefix(
                    preferredLifetime: preferredLifetime,
                    validLifetime: validLifetime,
                    prefixLength: prefixLength,
                    prefix: prefix
                ))

                if prefixes.count >= DHCPv6Constants.maxDelegatedPrefixes {
                    break
                }
            }

            subOffset = subValOffset + Int(subOptLen)
        }

        guard !prefixes.isEmpty else { return nil }

        return IAPDParseResult(
            iaid: iaid, t1: t1, t2: t2,
            prefixes: prefixes
        )
    }

    // MARK: - DNS Search List Parsing (RFC 3646, Option 24)

    /// Parse OPTION_DOMAIN_LIST (option 24) containing DNS wire format domain names.
    ///
    /// DNS wire format encodes each domain as a sequence of length-prefixed labels,
    /// terminated by a zero-length label. For example: "\x07example\x03com\x00".
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DHCPv6 message.
    ///   - info: The parsed option info for the domain list option.
    /// - Returns: An array of decoded domain name strings.
    static func parseDNSSearchList(from pbuf: Pbuf, info: DHCPv6OptionInfo?) -> [String] {
        guard let info = info, info.isGiven, info.valueLength > 0 else { return [] }

        // Extract the raw bytes for the domain list
        let length = Int(info.valueLength)
        var rawBytes = [UInt8](repeating: 0, count: length)
        rawBytes.withUnsafeMutableBufferPointer { buf in
            _ = pbuf.copyPartial(to: buf.baseAddress!, len: UInt16(length), offset: info.valueStart)
        }

        return decodeDNSWireFormatDomains(rawBytes)
    }

    /// Decode DNS wire format domain names from raw bytes.
    ///
    /// - Parameter data: Raw bytes in DNS wire format.
    /// - Returns: An array of decoded domain name strings.
    public static func decodeDNSWireFormatDomains(_ data: [UInt8]) -> [String] {
        var domains = [String]()
        var offset = 0

        while offset < data.count && domains.count < DHCPv6Constants.maxDNSSearchDomains {
            var labels = [String]()
            var domainValid = true

            while offset < data.count {
                let labelLen = Int(data[offset])
                offset += 1

                if labelLen == 0 {
                    // End of this domain name
                    break
                }

                // Sanity check: label length must not exceed remaining data
                guard offset + labelLen <= data.count else {
                    domainValid = false
                    break
                }

                // Sanity check: label length must not exceed 63 (DNS max label)
                guard labelLen <= 63 else {
                    domainValid = false
                    break
                }

                let labelBytes = Array(data[offset..<(offset + labelLen)])
                if let label = String(bytes: labelBytes, encoding: .utf8) {
                    labels.append(label)
                } else {
                    domainValid = false
                    break
                }
                offset += labelLen
            }

            if domainValid && !labels.isEmpty {
                domains.append(labels.joined(separator: "."))
            }
        }

        return domains
    }

    // MARK: - SNTP Server Parsing (Option 31)

    /// Parse SNTP server addresses from a server reply.
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer containing the DHCPv6 message.
    ///   - info: The parsed option info for the SNTP servers option.
    /// - Returns: An array of IPv6 addresses for SNTP servers.
    static func parseSNTPServers(from pbuf: Pbuf, info: DHCPv6OptionInfo?) -> [IPv6Address] {
        guard let info = info, info.isGiven else { return [] }
        let length = Int(info.valueLength)
        let start = Int(info.valueStart)
        var servers = [IPv6Address]()

        var idx = start
        while idx + DHCPv6Constants.ipv6AddressSize <= start + length
              && servers.count < DHCPv6Constants.maxSNTPServers {
            let w0 = pbuf.getUInt32NetworkOrder(at: idx)
            let w1 = pbuf.getUInt32NetworkOrder(at: idx + 4)
            let w2 = pbuf.getUInt32NetworkOrder(at: idx + 8)
            let w3 = pbuf.getUInt32NetworkOrder(at: idx + 12)
            servers.append(IPv6Address(w0, w1, w2, w3))
            idx += DHCPv6Constants.ipv6AddressSize
        }

        return servers
    }

    // MARK: - Address Management

    /// Assign the DHCPv6-obtained address to the network interface.
    private static func assignAddress(netif: NetworkInterface, data: DHCPv6Data) {
        let addr = data.iana.address

        // Check if already assigned at our known index
        if data.addressIndex >= 0 && data.addressIndex < netif.ipv6AddressCount {
            let existing = netif.ipv6Address(at: data.addressIndex)
            if existing == addr {
                // Same address, just update lifetimes
                netif.ipv6AddressValidLifetime[data.addressIndex] = data.iana.validLifetime
                netif.ipv6AddressPreferredLifetime[data.addressIndex] = data.iana.preferredLifetime
                if !netif.ipv6AddressIsValid(index: data.addressIndex) {
                    netif.setIPv6AddressState(at: data.addressIndex, state: .preferred)
                }
                return
            }
        }

        // Try to add the address to the interface
        let index = netif.addIPv6Address(addr)
        if index >= 0 {
            data.addressIndex = index
            netif.ipv6AddressValidLifetime[index] = data.iana.validLifetime
            netif.ipv6AddressPreferredLifetime[index] = data.iana.preferredLifetime
            // Mark as preferred (skip DAD for DHCPv6 per RFC 3315 section 18.1.8 note)
            netif.setIPv6AddressState(at: index, state: .tentative)
        }
    }

    /// Remove the DHCPv6-assigned address from the network interface.
    private static func removeAssignedAddress(netif: NetworkInterface, data: DHCPv6Data) {
        if data.addressIndex >= 0 && data.addressIndex < netif.ipv6AddressCount {
            netif.setIPv6Address(.any, at: data.addressIndex)
            netif.setIPv6AddressState(at: data.addressIndex, state: .invalid)
            netif.ipv6AddressValidLifetime[data.addressIndex] = 0
            netif.ipv6AddressPreferredLifetime[data.addressIndex] = 0
        }
        data.addressIndex = -1
    }

    // MARK: - Temporary Address Management (IA_TA)

    /// Assign temporary addresses obtained via IA_TA to the network interface.
    private static func assignTemporaryAddresses(netif: NetworkInterface, data: DHCPv6Data) {
        // Remove old temporary addresses first
        removeTemporaryAddresses(netif: netif, data: data)

        var indices = [Int]()
        for i in 0..<data.iata.addresses.count {
            let addr = data.iata.addresses[i]
            let preferred = i < data.iata.preferredLifetimes.count ? data.iata.preferredLifetimes[i] : 0
            let valid = i < data.iata.validLifetimes.count ? data.iata.validLifetimes[i] : 0

            let index = netif.addIPv6Address(addr)
            if index >= 0 {
                netif.ipv6AddressValidLifetime[index] = valid
                netif.ipv6AddressPreferredLifetime[index] = preferred
                netif.setIPv6AddressState(at: index, state: .tentative)
                indices.append(index)
            }
        }
        data.temporaryAddressIndices = indices
    }

    /// Remove all temporary addresses from the network interface.
    private static func removeTemporaryAddresses(netif: NetworkInterface, data: DHCPv6Data) {
        for idx in data.temporaryAddressIndices {
            if idx >= 0 && idx < netif.ipv6AddressCount {
                netif.setIPv6Address(.any, at: idx)
                netif.setIPv6AddressState(at: idx, state: .invalid)
                netif.ipv6AddressValidLifetime[idx] = 0
                netif.ipv6AddressPreferredLifetime[idx] = 0
            }
        }
        data.temporaryAddressIndices = []
    }

    // MARK: - Prefix Delegation Notifications

    /// Notify application that all delegated prefixes have expired or been released.
    private static func notifyPrefixExpiry(netif: NetworkInterface, data: DHCPv6Data) {
        guard let callback = data.prefixDelegationCallback else { return }
        for pfx in data.iapd.prefixes {
            callback(netif, pfx, .expired)
        }
        data.iapd.prefixes = []
    }

    // MARK: - Config Reply (DNS etc.)

    /// Handle DNS/domain config from a reply (shared between stateless and stateful).
    private static func handleConfigReply(netif: NetworkInterface, parsed: DHCPv6ParsedReply, pbuf: Pbuf) {
        guard let data = netif.dhcp6Data else { return }

        // Parse DNS servers (option 23)
        if let dnsInfo = parsed.dnsServer, dnsInfo.isGiven {
            let length = Int(dnsInfo.valueLength)
            let start = Int(dnsInfo.valueStart)
            var serverIndex: UInt8 = 0
            var idx = start
            while idx + DHCPv6Constants.ipv6AddressSize <= start + length {
                let w0 = pbuf.getUInt32NetworkOrder(at: idx)
                let w1 = pbuf.getUInt32NetworkOrder(at: idx + 4)
                let w2 = pbuf.getUInt32NetworkOrder(at: idx + 8)
                let w3 = pbuf.getUInt32NetworkOrder(at: idx + 12)
                let dnsAddr = IPv6Address(w0, w1, w2, w3)
                // Set DNS server via DNS module (dns_setserver equivalent)
                DNS.shared.setServer(index: Int(serverIndex), address: .v6(dnsAddr))
                serverIndex += 1
                idx += DHCPv6Constants.ipv6AddressSize
            }
        }

        // Parse DNS Search List (option 24)
        if let domainListInfo = parsed.domainList, domainListInfo.isGiven {
            data.dnsSearchList = parseDNSSearchList(from: pbuf, info: domainListInfo)
        }

        // Parse SNTP servers (option 31)
        if let sntpInfo = parsed.sntpServer, sntpInfo.isGiven {
            data.sntpServers = parseSNTPServers(from: pbuf, info: sntpInfo)
        }
    }

    // MARK: - Byte Extraction

    /// Extract raw bytes from a pbuf at a given option info location.
    private static func extractBytes(from pbuf: Pbuf, info: DHCPv6OptionInfo) -> [UInt8] {
        let len = Int(info.valueLength)
        var bytes = [UInt8](repeating: 0, count: len)
        bytes.withUnsafeMutableBufferPointer { buf in
            _ = pbuf.copyPartial(to: buf.baseAddress!, len: UInt16(len), offset: info.valueStart)
        }
        return bytes
    }
}
