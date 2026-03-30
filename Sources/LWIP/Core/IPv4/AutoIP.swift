//
//  AutoIP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - AutoIP Constants

/// Namespace for AutoIP constants.
public enum AutoIPConstants {
    /// Link-local network: 169.254.0.0
    public static let network: UInt32          = 0xA9FE0000
    /// Start of usable link-local range: 169.254.1.0
    public static let rangeStart: UInt32       = network | 0x0100
    /// End of usable link-local range: 169.254.254.255
    public static let rangeEnd: UInt32         = network | 0xFEFF
}

// MARK: - AutoIP State

/// AutoIP state machine states.
public enum AutoIPState: UInt8, Sendable {
    case off      = 0
    case checking = 1
    case bound    = 2
}

// MARK: - AutoIP Data

/// AutoIP state information for one network interface.
public final class AutoIPData {
    /// The currently selected link-local IP address.
    public var linkLocalAddress: IPv4Address = .any

    /// Current state.
    public var state: AutoIPState = .off
    /// Number of addresses tried so far.
    public var triedLLIPAddr: UInt8 = 0
    /// ACD module for conflict detection.
    public var acd: AddressConflictDetection = AddressConflictDetection()

    public init() {}
}

// MARK: - AutoIP Module

/// AutoIP protocol implementation.
public enum AutoIP {

    // MARK: - Set/Remove Struct

    /// Set a statically allocated AutoIP struct on a network interface.
    public static func setStruct(on netif: NetworkInterface, autoip: AutoIPData) {
        netif.autoipData = autoip
    }

    /// Remove the AutoIP struct from a network interface.
    public static func removeStruct(from netif: NetworkInterface) {
        netif.autoipData = nil
    }

    // MARK: - Start

    /// Start AutoIP client on an interface.
    ///
    /// Selects a link-local address and begins the ACD probing process.
    ///
    /// - Parameter netif: The network interface.
    /// - Returns: `.ok` on success, `.outOfMemory` on allocation failure.
    public static func start(on netif: NetworkInterface) -> LWIPError {
        var autoip = netif.autoipData

        if autoip == nil {
            autoip = AutoIPData()
            netif.autoipData = autoip
        }

        guard let ai = autoip else { return .outOfMemory }

        if ai.state == .off {
            // Register ACD callback
            ACD.add(to: netif, acd: ai.acd, callback: { n, state in
                autoipConflictCallback(n, state: state)
            })

            // If we don't have a valid link-local address, create one
            if !ai.linkLocalAddress.isLinkLocal {
                createAddr(netif: netif, ipAddr: &ai.linkLocalAddress)
            }

            ai.state = .checking
            let _ = ACD.start(on: netif, acd: ai.acd, ipAddr: ai.linkLocalAddress)
        }

        return .ok
    }

    // MARK: - Stop

    /// Stop AutoIP client on an interface.
    ///
    /// - Parameter netif: The network interface.
    /// - Returns: `.ok`
    @discardableResult
    public static func stop(on netif: NetworkInterface) -> LWIPError {
        guard let autoip = netif.autoipData else { return .ok }

        autoip.state = .off

        // If the current interface address is link-local, clear it
        if netif.ipAddr.isLinkLocal {
            netif.ipAddr = .any
            netif.netmask = .any
            netif.gateway = .any
        }

        return .ok
    }

    // MARK: - Network Changed

    /// Handle a link-up event for AutoIP.
    ///
    /// If AutoIP is active and not cooperating with DHCP, restart probing.
    public static func networkChangedLinkUp(on netif: NetworkInterface) {
        guard let autoip = netif.autoipData else { return }
        guard autoip.state != .off else { return }

        autoip.state = .checking
        let _ = ACD.start(on: netif, acd: autoip.acd, ipAddr: autoip.linkLocalAddress)
    }

    /// Handle a link-down event for AutoIP.
    ///
    /// If cooperating with DHCP, stop AutoIP so DHCP can reinitiate it.
    public static func networkChangedLinkDown(on netif: NetworkInterface) {
        guard let autoip = netif.autoipData else { return }
        guard autoip.state != .off else { return }

        let _ = stop(on: netif)
    }

    // MARK: - Supplied Address

    /// Check if AutoIP supplied the current interface address.
    ///
    /// - Parameter netif: The network interface.
    /// - Returns: `true` if the interface address is the AutoIP link-local address.
    public static func suppliedAddress(on netif: NetworkInterface) -> Bool {
        guard let autoip = netif.autoipData else { return false }
        return netif.ipAddr == autoip.linkLocalAddress && autoip.state == .bound
    }

    /// Check if a packet addressed to `addr` should be accepted based on AutoIP.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - addr: The destination address to check.
    /// - Returns: `true` if the address matches AutoIP and the state is bound.
    public static func acceptPacket(on netif: NetworkInterface, addr: IPv4Address) -> Bool {
        guard let autoip = netif.autoipData else { return false }
        return addr == autoip.linkLocalAddress && autoip.state == .bound
    }

    // MARK: - Private Helpers

    /// Create a link-local address from the interface hardware address.
    ///
    /// Generates an address in 169.254.1.0 - 169.254.254.255 per RFC 3927 Section 2.1.
    private static func createAddr(netif: NetworkInterface, ipAddr: inout IPv4Address) {
        guard let autoip = netif.autoipData else { return }
        let hwAddr = netif.hwAddr

        // Seed from last two bytes of hardware address
        var seed: UInt32 = UInt32(hwAddr.count > 4 ? hwAddr[4] : 0)
            | (UInt32(hwAddr.count > 5 ? hwAddr[5] : 0) << 8)
        seed = seed.bigEndian // Network byte order

        var addr = seed &+ UInt32(autoip.triedLLIPAddr)
        addr = AutoIPConstants.network | (addr & 0xFFFF)

        // Clamp to valid range
        if addr < AutoIPConstants.rangeStart {
            addr += AutoIPConstants.rangeEnd - AutoIPConstants.rangeStart + 1
        }
        if addr > AutoIPConstants.rangeEnd {
            addr -= AutoIPConstants.rangeEnd - AutoIPConstants.rangeStart + 1
        }

        ipAddr = IPv4Address(networkOrder: addr.bigEndian)
    }

    /// Bind the AutoIP link-local address to the interface.
    private static func bind(on netif: NetworkInterface) {
        guard let autoip = netif.autoipData else { return }

        autoip.state = .bound

        // Set the interface address with link-local subnet mask
        netif.ipAddr = autoip.linkLocalAddress
        netif.netmask = IPv4Address(255, 255, 0, 0)
        netif.gateway = .any
    }

    /// Restart AutoIP with a new address candidate.
    private static func restart(on netif: NetworkInterface) {
        guard let autoip = netif.autoipData else { return }
        autoip.triedLLIPAddr += 1
        let _ = start(on: netif)
    }

    /// ACD conflict callback for AutoIP.
    private static func autoipConflictCallback(_ netif: NetworkInterface, state: ACDCallbackState) {
        guard let autoip = netif.autoipData else { return }

        switch state {
        case .ipOK:
            bind(on: netif)

        case .restartClient:
            restart(on: netif)

        case .decline:
            autoip.linkLocalAddress = .any
            autoip.triedLLIPAddr += 1
            let _ = stop(on: netif)
        }
    }
}
