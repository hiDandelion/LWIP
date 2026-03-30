//
//  NetifAPI.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - NetifAPI ARP Entry Type

/// ARP entry types for the netif API.
public enum NetifAPIARPEntryType: Sendable {
    /// Permanent ARP entry.
    case permanent
}

// MARK: - Callback Types

extension NetifAPI {
    /// Void function called on a network interface (e.g., netif_set_up).
    public typealias VoidHandler = (NetworkInterface) -> Void

    /// Function returning an error called on a network interface (e.g., dhcp_start).
    public typealias ErrorHandler = (NetworkInterface) -> LWIPError

    /// Network interface initialization function.
    public typealias InitializationHandler = (NetworkInterface) -> LWIPError

    /// Network interface input function.
    public typealias InputHandler = (Pbuf, NetworkInterface) -> LWIPError
}

// MARK: - NetifAPI

/// Thread-safe API for network interface management.
///
/// All operations are dispatched to the TCPIP thread to ensure
/// thread safety when modifying network interfaces.
public enum NetifAPI {

    // MARK: - Add / Remove

    /// Add a network interface (thread-safe).
    ///
    /// - Parameters:
    ///   - netif: The network interface to add.
    ///   - ipAddr: IPv4 address (optional).
    ///   - netmask: IPv4 netmask (optional).
    ///   - gateway: IPv4 gateway (optional).
    ///   - state: Opaque state for the driver.
    ///   - initFn: Initialization function.
    ///   - inputFn: Input function.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func addNetif(
        _ netif: NetworkInterface,
        ipAddr: IPAddress? = nil,
        netmask: IPAddress? = nil,
        gateway: IPAddress? = nil,
        state: AnyObject? = nil,
        initFn: @escaping NetifAPI.InitializationHandler,
        inputFn: @escaping NetifAPI.InputHandler
    ) -> LWIPError {
        let callData = TCPIPApiCallData()
        let statePointer = state.map { UnsafeMutableRawPointer(Unmanaged.passUnretained($0).toOpaque()) }

        return TCPIP.shared.apiCall(fn: { data in
            let resolvedIP: IPv4Address
            if let ipAddr {
                guard case .v4(let addr) = ipAddr else {
                    data.err = .invalidValue
                    return .invalidValue
                }
                resolvedIP = addr
            } else {
                resolvedIP = .any
            }

            let resolvedMask: IPv4Address
            if let netmask {
                guard case .v4(let addr) = netmask else {
                    data.err = .invalidValue
                    return .invalidValue
                }
                resolvedMask = addr
            } else {
                resolvedMask = .any
            }

            let resolvedGateway: IPv4Address
            if let gateway {
                guard case .v4(let addr) = gateway else {
                    data.err = .invalidValue
                    return .invalidValue
                }
                resolvedGateway = addr
            } else {
                resolvedGateway = .any
            }

            let added = NetworkInterface.add(
                netif,
                ipAddr: resolvedIP,
                netmask: resolvedMask,
                gateway: resolvedGateway,
                state: statePointer,
                initFn: initFn,
                inputFn: inputFn
            )
            data.err = added == nil ? .interfaceError : .ok
            return data.err
        }, callData: callData)
    }

    /// Remove a network interface (thread-safe).
    ///
    /// - Parameter netif: The interface to remove.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func removeNetif(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { iface in
            iface.remove()
        })
    }

    // MARK: - Address Configuration

    /// Set the IPv4 address, netmask, and gateway for an interface.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - ipAddr: New IPv4 address.
    ///   - netmask: New netmask.
    ///   - gateway: New gateway.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setAddr(
        _ netif: NetworkInterface,
        ipAddr: IPAddress,
        netmask: IPAddress,
        gateway: IPAddress
    ) -> LWIPError {
        let callData = TCPIPApiCallData()

        return TCPIP.shared.apiCall(fn: { data in
            guard case .v4(let resolvedIP) = ipAddr,
                  case .v4(let resolvedMask) = netmask,
                  case .v4(let resolvedGateway) = gateway else {
                data.err = .invalidValue
                return .invalidValue
            }
            netif.setAddresses(ipAddr: resolvedIP, netmask: resolvedMask, gateway: resolvedGateway)
            data.err = .ok
            return .ok
        }, callData: callData)
    }

    // MARK: - Up / Down

    /// Set the interface up (thread-safe).
    ///
    /// - Parameter netif: The interface to bring up.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setUp(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { iface in
            iface.setUp()
        })
    }

    /// Set the interface down (thread-safe).
    ///
    /// - Parameter netif: The interface to bring down.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setDown(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { iface in
            iface.setDown()
        })
    }

    // MARK: - Default Interface

    /// Set the default network interface (thread-safe).
    ///
    /// - Parameter netif: The interface to make default.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setDefault(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { _ in
            NetworkInterface.setDefault(netif)
        })
    }

    // MARK: - Link State

    /// Set the link state to up (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setLinkUp(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { iface in
            iface.setLinkUp()
        })
    }

    /// Set the link state to down (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func setLinkDown(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { iface in
            iface.setLinkDown()
        })
    }

    // MARK: - Name / Index Lookup

    /// Convert a network interface name to its index.
    ///
    /// - Parameter name: The interface name (e.g. "en0").
    /// - Returns: The interface index, or an error.
    public static func nameToIndex(_ name: String) -> Result<UInt8, LWIPError> {
        var resultIndex: UInt8 = 0
        let callData = TCPIPApiCallData()

        let err = TCPIP.shared.apiCall(fn: { data in
            resultIndex = NetworkInterface.nameToIndex(name)
            data.err = resultIndex == NetworkInterfaceConstants.noIndex ? .invalidValue : .ok
            return data.err
        }, callData: callData)

        guard err == .ok else { return .failure(err) }
        return .success(resultIndex)
    }

    /// Convert a network interface index to its name.
    ///
    /// - Parameter index: The interface index.
    /// - Returns: The interface name, or an error.
    public static func indexToName(_ index: UInt8) -> Result<String, LWIPError> {
        var resultName = ""
        let callData = TCPIPApiCallData()

        let err = TCPIP.shared.apiCall(fn: { data in
            guard let name = NetworkInterface.indexToName(index) else {
                data.err = .invalidValue
                return .invalidValue
            }
            resultName = name
            data.err = .ok
            return data.err
        }, callData: callData)

        guard err == .ok else { return .failure(err) }
        return .success(resultName)
    }

    // MARK: - DHCP

    /// Start DHCP on an interface (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func dhcpStart(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, errorFn: { iface in
            DHCP.start(on: iface)
        })
    }

    /// Stop DHCP on an interface (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func dhcpStop(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { _ in
            DHCP.stop(on: netif)
        })
    }

    /// Release and stop DHCP on an interface (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func dhcpReleaseAndStop(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, voidFn: { _ in
            DHCP.releaseAndStop(on: netif)
        })
    }

    /// Renew DHCP lease on an interface (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func dhcpRenew(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, errorFn: { _ in
            DHCP.renew(on: netif)
        })
    }

    /// Send DHCP inform on an interface (thread-safe).
    ///
    /// - Parameter netif: The interface.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func dhcpInform(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, errorFn: { _ in
            .invalidArgument
        })
    }

    // MARK: - AutoIP

    /// Start AutoIP on an interface.
    @discardableResult
    public static func autoipStart(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, errorFn: { iface in
            AutoIP.start(on: iface)
        })
    }

    /// Stop AutoIP on an interface.
    @discardableResult
    public static func autoipStop(_ netif: NetworkInterface) -> LWIPError {
        return netifCommon(netif, errorFn: { iface in
            AutoIP.stop(on: iface)
        })
    }

    // MARK: - ARP

    /// Add a static ARP entry (thread-safe).
    ///
    /// - Parameters:
    ///   - ipAddr: IP address.
    ///   - ethAddr: Ethernet (MAC) address as 6 bytes.
    ///   - type: Entry type.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func arpAdd(ipAddr: IPAddress, ethAddr: [UInt8],
                              type: NetifAPIARPEntryType = .permanent) -> LWIPError {
        let callData = TCPIPApiCallData()
        return TCPIP.shared.apiCall(fn: { data in
            guard case .v4(let address) = ipAddr, ethAddr.count >= 6 else {
                data.err = .invalidValue
                return .invalidValue
            }
            let ethernetAddress = EthAddr(ethAddr[0], ethAddr[1], ethAddr[2], ethAddr[3], ethAddr[4], ethAddr[5])
            data.err = EthARP.addStaticEntry(ipAddr: address, ethAddr: ethernetAddress)
            return data.err
        }, callData: callData)
    }

    /// Remove a static ARP entry (thread-safe).
    ///
    /// - Parameters:
    ///   - ipAddr: IP address to remove.
    ///   - type: Entry type.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func arpRemove(ipAddr: IPAddress,
                                 type: NetifAPIARPEntryType = .permanent) -> LWIPError {
        let callData = TCPIPApiCallData()
        return TCPIP.shared.apiCall(fn: { data in
            guard case .v4(let address) = ipAddr else {
                data.err = .invalidValue
                return .invalidValue
            }
            data.err = EthARP.removeStaticEntry(ipAddr: address)
            return data.err
        }, callData: callData)
    }

    // MARK: - Common Dispatch

    /// Execute a void function on the TCPIP thread for a network interface.
    @discardableResult
    public static func netifCommon(_ netif: NetworkInterface,
                                   voidFn: @escaping NetifAPI.VoidHandler) -> LWIPError {
        let callData = TCPIPApiCallData()

        return TCPIP.shared.apiCall(fn: { data in
            voidFn(netif)
            data.err = .ok
            return .ok
        }, callData: callData)
    }

    /// Execute an error-returning function on the TCPIP thread for a network interface.
    @discardableResult
    public static func netifCommon(_ netif: NetworkInterface,
                                   errorFn: @escaping NetifAPI.ErrorHandler) -> LWIPError {
        let callData = TCPIPApiCallData()

        return TCPIP.shared.apiCall(fn: { data in
            let err = errorFn(netif)
            data.err = err
            return err
        }, callData: callData)
    }
}
