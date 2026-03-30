//
//  NetDB.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - DNS Error Codes

/// Errors returned by DNS / address info functions.
public enum NetDBError: Int32, Error, Sendable {
    /// Name not found.
    case noName     = 200  // EAI_NONAME
    /// Service not found.
    case service    = 201  // EAI_SERVICE
    /// Non-recoverable failure.
    case fail       = 202  // EAI_FAIL
    /// Out of memory.
    case memory     = 203  // EAI_MEMORY
    /// Address family not supported.
    case family     = 204  // EAI_FAMILY

    /// Host not found.
    case hostNotFound = 210
    /// No data for hostname.
    case noData       = 211
    /// Non-recoverable error.
    case noRecovery   = 212
    /// Try again later.
    case tryAgain     = 213
}

// MARK: - Address Info Flags

/// Input flags for `AddrInfo`.
public struct AddrInfoFlags: OptionSet, Sendable {
    public let rawValue: Int32
    public init(rawValue: Int32) { self.rawValue = rawValue }

    /// Socket address for bind().
    public static let passive     = AddrInfoFlags(rawValue: 0x01)
    /// Request canonical name.
    public static let canonName   = AddrInfoFlags(rawValue: 0x02)
    /// Hostname must be numeric.
    public static let numericHost = AddrInfoFlags(rawValue: 0x04)
    /// Service must be numeric.
    public static let numericServ = AddrInfoFlags(rawValue: 0x08)
    /// Include IPv4-mapped IPv6 addresses.
    public static let v4Mapped    = AddrInfoFlags(rawValue: 0x10)
    /// Include all addresses.
    public static let all         = AddrInfoFlags(rawValue: 0x20)
    /// Only if globally configured.
    public static let addrConfig  = AddrInfoFlags(rawValue: 0x40)
}

// MARK: - HostEntry

/// Resolved host entry (equivalent to `struct hostent`).
public struct HostEntry: Sendable {
    /// Official name of the host.
    public var name: String
    /// List of aliases (usually empty in lwIP).
    public var aliases: [String]
    /// Address type (AF_INET or AF_INET6).
    public var addrType: AddressFamily
    /// Address length in bytes.
    public var addrLength: Int
    /// List of addresses (usually one in lwIP).
    public var addresses: [IPAddress]

    public init(name: String, addrType: AddressFamily, addresses: [IPAddress]) {
        self.name = name
        self.aliases = []
        self.addrType = addrType
        self.addrLength = addrType == .inet ? 4 : 16
        self.addresses = addresses
    }
}

// MARK: - AddrInfo

/// Address information result (equivalent to `struct addrinfo`).
public final class AddrInfo: @unchecked Sendable {
    /// Input flags.
    public var flags: AddrInfoFlags
    /// Address family.
    public var family: AddressFamily
    /// Socket type.
    public var sockType: SocketType
    /// Protocol.
    public var proto: IPProtocol
    /// Socket address.
    public var addr: SockAddr
    /// Canonical name.
    public var canonName: String?
    /// Next entry in linked list.
    public var next: AddrInfo?

    public init(flags: AddrInfoFlags = [],
                family: AddressFamily = .unspec,
                sockType: SocketType = .stream,
                proto: IPProtocol = .ip,
                addr: SockAddr = SockAddr(),
                canonName: String? = nil) {
        self.flags = flags
        self.family = family
        self.sockType = sockType
        self.proto = proto
        self.addr = addr
        self.canonName = canonName
    }
}

// MARK: - NetDB

/// Network database functions for DNS resolution.
///
/// Provides BSD-compatible hostname resolution functions.
/// Thread-safe: uses the NetConn DNS API internally.
public enum NetDB {

    /// Thread-local h_errno equivalent.
    public static var hErrno: Int32 = 0

    // MARK: - gethostbyname

    /// Resolve a hostname to an IP address.
    ///
    /// Returns an entry containing AF_INET addresses for the given hostname.
    /// Due to DNS limitations, only one address is returned.
    ///
    /// - Parameter name: The hostname to resolve.
    /// - Returns: A `HostEntry`, or `nil` on failure (check `hErrno`).
    public static func getHostByName(_ name: String) -> HostEntry? {
        switch NetConn.getHostByName(name) {
        case .success(let addr):
            hErrno = 0
            return HostEntry(
                name: name,
                addrType: addr.isV4 ? .inet : .inet6,
                addresses: [addr]
            )
        case .failure:
            hErrno = NetDBError.hostNotFound.rawValue
            return nil
        }
    }

    /// Reentrant version of getHostByName.
    ///
    /// - Parameters:
    ///   - name: Hostname to resolve.
    ///   - result: On success, set to the resolved entry.
    /// - Returns: 0 on success, or an error code.
    public static func getHostByNameR(
        _ name: String,
        result: inout HostEntry?
    ) -> Int32 {
        guard let entry = getHostByName(name) else {
            result = nil
            return hErrno
        }
        result = entry
        return 0
    }

    // MARK: - getaddrinfo

    /// Get address information for a node name and/or service.
    ///
    /// - Parameters:
    ///   - nodeName: Hostname or numeric address string.
    ///   - serviceName: Service name or port number string.
    ///   - hints: Hints for the query (family, socktype, etc).
    /// - Returns: A linked list of `AddrInfo` results, or an error.
    public static func getAddrInfo(
        nodeName: String?,
        serviceName: String?,
        hints: AddrInfo? = nil
    ) -> Result<AddrInfo, NetDBError> {
        // Determine port from service name.
        var port: UInt16 = 0
        if let svc = serviceName, let p = UInt16(svc) {
            port = p
        }

        // Determine address family from hints.
        let family = hints?.family ?? .unspec

        // Resolve hostname.
        guard let name = nodeName else {
            // No hostname: return a wildcard result.
            let ai = AddrInfo(
                flags: hints?.flags ?? [],
                family: family == .unspec ? .inet : family,
                sockType: hints?.sockType ?? .stream,
                proto: hints?.proto ?? .ip,
                addr: SockAddr(
                    family: family == .unspec ? .inet : family,
                    addr: .any,
                    port: port
                )
            )
            return .success(ai)
        }

        // Try to parse as numeric address first.
        if let numericAddr = IPAddress(name) {
            let addrFamily: AddressFamily = numericAddr.isV4 ? .inet : .inet6
            if family != .unspec && family != addrFamily {
                return .failure(.family)
            }

            let ai = AddrInfo(
                family: addrFamily,
                sockType: hints?.sockType ?? .stream,
                proto: hints?.proto ?? .ip,
                addr: SockAddr(family: addrFamily, addr: numericAddr, port: port)
            )
            return .success(ai)
        }

        // DNS resolution.
        switch NetConn.getHostByName(name) {
        case .success(let addr):
            let addrFamily: AddressFamily = addr.isV4 ? .inet : .inet6
            let ai = AddrInfo(
                family: addrFamily,
                sockType: hints?.sockType ?? .stream,
                proto: hints?.proto ?? .ip,
                addr: SockAddr(family: addrFamily, addr: addr, port: port),
                canonName: name
            )
            return .success(ai)
        case .failure:
            return .failure(.noName)
        }
    }

    /// Free an `AddrInfo` chain.
    ///
    /// In Swift with ARC, this is typically a no-op, but provided for API compatibility.
    ///
    /// - Parameter ai: The head of the chain to free.
    public static func freeAddrInfo(_ ai: AddrInfo?) {
        // ARC handles deallocation. Break the chain to help avoid cycles.
        var current = ai
        while let node = current {
            let next = node.next
            node.next = nil
            current = next
        }
    }
}

