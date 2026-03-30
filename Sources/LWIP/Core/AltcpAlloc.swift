//
//  AltcpAlloc.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - TLS Configuration Reference

/// Opaque TLS configuration. Implemented by the TLS port (e.g. AltcpTLS).
/// Holds certificates, keys, and other TLS session setup data.
public protocol AltcpTLSConfig: AnyObject, Sendable {}

// MARK: - AltcpTLS

/// TLS-over-TCP allocation functions.
public enum AltcpTLS {

    /// Wrap an existing altcp connection with TLS.
    /// Implemented in AltcpTLS module.
    public static var wrapHandler: ((_ config: AltcpTLSConfig, _ innerConn: AltcpControlBlock) -> AltcpControlBlock?)? = nil

    /// Create a new altcp PCB for TLS over TCP.
    ///
    /// Allocates a TCP connection, then wraps it with TLS.
    ///
    /// - Parameters:
    ///   - config: TLS configuration (certificates, keys, etc.)
    ///   - ipType: IP version (0=IPv4, 6=IPv6)
    /// - Returns: A new altcp PCB with TLS over TCP, or nil on failure
    public static func new(config: AltcpTLSConfig, ipType: UInt8 = 0) -> AltcpControlBlock? {
        if let tlsConfig = config as? TLSConfiguration {
            return AltcpControlBlock.tlsNew(config: tlsConfig, ipType: ipType)
        }

        guard let wrap = wrapHandler else { return nil }

        guard let innerConn = AltcpTCPFunctions.createForIPType(ipType) else {
            return nil
        }

        guard let ret = wrap(config, innerConn) else {
            _ = innerConn.close()
            return nil
        }

        return ret
    }

    /// Allocator function for TLS over TCP.
    /// Suitable for use in AltcpAllocator.
    ///
    /// - Parameters:
    ///   - arg: Must be an AltcpTLSConfig instance
    ///   - ipType: IP version
    /// - Returns: A new altcp PCB with TLS, or nil
    public static func alloc(arg: AnyObject?, ipType: UInt8) -> AltcpControlBlock? {
        guard let config = arg as? AltcpTLSConfig else { return nil }
        return AltcpTLS.new(config: config, ipType: ipType)
    }

    /// Create an AltcpAllocator for TLS connections.
    ///
    /// - Parameter config: TLS configuration
    /// - Returns: An allocator that creates TLS-over-TCP connections
    public static func allocator(config: AltcpTLSConfig) -> AltcpAllocator {
        return AltcpAllocator(alloc: AltcpTLS.alloc, arg: config)
    }

    /// Create an AltcpAllocator for plain TCP connections (no TLS).
    public static func tcpAllocator() -> AltcpAllocator {
        return AltcpAllocator(alloc: AltcpTCPFunctions.allocate)
    }
}
