//
//  NetBuf.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - NetBuf Flags

/// Flags for NetBuf state.
public struct NetBufFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// This netbuf has a destination address set.
    public static let destAddr = NetBufFlags(rawValue: 0x01)
    /// This netbuf includes a checksum.
    public static let checksum = NetBufFlags(rawValue: 0x02)
}

// MARK: - NetBuf

/// Network buffer descriptor for the NetConn API.
///
/// Wraps a `Pbuf` chain and carries source/destination addressing information.
/// Not thread-safe -- buffers must not be shared across multiple threads.
public final class NetBuf {

    // MARK: - Properties

    /// The packet buffer chain. Owns a reference.
    public internal(set) var p: Pbuf?

    /// Current pointer into the pbuf chain (for iterating segments).
    public internal(set) var ptr: Pbuf?

    /// Source address (from-address for received data).
    public var addr: IPAddress = .any

    /// Source port.
    public var port: UInt16 = 0

    /// Flags (destination address set, checksum present).
    public var flags: NetBufFlags = []

    /// Destination port or checksum value (overloaded field, matching C union).
    public var toPortOrChecksum: UInt16 = 0

    /// Destination address (when `flags` contains `.destAddr`).
    public var toAddr: IPAddress = .any

    // MARK: - Initialization

    /// Create an empty network buffer (no pbuf allocated yet).
    public init() {}

    deinit {
        // Free any owned pbuf chain.
        p = nil
        ptr = nil
    }

    // MARK: - Allocation

    /// Allocate a pbuf of `size` bytes for this netbuf (transport layer, RAM).
    /// Replaces any previously allocated pbuf.
    ///
    /// - Parameter size: Number of bytes to allocate.
    /// - Returns: An `UnsafeMutableRawPointer` to the payload, or `nil` on failure.
    @discardableResult
    public func alloc(size: UInt16) -> UnsafeMutableRawPointer? {
        // Free existing pbuf if any.
        p = nil
        ptr = nil

        let newPbuf = Pbuf.alloc(layer: .transport, length: size, type: .ram)
        guard let buf = newPbuf else { return nil }
        Debug.assert("NetBuf.alloc: first pbuf can hold size", buf.length >= size)
        p = buf
        ptr = buf
        return buf.payload
    }

    /// Free the packet buffer in this netbuf without deallocating the netbuf itself.
    public func free() {
        p = nil
        ptr = nil
        flags = []
        toPortOrChecksum = 0
    }

    // MARK: - Reference

    /// Let this netbuf reference existing data without copying.
    ///
    /// - Parameters:
    ///   - dataptr: Pointer to the data to reference (must remain valid).
    ///   - size: Size of the referenced data in bytes.
    /// - Returns: `.ok` on success, `.outOfMemory` if the reference pbuf could not be allocated.
    public func ref(_ dataptr: UnsafeRawPointer, size: UInt16) -> LWIPError {
        // Free existing pbuf.
        p = nil

        let refBuf = Pbuf.alloc(layer: .transport, length: 0, type: .ref)
        guard let buf = refBuf else {
            ptr = nil
            return .outOfMemory
        }
        // Set payload and lengths for this reference pbuf.
        buf.payload = UnsafeMutableRawPointer(mutating: dataptr)
        buf.len = size
        buf.totLen = size
        p = buf
        ptr = buf
        return .ok
    }

    // MARK: - Chaining

    /// Chain `tail` onto this netbuf. The `tail` buffer is consumed and must
    /// not be referenced after this call.
    ///
    /// - Parameter tail: The netbuf to append. Its pbuf chain is concatenated.
    public func chain(_ tail: NetBuf) {
        guard let headP = p, let tailP = tail.p else { return }
        Pbuf.cat(headP, tailP)
        ptr = p
        // tail's pbuf is now owned by head -- prevent tail from freeing it.
        tail.p = nil
        tail.ptr = nil
    }

    // MARK: - Data Access

    /// Retrieve the current segment's data pointer and length.
    ///
    /// - Returns: A tuple of `(pointer, length)`, or `nil` if no data is available.
    public func data() -> (UnsafeMutableRawPointer, UInt16)? {
        guard let current = ptr else { return nil }
        return (current.payload, current.len)
    }

    // MARK: - Navigation

    /// Move to the next segment in the pbuf chain.
    ///
    /// - Returns: `-1` if there is no next part,
    ///            `1` if moved to the next part but it is the last,
    ///            `0` if moved to the next part and more parts follow.
    @discardableResult
    public func next() -> Int8 {
        guard let current = ptr else { return -1 }
        guard let nextBuf = current.next else { return -1 }
        ptr = nextBuf
        return nextBuf.next == nil ? 1 : 0
    }

    /// Reset the current pointer to the beginning of the pbuf chain.
    public func first() {
        ptr = p
    }

    // MARK: - Convenience

    /// Total length of data in all chained pbufs.
    public var totalLength: UInt16 {
        return p?.totLen ?? 0
    }

    /// The source address of this buffer.
    @inlinable
    public var fromAddr: IPAddress {
        get { addr }
        set { addr = newValue }
    }

    /// The source port of this buffer.
    @inlinable
    public var fromPort: UInt16 {
        get { port }
        set { port = newValue }
    }

    /// Destination address (valid when `.destAddr` flag is set).
    @inlinable
    public var destAddress: IPAddress? {
        flags.contains(.destAddr) ? toAddr : nil
    }

    /// Destination port (valid when `.destAddr` flag is set and checksum-on-copy is off).
    @inlinable
    public var destPort: UInt16? {
        flags.contains(.destAddr) ? toPortOrChecksum : nil
    }

    /// Set the checksum for this buffer (used with checksum-on-copy).
    public func setChecksum(_ checksum: UInt16) {
        flags = .checksum
        toPortOrChecksum = checksum
    }

    // MARK: - Copy

    /// Copy data from the pbuf chain to a destination buffer.
    ///
    /// - Parameters:
    ///   - dest: Destination buffer.
    ///   - length: Maximum bytes to copy.
    ///   - offset: Offset into the pbuf chain.
    /// - Returns: Number of bytes actually copied.
    @discardableResult
    public func copyPartial(to dest: UnsafeMutableRawPointer, length: UInt16, offset: UInt16 = 0) -> UInt16 {
        guard let buf = p else { return 0 }
        return buf.copyPartial(to: dest, len: length, offset: offset)
    }

    /// Copy data from a source buffer into the pbuf chain (take).
    ///
    /// - Parameters:
    ///   - source: Source data.
    ///   - length: Number of bytes to copy.
    /// - Returns: `.ok` on success, error otherwise.
    @discardableResult
    public func take(from source: UnsafeRawPointer, length: UInt16) -> LWIPError {
        guard let buf = p else { return .bufferError }
        return buf.take(from: source, len: length)
    }
}
