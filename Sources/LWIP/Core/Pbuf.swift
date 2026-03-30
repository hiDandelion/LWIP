//
//  Pbuf.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// Size of a Pbuf struct used for computing payload offsets in contiguous allocations.
/// We align this so payloads remain aligned.
@usableFromInline
internal let pbufStructSize: Int = MemoryAlignment.alignedSize(MemoryLayout<PbufHeader>.size)

// MARK: - PbufLayerOffset

/// Pbuf layer specification controlling header space reservation.
public struct PbufLayerOffset: Equatable, Hashable, Sendable {
    /// The number of bytes to reserve for protocol headers.
    public let offset: UInt16

    // MARK: - Individual header length constants

    /// Transport-layer (TCP/UDP) header length: 20 bytes.
    public static let transportHeaderLength: UInt16 = 20
    /// IP-layer header length: 20 bytes (IPv4 minimum).
    public static let ipHeaderLength: UInt16 = 20
    /// Link-layer header length (from configuration, typically 14 for Ethernet).
    public static var linkHeaderLength: UInt16 { UInt16(lwipConfig.pbufLinkHlen) }
    /// Link-layer encapsulation header length (from configuration, typically 0).
    public static var linkEncapsulationHeaderLength: UInt16 { UInt16(lwipConfig.pbufLinkEncapsulationHlen) }
    /// Default pool buffer size (from configuration).
    public static var defaultPoolBufferSize: UInt16 { UInt16(lwipConfig.pbufPoolBufsize) }

    // MARK: - Layer presets

    /// Includes transport (TCP/UDP), IP, link, and encapsulation headers.
    public static let transport = PbufLayerOffset(
        offset: linkEncapsulationHeaderLength + linkHeaderLength + ipHeaderLength + transportHeaderLength
    )
    /// Includes IP, link, and encapsulation headers.
    public static let ip = PbufLayerOffset(
        offset: linkEncapsulationHeaderLength + linkHeaderLength + ipHeaderLength
    )
    /// Includes link and encapsulation headers.
    public static let link = PbufLayerOffset(
        offset: linkEncapsulationHeaderLength + linkHeaderLength
    )
    /// Includes only encapsulation headers.
    public static let rawTx = PbufLayerOffset(
        offset: linkEncapsulationHeaderLength
    )
    /// No header space reserved (for incoming packets).
    public static let raw = PbufLayerOffset(offset: 0)

    public init(offset: UInt16) {
        self.offset = offset
    }
}

// MARK: - PbufType

/// Determines how a pbuf's memory is allocated and managed.
public enum PbufType: UInt8, Sendable {
    /// Payload data is stored in RAM immediately following the pbuf struct.
    /// Allocated as a single contiguous block. Used for outgoing (TX) packets.
    case ram = 0

    /// Payload points to immutable data in ROM or static memory.
    /// The pbuf struct itself is allocated from MEMP_PBUF.
    case rom = 1

    /// Payload points to volatile RAM data owned by someone else.
    /// Similar to ROM but data might change, so must be copied if queued.
    case ref = 2

    /// Payload data from the pbuf pool. Struct and payload are contiguous.
    /// Used for incoming (RX) packets. Can be chained (scatter-gather).
    case pool = 3

    // MARK: - Type flag queries

    /// Whether this type has struct and data contiguous in memory.
    @inlinable
    public var isContiguous: Bool {
        self == .ram || self == .pool
    }

    /// Whether the data referenced by this type may change (volatile).
    @inlinable
    public var isDataVolatile: Bool {
        self == .ref
    }

    /// Whether this pbuf needs to be copied before being queued.
    @inlinable
    public var needsCopy: Bool {
        isDataVolatile
    }
}

// MARK: - PbufFlags

/// Bit flags for `Pbuf.flags`.
public struct PbufFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// This packet's data should be immediately passed to the application.
    public static let push      = PbufFlags(rawValue: 0x01)
    /// This is a custom pbuf with a custom free function.
    public static let isCustom  = PbufFlags(rawValue: 0x02)
    /// UDP multicast to be looped back.
    public static let mcastLoop = PbufFlags(rawValue: 0x04)
    /// Received as link-level broadcast.
    public static let llBroadcast  = PbufFlags(rawValue: 0x08)
    /// Received as link-level multicast.
    public static let llMulticast  = PbufFlags(rawValue: 0x10)
    /// Includes a TCP FIN flag.
    public static let tcpFin    = PbufFlags(rawValue: 0x20)
}

// MARK: - PbufHeader (internal raw storage)

/// Raw header storage used for computing payload offsets.
/// Used only for computing sizes; actual field access is through the Pbuf class.
@usableFromInline
internal struct PbufHeader {
    var next: UnsafeMutableRawPointer?
    var payload: UnsafeMutableRawPointer?
    var totLen: UInt16
    var len: UInt16
    var typeInternal: UInt8
    var flags: UInt8
    var ref: UInt16
    var ifIdx: UInt8
}

// MARK: - Pbuf

/// Packet buffer -- the core data structure for network packets in lwIP.
///
/// This is a reference type with manual reference counting (not ARC).
/// Pbufs form singly-linked chains via `next`. A chain represents a single packet;
/// `totLen` on each node equals `len + (next?.totLen ?? 0)`.
public final class Pbuf {
    /// Next pbuf in the chain (singly linked list).
    public var next: Pbuf?

    /// Pointer to the actual data payload.
    public var payload: UnsafeMutableRawPointer

    /// Total length of this buffer and all subsequent buffers in the chain.
    public var totLen: UInt16

    /// Length of data in this buffer only.
    public var len: UInt16

    /// The allocation type of this pbuf.
    public let type: PbufType

    /// Miscellaneous flags.
    public var flags: PbufFlags

    /// Manual reference count.
    /// When it reaches zero, the pbuf is deallocated.
    public var refCount: UInt16

    /// For incoming packets, the index of the network interface that received this packet.
    public var ifIndex: UInt8

    /// If this is a RAM or POOL pbuf, the raw allocation pointer (for freeing).
    /// For REF/ROM, this is nil.
    internal var rawAllocation: UnsafeMutableRawPointer?

    /// Custom free function for custom pbufs (when `flags.contains(.isCustom)`).
    public var customFreeFunction: ((Pbuf) -> Void)?

    /// IPv6 fragment metadata used during reassembly.
    public var fragmentNode: IPv6FragmentNode?

    /// Linked-list pointer used by IPv6 fragment reassembly.
    public var fragmentNext: Pbuf?

    // MARK: - Private Init

    internal init(
        payload: UnsafeMutableRawPointer,
        totLen: UInt16,
        len: UInt16,
        type: PbufType,
        flags: PbufFlags = [],
        rawAllocation: UnsafeMutableRawPointer? = nil
    ) {
        self.next = nil
        self.payload = payload
        self.totLen = totLen
        self.len = len
        self.type = type
        self.flags = flags
        self.refCount = 1
        self.ifIndex = 0
        self.rawAllocation = rawAllocation
        self.customFreeFunction = nil
        self.fragmentNode = nil
        self.fragmentNext = nil
    }

    // MARK: - Allocation

    /// Allocate a new pbuf (possibly a chain for pool type).
    ///
    /// - Parameters:
    ///   - layer: Determines how much header space to reserve.
    ///   - length: Desired payload size.
    ///   - type: Allocation type (.ram, .rom, .ref, .pool).
    /// - Returns: The allocated pbuf, or `nil` on failure.
    public static func alloc(layer: PbufLayerOffset, length: UInt16, type: PbufType) -> Pbuf? {
        let offset = Int(layer.offset)

        switch type {
        case .ref, .rom:
            return allocReference(payload: nil, length: length, type: type)

        case .pool:
            let poolBufSize = Int(PbufLayerOffset.defaultPoolBufferSize)
            var head: Pbuf? = nil
            var last: Pbuf? = nil
            var remaining = Int(length)
            var currentOffset = offset

            while remaining > 0 || head == nil {
                guard let raw = Memp.malloc(.pbufPool) else {
                    // Free what we've allocated so far.
                    if let h = head { let _ = Self.free(h) }
                    return nil
                }

                let payloadSpace = poolBufSize - MemoryAlignment.alignedSize(currentOffset)
                let qlen = Swift.min(remaining, Swift.max(payloadSpace, 0))
                let payloadPtr = raw + MemoryAlignment.alignedSize(pbufStructSize + currentOffset)

                let p = Pbuf(
                    payload: payloadPtr,
                    totLen: UInt16(remaining),
                    len: UInt16(qlen),
                    type: .pool,
                    rawAllocation: raw
                )

                if head == nil {
                    head = p
                } else {
                    last?.next = p
                }
                last = p
                remaining -= qlen
                currentOffset = 0

                if remaining <= 0 { break }
            }
            return head

        case .ram:
            let alignedOffset = MemoryAlignment.alignedSize(offset)
            let alignedLength = MemoryAlignment.alignedSize(Int(length))
            let payloadLen = alignedOffset + alignedLength
            let allocLen = MemoryAlignment.alignedSize(pbufStructSize) + payloadLen

            // Overflow check.
            guard payloadLen >= alignedLength, allocLen >= alignedLength else {
                return nil
            }

            guard let raw = Mem.malloc(allocLen) else {
                return nil
            }

            let payloadPtr = raw + MemoryAlignment.alignedSize(pbufStructSize) + alignedOffset

            let p = Pbuf(
                payload: payloadPtr,
                totLen: length,
                len: length,
                type: .ram,
                rawAllocation: raw
            )
            return p
        }
    }

    /// Allocate a pbuf that references external data (for REF or ROM types).
    ///
    /// - Parameters:
    ///   - payload: Pointer to the external data (can be `nil` for deferred assignment).
    ///   - length: Length of the data.
    ///   - type: Must be `.ref` or `.rom`.
    /// - Returns: The allocated pbuf, or `nil` on failure.
    public static func allocReference(
        payload: UnsafeMutableRawPointer?,
        length: UInt16,
        type: PbufType
    ) -> Pbuf? {
        assert(type == .ref || type == .rom)
        guard let raw = Memp.malloc(.pbuf) else {
            return nil
        }
        // For REF/ROM we need a valid payload pointer or a non-nil sentinel.
        // bitPattern: 1 always succeeds (only bitPattern: 0 returns nil).
        let payloadPtr = payload ?? UnsafeMutableRawPointer(bitPattern: 1)!
        let p = Pbuf(
            payload: payloadPtr,
            totLen: length,
            len: length,
            type: type,
            rawAllocation: raw
        )
        if payload == nil {
            // Store raw allocation for later freeing, keep a sentinel payload.
            // Caller must set payload before use.
        }
        return p
    }

    // MARK: - Deallocation

    /// Decrement the reference count of a pbuf chain.
    /// Frees pbufs whose ref count reaches zero, walking the chain.
    ///
    /// - Parameter p: Head of the pbuf chain to free.
    /// - Returns: Number of pbufs actually deallocated.
    @discardableResult
    public static func free(_ p: Pbuf?) -> UInt8 {
        var current = p
        var count: UInt8 = 0

        while let c = current {
            assert(c.refCount > 0, "pbuf_free: refCount already zero")
            c.refCount -= 1

            if c.refCount == 0 {
                let nextPbuf = c.next
                c.next = nil

                // Call custom free if applicable.
                if c.flags.contains(.isCustom), let customFree = c.customFreeFunction {
                    customFree(c)
                } else {
                    // Deallocate based on type.
                    switch c.type {
                    case .pool:
                        if let raw = c.rawAllocation {
                            Memp.free(.pbufPool, raw)
                        }
                    case .rom, .ref:
                        if let raw = c.rawAllocation {
                            Memp.free(.pbuf, raw)
                        }
                    case .ram:
                        if let raw = c.rawAllocation {
                            Mem.free(raw)
                        }
                    }
                }

                count += 1
                current = nextPbuf
            } else {
                // Still referenced -- stop walking.
                current = nil
            }
        }
        return count
    }

    // MARK: - Realloc (shrink)

    /// Shrink a pbuf chain to `newLen` bytes. Cannot grow.
    ///
    /// - Parameters:
    ///   - p: The pbuf chain to shrink.
    ///   - newLen: The desired new total length.
    public static func realloc(_ p: Pbuf, _ newLen: UInt16) {
        guard newLen < p.totLen else { return }

        let shrink = p.totLen - newLen
        var remaining = newLen
        var q = p

        // Walk until we find the pbuf to truncate.
        while remaining > q.len {
            remaining -= q.len
            q.totLen &-= shrink
            guard let nextQ = q.next else { return }
            q = nextQ
        }

        // q is now the last pbuf to keep; remaining is its new len.
        // For RAM pbufs, we could trim the allocation; for simplicity
        // we just adjust length fields (matching C behavior for non-RAM).
        if q.type == .ram, remaining != q.len, !q.flags.contains(.isCustom) {
            if let raw = q.rawAllocation {
                let payloadOffset = q.payload - raw
                let _ = Mem.trim(raw, newSize: payloadOffset + Int(remaining))
            }
        }

        q.len = remaining
        q.totLen = remaining

        // Free any remaining chain members.
        if let tail = q.next {
            let _ = Self.free(tail)
        }
        q.next = nil
    }

    // MARK: - Header Manipulation

    /// Add header space by moving the payload pointer backward.
    /// Only works for contiguous types (RAM, POOL) unless `force` is true.
    ///
    /// - Parameters:
    ///   - headerSize: Number of bytes to reveal as header.
    ///   - force: If true, allow header expansion on REF/ROM types.
    /// - Returns: `true` on success, `false` on failure.
    @discardableResult
    public func addHeader(_ headerSize: Int, force: Bool = false) -> Bool {
        guard headerSize > 0 else { return true }
        guard headerSize <= 0xFFFF else { return false }
        let increment = UInt16(headerSize)

        // Check for tot_len overflow.
        guard UInt16(truncatingIfNeeded: UInt32(increment) + UInt32(totLen)) >= increment else {
            return false
        }

        if type.isContiguous {
            let newPayload = payload - headerSize
            // Bounds check: must not go before the raw allocation + struct size.
            if let raw = rawAllocation {
                let minPayload = raw + pbufStructSize
                guard newPayload >= minPayload else { return false }
            }
            payload = newPayload
        } else {
            guard force else { return false }
            payload = payload - headerSize
        }

        len &+= increment
        totLen &+= increment
        return true
    }

    /// Force-add header space (wraps `addHeader(_:force:)`).
    @discardableResult
    public func addHeaderForce(_ headerSize: Int) -> Bool {
        return addHeader(headerSize, force: true)
    }

    /// Remove header space by advancing the payload pointer forward.
    ///
    /// - Parameter headerSize: Number of bytes to hide.
    /// - Returns: `true` on success, `false` if headerSize > len.
    @discardableResult
    public func removeHeader(_ headerSize: Int) -> Bool {
        guard headerSize > 0 else { return true }
        guard headerSize <= 0xFFFF else { return false }
        let decrement = UInt16(headerSize)
        guard decrement <= len else { return false }

        payload = payload + headerSize
        len &-= decrement
        totLen &-= decrement
        return true
    }

    /// Adjust payload pointer. Positive values add headers (expose earlier bytes);
    /// negative values remove headers (skip bytes).
    ///
    /// - Parameters:
    ///   - headerSize: Signed offset. Positive reveals headers, negative hides them.
    ///   - force: Allow expanding REF/ROM types.
    /// - Returns: 0 on success, non-zero on failure.
    public func header(_ headerSize: Int16, force: Bool = false) -> UInt8 {
        if headerSize < 0 {
            return removeHeader(Int(-headerSize)) ? 0 : 1
        } else {
            return addHeader(Int(headerSize), force: force) ? 0 : 1
        }
    }

    /// Same as `header(_:force:)` with force=true.
    public func headerForce(_ headerSize: Int16) -> UInt8 {
        return header(headerSize, force: true)
    }

    /// Free header pbufs from the front of a chain until `size` bytes have been consumed.
    ///
    /// - Parameters:
    ///   - p: The pbuf chain.
    ///   - size: Number of header bytes to remove.
    /// - Returns: The remaining pbuf chain, or `nil` if fully consumed.
    public static func freeHeader(_ p: Pbuf?, size: UInt16) -> Pbuf? {
        var current = p
        var freeLeft = size
        while freeLeft > 0, let c = current {
            if freeLeft >= c.len {
                freeLeft -= c.len
                let nextP = c.next
                c.next = nil
                let _ = Self.free(c)
                current = nextP
            } else {
                c.removeHeader(Int(freeLeft))
                freeLeft = 0
            }
        }
        return current
    }

    // MARK: - Reference Counting

    /// Increment the reference count.
    public func ref() {
        refCount += 1
        assert(refCount > 0, "pbuf ref overflow")
    }

    // MARK: - Chain Length

    /// Count the number of pbufs in the chain starting from this pbuf.
    @inlinable
    public var chainLength: UInt16 {
        var count: UInt16 = 0
        var p: Pbuf? = self
        while p != nil {
            count += 1
            p = p?.next
        }
        return count
    }

    // MARK: - Concatenation

    /// Concatenate tail onto the end of head's chain.
    /// The caller transfers ownership of `tail` (must not free it separately).
    ///
    /// - Parameters:
    ///   - head: The head pbuf chain.
    ///   - tail: The tail pbuf chain to append.
    public static func cat(_ head: Pbuf, _ tail: Pbuf) {
        assert(head !== tail, "Creating an infinite loop")
        var p = head
        while let nextP = p.next {
            p.totLen &+= tail.totLen
            p = nextP
        }
        // p is now the last pbuf in head's chain.
        assert(p.totLen == p.len)
        p.totLen &+= tail.totLen
        p.next = tail
    }

    /// Chain tail onto head, incrementing tail's ref count.
    /// The caller retains ownership of `tail` and must free it when done.
    ///
    /// - Parameters:
    ///   - head: The head pbuf chain.
    ///   - tail: The tail pbuf chain to append.
    public static func chain(_ head: Pbuf, _ tail: Pbuf) {
        Pbuf.cat(head, tail)
        tail.ref()
    }

    /// Dechain the first pbuf from the rest of the chain.
    ///
    /// - Parameter p: The head of the chain.
    /// - Returns: The remainder of the chain, or `nil` if it was deallocated.
    public static func dechain(_ p: Pbuf) -> Pbuf? {
        guard let tail = p.next else {
            p.totLen = p.len
            return nil
        }

        tail.totLen = p.totLen - p.len
        p.next = nil
        p.totLen = p.len

        // Decrement ref on tail (since p no longer points to it).
        let freed: UInt8 = Self.free(tail)
        return freed > 0 ? nil : tail
    }

    // MARK: - Copy Between Pbufs

    /// Copy the contents of one pbuf chain into another.
    ///
    /// - Parameters:
    ///   - to: Destination pbuf chain.
    ///   - from: Source pbuf chain.
    /// - Returns: `.ok` on success, error code on failure.
    @discardableResult
    public static func copy(_ to: Pbuf, from: Pbuf) -> LWIPError {
        return copyPartialPbuf(to, from: from, copyLen: from.totLen, offset: 0)
    }

    /// Copy part of a source pbuf chain into a destination pbuf chain at an offset.
    ///
    /// - Parameters:
    ///   - to: Destination pbuf chain.
    ///   - from: Source pbuf chain.
    ///   - copyLen: Number of bytes to copy.
    ///   - offset: Offset into the destination.
    /// - Returns: `.ok` on success, error code on failure.
    @discardableResult
    public static func copyPartialPbuf(
        _ to: Pbuf,
        from: Pbuf,
        copyLen: UInt16,
        offset: UInt16
    ) -> LWIPError {
        guard from.totLen >= copyLen else { return .invalidArgument }
        guard to.totLen >= offset + copyLen else { return .invalidArgument }

        var pTo: Pbuf? = to
        var pFrom: Pbuf? = from
        var offsetTo: Int = Int(offset)
        var offsetFrom: Int = 0
        var remaining = Int(copyLen)

        // Advance pTo to the right offset.
        while let t = pTo, offsetTo >= Int(t.len) {
            offsetTo -= Int(t.len)
            pTo = t.next
        }

        while remaining > 0 {
            guard let t = pTo, let f = pFrom else { return .invalidArgument }

            let canCopy = Swift.min(Int(t.len) - offsetTo, Int(f.len) - offsetFrom)
            let toCopy = Swift.min(remaining, canCopy)

            memcpy(t.payload + offsetTo, f.payload + offsetFrom, toCopy)

            offsetTo += toCopy
            offsetFrom += toCopy
            remaining -= toCopy

            if offsetFrom >= Int(f.len) {
                offsetFrom = 0
                pFrom = f.next
            }
            if offsetTo >= Int(t.len) {
                offsetTo = 0
                pTo = t.next
            }
        }
        return .ok
    }

    /// Copy data from a pbuf chain into a flat buffer.
    ///
    /// - Parameters:
    ///   - dataptr: Destination buffer.
    ///   - len: Maximum bytes to copy.
    ///   - offset: Offset into the pbuf chain.
    /// - Returns: Number of bytes actually copied.
    public func copyPartial(to dataptr: UnsafeMutableRawPointer, len: UInt16, offset: UInt16) -> UInt16 {
        var p: Pbuf? = self
        var left: UInt16 = 0
        var copiedTotal: UInt16 = 0
        var off = offset
        var remaining = len

        while remaining > 0, let q = p {
            if off >= q.len {
                off -= q.len
            } else {
                let bufCopyLen = Swift.min(q.len - off, remaining)
                memcpy(dataptr + Int(left), q.payload + Int(off), Int(bufCopyLen))
                copiedTotal += bufCopyLen
                left += bufCopyLen
                remaining -= bufCopyLen
                off = 0
            }
            p = q.next
        }
        return copiedTotal
    }

    // MARK: - Get Contiguous

    /// Get a contiguous view of data in the pbuf chain.
    /// If the requested range is within a single pbuf, returns a direct pointer (zero-copy).
    /// Otherwise copies into the supplied buffer.
    ///
    /// - Parameters:
    ///   - buffer: Optional user-supplied buffer for copying.
    ///   - bufsize: Size of the user-supplied buffer.
    ///   - len: Number of bytes needed.
    ///   - offset: Offset into the pbuf chain.
    /// - Returns: Pointer to contiguous data, or `nil` on failure.
    public func contiguousBytes(
        buffer: UnsafeMutableRawPointer?,
        bufsize: Int,
        len: UInt16,
        offset: UInt16
    ) -> UnsafeMutableRawPointer? {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipConst(self, offset: offset, outOffset: &outOffset) else {
            return nil
        }
        if q.len >= outOffset + len {
            // Data is contiguous in this pbuf -- zero copy.
            return q.payload + Int(outOffset)
        }
        guard let buffer = buffer, bufsize >= Int(len) else {
            return nil
        }
        let copied = q.copyPartial(to: buffer, len: len, offset: outOffset)
        return copied == len ? buffer : nil
    }

    // MARK: - Take (Copy Into Pbuf)

    /// Copy data from an application buffer into this pbuf chain.
    ///
    /// - Parameters:
    ///   - dataptr: Source data.
    ///   - len: Number of bytes to copy.
    /// - Returns: `.ok` on success, error on failure.
    @discardableResult
    public func take(from dataptr: UnsafeRawPointer, len: UInt16) -> LWIPError {
        guard totLen >= len else { return .outOfMemory }

        var p: Pbuf? = self
        var copiedTotal: Int = 0
        var remaining = Int(len)

        while remaining > 0 {
            guard let q = p else { return .invalidArgument }
            let toCopy = Swift.min(remaining, Int(q.len))
            memcpy(q.payload, dataptr + copiedTotal, toCopy)
            remaining -= toCopy
            copiedTotal += toCopy
            p = q.next
        }
        return .ok
    }

    /// Copy data into the pbuf chain starting at a given offset.
    ///
    /// - Parameters:
    ///   - dataptr: Source data.
    ///   - len: Number of bytes to copy.
    ///   - offset: Offset into this pbuf chain.
    /// - Returns: `.ok` on success, error on failure.
    @discardableResult
    public func takeAt(from dataptr: UnsafeRawPointer, len: UInt16, offset: UInt16) -> LWIPError {
        var outOffset: UInt16 = 0
        guard let q = Self.skipMut(self, offset: offset, outOffset: &outOffset) else {
            return .outOfMemory
        }
        guard q.totLen >= outOffset + len else { return .outOfMemory }

        let firstCopy = Swift.min(UInt16(q.len - outOffset), len)
        memcpy(q.payload + Int(outOffset), dataptr, Int(firstCopy))

        let remaining = len - firstCopy
        if remaining > 0, let nextQ = q.next {
            return nextQ.take(from: dataptr + Int(firstCopy), len: remaining)
        }
        return remaining == 0 ? .ok : .outOfMemory
    }

    // MARK: - Byte Access

    /// Get a single byte from the pbuf chain at the given offset.
    /// Returns 0 if offset is out of range.
    @inlinable
    public func byte(at offset: UInt16) -> UInt8 {
        let result = tryByte(at: offset)
        return result >= 0 ? UInt8(result) : 0
    }

    /// Try to get a single byte from the pbuf chain.
    /// Returns the byte value (0-255) or -1 if offset is out of range.
    @inlinable
    public func tryByte(at offset: UInt16) -> Int {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipConst(self, offset: offset, outOffset: &outOffset) else {
            return -1
        }
        guard q.len > outOffset else { return -1 }
        return Int(q.payload.load(fromByteOffset: Int(outOffset), as: UInt8.self))
    }

    /// Put a single byte at the specified offset in the pbuf chain.
    /// Silently ignored if offset is out of range.
    @inlinable
    public func writeByte(at offset: UInt16, value: UInt8) {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipMut(self, offset: offset, outOffset: &outOffset) else { return }
        guard q.len > outOffset else { return }
        q.payload.storeBytes(of: value, toByteOffset: Int(outOffset), as: UInt8.self)
    }

    /// Legacy lwIP-style byte writer retained for compatibility with older call sites.
    @inlinable
    public func setByte(at offset: UInt16, to value: UInt8) {
        writeByte(at: offset, value: value)
    }

    // MARK: - Skip

    /// Skip a number of bytes at the start of a pbuf chain.
    ///
    /// - Parameters:
    ///   - offset: Number of bytes to skip.
    ///   - outOffset: On return, the offset within the returned pbuf.
    /// - Returns: The pbuf where the offset lands, or `nil` if out of range.
    public func skip(_ offset: UInt16, outOffset: inout UInt16) -> Pbuf? {
        return Pbuf.skipMut(self, offset: offset, outOffset: &outOffset)
    }

    @usableFromInline
    internal static func skipConst(_ p: Pbuf, offset: UInt16, outOffset: inout UInt16) -> Pbuf? {
        var offsetLeft = offset
        var q: Pbuf? = p
        while let current = q, current.len <= offsetLeft {
            offsetLeft -= current.len
            q = current.next
        }
        outOffset = offsetLeft
        return q
    }

    @usableFromInline
    internal static func skipMut(_ p: Pbuf, offset: UInt16, outOffset: inout UInt16) -> Pbuf? {
        return skipConst(p, offset: offset, outOffset: &outOffset)
    }

    // MARK: - Memcmp

    /// Compare pbuf contents at a given offset with a memory buffer.
    ///
    /// - Parameters:
    ///   - offset: Offset into the pbuf chain.
    ///   - s2: Buffer to compare against.
    ///   - n: Number of bytes to compare.
    /// - Returns: 0 if equal, 0xFFFF if pbuf is too short, or (diffIndex+1) otherwise.
    public func memcmp(offset: UInt16, _ s2: UnsafeRawPointer, _ n: UInt16) -> UInt16 {
        guard totLen >= offset + n else { return 0xFFFF }

        for i in 0..<n {
            let a = byte(at: offset + i)
            let b = s2.load(fromByteOffset: Int(i), as: UInt8.self)
            if a != b {
                return UInt16(Swift.min(Int(i) + 1, 0xFFFF))
            }
        }
        return 0
    }

    // MARK: - Memfind

    /// Find occurrence of `mem` (of length `memLen`) in this pbuf chain,
    /// starting at `startOffset`.
    ///
    /// - Parameters:
    ///   - mem: The pattern to search for.
    ///   - memLen: Length of the pattern.
    ///   - startOffset: Where to start searching.
    /// - Returns: The offset where found, or 0xFFFF if not found.
    public func memfind(_ mem: UnsafeRawPointer, memLen: UInt16, startOffset: UInt16 = 0) -> UInt16 {
        guard totLen >= memLen + startOffset else { return 0xFFFF }
        let maxStart = totLen - memLen
        for i in startOffset...maxStart {
            if memcmp(offset: i, mem, memLen) == 0 {
                return i
            }
        }
        return 0xFFFF
    }

    // MARK: - Strstr

    /// Find occurrence of a C string in this pbuf chain.
    ///
    /// - Parameter substr: Null-terminated string to search for.
    /// - Returns: The offset where found, or 0xFFFF if not found.
    public func strstr(_ substr: UnsafePointer<CChar>) -> UInt16 {
        let len = strlen(substr)
        guard len > 0, len < 0xFFFF, totLen != 0xFFFF else { return 0xFFFF }
        return memfind(UnsafeRawPointer(substr), memLen: UInt16(len))
    }

    // MARK: - Coalesce

    /// Create a single pbuf from a chain by copying all data.
    /// If the chain is already a single pbuf, returns it as-is.
    ///
    /// - Parameters:
    ///   - p: The pbuf chain to coalesce.
    ///   - layer: Layer for the new allocation.
    /// - Returns: A single contiguous pbuf, or the original if allocation fails.
    public static func coalesce(_ p: Pbuf, layer: PbufLayerOffset) -> Pbuf {
        guard p.next != nil else { return p }
        guard let q = Pbuf.clone(layer: layer, type: .ram, source: p) else {
            return p
        }
        let _ = Self.free(p)
        return q
    }

    // MARK: - Clone

    /// Allocate a new pbuf and copy the source pbuf's data into it.
    ///
    /// - Parameters:
    ///   - layer: Layer for the new allocation.
    ///   - type: Allocation type for the new pbuf.
    ///   - source: The source pbuf to clone.
    /// - Returns: A new pbuf with copied data, or `nil` on failure.
    public static func clone(
        layer: PbufLayerOffset,
        type: PbufType,
        source: Pbuf
    ) -> Pbuf? {
        guard let q = Pbuf.alloc(layer: layer, length: source.totLen, type: type) else {
            return nil
        }
        let err = Pbuf.copy(q, from: source)
        assert(err == .ok, "pbuf_copy failed in clone")
        return q
    }

    // MARK: - Split at 64K boundary

    /// Split a pbuf chain so the first part's total length fits in UInt16.
    /// The remainder is stored in `rest`.
    ///
    /// - Parameters:
    ///   - p: The pbuf chain to split.
    ///   - rest: On return, points to the remainder (or nil).
    public static func split64k(_ p: Pbuf, rest: inout Pbuf?) {
        rest = nil
        guard p.next != nil else { return }

        var totLenFront: UInt16 = p.len
        var i = p
        var r = p.next

        while let nextR = r {
            let newTotal = totLenFront &+ nextR.len
            guard newTotal >= totLenFront else { break }
            totLenFront = newTotal
            i = nextR
            r = nextR.next
        }

        i.next = nil
        if let remainder = r {
            var walker: Pbuf? = p
            while let w = walker {
                w.totLen &-= remainder.totLen
                assert(w.next != nil || w.totLen == w.len)
                walker = w.next
            }
            if p.flags.contains(.tcpFin) {
                // Move FIN flag to the remainder.
                var rFlags = remainder.flags
                rFlags.insert(.tcpFin)
                remainder.flags = rFlags
            }
            rest = remainder
        }
    }
}

// MARK: - Convenience Subscript

extension Pbuf {
    /// Subscript for byte-level access into the pbuf chain.
    public subscript(offset: UInt16) -> UInt8 {
        get { byte(at: offset) }
        set { writeByte(at: offset, value: newValue) }
    }
}

// MARK: - Instance method convenience (for IPv6 modules)

extension Pbuf {

    /// Current pbuf length (this segment only), as Int.
    @inlinable
    public var length: Int { Int(len) }

    /// Total chain length, as Int.
    @inlinable
    public var totalLength: Int { Int(totLen) }

    /// Free this pbuf chain (instance convenience wrapping static `Pbuf.free`).
    @inlinable
    @discardableResult
    public func free() -> UInt8 {
        Pbuf.free(self)
    }

    /// Realloc/shrink this pbuf to a new total length.
    @inlinable
    public func realloc(to newLen: UInt16) {
        Pbuf.realloc(self, newLen)
    }

    /// Merge this pbuf chain into a single contiguous pbuf.
    ///
    /// If this pbuf is already a single segment (no `next`), returns `self`
    /// unchanged. Otherwise, allocates a new `.ram` pbuf with room for the
    /// requested layer headers, copies all data from the chain into it, frees
    /// the original chain, and returns the new pbuf.
    ///
    /// - Important: On allocation failure the original pbuf is returned
    ///   unmodified.
    ///
    /// - Parameter layer: The `PbufLayerOffset` controlling how much header
    ///   space to reserve in the new contiguous buffer.
    /// - Returns: A single-segment pbuf (where `next` is `nil`), or `self`
    ///   if the chain was already a single segment or allocation failed.
    public func coalesce(layer: PbufLayerOffset) -> Pbuf {
        Pbuf.coalesce(self, layer: layer)
    }

    /// Copy the contents from another pbuf chain into this one.
    @inlinable
    @discardableResult
    public func copy(from src: Pbuf) -> LWIPError {
        // Copy up to the smaller of the two total lengths.
        let copyLen = Swift.min(self.totLen, src.totLen)
        var srcOff: UInt16 = 0
        var dstOff: UInt16 = 0
        while srcOff < copyLen {
            let byte = src.byte(at: srcOff)
            self.setByte(at: dstOff, to: byte)
            srcOff += 1
            dstOff += 1
        }
        return .ok
    }

    /// Copy partial data from another pbuf into this one at a given offset.
    @inlinable
    public func copyPartialFrom(_ src: Pbuf, length: Int, destOffset: Int) {
        for i in 0..<length {
            let b = src.byte(at: UInt16(i))
            self.setByte(at: UInt16(destOffset + i), to: b)
        }
    }

    /// Copy partial data from another pbuf with source offset.
    @inlinable
    public func copyPartialFrom(_ src: Pbuf, length: Int, srcOffset: Int, destOffset: Int) {
        for i in 0..<length {
            let b = src.byte(at: UInt16(srcOffset + i))
            self.setByte(at: UInt16(destOffset + i), to: b)
        }
    }

    /// Add header space (convenience returning Bool).
    @inlinable
    @discardableResult
    public func addHeader(_ size: Int) -> Bool {
        addHeader(size, force: false)
    }

    /// Get a byte at an Int offset.
    @inlinable
    public func getByte(at offset: Int) -> UInt8 {
        byte(at: UInt16(offset))
    }

    /// Get a big-endian UInt16 at an Int offset.
    @inlinable
    public func getUInt16(at offset: Int) -> UInt16 {
        let hi = UInt16(byte(at: UInt16(offset))) << 8
        let lo = UInt16(byte(at: UInt16(offset + 1)))
        return hi | lo
    }

    /// Get a big-endian UInt32 at an Int offset.
    @inlinable
    public func getUInt32(at offset: Int) -> UInt32 {
        let b0 = UInt32(byte(at: UInt16(offset))) << 24
        let b1 = UInt32(byte(at: UInt16(offset + 1))) << 16
        let b2 = UInt32(byte(at: UInt16(offset + 2))) << 8
        let b3 = UInt32(byte(at: UInt16(offset + 3)))
        return b0 | b1 | b2 | b3
    }

    /// Get a UInt32 at an offset in network byte order (no conversion, raw 4 bytes).
    @inlinable
    public func getUInt32NetworkOrder(at offset: Int) -> UInt32 {
        if offset + 4 <= length {
            return payload.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
        }
        // Cross-pbuf: read bytes individually
        let b0 = UInt32(byte(at: UInt16(offset)))
        let b1 = UInt32(byte(at: UInt16(offset + 1)))
        let b2 = UInt32(byte(at: UInt16(offset + 2)))
        let b3 = UInt32(byte(at: UInt16(offset + 3)))
        return (b0) | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    // ref() is already defined in the main Pbuf class
}

// MARK: - Utility Methods

extension Pbuf {

    /// Get a single byte at the given offset across the pbuf chain.
    ///
    /// - Parameter offset: Byte offset into the pbuf chain.
    /// - Returns: The byte at that offset, or `nil` if offset is out of bounds.
    public func getByteAt(offset: UInt16) -> UInt8? {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipConst(self, offset: offset, outOffset: &outOffset) else {
            return nil
        }
        guard q.len > outOffset else { return nil }
        return q.payload.load(fromByteOffset: Int(outOffset), as: UInt8.self)
    }

    /// Set a single byte at the given offset across the pbuf chain.
    ///
    /// Silently ignored if offset is out of range.
    ///
    /// - Parameters:
    ///   - byte: The byte value to write.
    ///   - offset: Byte offset into the pbuf chain.
    public func putByte(_ byte: UInt8, at offset: UInt16) {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipMut(self, offset: offset, outOffset: &outOffset) else { return }
        guard q.len > outOffset else { return }
        q.payload.storeBytes(of: byte, toByteOffset: Int(outOffset), as: UInt8.self)
    }

    /// Compare bytes in the pbuf chain starting at `offset` with the contents of `data`.
    ///
    /// Skips to the correct pbuf first, then reads byte-by-byte using the
    /// existing `byte(at:)` which traverses the sub-chain.
    ///
    /// - Parameters:
    ///   - offset: Offset into the pbuf chain where comparison starts.
    ///   - data: The byte sequence to compare against.
    /// - Returns: `true` if the bytes match, `false` otherwise (including when
    ///   the pbuf chain is too short).
    public func memoryCompare(at offset: UInt16, with data: UnsafeRawBufferPointer) -> Bool {
        let n = UInt16(data.count)
        // Check for overflow and sufficient length.
        guard offset &+ n >= offset, totLen >= offset &+ n else { return false }

        // Skip to the correct pbuf in the chain.
        var q: Pbuf? = self
        var start = offset
        while let current = q, current.len <= start {
            start -= current.len
            q = current.next
        }
        guard let startPbuf = q else { return false }

        // Compare byte-by-byte. byte(at:) on startPbuf walks the sub-chain
        // so (start + i) can exceed startPbuf.len safely.
        for i: UInt16 in 0..<n {
            let a = startPbuf.byte(at: start + i)
            let b = data[Int(i)]
            if a != b { return false }
        }
        return true
    }

    /// Search for a byte sequence within the pbuf chain starting from `offset`.
    ///
    /// - Parameters:
    ///   - data: The byte sequence to search for.
    ///   - offset: Starting offset in the pbuf chain.
    /// - Returns: The offset of the first match, or `nil` if not found.
    public func findMemory(_ data: UnsafeRawBufferPointer, startingAt offset: UInt16 = 0) -> UInt16? {
        let memLen = UInt16(data.count)
        guard totLen >= memLen &+ offset, memLen &+ offset >= offset else { return nil }
        let maxStart = totLen - memLen
        for i in offset...maxStart {
            if memcmp(offset: i, data.baseAddress!, memLen) == 0 {
                return i
            }
        }
        return nil
    }

    /// Search for a string within the pbuf chain.
    ///
    /// Convenience wrapper around `findMemory`.
    ///
    /// - Parameter string: The string to search for.
    /// - Returns: The offset of the first match, or `nil` if not found.
    public func findString(_ string: String) -> UInt16? {
        return string.withCString { cstr in
            let len = strlen(cstr)
            guard len > 0, len < 0xFFFF, totLen != 0xFFFF else { return nil }
            let buf = UnsafeRawBufferPointer(start: UnsafeRawPointer(cstr), count: len)
            return findMemory(buf, startingAt: 0)
        }
    }

    /// If the requested byte range is contiguous in memory, return a pointer to
    /// it directly. Otherwise, copy the range into the provided buffer and return
    /// a pointer to that buffer.
    ///
    /// - Parameters:
    ///   - length: Number of bytes needed.
    ///   - offset: Offset into the pbuf chain.
    ///   - buffer: User-supplied buffer for copying when data spans pbufs. Pass
    ///     `nil` if only zero-copy access is desired.
    /// - Returns: A pointer to the contiguous data, or `nil` on failure.
    public func getContiguous(
        length: UInt16,
        at offset: UInt16,
        buffer: UnsafeMutableRawBufferPointer?
    ) -> UnsafeMutableRawPointer? {
        var outOffset: UInt16 = 0
        guard let q = Pbuf.skipConst(self, offset: offset, outOffset: &outOffset) else {
            return nil
        }
        if q.len >= outOffset + length {
            // Data is contiguous in this pbuf -- zero copy.
            return q.payload + Int(outOffset)
        }
        guard let buffer = buffer, buffer.count >= Int(length) else {
            return nil
        }
        let copied = q.copyPartial(
            to: buffer.baseAddress!,
            len: length,
            offset: outOffset
        )
        return copied == length ? buffer.baseAddress! : nil
    }

    /// Copy data from another pbuf chain into this one at the given offset.
    ///
    /// - Parameters:
    ///   - pbuf: Source pbuf chain.
    ///   - length: Number of bytes to copy.
    ///   - offset: Offset into this (destination) pbuf chain.
    /// - Returns: `.ok` on success, error code on failure.
    @discardableResult
    public func copyFrom(pbuf source: Pbuf, length: UInt16, at offset: UInt16) -> LWIPError {
        return Pbuf.copyPartialPbuf(self, from: source, copyLen: length, offset: offset)
    }

    /// Adjust the payload pointer like `header(_:force:)` but always forces,
    /// allowing the payload to move even on REF/ROM pbufs.
    ///
    /// - Parameter increment: Signed offset. Positive reveals headers (moves
    ///   payload backward), negative hides them (moves payload forward).
    /// - Returns: 0 on success, non-zero on failure.
    public func adjustHeaderForce(_ increment: Int16) -> UInt8 {
        return header(increment, force: true)
    }

    /// Free header space from the front of this pbuf chain.
    ///
    /// Shrinks (or removes) the first pbuf(s) until `size` bytes have been
    /// consumed. If the first pbuf is fully consumed, it is freed and the next
    /// pbuf in the chain is returned.
    ///
    /// - Parameter size: Number of header bytes to remove from the front.
    /// - Returns: The remaining pbuf chain, or `nil` if fully consumed.
    public func freeHeader(size: UInt16) -> Pbuf? {
        return Pbuf.freeHeader(self, size: size)
    }
}

// MARK: - Checksum-on-copy (LWIP_CHECKSUM_ON_COPY)

extension Pbuf {

    /// Copy data into the pbuf at `offset` and simultaneously compute the
    /// Internet checksum of the copied data.
    ///
    /// Used when checksum-on-copy is enabled to avoid a second pass over the
    /// data for checksum computation.
    ///
    /// - Parameters:
    ///   - offset: Byte offset into this pbuf at which to start writing.
    ///   - src: Pointer to the data to copy.
    ///   - len: Number of bytes to copy.
    ///   - checksum: On entry, the running checksum accumulator. On return,
    ///     updated with the checksum of the copied data folded in.
    @inlinable
    public func fillChecksum(at offset: UInt16, src: UnsafeRawPointer,
                             len: UInt16, checksum: inout UInt16) {
        guard offset + len <= self.len else { return }
        let dst = payload.advanced(by: Int(offset))
        let rawChk = InetChecksum.checksumCopy(dst: dst, src: src, len: len)
        // Fold the new raw checksum into the running accumulator
        var acc = UInt32(checksum) + UInt32(rawChk)
        acc = InetChecksum.foldUInt32(acc)
        checksum = UInt16(acc & 0xFFFF)
    }
}

// MARK: - Sequence Conformance (Chain Iteration)

/// Allows iterating over all pbufs in a chain with `for pbuf in chain`.
extension Pbuf: Sequence {
    public struct ChainIterator: IteratorProtocol {
        private var current: Pbuf?

        init(_ start: Pbuf?) {
            self.current = start
        }

        public mutating func next() -> Pbuf? {
            guard let node = current else { return nil }
            current = node.next
            return node
        }
    }

    public func makeIterator() -> ChainIterator {
        ChainIterator(self)
    }
}
