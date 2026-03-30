//
//  Memp.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Pool Type Enum

/// Enumeration of all built-in lwIP memory pool types.
/// Matches the C `memp_t` enum generated from `memp_std.h`.
public enum MemPoolType: Int, CaseIterable, Sendable {
    case rawProtocolControlBlock = 0
    case udpProtocolControlBlock
    case tcpProtocolControlBlock
    case tcpProtocolControlBlockListen
    case tcpSegment
    case reassemblyData
    case arpQueueEntry
    case igmpGroup
    case systemTimeout
    case netbuf
    case netconn
    case tcpipMessageAPI
    case tcpipMessageInputPacket
    case dnsTableEntry
    case nd6QueueEntry
    case ipv6ReassemblyData
    case mld6Group
    case pbuf
    case pbufPool

    /// Human-readable description for debugging.
    public var description: String {
        switch self {
        case .rawProtocolControlBlock:            return "RAW_PCB"
        case .udpProtocolControlBlock:            return "UDP_PCB"
        case .tcpProtocolControlBlock:            return "TCP_PCB"
        case .tcpProtocolControlBlockListen:      return "TCP_PCB_LISTEN"
        case .tcpSegment:                         return "TCP_SEG"
        case .reassemblyData:                     return "REASSDATA"
        case .arpQueueEntry:                      return "ARP_QUEUE"
        case .igmpGroup:                          return "IGMP_GROUP"
        case .systemTimeout:                      return "SYS_TIMEOUT"
        case .netbuf:                             return "NETBUF"
        case .netconn:                            return "NETCONN"
        case .tcpipMessageAPI:                    return "TCPIP_MSG_API"
        case .tcpipMessageInputPacket:            return "TCPIP_MSG_INPKT"
        case .dnsTableEntry:                      return "DNS_TABLE_ENTRY"
        case .nd6QueueEntry:                      return "ND6_QUEUE"
        case .ipv6ReassemblyData:                 return "IP6_REASSDATA"
        case .mld6Group:                          return "MLD6_GROUP"
        case .pbuf:                               return "PBUF"
        case .pbufPool:                           return "PBUF_POOL"
        }
    }
}

// MARK: - Pool Statistics

/// Statistics for a single memory pool.
public final class PoolStats: @unchecked Sendable {
    /// Number of elements available (configured capacity).
    public internal(set) var available: Int = 0
    /// Number of elements currently in use.
    public private(set) var used: Int = 0
    /// Peak number of elements ever in use simultaneously.
    public private(set) var peak: Int = 0
    /// Number of allocation failures.
    public private(set) var errors: Int = 0

    private let lock = NSLock()

    @usableFromInline
    internal func recordAlloc() {
        lock.lock()
        used += 1
        if used > peak { peak = used }
        lock.unlock()
    }

    @usableFromInline
    internal func recordFree() {
        lock.lock()
        used -= 1
        lock.unlock()
    }

    @usableFromInline
    internal func recordError() {
        lock.lock()
        errors += 1
        lock.unlock()
    }
}

// MARK: - Pool Free Node

/// Internal linked-list node for the pool free list.
/// Stored inside the first bytes of each free element.
@usableFromInline
internal struct PoolFreeNode {
    @usableFromInline var next: UnsafeMutablePointer<PoolFreeNode>?
}

// MARK: - Pool Descriptor

/// Describes a single memory pool: element size, count, storage, and free list.
public final class PoolDescriptor: @unchecked Sendable {
    /// Human-readable name.
    public let name: String
    /// Size of each element in bytes (aligned).
    public let elementSize: Int
    /// Number of elements in the pool.
    public let count: Int
    /// Statistics for this pool.
    public let stats: PoolStats

    /// Backing storage for pool-based allocation.
    /// `nil` when using heap fallback mode (`useMalloc == true`).
    internal var storage: UnsafeMutableRawPointer?

    /// Head of the free list.
    internal var freeList: UnsafeMutablePointer<PoolFreeNode>?

    /// Lock for thread-safe access to the free list.
    internal let lock = NSLock()

    /// When true, this pool falls back to `Mem.malloc`/`Mem.free` instead of
    /// using a pre-allocated block (equivalent to MEMP_MEM_MALLOC).
    public let useMalloc: Bool

    /// Create a pool descriptor.
    ///
    /// - Parameters:
    ///   - name: Descriptive name for debugging.
    ///   - elementSize: Size in bytes of each pool element.
    ///   - count: Number of elements to pre-allocate.
    ///   - useMalloc: If `true`, delegate to `Mem.malloc`/`Mem.free`.
    public init(name: String, elementSize: Int, count: Int, useMalloc: Bool = false) {
        self.name = name
        self.elementSize = MemoryAlignment.alignedSize(max(elementSize, MemoryLayout<PoolFreeNode>.size))
        self.count = count
        self.stats = PoolStats()
        self.useMalloc = useMalloc
        self.storage = nil
        self.freeList = nil
    }

    deinit {
        if let storage = storage {
            Darwin.free(storage)
        }
    }

    /// Initialize the pool, allocating backing memory and linking the free list.
    public func initialize() {
        stats.available = count

        guard !useMalloc else { return }

        let totalSize = count * elementSize
        guard totalSize > 0 else { return }

        storage = Darwin.malloc(totalSize)
        guard let base = storage else { return }

        // Zero out
        memset(base, 0, totalSize)

        // Build the free list in reverse so element 0 is at the head.
        freeList = nil
        for i in stride(from: count - 1, through: 0, by: -1) {
            let node = (base + i * elementSize).assumingMemoryBound(to: PoolFreeNode.self)
            node.pointee.next = freeList
            freeList = node
        }
    }

    /// Allocate one element from this pool.
    ///
    /// - Returns: Pointer to the element, or `nil` if the pool is exhausted.
    @usableFromInline
    internal func alloc() -> UnsafeMutableRawPointer? {
        if useMalloc {
            let ptr = Mem.malloc(elementSize)
            if ptr != nil {
                stats.recordAlloc()
            } else {
                stats.recordError()
            }
            return ptr
        }

        lock.lock()
        guard let node = freeList else {
            lock.unlock()
            stats.recordError()
            return nil
        }
        freeList = node.pointee.next
        lock.unlock()

        stats.recordAlloc()
        let ptr = UnsafeMutableRawPointer(node)
        memset(ptr, 0, elementSize)

        if Memp.overflowCheckEnabled {
            overflowInitElement(ptr)
        }
        return ptr
    }

    /// Free one element back to this pool.
    ///
    /// - Parameter ptr: The element to return. Must have been obtained from `alloc()`.
    @usableFromInline
    internal func free(_ ptr: UnsafeMutableRawPointer) {
        if useMalloc {
            stats.recordFree()
            Mem.free(ptr)
            return
        }

        if Memp.overflowCheckEnabled {
            overflowCheckElement(ptr)
        }

        let node = ptr.assumingMemoryBound(to: PoolFreeNode.self)
        lock.lock()
        node.pointee.next = freeList
        freeList = node
        lock.unlock()

        stats.recordFree()
    }

    // MARK: - Overflow Detection

    /// Sentinel value used for pool overflow detection.
    private static let overflowSentinel: UInt16 = 0x5A5A

    /// Write sentinel bytes at the end of a pool element for overflow detection.
    internal func overflowInitElement(_ ptr: UnsafeMutableRawPointer) {
        let sentinelOffset = elementSize - MemoryLayout<UInt16>.size
        guard sentinelOffset > 0 else { return }
        (ptr + sentinelOffset).storeBytes(of: PoolDescriptor.overflowSentinel, as: UInt16.self)
    }

    /// Verify that the sentinel bytes at the end of a pool element are intact.
    internal func overflowCheckElement(_ ptr: UnsafeMutableRawPointer) {
        let sentinelOffset = elementSize - MemoryLayout<UInt16>.size
        guard sentinelOffset > 0 else { return }
        let val = (ptr + sentinelOffset).load(as: UInt16.self)
        if val != PoolDescriptor.overflowSentinel {
            Debug.print(DebugFlags.on.rawValue,
                        "Memp(\(name)): overflow detected at \(ptr)\n")
        }
    }
}

// MARK: - Memp (Memory Pool Manager)

/// Central memory pool manager. Manages all built-in pools and supports custom pools.
public enum Memp {
    /// All built-in pool descriptors, indexed by `MemPoolType.rawValue`.
    public private(set) static nonisolated(unsafe) var pools: [PoolDescriptor] = []

    /// Whether the pool system has been initialized.
    public private(set) static nonisolated(unsafe) var initialized = false

    /// Whether overflow sentinel checking is enabled for pool allocations.
    /// Set before calling `initialize()`.
    public static var overflowCheckEnabled: Bool = false

    // MARK: - Default Pool Configuration

    /// Default pool sizes for each built-in type.
    /// Format: (elementSize, count). These match lwIP defaults and can be
    /// overridden via `LWIPConfig` before calling `initialize()`.
    private static let defaultPoolConfig: [(Int, Int)] = [
        (  40,  4), // rawPcb
        (  48,  4), // udpPcb
        ( 160,  5), // tcpPcb
        (  80,  8), // tcpPcbListen
        (  32, 16), // tcpSeg
        (  32,  5), // reassData
        (  32, 30), // arpQueue
        (  32,  8), // igmpGroup
        (  32,  8), // sysTimeout
        (  48, 16), // netbuf
        (  64,  4), // netconn
        (  32,  8), // tcpipMsgApi
        (  32,  8), // tcpipMsgInPkt
        ( 200,  1), // dnsTableEntry
        (  32, 20), // nd6Queue
        (  32,  5), // ip6Reassdata
        (  32,  8), // mld6Group
        (  24, 16), // pbuf (struct-only, for REF/ROM)
        ( 640, 16), // pbufPool (struct + payload)
    ]

    // MARK: - Initialization

    /// Initialize all built-in memory pools.
    /// Must be called once at startup before any allocation.
    public static func initialize() {
        guard !initialized else { return }

        pools = []
        pools.reserveCapacity(MemPoolType.allCases.count)

        for poolType in MemPoolType.allCases {
            let (elemSize, count) = defaultPoolConfig[poolType.rawValue]
            let desc = PoolDescriptor(
                name: poolType.description,
                elementSize: elemSize,
                count: count
            )
            desc.initialize()
            pools.append(desc)
        }

        initialized = true
    }

    /// Initialize all pools with custom configuration.
    ///
    /// - Parameter config: Array of `(elementSize, count)` tuples, one per `MemPoolType`
    ///   in raw-value order.
    public static func initialize(config: [(elementSize: Int, count: Int)]) {
        guard !initialized else { return }
        precondition(config.count == MemPoolType.allCases.count,
                     "Config must have exactly \(MemPoolType.allCases.count) entries")

        pools = []
        pools.reserveCapacity(config.count)

        for (i, poolType) in MemPoolType.allCases.enumerated() {
            let desc = PoolDescriptor(
                name: poolType.description,
                elementSize: config[i].elementSize,
                count: config[i].count
            )
            desc.initialize()
            pools.append(desc)
        }

        initialized = true
    }

    // MARK: - Allocation (by pool type)

    /// Allocate an element from the specified pool type.
    ///
    /// - Parameter type: The pool to allocate from.
    /// - Returns: A pointer to the allocated element, or `nil` if the pool is empty.
    @inlinable
    public static func malloc(_ type: MemPoolType) -> UnsafeMutableRawPointer? {
        guard type.rawValue < pools.count else { return nil }
        return pools[type.rawValue].alloc()
    }

    /// Free an element back to its pool.
    ///
    /// - Parameters:
    ///   - type: The pool the element belongs to.
    ///   - mem: The element to free. `nil` is a no-op.
    @inlinable
    public static func free(_ type: MemPoolType, _ mem: UnsafeMutableRawPointer?) {
        guard let mem = mem, type.rawValue < pools.count else { return }
        pools[type.rawValue].free(mem)
    }

    // MARK: - Allocation (by pool descriptor)

    /// Allocate an element from a custom pool descriptor.
    ///
    /// - Parameter desc: The pool descriptor.
    /// - Returns: Pointer to the allocated element, or `nil` on failure.
    @inlinable
    public static func mallocPool(_ desc: PoolDescriptor) -> UnsafeMutableRawPointer? {
        return desc.alloc()
    }

    /// Free an element back to a custom pool descriptor.
    ///
    /// - Parameters:
    ///   - desc: The pool descriptor.
    ///   - mem: The element to free.
    @inlinable
    public static func freePool(_ desc: PoolDescriptor, _ mem: UnsafeMutableRawPointer?) {
        guard let mem = mem else { return }
        desc.free(mem)
    }

    // MARK: - Initialize a single custom pool

    /// Initialize a custom pool descriptor (for user-defined pools).
    ///
    /// - Parameter desc: The pool descriptor to initialize.
    public static func initPool(_ desc: PoolDescriptor) {
        desc.initialize()
    }

    // MARK: - Overflow Detection

    /// Verify overflow sentinels on all in-use elements across all pools.
    ///
    /// Walks every pool and checks each allocated element for sentinel
    /// corruption.
    /// Only meaningful when `overflowCheckEnabled` is true.
    public static func overflowCheckAll() {
        guard overflowCheckEnabled else { return }
        for pool in pools where !pool.useMalloc {
            guard let storage = pool.storage else { continue }
            for i in 0..<pool.count {
                let ptr = storage + i * pool.elementSize
                // Only check elements that are NOT on the free list.
                if !isOnFreeList(pool: pool, ptr: ptr) {
                    pool.overflowCheckElement(ptr)
                }
            }
        }
    }

    /// Run sanity checks on all pool free lists.
    ///
    /// Verifies that every free-list node points within the pool's storage
    /// bounds and that the list length does not exceed the pool's capacity.
    public static func sanity() {
        for pool in pools where !pool.useMalloc {
            guard let storage = pool.storage else { continue }
            let end = storage + pool.count * pool.elementSize
            var node = pool.freeList
            var visited = 0
            while let n = node {
                let p = UnsafeMutableRawPointer(n)
                if p < storage || p >= end {
                    Debug.print(DebugFlags.on.rawValue,
                                "Memp(\(pool.name)): free-list pointer out of bounds\n")
                    break
                }
                visited += 1
                if visited > pool.count {
                    Debug.print(DebugFlags.on.rawValue,
                                "Memp(\(pool.name)): free-list cycle detected\n")
                    break
                }
                node = n.pointee.next
            }
        }
    }

    /// Check if a pointer is currently on a pool's free list.
    private static func isOnFreeList(pool: PoolDescriptor, ptr: UnsafeMutableRawPointer) -> Bool {
        var node = pool.freeList
        while let n = node {
            if UnsafeMutableRawPointer(n) == ptr { return true }
            node = n.pointee.next
        }
        return false
    }
}
