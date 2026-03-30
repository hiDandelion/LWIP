//
//  Mem.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Overflow Detection Configuration

/// Sentinel value written before and after allocations for overflow detection.
private let memOverflowSentinel: UInt32 = 0x5A5A_A5A5
/// Number of bytes used for each overflow sentinel guard.
private let memOverflowGuardSize = MemoryLayout<UInt32>.size

// MARK: - Memory Size Type

/// Memory size type used throughout the allocator.
public typealias MemSize = Int

// MARK: - Memory Statistics

/// Tracks memory usage statistics (allocations, frees, high water marks).
public final class MemStats: @unchecked Sendable {
    /// Total bytes currently allocated.
    public private(set) var used: Int = 0
    /// Peak bytes ever allocated simultaneously.
    public private(set) var peak: Int = 0
    /// Total number of successful allocations.
    public private(set) var allocCount: Int = 0
    /// Total number of frees.
    public private(set) var freeCount: Int = 0
    /// Total number of allocation failures.
    public private(set) var errorCount: Int = 0

    /// Lock for concurrent access.
    private let lock = NSLock()

    @usableFromInline
    internal func recordAlloc(size: Int) {
        lock.lock()
        used += size
        allocCount += 1
        if used > peak {
            peak = used
        }
        lock.unlock()
    }

    @usableFromInline
    internal func recordFree(size: Int) {
        lock.lock()
        used -= size
        freeCount += 1
        lock.unlock()
    }

    @usableFromInline
    internal func recordError() {
        lock.lock()
        errorCount += 1
        lock.unlock()
    }

    /// Reset all statistics to zero.
    public func reset() {
        lock.lock()
        used = 0
        peak = 0
        allocCount = 0
        freeCount = 0
        errorCount = 0
        lock.unlock()
    }
}

// MARK: - Pool-Based Malloc Helper

/// Header prepended to each pool-based allocation so that `free` can identify
/// which pool the element came from.
@usableFromInline
internal struct MallocPoolHelper {
    /// Index of the pool this allocation came from.
    var poolIndex: Int
    /// Original requested size (for statistics / overflow checking).
    var size: Int
}

/// Size of the helper header, aligned.
@usableFromInline
internal let mallocPoolHelperSize = MemoryAlignment.alignedSize(MemoryLayout<MallocPoolHelper>.size)

// MARK: - Mem (Memory Manager)

/// lwIP-style heap memory manager.
///
/// Wraps the system allocator with optional tracking. All returned pointers are
/// aligned to `MEM_ALIGNMENT`.
///
/// Supports two modes:
/// - **System allocator** (default): delegates to the platform `malloc`/`free`.
/// - **Pool-based** (`MEM_USE_POOLS`): routes allocations through a sorted array
///   of fixed-size memory pools, eliminating heap fragmentation. Enable by
///   setting `lwipConfig.memUsePools = true` and calling
///   `Mem.initializePools(sizes:)` before use.
public enum Mem {
    /// Global memory statistics instance.
    public static let stats = MemStats()

    /// Whether statistics tracking is enabled. Set before first allocation.
    public static var statsEnabled: Bool {
        get { _statsEnabled }
        set { _statsEnabled = newValue }
    }
    private static var _statsEnabled: Bool = true

    /// Whether overflow detection sentinels are enabled. When true, guard
    /// bytes are placed before and after every allocation and verified on free.
    /// Set before first allocation.
    public static var overflowCheckEnabled: Bool = false

    /// Whether to use pool-based allocation instead of the system allocator.
    /// Set before first allocation and call `initializePools(sizes:)`.
    public static var usePools: Bool = false

    /// When `true` and `usePools` is active, a failed allocation in the
    /// best-fit pool will try the next larger pool.
    public static var usePoolsTryBigger: Bool = false

    /// Sorted array of pool descriptors used when `usePools` is `true`.
    /// Pools are ordered by element size (ascending). Each element size
    /// must include room for the `MallocPoolHelper` header.
    public private(set) static nonisolated(unsafe) var mallocPools: [PoolDescriptor] = []

    // MARK: - Initialization

    /// Initialize the memory subsystem. When `usePools` is `true`, this also
    /// initializes any previously configured malloc pools.
    public static func initialize() {
        // System allocator needs no initialization.
        // Pool storage is initialized in initializePools(sizes:).
    }

    /// Configure and initialize the pool-based malloc pools.
    ///
    /// Each entry defines a pool with elements of the given size and count.
    /// Pools are sorted by size automatically. The element size is the
    /// **usable** allocation size; the helper header is added internally.
    ///
    /// Example matching C lwIP `lwippools.h`:
    /// ```swift
    /// Mem.usePools = true
    /// Mem.initializePools(sizes: [
    ///     (usableSize: 256,  count: 5),
    ///     (usableSize: 512,  count: 5),
    ///     (usableSize: 1512, count: 5),
    /// ])
    /// ```
    ///
    /// - Parameter sizes: Array of `(usableSize, count)` tuples.
    public static func initializePools(sizes: [(usableSize: Int, count: Int)]) {
        let sorted = sizes.sorted { $0.usableSize < $1.usableSize }
        mallocPools = sorted.enumerated().map { index, entry in
            // Each pool element must hold the helper header plus the usable payload.
            let totalElementSize = mallocPoolHelperSize + MemoryAlignment.alignedSize(entry.usableSize)
            let desc = PoolDescriptor(
                name: "MALLOC_\(entry.usableSize)",
                elementSize: totalElementSize,
                count: entry.count
            )
            desc.initialize()
            return desc
        }
    }

    // MARK: - malloc

    /// Allocate a block of at least `size` bytes.
    ///
    /// - Parameter size: Minimum number of bytes to allocate. Must be > 0.
    /// - Returns: An aligned pointer to the allocated memory, or `nil` on failure.
    public static func malloc(_ size: MemSize) -> UnsafeMutableRawPointer? {
        guard size > 0 else { return nil }

        if usePools {
            return mallocFromPools(size)
        }
        return mallocFromSystem(size)
    }

    /// System-allocator path for `malloc`.
    private static func mallocFromSystem(_ size: MemSize) -> UnsafeMutableRawPointer? {
        let alignedSize = MemoryAlignment.alignedSize(size)
        let headerSize = MemoryAlignment.alignedSize(MemoryLayout<Int>.size)

        // When overflow checking is enabled, add guard bytes before and after.
        let guardSize = overflowCheckEnabled ? memOverflowGuardSize : 0
        let totalSize = headerSize + guardSize + alignedSize + guardSize
        guard let raw = Darwin.malloc(totalSize) else {
            if statsEnabled { stats.recordError() }
            return nil
        }

        // Store size header.
        let headerPtr = raw.assumingMemoryBound(to: Int.self)
        headerPtr.pointee = alignedSize

        let result: UnsafeMutableRawPointer
        if overflowCheckEnabled {
            let preGuard = raw + headerSize
            preGuard.storeBytes(of: memOverflowSentinel, as: UInt32.self)
            result = preGuard + guardSize
            let postGuard = result + alignedSize
            postGuard.storeBytes(of: memOverflowSentinel, as: UInt32.self)
        } else {
            result = raw + headerSize
        }

        if statsEnabled { stats.recordAlloc(size: alignedSize) }
        return result
    }

    /// Pool-based path for `malloc`. Finds the smallest pool that fits
    /// the requested size plus the helper header, then allocates from it.
    private static func mallocFromPools(_ size: MemSize) -> UnsafeMutableRawPointer? {
        let requiredSize = MemoryAlignment.alignedSize(size) + mallocPoolHelperSize

        for (index, pool) in mallocPools.enumerated() {
            guard requiredSize <= pool.elementSize else { continue }

            guard let element = pool.alloc() else {
                // Pool exhausted — try the next larger pool if configured.
                if usePoolsTryBigger && index < mallocPools.count - 1 {
                    continue
                }
                if statsEnabled { stats.recordError() }
                return nil
            }

            // Write the helper header (pool index + requested size).
            let helper = element.assumingMemoryBound(to: MallocPoolHelper.self)
            helper.pointee = MallocPoolHelper(poolIndex: index, size: size)

            let result = element + mallocPoolHelperSize

            if statsEnabled { stats.recordAlloc(size: size) }

            if overflowCheckEnabled {
                // Fill unused bytes beyond the requested size with a sentinel pattern.
                let usableInPool = pool.elementSize - mallocPoolHelperSize
                if usableInPool > size {
                    memset(result + size, 0xCD, usableInPool - size)
                }
            }

            return result
        }

        // No pool large enough.
        if statsEnabled { stats.recordError() }
        return nil
    }

    // MARK: - free

    /// Free memory previously returned by `malloc`, `calloc`, or `trim`.
    ///
    /// - Parameter ptr: Pointer previously returned by this allocator. `nil` is a no-op.
    public static func free(_ ptr: UnsafeMutableRawPointer?) {
        guard let ptr = ptr else { return }

        if usePools {
            freeToPool(ptr)
            return
        }

        let headerSize = MemoryAlignment.alignedSize(MemoryLayout<Int>.size)
        let guardSize = overflowCheckEnabled ? memOverflowGuardSize : 0

        let raw = ptr - guardSize - headerSize
        let size = raw.assumingMemoryBound(to: Int.self).pointee

        if overflowCheckEnabled {
            overflowCheckElement(ptr, size: size)
        }

        if statsEnabled { stats.recordFree(size: size) }
        Darwin.free(raw)
    }

    /// Return a pool-based allocation to its originating pool.
    private static func freeToPool(_ ptr: UnsafeMutableRawPointer) {
        let element = ptr - mallocPoolHelperSize
        let helper = element.assumingMemoryBound(to: MallocPoolHelper.self).pointee

        guard helper.poolIndex >= 0, helper.poolIndex < mallocPools.count else {
            Debug.print(DebugFlags.on.rawValue,
                        "Mem: pool free with invalid pool index \(helper.poolIndex)\n")
            return
        }

        let pool = mallocPools[helper.poolIndex]

        if statsEnabled { stats.recordFree(size: helper.size) }

        if overflowCheckEnabled {
            // Verify that sentinel bytes beyond the requested size are intact.
            let usableInPool = pool.elementSize - mallocPoolHelperSize
            if usableInPool > helper.size {
                for i in helper.size..<usableInPool {
                    let byte = (ptr + i).load(as: UInt8.self)
                    if byte != 0xCD {
                        Debug.print(DebugFlags.on.rawValue,
                                    "Mem: pool overflow detected at offset \(i)\n")
                        break
                    }
                }
            }
        }

        pool.free(element)
    }

    // MARK: - calloc

    /// Allocate and zero-fill memory for `count` objects each of `size` bytes.
    ///
    /// - Parameters:
    ///   - count: Number of objects.
    ///   - size: Size of each object in bytes.
    /// - Returns: Pointer to zeroed memory, or `nil` on failure.
    @inlinable
    public static func calloc(_ count: MemSize, _ size: MemSize) -> UnsafeMutableRawPointer? {
        let totalSize = count * size
        guard totalSize > 0 else { return nil }

        guard let ptr = malloc(totalSize) else { return nil }
        memset(ptr, 0, totalSize)
        return ptr
    }

    // MARK: - trim (shrink)

    /// Shrink a previously allocated block. The returned pointer is always the
    /// same as the input (we just update the tracked size).
    ///
    /// For pool-based allocations, trimming is a no-op (the element stays in its
    /// original pool).
    ///
    /// - Parameters:
    ///   - ptr: Pointer previously returned by `malloc`.
    ///   - newSize: Desired new size (must be <= original size).
    /// - Returns: The same pointer, or `nil` if `newSize` > current size.
    public static func trim(_ ptr: UnsafeMutableRawPointer?, newSize: MemSize) -> UnsafeMutableRawPointer? {
        guard let ptr = ptr, newSize > 0 else { return ptr }

        // Pool-based: trimming is a no-op (element cannot be resized in its pool).
        if usePools {
            return ptr
        }

        let headerSize = MemoryAlignment.alignedSize(MemoryLayout<Int>.size)
        let guardSize = overflowCheckEnabled ? memOverflowGuardSize : 0
        let raw = ptr - guardSize - headerSize
        let headerPtr = raw.assumingMemoryBound(to: Int.self)
        let oldSize = headerPtr.pointee
        let alignedNewSize = MemoryAlignment.alignedSize(newSize)

        guard alignedNewSize <= oldSize else { return nil }

        if statsEnabled && alignedNewSize < oldSize {
            stats.recordFree(size: oldSize - alignedNewSize)
        }
        headerPtr.pointee = alignedNewSize

        // Move the post-guard sentinel to the new boundary.
        if overflowCheckEnabled {
            let postGuard = ptr + alignedNewSize
            postGuard.storeBytes(of: memOverflowSentinel, as: UInt32.self)
        }
        return ptr
    }

    // MARK: - Overflow Detection

    /// Verify that the sentinel guard bytes around an allocation are intact.
    ///
    /// Logs a diagnostic message if corruption is detected.
    ///
    /// - Parameters:
    ///   - ptr: The user-visible pointer (past the pre-guard).
    ///   - size: The recorded allocation size.
    public static func overflowCheckElement(_ ptr: UnsafeMutableRawPointer, size: Int) {
        let preGuard = ptr - memOverflowGuardSize
        let preVal = preGuard.load(as: UInt32.self)
        if preVal != memOverflowSentinel {
            Debug.print(DebugFlags.on.rawValue,
                        "Mem: pre-guard overflow detected at \(ptr)\n")
        }

        let postGuard = ptr + size
        let postVal = postGuard.load(as: UInt32.self)
        if postVal != memOverflowSentinel {
            Debug.print(DebugFlags.on.rawValue,
                        "Mem: post-guard overflow detected at \(ptr)\n")
        }
    }

    /// Walk all tracked allocations and verify their overflow sentinels.
    ///
    /// The system-allocator path does not maintain a linked list of live
    /// allocations, so this is a no-op. For pool-based allocations see
    /// `Memp.overflowCheckAll()`.
    public static func sanity() {
        // No-op for system allocator — individual checks happen on free().
    }
}
