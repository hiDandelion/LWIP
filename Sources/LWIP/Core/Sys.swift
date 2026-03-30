//
//  Sys.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Timeout sentinel

/// Namespace for system abstraction layer constants.
public enum SystemConstants {
    /// Return code for timeouts from architecture-level wait functions.
    public static let architectureTimeout: UInt32 = 0xFFFF_FFFF
    /// Return code when a mailbox is empty.
    public static let mailboxEmpty: UInt32 = architectureTimeout
}

// MARK: - Semaphore abstraction

/// A counting semaphore abstraction for lwIP.
/// The default implementation uses `DispatchSemaphore` on Apple platforms.
public final class LWIPSemaphore: @unchecked Sendable {
    private let semaphore: DispatchSemaphore
    private var valid: Bool = true

    /// Create a new semaphore with the given initial count (0 or 1).
    public init(count: Int = 0) {
        self.semaphore = DispatchSemaphore(value: count)
    }

    /// Signal (post) the semaphore.
    public func signal() {
        semaphore.signal()
    }

    /// Wait for the semaphore, blocking indefinitely.
    public func wait() {
        semaphore.wait()
    }

    /// Wait for the semaphore with a timeout in milliseconds.
    /// Returns `SystemConstants.architectureTimeout` on timeout, 0 on success.
    public func wait(timeoutMs: UInt32) -> UInt32 {
        if timeoutMs == 0 {
            semaphore.wait()
            return 0
        }
        let result = semaphore.wait(timeout: .now() + .milliseconds(Int(timeoutMs)))
        return result == .timedOut ? SystemConstants.architectureTimeout : 0
    }

    /// Invalidate this semaphore.
    public func invalidate() { valid = false }

    /// Check if this semaphore is valid.
    public var isValid: Bool { valid }
}

// MARK: - Mutex abstraction

/// A mutual exclusion lock abstraction for lwIP.
/// The default implementation uses `NSLock`.
public final class LWIPMutex: @unchecked Sendable {
    private let innerLock = NSLock()
    private var valid: Bool = true

    public init() {}

    /// Acquire the mutex (blocking).
    public func lock() { innerLock.lock() }

    /// Release the mutex.
    public func unlock() { innerLock.unlock() }

    /// Invalidate this mutex.
    public func invalidate() { valid = false }

    /// Check if this mutex is valid.
    public var isValid: Bool { valid }
}

// MARK: - Mailbox abstraction

/// A type-safe message-passing mailbox for lwIP. Thread-safe.
public final class LWIPMailbox<Message>: @unchecked Sendable {
    private var queue: [Message] = []
    private let lock = NSLock()
    private let itemAvailable = DispatchSemaphore(value: 0)
    private let capacity: Int
    private var valid: Bool = true

    /// Create a mailbox with the given maximum capacity.
    public init(size: Int) {
        self.capacity = size
        self.queue.reserveCapacity(size)
    }

    /// Post a message to the mailbox, blocking if full.
    public func post(_ msg: Message) {
        lock.lock()
        queue.append(msg)
        lock.unlock()
        itemAvailable.signal()
    }

    /// Try to post a message. Returns `.ok` on success, `.outOfMemory` if full.
    public func tryPost(_ msg: Message) -> LWIPError {
        lock.lock()
        if queue.count >= capacity {
            lock.unlock()
            return .outOfMemory
        }
        queue.append(msg)
        lock.unlock()
        itemAvailable.signal()
        return .ok
    }

    /// Fetch a message, blocking up to `timeoutMs` milliseconds (0 = forever).
    /// Returns `SystemConstants.architectureTimeout` on timeout, 0 on success.
    public func fetch(timeoutMs: UInt32) -> (UInt32, Message?) {
        let waitResult: DispatchTimeoutResult
        if timeoutMs == 0 {
            itemAvailable.wait()
            waitResult = .success
        } else {
            waitResult = itemAvailable.wait(timeout: .now() + .milliseconds(Int(timeoutMs)))
        }

        if waitResult == .timedOut {
            return (SystemConstants.architectureTimeout, nil)
        }

        lock.lock()
        let msg = queue.isEmpty ? nil : queue.removeFirst()
        lock.unlock()
        return (0, msg)
    }

    /// Try to fetch a message without blocking.
    /// Returns the message if one was available, or nil if empty.
    public func tryFetch() -> Message? {
        let result = itemAvailable.wait(timeout: .now())
        if result == .timedOut { return nil }
        lock.lock()
        let msg = queue.isEmpty ? nil : queue.removeFirst()
        lock.unlock()
        return msg
    }

    /// Invalidate this mailbox.
    public func invalidate() { valid = false }

    /// Check if this mailbox is valid.
    public var isValid: Bool { valid }
}

/// Convenience type alias for the legacy raw-pointer mailbox used in lwIP internals.
public typealias LWIPRawMailbox = LWIPMailbox<UnsafeMutableRawPointer?>

// MARK: - Thread function type

/// Function prototype for lwIP thread entry points.
public typealias LWIPThreadFn = @convention(c) (UnsafeMutableRawPointer?) -> Void

// MARK: - LWIPSystem

/// System abstraction layer functions.
public enum LWIPSystem {

    /// Returns the current system time in milliseconds using monotonic timing.
    @inlinable
    public static func timeMilliseconds() -> UInt32 {
        let nanos = DispatchTime.now().uptimeNanoseconds
        return UInt32(truncatingIfNeeded: nanos / 1_000_000)
    }

    /// Returns system ticks/jiffies (same as `timeMilliseconds()` in this implementation).
    @inlinable
    public static func jiffies() -> UInt32 {
        timeMilliseconds()
    }

    /// Sleep for the given number of milliseconds. Timeouts are NOT processed.
    public static func sleep(milliseconds ms: UInt32) {
        guard ms > 0 else { return }
        Thread.sleep(forTimeInterval: Double(ms) / 1000.0)
    }

    /// Execute a closure while holding the critical section lock.
    @inlinable
    public static func withLock<T>(_ body: () throws -> T) rethrows -> T {
        let lev = SysProtect.protect()
        defer { SysProtect.unprotect(lev) }
        return try body()
    }

    /// Initialize the system abstraction layer.
    /// In this Swift implementation, there is nothing platform-specific to initialize.
    public static func initialize() {
        // No-op. Platform resources are initialized lazily.
    }
}

// MARK: - Critical region protection

/// A lightweight critical region guard using a global lock.
/// For use with `SYS_LIGHTWEIGHT_PROT`.
public final class SysProtect: @unchecked Sendable {
    @usableFromInline
    internal static let globalLock = NSLock()

    /// Enter a critical section. Returns a token for `unprotect`.
    @inlinable
    public static func protect() -> UInt32 {
        globalLock.lock()
        return 1
    }

    /// Leave a critical section.
    @inlinable
    public static func unprotect(_ level: UInt32) {
        globalLock.unlock()
    }
}

