//
//  Timeouts.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Constants

/// Namespace for timeout constants.
public enum TimeoutConstants {
    /// Returned by `sleepTime()` when there are no pending timeouts.
    public static let sleepTimeInfinite: UInt32 = 0xFFFF_FFFF
    /// Maximum timeout value (avoids wraparound issues).
    public static let maximumTimeout: UInt32 = 0x7FFF_FFFF
}

// MARK: - Time Comparison

/// Check if time `t` is less than `compareTo`, handling UInt32 wraparound.
/// Returns true if `t` is in the past relative to `compareTo`.
@inlinable @inline(__always)
internal func timeLessThan(_ t: UInt32, _ compareTo: UInt32) -> Bool {
    return (t &- compareTo) > TimeoutConstants.maximumTimeout
}

// MARK: - Callback Types

/// Callback type for one-shot timeout handlers.
public typealias TimeoutHandler = () -> Void

/// Callback type for cyclic (repeating) timer handlers.
public typealias CyclicTimerHandler = () -> Void

// MARK: - CyclicTimer

/// Describes a stack-internal cyclic timer that fires at a fixed interval.
public struct CyclicTimer: Sendable {
    /// Interval in milliseconds between invocations.
    public let intervalMs: UInt32

    /// The handler function called each interval.
    /// Note: stored as @Sendable nonisolated closure.
    public let handler: @Sendable () -> Void

    /// Human-readable name for debugging.
    public let name: String

    /// Create a cyclic timer descriptor.
    ///
    /// - Parameters:
    ///   - intervalMs: Firing interval in milliseconds.
    ///   - handler: Function to call each interval.
    ///   - name: Descriptive name for debugging.
    public init(intervalMs: UInt32, handler: @escaping @Sendable () -> Void, name: String = "") {
        self.intervalMs = intervalMs
        self.handler = handler
        self.name = name
    }
}

// MARK: - TimeoutEntry (internal linked list node)

/// Internal node in the timeout linked list.
internal final class TimeoutEntry {
    /// Next entry in the sorted list.
    var next: TimeoutEntry?

    /// Absolute time (ms) when this timeout expires.
    var time: UInt32

    /// The handler to call when the timeout fires.
    var handler: TimeoutHandler

    /// Name for debugging.
    var handlerName: String

    init(time: UInt32, handler: @escaping TimeoutHandler, name: String = "") {
        self.next = nil
        self.time = time
        self.handler = handler
        self.handlerName = name
    }
}

// MARK: - Timeouts

/// Central timeout manager for the lwIP stack.
///
/// Manages a sorted linked list of pending timeouts and a table of
/// cyclic timers. Call `checkTimeouts()` periodically from your main loop
/// (NO_SYS mode) or from the tcpip thread.
public final class Timeouts {
    /// The sorted linked list of pending timeouts (earliest first).
    internal var nextTimeout: TimeoutEntry?

    /// The due time of the timeout currently being processed.
    internal var currentTimeoutDueTime: UInt32 = 0

    /// The system tick function. Must return monotonic milliseconds.
    /// Users must set this before using the timeout system.
    public var systemTimeMilliseconds: () -> UInt32 = { 0 }

    /// Registered cyclic timers.
    public private(set) var cyclicTimers: [CyclicTimer] = []

    /// Whether the TCP timer is currently active (for on-demand scheduling).
    public var tcpTimerActive: Bool = false

    /// Shared default instance.
    public static nonisolated(unsafe) let shared = Timeouts()

    public init() {}

    // MARK: - Initialization

    /// Initialize the timeout system and schedule all registered cyclic timers.
    /// TCP timer (index 0) is started on demand, not here.
    ///
    /// - Parameter cyclicTimers: Array of cyclic timer descriptors.
    ///   Index 0 is treated as the TCP timer (started on demand).
    public func initialize(cyclicTimers: [CyclicTimer]) {
        self.cyclicTimers = cyclicTimers

        let startIndex = cyclicTimers.isEmpty ? 0 : 1
        for i in startIndex..<cyclicTimers.count {
            let timer = cyclicTimers[i]
            setTimeout(
                msecs: timer.intervalMs,
                handler: { [weak self] in
                    self?.cyclicTimerCallback(index: i)
                },
                name: timer.name
            )
        }
    }

    /// Initialize with default empty timers.
    public func initialize() {
        initialize(cyclicTimers: [])
    }

    // MARK: - Cyclic Timer Callback

    /// Internal callback that fires a cyclic timer and reschedules it.
    private func cyclicTimerCallback(index: Int) {
        guard index >= 0, index < cyclicTimers.count else { return }

        let cyclic = cyclicTimers[index]
        cyclic.handler()

        let now = systemTimeMilliseconds()
        let nextTime = currentTimeoutDueTime &+ cyclic.intervalMs

        let scheduleTime: UInt32
        if timeLessThan(nextTime, now) {
            // Timer overloaded -- restart from now.
            scheduleTime = now &+ cyclic.intervalMs
        } else {
            // Normal: schedule at the corrected next time.
            scheduleTime = nextTime
        }

        setTimeoutAbs(
            absTime: scheduleTime,
            handler: { [weak self] in
                self?.cyclicTimerCallback(index: index)
            },
            name: cyclic.name
        )
    }

    // MARK: - Set Timeout

    /// Create a one-shot timeout.
    ///
    /// - Parameters:
    ///   - msecs: Milliseconds until the timeout fires.
    ///   - handler: Callback to invoke when the timeout expires.
    ///   - name: Debug name for the timeout.
    public func setTimeout(
        msecs: UInt32,
        handler: @escaping TimeoutHandler,
        name: String = ""
    ) {
        assert(msecs <= TimeoutConstants.maximumTimeout / 4, "Timeout time too long")
        let nextTime = systemTimeMilliseconds() &+ msecs
        setTimeoutAbs(absTime: nextTime, handler: handler, name: name)
    }

    /// Internal: insert a timeout at an absolute time into the sorted list.
    internal func setTimeoutAbs(
        absTime: UInt32,
        handler: @escaping TimeoutHandler,
        name: String = ""
    ) {
        let entry = TimeoutEntry(time: absTime, handler: handler, name: name)

        // Empty list.
        guard let head = nextTimeout else {
            nextTimeout = entry
            return
        }

        // Insert before head?
        if timeLessThan(entry.time, head.time) {
            entry.next = head
            nextTimeout = entry
            return
        }

        // Find insertion point.
        var t = head
        while let nextT = t.next {
            if timeLessThan(entry.time, nextT.time) {
                entry.next = nextT
                t.next = entry
                return
            }
            t = nextT
        }

        // Append at end.
        t.next = entry
    }

    // MARK: - Remove Timeout

    /// Remove the first matching timeout from the list.
    ///
    /// - Parameter name: The handler name to match. Timeouts are identified
    ///   by the name string provided when they were registered.
    public func untimeout(name: String) {
        guard nextTimeout != nil else { return }

        var prev: TimeoutEntry? = nil
        var t = nextTimeout

        while let entry = t {
            if entry.handlerName == name {
                if let prev = prev {
                    prev.next = entry.next
                } else {
                    nextTimeout = entry.next
                }
                return
            }
            prev = entry
            t = entry.next
        }
    }

    // MARK: - Check Timeouts

    /// Process all expired timeouts. Call this periodically from your main loop.
    ///
    /// Iterates the timeout list, invoking handlers for any timeouts whose
    /// expiry time has passed. Expired entries are removed from the list.
    public func checkTimeouts() {
        let now = systemTimeMilliseconds()

        while true {
            guard let entry = nextTimeout else { return }

            if timeLessThan(now, entry.time) {
                // No more expired timeouts.
                return
            }

            // Remove from list.
            nextTimeout = entry.next

            // Record due time for cyclic timer correction.
            currentTimeoutDueTime = entry.time

            // Invoke handler.
            entry.handler()
        }
    }

    // MARK: - Restart Timeouts

    /// Rebase all timeout times relative to the current time.
    /// Call this after a long sleep to prevent all timers from firing at once.
    public func restartTimeouts() {
        guard let head = nextTimeout else { return }
        let now = systemTimeMilliseconds()
        let base = head.time

        var t: TimeoutEntry? = head
        while let entry = t {
            entry.time = (entry.time &- base) &+ now
            t = entry.next
        }
    }

    // MARK: - Sleep Time

    /// Return the time in milliseconds until the next timeout fires.
    ///
    /// - Returns: Milliseconds until next timeout, or `TimeoutConstants.sleepTimeInfinite`
    ///   if there are no pending timeouts.
    public func sleepTime() -> UInt32 {
        guard let head = nextTimeout else {
            return TimeoutConstants.sleepTimeInfinite
        }
        let now = systemTimeMilliseconds()
        if timeLessThan(head.time, now) {
            return 0
        }
        let remaining = head.time &- now
        assert(remaining <= TimeoutConstants.maximumTimeout, "invalid sleeptime")
        return remaining
    }

    // MARK: - TCP Timer Support

    /// Called when a TCP PCB is registered and the TCP timer might need to start.
    /// The TCP timer is the cyclic timer at index 0.
    public func tcpTimerNeeded() {
        guard !tcpTimerActive, !cyclicTimers.isEmpty else { return }

        tcpTimerActive = true
        let timer = cyclicTimers[0]

        setTimeout(
            msecs: timer.intervalMs,
            handler: { [weak self] in
                self?.cyclicTimerCallback(index: 0)
            },
            name: timer.name
        )
    }

    // MARK: - Test / Debug Support

    /// Access the raw timeout list (for testing).
    /// Returns true if there is a pending timeout.
    public var hasNextTimeout: Bool {
        return nextTimeout != nil
    }

    /// Number of pending timeouts.
    public var pendingCount: Int {
        var count = 0
        var t = nextTimeout
        while t != nil {
            count += 1
            t = t?.next
        }
        return count
    }
}
