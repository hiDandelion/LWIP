//
//  Debug.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Debug level constants

/// Debug level constants.
public struct DebugLevel: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// All messages (lowest level).
    public static let all: DebugLevel     = [] // rawValue: 0x00
    /// Warnings: bad checksums, dropped packets, etc.
    public static let warning = DebugLevel(rawValue: 0x01)
    /// Serious: memory allocation failures, etc.
    public static let serious = DebugLevel(rawValue: 0x02)
    /// Severe errors.
    public static let severe  = DebugLevel(rawValue: 0x03)
}

// MARK: - Debug type flags

/// Flags controlling which debug message types are active.
public struct DebugFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Flag to enable a debug message.
    public static let on    = DebugFlags(rawValue: 0x80)
    /// Flag to disable a debug message.
    public static let off: DebugFlags   = [] // rawValue: 0x00
    /// Tracing message (follow program flow).
    public static let trace = DebugFlags(rawValue: 0x40)
    /// State debug message (follow module states).
    public static let state = DebugFlags(rawValue: 0x20)
    /// Newly added code, not thoroughly tested yet.
    public static let fresh = DebugFlags(rawValue: 0x10)
    /// Halt after printing this debug message.
    public static let halt  = DebugFlags(rawValue: 0x08)

    /// Mask to extract the level bits from a combined debug value.
    public static let levelMask = DebugFlags(rawValue: 0x03)
}

// MARK: - Debug configuration and output

/// Centralized debug configuration and output for the lwIP stack.
public enum Debug {

    // MARK: - Configuration

    /// Thread-safe container for debug configuration.
    /// Access configuration through `Debug.config` and mutate via `Debug.configure(_:)`.
    public final class Configuration: @unchecked Sendable {
        private let lock = NSLock()

        /// Global switch for lwIP debug output.
        public private(set) var isEnabled: Bool
        /// The minimum debug level that will be printed.
        public private(set) var minimumLevel: UInt8
        /// Bitmask of debug types that are currently enabled.
        public private(set) var enabledTypes: UInt8
        /// A user-replaceable handler for debug output.
        public private(set) var platformDiagnostic: @Sendable (String) -> Void

        internal init() {
            #if DEBUG
            self.isEnabled = true
            #else
            self.isEnabled = false
            #endif
            self.minimumLevel = DebugLevel.all.rawValue
            self.enabledTypes = DebugFlags.on.rawValue
            self.platformDiagnostic = { message in
                #if DEBUG
                Swift.print("[LWIP] \(message)", terminator: "")
                #endif
            }
        }

        /// Thread-safe update of configuration fields.
        public func update(
            isEnabled: Bool? = nil,
            minimumLevel: UInt8? = nil,
            enabledTypes: UInt8? = nil,
            platformDiagnostic: (@Sendable (String) -> Void)? = nil
        ) {
            lock.lock()
            if let v = isEnabled { self.isEnabled = v }
            if let v = minimumLevel { self.minimumLevel = v }
            if let v = enabledTypes { self.enabledTypes = v }
            if let v = platformDiagnostic { self.platformDiagnostic = v }
            lock.unlock()
        }
    }

    /// The shared debug configuration instance.
    public static let config = Configuration()

    /// Global switch for lwIP debug output. Set to `false` to silence all debug messages at runtime.
    @inlinable
    public static var isEnabled: Bool { config.isEnabled }

    /// The minimum debug level that will be printed. Messages below this level are suppressed.
    @inlinable
    public static var minimumLevel: UInt8 { config.minimumLevel }

    /// Bitmask of debug types that are currently enabled.
    @inlinable
    public static var enabledTypes: UInt8 { config.enabledTypes }

    /// A user-replaceable handler for debug output.
    @inlinable
    public static var platformDiagnostic: @Sendable (String) -> Void { config.platformDiagnostic }

    // MARK: Debug checks

    /// Check whether a given debug descriptor is enabled.
    @inlinable
    public static func isLevelEnabled(_ debug: UInt8) -> Bool {
        guard isEnabled else { return false }
        return (debug & DebugFlags.on.rawValue) != 0
            && (debug & enabledTypes) != 0
            && Int8(bitPattern: debug & DebugFlags.levelMask.rawValue) >= Int8(bitPattern: minimumLevel)
    }

    // MARK: Output

    /// Print a debug message if the given debug descriptor is enabled.
    /// This is the Swift equivalent of `LWIP_DEBUGF(debug, message)`.
    @inlinable
    public static func print(_ debug: UInt8, _ message: @autoclosure () -> String) {
        guard isLevelEnabled(debug) else { return }
        platformDiagnostic(message())
    }

    // MARK: Assertions

    /// A user-replaceable assertion handler.
    /// By default this calls `fatalError`. Replace this closure if you need
    /// a different behavior on embedded platforms.
    public static let assertHandler = AssertHandler()

    /// Thread-safe container for the assertion handler.
    public final class AssertHandler: @unchecked Sendable {
        private let lock = NSLock()
        private var handler: @Sendable (String, StaticString, UInt) -> Never = { message, file, line in
            fatalError("LWIP assertion failed: \(message)", file: file, line: line)
        }

        internal init() {}

        public func set(_ newHandler: @escaping @Sendable (String, StaticString, UInt) -> Never) {
            lock.lock()
            handler = newHandler
            lock.unlock()
        }

        public func callAsFunction(_ message: String, file: StaticString, line: UInt) -> Never {
            lock.lock()
            let h = handler
            lock.unlock()
            h(message, file, line)
        }
    }

    /// Assert a condition, halting if it fails.
    @inlinable
    public static func assert(
        _ message: @autoclosure () -> String,
        _ condition: @autoclosure () -> Bool,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        if !condition() {
            assertHandler(message(), file: file, line: line)
        }
    }

    // MARK: Error reporting

    /// Print an error message and execute a handler if the expression is false.
    @inlinable
    public static func error(
        _ message: @autoclosure () -> String,
        _ expression: @autoclosure () -> Bool,
        handler: () -> Void
    ) {
        if !expression() {
            platformDiagnostic(message())
            handler()
        }
    }
}

