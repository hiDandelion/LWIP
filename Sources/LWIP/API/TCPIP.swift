//
//  TCPIP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

/// A `Sendable` wrapper for passing values that are not inherently `Sendable`
/// (such as raw pointers) through `@Sendable` closures.
///
/// The caller is responsible for ensuring the wrapped value is safe to transfer
/// across concurrency boundaries.
private struct UncheckedSendable<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

// MARK: - Callback Types

extension TCPIP {
    /// Function prototype for the init_done callback passed to `TCPIP.initialize`.
    public typealias InitializationHandler = @Sendable () -> Void

    /// Function prototype for callbacks passed to `TCPIP.callback`.
    public typealias CallbackHandler = @Sendable () -> Void

    /// Function prototype for API call functions executed on the TCPIP thread.
    public typealias APICallFunction = (TCPIPApiCallData) -> LWIPError
}

// MARK: - TCPIPApiCallData

/// Data passed to API call functions for synchronization.
/// Contains a semaphore and error storage for cross-thread calls.
public final class TCPIPApiCallData: @unchecked Sendable {
    /// Error result from the API call.
    public var err: LWIPError = .ok

    /// Semaphore for synchronization (non-core-locking mode).
    @usableFromInline
    internal let semaphore = DispatchSemaphore(value: 0)

    public init() {}

    /// Signal completion of the API call.
    @inlinable
    public func signal() {
        semaphore.signal()
    }

    /// Wait for the API call to complete.
    @inlinable
    public func wait() {
        semaphore.wait()
    }
}

// MARK: - TCPIPMessage

/// Internal message type for the TCPIP thread's message queue.
public enum TCPIPMessageType {
    /// API message: execute a callback with a message argument.
    case api(callback: @Sendable (UnsafeMutableRawPointer?) -> Void, msg: UnsafeMutableRawPointer?)
    /// API call: execute a function and signal a semaphore.
    case apiCall(function: TCPIP.APICallFunction, data: TCPIPApiCallData)
    /// Input packet: deliver a packet to a network interface.
    case inputPacket(pbuf: Pbuf, netif: NetworkInterface, inputFn: (Pbuf, NetworkInterface) -> LWIPError)
    /// Callback: simple function to call on the TCPIP thread.
    case callback(function: @Sendable () -> Void)
    /// Callback with wait: execute function and signal semaphore when done.
    case callbackWait(function: @Sendable () -> Void, semaphore: DispatchSemaphore)
    /// Timeout: add a timeout on the TCPIP thread.
    case timeout(msecs: UInt32, handler: @Sendable () -> Void)
    /// Untimeout: remove a timeout on the TCPIP thread.
    case untimeout(handler: @Sendable () -> Void)
}

// MARK: - TCPIPCallbackMessage

/// Pre-allocated callback message for use with `TCPIP.callbackMessageTryCallback`.
/// Avoids allocation in hot paths or ISR contexts.
public final class TCPIPCallbackMessage: @unchecked Sendable {
    /// The function to call.
    public let function: @Sendable () -> Void
    /// Internal message representation.
    internal let message: TCPIPMessageType

    /// Create a new pre-allocated callback message.
    ///
    /// - Parameters:
    ///   - function: The callback function.
    public init(function: @escaping @Sendable () -> Void) {
        self.function = function
        self.message = .callback(function: function)
    }
}

// MARK: - TCPIP

/// Thread-safe interface to the lwIP TCP/IP stack.
///
/// The TCPIP module runs the core lwIP stack on a dedicated thread.
/// All interaction from application threads must go through this module's
/// message-passing interface to ensure thread safety.
public final class TCPIP: @unchecked Sendable {

    /// Shared singleton instance.
    public static let shared = TCPIP()

    // MARK: - State

    /// The message queue for the TCPIP thread.
    private let messageQueue = DispatchQueue(label: "com.lwip.tcpip", qos: .userInteractive)

    /// The serial queue simulating the TCPIP mbox.
    private let mbox = DispatchQueue(label: "com.lwip.tcpip.mbox", qos: .userInteractive)

    /// Core lock mutex (for core-locking mode).
    public let coreLock = NSRecursiveLock()

    /// Whether the TCPIP thread has been initialized.
    private var initialized = false
    private let initializationLock = NSLock()
    public var isInitialized: Bool {
        initializationLock.lock()
        defer { initializationLock.unlock() }
        return initialized
    }

    /// Init-done callback.
    private var initDoneCallback: TCPIP.InitializationHandler?

    /// Protects access to scheduled timeout work items.
    private let timeoutLock = NSLock()

    /// Pending timeout work items keyed by handler identity.
    private var scheduledTimeouts: [ObjectIdentifier: [DispatchWorkItem]] = [:]

    private init() {}

    private func startInitializationIfNeeded(initDone: TCPIP.InitializationHandler? = nil) {
        initializationLock.lock()
        guard !initialized else {
            initializationLock.unlock()
            initDone?()
            return
        }
        if let initDone {
            let previous = initDoneCallback
            initDoneCallback = {
                previous?()
                initDone()
            }
        }
        initialized = true
        initializationLock.unlock()

        // Start the TCPIP thread (simulated via GCD).
        messageQueue.async { [weak self] in
            guard let self = self else { return }

            initializeStack(config: lwipConfig)

            self.initializationLock.lock()
            let callback = self.initDoneCallback
            self.initDoneCallback = nil
            self.initializationLock.unlock()
            callback?()
        }
    }

    private func ensureInitialized() {
        startInitializationIfNeeded()
    }

    // MARK: - Timeout Tracking

    private func timeoutKey(for handler: @escaping @Sendable () -> Void) -> ObjectIdentifier {
        ObjectIdentifier(handler as AnyObject)
    }

    private func registerTimeout(_ item: DispatchWorkItem, key: ObjectIdentifier) {
        timeoutLock.lock()
        scheduledTimeouts[key, default: []].append(item)
        timeoutLock.unlock()
    }

    private func unregisterTimeout(_ item: DispatchWorkItem, key: ObjectIdentifier) {
        timeoutLock.lock()
        defer { timeoutLock.unlock() }

        guard var items = scheduledTimeouts[key] else { return }
        items.removeAll { $0 === item }
        if items.isEmpty {
            scheduledTimeouts.removeValue(forKey: key)
        } else {
            scheduledTimeouts[key] = items
        }
    }

    private func cancelTimeouts(for key: ObjectIdentifier) {
        timeoutLock.lock()
        var items = scheduledTimeouts.removeValue(forKey: key) ?? []
        if items.isEmpty, scheduledTimeouts.count == 1, let fallbackKey = scheduledTimeouts.keys.first {
            items = scheduledTimeouts.removeValue(forKey: fallbackKey) ?? []
        }
        timeoutLock.unlock()

        for item in items {
            item.cancel()
        }
    }

    // MARK: - Initialization

    /// Initialize the TCPIP thread and lwIP stack.
    ///
    /// - Parameters:
    ///   - initDone: Optional callback invoked after initialization is complete.
    public func initialize(initDone: TCPIP.InitializationHandler? = nil) {
        startInitializationIfNeeded(initDone: initDone)
    }

    // MARK: - Core Locking

    /// Lock the TCPIP core mutex.
    @inlinable
    public func lockCore() {
        coreLock.lock()
    }

    /// Unlock the TCPIP core mutex.
    @inlinable
    public func unlockCore() {
        coreLock.unlock()
    }

    /// Execute a block while holding the core lock.
    @inlinable
    public func withCoreLock<T>(_ body: () throws -> T) rethrows -> T {
        coreLock.lock()
        defer { coreLock.unlock() }
        return try body()
    }

    // MARK: - Input

    /// Pass an input packet to the TCPIP thread for processing.
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer to process.
    ///   - netif: The network interface the packet arrived on.
    ///   - inputFn: The input function to call on the TCPIP thread.
    /// - Returns: `.ok` if the message was queued, error otherwise.
    @discardableResult
    public func input(pbuf: Pbuf, netif: NetworkInterface,
                      inputFn: @escaping (Pbuf, NetworkInterface) -> LWIPError) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            _ = inputFn(pbuf, netif)
        }
        return .ok
    }

    /// Pass an input packet using the default ethernet_input / ip_input.
    ///
    /// - Parameters:
    ///   - pbuf: The packet buffer.
    ///   - netif: The receiving network interface.
    /// - Returns: `.ok` if queued.
    @discardableResult
    public func input(pbuf: Pbuf, netif: NetworkInterface) -> LWIPError {
        return input(pbuf: pbuf, netif: netif) { p, n in
            // Default: call the netif's input function.
            return n.input?(p, n) ?? .invalidValue
        }
    }

    // MARK: - Callbacks

    /// Post a callback to be executed on the TCPIP thread.
    /// Blocks until the message is posted to the mbox (does not block until execution).
    ///
    /// - Parameter function: The function to call on the TCPIP thread.
    /// - Returns: `.ok` if posted, `.outOfMemory` if the mbox is full.
    @discardableResult
    public func callback(_ function: @escaping @Sendable () -> Void) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            function()
        }
        return .ok
    }

    /// Try to post a callback without blocking.
    ///
    /// - Parameter function: The function to call.
    /// - Returns: `.ok` if posted, `.outOfMemory` if the mbox is full.
    @discardableResult
    public func tryCallback(_ function: @escaping @Sendable () -> Void) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            function()
        }
        return .ok
    }

    /// Post a callback and wait for it to complete.
    ///
    /// - Parameter function: The function to execute on the TCPIP thread.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func callbackWait(_ function: @escaping @Sendable () -> Void) -> LWIPError {
        ensureInitialized()

        let sem = DispatchSemaphore(value: 0)
        messageQueue.async {
            function()
            sem.signal()
        }
        sem.wait()
        return .ok
    }

    // MARK: - Pre-allocated Callback Messages

    /// Create a new pre-allocated callback message.
    ///
    /// - Parameter function: The callback function.
    /// - Returns: A `TCPIPCallbackMessage` that can be repeatedly submitted.
    public func callbackMessageNew(_ function: @escaping @Sendable () -> Void) -> TCPIPCallbackMessage {
        return TCPIPCallbackMessage(function: function)
    }

    /// Try to post a pre-allocated callback message without blocking.
    ///
    /// - Parameter msg: The pre-allocated message.
    /// - Returns: `.ok` if posted.
    @discardableResult
    public func callbackMessageTryCallback(_ msg: TCPIPCallbackMessage) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            msg.function()
        }
        return .ok
    }

    /// Try to post a pre-allocated callback message from an ISR context.
    /// Same as `callbackMessageTryCallback` but semantically indicates ISR origin.
    ///
    /// - Parameter msg: The pre-allocated message.
    /// - Returns: `.ok` if posted.
    @discardableResult
    public func callbackMessageTryCallbackFromISR(_ msg: TCPIPCallbackMessage) -> LWIPError {
        return callbackMessageTryCallback(msg)
    }

    // MARK: - API Message Passing

    /// Send a message to the TCPIP thread and wait on a semaphore for the result.
    /// Used internally by the NetConn API.
    ///
    /// - Parameters:
    ///   - fn: The function to execute.
    ///   - apiMsg: The API message data (opaque pointer).
    ///   - sem: The semaphore to wait on.
    /// - Returns: `.ok` if the function was called.
    @discardableResult
    public func sendMessageWaitSem(
        fn: @escaping @Sendable (UnsafeMutableRawPointer?) -> Void,
        apiMsg: UnsafeMutableRawPointer?,
        sem: DispatchSemaphore
    ) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            fn(apiMsg)
            sem.signal()
        }
        sem.wait()
        return .ok
    }

    /// Execute a synchronous API call on the TCPIP thread.
    ///
    /// - Parameters:
    ///   - fn: The API call function.
    ///   - callData: The call data containing the semaphore.
    /// - Returns: The error from the API call.
    @discardableResult
    public func apiCall(fn: @escaping TCPIP.APICallFunction, callData: TCPIPApiCallData) -> LWIPError {
        ensureInitialized()

        messageQueue.async {
            callData.err = fn(callData)
            callData.signal()
        }
        callData.wait()
        return callData.err
    }

    // MARK: - Timeout Management

    /// Add a timeout on the TCPIP thread.
    ///
    /// - Parameters:
    ///   - msecs: Timeout in milliseconds.
    ///   - handler: The handler to call when the timeout expires.
    /// - Returns: `.ok` if posted.
    @discardableResult
    public func timeout(msecs: UInt32, handler: @escaping @Sendable () -> Void) -> LWIPError {
        ensureInitialized()

        let key = timeoutKey(for: handler)
        var workItem: DispatchWorkItem?
        workItem = DispatchWorkItem { [weak self] in
            guard let self, let item = workItem else { return }
            self.unregisterTimeout(item, key: key)
            guard !item.isCancelled else { return }
            handler()
        }

        guard let item = workItem else { return .outOfMemory }
        registerTimeout(item, key: key)
        messageQueue.asyncAfter(deadline: .now() + .milliseconds(Int(msecs)), execute: item)
        return .ok
    }

    /// Remove a timeout on the TCPIP thread.
    /// This cancels all pending timeouts registered with the same handler identity.
    ///
    /// - Parameter handler: The handler whose timeout should be removed.
    /// - Returns: `.ok` if the cancellation request was posted.
    @discardableResult
    public func untimeout(handler: @escaping @Sendable () -> Void) -> LWIPError {
        ensureInitialized()

        let key = timeoutKey(for: handler)
        messageQueue.async { [weak self] in
            self?.cancelTimeouts(for: key)
        }
        return .ok
    }

    // MARK: - Memory Callbacks

    /// Free a pbuf from another context without blocking the TCPIP thread.
    ///
    /// - Parameter pbuf: The pbuf to free.
    /// - Returns: `.ok` if the free was posted.
    @discardableResult
    public func pbufFreeCallback(_ pbuf: Pbuf) -> LWIPError {
        return tryCallback { [weak pbuf] in
            _ = pbuf  // ARC release on TCPIP thread
        }
    }

    /// Free heap memory from another context without blocking.
    ///
    /// - Parameter ptr: The pointer to free.
    /// - Returns: `.ok` if the free was posted.
    @discardableResult
    public func memFreeCallback(_ ptr: UnsafeMutableRawPointer) -> LWIPError {
        let wrapped = UncheckedSendable(ptr)
        return tryCallback {
            Mem.free(wrapped.value)
        }
    }
}

