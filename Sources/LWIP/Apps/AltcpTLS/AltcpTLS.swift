//
//  AltcpTLS.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// -- Platform TLS Strategy --
//
// The original C lwIP library embeds mbedTLS as its TLS backend. It compiles
// mbedTLS sources directly into the lwIP build, manages TLS memory through
// lwIP's own allocators, and drives the TLS handshake byte-by-byte over the
// altcp layer chain.
//
// This Swift port takes a different approach: TLS is delegated to the
// platform's native TLS implementation rather than embedding mbedTLS.
//
// On Apple platforms this means Security.framework and Network.framework,
// which provide:
//   - Hardware-accelerated cryptographic primitives
//   - OS-managed trust store and certificate chain validation
//   - Automatic security updates independent of application releases
//   - Keychain integration for client certificates and private keys
//   - System-wide TLS session caching
//
// On non-Apple platforms (e.g. Linux), the concrete TLS backend should
// wrap the platform's OpenSSL/BoringSSL or similar library instead.
//
// -- Architecture --
//
// The TLS layer sits in the altcp chain as follows:
//
//   Application  ->  AltcpTLS  ->  AltcpTCP  ->  TCP stack
//
// AltcpTLS implements `AltcpFunctions` and wraps an inner TCP connection.
// It intercepts `write` to encrypt outbound data and `recv` to decrypt
// inbound data, and manages the TLS handshake during `connect`.
//
// The actual cryptographic operations are performed by `TLSBackend`
// (a protocol defined below). Users supply a platform-specific conforming
// type -- for example, one built on `sec_protocol_options` and
// `nw_connection` on Apple platforms.

import Foundation

// MARK: - TLS Configuration

/// TLS session configuration.
///
/// Holds platform-agnostic descriptions of the desired TLS policy; the actual
/// cryptographic objects are created by the `TLSBackend` at handshake time.
///
/// ## Providing certificates
///
/// - **CA certificates (server verification):** Set `caCertificates` to
///   DER-encoded root certificates. On Apple platforms, the system trust
///   store is consulted automatically; these are *additional* roots.
///
/// - **Client certificates (mutual TLS):** Set `clientCertificate` and
///   `privateKey` with DER-encoded data. On Apple platforms you can
///   alternatively reference a Keychain identity by setting
///   `keychainIdentityLabel`.
///
/// - **Hostname verification:** Set `hostname` to enable SNI and
///   certificate hostname checking. This is required for most servers.
///
/// - **Cipher suites:** Leave `preferredCipherSuites` nil to use the
///   platform defaults (recommended). Provide explicit IANA cipher suite
///   identifiers only when interoperating with constrained devices.
///
/// - **Session resumption:** The platform TLS stack handles session
///   tickets and caching transparently. `enableSessionResumption`
///   controls whether the backend is allowed to use this optimization
///   (default: true).
public final class TLSConfiguration: AltcpTLSConfig, @unchecked Sendable {

    // MARK: Trust and Identity

    /// DER-encoded CA certificates for server verification.
    /// These augment (not replace) the platform trust store.
    public var caCertificates: [Data]

    /// DER-encoded client certificate for mutual TLS (optional).
    public var clientCertificate: Data?

    /// DER-encoded private key corresponding to `clientCertificate` (optional).
    /// On Apple platforms, prefer Keychain-based identity instead.
    public var privateKey: Data?

    /// On Apple platforms, a Keychain identity label to use for mutual TLS.
    /// When set, `clientCertificate` and `privateKey` are ignored.
    public var keychainIdentityLabel: String?

    // MARK: Verification

    /// Server hostname for SNI and certificate verification.
    /// Must match the server's certificate Common Name or Subject Alternative Name.
    public var hostname: String?

    // MARK: Protocol and Cipher Configuration

    /// Minimum TLS protocol version to accept (e.g. .tlsv12, .tlsv13).
    /// Defaults to TLS 1.2.
    public var minimumTLSVersion: TLSVersion

    /// Explicit cipher suite list (IANA identifiers). Nil uses platform defaults.
    /// Setting this is rarely needed and may reduce security if done incorrectly.
    public var preferredCipherSuites: [UInt16]?

    /// ALPN protocol strings (e.g. ["h2", "http/1.1"]).
    public var alpnProtocols: [String]?

    // MARK: Session Management

    /// Whether the backend may cache and resume TLS sessions.
    /// The platform TLS stack manages the session cache; this flag simply
    /// tells the backend whether to opt in. Default: true.
    public var enableSessionResumption: Bool

    // MARK: Initialization

    /// Create a TLS configuration for a client connection.
    ///
    /// - Parameters:
    ///   - hostname: Server hostname for SNI and verification.
    ///   - caCertificates: Additional CA certificates in DER format.
    public init(hostname: String? = nil, caCertificates: [Data] = []) {
        self.hostname = hostname
        self.caCertificates = caCertificates
        self.clientCertificate = nil
        self.privateKey = nil
        self.keychainIdentityLabel = nil
        self.minimumTLSVersion = .tlsv12
        self.preferredCipherSuites = nil
        self.alpnProtocols = nil
        self.enableSessionResumption = true
    }

    /// Create a TLS configuration for a server listener.
    ///
    /// - Parameters:
    ///   - serverCertificate: Server certificate in DER format.
    ///   - privateKey: Private key in DER format.
    ///   - caCertificates: CA certificates for client verification (mutual TLS).
    public init(serverCertificate: Data, privateKey: Data, caCertificates: [Data] = []) {
        self.hostname = nil
        self.caCertificates = caCertificates
        self.clientCertificate = serverCertificate
        self.privateKey = privateKey
        self.keychainIdentityLabel = nil
        self.minimumTLSVersion = .tlsv12
        self.preferredCipherSuites = nil
        self.alpnProtocols = nil
        self.enableSessionResumption = true
    }
}

// MARK: - TLS Version

/// Minimum TLS protocol version.
public enum TLSVersion: Int, Sendable {
    /// TLS 1.2 (recommended minimum for most use cases).
    case tlsv12 = 0x0303
    /// TLS 1.3.
    case tlsv13 = 0x0304
}

// MARK: - TLS Error Codes

/// TLS-specific error codes for detailed error reporting.
///
/// These provide finer-grained information than `LWIPError` for diagnosing
/// TLS failures. They correspond to common mbedTLS / platform TLS error
/// categories.
public enum TLSError: Int, Sendable {
    case none                    = 0
    case handshakeFailed         = -1
    case certificateExpired      = -2
    case certificateRevoked      = -3
    case certificateUnknownCA    = -4
    case certificateHostMismatch = -5
    case protocolError           = -6
    case recordOverflow          = -7
    case decryptError            = -8
    case peerCloseNotify         = -9
    case wantRead                = -10
    case wantWrite               = -11
    case timeout                 = -12
    case unknown                 = -99
}

// MARK: - TLS Backend Protocol

/// Abstraction over the platform TLS implementation.
///
/// A conforming type bridges between the altcp layer and the native TLS
/// stack. On Apple platforms, an implementation would use
/// `Security.framework` (`SSLCreateContext` / `sec_protocol_options`)
/// or `Network.framework` (`NWProtocolTLS`). On Linux, an implementation
/// might wrap OpenSSL or BoringSSL.
///
/// ## Implementing a TLS backend
///
/// 1. Create a class conforming to `TLSBackend`.
///
/// 2. In `startHandshake`, configure the platform TLS context using the
///    values from the provided `TLSConfiguration`:
///    - Load CA certificates for server trust evaluation.
///    - Load client certificate and private key for mutual TLS.
///    - Set the SNI hostname.
///    - Configure minimum protocol version and cipher suites.
///    - Enable or disable session caching/resumption.
///
/// 3. Implement `encrypt` and `decrypt` to pass data through the
///    platform TLS context. These are called by the altcp TLS layer's
///    `write` and `recv` functions respectively.
///
/// 4. Register your backend at startup by assigning it to
///    `AltcpTLSLayer.backendFactory`, or by setting the global
///    `AltcpTLS.wrapHandler` in `AltcpAlloc.swift`.
///
/// ## Correspondence to C lwIP mbedTLS calls
///
/// | C lwIP / mbedTLS function              | TLSBackend method     |
/// |----------------------------------------|-----------------------|
/// | `mbedtls_ssl_handshake`                | `startHandshake`      |
/// | `mbedtls_ssl_write`                    | `encrypt`             |
/// | `mbedtls_ssl_read`                     | `decrypt`             |
/// | `mbedtls_ssl_close_notify`             | `shutdown`            |
/// | `mbedtls_x509_crt_parse`              | via `TLSConfiguration.caCertificates` |
/// | `mbedtls_ssl_set_hostname`            | via `TLSConfiguration.hostname` |
/// | `mbedtls_ssl_conf_ciphersuites`       | via `TLSConfiguration.preferredCipherSuites` |
/// | `mbedtls_ssl_session_reset`           | via `TLSConfiguration.enableSessionResumption` |
public protocol TLSBackend: AnyObject {

    /// Begin the TLS handshake over the given transport.
    ///
    /// The backend reads and writes handshake bytes through `transport`.
    /// When the handshake completes (success or failure), call `completion`.
    ///
    /// - Parameters:
    ///   - config: TLS configuration describing certificates, hostname, etc.
    ///   - transport: Callbacks for reading/writing raw bytes to the inner connection.
    ///   - completion: Called when the handshake finishes. Pass nil on success
    ///     or an error on failure.
    func startHandshake(config: TLSConfiguration,
                        transport: TLSTransport,
                        completion: @escaping (LWIPError?) -> Void)

    /// Encrypt plaintext for transmission.
    ///
    /// - Parameters:
    ///   - data: Plaintext bytes to encrypt.
    ///   - length: Number of bytes.
    /// - Returns: Encrypted (TLS record) data, or nil on error.
    func encrypt(data: UnsafeRawPointer, length: Int) -> Data?

    /// Decrypt a received TLS record into plaintext.
    ///
    /// - Parameter data: Ciphertext bytes received from the network.
    /// - Returns: Decrypted plaintext data, or nil on error.
    func decrypt(data: Data) -> Data?

    /// Send a TLS close_notify alert and tear down the session.
    func shutdown()

    /// Send a TLS close_notify alert to the peer.
    ///
    /// Unlike `shutdown()`, this method only sends the close_notify alert
    /// without tearing down the session state. Returns `true` if the alert
    /// was sent or queued successfully.
    func sendCloseNotify() -> Bool

    /// Returns the last TLS error that occurred.
    ///
    /// Backends should update their internal error state whenever a TLS
    /// operation fails. This allows the application layer to query the
    /// specific failure reason after a handshake failure, decrypt error,
    /// or other TLS-level problem.
    func lastError() -> TLSError
}

// MARK: - TLSBackend Default Implementations

extension TLSBackend {
    /// Default implementation: delegates to `shutdown()` for backward
    /// compatibility with backends that do not distinguish between
    /// close_notify and full teardown.
    public func sendCloseNotify() -> Bool {
        shutdown()
        return true
    }

    /// Default implementation: returns `.none` for backends that do not
    /// track detailed TLS errors.
    public func lastError() -> TLSError {
        return .none
    }
}

// MARK: - TLS Transport Callbacks

/// Raw byte transport used by `TLSBackend` during the handshake.
///
/// The TLS backend calls these to send and receive handshake bytes over
/// the underlying (unencrypted) TCP connection managed by the altcp layer.
public protocol TLSTransport: AnyObject {

    /// Write raw bytes to the inner connection.
    /// - Returns: `.ok` on success, or an error.
    func tlsWrite(_ data: UnsafeRawPointer, length: Int) -> LWIPError

    /// Register a handler that receives raw handshake bytes from the network.
    func setTLSReceiveHandler(_ handler: ((Data) -> Void)?)

    /// Provide received raw bytes to the TLS backend for processing.
    func tlsDidReceive(_ data: Data)
}

// MARK: - AltcpTLS Layer

/// Altcp layer that adds TLS encryption to an inner TCP connection.
///
/// This class implements `AltcpFunctions` and acts as the TLS layer in the
/// altcp chain. It delegates all cryptographic operations to a `TLSBackend`
/// instance, which in turn uses the platform's native TLS stack.
///
/// ## Usage
///
/// Most callers should not use this class directly. Instead, use the
/// allocator functions in `AltcpAlloc.swift`:
///
/// ```swift
/// let config = TLSConfiguration(hostname: "example.com")
/// let conn = AltcpTLS.new(config: config)
/// ```
///
/// To register a platform TLS backend, set the factory before creating
/// any TLS connections:
///
/// ```swift
/// AltcpTLSLayer.backendFactory = { MyPlatformTLSBackend() }
/// ```
public final class AltcpTLSLayer: AltcpFunctions, TLSTransport {

    /// Factory that creates a new `TLSBackend` instance for each connection.
    ///
    /// Must be set by the application before TLS connections are created.
    /// On Apple platforms, this would return a backend wrapping
    /// Security.framework or Network.framework.
    public static var backendFactory: (() -> TLSBackend)?

    /// The TLS backend handling cryptographic operations for this connection.
    internal var backend: TLSBackend?

    /// The TLS configuration for this connection.
    internal var config: TLSConfiguration?

    internal weak var outerConn: AltcpControlBlock?
    private var handshakeComplete = false
    private var tlsReceiveHandler: ((Data) -> Void)?

    /// The last TLS error that occurred on this connection.
    /// Applications can query this after a failure to determine the cause.
    public private(set) var lastTLSError: TLSError = .none

    /// Buffer for incoming encrypted data that may contain partial TLS records.
    private var rxBuffer: Pbuf?

    /// Buffer for decrypted application data ready for the upper layer.
    private var rxAppBuffer: Pbuf?

    /// Bytes passed to upper layer but not yet TCP-acked.
    /// The TLS layer only calls `recved` on the inner TCP connection when
    /// the application acknowledges data via the upper-layer `recved()` call.
    private var rxPassedUnrecved: UInt32 = 0

    public init() {}

    // MARK: - AltcpFunctions

    public func setPoll(_ conn: AltcpControlBlock, interval: UInt8) {
        conn.innerConn?.setPoll({ [weak conn] _, _ in
            guard let conn, let poll = conn.pollFn else { return .ok }
            return poll(conn.arg, conn)
        }, interval: interval)
    }

    public func recved(_ conn: AltcpControlBlock, len: UInt16) {
        guard handshakeComplete else { return }

        var lowerRecved = UInt32(len)
        if lowerRecved > rxPassedUnrecved {
            lowerRecved = rxPassedUnrecved
        }
        rxPassedUnrecved -= lowerRecved

        // Acknowledge data on the inner TCP connection. The value may
        // exceed UInt16.max when TLS record overhead accumulates, so
        // call recved in a loop just like altcp_mbedtls_lower_recved.
        while lowerRecved > 0 {
            let part = UInt16(min(lowerRecved, UInt32(UInt16.max)))
            conn.innerConn?.recved(part)
            lowerRecved -= UInt32(part)
        }
    }

    public func bind(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16) -> LWIPError {
        return conn.innerConn?.bind(ipaddr: ipaddr, port: port) ?? .invalidValue
    }

    public func connect(_ conn: AltcpControlBlock, ipaddr: IPAddress?, port: UInt16,
                        connected: AltcpControlBlock.ConnectedHandler?) -> LWIPError {
        guard let config, let backend else { return .invalidValue }

        conn.connectedFn = connected
        outerConn = conn
        handshakeComplete = false
        tlsReceiveHandler = nil

        return conn.innerConn?.connect(ipaddr: ipaddr, port: port, connected: { [weak self, weak conn] arg, inner, err in
            guard let self = self, let conn = conn else { return .invalidValue }
            guard err == .ok else {
                _ = conn.connectedFn?(conn.arg, conn, err)
                return .ok
            }

            backend.startHandshake(config: config, transport: self) { handshakeErr in
                self.handshakeComplete = handshakeErr == nil
                if let handshakeErr {
                    // Store detailed error from the backend for application inspection.
                    let detailedError = backend.lastError()
                    self.lastTLSError = detailedError != .none ? detailedError : .handshakeFailed
                    _ = conn.innerConn?.close()
                    _ = conn.connectedFn?(conn.arg, conn, handshakeErr)
                } else {
                    self.lastTLSError = .none
                    _ = conn.connectedFn?(conn.arg, conn, .ok)
                }
            }
            return .ok
        }) ?? .invalidValue
    }

    public func listen(_ conn: AltcpControlBlock, backlog: UInt8, err: inout LWIPError?) -> AltcpControlBlock? {
        return conn.innerConn?.listen(backlog: backlog, err: &err)
    }

    public func abort(_ conn: AltcpControlBlock) {
        tlsReceiveHandler = nil
        handshakeComplete = false
        outerConn = nil
        freeRxBuffers()
        backend?.shutdown()
        conn.innerConn?.abort()
    }

    public func close(_ conn: AltcpControlBlock) -> LWIPError {
        tlsReceiveHandler = nil

        // Send a TLS close_notify alert before closing the underlying
        // TCP connection.
        if handshakeComplete {
            _ = backend?.sendCloseNotify()
        }

        handshakeComplete = false
        outerConn = nil
        freeRxBuffers()
        backend?.shutdown()
        backend = nil
        config = nil
        return conn.innerConn?.close() ?? .ok
    }

    public func shutdown(_ conn: AltcpControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError {
        if shutRx && shutTx {
            return close(conn)
        }
        // When shutting down the TX direction, send a close_notify alert
        // so the peer knows we are done sending application data.
        if shutTx && handshakeComplete {
            _ = backend?.sendCloseNotify()
        }
        return conn.innerConn?.shutdown(rx: shutRx, tx: shutTx) ?? .invalidValue
    }

    public func write(_ conn: AltcpControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8) -> LWIPError {
        guard let encrypted = backend?.encrypt(data: data, length: Int(len)) else {
            return .invalidValue
        }
        return encrypted.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return LWIPError.invalidValue }
            return conn.innerConn?.write(base, len: UInt16(buffer.count), apiFlags: apiFlags) ?? .invalidValue
        }
    }

    public func output(_ conn: AltcpControlBlock) -> LWIPError {
        return conn.innerConn?.output() ?? .invalidValue
    }

    public func mss(_ conn: AltcpControlBlock) -> UInt16 {
        // TLS record overhead reduces the effective MSS
        let innerMSS = conn.innerConn?.mss() ?? 0
        let tlsOverhead: UInt16 = 29 // Approximate TLS 1.2 record overhead
        return innerMSS > tlsOverhead ? innerMSS - tlsOverhead : 0
    }

    public func sndbuf(_ conn: AltcpControlBlock) -> UInt16 {
        return conn.innerConn?.sndbuf() ?? 0
    }

    public func sndqueuelen(_ conn: AltcpControlBlock) -> UInt16 {
        return conn.innerConn?.sndqueuelen() ?? 0
    }

    public func nagleDisable(_ conn: AltcpControlBlock) {
        conn.innerConn?.nagleDisable()
    }

    public func nagleEnable(_ conn: AltcpControlBlock) {
        conn.innerConn?.nagleEnable()
    }

    public func nagleDisabled(_ conn: AltcpControlBlock) -> Bool {
        return conn.innerConn?.nagleDisabled() ?? false
    }

    public func setPrio(_ conn: AltcpControlBlock, prio: UInt8) {
        conn.innerConn?.setPrio(prio)
    }

    public func dealloc(_ conn: AltcpControlBlock) {
        tlsReceiveHandler = nil
        handshakeComplete = false
        outerConn = nil
        freeRxBuffers()
        backend?.shutdown()
        backend = nil
        config = nil
    }

    public func getAddrInfo(_ conn: AltcpControlBlock, local: Bool) -> (IPAddress?, UInt16)? {
        return conn.innerConn?.getAddrInfo(local: local)
    }

    public func getIP(_ conn: AltcpControlBlock, local: Bool) -> IPAddress? {
        return conn.innerConn?.getIP(local: local)
    }

    public func getPort(_ conn: AltcpControlBlock, local: Bool) -> UInt16 {
        return conn.innerConn?.getPort(local: local) ?? 0
    }

    // MARK: - TLSTransport

    public func tlsWrite(_ data: UnsafeRawPointer, length: Int) -> LWIPError {
        guard let outerConn else { return .closed }
        return outerConn.innerConn?.write(data, len: UInt16(min(length, Int(UInt16.max))),
                                          apiFlags: TCPConstants.writeFlagCopy) ?? .invalidValue
    }

    public func setTLSReceiveHandler(_ handler: ((Data) -> Void)?) {
        tlsReceiveHandler = handler
    }

    public func tlsDidReceive(_ data: Data) {
        tlsReceiveHandler?(data)
    }

    // MARK: - Lower-layer Bridging

    /// Free any buffered rx pbufs. Called during close, abort, and dealloc.
    private func freeRxBuffers() {
        if let rx = rxBuffer {
            _ = Pbuf.free(rx)
            rxBuffer = nil
        }
        if let rxApp = rxAppBuffer {
            _ = Pbuf.free(rxApp)
            rxAppBuffer = nil
        }
        rxPassedUnrecved = 0
    }

    /// Process incoming data from the inner TCP connection.
    ///
    /// During the handshake phase, raw bytes are forwarded to the TLS backend
    /// via `tlsDidReceive`. After the handshake completes, incoming data is
    /// appended to `rxBuffer` (which may contain partial TLS records from
    /// previous calls), then decrypted in a loop. Successfully decrypted
    /// plaintext is accumulated in `rxAppBuffer` and delivered to the
    /// application.
    internal func lowerRecv(conn: AltcpControlBlock, pbuf: Pbuf?, err: LWIPError) -> LWIPError {
        guard err == .ok else {
            if let pbuf { _ = Pbuf.free(pbuf) }
            lastTLSError = .protocolError
            if let recv = conn.recvFn {
                return recv(conn.arg, conn, nil, err)
            }
            return err
        }

        // nil pbuf signals the remote side closed the connection.
        guard let pbuf else {
            // If we still have buffered encrypted or decrypted data, try
            // to drain it before propagating the close indication.
            if rxBuffer != nil || rxAppBuffer != nil {
                _ = handleRxAppData(conn: conn)
            }
            if let recv = conn.recvFn {
                return recv(conn.arg, conn, nil, .ok)
            }
            return .ok
        }

        // During the handshake, forward raw bytes to the TLS backend and
        // immediately acknowledge them on the inner TCP connection (the
        // backend consumes them for the handshake state machine).
        if !handshakeComplete {
            let payloadLength = Int(pbuf.totLen)
            var ciphertext = Data(count: payloadLength)
            ciphertext.withUnsafeMutableBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
            }
            conn.innerConn?.recved(pbuf.totLen)
            _ = Pbuf.free(pbuf)
            tlsDidReceive(ciphertext)
            return .ok
        }

        // -- Application data phase --
        // Append the incoming pbuf to the encrypted rx buffer. This
        // accumulates partial TLS records until a complete record is
        // available for decryption.
        if let existing = rxBuffer {
            Pbuf.cat(existing, pbuf)
        } else {
            rxBuffer = pbuf
        }
        // Do NOT call recved on the inner connection here. We defer the
        // TCP window acknowledgment until the application calls recved()
        // on the outer connection.

        return handleRxAppData(conn: conn)
    }

    /// Attempt to decrypt complete TLS records from `rxBuffer` and deliver
    /// the resulting plaintext to the application via `rxAppBuffer`.
    private func handleRxAppData(conn: AltcpControlBlock) -> LWIPError {
        // Drain as many complete TLS records as possible.
        while let rx = rxBuffer {
            let payloadLength = Int(rx.totLen)
            var ciphertext = Data(count: payloadLength)
            ciphertext.withUnsafeMutableBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                _ = rx.copyPartial(to: baseAddress, len: rx.totLen, offset: 0)
            }

            guard let plaintext = backend?.decrypt(data: ciphertext) else {
                // Check if the backend needs more data (partial TLS record).
                let backendError = backend?.lastError() ?? .unknown
                if backendError == .wantRead {
                    // Incomplete record -- keep rxBuffer and wait for more data.
                    break
                }
                // A real decrypt error occurred.
                lastTLSError = backendError != .none ? backendError : .decryptError
                return .closed
            }

            // The entire rxBuffer was consumed by this decrypt pass.
            _ = Pbuf.free(rx)
            rxBuffer = nil

            guard !plaintext.isEmpty else { break }

            // Wrap decrypted plaintext into a pbuf and append to rxAppBuffer.
            guard plaintext.count <= Int(UInt16.max),
                  let appPbuf = Pbuf.alloc(layer: .transport, length: UInt16(plaintext.count), type: .ram) else {
                return .outOfMemory
            }
            plaintext.withUnsafeBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                appPbuf.payload.copyMemory(from: baseAddress, byteCount: plaintext.count)
            }

            if let existing = rxAppBuffer {
                Pbuf.cat(existing, appPbuf)
            } else {
                rxAppBuffer = appPbuf
            }
        }

        // Deliver buffered application data to the upper layer.
        return deliverRxAppData(conn: conn)
    }

    /// Pass accumulated decrypted data (`rxAppBuffer`) to the application
    /// receive callback.
    ///
    /// Tracks `rxPassedUnrecved` so the TCP window is only opened when the
    /// application explicitly acknowledges data via `recved()`.
    private func deliverRxAppData(conn: AltcpControlBlock) -> LWIPError {
        guard let buf = rxAppBuffer else { return .ok }
        rxAppBuffer = nil

        guard let recv = conn.recvFn else {
            // No receive callback registered; re-queue the data.
            rxAppBuffer = buf
            return .ok
        }

        let totLen = buf.totLen
        // Track bytes passed up so recved() can acknowledge them properly.
        rxPassedUnrecved += UInt32(totLen)

        let err = recv(conn.arg, conn, buf, .ok)
        if err != .ok {
            // The application did not consume the data. Re-queue it and
            // roll back the unrecved counter.
            rxAppBuffer = buf
            rxPassedUnrecved -= UInt32(totLen)
            if rxPassedUnrecved > UInt32(Int32.max) {
                rxPassedUnrecved = 0
            }
            return err
        }
        return .ok
    }

    internal func lowerSent(conn: AltcpControlBlock, len: UInt16) -> LWIPError {
        guard handshakeComplete else { return .ok }

        // If there is pending decrypted data that could not be delivered
        // earlier (e.g. because the application was not ready), try again now.
        if rxAppBuffer != nil {
            let rxErr = deliverRxAppData(conn: conn)
            if rxErr == .aborted { return .aborted }
        }

        guard let sent = conn.sentFn else { return .ok }
        return sent(conn.arg, conn, len)
    }

    internal func lowerErr(conn: AltcpControlBlock, err: LWIPError) {
        outerConn = nil
        tlsReceiveHandler = nil
        handshakeComplete = false
        // Store the TLS error from the backend if available.
        let backendError = backend?.lastError() ?? .none
        if backendError != .none {
            lastTLSError = backendError
        }
        freeRxBuffers()
        conn.innerConn = nil
        conn.errFn?(conn.arg, err)
        conn.free()
    }
}

// MARK: - Factory Functions

extension AltcpControlBlock {

    /// Create a new altcp TLS connection over TCP.
    ///
    /// This creates the full altcp chain: TLS -> TCP -> raw TCP stack.
    /// The TLS layer uses whatever `TLSBackend` is registered in
    /// `AltcpTLSLayer.backendFactory`.
    ///
    /// - Parameters:
    ///   - config: TLS configuration (hostname, certificates, etc.).
    ///   - ipType: IP address type (0 = IPv4, 6 = IPv6).
    /// - Returns: A configured altcp connection, or nil if the backend
    ///   factory is not set or TCP allocation fails.
    public static func tlsNew(config: TLSConfiguration, ipType: UInt8 = 0) -> AltcpControlBlock? {
        guard let factory = AltcpTLSLayer.backendFactory else { return nil }

        guard let innerConn = AltcpTCPFunctions.createForIPType(ipType) else {
            return nil
        }

        let conn = AltcpControlBlock()
        let tlsLayer = AltcpTLSLayer()
        tlsLayer.backend = factory()
        tlsLayer.config = config
        tlsLayer.outerConn = conn

        conn.innerConn = innerConn
        conn.fns = tlsLayer
        // The tlsLayer is retained as `fns`; store it in `state` as well
        // so it is not deallocated prematurely.
        conn.state = tlsLayer

        innerConn.setRecv { [weak conn, weak tlsLayer] _, _, pbuf, err in
            guard let conn, let tlsLayer else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .closed
            }
            return tlsLayer.lowerRecv(conn: conn, pbuf: pbuf, err: err)
        }
        innerConn.setSent { [weak conn, weak tlsLayer] _, _, len in
            guard let conn, let tlsLayer else { return .ok }
            return tlsLayer.lowerSent(conn: conn, len: len)
        }
        innerConn.setErr { [weak conn, weak tlsLayer] _, err in
            guard let conn, let tlsLayer else { return }
            tlsLayer.lowerErr(conn: conn, err: err)
        }
        return conn
    }
}
