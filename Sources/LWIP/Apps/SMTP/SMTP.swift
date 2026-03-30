//
//  SMTP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - SMTP Configuration

/// SMTP client configuration constants.
public enum SMTPConfig {
    /// Default SMTP server port.
    public static let defaultPort: UInt16 = 25
    /// Default SMTPS (TLS) port.
    public static let defaultTLSPort: UInt16 = 465
    /// Default submission port (STARTTLS).
    public static let submissionPort: UInt16 = 587
    /// Maximum server name length.
    public static var maxServerNameLength: Int = 256
    /// Maximum username length.
    public static var maxUsernameLength: Int = 64
    /// Maximum password length.
    public static var maxPasswordLength: Int = 64
    /// TCP poll interval (units of 0.5 seconds).
    public static var pollInterval: UInt8 = 4
    /// Timeout while sending message body (seconds).
    public static var timeoutDataBlock: UInt16 = 3 * 60 * UInt16(pollInterval) / 2
    /// Timeout waiting for body confirmation (seconds).
    public static var timeoutDataTermination: UInt16 = 10 * 60 * UInt16(pollInterval) / 2
    /// Default timeout for non-body commands (seconds).
    public static var timeout: UInt16 = 2 * 60 * UInt16(pollInterval) / 2
    /// Transmit buffer length.
    public static var transmitBufferLength: Int = 255
    /// Receive buffer length.
    public static var receiveBufferLength: Int = 255
    /// Whether to copy authentication data per-session.
    public static var copyAuthData: Bool = false
    /// Whether to verify mail data conforms to RFC.
    public static var checkData: Bool = true
    /// Support PLAIN authentication.
    public static var supportAuthPlain: Bool = true
    /// Support LOGIN authentication.
    public static var supportAuthLogin: Bool = true
    /// Whether to attempt STARTTLS upgrade when advertised by the server.
    public static var enableSTARTTLS: Bool = true
}

// MARK: - SMTP Result

/// SMTP send result codes.
public enum SMTPResult: UInt8, Sendable, CustomStringConvertible {
    /// Email successfully sent.
    case ok              = 0
    /// Unknown error.
    case errorUnknown    = 1
    /// Connection to server failed.
    case errorConnect    = 2
    /// Failed to resolve server hostname.
    case errorHostname   = 3
    /// Connection unexpectedly closed by remote server.
    case errorClosed     = 4
    /// Connection timed out.
    case errorTimeout    = 5
    /// Server responded with an error code.
    case errorServerResp = 6
    /// Out of memory.
    case errorMemory     = 7

    public var description: String {
        switch self {
        case .ok:              return "SMTP_RESULT_OK"
        case .errorUnknown:    return "SMTP_RESULT_ERR_UNKNOWN"
        case .errorConnect:    return "SMTP_RESULT_ERR_CONNECT"
        case .errorHostname:   return "SMTP_RESULT_ERR_HOSTNAME"
        case .errorClosed:     return "SMTP_RESULT_ERR_CLOSED"
        case .errorTimeout:    return "SMTP_RESULT_ERR_TIMEOUT"
        case .errorServerResp: return "SMTP_RESULT_ERR_SVR_RESP"
        case .errorMemory:     return "SMTP_RESULT_ERR_MEM"
        }
    }
}

// MARK: - SMTP Authentication Method

/// SMTP authentication methods.
public enum SMTPAuthMethod: Sendable {
    /// No authentication.
    case none
    /// PLAIN authentication (RFC 4616).
    case plain
    /// LOGIN authentication.
    case login
}

// MARK: - SMTP Session State

/// Internal SMTP state machine states.
internal enum SMTPSessionState: UInt8, Sendable, CustomStringConvertible {
    case null            = 0
    case helo            = 1
    case starttls        = 2
    case starttlsHandshake = 3
    case heloAfterTLS    = 4
    case authPlain       = 5
    case authLoginUname  = 6
    case authLoginPass   = 7
    case authLogin       = 8
    case mail            = 9
    case rcpt            = 10
    case data            = 11
    case body            = 12
    case quit            = 13
    case closed          = 14

    var description: String {
        switch self {
        case .null:              return "SMTP_NULL"
        case .helo:              return "SMTP_HELO"
        case .starttls:          return "SMTP_STARTTLS"
        case .starttlsHandshake: return "SMTP_STARTTLS_HANDSHAKE"
        case .heloAfterTLS:      return "SMTP_HELO_AFTER_TLS"
        case .authPlain:         return "SMTP_AUTH_PLAIN"
        case .authLoginUname:    return "SMTP_AUTH_LOGIN_UNAME"
        case .authLoginPass:     return "SMTP_AUTH_LOGIN_PASS"
        case .authLogin:         return "SMTP_AUTH_LOGIN"
        case .mail:              return "SMTP_MAIL"
        case .rcpt:              return "SMTP_RCPT"
        case .data:              return "SMTP_DATA"
        case .body:              return "SMTP_BODY"
        case .quit:              return "SMTP_QUIT"
        case .closed:            return "SMTP_CLOSED"
        }
    }
}

// MARK: - Body Data Handler

/// Result from a body data handler callback indicating whether more data is pending.
public enum SMTPBodyDataResult: Int, Sendable {
    /// Body generation is complete.
    case done    = 0
    /// More data is available; call again.
    case working = 1
}

/// State passed to body data handler callbacks for streaming body generation.
public final class SMTPBodyDataState: @unchecked Sendable {
    /// Application-controlled state counter.
    public var state: UInt16 = 0
    /// Length of content currently in the buffer.
    public var length: UInt16 = 0
    /// Buffer for generated content.
    public var buffer: [UInt8]

    public init(bufferSize: Int = 256) {
        buffer = [UInt8](repeating: 0, count: bufferSize)
    }
}

// MARK: - Callback Types

extension SMTPClient {
    /// Result callback invoked when a mail transfer completes or fails.
    ///
    /// - Parameters:
    ///   - result: The SMTP result code.
    ///   - serverError: If the server aborted, the SMTP error code received.
    ///   - error: An lwIP error code that may provide additional context.
    public typealias ResultHandler = @Sendable (SMTPResult, UInt16, LWIPError) -> Void

    /// Body data callback for streaming body generation.
    ///
    /// - Parameter bodyState: The body data state with a buffer to fill.
    /// - Returns: `.done` when finished, `.working` to be called again.
    public typealias BodyDataHandler = @Sendable (SMTPBodyDataState) -> SMTPBodyDataResult
}

// MARK: - SMTP Send Request

/// Encapsulates all information needed to send an email.
/// Can be used with `sendMail(request:)` for thread-safe invocation.
public struct SMTPSendRequest: Sendable {
    /// Source email address.
    public var from: String
    /// Destination email address(es).
    public var to: [String]
    /// CC recipient address(es).
    public var cc: [String]
    /// BCC recipient address(es).
    public var bcc: [String]
    /// Email subject.
    public var subject: String
    /// Email body.
    public var body: String
    /// Completion callback.
    public var callback: SMTPClient.ResultHandler?
    /// If true, string data is not copied (caller must keep it alive until callback).
    public var staticData: Bool

    public init(from: String,
                to: [String],
                cc: [String] = [],
                bcc: [String] = [],
                subject: String,
                body: String,
                callback: SMTPClient.ResultHandler? = nil,
                staticData: Bool = false) {
        self.from = from
        self.to = to
        self.cc = cc
        self.bcc = bcc
        self.subject = subject
        self.body = body
        self.callback = callback
        self.staticData = staticData
    }

    /// Convenience initializer accepting a single recipient string.
    public init(from: String,
                to: String,
                subject: String,
                body: String,
                callback: SMTPClient.ResultHandler? = nil,
                staticData: Bool = false) {
        self.init(from: from, to: [to], cc: [], bcc: [],
                  subject: subject, body: body,
                  callback: callback, staticData: staticData)
    }
}

// MARK: - SMTP Body Data Handler State

/// Internal state for the body data handler streaming mechanism.
internal enum SMTPBodyDHState: UInt8 {
    /// Actively calling user function to generate body content.
    case sending = 0
    /// User function signaled done, finishing up.
    case stop    = 1
}

/// Internal body-data-handler context tracking one streaming send.
internal final class SMTPBodyDHContext: @unchecked Sendable {
    var callbackFn: SMTPClient.BodyDataHandler
    var handlerState: SMTPBodyDHState = .sending
    var exposed: SMTPBodyDataState

    init(callback: @escaping SMTPClient.BodyDataHandler) {
        self.callbackFn = callback
        self.exposed = SMTPBodyDataState()
    }
}

// MARK: - SMTP Session (internal)

/// Internal session state tracking a single email send operation.
internal final class SMTPSession: @unchecked Sendable {
    var state: SMTPSessionState = .null
    var timer: UInt16 = 0
    var transmitBuffer: [UInt8]

    var from: String = ""
    var to: [String] = []
    var cc: [String] = []
    var bcc: [String] = []
    var subject: String = ""
    /// For static body: the body string. For BDH: temporarily used as pointer
    /// into the BDH buffer for partial-send tracking.
    var body: String = ""
    var bodyLen: UInt16 = 0
    var bodySent: UInt16 = 0

    /// Flattened list of all RCPT TO recipients (to + cc + bcc).
    var allRecipients: [String] = []
    /// Index of the next recipient to send RCPT TO for.
    var rcptIndex: Int = 0

    /// Accumulated receive pbuf (may span multiple TCP segments).
    var receivedPbuf: Pbuf?

    var callback: SMTPClient.ResultHandler?

    var username: String = ""
    var password: String = ""
    var authPlainData: [UInt8] = []

    /// Body data handler context (nil for static body mode).
    var bodydh: SMTPBodyDHContext?

    /// Residual BDH buffer data for resuming partial writes.
    var bdhResidual: [UInt8]?
    var bdhResidualOffset: Int = 0

    var connection: AltcpControlBlock?

    /// Reference back to client for server config during DNS callback.
    weak var client: SMTPClient?

    /// TLS configuration for STARTTLS upgrade (set from client when STARTTLS is enabled).
    var starttlsConfig: TLSConfiguration?

    /// Whether the server advertised STARTTLS in the EHLO response.
    var serverSupportsSTARTTLS: Bool = false

    init() {
        transmitBuffer = [UInt8](repeating: 0, count: SMTPConfig.transmitBufferLength + 1)
    }

    deinit {
        if let p = receivedPbuf {
            _ = Pbuf.free(p)
        }
    }
}

// MARK: - SMTP Client

/// SMTP client for sending emails over TCP.
///
/// Usage:
/// ```swift
/// let client = SMTPClient()
/// client.setServer("mail.example.com")
/// client.setAuth(username: "user", password: "pass")
/// client.sendMail(from: "sender@example.com",
///                 to: "recipient@example.com",
///                 subject: "Test",
///                 body: "Hello!") { result, serverErr, err in
///     print("Result: \(result)")
/// }
/// ```
public final class SMTPClient: @unchecked Sendable {

    // MARK: - Properties

    /// Server hostname or IP address.
    internal var serverAddress: String = ""
    /// Server TCP port.
    internal var serverPort: UInt16 = SMTPConfig.defaultPort
    /// TLS configuration (nil for plain SMTP).
    internal var tlsConfig: TLSConfiguration?

    /// Username for authentication.
    private var username: String?
    /// Password for authentication.
    private var password: String?
    /// Pre-encoded PLAIN authentication data (\0username\0password).
    private var authPlainData: [UInt8] = []

    /// Lock for thread safety.
    private let lock = NSLock()

    // MARK: - Initialization

    /// Create a new SMTP client.
    public init() {}

    // MARK: - Server Configuration

    /// Set the SMTP server address (IP or hostname).
    ///
    /// - Parameter server: The server address string.
    /// - Returns: `.ok` on success, `.outOfMemory` if the address is too long.
    @discardableResult
    public func setServer(_ server: String) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard server.count <= SMTPConfig.maxServerNameLength else {
            return .outOfMemory
        }
        serverAddress = server
        return .ok
    }

    /// Set the SMTP server port.
    ///
    /// - Parameter port: The TCP port number.
    public func setServerPort(_ port: UInt16) {
        lock.lock()
        defer { lock.unlock() }
        serverPort = port
    }

    /// Set the TLS configuration for SMTPS connections.
    ///
    /// - Parameter config: The TLS configuration object, or nil to disable TLS.
    public func setTLSConfig(_ config: TLSConfiguration?) {
        lock.lock()
        defer { lock.unlock() }
        tlsConfig = config
    }

    /// Set authentication credentials.
    ///
    /// Pass nil for both to disable authentication.
    ///
    /// - Parameters:
    ///   - username: The login username.
    ///   - password: The login password.
    /// - Returns: `.ok` on success, `.invalidArgument` if credentials are too long.
    @discardableResult
    public func setAuth(username: String?, password: String?) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        if let u = username, u.count > SMTPConfig.maxUsernameLength {
            return .invalidArgument
        }
        if let p = password, p.count > SMTPConfig.maxPasswordLength {
            return .invalidArgument
        }

        self.username = username
        self.password = password

        // Build PLAIN auth data: \0username\0password
        var plain: [UInt8] = [0]
        if let u = username {
            plain.append(contentsOf: Array(u.utf8))
        }
        plain.append(0)
        if let p = password {
            plain.append(contentsOf: Array(p.utf8))
        }
        authPlainData = plain

        return .ok
    }

    // MARK: - Send Mail

    /// Send an email using the configured server and credentials.
    ///
    /// The callback is invoked when the send operation completes or fails.
    /// Data is copied into internal buffers.
    ///
    /// - Parameters:
    ///   - from: Source email address.
    ///   - to: Destination email address(es).
    ///   - cc: CC recipient address(es).
    ///   - bcc: BCC recipient address(es).
    ///   - subject: Email subject line.
    ///   - body: Email body text.
    ///   - callback: Completion callback.
    /// - Returns: `.ok` if the operation was started successfully.
    @discardableResult
    public func sendMail(from: String,
                         to: [String],
                         cc: [String] = [],
                         bcc: [String] = [],
                         subject: String,
                         body: String,
                         callback: ResultHandler? = nil) -> LWIPError {
        let session = SMTPSession()
        session.from = from
        session.to = to
        session.cc = cc
        session.bcc = bcc
        session.allRecipients = to + cc + bcc
        session.rcptIndex = 0
        session.subject = subject
        session.body = body
        session.bodyLen = UInt16(min(body.utf8.count, Int(UInt16.max)))
        session.callback = callback
        session.timer = SMTPConfig.timeout
        session.client = self

        lock.lock()
        if let u = username { session.username = u }
        if let p = password { session.password = p }
        session.authPlainData = authPlainData
        if SMTPConfig.enableSTARTTLS {
            session.starttlsConfig = tlsConfig
        }
        lock.unlock()

        return startSession(session)
    }

    /// Convenience overload accepting a single recipient string.
    @discardableResult
    public func sendMail(from: String,
                         to: String,
                         subject: String,
                         body: String,
                         callback: ResultHandler? = nil) -> LWIPError {
        return sendMail(from: from, to: [to], cc: [], bcc: [],
                        subject: subject, body: body, callback: callback)
    }

    /// Send an email with a body data handler for streaming body generation.
    ///
    /// - Parameters:
    ///   - from: Source email address.
    ///   - to: Destination email address(es).
    ///   - cc: CC recipient address(es).
    ///   - bcc: BCC recipient address(es).
    ///   - subject: Email subject line.
    ///   - bodyHandler: Callback that generates body content on demand.
    ///   - callback: Completion callback.
    /// - Returns: `.ok` if the operation was started successfully.
    @discardableResult
    public func sendMailWithBodyHandler(from: String,
                                        to: [String],
                                        cc: [String] = [],
                                        bcc: [String] = [],
                                        subject: String,
                                        bodyHandler: @escaping BodyDataHandler,
                                        callback: ResultHandler? = nil) -> LWIPError {
        let session = SMTPSession()
        session.from = from
        session.to = to
        session.cc = cc
        session.bcc = bcc
        session.allRecipients = to + cc + bcc
        session.rcptIndex = 0
        session.subject = subject
        session.callback = callback
        session.timer = SMTPConfig.timeout
        session.client = self
        session.bodydh = SMTPBodyDHContext(callback: bodyHandler)
        // bodyLen starts at 0; body is unused in BDH mode
        session.body = ""
        session.bodyLen = 0

        lock.lock()
        if let u = username { session.username = u }
        if let p = password { session.password = p }
        session.authPlainData = authPlainData
        if SMTPConfig.enableSTARTTLS {
            session.starttlsConfig = tlsConfig
        }
        lock.unlock()

        return startSession(session)
    }

    /// Convenience overload accepting a single recipient string for body handler.
    @discardableResult
    public func sendMailWithBodyHandler(from: String,
                                        to: String,
                                        subject: String,
                                        bodyHandler: @escaping BodyDataHandler,
                                        callback: ResultHandler? = nil) -> LWIPError {
        return sendMailWithBodyHandler(from: from, to: [to], cc: [], bcc: [],
                                       subject: subject, bodyHandler: bodyHandler,
                                       callback: callback)
    }

    /// Send a mail from an `SMTPSendRequest` structure.
    ///
    /// Useful for dispatching from interrupt context or non-TCPIP threads.
    ///
    /// - Parameter request: The send request.
    /// - Returns: `.ok` if the operation was started successfully.
    @discardableResult
    public func sendMail(request: SMTPSendRequest) -> LWIPError {
        return sendMail(from: request.from,
                        to: request.to,
                        cc: request.cc,
                        bcc: request.bcc,
                        subject: request.subject,
                        body: request.body,
                        callback: request.callback)
    }

    // MARK: - Internal Session Management

    /// Set up altcp PCB with session callbacks and return it.
    private func setupPCB(session: SMTPSession, remoteIP: IPAddress) -> AltcpControlBlock? {
        let pcb: AltcpControlBlock?

        lock.lock()
        let tls = tlsConfig
        lock.unlock()

        if let tlsConf = tls {
            // SMTPS: create TLS-wrapped connection (port 465 typically)
            pcb = AltcpControlBlock.tlsNew(config: tlsConf, ipType: remoteIP.isV6 ? 6 : 0)
        } else {
            pcb = AltcpControlBlock.create(ipType: remoteIP.isV6 ? 6 : 0)
        }

        guard let connection = pcb else { return nil }

        connection.setArg(session)
        connection.setRecv(smtpTCPRecv)
        connection.setErr(smtpTCPErr)
        connection.setPoll(smtpTCPPoll, interval: SMTPConfig.pollInterval)
        connection.setSent(smtpTCPSent)

        return connection
    }

    /// Start a new SMTP session by resolving the server and connecting.
    private func startSession(_ session: SMTPSession) -> LWIPError {
        session.state = .null
        session.timer = SMTPConfig.timeout

        lock.lock()
        let server = serverAddress
        let port = serverPort
        lock.unlock()

        // Validate data if configured
        if SMTPConfig.checkData {
            if SMTPClient.verifyData(session.from) != .ok { return .invalidArgument }
            for recipient in session.allRecipients {
                if SMTPClient.verifyData(recipient) != .ok { return .invalidArgument }
            }
            if session.allRecipients.isEmpty { return .invalidArgument }
            if SMTPClient.verifyData(session.subject) != .ok { return .invalidArgument }
            if session.bodydh == nil {
                if SMTPClient.verifyData(session.body) != .ok { return .invalidArgument }
            }
        }

        // Try DNS resolution (handles IP literals and cached entries synchronously)
        let (dnsErr, resolvedAddr) = DNS.shared.getHostByName(server, found: { [weak self] hostname, ipaddr, arg in
            guard let session = arg as? SMTPSession else { return }
            self?.dnsFound(hostname: hostname, ipaddr: ipaddr, session: session)
        }, arg: session)

        if dnsErr == .ok, let addr = resolvedAddr {
            // Address resolved immediately (IP literal or cached)
            guard let pcb = setupPCB(session: session, remoteIP: addr) else {
                return .outOfMemory
            }
            session.connection = pcb
            let connErr = pcb.connect(ipaddr: addr, port: port, connected: smtpTCPConnected)
            if connErr != .ok {
                pcb.setArg(nil)
                pcb.close()
                return connErr
            }
        } else if dnsErr != .inProgress {
            // DNS lookup failed immediately
            session.callback?(.errorHostname, 0, dnsErr)
            return dnsErr
        }
        // If .inProgress, DNS callback will fire later and continue the connection

        return .ok
    }

    // MARK: - DNS Callback

    /// Called when DNS resolution completes asynchronously.
    private func dnsFound(hostname: String, ipaddr: IPAddress?, session: SMTPSession) {
        guard let addr = ipaddr else {
            // DNS resolution failed
            smtpClose(session: session, pcb: nil, result: .errorHostname, serverError: 0, err: .invalidArgument)
            return
        }

        guard let pcb = setupPCB(session: session, remoteIP: addr) else {
            smtpClose(session: session, pcb: nil, result: .errorMemory, serverError: 0, err: .outOfMemory)
            return
        }

        session.connection = pcb

        lock.lock()
        let port = serverPort
        lock.unlock()

        let connErr = pcb.connect(ipaddr: addr, port: port, connected: smtpTCPConnected)
        if connErr != .ok {
            smtpClose(session: session, pcb: pcb, result: .errorConnect, serverError: 0, err: connErr)
        }
    }

    // MARK: - TCP Callbacks

    /// Connected callback: server TCP connection established, wait for greeting.
    private let smtpTCPConnected: AltcpControlBlock.ConnectedHandler = { arg, conn, err in
        if err != .ok {
            if let session = arg as? SMTPSession {
                SMTPClient.smtpClose(session: session, pcb: conn, result: .errorConnect, serverError: 0, err: err)
            }
        }
        // Connection established; remain in .null state and wait for 220 greeting
        return .ok
    }

    /// Receive callback: accumulate data and drive the state machine.
    private let smtpTCPRecv: AltcpControlBlock.ReceiveHandler = { arg, conn, pbuf, err in
        if let p = pbuf {
            conn.recved(UInt16(truncatingIfNeeded: p.totLen))
            SMTPClient.smtpProcess(arg: arg, pcb: conn, p: p)
        } else {
            // Connection closed by remote
            if let session = arg as? SMTPSession {
                SMTPClient.smtpClose(session: session, pcb: conn, result: .errorClosed, serverError: 0, err: .closed)
            }
        }
        return .ok
    }

    /// Sent callback: continue streaming body data or handle idle.
    private let smtpTCPSent: AltcpControlBlock.SentHandler = { arg, conn, len in
        SMTPClient.smtpProcess(arg: arg, pcb: conn, p: nil)
        return .ok
    }

    /// Poll callback: drive timeout and body send.
    private let smtpTCPPoll: AltcpControlBlock.PollHandler = { arg, conn in
        if let session = arg as? SMTPSession {
            if session.timer > 0 {
                session.timer -= 1
            }
        }
        SMTPClient.smtpProcess(arg: arg, pcb: conn, p: nil)
        return .ok
    }

    /// Error callback: connection error, PCB already deallocated.
    private let smtpTCPErr: AltcpControlBlock.ErrorHandler = { arg, err in
        guard let session = arg as? SMTPSession else { return }
        session.connection = nil
        SMTPClient.smtpFree(session: session, result: .errorClosed, serverError: 0, err: err)
    }

    // MARK: - Close and Free Helpers

    /// Free the session and invoke the callback.
    fileprivate static func smtpFree(session: SMTPSession, result: SMTPResult,
                                      serverError: UInt16, err: LWIPError) {
        let fn = session.callback
        session.callback = nil
        if let p = session.receivedPbuf {
            _ = Pbuf.free(p)
            session.receivedPbuf = nil
        }
        session.state = .closed
        fn?(result, serverError, err)
    }

    /// Close the PCB and free the session.
    fileprivate static func smtpClose(session: SMTPSession?, pcb: AltcpControlBlock?,
                                       result: SMTPResult, serverError: UInt16, err: LWIPError) {
        if let pcb = pcb {
            pcb.setArg(nil)
            if pcb.close() == .ok {
                if let s = session {
                    smtpFree(session: s, result: result, serverError: serverError, err: err)
                }
            } else {
                // Close failed; restore arg for retry later
                pcb.setArg(session)
            }
        } else if let s = session {
            smtpFree(session: s, result: result, serverError: serverError, err: err)
        }
    }

    /// Instance-level convenience wrapper.
    private func smtpClose(session: SMTPSession?, pcb: AltcpControlBlock?,
                           result: SMTPResult, serverError: UInt16, err: LWIPError) {
        SMTPClient.smtpClose(session: session, pcb: pcb, result: result,
                             serverError: serverError, err: err)
    }

    // MARK: - Response Parsing

    /// Extract the 3-digit response code from the beginning of the pbuf.
    /// Returns 0 if no valid code found.
    private static func smtpIsResponse(session: SMTPSession) -> UInt16 {
        guard let p = session.receivedPbuf, p.totLen >= 3 else { return 0 }
        var digits = [UInt8](repeating: 0, count: 3)
        digits.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = p.copyPartial(to: UnsafeMutableRawPointer(base), len: 3, offset: 0)
        }
        // Parse ASCII digits
        guard digits[0] >= 0x30, digits[0] <= 0x39,
              digits[1] >= 0x30, digits[1] <= 0x39,
              digits[2] >= 0x30, digits[2] <= 0x39 else { return 0 }
        let num = UInt16(digits[0] - 0x30) * 100
                + UInt16(digits[1] - 0x30) * 10
                + UInt16(digits[2] - 0x30)
        guard num > 0 && num < 1000 else { return 0 }
        return num
    }

    /// Check that a complete response has been received (3-digit code + space + ... + CRLF).
    /// Multi-line responses use '-' after the code; only the final line uses ' '.
    private static func smtpIsResponseFinished(session: SMTPSession) -> Bool {
        guard let p = session.receivedPbuf else { return false }
        var offset: UInt16 = 0
        let crlfBytes: [UInt8] = [0x0D, 0x0A]
        while true {
            guard offset <= 0xFFFB else { return false }
            // Find CRLF after offset+4 (code + separator + at least one char)
            let crlf = crlfBytes.withUnsafeBufferPointer { buf -> UInt16 in
                return p.memfind(UnsafeRawPointer(buf.baseAddress!), memLen: 2,
                                 startOffset: offset + 4)
            }
            if crlf == 0xFFFF { return false }
            // Check character after 3-digit code
            let sp = p.byte(at: offset + 3)
            if sp == UInt8(ascii: "-") {
                // Multi-line continuation; check next line
                offset = crlf + 2
                if offset < crlf { return false } // overflow
                continue
            } else if sp == UInt8(ascii: " ") {
                // Final line of response
                return true
            }
            // Invalid character
            return false
        }
    }

    // MARK: - SMTP State Machine

    /// Central state machine: called on recv, sent, and poll.
    fileprivate static func smtpProcess(arg: AnyObject?, pcb: AltcpControlBlock, p: Pbuf?) {
        guard let session = arg as? SMTPSession else {
            // Already closed
            if let p = p { _ = Pbuf.free(p) }
            return
        }

        var nextState = session.state
        var txBufLen: UInt16 = 0

        if let p = p {
            // Received data: accumulate into session pbuf
            if let existing = session.receivedPbuf {
                Pbuf.cat(existing, p)
            } else {
                session.receivedPbuf = p
            }
        } else {
            // Idle (poll or sent callback)
            if session.timer == 0 {
                smtpClose(session: session, pcb: pcb, result: .errorTimeout, serverError: 0, err: .timeout)
                return
            }
            if session.state == .body {
                smtpSendBody(session: session, pcb: pcb)
                return
            }
            // Nothing more to do on idle if not in body state
            return
        }

        // Check for response code
        let responseCode = smtpIsResponse(session: session)
        if responseCode != 0 {
            if !smtpIsResponseFinished(session: session) {
                // Partial response; wait for more data
                return
            }
        } else {
            // No valid response code; discard data
            if let p = session.receivedPbuf {
                _ = Pbuf.free(p)
                session.receivedPbuf = nil
            }
            return
        }

        // State machine dispatch
        switch session.state {
        case .null:
            // Waiting for 220 greeting
            if responseCode == 220 {
                txBufLen = smtpPrepareHelo(session: session, pcb: pcb)
                nextState = .helo
            }

        case .helo:
            // Waiting for 250 from EHLO
            if responseCode == 250 {
                // Check for STARTTLS capability before auth
                if SMTPConfig.enableSTARTTLS && session.starttlsConfig != nil {
                    let starttlsAdvertised = smtpPbufContains(session: session, needle: "STARTTLS")
                    if starttlsAdvertised {
                        session.serverSupportsSTARTTLS = true
                        txBufLen = smtpPrepareSTARTTLS(session: session)
                        nextState = .starttls
                        break
                    }
                }
                // No STARTTLS; proceed with auth or mail
                if SMTPConfig.supportAuthPlain || SMTPConfig.supportAuthLogin {
                    (nextState, txBufLen) = smtpPrepareAuthOrMail(session: session)
                } else {
                    txBufLen = smtpPrepareMail(session: session)
                    nextState = .mail
                }
            }

        case .starttls:
            // Waiting for 220 (ready to start TLS)
            if responseCode == 220 {
                // Initiate TLS handshake on the existing connection
                smtpUpgradeToTLS(session: session, pcb: pcb)
                // Free consumed receive data before handshake
                if let p = session.receivedPbuf {
                    _ = Pbuf.free(p)
                    session.receivedPbuf = nil
                }
                session.state = .starttlsHandshake
                session.timer = SMTPConfig.timeout
                return
            }

        case .starttlsHandshake:
            // TLS handshake completes asynchronously via callback; should not
            // receive SMTP-layer data in this state. If we do, ignore it.
            break

        case .heloAfterTLS:
            // Waiting for 250 from second EHLO (after TLS upgrade)
            if responseCode == 250 {
                if SMTPConfig.supportAuthPlain || SMTPConfig.supportAuthLogin {
                    (nextState, txBufLen) = smtpPrepareAuthOrMail(session: session)
                } else {
                    txBufLen = smtpPrepareMail(session: session)
                    nextState = .mail
                }
            }

        case .authPlain:
            // Waiting for 235 (auth success)
            if responseCode == 235 {
                txBufLen = smtpPrepareMail(session: session)
                nextState = .mail
            }

        case .authLogin:
            // Waiting for 235 (auth success via LOGIN)
            if responseCode == 235 {
                txBufLen = smtpPrepareMail(session: session)
                nextState = .mail
            }

        case .authLoginUname:
            // Waiting for 334 Username challenge
            if responseCode == 334 {
                // Verify the challenge contains "VXNlcm5hbWU6" (base64 "Username:")
                if smtpPbufContains(session: session, needle: "VXNlcm5hbWU6") {
                    txBufLen = smtpPrepareAuthLoginUname(session: session)
                    nextState = .authLoginPass
                }
            }

        case .authLoginPass:
            // Waiting for 334 Password challenge
            if responseCode == 334 {
                // Verify the challenge contains "UGFzc3dvcmQ6" (base64 "Password:")
                if smtpPbufContains(session: session, needle: "UGFzc3dvcmQ6") {
                    txBufLen = smtpPrepareAuthLoginPass(session: session)
                    nextState = .authLogin
                }
            }

        case .mail:
            // Waiting for 250 (MAIL FROM accepted)
            if responseCode == 250 {
                session.rcptIndex = 0
                txBufLen = smtpPrepareRcpt(session: session)
                nextState = .rcpt
            }

        case .rcpt:
            // Waiting for 250 (RCPT TO accepted)
            if responseCode == 250 {
                if session.rcptIndex < session.allRecipients.count {
                    // More recipients to send RCPT TO for
                    txBufLen = smtpPrepareRcpt(session: session)
                    nextState = .rcpt
                } else {
                    // All recipients accepted; send DATA
                    let dataCmd: [UInt8] = Array("DATA\r\n".utf8)
                    session.transmitBuffer.replaceSubrange(0..<dataCmd.count, with: dataCmd)
                    txBufLen = UInt16(dataCmd.count)
                    nextState = .data
                }
            }

        case .data:
            // Waiting for 354 (ready for body)
            if responseCode == 354 {
                txBufLen = smtpPrepareHeader(session: session)
                nextState = .body
            }

        case .body:
            // Should not normally receive response during body; ignore
            break

        case .quit:
            // Waiting for 250 (body accepted)
            if responseCode == 250 {
                txBufLen = smtpPrepareQuit(session: session)
                nextState = .closed
            }

        case .closed:
            // Nothing to do, waiting for remote close
            return
        }

        // If state didn't advance, server returned unexpected code -> error.
        // Exception: .rcpt can remain .rcpt when iterating through multiple recipients.
        let stateAdvanced = (session.state != nextState) ||
                            (session.state == .rcpt && nextState == .rcpt && txBufLen > 0)
        if !stateAdvanced {
            smtpClose(session: session, pcb: pcb, result: .errorServerResp,
                      serverError: responseCode, err: .ok)
            return
        }

        // Send command if prepared
        if txBufLen > 0 {
            let writeErr = session.transmitBuffer.withUnsafeBufferPointer { buf -> LWIPError in
                guard let base = buf.baseAddress else { return .outOfMemory }
                return pcb.write(UnsafeRawPointer(base), len: txBufLen,
                                 apiFlags: TCPConstants.writeFlagCopy)
            }
            if writeErr == .ok {
                pcb.output()
                session.timer = SMTPConfig.timeout

                // Free consumed receive data
                if let p = session.receivedPbuf {
                    _ = Pbuf.free(p)
                    session.receivedPbuf = nil
                }

                session.state = nextState

                if nextState == .body {
                    // Immediately start streaming body data
                    smtpSendBody(session: session, pcb: pcb)
                } else if nextState == .closed {
                    // All done, sent QUIT, free session
                    pcb.setArg(nil)
                    smtpFree(session: session, result: .ok, serverError: 0, err: .ok)
                }
            }
            // If write failed, we stay in current state; next poll/sent will retry
        }
    }

    // MARK: - Command Preparation

    /// Prepare EHLO command using local IP.
    /// Returns the number of bytes placed in transmitBuffer.
    private static func smtpPrepareHelo(session: SMTPSession, pcb: AltcpControlBlock) -> UInt16 {
        let prefix = "EHLO ["
        let suffix = "]\r\n"

        // Get local IP from connection
        let localIP: String
        if let ip = pcb.getIP(local: true) {
            localIP = ip.description
        } else {
            localIP = "127.0.0.1"
        }

        let cmd = prefix + localIP + suffix
        let cmdBytes = Array(cmd.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Parse EHLO response for AUTH capabilities and prepare the appropriate
    /// auth command or fall through to MAIL FROM.
    private static func smtpPrepareAuthOrMail(session: SMTPSession) -> (SMTPSessionState, UInt16) {
        guard let p = session.receivedPbuf else {
            let len = smtpPrepareMail(session: session)
            return (.mail, len)
        }

        // Look for "AUTH " or "AUTH=" in the response
        let authFound: Bool = "AUTH ".withCString { cstr -> Bool in
            let pos = p.strstr(cstr)
            if pos != 0xFFFF { return true }
            return "AUTH=".withCString { cstr2 -> Bool in
                return p.strstr(cstr2) != 0xFFFF
            }
        }

        guard authFound && !session.username.isEmpty else {
            // No auth available or no credentials; go straight to MAIL
            let len = smtpPrepareMail(session: session)
            return (.mail, len)
        }

        // Extract the AUTH line to check supported methods
        let authLineContainsPlain = "PLAIN".withCString { cstr -> Bool in
            return p.strstr(cstr) != 0xFFFF
        }
        let authLineContainsLogin = "LOGIN".withCString { cstr -> Bool in
            return p.strstr(cstr) != 0xFFFF
        }

        if SMTPConfig.supportAuthPlain && authLineContainsPlain {
            // Prefer PLAIN over LOGIN (fewer round-trips)
            let prefix = "AUTH PLAIN "
            let encoded = base64Encode(session.authPlainData)
            let cmdStr = prefix + encoded + "\r\n"
            let cmdBytes = Array(cmdStr.utf8)
            let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
            session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
            return (.authPlain, UInt16(len))
        }

        if SMTPConfig.supportAuthLogin && authLineContainsLogin {
            let cmdStr = "AUTH LOGIN\r\n"
            let cmdBytes = Array(cmdStr.utf8)
            let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
            session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
            return (.authLoginUname, UInt16(len))
        }

        // Server didn't advertise a supported auth method; try sending mail anyway
        let len = smtpPrepareMail(session: session)
        return (.mail, len)
    }

    /// Prepare base64-encoded username for AUTH LOGIN.
    private static func smtpPrepareAuthLoginUname(session: SMTPSession) -> UInt16 {
        let encoded = base64Encode(Array(session.username.utf8))
        let cmdStr = encoded + "\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Prepare base64-encoded password for AUTH LOGIN.
    private static func smtpPrepareAuthLoginPass(session: SMTPSession) -> UInt16 {
        let encoded = base64Encode(Array(session.password.utf8))
        let cmdStr = encoded + "\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Prepare MAIL FROM command.
    @discardableResult
    private static func smtpPrepareMail(session: SMTPSession) -> UInt16 {
        let cmdStr = "MAIL FROM: <\(session.from)>\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Prepare RCPT TO command for the next recipient in the list.
    /// Advances `rcptIndex` after preparing the command.
    private static func smtpPrepareRcpt(session: SMTPSession) -> UInt16 {
        guard session.rcptIndex < session.allRecipients.count else { return 0 }
        let recipient = session.allRecipients[session.rcptIndex]
        session.rcptIndex += 1
        let cmdStr = "RCPT TO: <\(recipient)>\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Prepare email header (From, To, CC, Subject).
    /// BCC recipients are intentionally omitted from headers per RFC 5321.
    private static func smtpPrepareHeader(session: SMTPSession) -> UInt16 {
        var header = "From: <\(session.from)>\r\n"

        // To header: comma-separated list of To recipients
        if !session.to.isEmpty {
            let toList = session.to.map { "<\($0)>" }.joined(separator: ", ")
            header += "To: \(toList)\r\n"
        }

        // CC header: comma-separated list of CC recipients (visible to all)
        if !session.cc.isEmpty {
            let ccList = session.cc.map { "<\($0)>" }.joined(separator: ", ")
            header += "Cc: \(ccList)\r\n"
        }

        // BCC recipients are NOT included in headers

        header += "Subject: \(session.subject)\r\n"
        header += "\r\n"

        let headerBytes = Array(header.utf8)
        let len = min(headerBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: headerBytes[0..<len])
        return UInt16(len)
    }

    /// Prepare QUIT command.
    private static func smtpPrepareQuit(session: SMTPSession) -> UInt16 {
        let cmdStr = "QUIT\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        session.transmitBuffer.replaceSubrange(0..<cmdBytes.count, with: cmdBytes)
        return UInt16(cmdBytes.count)
    }

    // MARK: - STARTTLS

    /// Prepare the STARTTLS command.
    private static func smtpPrepareSTARTTLS(session: SMTPSession) -> UInt16 {
        let cmdStr = "STARTTLS\r\n"
        let cmdBytes = Array(cmdStr.utf8)
        let len = min(cmdBytes.count, SMTPConfig.transmitBufferLength)
        session.transmitBuffer.replaceSubrange(0..<len, with: cmdBytes[0..<len])
        return UInt16(len)
    }

    /// Upgrade the existing plain TCP connection to TLS for STARTTLS.
    /// Creates a TLS layer on top of the current connection and initiates the handshake.
    /// On completion, sends a new EHLO and transitions to `.heloAfterTLS`.
    private static func smtpUpgradeToTLS(session: SMTPSession, pcb: AltcpControlBlock) {
        guard let tlsConfig = session.starttlsConfig else {
            smtpClose(session: session, pcb: pcb, result: .errorUnknown, serverError: 0, err: .invalidArgument)
            return
        }
        guard let factory = AltcpTLSLayer.backendFactory else {
            smtpClose(session: session, pcb: pcb, result: .errorUnknown, serverError: 0, err: .invalidArgument)
            return
        }

        // Create a TLS layer that wraps the existing TCP connection
        let tlsLayer = AltcpTLSLayer()
        tlsLayer.backend = factory()
        tlsLayer.config = tlsConfig

        // The current pcb becomes the inner (TCP) layer.
        // We create a new outer connection that delegates through the TLS layer.
        let outerConn = AltcpControlBlock()
        outerConn.innerConn = pcb
        outerConn.fns = tlsLayer
        outerConn.state = tlsLayer
        tlsLayer.outerConn = outerConn

        // Preserve application callbacks on the outer connection
        outerConn.arg = session
        outerConn.recvFn = pcb.recvFn
        outerConn.sentFn = pcb.sentFn
        outerConn.pollFn = pcb.pollFn
        outerConn.errFn = pcb.errFn
        outerConn.pollInterval = pcb.pollInterval

        // Redirect inner connection callbacks to the TLS layer
        pcb.setRecv { [weak outerConn, weak tlsLayer] _, _, pbuf, err in
            guard let outerConn, let tlsLayer else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .closed
            }
            return tlsLayer.lowerRecv(conn: outerConn, pbuf: pbuf, err: err)
        }
        pcb.setSent { [weak outerConn, weak tlsLayer] _, _, len in
            guard let outerConn, let tlsLayer else { return .ok }
            return tlsLayer.lowerSent(conn: outerConn, len: len)
        }
        pcb.setErr { [weak outerConn, weak tlsLayer] _, err in
            guard let outerConn, let tlsLayer else { return }
            tlsLayer.lowerErr(conn: outerConn, err: err)
        }

        // Update session to use the new outer (TLS) connection
        session.connection = outerConn

        // Start TLS handshake
        guard let backend = tlsLayer.backend else {
            smtpClose(session: session, pcb: outerConn, result: .errorUnknown, serverError: 0, err: .invalidArgument)
            return
        }
        backend.startHandshake(config: tlsConfig, transport: tlsLayer) { [weak session, weak outerConn] handshakeErr in
            guard let session, let outerConn else { return }
            if let handshakeErr {
                smtpClose(session: session, pcb: outerConn, result: .errorConnect, serverError: 0, err: handshakeErr)
            } else {
                // TLS handshake succeeded; re-send EHLO over the encrypted connection
                let txLen = smtpPrepareHelo(session: session, pcb: outerConn)
                if txLen > 0 {
                    let writeErr = session.transmitBuffer.withUnsafeBufferPointer { buf -> LWIPError in
                        guard let base = buf.baseAddress else { return .outOfMemory }
                        return outerConn.write(UnsafeRawPointer(base), len: txLen,
                                               apiFlags: TCPConstants.writeFlagCopy)
                    }
                    if writeErr == .ok {
                        outerConn.output()
                        session.timer = SMTPConfig.timeout
                        session.state = .heloAfterTLS
                    } else {
                        smtpClose(session: session, pcb: outerConn, result: .errorUnknown, serverError: 0, err: writeErr)
                    }
                }
            }
        }
    }

    // MARK: - Body Sending

    /// Write body data to the connection. Called from smtpProcess on state transitions
    /// and from sent/poll callbacks while in BODY state.
    fileprivate static func smtpSendBody(session: SMTPSession, pcb: AltcpControlBlock) {
        guard session.state == .body else { return }

        if let bdh = session.bodydh {
            smtpSendBodyDataHandler(session: session, pcb: pcb, bdh: bdh)
        } else {
            smtpSendBodyStatic(session: session, pcb: pcb)
        }
    }

    /// Send static body data, respecting send buffer limits.
    private static func smtpSendBodyStatic(session: SMTPSession, pcb: AltcpControlBlock) {
        let bodyBytes = Array(session.body.utf8)
        let bodyLen = UInt16(min(bodyBytes.count, Int(UInt16.max)))
        var sendLen = bodyLen - session.bodySent

        if sendLen > 0 {
            let sndBuf = pcb.sndbuf()
            if sendLen > sndBuf {
                sendLen = sndBuf
            }
            if sendLen > 0 {
                let startIdx = Int(session.bodySent)
                let endIdx = startIdx + Int(sendLen)
                let chunk = Array(bodyBytes[startIdx..<endIdx])
                let writeErr = chunk.withUnsafeBufferPointer { buf -> LWIPError in
                    guard let base = buf.baseAddress else { return .outOfMemory }
                    return pcb.write(UnsafeRawPointer(base), len: UInt16(chunk.count),
                                     apiFlags: TCPConstants.writeFlagCopy)
                }
                if writeErr == .ok {
                    session.timer = SMTPConfig.timeoutDataBlock
                    session.bodySent += UInt16(chunk.count)
                }
            }
        }

        // Check if entire body has been sent
        if session.bodySent >= bodyLen {
            // Write the body terminator "\r\n.\r\n"
            let terminator: [UInt8] = Array("\r\n.\r\n".utf8)
            let termErr = terminator.withUnsafeBufferPointer { buf -> LWIPError in
                guard let base = buf.baseAddress else { return .outOfMemory }
                return pcb.write(UnsafeRawPointer(base), len: UInt16(terminator.count),
                                 apiFlags: TCPConstants.writeFlagCopy)
            }
            if termErr == .ok {
                pcb.output()
                session.timer = SMTPConfig.timeoutDataTermination
                session.state = .quit
            }
        }
    }

    // MARK: - Body Data Handler (streaming)

    /// Helper: write up to `howmany` bytes from `data` starting at `offset`, respecting sndbuf.
    /// Returns: 2 = all data sent, 1 = some data sent (sndbuf full), 0 = nothing sent.
    private static let bdhAllDataSent = 2
    private static let bdhSomeDataSent = 1

    private static func smtpSendBodyHData(pcb: AltcpControlBlock, data: [UInt8],
                                           offset: inout Int, remaining: inout Int) -> Int {
        guard remaining > 0 else { return bdhAllDataSent }
        var len = remaining
        let sndBuf = Int(pcb.sndbuf())
        if len > sndBuf { len = sndBuf }
        if len <= 0 { return 0 }

        let slice = Array(data[offset..<(offset + len)])
        let writeErr = slice.withUnsafeBufferPointer { buf -> LWIPError in
            guard let base = buf.baseAddress else { return .outOfMemory }
            return pcb.write(UnsafeRawPointer(base), len: UInt16(len),
                             apiFlags: TCPConstants.writeFlagCopy)
        }
        if writeErr == .ok {
            offset += len
            remaining -= len
            if remaining > 0 {
                return bdhSomeDataSent
            }
            return bdhAllDataSent
        }
        return 0
    }

    /// Drive the body data handler. Called repeatedly from sent/poll callbacks.
    private static func smtpSendBodyDataHandler(session: SMTPSession, pcb: AltcpControlBlock,
                                                 bdh: SMTPBodyDHContext) {
        var res = 0
        var ret = 0

        // Resume any leftover data from a previous partial write
        if let residual = session.bdhResidual, session.bdhResidualOffset < residual.count {
            var off = session.bdhResidualOffset
            var rem = residual.count - off
            res = smtpSendBodyHData(pcb: pcb, data: residual, offset: &off, remaining: &rem)
            session.bdhResidualOffset = off
            if res != bdhAllDataSent {
                return
            }
            session.bdhResidual = nil
            session.bdhResidualOffset = 0
        }
        ret = res

        // Call the user callback to generate more data
        if bdh.handlerState == .sending {
            repeat {
                ret |= res
                bdh.exposed.length = 0
                let result = bdh.callbackFn(bdh.exposed)
                if result == .done {
                    bdh.handlerState = .stop
                }
                let dataLen = Int(bdh.exposed.length)
                if dataLen > 0 {
                    let data = Array(bdh.exposed.buffer.prefix(dataLen))
                    var off = 0
                    var rem = dataLen
                    res = smtpSendBodyHData(pcb: pcb, data: data, offset: &off, remaining: &rem)
                    if res != bdhAllDataSent {
                        // Partial write; save residual for next callback
                        session.bdhResidual = data
                        session.bdhResidualOffset = off
                        session.timer = SMTPConfig.timeoutDataBlock
                        return
                    }
                } else {
                    res = bdhAllDataSent
                }
            } while bdh.handlerState == .sending && res == bdhAllDataSent && bdh.exposed.length > 0

            session.timer = SMTPConfig.timeoutDataBlock
        }

        // Check if done
        if bdh.handlerState != .sending && ret != bdhSomeDataSent {
            // All data has been sent; write body terminator
            let terminator: [UInt8] = Array("\r\n.\r\n".utf8)
            let termErr = terminator.withUnsafeBufferPointer { buf -> LWIPError in
                guard let base = buf.baseAddress else { return .outOfMemory }
                return pcb.write(UnsafeRawPointer(base), len: UInt16(terminator.count),
                                 apiFlags: TCPConstants.writeFlagCopy)
            }
            if termErr == .ok {
                pcb.output()
                session.timer = SMTPConfig.timeoutDataTermination
                session.state = .quit
            }
        }
    }

    // MARK: - Data Verification

    /// Verify that a string conforms to SMTP rules (7-bit ASCII, proper line endings).
    private static func verifyData(_ data: String, linebreaksAllowed: Bool = false) -> LWIPError {
        var lastWasCR = false
        for byte in data.utf8 {
            if (byte & 0x80) != 0 {
                return .invalidArgument
            }
            if byte == 0x0D { // CR
                if !linebreaksAllowed { return .invalidArgument }
                if lastWasCR { return .invalidArgument }
                lastWasCR = true
            } else {
                if byte == 0x0A { // LF
                    if !lastWasCR { return .invalidArgument }
                }
                lastWasCR = false
            }
        }
        return .ok
    }

    // MARK: - Pbuf Helpers

    /// Check if the session's receive pbuf contains a given ASCII needle.
    private static func smtpPbufContains(session: SMTPSession, needle: String) -> Bool {
        guard let p = session.receivedPbuf else { return false }
        return needle.withCString { cstr -> Bool in
            return p.strstr(cstr) != 0xFFFF
        }
    }

    // MARK: - Base64 Encoding

    /// Encode binary data to Base64 string.
    static func base64Encode(_ data: [UInt8]) -> String {
        let base64Chars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        var result = ""
        result.reserveCapacity(((data.count + 2) / 3) * 4)

        var i = 0
        while i < data.count {
            let b0 = data[i]
            let b1 = (i + 1 < data.count) ? data[i + 1] : 0
            let b2 = (i + 2 < data.count) ? data[i + 2] : 0

            result.append(base64Chars[Int(b0 >> 2)])
            result.append(base64Chars[Int((b0 & 0x03) << 4 | b1 >> 4)])

            if i + 1 < data.count {
                result.append(base64Chars[Int((b1 & 0x0F) << 2 | b2 >> 6)])
            } else {
                result.append("=")
            }

            if i + 2 < data.count {
                result.append(base64Chars[Int(b2 & 0x3F)])
            } else {
                result.append("=")
            }

            i += 3
        }

        return result
    }
}
