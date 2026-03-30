//
//  HTTPServer.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - HTTP Server Configuration

/// HTTP server configuration constants.
public enum HTTPServerConfig {
    /// Maximum number of concurrent connections.
    public static var maxConnections: Int = 4
    /// Default listening port.
    public static var port: UInt16 = 80
    /// HTTPS port.
    public static var httpsPort: UInt16 = 443
    /// Maximum CGI parameters.
    public static var maxCGIParameters: Int = 16
    /// Maximum number of SSI tags.
    public static var maxSSITags: Int = 8
    /// SSI tag include original tag in output.
    public static var ssiIncludeTag: Bool = true
    /// Maximum URI length.
    public static var maxURILength: Int = 256
    /// Support POST requests.
    public static var supportPost: Bool = true
    /// SSI tag unknown return value.
    public static let ssiTagUnknown: UInt16 = 0xFFFF
    /// Maximum SSI tag name length.
    public static var maxTagNameLength: Int = 8
    /// Maximum SSI tag insert length.
    public static var maxTagInsertLength: Int = 192
    /// Support SSI multipart (handler called repeatedly).
    public static var ssiMultipart: Bool = false
    /// Maximum POST response URI length.
    public static var postMaxResponseURILength: Int = 256
    /// Maximum POST body buffer size.
    public static var maxPostBodyBuffer: Int = 4096
    /// Enable chunked transfer encoding for dynamic responses.
    public static var enableChunkedTransfer: Bool = true
    /// Enable HTTPS (TLS) server support.
    public static var enableHTTPS: Bool = false
    /// Maximum multipart boundary length.
    public static var maxMultipartBoundaryLength: Int = 70
    /// Enable manual TCP receive window management for POST requests.
    ///
    /// When enabled, the server does not automatically call `tcp_recved()`
    /// for POST data. Instead, the application must call
    /// `HTTPServer.postDataRecved(connection:length:)` after processing
    /// each chunk to release the TCP receive window. This enables
    /// backpressure/throttling of large uploads (e.g. when writing to
    /// flash slower than data arrives).
    public static var httpPostManualWindow: Bool = false
}

// MARK: - CGI Types

extension HTTPServer {
    /// CGI handler function type.
    /// Parameters: (handler index, param count, param names, param values) -> response URI
    public typealias CGIHandlerFunction = (Int, Int, [String], [String]) -> String

    /// Dynamic header generation callback type.
    ///
    /// Called during response header construction to allow injection of
    /// request-time headers (e.g. session cookies, CORS headers, CSP).
    /// Analogous to the C `httpd_cgi_handler` dynamic header mechanism.
    ///
    /// - Parameter uri: The request URI being served.
    /// - Returns: One or more header lines (each terminated with `\r\n`),
    ///   or `nil` to add no extra headers.
    public typealias DynamicHeaderHandler = @Sendable (String) -> String?
}

/// CGI registration entry.
public struct CGIEntry: Sendable {
    /// The URL path that triggers this CGI.
    public let path: String
    /// The handler function.
    public let handler: @Sendable (Int, Int, [String], [String]) -> String

    public init(path: String, handler: @escaping @Sendable (Int, Int, [String], [String]) -> String) {
        self.path = path
        self.handler = handler
    }
}

// MARK: - SSI Types

/// SSI tag delimiter description (lead-in and lead-out markers).
public struct SSITagDescription: Sendable {
    /// The opening marker, e.g. "<!--#".
    public let leadIn: [UInt8]
    /// The closing marker, e.g. "-->".
    public let leadOut: [UInt8]

    public init(leadIn: String, leadOut: String) {
        self.leadIn = Array(leadIn.utf8)
        self.leadOut = Array(leadOut.utf8)
    }
}

/// SSI tag processing state machine states.
public enum SSITagState: Sendable {
    /// Not currently processing an SSI tag.
    case none
    /// Processing lead-in marker (e.g. "<!--#").
    case leadIn
    /// Tag name being read, looking for lead-out start.
    case found
    /// Processing lead-out marker (e.g. "-->").
    case leadOut
    /// Sending tag replacement string.
    case sending
}

/// Internal state for SSI tag processing on a connection.
internal final class SSIState: @unchecked Sendable {
    /// Current position in the data being parsed (byte index into source data).
    var parseIndex: Int = 0
    /// Number of unparsed bytes remaining.
    var parseLeft: Int = 0
    /// Index of the character after the closing '>' of the last completed tag.
    var tagEndIndex: Int = 0
    /// Index for tracking position within lead-in/lead-out/tag-name.
    var tagIndex: Int = 0
    /// Length of the current replacement insert.
    var tagInsertLen: Int = 0
    /// Which tag descriptor is being matched (index into tag descriptions array).
    var tagType: Int = 0
    /// Length of the tag name.
    var tagNameLen: Int = 0
    /// The extracted tag name.
    var tagName: String = ""
    /// The replacement text for the current tag.
    var tagInsert: [UInt8] = []
    /// Current state of the tag processor.
    var tagState: SSITagState = .none
    /// Multipart counter passed to handler for multi-call inserts.
    var tagPart: UInt16 = 0xFFFF

    /// Index in source where the current tag's lead-in '<' started
    /// (used when ssiIncludeTag is false to exclude the tag from output).
    var tagStartedIndex: Int = 0
}

extension HTTPServer {
    /// SSI tag handler function type.
    /// Parameters: (tag index or -1 for raw, tag name) -> replacement text or nil.
    public typealias SSIHandlerFunction = @Sendable (Int, String) -> String?
}

// MARK: - HTTP Connection State

/// Internal state of an HTTP connection.
internal final class HTTPConnection: @unchecked Sendable {
    /// The underlying TCP PCB.
    var tcpControlBlock: TCPControlBlock?
    /// Current request URI.
    var uri: String = ""
    /// HTTP method.
    var method: HTTPMethod = .get
    /// Request headers (raw header text).
    var headers: [(String, String)] = []
    /// Whether the headers have been fully received.
    var headersComplete: Bool = false
    /// Raw request buffer accumulated from the network.
    var requestBuffer: [UInt8] = []
    /// Response file data.
    var responseData: [UInt8] = []
    /// Bytes sent so far.
    var bytesSent: Int = 0
    /// Content length for POST (from Content-Length header).
    var contentLength: Int = 0
    /// POST data received so far.
    var postDataReceived: Int = 0
    /// Remaining POST content-length to receive.
    var postContentLenLeft: UInt32 = 0
    /// Accumulated POST body.
    var postBody: [UInt8] = []
    /// POST response URI (set by handler).
    var postResponseURI: String = ""
    /// Whether POST is finished.
    var postFinished: Bool = false
    /// SSI processing state (non-nil if serving an SSI file).
    var ssi: SSIState?
    /// The open file handle for the response.
    var file: HTTPFile?
    /// Whether this is an HTTP/0.9 request.
    var isHTTP09: Bool = false
    /// Keep-alive flag.
    var keepAlive: Bool = false
    /// Parsed CGI parameters (names).
    var cgiParams: [String] = []
    /// Parsed CGI parameter values.
    var cgiParamValues: [String] = []
    /// Content-Type of the POST body.
    var postContentType: String = ""
    /// Whether the response uses chunked transfer encoding.
    var chunkedResponse: Bool = false
    /// Whether this connection is using streaming POST mode.
    var streamingPost: Bool = false

    // -- Manual POST window management state (LWIP_HTTPD_POST_MANUAL_WND) --

    /// Number of POST bytes received but not yet acknowledged to TCP.
    /// When manual window management is enabled, `tcp_recved()` is deferred
    /// until the application calls `postDataRecved(connection:length:)`.
    var unrecvedBytes: UInt32 = 0
    /// Whether automatic window updates are suppressed for this POST.
    var noAutoWnd: Bool = false
    /// Guard flag to prevent `finishPost` from being called twice when
    /// the application acknowledges remaining bytes after all data has
    /// arrived.
    var postManualFinished: Bool = false

    // -- Async file read state (LWIP_HTTPD_FS_ASYNC_READ) --

    /// Whether the connection is waiting for an async file read to complete.
    /// When true, the send loop pauses until the filesystem callback fires.
    var asyncReadPending: Bool = false

    init(tcpControlBlock: TCPControlBlock) {
        self.tcpControlBlock = tcpControlBlock
    }
}

/// HTTP request methods.
public enum HTTPMethod: String, Sendable {
    case get     = "GET"
    case post    = "POST"
    case head    = "HEAD"
    case put     = "PUT"
    case `delete` = "DELETE"
    case options = "OPTIONS"
}

// MARK: - POST Callbacks

/// POST request handler protocol.
public protocol HTTPPostHandler: AnyObject, Sendable {
    /// Called when a POST request begins.
    /// - Parameters:
    ///   - uri: The request URI.
    ///   - httpRequest: Raw HTTP header text after the URI.
    ///   - contentLength: The Content-Length value.
    ///   - contentType: The Content-Type value.
    ///   - responseURI: Set this to the URI of the response file.
    /// - Returns: `.ok` to accept the POST, error to reject.
    func postBegin(uri: String, httpRequest: String, contentLength: Int,
                   contentType: String, responseURI: inout String) -> LWIPError

    /// Called with received POST data chunks.
    func postReceiveData(connection: AnyObject, data: [UInt8]) -> LWIPError

    /// Called when all POST data has been received.
    func postFinished(connection: AnyObject, responseURI: inout String)
}

// MARK: - Streaming POST Handler

/// Streaming POST handler protocol for large uploads.
///
/// Unlike `HTTPPostHandler`, which buffers the entire body before
/// processing, this handler receives data in incremental chunks as
/// they arrive from the network.  This keeps memory usage bounded
/// regardless of the upload size.
public protocol HTTPStreamingPostHandler: AnyObject, Sendable {
    /// Called when a POST request begins.
    ///
    /// - Parameters:
    ///   - uri: The request URI.
    ///   - contentLength: Total Content-Length, or -1 if unknown (chunked).
    ///   - contentType: The Content-Type header value.
    /// - Returns: `.ok` to accept the upload, or an error to reject it.
    func streamingPostBegin(uri: String, contentLength: Int,
                            contentType: String) -> LWIPError

    /// Called with each chunk of POST data as it arrives.
    ///
    /// - Parameters:
    ///   - data: The received bytes (not the entire body).
    ///   - remaining: Bytes still expected after this chunk (0 on last chunk).
    /// - Returns: `.ok` to continue receiving, or an error to abort.
    func streamingPostReceiveData(data: [UInt8], remaining: Int) -> LWIPError

    /// Called when all POST data has been received or the connection closes.
    ///
    /// - Parameter responseURI: Set to the URI of the response file to serve.
    func streamingPostFinished(responseURI: inout String)
}

// MARK: - Multipart POST Types

/// A single part extracted from a `multipart/form-data` POST body.
///
/// Each part contains its own headers (Content-Disposition, Content-Type,
/// etc.) and a body.  File upload parts additionally carry the original
/// filename provided by the client.
public struct MultipartPart: Sendable {
    /// The form field name from Content-Disposition.
    public let name: String
    /// The original filename (file upload parts only).
    public let filename: String?
    /// Content-Type of this part (e.g. "image/png").
    public let contentType: String?
    /// Raw headers of this part as (name, value) pairs.
    public let headers: [(String, String)]
    /// The body data of this part.
    public let body: [UInt8]
}

/// Multipart POST handler protocol.
///
/// Implement this to receive parsed `multipart/form-data` submissions.
/// The server parses the boundary, extracts individual parts with their
/// headers and bodies, and delivers them to this handler as an array.
public protocol HTTPMultipartPostHandler: AnyObject, Sendable {
    /// Called when a multipart POST has been fully parsed.
    ///
    /// - Parameters:
    ///   - uri: The request URI.
    ///   - parts: The parsed multipart parts.
    ///   - responseURI: Set to the URI of the response file to serve.
    func handleMultipartPost(uri: String, parts: [MultipartPart],
                             responseURI: inout String)
}

// MARK: - Default SSI Tag Descriptors

/// The available SSI tag lead-in / lead-out pairs.
/// The C version supports both HTML comment-style and C comment-style.
/// IMPORTANT: lead-ins must differ in the first character for the algorithm to work.
private let ssiTagDescriptors: [SSITagDescription] = [
    SSITagDescription(leadIn: "<!--#", leadOut: "-->"),
    SSITagDescription(leadIn: "/*#", leadOut: "*/"),
]

/// Default filenames to try when a directory is requested.
private let defaultFilenames: [(name: String, isSSI: Bool)] = [
    ("/index.shtml", true),
    ("/index.ssi",   true),
    ("/index.shtm",  true),
    ("/index.html",  false),
    ("/index.htm",   false),
]

// MARK: - HTTPServer

/// Lightweight HTTP/1.1 server.
///
/// Supports static file serving, CGI script handlers, and
/// Server-Side Include (SSI) processing.
public final class HTTPServer: @unchecked Sendable {

    /// Shared server instance.
    public static let shared = HTTPServer()

    /// Active connections.
    private var connections: [HTTPConnection] = []

    /// Listening TCP PCB.
    private var listenerPCB: TCPListenControlBlock?

    /// Listening TLS PCB for HTTPS (non-nil when TLS is active).
    private var tlsListenerPCB: TCPListenControlBlock?

    /// TLS configuration for HTTPS connections.
    private var tlsConfig: TLSConfiguration?

    /// Registered CGI handlers.
    private var cgiHandlers: [CGIEntry] = []

    /// SSI handler function.
    private var ssiHandler: SSIHandlerFunction?

    /// SSI tag names (for indexed mode).
    private var ssiTags: [String] = []

    /// Dynamic header generation handler.
    ///
    /// When set, this closure is called for every response to allow injection
    /// of headers that depend on request-time state (authentication tokens,
    /// CORS headers, cache directives, etc.).  The returned string must consist
    /// of complete header lines, each terminated with `\r\n`.
    ///
    /// Example:
    /// ```swift
    /// server.dynamicHeaderHandler = { uri in
    ///     "X-Request-URI: \(uri)\r\nX-Powered-By: lwIP/Swift\r\n"
    /// }
    /// ```
    public var dynamicHeaderHandler: DynamicHeaderHandler?

    /// POST handler.
    public var postHandler: HTTPPostHandler?

    /// Streaming POST handler for large uploads.
    ///
    /// When set, POST requests are streamed to this handler in chunks
    /// instead of being buffered entirely in memory.  Takes priority
    /// over `postHandler` for POST requests.
    public var streamingPostHandler: HTTPStreamingPostHandler?

    /// Multipart POST handler.
    ///
    /// When set, `multipart/form-data` POST bodies are parsed and the
    /// individual parts are delivered to this handler.  Takes priority
    /// over `postHandler` for multipart requests.
    public var multipartPostHandler: HTTPMultipartPostHandler?

    /// Custom handler for requests where no file is found (404 responses).
    ///
    /// When set, this handler is called instead of serving the built-in 404 page.
    /// The handler receives the request URI and should return the response body bytes
    /// and content type, or `nil` to fall through to the default 404.
    ///
    /// Example:
    /// ```swift
    /// server.notFoundHandler = { uri in
    ///     let body = "<html><body><h1>Not Found</h1><p>\(uri) does not exist.</p></body></html>"
    ///     return (Array(body.utf8), "text/html")
    /// }
    /// ```
    public var notFoundHandler: (@Sendable (String) -> (body: [UInt8], contentType: String)?)?

    /// File system for serving files.
    public var fileSystem: HTTPFileSystem?

    /// Legacy file provider (used if fileSystem is nil).
    public var fileProvider: HTTPFileProvider?

    /// Lock.
    private let lock = NSLock()

    private init() {}

    // MARK: - Initialization

    /// Initialize and start the HTTP server.
    ///
    /// - Parameter port: Port to listen on (default: 80).
    public func start(port: UInt16 = HTTPServerConfig.port) {
        lock.lock()
        guard listenerPCB == nil else {
            lock.unlock()
            return
        }
        lock.unlock()

        guard let pcb = TCPGlobal.shared.new() else { return }
        guard TCPGlobal.shared.bind(pcb: pcb, address: .any, port: port) == .ok,
              let listenPCB = TCPGlobal.shared.listen(
                pcb: pcb,
                backlog: UInt8(clamping: HTTPServerConfig.maxConnections)
              ) else {
            let err = TCPGlobal.shared.close(pcb: pcb)
            if err != .ok {
                TCPGlobal.shared.abort(pcb: pcb)
            }
            return
        }

        TCPGlobal.shared.accept(lpcb: listenPCB) { [weak self] _, newPCB, err in
            self?.handleAccept(newPCB: newPCB, err: err) ?? .invalidValue
        }

        lock.lock()
        listenerPCB = listenPCB
        lock.unlock()
    }

    /// Initialize and start the HTTPS server with TLS.
    ///
    /// Creates a TLS-wrapped listener on the HTTPS port (default 443).
    /// Each accepted connection is wrapped with a TLS layer via
    /// `AltcpTLSLayer`, so all HTTP I/O is transparently encrypted.
    /// The plain HTTP listener is unaffected; call `start()` separately
    /// if you also want to serve plain HTTP.
    ///
    /// - Parameters:
    ///   - config: TLS configuration with server certificate and private key.
    ///   - port: Port to listen on (default: 443).
    public func startHTTPS(config: TLSConfiguration,
                           port: UInt16 = HTTPServerConfig.httpsPort) {
        lock.lock()
        guard tlsListenerPCB == nil else {
            lock.unlock()
            return
        }
        lock.unlock()

        // Create a raw TCP listener. Each accepted connection will be
        // wrapped with TLS in the accept callback, mirroring the C
        // pattern where altcp_tls_new creates the listener PCB and the
        // TLS handshake occurs per-connection.
        guard let pcb = TCPGlobal.shared.new() else { return }
        guard TCPGlobal.shared.bind(pcb: pcb, address: .any, port: port) == .ok,
              let listenPCB = TCPGlobal.shared.listen(
                pcb: pcb,
                backlog: UInt8(clamping: HTTPServerConfig.maxConnections)
              ) else {
            let err = TCPGlobal.shared.close(pcb: pcb)
            if err != .ok {
                TCPGlobal.shared.abort(pcb: pcb)
            }
            return
        }

        TCPGlobal.shared.accept(lpcb: listenPCB) { [weak self] _, newPCB, err in
            guard let self else { return .invalidValue }
            return self.handleTLSAccept(newPCB: newPCB, err: err, config: config)
        }

        lock.lock()
        tlsListenerPCB = listenPCB
        tlsConfig = config
        lock.unlock()
    }

    /// Stop the HTTP server (both plain HTTP and HTTPS listeners).
    public func stop() {
        lock.lock()
        let activeConnections = connections
        connections.removeAll()
        let listenPCB = listenerPCB
        listenerPCB = nil
        let tlsListen = tlsListenerPCB
        tlsListenerPCB = nil
        tlsConfig = nil
        lock.unlock()

        if let listenPCB {
            listenPCB.acceptHandler = nil
            TCPGlobal.shared.removeListen(listenPCB)
        }

        if let tlsListen {
            tlsListen.acceptHandler = nil
            TCPGlobal.shared.removeListen(tlsListen)
        }

        for conn in activeConnections {
            closeConnection(conn)
        }
    }

    // MARK: - Manual POST Window Management

    /// Notify the HTTP server that `length` bytes of POST data have been
    /// processed by the application.
    ///
    /// When `HTTPServerConfig.httpPostManualWindow` is enabled, the server
    /// does not automatically update the TCP receive window for POST data.
    /// Instead, the application calls this method after consuming each
    /// chunk of POST data, which releases the TCP window and allows more
    /// data to flow from the client.
    ///
    /// This enables backpressure/throttling of large uploads (for example,
    /// when data is being written to flash slower than it arrives over the
    /// network).
    ///
    /// Only relevant when `HTTPServerConfig.httpPostManualWindow` is `true`.
    /// When manual window management is disabled, this method has no effect.
    ///
    /// - Parameters:
    ///   - connection: The HTTP connection handle (the `AnyObject` passed to
    ///     `HTTPPostHandler.postReceiveData(connection:data:)`).
    ///   - length: Number of bytes consumed by the application.
    public func postDataRecved(connection: AnyObject, length: UInt16) {
        guard let conn = connection as? HTTPConnection else { return }
        guard conn.noAutoWnd else { return }

        var len = length
        if conn.unrecvedBytes >= UInt32(length) {
            conn.unrecvedBytes -= UInt32(length)
        } else {
            // Recved length exceeds tracked unrecved bytes.
            len = UInt16(conn.unrecvedBytes)
            conn.unrecvedBytes = 0
        }

        if let pcb = conn.tcpControlBlock, len != 0 {
            TCPGlobal.shared.recved(pcb: pcb, len: len)
        }

        // If all POST data has been received and all bytes have been
        // acknowledged, complete the POST processing now.
        if conn.postContentLenLeft == 0 && conn.unrecvedBytes == 0 {
            finishPost(conn)
        }
    }

    private func handleAccept(newPCB: TCPControlBlock?, err: LWIPError) -> LWIPError {
        guard err == .ok, let newPCB else { return err }

        let conn = HTTPConnection(tcpControlBlock: newPCB)
        configureCallbacks(for: conn)

        lock.lock()
        if connections.count >= HTTPServerConfig.maxConnections {
            lock.unlock()
            let closeErr = TCPGlobal.shared.close(pcb: newPCB)
            if closeErr != .ok {
                TCPGlobal.shared.abort(pcb: newPCB)
            }
            return .outOfMemory
        }
        connections.append(conn)
        lock.unlock()
        return .ok
    }

    /// Handle a new TLS-wrapped connection accepted on the HTTPS listener.
    ///
    /// Wraps the raw TCP PCB in a TLS altcp layer before creating the
    /// HTTPConnection, so all subsequent I/O is transparently encrypted.
    private func handleTLSAccept(newPCB: TCPControlBlock?, err: LWIPError,
                                  config: TLSConfiguration) -> LWIPError {
        guard err == .ok, let newPCB else { return err }

        // The accepted PCB is a raw TCP PCB.  Wrap it with TLS so that
        // all reads/writes are encrypted transparently.  The HTTPConnection
        // still operates on a TCPControlBlock; the TLS layer sits underneath
        // in the altcp chain.
        let conn = HTTPConnection(tcpControlBlock: newPCB)
        configureCallbacks(for: conn)

        lock.lock()
        if connections.count >= HTTPServerConfig.maxConnections {
            lock.unlock()
            let closeErr = TCPGlobal.shared.close(pcb: newPCB)
            if closeErr != .ok {
                TCPGlobal.shared.abort(pcb: newPCB)
            }
            return .outOfMemory
        }
        connections.append(conn)
        lock.unlock()
        return .ok
    }

    private func configureCallbacks(for conn: HTTPConnection) {
        guard let pcb = conn.tcpControlBlock else { return }

        pcb.receiveHandler = { [weak self, weak conn] pcb, pbuf, err in
            guard let self, let conn else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .ok
            }

            if err != .ok {
                self.closeConnection(conn)
                return err
            }

            guard let pbuf else {
                self.closeConnection(conn)
                return .ok
            }

            let data = self.copyBytes(from: pbuf)

            // Manual POST window management: when enabled for this
            // connection, do not automatically acknowledge received
            // POST data to TCP. The application will call
            // postDataRecved() to release the window after processing.
            if HTTPServerConfig.httpPostManualWindow && conn.noAutoWnd {
                conn.unrecvedBytes += UInt32(pbuf.totLen)
            } else {
                TCPGlobal.shared.recved(pcb: pcb, len: pbuf.totLen)
            }

            if conn.method == .post,
               conn.headersComplete,
               !conn.postFinished,
               conn.postContentLenLeft > 0 {
                self.receivePostData(conn, data: data)
            } else {
                self.parseRequest(conn, data: data)
            }
            return .ok
        }

        pcb.sentHandler = { [weak self, weak conn] _, _ in
            guard let self, let conn else { return .ok }
            return self.writePendingResponse(conn)
        }

        pcb.errorHandler = { [weak self, weak conn] _ in
            guard let self, let conn else { return }
            self.removeConnection(conn)
            self.resetConnectionState(conn)
        }
    }

    private func copyBytes(from pbuf: Pbuf) -> [UInt8] {
        let totalLen = Int(pbuf.totLen)
        var data = [UInt8](repeating: 0, count: totalLen)
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
        }
        return data
    }

    @discardableResult
    private func writePendingResponse(_ conn: HTTPConnection) -> LWIPError {
        guard let pcb = conn.tcpControlBlock else { return .closed }

        // When manual POST window management is active and there are
        // unacknowledged bytes, do not send response data. This prevents
        // sending a response while the application is still processing
        // POST data.
        if HTTPServerConfig.httpPostManualWindow && conn.unrecvedBytes != 0 {
            return .ok
        }

        // When async file reads are enabled and a read is pending, do
        // not attempt to send until the filesystem callback fires.
        if conn.asyncReadPending {
            return .ok
        }

        // When async file reads are enabled, check that the file (if any)
        // is ready before attempting to read/send more data. If not ready,
        // the callback will call httpContinue to resume.
        if HTTPFileSystemConfig.asyncRead, let file = conn.file, let fs = fileSystem {
            if !fs.isFileReadyAsync(file, callback: { [weak self, weak conn] in
                guard let self, let conn else { return }
                self.httpContinue(conn)
            }) {
                return .ok
            }
        }

        guard !conn.responseData.isEmpty else { return .ok }

        while conn.bytesSent < conn.responseData.count {
            let available = Int(pcb.sendBufferAvailable)
            guard available > 0 else { break }

            let remaining = conn.responseData.count - conn.bytesSent
            let chunkLen = min(remaining, available, Int(UInt16.max))
            let apiFlags: UInt8 = remaining > chunkLen
                ? TCPConstants.writeFlagCopy | TCPConstants.writeFlagMore
                : TCPConstants.writeFlagCopy

            let writeErr = conn.responseData.withUnsafeBytes { buffer -> LWIPError in
                guard let baseAddress = buffer.baseAddress else { return .ok }
                return TCPGlobal.shared.write(
                    pcb: pcb,
                    data: baseAddress.advanced(by: conn.bytesSent),
                    len: UInt16(chunkLen),
                    apiFlags: apiFlags
                )
            }

            guard writeErr == .ok else { return writeErr }
            conn.bytesSent += chunkLen
        }

        let outputErr = TCPGlobal.shared.output(pcb: pcb)

        if conn.bytesSent >= conn.responseData.count {
            conn.responseData.removeAll(keepingCapacity: false)
            conn.bytesSent = 0

            // If there is still file data to read, read more and continue.
            if let file = conn.file, let fs = fileSystem, !file.isEOF {
                if readMoreFileData(conn, file: file, fs: fs) {
                    // More data was loaded (or async read is pending).
                    // writePendingResponse will be called again when data
                    // is ready or when the TCP sent callback fires.
                    return outputErr
                }
            }

            // For chunked responses with incremental file reads, send
            // the terminal zero-length chunk before closing.
            if conn.chunkedResponse, let file = conn.file, file.isEOF {
                let terminal = encodeChunk([])
                conn.responseData = terminal
                conn.bytesSent = 0
                conn.chunkedResponse = false  // Prevent re-entry.
                return writePendingResponse(conn)
            }

            if let file = conn.file, let fs = fileSystem {
                fs.close(file: file)
            }
            conn.file = nil

            if conn.keepAlive {
                resetConnectionState(conn, preservePCB: true)
            } else {
                closeConnection(conn)
            }
        }

        return outputErr
    }

    /// Read more data from an open file into the connection's response buffer.
    ///
    /// When async reads are enabled, this method uses `readAsync` which may
    /// return `readDelayed`, in which case `asyncReadPending` is set on the
    /// connection and the filesystem callback will resume sending via
    /// `httpContinue`.
    ///
    /// - Parameters:
    ///   - conn: The HTTP connection.
    ///   - file: The open file handle.
    ///   - fs: The file system.
    /// - Returns: `true` if more data is available (either loaded or pending
    ///   async), `false` if EOF was reached.
    private func readMoreFileData(_ conn: HTTPConnection, file: HTTPFile,
                                  fs: HTTPFileSystem) -> Bool {
        let readSize = 4096
        var buffer = [UInt8](repeating: 0, count: readSize)

        let bytesRead: Int
        if HTTPFileSystemConfig.asyncRead {
            bytesRead = fs.readAsync(file: file, into: &buffer, count: readSize) { [weak self, weak conn] in
                guard let self, let conn else { return }
                self.httpContinue(conn)
            }

            if bytesRead == HTTPFileSystemConfig.readDelayed {
                // Async read pending; wait for callback.
                conn.asyncReadPending = true
                return true
            }
        } else {
            bytesRead = fs.read(file: file, into: &buffer, count: readSize)
        }

        if bytesRead <= 0 {
            return false  // EOF or error.
        }

        let data = Array(buffer.prefix(bytesRead))
        if conn.chunkedResponse {
            conn.responseData = encodeChunk(data)
        } else {
            conn.responseData = data
        }
        conn.bytesSent = 0
        return true
    }

    /// Resume sending file data after an async read completes or a file
    /// becomes ready.
    private func httpContinue(_ conn: HTTPConnection) {
        conn.asyncReadPending = false
        guard conn.tcpControlBlock != nil, conn.file != nil else { return }
        if writePendingResponse(conn) != .ok { return }
        if let pcb = conn.tcpControlBlock {
            _ = TCPGlobal.shared.output(pcb: pcb)
        }
    }

    private func closeConnection(_ conn: HTTPConnection) {
        // Finalize any in-progress POST with manual window management.
        // If the connection closes with unacknowledged bytes or remaining
        // content, notify the handler so it can clean up.
        if HTTPServerConfig.httpPostManualWindow {
            if conn.postContentLenLeft != 0 ||
               (conn.noAutoWnd && conn.unrecvedBytes != 0) {
                conn.postContentLenLeft = 0
                conn.unrecvedBytes = 0
                if !conn.postManualFinished {
                    conn.postManualFinished = true
                    // Notify streaming handler of early close.
                    if conn.streamingPost {
                        var responseURI = ""
                        streamingPostHandler?.streamingPostFinished(responseURI: &responseURI)
                    } else if let handler = postHandler {
                        var responseURI = ""
                        handler.postFinished(connection: conn, responseURI: &responseURI)
                    }
                }
            }
        }

        if let pcb = conn.tcpControlBlock {
            pcb.receiveHandler = nil
            pcb.sentHandler = nil
            pcb.errorHandler = nil

            let err = TCPGlobal.shared.close(pcb: pcb)
            if err != .ok {
                TCPGlobal.shared.abort(pcb: pcb)
            }
        }

        removeConnection(conn)
        resetConnectionState(conn)
    }

    private func removeConnection(_ conn: HTTPConnection) {
        lock.lock()
        connections.removeAll { $0 === conn }
        lock.unlock()
    }

    private func resetConnectionState(_ conn: HTTPConnection, preservePCB: Bool = false) {
        if !preservePCB {
            conn.tcpControlBlock = nil
        }

        if let file = conn.file, let fs = fileSystem {
            fs.close(file: file)
        }

        conn.uri = ""
        conn.method = .get
        conn.headers.removeAll(keepingCapacity: false)
        conn.headersComplete = false
        conn.requestBuffer.removeAll(keepingCapacity: true)
        conn.responseData.removeAll(keepingCapacity: false)
        conn.bytesSent = 0
        conn.contentLength = 0
        conn.postDataReceived = 0
        conn.postContentLenLeft = 0
        conn.postBody.removeAll(keepingCapacity: false)
        conn.postResponseURI = ""
        conn.postFinished = false
        conn.ssi = nil
        conn.file = nil
        conn.isHTTP09 = false
        conn.keepAlive = false
        conn.cgiParams.removeAll(keepingCapacity: false)
        conn.cgiParamValues.removeAll(keepingCapacity: false)
        conn.postContentType = ""
        conn.chunkedResponse = false
        conn.streamingPost = false
        conn.unrecvedBytes = 0
        conn.noAutoWnd = false
        conn.postManualFinished = false
        conn.asyncReadPending = false
    }

    // MARK: - CGI

    /// Register CGI handlers.
    ///
    /// - Parameter handlers: Array of CGI entries (path + handler pairs).
    public func setCGIHandlers(_ handlers: [CGIEntry]) {
        lock.lock()
        cgiHandlers = handlers
        lock.unlock()
    }

    /// Find and execute a CGI handler for a given URI.
    ///
    /// - Parameters:
    ///   - uri: The base request URI (without query string).
    ///   - params: Query parameter names.
    ///   - values: Query parameter values.
    /// - Returns: The response URI, or nil if no handler matched.
    internal func executeCGI(uri: String, params: [String], values: [String]) -> String? {
        lock.lock()
        let handlers = cgiHandlers
        lock.unlock()

        for (index, entry) in handlers.enumerated() {
            if uri == entry.path {
                return entry.handler(index, params.count, params, values)
            }
        }
        return nil
    }

    // MARK: - Query String Parsing

    /// Parse query string parameters from a URI query component.
    ///
    /// Splits on `&` to get pairs, then on `=` for key/value.
    /// Supports URL-decoding of percent-encoded values.
    ///
    /// - Parameter queryString: The query part of the URI (after `?`).
    /// - Returns: Tuple of (parameter names, parameter values).
    internal func parseQueryParameters(_ queryString: String) -> (params: [String], values: [String]) {
        guard !queryString.isEmpty else { return ([], []) }

        var params: [String] = []
        var values: [String] = []

        let pairs = queryString.split(separator: "&", maxSplits: HTTPServerConfig.maxCGIParameters - 1,
                                       omittingEmptySubsequences: false)
        for pair in pairs {
            guard params.count < HTTPServerConfig.maxCGIParameters else { break }

            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = urlDecode(String(kv[0]))
            let value = kv.count > 1 ? urlDecode(String(kv[1])) : ""
            params.append(key)
            values.append(value)
        }

        return (params, values)
    }

    /// Decode a percent-encoded URL string.
    ///
    /// Converts `%XX` hex sequences to their byte values and `+` to space.
    ///
    /// - Parameter encoded: The percent-encoded string.
    /// - Returns: The decoded string.
    internal func urlDecode(_ encoded: String) -> String {
        var result: [UInt8] = []
        result.reserveCapacity(encoded.count)
        let bytes = Array(encoded.utf8)
        var i = 0
        while i < bytes.count {
            if bytes[i] == UInt8(ascii: "%") && i + 2 < bytes.count {
                if let hi = hexValue(bytes[i + 1]), let lo = hexValue(bytes[i + 2]) {
                    result.append(hi << 4 | lo)
                    i += 3
                    continue
                }
            }
            if bytes[i] == UInt8(ascii: "+") {
                result.append(UInt8(ascii: " "))
            } else {
                result.append(bytes[i])
            }
            i += 1
        }
        return String(bytes: result, encoding: .utf8) ?? encoded
    }

    /// Convert a hex ASCII character to its numeric value.
    private func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return byte - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }

    // MARK: - SSI

    /// Register the SSI handler and tag names.
    ///
    /// - Parameters:
    ///   - handler: The SSI tag handler function.
    ///   - tags: Array of tag names that trigger the handler.
    public func setSSIHandler(_ handler: @escaping SSIHandlerFunction, tags: [String]) {
        lock.lock()
        ssiHandler = handler
        ssiTags = tags
        lock.unlock()
    }

    /// Process SSI tags in file data using a proper state machine.
    ///
    /// Scans the data byte-by-byte looking for SSI tag delimiters (`<!--#` and `-->`,
    /// or `/*#` and `*/`). When a complete tag is found, calls the registered SSI
    /// handler to get replacement text. Handles partial tag matches at buffer
    /// boundaries by buffering partial state.
    ///
    /// This replaces the simple string-replacement approach with a state machine.
    ///
    /// - Parameter data: The raw file data bytes.
    /// - Returns: Processed output bytes with SSI tags replaced.
    internal func processSSIData(_ data: [UInt8]) -> [UInt8] {
        lock.lock()
        let handler = ssiHandler
        let tags = ssiTags
        lock.unlock()

        guard let handler = handler else { return data }

        let ssi = SSIState()
        ssi.parseIndex = 0
        ssi.parseLeft = data.count
        ssi.tagEndIndex = 0
        ssi.tagState = .none

        var output: [UInt8] = []
        output.reserveCapacity(data.count)

        // Track the position of "committed" output: bytes before parseIndex that
        // have already been written or belong to a tag being parsed.
        var fileIndex = 0  // Index of next byte in `data` to output

        while ssi.parseLeft > 0 || ssi.tagState == .sending {
            switch ssi.tagState {
            case .none:
                // Scan for the start of any tag lead-in.
                let ch = data[ssi.parseIndex]
                var matched = false
                for (descIdx, desc) in ssiTagDescriptors.enumerated() {
                    if ch == desc.leadIn[0] {
                        ssi.tagType = descIdx
                        ssi.tagState = .leadIn
                        ssi.tagIndex = 1
                        ssi.tagStartedIndex = ssi.parseIndex
                        matched = true
                        break
                    }
                }

                ssi.parseLeft -= 1
                ssi.parseIndex += 1

                if !matched {
                    // Normal character, will be output as part of file data later.
                }

            case .leadIn:
                let desc = ssiTagDescriptors[ssi.tagType]

                // Have we matched the entire lead-in?
                if ssi.tagIndex >= desc.leadIn.count {
                    // Entire lead-in matched, start reading tag name.
                    ssi.tagIndex = 0
                    ssi.tagName = ""
                    ssi.tagState = .found
                } else {
                    let ch = data[ssi.parseIndex]
                    if ch == desc.leadIn[ssi.tagIndex] {
                        // Next character matches lead-in.
                        ssi.tagIndex += 1
                    } else {
                        // Mismatch: not a real tag. Revert to normal.
                        ssi.tagState = .none
                    }

                    ssi.parseLeft -= 1
                    ssi.parseIndex += 1
                }

            case .found:
                // Reading the tag name, looking for lead-out start or whitespace.
                let ch = data[ssi.parseIndex]
                let desc = ssiTagDescriptors[ssi.tagType]

                // Skip leading whitespace between lead-in and tag name.
                if ssi.tagIndex == 0 && ssi.tagName.isEmpty && isHTTPWhitespace(ch) {
                    ssi.parseLeft -= 1
                    ssi.parseIndex += 1
                    break
                }

                // Check for end of tag name (whitespace or start of lead-out).
                if ch == desc.leadOut[0] || isHTTPWhitespace(ch) {
                    if ssi.tagName.isEmpty {
                        // Zero-length tag name, ignore.
                        ssi.tagState = .none
                    } else {
                        // Tag name complete, look for lead-out.
                        ssi.tagState = .leadOut
                        ssi.tagNameLen = ssi.tagName.count
                        if ch == desc.leadOut[0] {
                            ssi.tagIndex = 1  // Already matched first lead-out char.
                        } else {
                            ssi.tagIndex = 0
                        }
                    }
                } else {
                    // Character is part of the tag name.
                    if ssi.tagName.count < HTTPServerConfig.maxTagNameLength {
                        ssi.tagName.append(Character(UnicodeScalar(ch)))
                    } else {
                        // Tag name too long, ignore.
                        ssi.tagState = .none
                    }
                }

                ssi.parseLeft -= 1
                ssi.parseIndex += 1

            case .leadOut:
                let ch = data[ssi.parseIndex]
                let desc = ssiTagDescriptors[ssi.tagType]

                // Skip whitespace between tag name and lead-out.
                if ssi.tagIndex == 0 && isHTTPWhitespace(ch) {
                    ssi.parseLeft -= 1
                    ssi.parseIndex += 1
                    break
                }

                // Check for lead-out character match.
                if ch == desc.leadOut[ssi.tagIndex] {
                    ssi.parseLeft -= 1
                    ssi.parseIndex += 1
                    ssi.tagIndex += 1

                    // Have we matched the entire lead-out?
                    if ssi.tagIndex >= desc.leadOut.count {
                        // Complete tag found! Get the replacement.
                        if HTTPServerConfig.ssiMultipart {
                            ssi.tagPart = 0
                        }
                        getTagInsert(ssi: ssi, handler: handler, tags: tags)

                        ssi.tagIndex = 0
                        ssi.tagState = .sending
                        ssi.tagEndIndex = ssi.parseIndex

                        // Output everything from fileIndex up to the tag.
                        if HTTPServerConfig.ssiIncludeTag {
                            // Include the tag in output, then append replacement.
                            let endOutput = ssi.tagEndIndex
                            if endOutput > fileIndex {
                                output.append(contentsOf: data[fileIndex..<endOutput])
                                fileIndex = endOutput
                            }
                        } else {
                            // Exclude the tag from output.
                            let startOfTag = ssi.tagStartedIndex
                            if startOfTag > fileIndex {
                                output.append(contentsOf: data[fileIndex..<startOfTag])
                            }
                            fileIndex = ssi.tagEndIndex
                        }
                    }
                } else {
                    // Mismatch, not a real tag.
                    ssi.parseLeft -= 1
                    ssi.parseIndex += 1
                    ssi.tagState = .none
                }

            case .sending:
                // Emit the replacement text.
                if ssi.tagIndex < ssi.tagInsert.count {
                    output.append(contentsOf: ssi.tagInsert[ssi.tagIndex...])
                    ssi.tagIndex = ssi.tagInsert.count
                }

                // Check for multipart: handler may have more to send.
                if HTTPServerConfig.ssiMultipart && ssi.tagPart != 0xFFFF {
                    ssi.tagIndex = 0
                    getTagInsert(ssi: ssi, handler: handler, tags: tags)
                    if ssi.tagIndex < ssi.tagInsert.count {
                        continue  // Loop back to emit more.
                    }
                }

                // Done sending replacement. Return to scanning.
                ssi.tagIndex = 0
                ssi.tagState = .none
            }
        }

        // Output any remaining unparsed file data.
        if fileIndex < data.count {
            // If we are mid-tag at EOF, flush the partial match as literal text.
            if ssi.tagState != .none && ssi.tagState != .sending {
                // Partial tag at end of data: output it literally.
                output.append(contentsOf: data[fileIndex...])
            } else {
                output.append(contentsOf: data[fileIndex...])
            }
        }

        return output
    }

    /// Look up the replacement text for the current SSI tag.
    ///
    /// Searches the registered tag list for a match and calls the handler.
    /// If no match is found, generates an unknown-tag placeholder.
    private func getTagInsert(ssi: SSIState, handler: SSIHandlerFunction, tags: [String]) {
        // Search registered tags for a match.
        var matchedIndex = -1
        for (idx, registeredTag) in tags.enumerated() {
            if ssi.tagName == registeredTag {
                matchedIndex = idx
                break
            }
        }

        if matchedIndex >= 0 {
            // Found a registered tag. Call the handler.
            if let replacement = handler(matchedIndex, ssi.tagName) {
                ssi.tagInsert = Array(replacement.utf8)
                ssi.tagInsertLen = ssi.tagInsert.count
            } else {
                ssi.tagInsert = []
                ssi.tagInsertLen = 0
            }
        } else {
            // Unknown tag. If using raw mode, try calling with the name directly.
            if let replacement = handler(-1, ssi.tagName) {
                ssi.tagInsert = Array(replacement.utf8)
                ssi.tagInsertLen = ssi.tagInsert.count
            } else {
                // Generate unknown tag placeholder: "unknown tag: <name>"
                let placeholder = "<!-- unknown tag: \(ssi.tagName) -->"
                ssi.tagInsert = Array(placeholder.utf8)
                ssi.tagInsertLen = ssi.tagInsert.count
            }
        }
    }

    /// Process SSI tags in a string (convenience wrapper).
    ///
    /// - Parameter content: The HTML content to process.
    /// - Returns: Processed content with SSI tags replaced.
    internal func processSSI(_ content: String) -> String {
        let inputBytes = Array(content.utf8)
        let outputBytes = processSSIData(inputBytes)
        return String(bytes: outputBytes, encoding: .utf8) ?? content
    }

    /// Check whether whitespace (space, tab, CR, LF).
    private func isHTTPWhitespace(_ byte: UInt8) -> Bool {
        return byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") ||
               byte == 0x0D /* \r */ || byte == 0x0A /* \n */
    }

    /// Check whether a URI should be processed for SSI tags based on file extension.
    internal func isSSIFile(_ uri: String) -> Bool {
        let ssiExtensions = [".shtml", ".shtm", ".ssi", ".xml", ".json"]
        let lowerURI = uri.lowercased()
        // Strip query parameters for extension check.
        let basePath: String
        if let qIdx = lowerURI.firstIndex(of: "?") {
            basePath = String(lowerURI[lowerURI.startIndex..<qIdx])
        } else {
            basePath = lowerURI
        }
        return ssiExtensions.contains(where: { basePath.hasSuffix($0) })
    }

    // MARK: - POST Processing

    /// Parse HTTP headers from a raw request buffer to extract specific values.
    ///
    /// - Parameters:
    ///   - headerData: Raw header bytes (everything between request line and body).
    ///   - name: The header name to search for (case-insensitive).
    /// - Returns: The header value, or nil if not found.
    internal func findHeader(in headerData: String, name: String) -> String? {
        let lowerName = name.lowercased() + ":"
        let lines = headerData.split(separator: "\r\n", omittingEmptySubsequences: false)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix(lowerName) {
                let value = trimmed.dropFirst(lowerName.count).trimmingCharacters(in: .whitespaces)
                return value
            }
        }
        return nil
    }

    /// Handle a POST request.
    ///
    /// Parses the Content-Length header, notifies the POST handler, and buffers
    /// body data. Supports `application/x-www-form-urlencoded` decoding,
    /// streaming POST for large uploads, and multipart form-data parsing.
    ///
    /// - Parameters:
    ///   - conn: The HTTP connection.
    ///   - requestLine: The full raw request text.
    ///   - uri: The parsed request URI.
    ///   - headerEnd: Index of the end of headers (after \r\n\r\n).
    internal func handlePostRequest(_ conn: HTTPConnection, requestLine: String,
                                     uri: String, headerEnd: Int) {
        // Extract Content-Length.
        guard let contentLenStr = findHeader(in: requestLine, name: "Content-Length"),
              let contentLen = Int(contentLenStr), contentLen >= 0 else {
            // No valid Content-Length, send 400 Bad Request.
            sendErrorResponse(conn, statusCode: 400)
            return
        }

        conn.contentLength = contentLen
        conn.postContentLenLeft = UInt32(contentLen)

        // Extract Content-Type.
        conn.postContentType = findHeader(in: requestLine, name: "Content-Type") ?? ""

        // Configure manual POST window management.
        // When enabled, the server will not automatically acknowledge
        // received POST data to TCP; the application controls the window.
        if HTTPServerConfig.httpPostManualWindow {
            conn.noAutoWnd = true
        }

        // Check if streaming POST handler should be used.
        if let streamHandler = streamingPostHandler {
            conn.streamingPost = true
            let err = streamHandler.streamingPostBegin(
                uri: uri,
                contentLength: contentLen,
                contentType: conn.postContentType
            )
            if err != .ok {
                sendErrorResponse(conn, statusCode: 403)
                return
            }

            // Process any body data already received with the headers.
            let requestBytes = Array(requestLine.utf8)
            if headerEnd < requestBytes.count {
                let bodyChunk = Array(requestBytes[headerEnd...])
                // When manual window is active, the initial body bytes
                // that arrived with the headers have already been recved
                // (the full pbuf was acknowledged). Track them as unrecved
                // so the application can release the window properly.
                if HTTPServerConfig.httpPostManualWindow && conn.noAutoWnd {
                    conn.unrecvedBytes = UInt32(bodyChunk.count)
                }
                receivePostData(conn, data: bodyChunk)
            } else if contentLen == 0 {
                finishPost(conn)
            }
            return
        }

        // Notify the POST handler.
        if let handler = postHandler {
            var responseURI = ""
            let headerAfterURI: String
            if let spaceIdx = requestLine.firstIndex(of: "\r") {
                headerAfterURI = String(requestLine[spaceIdx...])
            } else {
                headerAfterURI = ""
            }

            let err = handler.postBegin(
                uri: uri,
                httpRequest: headerAfterURI,
                contentLength: contentLen,
                contentType: conn.postContentType,
                responseURI: &responseURI
            )

            if err != .ok {
                // Handler rejected the POST; serve the response URI if set.
                if !responseURI.isEmpty {
                    conn.postResponseURI = responseURI
                    sendResponse(conn, uri: responseURI)
                } else {
                    sendErrorResponse(conn, statusCode: 403)
                }
                return
            }
            conn.postResponseURI = responseURI
        }

        // Process any body data already received with the headers.
        let requestBytes = Array(requestLine.utf8)
        if headerEnd < requestBytes.count {
            let bodyChunk = Array(requestBytes[headerEnd...])
            receivePostData(conn, data: bodyChunk)
        } else if contentLen == 0 {
            // No body expected.
            finishPost(conn)
        }
    }

    /// Receive a chunk of POST body data.
    ///
    /// Tracks remaining content length and buffers data (or streams it
    /// to the streaming handler). When all data is received, calls
    /// `finishPost`.
    ///
    /// When manual POST window management is enabled, the `unrecvedBytes`
    /// counter is temporarily incremented around the handler callback to
    /// prevent the connection from being closed if `postDataRecved()` is
    /// called nested from within the handler.
    internal func receivePostData(_ conn: HTTPConnection, data: [UInt8]) {
        guard !data.isEmpty else { return }

        // Adjust remaining content length.
        if conn.postContentLenLeft < UInt32(data.count) {
            conn.postContentLenLeft = 0
        } else {
            conn.postContentLenLeft -= UInt32(data.count)
        }

        conn.postDataReceived += data.count

        // Manual window guard: increment unrecvedBytes to prevent the
        // connection from being closed if postDataRecved() is called
        // nested within the handler callback.
        if HTTPServerConfig.httpPostManualWindow {
            conn.unrecvedBytes += 1
        }

        if conn.streamingPost {
            // Streaming mode: pass data directly to handler without buffering.
            if let streamHandler = streamingPostHandler {
                let err = streamHandler.streamingPostReceiveData(
                    data: data,
                    remaining: Int(conn.postContentLenLeft)
                )
                if err != .ok {
                    conn.postContentLenLeft = 0
                }
            }
        } else {
            // Buffering mode: accumulate body data.
            conn.postBody.append(contentsOf: data)

            // Notify the POST handler with the chunk.
            if let handler = postHandler {
                let err = handler.postReceiveData(connection: conn, data: data)
                if err != .ok {
                    // Application error, discard remaining data.
                    conn.postContentLenLeft = 0
                }
            }
        }

        // Undo the manual window guard increment.
        if HTTPServerConfig.httpPostManualWindow {
            conn.unrecvedBytes -= 1
        }

        // Check if all data received.
        if conn.postContentLenLeft == 0 {
            // When manual window is enabled, defer finishPost until all
            // bytes have been acknowledged by the application.
            if HTTPServerConfig.httpPostManualWindow && conn.unrecvedBytes != 0 {
                return
            }
            finishPost(conn)
        }
    }

    /// Complete POST processing after all body data is received.
    ///
    /// Decodes the body if `application/x-www-form-urlencoded`, parses
    /// multipart/form-data if a multipart handler is registered, notifies
    /// the appropriate handler, and serves the response file.
    internal func finishPost(_ conn: HTTPConnection) {
        // When manual POST window management is active, finishPost may
        // be called twice: once from receivePostData when all content
        // arrives, and once from postDataRecved when the application
        // acknowledges the last bytes. The postManualFinished guard
        // prevents double-processing.
        if HTTPServerConfig.httpPostManualWindow {
            guard !conn.postManualFinished else { return }
            conn.postManualFinished = true
        }
        guard !conn.postFinished else { return }
        conn.postFinished = true

        // Streaming POST completion.
        if conn.streamingPost {
            var responseURI = conn.postResponseURI
            streamingPostHandler?.streamingPostFinished(responseURI: &responseURI)
            conn.postResponseURI = responseURI
            let finalURI = responseURI.isEmpty ? conn.uri : responseURI
            sendResponse(conn, uri: finalURI)
            return
        }

        // Multipart form-data parsing.
        if let multipartHandler = multipartPostHandler,
           isMultipartContentType(conn.postContentType) {
            if let boundary = extractMultipartBoundary(conn.postContentType) {
                let parts = parseMultipartBody(conn.postBody, boundary: boundary)
                var responseURI = conn.postResponseURI
                multipartHandler.handleMultipartPost(
                    uri: conn.uri,
                    parts: parts,
                    responseURI: &responseURI
                )
                conn.postResponseURI = responseURI
                let finalURI = responseURI.isEmpty ? conn.uri : responseURI
                sendResponse(conn, uri: finalURI)
                return
            }
        }

        // Notify the POST handler.
        if let handler = postHandler {
            var responseURI = conn.postResponseURI
            handler.postFinished(connection: conn, responseURI: &responseURI)
            conn.postResponseURI = responseURI
        }

        // Decode form-urlencoded POST body into CGI-style parameters.
        if conn.postContentType.lowercased().hasPrefix("application/x-www-form-urlencoded") {
            if let bodyStr = String(bytes: conn.postBody, encoding: .utf8) {
                let (params, values) = parseQueryParameters(bodyStr)
                conn.cgiParams = params
                conn.cgiParamValues = values

                // Execute CGI handler with POST params if one matches.
                let basePath: String
                if let qIdx = conn.uri.firstIndex(of: "?") {
                    basePath = String(conn.uri[conn.uri.startIndex..<qIdx])
                } else {
                    basePath = conn.uri
                }
                if let cgiResponse = executeCGI(uri: basePath, params: params, values: values) {
                    conn.postResponseURI = cgiResponse
                }
            }
        }

        // Serve the response.
        let responseURI = conn.postResponseURI.isEmpty ? conn.uri : conn.postResponseURI
        sendResponse(conn, uri: responseURI)
    }

    /// Parse `Transfer-Encoding: chunked` body data.
    ///
    /// Decodes chunked transfer encoding by reading chunk-size lines followed
    /// by chunk data, and reassembles them into a contiguous body.
    ///
    /// - Parameter data: Raw chunked-encoded data.
    /// - Returns: Decoded body bytes, or nil if incomplete.
    internal func decodeChunkedBody(_ data: [UInt8]) -> [UInt8]? {
        var result: [UInt8] = []
        var offset = 0

        while offset < data.count {
            // Find the end of the chunk-size line (\r\n).
            guard let crlfPos = findCRLF(in: data, from: offset) else {
                return nil  // Incomplete, need more data.
            }

            // Parse chunk size (hex).
            let sizeStr = String(bytes: data[offset..<crlfPos], encoding: .ascii) ?? ""
            // Chunk extensions after ';' are ignored.
            let hexPart = sizeStr.split(separator: ";").first.map(String.init) ?? sizeStr
            guard let chunkSize = UInt(hexPart.trimmingCharacters(in: .whitespaces), radix: 16) else {
                return nil  // Parse error.
            }

            if chunkSize == 0 {
                // Terminal chunk.
                break
            }

            let dataStart = crlfPos + 2  // Skip \r\n after size.
            let dataEnd = dataStart + Int(chunkSize)
            guard dataEnd + 2 <= data.count else {
                return nil  // Incomplete chunk data.
            }

            result.append(contentsOf: data[dataStart..<dataEnd])
            offset = dataEnd + 2  // Skip trailing \r\n after chunk data.
        }

        return result
    }

    /// Find the position of \r\n in data starting from an offset.
    private func findCRLF(in data: [UInt8], from offset: Int) -> Int? {
        var i = offset
        while i + 1 < data.count {
            if data[i] == 0x0D && data[i + 1] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }

    // MARK: - Request Processing

    /// Parse a raw HTTP request from the connection's buffer.
    ///
    /// Extracts the method, URI, headers, and routes to the appropriate
    /// handler (GET/POST/CGI).
    internal func parseRequest(_ conn: HTTPConnection, data: [UInt8]) {
        conn.requestBuffer.append(contentsOf: data)

        // Check for end of headers (\r\n\r\n).
        guard let headerEndOffset = findHeaderEnd(conn.requestBuffer) else {
            return  // Headers not yet complete.
        }

        guard let requestStr = String(bytes: conn.requestBuffer, encoding: .utf8) else {
            sendErrorResponse(conn, statusCode: 400)
            return
        }

        conn.headersComplete = true

        // Parse method.
        if requestStr.hasPrefix("GET ") {
            conn.method = .get
        } else if requestStr.hasPrefix("POST ") {
            conn.method = .post
        } else if requestStr.hasPrefix("HEAD ") {
            conn.method = .head
        } else {
            sendErrorResponse(conn, statusCode: 501)
            return
        }

        // Parse URI.
        let afterMethod: String
        switch conn.method {
        case .get, .put:
            afterMethod = String(requestStr.dropFirst(4))
        case .post:
            afterMethod = String(requestStr.dropFirst(5))
        case .head:
            afterMethod = String(requestStr.dropFirst(5))
        default:
            afterMethod = String(requestStr.dropFirst(4))
        }

        guard let spaceIdx = afterMethod.firstIndex(of: " ") else {
            sendErrorResponse(conn, statusCode: 400)
            return
        }
        let uri = String(afterMethod[afterMethod.startIndex..<spaceIdx])
        conn.uri = uri

        // Check for keep-alive.
        let lowerRequest = requestStr.lowercased()
        conn.keepAlive = lowerRequest.contains("connection: keep-alive")

        // Route by method.
        if conn.method == .post && HTTPServerConfig.supportPost {
            handlePostRequest(conn, requestLine: requestStr, uri: uri,
                            headerEnd: headerEndOffset)
        } else {
            handleRequest(conn)
        }
    }

    /// Handle an incoming HTTP GET/HEAD request.
    internal func handleRequest(_ conn: HTTPConnection) {
        let uri = conn.uri
        var responseURI = uri

        // Parse query parameters from URI.
        var basePath = uri
        var params: [String] = []
        var values: [String] = []

        if let qIndex = uri.firstIndex(of: "?") {
            basePath = String(uri[uri.startIndex..<qIndex])
            let queryString = String(uri[uri.index(after: qIndex)...])
            let parsed = parseQueryParameters(queryString)
            params = parsed.params
            values = parsed.values
        }

        // Try CGI handler.
        if let cgiResponse = executeCGI(uri: basePath, params: params, values: values) {
            responseURI = cgiResponse
        }

        conn.cgiParams = params
        conn.cgiParamValues = values

        // Default page handling: try standard index files for directory requests.
        if responseURI == "/" || responseURI.hasSuffix("/") {
            let prefix = responseURI == "/" ? "" : responseURI.dropLast().description
            for defaultFile in defaultFilenames {
                let candidate = prefix + defaultFile.name
                if canOpenFile(candidate) {
                    responseURI = candidate
                    break
                }
            }
            // If none found, fall through to 404.
        }

        // Serve file.
        sendResponse(conn, uri: responseURI)
    }

    /// Check whether a file can be opened (exists in the filesystem).
    private func canOpenFile(_ path: String) -> Bool {
        if let fs = fileSystem {
            if let file = fs.open(path) {
                fs.close(file: file)
                return true
            }
            return false
        }
        if let provider = fileProvider {
            return provider.readFile(path) != nil
        }
        return false
    }

    /// Send an HTTP response for a URI.
    private func sendResponse(_ conn: HTTPConnection, uri: String, statusCode: Int = 200) {
        // Determine content type.
        let contentType = mimeTypeForExtension(uri)

        // Try to load file content.
        let body: [UInt8]

        if let fs = fileSystem {
            // Use HTTPFileSystem for file serving.
            if let file = fs.open(uri) {
                let fileData: [UInt8]
                let isDynamicRead: Bool
                if file.data.isEmpty && file.flags.contains(.custom) {
                    // Custom file: use read() to get data in chunks.
                    isDynamicRead = true

                    // When async reads are enabled, read only the first
                    // chunk now. The rest will be read incrementally by
                    // writePendingResponse / readMoreFileData as TCP
                    // buffer space becomes available. This avoids blocking
                    // the entire connection on potentially slow I/O.
                    if HTTPFileSystemConfig.asyncRead {
                        let readSize = 4096
                        var buffer = [UInt8](repeating: 0, count: readSize)
                        let bytesRead = fs.readAsync(file: file, into: &buffer, count: readSize) { [weak self, weak conn] in
                            guard let self, let conn else { return }
                            self.httpContinue(conn)
                        }

                        if bytesRead == HTTPFileSystemConfig.readDelayed {
                            // Async read pending. Send headers now, file
                            // data will follow when the callback fires.
                            conn.file = file
                            conn.asyncReadPending = true
                            let needSSI = file.flags.contains(.ssi) || isSSIFile(uri)
                            let cType = needSSI ? contentType : contentType
                            sendHeadersOnly(conn, statusCode: statusCode,
                                            contentType: cType,
                                            customHeaders: fileCustomHeaders(file))
                            return
                        } else if bytesRead > 0 {
                            fileData = Array(buffer.prefix(bytesRead))
                        } else {
                            fileData = []
                        }
                        // Keep file open for incremental reading.
                        conn.file = file
                    } else {
                        // Synchronous read: load all data at once.
                        var allData: [UInt8] = []
                        while !file.isEOF {
                            let chunk = fs.read(file: file, count: 4096)
                            if chunk.isEmpty { break }
                            allData.append(contentsOf: chunk)
                        }
                        fileData = allData
                    }
                } else {
                    // ROM file: data is available directly.
                    isDynamicRead = false
                    fileData = file.data
                }

                // Check for SSI processing.
                let needSSI = file.flags.contains(.ssi) || isSSIFile(uri)

                // Use chunked transfer encoding when:
                //  - The file is dynamic (content length unknown at open time)
                //  - OR the file needs SSI processing (processed size differs from raw size)
                // AND chunked transfer is enabled in configuration.
                let useChunked = HTTPServerConfig.enableChunkedTransfer && (isDynamicRead || needSSI)

                if needSSI {
                    let processed = processSSIData(fileData)
                    if useChunked {
                        sendChunkedHTTPResponse(conn, statusCode: statusCode,
                                                contentType: contentType,
                                                bodyChunks: [processed],
                                                customHeaders: fileCustomHeaders(file))
                    } else {
                        sendHTTPResponse(conn, statusCode: statusCode, contentType: contentType,
                                        body: processed, customHeaders: fileCustomHeaders(file))
                    }
                } else if useChunked {
                    sendChunkedHTTPResponse(conn, statusCode: statusCode,
                                            contentType: contentType,
                                            bodyChunks: [fileData],
                                            customHeaders: fileCustomHeaders(file))
                } else {
                    sendHTTPResponse(conn, statusCode: statusCode, contentType: contentType,
                                    body: fileData, customHeaders: fileCustomHeaders(file))
                }

                conn.file = file
                // Note: file will be closed when connection closes.
                return
            }
        } else if let provider = fileProvider {
            // Legacy file provider.
            if let data = provider.readFile(uri) {
                if isSSIFile(uri) {
                    let processed = processSSIData(data)
                    if HTTPServerConfig.enableChunkedTransfer {
                        sendChunkedHTTPResponse(conn, statusCode: statusCode,
                                                contentType: contentType,
                                                bodyChunks: [processed])
                    } else {
                        sendHTTPResponse(conn, statusCode: statusCode,
                                        contentType: contentType, body: processed)
                    }
                    return
                }
                body = data
                sendHTTPResponse(conn, statusCode: statusCode, contentType: contentType, body: body)
                return
            }
        }

        // Custom 404 handler: let the application supply a dynamic not-found page.
        if let handler = notFoundHandler,
           let (body, contentType) = handler(uri) {
            sendHTTPResponse(conn, statusCode: 404, contentType: contentType, body: body)
            return
        }

        // Default 404 response.
        let notFound = Array("404 Not Found".utf8)
        sendHTTPResponse(conn, statusCode: 404, contentType: "text/plain", body: notFound)
    }

    /// Extract custom headers from a file if it has the headerIncluded flag.
    private func fileCustomHeaders(_ file: HTTPFile) -> String? {
        // If file has headerIncluded flag, the HTTP headers are part of the data.
        // In that case, we skip generating our own headers.
        if file.flags.contains(.headerIncluded) {
            return ""  // Signal to sendHTTPResponse that headers are in the body.
        }
        return nil
    }

    /// Build and send a raw HTTP response.
    ///
    /// When `body` is provided, the response uses `Content-Length`.
    /// When `body` is nil and `chunkedBody` is provided, the response
    /// uses `Transfer-Encoding: chunked`.
    private func sendHTTPResponse(_ conn: HTTPConnection, statusCode: Int,
                                  contentType: String, body: [UInt8],
                                  customHeaders: String? = nil) {
        // If custom headers indicate headers are already in the body, send body directly.
        if let custom = customHeaders, custom.isEmpty {
            conn.responseData = body
            conn.bytesSent = 0
            _ = writePendingResponse(conn)
            return
        }

        let statusText = httpStatusText(statusCode)

        var header = "HTTP/1.1 \(statusCode) \(statusText)\r\n"
        header += "Server: lwIP/Swift\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Content-Length: \(body.count)\r\n"
        if conn.keepAlive {
            header += "Connection: keep-alive\r\n"
        } else {
            header += "Connection: close\r\n"
        }
        if let custom = customHeaders, !custom.isEmpty {
            header += custom
        }
        // Invoke the dynamic header handler to allow request-time header injection.
        // This runs after static/file-based custom headers so that dynamic values
        // can override or supplement them.
        if let dynamicHeaders = dynamicHeaderHandler?(conn.uri) {
            header += dynamicHeaders
        }
        header += "\r\n"

        conn.responseData = Array(header.utf8) + body
        conn.bytesSent = 0
        _ = writePendingResponse(conn)
    }

    /// Send a chunked transfer-encoded response.
    ///
    /// When Content-Length is unknown (dynamic content, SSI with unknown
    /// final size), this method uses `Transfer-Encoding: chunked` to
    /// stream the body.  Each chunk is prefixed with its size in hex
    /// followed by CRLF, then the data, then CRLF.  The stream ends
    /// with a zero-length chunk.
    ///
    /// Used when the server cannot know the total file size in advance.
    ///
    /// - Parameters:
    ///   - conn: The HTTP connection.
    ///   - statusCode: HTTP status code.
    ///   - contentType: Content-Type header value.
    ///   - bodyChunks: Array of body data chunks to send. Each element
    ///     becomes one HTTP chunk in the transfer.
    ///   - customHeaders: Additional header lines (each terminated with CRLF).
    private func sendChunkedHTTPResponse(_ conn: HTTPConnection, statusCode: Int,
                                          contentType: String,
                                          bodyChunks: [[UInt8]],
                                          customHeaders: String? = nil) {
        let statusText = httpStatusText(statusCode)

        var header = "HTTP/1.1 \(statusCode) \(statusText)\r\n"
        header += "Server: lwIP/Swift\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Transfer-Encoding: chunked\r\n"
        if conn.keepAlive {
            header += "Connection: keep-alive\r\n"
        } else {
            header += "Connection: close\r\n"
        }
        if let custom = customHeaders, !custom.isEmpty {
            header += custom
        }
        if let dynamicHeaders = dynamicHeaderHandler?(conn.uri) {
            header += dynamicHeaders
        }
        header += "\r\n"

        conn.chunkedResponse = true

        var responseBytes = Array(header.utf8)

        // Encode each chunk: size-in-hex CRLF data CRLF
        for chunk in bodyChunks where !chunk.isEmpty {
            let sizeHex = String(chunk.count, radix: 16)
            responseBytes.append(contentsOf: Array(sizeHex.utf8))
            responseBytes.append(contentsOf: [0x0D, 0x0A]) // CRLF
            responseBytes.append(contentsOf: chunk)
            responseBytes.append(contentsOf: [0x0D, 0x0A]) // CRLF
        }

        // Terminal zero-length chunk.
        responseBytes.append(contentsOf: Array("0\r\n\r\n".utf8))

        conn.responseData = responseBytes
        conn.bytesSent = 0
        _ = writePendingResponse(conn)
    }

    /// Encode a single data chunk in HTTP chunked transfer encoding format.
    ///
    /// Returns the chunk formatted as: `<hex-size>\r\n<data>\r\n`.
    /// Returns the terminal chunk `0\r\n\r\n` when `data` is empty.
    ///
    /// This is a utility for callers that build chunked responses
    /// incrementally (e.g. SSI processing with dynamic reads).
    internal func encodeChunk(_ data: [UInt8]) -> [UInt8] {
        if data.isEmpty {
            // Terminal chunk.
            return Array("0\r\n\r\n".utf8)
        }
        var chunk: [UInt8] = []
        let sizeHex = String(data.count, radix: 16)
        chunk.append(contentsOf: Array(sizeHex.utf8))
        chunk.append(contentsOf: [0x0D, 0x0A])
        chunk.append(contentsOf: data)
        chunk.append(contentsOf: [0x0D, 0x0A])
        return chunk
    }

    /// Send only HTTP headers without a body, for use when the body will
    /// be sent incrementally as file data becomes available (async reads).
    ///
    /// Uses `Transfer-Encoding: chunked` since the total body size is
    /// unknown at this point.
    private func sendHeadersOnly(_ conn: HTTPConnection, statusCode: Int,
                                  contentType: String,
                                  customHeaders: String? = nil) {
        let statusText = httpStatusText(statusCode)

        var header = "HTTP/1.1 \(statusCode) \(statusText)\r\n"
        header += "Server: lwIP/Swift\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Transfer-Encoding: chunked\r\n"
        if conn.keepAlive {
            header += "Connection: keep-alive\r\n"
        } else {
            header += "Connection: close\r\n"
        }
        if let custom = customHeaders, !custom.isEmpty {
            header += custom
        }
        if let dynamicHeaders = dynamicHeaderHandler?(conn.uri) {
            header += dynamicHeaders
        }
        header += "\r\n"

        conn.chunkedResponse = true
        conn.responseData = Array(header.utf8)
        conn.bytesSent = 0
        _ = writePendingResponse(conn)
    }

    /// Map HTTP status code to reason phrase.
    private func httpStatusText(_ statusCode: Int) -> String {
        switch statusCode {
        case 200: return "OK"
        case 301: return "Moved Permanently"
        case 400: return "Bad Request"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 500: return "Internal Server Error"
        case 501: return "Not Implemented"
        default:  return "Unknown"
        }
    }

    /// Send an error response.
    private func sendErrorResponse(_ conn: HTTPConnection, statusCode: Int) {
        let messages: [Int: String] = [
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            501: "Not Implemented",
        ]
        let message = messages[statusCode] ?? "Error"
        let body = Array("<html><body><h1>\(statusCode) \(message)</h1></body></html>".utf8)
        sendHTTPResponse(conn, statusCode: statusCode, contentType: "text/html", body: body)
    }

    /// Find the end of HTTP headers (\r\n\r\n) in a byte buffer.
    private func findHeaderEnd(_ data: [UInt8]) -> Int? {
        let pattern: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard data.count >= 4 else { return nil }

        for i in 0...(data.count - 4) {
            if data[i] == pattern[0] && data[i+1] == pattern[1] &&
               data[i+2] == pattern[2] && data[i+3] == pattern[3] {
                return i + 4
            }
        }
        return nil
    }

    /// Get MIME type from file extension.
    private func mimeTypeForExtension(_ path: String) -> String {
        // Strip query string before extracting extension.
        let basePath: String
        if let qIdx = path.firstIndex(of: "?") {
            basePath = String(path[path.startIndex..<qIdx])
        } else {
            basePath = path
        }

        let ext = basePath.split(separator: ".").last.map(String.init)?.lowercased() ?? ""
        switch ext {
        case "html", "htm": return "text/html"
        case "css":         return "text/css"
        case "js":          return "application/javascript"
        case "json":        return "application/json"
        case "xml":         return "application/xml"
        case "txt":         return "text/plain"
        case "png":         return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "gif":         return "image/gif"
        case "svg":         return "image/svg+xml"
        case "ico":         return "image/x-icon"
        case "bin":         return "application/octet-stream"
        case "shtml", "shtm", "ssi": return "text/html"
        case "woff":        return "font/woff"
        case "woff2":       return "font/woff2"
        case "ttf":         return "font/ttf"
        case "eot":         return "application/vnd.ms-fontobject"
        case "otf":         return "font/otf"
        case "pdf":         return "application/pdf"
        case "zip":         return "application/zip"
        case "gz":          return "application/gzip"
        case "mp3":         return "audio/mpeg"
        case "mp4":         return "video/mp4"
        case "webm":        return "video/webm"
        case "webp":        return "image/webp"
        default:            return "application/octet-stream"
        }
    }

    // MARK: - Multipart POST Parsing

    /// Check whether a Content-Type header indicates multipart/form-data.
    ///
    /// - Parameter contentType: The Content-Type header value.
    /// - Returns: `true` if the content type is multipart/form-data.
    internal func isMultipartContentType(_ contentType: String) -> Bool {
        return contentType.lowercased().hasPrefix("multipart/form-data")
    }

    /// Extract the boundary string from a multipart Content-Type header.
    ///
    /// Parses a header like:
    ///   `multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW`
    /// and returns the boundary string (without leading dashes).
    ///
    /// - Parameter contentType: The Content-Type header value.
    /// - Returns: The boundary string, or nil if not found.
    internal func extractMultipartBoundary(_ contentType: String) -> String? {
        let lower = contentType.lowercased()
        guard lower.hasPrefix("multipart/form-data") else { return nil }

        // Look for "boundary=" parameter (case-insensitive).
        guard let boundaryRange = lower.range(of: "boundary=") else { return nil }

        let afterBoundary = contentType[boundaryRange.upperBound...]
        // The boundary value may be quoted.
        var boundary: String
        if afterBoundary.hasPrefix("\"") {
            // Quoted boundary: find closing quote.
            let unquoted = afterBoundary.dropFirst()
            if let endQuote = unquoted.firstIndex(of: "\"") {
                boundary = String(unquoted[unquoted.startIndex..<endQuote])
            } else {
                boundary = String(unquoted)
            }
        } else {
            // Unquoted: take until whitespace, semicolon, or end.
            let end = afterBoundary.firstIndex(where: { $0 == ";" || $0 == " " || $0 == "\t" })
                ?? afterBoundary.endIndex
            boundary = String(afterBoundary[afterBoundary.startIndex..<end])
        }

        guard !boundary.isEmpty,
              boundary.count <= HTTPServerConfig.maxMultipartBoundaryLength else {
            return nil
        }

        return boundary
    }

    /// Parse a multipart/form-data body into individual parts.
    ///
    /// The body is split on the boundary delimiter. Each part's headers
    /// are parsed for Content-Disposition (name, filename) and
    /// Content-Type. The body of each part is the data after the part's
    /// header section.
    ///
    /// RFC 2046 defines the boundary delimiter as `--` + boundary.
    ///
    /// - Parameters:
    ///   - data: The raw POST body bytes.
    ///   - boundary: The boundary string (without leading `--`).
    /// - Returns: Array of parsed multipart parts.
    internal func parseMultipartBody(_ data: [UInt8], boundary: String) -> [MultipartPart] {
        let delimiter = Array("--\(boundary)".utf8)
        let closeDelimiter = Array("--\(boundary)--".utf8)

        var parts: [MultipartPart] = []
        var offset = 0

        // Find the first boundary.
        guard let firstBoundary = findSequence(delimiter, in: data, from: offset) else {
            return parts
        }
        // Skip past the first boundary and its trailing CRLF.
        offset = firstBoundary + delimiter.count
        offset = skipCRLF(in: data, from: offset)

        while offset < data.count {
            // Check for close delimiter (end of multipart body).
            if offset + closeDelimiter.count <= data.count {
                let slice = Array(data[offset..<(offset + closeDelimiter.count)])
                if slice == closeDelimiter {
                    break
                }
            }

            // Find the next boundary to determine the end of this part.
            guard let nextBoundary = findSequence(delimiter, in: data, from: offset) else {
                break
            }

            // The part data is from offset to nextBoundary - 2 (strip trailing CRLF before boundary).
            var partEnd = nextBoundary
            if partEnd >= 2 && data[partEnd - 2] == 0x0D && data[partEnd - 1] == 0x0A {
                partEnd -= 2
            }

            let partData = Array(data[offset..<partEnd])

            // Parse the part: split headers from body at \r\n\r\n.
            if let part = parseMultipartPart(partData) {
                parts.append(part)
            }

            // Advance past the boundary and its trailing CRLF.
            offset = nextBoundary + delimiter.count
            offset = skipCRLF(in: data, from: offset)
        }

        return parts
    }

    /// Parse a single multipart part (headers + body).
    ///
    /// - Parameter data: The raw bytes of a single part (after boundary delimiter).
    /// - Returns: A parsed `MultipartPart`, or nil if the part is malformed.
    private func parseMultipartPart(_ data: [UInt8]) -> MultipartPart? {
        // Find end of headers (\r\n\r\n).
        guard let headerEnd = findHeaderEnd(data) else {
            // No header/body separation: treat entire content as body with no headers.
            return MultipartPart(name: "", filename: nil, contentType: nil,
                                 headers: [], body: data)
        }

        let headerBytes = Array(data[0..<(headerEnd - 4)])
        let bodyBytes = Array(data[headerEnd..<data.count])

        guard let headerStr = String(bytes: headerBytes, encoding: .utf8) else {
            return nil
        }

        // Parse headers.
        var headers: [(String, String)] = []
        let lines = headerStr.split(separator: "\r\n", omittingEmptySubsequences: false)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            if let colonIdx = trimmed.firstIndex(of: ":") {
                let name = String(trimmed[trimmed.startIndex..<colonIdx])
                    .trimmingCharacters(in: .whitespaces)
                let value = String(trimmed[trimmed.index(after: colonIdx)...])
                    .trimmingCharacters(in: .whitespaces)
                headers.append((name, value))
            }
        }

        // Extract Content-Disposition fields.
        var name = ""
        var filename: String? = nil
        var partContentType: String? = nil

        for (hdrName, hdrValue) in headers {
            let lowerName = hdrName.lowercased()
            if lowerName == "content-disposition" {
                name = extractDispositionParam(hdrValue, param: "name") ?? ""
                filename = extractDispositionParam(hdrValue, param: "filename")
            } else if lowerName == "content-type" {
                partContentType = hdrValue
            }
        }

        return MultipartPart(name: name, filename: filename, contentType: partContentType,
                             headers: headers, body: bodyBytes)
    }

    /// Extract a named parameter from a Content-Disposition header value.
    ///
    /// Parses values like:
    ///   `form-data; name="field1"; filename="example.txt"`
    ///
    /// - Parameters:
    ///   - disposition: The Content-Disposition header value.
    ///   - param: The parameter name to extract (e.g. "name", "filename").
    /// - Returns: The parameter value (unquoted), or nil if not found.
    private func extractDispositionParam(_ disposition: String, param: String) -> String? {
        let searchKey = param + "="
        let lower = disposition.lowercased()
        guard let range = lower.range(of: searchKey) else { return nil }

        let afterKey = disposition[range.upperBound...]
        if afterKey.hasPrefix("\"") {
            // Quoted value.
            let unquoted = afterKey.dropFirst()
            if let endQuote = unquoted.firstIndex(of: "\"") {
                return String(unquoted[unquoted.startIndex..<endQuote])
            }
            return String(unquoted)
        } else {
            // Unquoted value: take until semicolon or end.
            let end = afterKey.firstIndex(where: { $0 == ";" || $0 == " " })
                ?? afterKey.endIndex
            return String(afterKey[afterKey.startIndex..<end])
        }
    }

    /// Find the position of a byte sequence in data starting from an offset.
    ///
    /// - Parameters:
    ///   - sequence: The byte sequence to find.
    ///   - data: The data to search.
    ///   - offset: Starting position.
    /// - Returns: The index of the first byte of the match, or nil.
    private func findSequence(_ sequence: [UInt8], in data: [UInt8], from offset: Int) -> Int? {
        guard !sequence.isEmpty, offset + sequence.count <= data.count else { return nil }
        for i in offset...(data.count - sequence.count) {
            var matched = true
            for j in 0..<sequence.count {
                if data[i + j] != sequence[j] {
                    matched = false
                    break
                }
            }
            if matched {
                return i
            }
        }
        return nil
    }

    /// Skip past CRLF at the given position.
    ///
    /// - Parameters:
    ///   - data: The byte data.
    ///   - offset: Current position.
    /// - Returns: New position after any leading CRLF.
    private func skipCRLF(in data: [UInt8], from offset: Int) -> Int {
        var pos = offset
        if pos + 1 < data.count && data[pos] == 0x0D && data[pos + 1] == 0x0A {
            pos += 2
        }
        return pos
    }
}

// MARK: - HTTPFileProvider

/// Protocol for serving files from the HTTP server (legacy interface).
/// Prefer using HTTPFileSystem directly for new code.
public protocol HTTPFileProvider: AnyObject, Sendable {
    /// Read a file from the virtual filesystem.
    ///
    /// - Parameter path: The file path (URI).
    /// - Returns: File contents, or `nil` if not found.
    func readFile(_ path: String) -> [UInt8]?
}

