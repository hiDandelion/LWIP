//
//  HTTPClient.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - HTTP Client Configuration

/// HTTP client constants.
public extension HTTPClient {
    /// Default HTTP port.
    static let defaultPort: UInt16 = 80

    /// Default HTTPS port.
    static let defaultHTTPSPort: UInt16 = 443

    /// Default maximum number of redirects to follow.
    static let defaultMaxRedirects: Int = 5
}

// MARK: - HTTPClientResult

/// HTTP client result codes.
public enum HTTPClientResult: Int, Sendable {
    /// File successfully received.
    case ok               = 0
    /// Unknown error.
    case errorUnknown     = 1
    /// Connection to server failed.
    case errorConnect     = 2
    /// Failed to resolve server hostname.
    case errorHostname    = 3
    /// Connection unexpectedly closed by remote server.
    case errorClosed      = 4
    /// Connection timed out.
    case errorTimeout     = 5
    /// Server responded with an error code.
    case errorServerResp  = 6
    /// Local memory error.
    case errorMemory      = 7
    /// Local abort.
    case localAbort       = 8
    /// Content length mismatch.
    case errorContentLen  = 9
    /// Too many redirects.
    case errorRedirect    = 10
}

// MARK: - Callback Types

extension HTTPClient {
    /// Called when the HTTP transfer is finished or aborted.
    public typealias ResultHandler = @Sendable (
        HTTPClientResult, UInt32, UInt32, LWIPError
    ) -> Void

    /// Called when HTTP headers have been fully received.
    public typealias HeadersCompleteHandler = @Sendable (
        [UInt8], UInt16, Int32
    ) -> LWIPError

    /// Called when body data is received.
    public typealias DataHandler = @Sendable ([UInt8]) -> LWIPError
}

// MARK: - HTTPClientConnection

/// HTTP client connection settings.
public struct HTTPClientConnection: Sendable {
    /// Proxy address (if using a proxy).
    public var proxyAddr: IPAddress?
    /// Proxy port.
    public var proxyPort: UInt16 = 0
    /// Whether to use a proxy.
    public var useProxy: Bool = false

    /// Result callback (called when transfer completes or fails).
    public var resultCallback: HTTPClient.ResultHandler?
    /// Headers-done callback.
    public var headersDoneCallback: HTTPClient.HeadersCompleteHandler?

    /// TLS configuration for HTTPS connections. When set, the connection uses TLS.
    public var tlsConfig: AltcpTLSConfig?

    /// Maximum number of redirects to follow. Set to 0 to disable redirect following.
    public var maxRedirects: Int = HTTPClient.defaultMaxRedirects

    public init(resultCallback: HTTPClient.ResultHandler? = nil,
                headersDoneCallback: HTTPClient.HeadersCompleteHandler? = nil) {
        self.resultCallback = resultCallback
        self.headersDoneCallback = headersDoneCallback
    }
}

// MARK: - HTTPClientState

/// Internal state of an HTTP client request.
internal final class HTTPClientState: @unchecked Sendable {
    /// Connection settings.
    let settings: HTTPClientConnection
    /// Data receive callback.
    let dataCallback: HTTPClient.DataHandler?
    /// User callback argument (kept as unmanaged reference).
    var callbackArg: AnyObject?
    /// TCP connection (plain TCP).
    var tcpControlBlock: TCPControlBlock?
    /// Altcp connection (used for TLS).
    var altcpControlBlock: AltcpControlBlock?
    /// Server hostname (for DNS resolution).
    var hostname: String?
    /// Request URI.
    var uri: String
    /// Port.
    var port: UInt16
    /// HTTP method.
    var method: HTTPMethod
    /// Request body (for POST/PUT).
    var body: [UInt8]?
    /// Content type for the request body.
    var contentType: String?

    /// Response parsing state.
    var headerBuffer: [UInt8] = []
    var headersComplete: Bool = false
    var httpStatusCode: UInt32 = 0
    var contentLength: Int32 = -1
    var rxContentLen: UInt32 = 0

    /// Chunked transfer decoding state.
    var isChunked: Bool = false
    var chunkParseState: ChunkParseState = .expectSize
    var currentChunkRemaining: Int = 0
    var chunkSizeLine: [UInt8] = []

    /// Redirect tracking.
    var redirectCount: Int = 0

    /// Chunked transfer decoding sub-states.
    enum ChunkParseState {
        /// Expecting a chunk size line (hex digits followed by \r\n).
        case expectSize
        /// Reading chunk data bytes.
        case readingData
        /// Expecting \r\n after chunk data.
        case expectDataCRLF
        /// Final chunk received; consuming optional trailers.
        case trailers
        /// All chunks received.
        case done
    }

    init(settings: HTTPClientConnection, uri: String, port: UInt16,
         method: HTTPMethod = .get, body: [UInt8]? = nil,
         contentType: String? = nil,
         dataCallback: HTTPClient.DataHandler?) {
        self.settings = settings
        self.uri = uri
        self.port = port
        self.method = method
        self.body = body
        self.contentType = contentType
        self.dataCallback = dataCallback
    }
}

// MARK: - HTTPClient

/// Asynchronous HTTP client.
///
/// Performs HTTP requests (GET, POST, PUT, DELETE) with callback-based
/// notification for headers, body data, and completion. Supports proxy
/// routing, chunked transfer decoding, and automatic redirect following.
public final class HTTPClient: @unchecked Sendable {

    /// Shared instance.
    public static let shared = HTTPClient()

    /// Active requests.
    private var activeRequests: [HTTPClientState] = []
    private let lock = NSLock()

    private init() {}

    private func copyBytes(from pbuf: Pbuf) -> [UInt8] {
        let totalLen = Int(pbuf.totLen)
        var data = [UInt8](repeating: 0, count: totalLen)
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            _ = pbuf.copyPartial(to: baseAddress, len: pbuf.totLen, offset: 0)
        }
        return data
    }

    private func closePCB(_ pcb: TCPControlBlock) {
        pcb.receiveHandler = nil
        pcb.sentHandler = nil
        pcb.connectedHandler = nil
        pcb.errorHandler = nil

        let err = TCPGlobal.shared.close(pcb: pcb)
        if err != .ok {
            TCPGlobal.shared.abort(pcb: pcb)
        }
    }

    private func closeAltcpPCB(_ pcb: AltcpControlBlock) {
        pcb.setRecv(nil)
        pcb.setSent(nil)
        pcb.setErr(nil)

        let err = pcb.close()
        if err != .ok {
            pcb.abort()
        }
    }

    private func finalResult(for state: HTTPClientState) -> HTTPClientResult {
        if !state.headersComplete {
            return .errorClosed
        }
        if state.httpStatusCode >= 400 {
            return .errorServerResp
        }
        // For chunked responses, content length is unknown (-1), so only
        // check when an explicit Content-Length was provided.
        if !state.isChunked && state.contentLength >= 0 &&
           state.rxContentLen != UInt32(state.contentLength) {
            return .errorContentLen
        }
        return .ok
    }

    // MARK: - GET by IP Address

    /// Perform an HTTP GET request to a server by IP address.
    ///
    /// - Parameters:
    ///   - serverAddr: Server IP address.
    ///   - port: Server port.
    ///   - uri: Request URI (e.g. "/index.html").
    ///   - settings: Connection settings with callbacks.
    ///   - dataCallback: Called with received body data.
    /// - Returns: `.ok` if the request was started.
    @discardableResult
    public func getFile(
        serverAddr: IPAddress,
        port: UInt16 = HTTPClient.defaultPort,
        uri: String,
        settings: HTTPClientConnection,
        dataCallback: HTTPClient.DataHandler? = nil
    ) -> LWIPError {
        let state = HTTPClientState(
            settings: settings,
            uri: uri,
            port: port,
            dataCallback: dataCallback
        )

        lock.lock()
        activeRequests.append(state)
        lock.unlock()

        TCPIP.shared.callback { [weak self] in
            self?.startRequest(state, address: serverAddr)
        }

        return .ok
    }

    // MARK: - GET by DNS Name

    /// Perform an HTTP GET request to a server by hostname.
    ///
    /// - Parameters:
    ///   - serverName: Server hostname.
    ///   - port: Server port.
    ///   - uri: Request URI.
    ///   - settings: Connection settings with callbacks.
    ///   - dataCallback: Called with received body data.
    /// - Returns: `.ok` if the request was started.
    @discardableResult
    public func getFileDNS(
        serverName: String,
        port: UInt16 = HTTPClient.defaultPort,
        uri: String,
        settings: HTTPClientConnection,
        dataCallback: HTTPClient.DataHandler? = nil
    ) -> LWIPError {
        let state = HTTPClientState(
            settings: settings,
            uri: uri,
            port: port,
            dataCallback: dataCallback
        )
        state.hostname = serverName

        lock.lock()
        activeRequests.append(state)
        lock.unlock()

        // Resolve hostname.
        TCPIP.shared.callback { [weak self] in
            switch NetConn.getHostByName(serverName) {
            case .success(let addr):
                self?.startRequest(state, address: addr)
            case .failure:
                self?.completeRequest(state, result: .errorHostname, err: .invalidValue)
            }
        }

        return .ok
    }

    // MARK: - HTTPS (TLS)

    /// Perform an HTTPS GET request to a server by hostname.
    ///
    /// - Parameters:
    ///   - serverName: Server hostname.
    ///   - port: Server port (default: 443).
    ///   - uri: Request URI.
    ///   - settings: Connection settings with callbacks (must include tlsConfig).
    ///   - dataCallback: Called with received body data.
    /// - Returns: `.ok` if the request was started.
    @discardableResult
    public func getFileSecure(
        serverName: String,
        port: UInt16 = HTTPClient.defaultHTTPSPort,
        uri: String,
        settings: HTTPClientConnection,
        dataCallback: HTTPClient.DataHandler? = nil
    ) -> LWIPError {
        return getFileDNS(
            serverName: serverName, port: port, uri: uri,
            settings: settings, dataCallback: dataCallback
        )
    }

    // MARK: - Generic Request by IP Address

    /// Perform an HTTP request with a specified method to a server by IP address.
    ///
    /// - Parameters:
    ///   - method: HTTP method (GET, POST, PUT, DELETE).
    ///   - serverAddr: Server IP address.
    ///   - port: Server port.
    ///   - uri: Request URI (e.g. "/api/resource").
    ///   - settings: Connection settings with callbacks.
    ///   - body: Optional request body bytes.
    ///   - contentType: Content-Type header value (e.g. "application/json").
    ///   - dataCallback: Called with received body data.
    /// - Returns: `.ok` if the request was started.
    @discardableResult
    public func request(
        method: HTTPMethod,
        serverAddr: IPAddress,
        port: UInt16 = HTTPClient.defaultPort,
        uri: String,
        settings: HTTPClientConnection,
        body: [UInt8]? = nil,
        contentType: String? = nil,
        dataCallback: HTTPClient.DataHandler? = nil
    ) -> LWIPError {
        let state = HTTPClientState(
            settings: settings,
            uri: uri,
            port: port,
            method: method,
            body: body,
            contentType: contentType,
            dataCallback: dataCallback
        )

        lock.lock()
        activeRequests.append(state)
        lock.unlock()

        TCPIP.shared.callback { [weak self] in
            self?.startRequest(state, address: serverAddr)
        }

        return .ok
    }

    // MARK: - Generic Request by DNS Name

    /// Perform an HTTP request with a specified method to a server by hostname.
    ///
    /// - Parameters:
    ///   - method: HTTP method (GET, POST, PUT, DELETE).
    ///   - serverName: Server hostname.
    ///   - port: Server port.
    ///   - uri: Request URI.
    ///   - settings: Connection settings with callbacks.
    ///   - body: Optional request body bytes.
    ///   - contentType: Content-Type header value.
    ///   - dataCallback: Called with received body data.
    /// - Returns: `.ok` if the request was started.
    @discardableResult
    public func requestDNS(
        method: HTTPMethod,
        serverName: String,
        port: UInt16 = HTTPClient.defaultPort,
        uri: String,
        settings: HTTPClientConnection,
        body: [UInt8]? = nil,
        contentType: String? = nil,
        dataCallback: HTTPClient.DataHandler? = nil
    ) -> LWIPError {
        let state = HTTPClientState(
            settings: settings,
            uri: uri,
            port: port,
            method: method,
            body: body,
            contentType: contentType,
            dataCallback: dataCallback
        )
        state.hostname = serverName

        lock.lock()
        activeRequests.append(state)
        lock.unlock()

        TCPIP.shared.callback { [weak self] in
            switch NetConn.getHostByName(serverName) {
            case .success(let addr):
                self?.startRequest(state, address: addr)
            case .failure:
                self?.completeRequest(state, result: .errorHostname, err: .invalidValue)
            }
        }

        return .ok
    }

    // MARK: - Internal: Request Building

    /// Build the HTTP request string for the given state and host.
    ///
    /// When a proxy is configured the request line uses the full URL
    /// (e.g. "GET http://host/path HTTP/1.1") as required by HTTP proxies.
    private func buildRequestString(_ state: HTTPClientState, host: String) -> String {
        let settings = state.settings
        let method = state.method.rawValue

        // Request line: use full URL when going through a proxy.
        var requestLine: String
        if settings.useProxy && settings.tlsConfig == nil {
            // Plain-HTTP proxy: absolute URI in request line.
            if state.port != HTTPClient.defaultPort {
                requestLine = "\(method) http://\(host):\(state.port)\(state.uri) HTTP/1.1\r\n"
            } else {
                requestLine = "\(method) http://\(host)\(state.uri) HTTP/1.1\r\n"
            }
        } else {
            requestLine = "\(method) \(state.uri) HTTP/1.1\r\n"
        }

        var request = requestLine
        request += "Host: \(host)\r\n"
        request += "User-Agent: lwIP/Swift\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"

        // Body headers for POST/PUT.
        if let body = state.body, !body.isEmpty {
            let ct = state.contentType ?? "application/octet-stream"
            request += "Content-Type: \(ct)\r\n"
            request += "Content-Length: \(body.count)\r\n"
        }

        request += "\r\n"
        return request
    }

    // MARK: - Internal: Connection Start

    /// Start the TCP connection and send the HTTP request.
    ///
    /// When a TLS configuration is present in the connection settings, the
    /// connection is established through the altcp TLS layer. When a proxy is
    /// configured, the connection goes through the proxy: for plain HTTP, we
    /// connect to the proxy and use an absolute URI in the request line; for
    /// HTTPS through a proxy, we use the CONNECT tunnel via
    /// `AltcpProxyConnect`.
    private func startRequest(_ state: HTTPClientState, address: IPAddress) {
        if let tlsConfig = state.settings.tlsConfig {
            if state.settings.useProxy, let proxyAddr = state.settings.proxyAddr {
                startRequestTLSProxy(state, address: address,
                                     tlsConfig: tlsConfig,
                                     proxyAddr: proxyAddr,
                                     proxyPort: state.settings.proxyPort)
            } else {
                startRequestTLS(state, address: address, tlsConfig: tlsConfig)
            }
        } else {
            startRequestPlain(state, address: address)
        }
    }

    /// Determine the connect address and port accounting for proxy settings.
    /// For plain-HTTP proxy requests, we connect to the proxy but send the
    /// full URL in the request line (handled by `buildRequestString`).
    private func connectTarget(_ state: HTTPClientState,
                               address: IPAddress) -> (IPAddress, UInt16) {
        if state.settings.useProxy && state.settings.tlsConfig == nil,
           let proxyAddr = state.settings.proxyAddr {
            return (proxyAddr, state.settings.proxyPort)
        }
        return (address, state.port)
    }

    /// Start a plain (non-TLS) TCP request.
    private func startRequestPlain(_ state: HTTPClientState, address: IPAddress) {
        guard let pcb = TCPGlobal.shared.new() else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }
        state.tcpControlBlock = pcb

        pcb.receiveHandler = { [weak self, weak state] pcb, pbuf, err in
            guard let self, let state else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .ok
            }

            if err != .ok {
                self.completeRequest(state, result: .errorClosed, err: err)
                return .ok
            }

            guard let pbuf else {
                self.completeRequest(state, result: self.finalResult(for: state))
                return .ok
            }

            let data = self.copyBytes(from: pbuf)
            TCPGlobal.shared.recved(pcb: pcb, len: pbuf.totLen)
            self.processResponseData(state, data: data)
            return .ok
        }

        pcb.errorHandler = { [weak self, weak state] err in
            guard let self, let state else { return }
            let result: HTTPClientResult = state.headersComplete || state.rxContentLen > 0
                ? .errorClosed
                : .errorConnect
            self.completeRequest(state, result: result, err: err)
        }

        // Build HTTP request.
        let host = state.hostname ?? address.description
        let request = buildRequestString(state, host: host)

        let requestBytes = Array(request.utf8)
        guard requestBytes.count <= Int(UInt16.max) else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }

        let (connectAddr, connectPort) = connectTarget(state, address: address)

        let connectErr = TCPGlobal.shared.connect(
            pcb: pcb,
            address: connectAddr,
            port: connectPort
        ) { [weak self, weak state] pcb, err in
            guard let self, let state else { return .ok }
            guard err == .ok else {
                self.completeRequest(state, result: .errorConnect, err: err)
                return .ok
            }

            // Write request headers.
            let writeErr = requestBytes.withUnsafeBytes { buffer -> LWIPError in
                guard let baseAddress = buffer.baseAddress else { return .invalidValue }
                return TCPGlobal.shared.write(
                    pcb: pcb,
                    data: baseAddress,
                    len: UInt16(requestBytes.count),
                    apiFlags: TCPConstants.writeFlagCopy
                )
            }
            guard writeErr == .ok else {
                let result: HTTPClientResult = writeErr == .outOfMemory ? .errorMemory : .errorConnect
                self.completeRequest(state, result: result, err: writeErr)
                return .ok
            }

            // Write request body if present.
            if let body = state.body, !body.isEmpty {
                let bodyWriteErr = body.withUnsafeBytes { buffer -> LWIPError in
                    guard let baseAddress = buffer.baseAddress else { return .invalidValue }
                    return TCPGlobal.shared.write(
                        pcb: pcb,
                        data: baseAddress,
                        len: UInt16(min(body.count, Int(UInt16.max))),
                        apiFlags: TCPConstants.writeFlagCopy
                    )
                }
                guard bodyWriteErr == .ok else {
                    let result: HTTPClientResult = bodyWriteErr == .outOfMemory ? .errorMemory : .errorConnect
                    self.completeRequest(state, result: result, err: bodyWriteErr)
                    return .ok
                }
            }

            let outputErr = TCPGlobal.shared.output(pcb: pcb)
            if outputErr != .ok {
                self.completeRequest(state, result: .errorConnect, err: outputErr)
            }
            return .ok
        }

        if connectErr != .ok {
            let result: HTTPClientResult = connectErr == .outOfMemory ? .errorMemory : .errorConnect
            completeRequest(state, result: result, err: connectErr)
        }
    }

    /// Start a TLS-secured request using the altcp layer.
    ///
    /// Creates an `AltcpControlBlock` via `AltcpTLS.new` and drives the
    /// connection through the altcp API, which handles the TLS handshake
    /// transparently before application data is exchanged.
    private func startRequestTLS(_ state: HTTPClientState, address: IPAddress,
                                  tlsConfig: AltcpTLSConfig) {
        guard let altcpPCB = AltcpTLS.new(config: tlsConfig) else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }
        state.altcpControlBlock = altcpPCB

        setupAltcpRecvErr(state, altcpPCB: altcpPCB)

        // Build HTTP request.
        let host = state.hostname ?? address.description
        let request = buildRequestString(state, host: host)

        let requestBytes = Array(request.utf8)
        guard requestBytes.count <= Int(UInt16.max) else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }

        let connectErr = altcpPCB.connect(
            ipaddr: address,
            port: state.port
        ) { [weak self, weak state] _, conn, err in
            guard let self, let state else { return .ok }
            guard err == .ok else {
                self.completeRequest(state, result: .errorConnect, err: err)
                return .ok
            }

            return self.sendRequestOnAltcp(state, conn: conn,
                                           requestBytes: requestBytes)
        }

        if connectErr != .ok {
            let result: HTTPClientResult = connectErr == .outOfMemory ? .errorMemory : .errorConnect
            completeRequest(state, result: result, err: connectErr)
        }
    }

    /// Start a TLS request tunneled through an HTTP CONNECT proxy.
    ///
    /// The altcp chain is: TLS -> ProxyConnect -> TCP.  The proxy connect
    /// layer handles the CONNECT handshake, then TLS negotiates over the
    /// established tunnel.
    private func startRequestTLSProxy(_ state: HTTPClientState, address: IPAddress,
                                       tlsConfig: AltcpTLSConfig,
                                       proxyAddr: IPAddress, proxyPort: UInt16) {
        let proxyConfig = AltcpProxyConnectConfig(
            proxyAddress: proxyAddr,
            proxyPort: proxyPort
        )
        guard let proxyPCB = AltcpControlBlock.proxyConnectTCP(config: proxyConfig) else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }

        // Wrap the proxy PCB with TLS. If AltcpTLS.wrapHandler is set, use it;
        // otherwise fall back to the proxy PCB alone (TLS wrapping is
        // platform-specific and may not be compiled in).
        let altcpPCB: AltcpControlBlock
        if let wrap = AltcpTLS.wrapHandler {
            guard let tlsPCB = wrap(tlsConfig, proxyPCB) else {
                _ = proxyPCB.close()
                completeRequest(state, result: .errorMemory, err: .outOfMemory)
                return
            }
            altcpPCB = tlsPCB
        } else {
            altcpPCB = proxyPCB
        }
        state.altcpControlBlock = altcpPCB

        setupAltcpRecvErr(state, altcpPCB: altcpPCB)

        // Build HTTP request (same as non-proxy TLS; the proxy tunnel is transparent).
        let host = state.hostname ?? address.description
        let request = buildRequestString(state, host: host)

        let requestBytes = Array(request.utf8)
        guard requestBytes.count <= Int(UInt16.max) else {
            completeRequest(state, result: .errorMemory, err: .outOfMemory)
            return
        }

        // Connect to the actual server address; the proxy connect layer will
        // intercept this and route through the proxy.
        let connectErr = altcpPCB.connect(
            ipaddr: address,
            port: state.port
        ) { [weak self, weak state] _, conn, err in
            guard let self, let state else { return .ok }
            guard err == .ok else {
                self.completeRequest(state, result: .errorConnect, err: err)
                return .ok
            }

            return self.sendRequestOnAltcp(state, conn: conn,
                                           requestBytes: requestBytes)
        }

        if connectErr != .ok {
            let result: HTTPClientResult = connectErr == .outOfMemory ? .errorMemory : .errorConnect
            completeRequest(state, result: result, err: connectErr)
        }
    }

    /// Set up receive and error handlers on an altcp PCB.
    private func setupAltcpRecvErr(_ state: HTTPClientState,
                                    altcpPCB: AltcpControlBlock) {
        altcpPCB.setRecv { [weak self, weak state] _, conn, pbuf, err in
            guard let self, let state else {
                if let pbuf { _ = Pbuf.free(pbuf) }
                return .ok
            }

            if err != .ok {
                self.completeRequest(state, result: .errorClosed, err: err)
                return .ok
            }

            guard let pbuf else {
                self.completeRequest(state, result: self.finalResult(for: state))
                return .ok
            }

            let data = self.copyBytes(from: pbuf)
            conn.recved(pbuf.totLen)
            self.processResponseData(state, data: data)
            return .ok
        }

        altcpPCB.setErr { [weak self, weak state] _, err in
            guard let self, let state else { return }
            let result: HTTPClientResult = state.headersComplete || state.rxContentLen > 0
                ? .errorClosed
                : .errorConnect
            self.completeRequest(state, result: result, err: err)
        }
    }

    /// Write the request header bytes (and optional body) on an altcp connection.
    private func sendRequestOnAltcp(_ state: HTTPClientState,
                                     conn: AltcpControlBlock,
                                     requestBytes: [UInt8]) -> LWIPError {
        let writeErr = requestBytes.withUnsafeBytes { buffer -> LWIPError in
            guard let baseAddress = buffer.baseAddress else { return .invalidValue }
            return conn.write(baseAddress, len: UInt16(requestBytes.count),
                              apiFlags: TCPConstants.writeFlagCopy)
        }
        guard writeErr == .ok else {
            let result: HTTPClientResult = writeErr == .outOfMemory ? .errorMemory : .errorConnect
            completeRequest(state, result: result, err: writeErr)
            return .ok
        }

        // Write request body if present.
        if let body = state.body, !body.isEmpty {
            let bodyWriteErr = body.withUnsafeBytes { buffer -> LWIPError in
                guard let baseAddress = buffer.baseAddress else { return .invalidValue }
                return conn.write(baseAddress,
                                  len: UInt16(min(body.count, Int(UInt16.max))),
                                  apiFlags: TCPConstants.writeFlagCopy)
            }
            guard bodyWriteErr == .ok else {
                let result: HTTPClientResult = bodyWriteErr == .outOfMemory ? .errorMemory : .errorConnect
                completeRequest(state, result: result, err: bodyWriteErr)
                return .ok
            }
        }

        let outputErr = conn.output()
        if outputErr != .ok {
            completeRequest(state, result: .errorConnect, err: outputErr)
        }
        return .ok
    }

    // MARK: - Internal: Response Processing

    /// Process received response data.
    internal func processResponseData(_ state: HTTPClientState, data: [UInt8]) {
        if !state.headersComplete {
            // Accumulate header data.
            state.headerBuffer.append(contentsOf: data)

            // Check for end of headers.
            if let headerEndRange = findHeaderEnd(state.headerBuffer) {
                state.headersComplete = true

                // Parse status code.
                parseStatusCode(state)

                // Parse content length.
                parseContentLength(state)

                // Detect Transfer-Encoding: chunked.
                parseTransferEncoding(state)

                // Handle redirects (3xx with Location header).
                if shouldRedirect(state) {
                    handleRedirect(state, headerEnd: headerEndRange)
                    return
                }

                // Notify headers-done callback.
                if let headersDone = state.settings.headersDoneCallback {
                    let headerLen = UInt16(headerEndRange)
                    let err = headersDone(
                        Array(state.headerBuffer[0..<headerEndRange]),
                        headerLen,
                        state.contentLength
                    )
                    if err != .ok {
                        completeRequest(state, result: .localAbort, err: err)
                        return
                    }
                }

                // Process body data that came with headers.
                if headerEndRange < state.headerBuffer.count {
                    let bodyData = Array(state.headerBuffer[headerEndRange...])
                    deliverBodyData(state, data: bodyData)
                }
                state.headerBuffer = []
            }
        } else {
            deliverBodyData(state, data: data)
        }
    }

    /// Deliver body data, decoding chunked transfer encoding when active.
    private func deliverBodyData(_ state: HTTPClientState, data: [UInt8]) {
        if state.isChunked {
            processChunkedData(state, data: data)
        } else {
            deliverData(state, data: data)
        }
    }

    /// Deliver decoded body data to the callback.
    private func deliverData(_ state: HTTPClientState, data: [UInt8]) {
        guard !data.isEmpty else { return }
        state.rxContentLen += UInt32(data.count)
        if let err = state.dataCallback?(data), err != .ok {
            completeRequest(state, result: .localAbort, err: err)
        }
    }

    // MARK: - Internal: Chunked Transfer Decoding

    /// Process data that uses chunked transfer encoding.
    ///
    /// Chunked encoding format:
    ///   <hex-size>\r\n
    ///   <data of hex-size bytes>\r\n
    ///   ...
    ///   0\r\n
    ///   \r\n   (optional trailers)
    private func processChunkedData(_ state: HTTPClientState, data: [UInt8]) {
        var offset = 0

        while offset < data.count {
            switch state.chunkParseState {
            case .expectSize:
                // Accumulate chunk size line until \r\n.
                while offset < data.count {
                    let byte = data[offset]
                    offset += 1
                    state.chunkSizeLine.append(byte)

                    // Check for \r\n at end of accumulated line.
                    if state.chunkSizeLine.count >= 2 {
                        let len = state.chunkSizeLine.count
                        if state.chunkSizeLine[len - 2] == 0x0D &&
                           state.chunkSizeLine[len - 1] == 0x0A {
                            // Parse hex size (strip any chunk-extension after ';').
                            let sizeBytes = Array(state.chunkSizeLine[0..<(len - 2)])
                            let sizeStr: String
                            if let semiIdx = sizeBytes.firstIndex(of: UInt8(ascii: ";")) {
                                sizeStr = String(bytes: sizeBytes[0..<semiIdx],
                                                 encoding: .utf8) ?? "0"
                            } else {
                                sizeStr = String(bytes: sizeBytes, encoding: .utf8) ?? "0"
                            }
                            let chunkSize = UInt64(
                                sizeStr.trimmingCharacters(in: .whitespaces),
                                radix: 16
                            ) ?? 0
                            state.chunkSizeLine = []

                            if chunkSize == 0 {
                                // Final chunk. Transition to trailers.
                                state.chunkParseState = .trailers
                            } else {
                                state.currentChunkRemaining = Int(chunkSize)
                                state.chunkParseState = .readingData
                            }
                            break
                        }
                    }
                }

            case .readingData:
                let available = data.count - offset
                let toRead = min(available, state.currentChunkRemaining)
                if toRead > 0 {
                    let chunk = Array(data[offset..<(offset + toRead)])
                    offset += toRead
                    state.currentChunkRemaining -= toRead
                    deliverData(state, data: chunk)
                }
                if state.currentChunkRemaining == 0 {
                    state.chunkParseState = .expectDataCRLF
                }

            case .expectDataCRLF:
                // Consume the \r\n after chunk data.
                while offset < data.count {
                    let byte = data[offset]
                    offset += 1
                    state.chunkSizeLine.append(byte)
                    if state.chunkSizeLine.count == 2 {
                        // Should be \r\n; either way, move on.
                        state.chunkSizeLine = []
                        state.chunkParseState = .expectSize
                        break
                    }
                }

            case .trailers:
                // Consume trailer headers until an empty line (\r\n).
                while offset < data.count {
                    let byte = data[offset]
                    offset += 1
                    state.chunkSizeLine.append(byte)
                    if state.chunkSizeLine.count >= 2 {
                        let len = state.chunkSizeLine.count
                        if state.chunkSizeLine[len - 2] == 0x0D &&
                           state.chunkSizeLine[len - 1] == 0x0A {
                            if len == 2 {
                                // Empty line -> end of trailers.
                                state.chunkParseState = .done
                                state.chunkSizeLine = []
                                return
                            }
                            // Non-empty trailer line; reset for next trailer.
                            state.chunkSizeLine = []
                        }
                    }
                }

            case .done:
                // All chunks received; ignore any trailing bytes.
                return
            }
        }
    }

    // MARK: - Internal: Redirect Following

    /// Determine if the response is a redirect we should follow.
    private func shouldRedirect(_ state: HTTPClientState) -> Bool {
        guard state.settings.maxRedirects > 0 else { return false }
        guard state.redirectCount < state.settings.maxRedirects else { return false }
        let code = state.httpStatusCode
        return code == 301 || code == 302 || code == 303 ||
               code == 307 || code == 308
    }

    /// Handle a redirect by closing the current connection and re-issuing
    /// the request to the Location URL.
    private func handleRedirect(_ state: HTTPClientState, headerEnd: Int) {
        guard let location = parseLocationHeader(state) else {
            // No Location header; treat as a normal response.
            redeliverAfterHeadersParsed(state, headerEnd: headerEnd)
            return
        }

        // Close the current connection.
        if let pcb = state.tcpControlBlock {
            state.tcpControlBlock = nil
            closePCB(pcb)
        }
        if let altcpPCB = state.altcpControlBlock {
            state.altcpControlBlock = nil
            closeAltcpPCB(altcpPCB)
        }

        // Parse the redirect URL.
        let parsed = parseURL(location, currentHost: state.hostname,
                              currentPort: state.port,
                              currentTLS: state.settings.tlsConfig != nil)

        // For 303, change method to GET and drop the body.
        var newMethod = state.method
        var newBody = state.body
        var newContentType = state.contentType
        if state.httpStatusCode == 303 {
            newMethod = .get
            newBody = nil
            newContentType = nil
        }

        // Reset state for the new request.
        state.redirectCount += 1
        state.method = newMethod
        state.body = newBody
        state.contentType = newContentType
        state.uri = parsed.uri
        state.port = parsed.port
        state.hostname = parsed.host
        state.headerBuffer = []
        state.headersComplete = false
        state.httpStatusCode = 0
        state.contentLength = -1
        state.rxContentLen = 0
        state.isChunked = false
        state.chunkParseState = .expectSize
        state.currentChunkRemaining = 0
        state.chunkSizeLine = []

        // Resolve and connect to the new location.
        if let host = parsed.host {
            TCPIP.shared.callback { [weak self] in
                switch NetConn.getHostByName(host) {
                case .success(let addr):
                    self?.startRequest(state, address: addr)
                case .failure:
                    self?.completeRequest(state, result: .errorHostname, err: .invalidValue)
                }
            }
        } else {
            completeRequest(state, result: .errorRedirect, err: .invalidValue)
        }
    }

    /// Re-deliver headers and body when a redirect check decided not to redirect.
    private func redeliverAfterHeadersParsed(_ state: HTTPClientState, headerEnd: Int) {
        if let headersDone = state.settings.headersDoneCallback {
            let headerLen = UInt16(headerEnd)
            let err = headersDone(
                Array(state.headerBuffer[0..<headerEnd]),
                headerLen,
                state.contentLength
            )
            if err != .ok {
                completeRequest(state, result: .localAbort, err: err)
                return
            }
        }

        if headerEnd < state.headerBuffer.count {
            let bodyData = Array(state.headerBuffer[headerEnd...])
            deliverBodyData(state, data: bodyData)
        }
        state.headerBuffer = []
    }

    /// Parse the Location header value from the response headers.
    private func parseLocationHeader(_ state: HTTPClientState) -> String? {
        guard let headerStr = String(bytes: state.headerBuffer, encoding: .utf8) else {
            return nil
        }

        let lines = headerStr.split(separator: "\r\n")
        for line in lines {
            let lower = line.lowercased()
            if lower.hasPrefix("location:") {
                let value = line.dropFirst("location:".count)
                    .trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    /// Minimal URL parser for redirect targets. Handles absolute URLs and
    /// relative paths.
    private func parseURL(_ urlString: String, currentHost: String?,
                          currentPort: UInt16, currentTLS: Bool)
        -> (host: String?, port: UInt16, uri: String, isTLS: Bool) {

        // Absolute URL.
        if urlString.lowercased().hasPrefix("http://") ||
           urlString.lowercased().hasPrefix("https://") {
            let isTLS = urlString.lowercased().hasPrefix("https://")
            let withoutScheme: String
            if isTLS {
                withoutScheme = String(urlString.dropFirst("https://".count))
            } else {
                withoutScheme = String(urlString.dropFirst("http://".count))
            }

            let pathStart = withoutScheme.firstIndex(of: "/") ?? withoutScheme.endIndex
            let hostPort = String(withoutScheme[..<pathStart])
            let uri = pathStart < withoutScheme.endIndex
                ? String(withoutScheme[pathStart...])
                : "/"

            let defaultPort: UInt16 = isTLS
                ? HTTPClient.defaultHTTPSPort
                : HTTPClient.defaultPort

            if let colonIdx = hostPort.lastIndex(of: ":") {
                let host = String(hostPort[..<colonIdx])
                let portStr = String(hostPort[hostPort.index(after: colonIdx)...])
                let port = UInt16(portStr) ?? defaultPort
                return (host, port, uri, isTLS)
            } else {
                return (hostPort, defaultPort, uri, isTLS)
            }
        }

        // Relative URL (starts with /).
        if urlString.hasPrefix("/") {
            return (currentHost, currentPort, urlString, currentTLS)
        }

        // Relative URL without leading slash.
        return (currentHost, currentPort, "/" + urlString, currentTLS)
    }

    // MARK: - Internal: Completion

    /// Complete a request and notify the result callback.
    private func completeRequest(_ state: HTTPClientState, result: HTTPClientResult,
                                 err: LWIPError = .ok) {
        lock.lock()
        let shouldComplete: Bool
        if let index = activeRequests.firstIndex(where: { $0 === state }) {
            activeRequests.remove(at: index)
            shouldComplete = true
        } else {
            shouldComplete = false
        }
        lock.unlock()

        guard shouldComplete else { return }

        if let pcb = state.tcpControlBlock {
            state.tcpControlBlock = nil
            closePCB(pcb)
        }

        if let altcpPCB = state.altcpControlBlock {
            state.altcpControlBlock = nil
            closeAltcpPCB(altcpPCB)
        }

        state.settings.resultCallback?(
            result, state.rxContentLen, state.httpStatusCode, err
        )
    }

    // MARK: - Internal: Header Parsing

    /// Find the end of HTTP headers (\r\n\r\n).
    private func findHeaderEnd(_ data: [UInt8]) -> Int? {
        let pattern: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]  // \r\n\r\n
        guard data.count >= 4 else { return nil }

        for i in 0...(data.count - 4) {
            if data[i] == pattern[0] && data[i+1] == pattern[1] &&
               data[i+2] == pattern[2] && data[i+3] == pattern[3] {
                return i + 4
            }
        }
        return nil
    }

    /// Parse HTTP status code from headers.
    private func parseStatusCode(_ state: HTTPClientState) {
        // Look for "HTTP/1.x NNN"
        let header = state.headerBuffer
        guard header.count > 12 else { return }

        // Find the status code after "HTTP/1.x "
        var i = 0
        while i < header.count && header[i] != UInt8(ascii: " ") { i += 1 }
        i += 1  // Skip space

        var code: UInt32 = 0
        while i < header.count && header[i] >= UInt8(ascii: "0") && header[i] <= UInt8(ascii: "9") {
            code = code * 10 + UInt32(header[i] - UInt8(ascii: "0"))
            i += 1
        }
        state.httpStatusCode = code
    }

    /// Parse Content-Length from headers.
    private func parseContentLength(_ state: HTTPClientState) {
        guard let headerStr = String(bytes: state.headerBuffer, encoding: .utf8) else { return }

        let lines = headerStr.split(separator: "\r\n")
        for line in lines {
            let lower = line.lowercased()
            if lower.hasPrefix("content-length:") {
                let value = line.dropFirst("content-length:".count)
                    .trimmingCharacters(in: .whitespaces)
                if let len = Int32(value) {
                    state.contentLength = len
                }
                break
            }
        }
    }

    /// Parse Transfer-Encoding header to detect chunked encoding.
    private func parseTransferEncoding(_ state: HTTPClientState) {
        guard let headerStr = String(bytes: state.headerBuffer, encoding: .utf8) else { return }

        let lines = headerStr.split(separator: "\r\n")
        for line in lines {
            let lower = line.lowercased()
            if lower.hasPrefix("transfer-encoding:") {
                let value = line.dropFirst("transfer-encoding:".count)
                    .trimmingCharacters(in: .whitespaces)
                    .lowercased()
                if value.contains("chunked") {
                    state.isChunked = true
                    // With chunked encoding, Content-Length is not authoritative.
                    state.contentLength = -1
                }
                break
            }
        }
    }
}
