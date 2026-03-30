//
//  TFTP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - TFTP Configuration

/// TFTP configuration constants.
public enum TFTPConfig {
    /// TFTP server port.
    public static let port: UInt16 = 69
    /// Maximum retries.
    public static var maxRetries: Int = 5
    /// Timeout in milliseconds.
    public static var timeoutMs: UInt32 = 3000
    /// Maximum block size (data payload per packet).
    public static var blockSize: Int = 512
    /// Timer interval in milliseconds.
    public static var timerMs: UInt32 = 50
}

// MARK: - TFTP Opcodes

/// TFTP packet opcodes (RFC 1350).
public enum TFTPOpcode: UInt16, Sendable {
    /// Read request.
    case rrq   = 1
    /// Write request.
    case wrq   = 2
    /// Data packet.
    case data  = 3
    /// Acknowledgment.
    case ack   = 4
    /// Error.
    case error = 5
}

// MARK: - TFTP Error Codes

/// TFTP error codes (RFC 1350).
public enum TFTPError: UInt16, Sendable {
    case notDefined       = 0
    case fileNotFound     = 1
    case accessViolation  = 2
    case diskFull         = 3
    case illegalOperation = 4
    case unknownTransfer  = 5
    case fileExists       = 6
    case noSuchUser       = 7
}

// MARK: - TFTP Transfer Mode

/// TFTP transfer mode.
public enum TFTPTransferMode: Sendable {
    /// Binary/octet mode (preferred).
    case octet
    /// ASCII/netascii mode.
    case netascii

    /// String representation for the wire protocol.
    public var wireString: String {
        switch self {
        case .octet:    return "octet"
        case .netascii: return "netascii"
        }
    }
}

// MARK: - TFTP Mode Flags

/// TFTP operation mode flags.
public struct TFTPMode: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Server mode.
    public static let server       = TFTPMode(rawValue: 0x01)
    /// Client mode.
    public static let client       = TFTPMode(rawValue: 0x02)
    /// Both server and client.
    public static let clientServer: TFTPMode = [.server, .client]
}

// MARK: - TFTPContext

/// Callback context for TFTP file operations.
///
/// Implement this protocol to provide file I/O for TFTP transfers.
public protocol TFTPContext: AnyObject, Sendable {
    /// Open a file for read or write.
    ///
    /// - Parameters:
    ///   - filename: The filename from the TFTP request.
    ///   - mode: Transfer mode string ("octet", "netascii").
    ///   - isWrite: `true` for write (WRQ), `false` for read (RRQ).
    /// - Returns: A file handle, or `nil` on error.
    func open(filename: String, mode: String, isWrite: Bool) -> AnyObject?

    /// Close a file handle.
    ///
    /// - Parameter handle: The file handle from `open` or client get/put.
    func close(handle: AnyObject)

    /// Read data from a file.
    ///
    /// - Parameters:
    ///   - handle: The file handle.
    ///   - buffer: Buffer to read into.
    ///   - maxBytes: Maximum bytes to read.
    /// - Returns: Number of bytes read, or negative on error.
    func read(handle: AnyObject, buffer: UnsafeMutableRawPointer, maxBytes: Int) -> Int

    /// Write data to a file.
    ///
    /// - Parameters:
    ///   - handle: The file handle.
    ///   - data: The data to write (pbuf).
    /// - Returns: Number of bytes written, or negative on error.
    func write(handle: AnyObject, data: Pbuf) -> Int

    /// Error callback.
    ///
    /// - Parameters:
    ///   - handle: The file handle (may be nil).
    ///   - errorCode: TFTP error code.
    ///   - message: Error message.
    func error(handle: AnyObject?, errorCode: Int, message: String)
}

// MARK: - TFTPState

/// Internal state for an active TFTP transfer.
internal final class TFTPState: @unchecked Sendable {
    /// File handle from the context.
    var handle: AnyObject?
    /// Remote address.
    var remoteAddr: IPAddress = .any
    /// Remote port.
    var remotePort: UInt16 = 0
    /// Current block number.
    var blockNumber: UInt16 = 0
    /// Last data packet for retransmission.
    var lastData: [UInt8] = []
    /// Retry counter.
    var retries: Int = 0
    /// Timer counter.
    var timerCounter: UInt32 = 0
    /// Whether this is a write (receiving data) transfer.
    var isWrite: Bool = false
    /// Whether the transfer is complete.
    var isComplete: Bool = false
}

// MARK: - TFTP

/// TFTP server and client implementation.
///
/// Supports RFC 1350 TFTP with octet and netascii modes.
public final class TFTP: @unchecked Sendable {

    /// Shared instance.
    public static let shared = TFTP()

    /// Operating mode.
    private var mode: TFTPMode = []

    /// File I/O context.
    private var context: TFTPContext?

    /// UDP control block.
    private var udpControlBlock: UDPControlBlock?

    /// Active transfer state.
    private var activeTransfer: TFTPState?

    /// Lock.
    private let lock = NSLock()

    private init() {}

    // MARK: - Server

    /// Initialize the TFTP server.
    ///
    /// - Parameter ctx: File I/O context for serving files.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func initServer(_ ctx: TFTPContext) -> LWIPError {
        return initCommon(mode: .server, ctx: ctx)
    }

    // MARK: - Client

    /// Initialize the TFTP client.
    ///
    /// - Parameter ctx: File I/O context for storing/reading files.
    /// - Returns: `.ok` on success.
    @discardableResult
    public func initClient(_ ctx: TFTPContext) -> LWIPError {
        return initCommon(mode: .client, ctx: ctx)
    }

    /// Download a file from a TFTP server (client GET).
    ///
    /// - Parameters:
    ///   - handle: File handle to write received data to.
    ///   - addr: Server address.
    ///   - port: Server port (default: 69).
    ///   - filename: Remote filename.
    ///   - mode: Transfer mode.
    /// - Returns: `.ok` if the request was sent.
    @discardableResult
    public func get(
        handle: AnyObject,
        addr: IPAddress,
        port: UInt16 = TFTPConfig.port,
        filename: String,
        mode: TFTPTransferMode = .octet
    ) -> LWIPError {
        lock.lock()
        guard self.mode.contains(.client) else { lock.unlock(); return .invalidValue }
        guard activeTransfer == nil else { lock.unlock(); return .addressInUse }

        let state = TFTPState()
        state.handle = handle
        state.remoteAddr = addr
        state.remotePort = port
        state.isWrite = true  // We are writing received data
        state.blockNumber = 0
        activeTransfer = state
        lock.unlock()

        // Send RRQ.
        let packet = buildRequestPacket(opcode: .rrq, filename: filename, mode: mode)
        sendPacket(packet, to: addr, port: port)

        return .ok
    }

    /// Upload a file to a TFTP server (client PUT).
    ///
    /// - Parameters:
    ///   - handle: File handle to read data from.
    ///   - addr: Server address.
    ///   - port: Server port.
    ///   - filename: Remote filename.
    ///   - mode: Transfer mode.
    /// - Returns: `.ok` if the request was sent.
    @discardableResult
    public func put(
        handle: AnyObject,
        addr: IPAddress,
        port: UInt16 = TFTPConfig.port,
        filename: String,
        mode: TFTPTransferMode = .octet
    ) -> LWIPError {
        lock.lock()
        guard self.mode.contains(.client) else { lock.unlock(); return .invalidValue }
        guard activeTransfer == nil else { lock.unlock(); return .addressInUse }

        let state = TFTPState()
        state.handle = handle
        state.remoteAddr = addr
        state.remotePort = port
        state.isWrite = false  // We are reading and sending data
        state.blockNumber = 0
        activeTransfer = state
        lock.unlock()

        // Send WRQ.
        let packet = buildRequestPacket(opcode: .wrq, filename: filename, mode: mode)
        sendPacket(packet, to: addr, port: port)

        return .ok
    }

    // MARK: - Common

    /// Initialize TFTP with a mode and context.
    @discardableResult
    private func initCommon(mode: TFTPMode, ctx: TFTPContext) -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard udpControlBlock == nil else { return .addressInUse }

        self.mode = mode
        self.context = ctx

        // Create UDP PCB.
        let udpPcb = UDPControlBlock()

        // Bind to TFTP port if server mode.
        if mode.contains(.server) {
            let err = UDPGlobal.shared.bind(udpPcb, address: .any, port: TFTPConfig.port)
            if err != .ok {
                UDPGlobal.shared.remove(udpPcb)
                return err
            }
        }

        // Set receive callback.
        udpPcb.receiveHandler = { [weak self] _, pbuf, addr, port in
            guard let self = self else { return }
            // Extract raw bytes from the pbuf.
            let totalLen = Int(pbuf.totLen)
            var data = [UInt8](repeating: 0, count: totalLen)
            data.withUnsafeMutableBufferPointer { buf in
                guard let base = buf.baseAddress else { return }
                _ = pbuf.copyPartial(to: UnsafeMutableRawPointer(base),
                                     len: UInt16(totalLen), offset: 0)
            }
            _ = Pbuf.free(pbuf)
            self.processReceived(data: data, from: addr, port: port)
        }

        udpControlBlock = udpPcb
        return .ok
    }

    /// Clean up the TFTP module.
    public func cleanup() {
        lock.lock()

        if let state = activeTransfer, let handle = state.handle {
            context?.close(handle: handle)
        }
        activeTransfer = nil

        if let udpPcb = udpControlBlock {
            UDPGlobal.shared.remove(udpPcb)
            udpControlBlock = nil
        }

        context = nil
        mode = []

        lock.unlock()
    }

    // MARK: - Packet Building

    /// Build a request packet (RRQ or WRQ).
    private func buildRequestPacket(opcode: TFTPOpcode, filename: String,
                                    mode: TFTPTransferMode) -> [UInt8] {
        var packet: [UInt8] = []
        // Opcode (2 bytes, big-endian).
        packet.append(UInt8(opcode.rawValue >> 8))
        packet.append(UInt8(opcode.rawValue & 0xFF))
        // Filename (null-terminated).
        packet.append(contentsOf: Array(filename.utf8))
        packet.append(0)
        // Mode (null-terminated).
        packet.append(contentsOf: Array(mode.wireString.utf8))
        packet.append(0)
        return packet
    }

    /// Build an ACK packet.
    private func buildAckPacket(blockNumber: UInt16) -> [UInt8] {
        var packet: [UInt8] = []
        packet.append(UInt8(TFTPOpcode.ack.rawValue >> 8))
        packet.append(UInt8(TFTPOpcode.ack.rawValue & 0xFF))
        packet.append(UInt8(blockNumber >> 8))
        packet.append(UInt8(blockNumber & 0xFF))
        return packet
    }

    /// Build a DATA packet.
    private func buildDataPacket(blockNumber: UInt16, data: [UInt8]) -> [UInt8] {
        var packet: [UInt8] = []
        packet.append(UInt8(TFTPOpcode.data.rawValue >> 8))
        packet.append(UInt8(TFTPOpcode.data.rawValue & 0xFF))
        packet.append(UInt8(blockNumber >> 8))
        packet.append(UInt8(blockNumber & 0xFF))
        packet.append(contentsOf: data)
        return packet
    }

    /// Build an ERROR packet.
    private func buildErrorPacket(code: TFTPError, message: String) -> [UInt8] {
        var packet: [UInt8] = []
        packet.append(UInt8(TFTPOpcode.error.rawValue >> 8))
        packet.append(UInt8(TFTPOpcode.error.rawValue & 0xFF))
        packet.append(UInt8(code.rawValue >> 8))
        packet.append(UInt8(code.rawValue & 0xFF))
        packet.append(contentsOf: Array(message.utf8))
        packet.append(0)
        return packet
    }

    // MARK: - Packet Sending

    /// Send a TFTP packet.
    private func sendPacket(_ packet: [UInt8], to addr: IPAddress, port: UInt16) {
        guard let udpPcb = udpControlBlock else { return }
        guard let p = Pbuf.alloc(layer: .transport, length: UInt16(packet.count), type: .ram) else {
            return
        }
        packet.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            p.payload.copyMemory(from: base, byteCount: packet.count)
        }
        _ = UDPGlobal.shared.sendTo(udpPcb, pbuf: p, dstIP: addr, dstPort: port)
        _ = Pbuf.free(p)
    }

    // MARK: - Receive Processing

    /// Process a received TFTP packet.
    internal func processReceived(data: [UInt8], from: IPAddress, port: UInt16) {
        guard data.count >= 4 else { return }

        let opcode = (UInt16(data[0]) << 8) | UInt16(data[1])
        guard let op = TFTPOpcode(rawValue: opcode) else { return }

        lock.lock()
        let ctx = context
        lock.unlock()

        switch op {
        case .rrq:
            // Server: handle read request.
            guard mode.contains(.server) else { return }
            handleReadRequest(data: data, from: from, port: port)

        case .wrq:
            // Server: handle write request.
            guard mode.contains(.server) else { return }
            handleWriteRequest(data: data, from: from, port: port)

        case .data:
            // Received data (response to RRQ or WRQ from server).
            handleDataPacket(data: data, from: from, port: port)

        case .ack:
            // Received ACK (response to our DATA packet).
            handleAckPacket(data: data, from: from, port: port)

        case .error:
            // Received error.
            let errorCode = (UInt16(data[2]) << 8) | UInt16(data[3])
            let message = data.count > 4 ?
                String(bytes: data[4...], encoding: .utf8) ?? "Unknown error" : "Unknown error"

            lock.lock()
            if let state = activeTransfer {
                ctx?.error(handle: state.handle, errorCode: Int(errorCode), message: message)
                if let handle = state.handle { ctx?.close(handle: handle) }
                activeTransfer = nil
            }
            lock.unlock()
        }
    }

    /// Handle a read request (server mode).
    private func handleReadRequest(data: [UInt8], from: IPAddress, port: UInt16) {
        guard let (filename, modeStr) = parseRequestPacket(data) else { return }

        lock.lock()
        let ctx = context
        guard activeTransfer == nil else {
            lock.unlock()
            let errPkt = buildErrorPacket(code: .notDefined, message: "Busy")
            sendPacket(errPkt, to: from, port: port)
            return
        }

        guard let handle = ctx?.open(filename: filename, mode: modeStr, isWrite: false) else {
            lock.unlock()
            let errPkt = buildErrorPacket(code: .fileNotFound, message: "File not found")
            sendPacket(errPkt, to: from, port: port)
            return
        }

        let state = TFTPState()
        state.handle = handle
        state.remoteAddr = from
        state.remotePort = port
        state.isWrite = false
        state.blockNumber = 1
        activeTransfer = state
        lock.unlock()

        // Send first data block.
        sendNextDataBlock()
    }

    /// Handle a write request (server mode).
    private func handleWriteRequest(data: [UInt8], from: IPAddress, port: UInt16) {
        guard let (filename, modeStr) = parseRequestPacket(data) else { return }

        lock.lock()
        let ctx = context

        guard activeTransfer == nil else {
            lock.unlock()
            let errPkt = buildErrorPacket(code: .notDefined, message: "Busy")
            sendPacket(errPkt, to: from, port: port)
            return
        }

        guard let handle = ctx?.open(filename: filename, mode: modeStr, isWrite: true) else {
            lock.unlock()
            let errPkt = buildErrorPacket(code: .accessViolation, message: "Cannot write")
            sendPacket(errPkt, to: from, port: port)
            return
        }

        let state = TFTPState()
        state.handle = handle
        state.remoteAddr = from
        state.remotePort = port
        state.isWrite = true
        state.blockNumber = 0
        activeTransfer = state
        lock.unlock()

        // Send ACK for block 0.
        let ack = buildAckPacket(blockNumber: 0)
        sendPacket(ack, to: from, port: port)
    }

    /// Handle a received DATA packet.
    private func handleDataPacket(data: [UInt8], from: IPAddress, port: UInt16) {
        guard data.count >= 4 else { return }
        let blockNumber = (UInt16(data[2]) << 8) | UInt16(data[3])
        let payload = Array(data[4...])

        lock.lock()
        guard let state = activeTransfer, state.isWrite else { lock.unlock(); return }
        let ctx = context

        if blockNumber == state.blockNumber + 1 {
            state.blockNumber = blockNumber
            state.remotePort = port

            // Write data to file.
            if !payload.isEmpty {
                let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(payload.count), type: .ram)
                if let p = pbuf {
                    let payloadPtr = p.payload
                    payload.withUnsafeBytes { ptr in
                        payloadPtr.copyMemory(from: ptr.baseAddress!, byteCount: payload.count)
                    }
                    _ = ctx?.write(handle: state.handle!, data: p)
                }
            }

            // Check for end of transfer (block < 512 bytes).
            if payload.count < TFTPConfig.blockSize {
                state.isComplete = true
                if let handle = state.handle { ctx?.close(handle: handle) }
                activeTransfer = nil
            }
        }

        lock.unlock()

        // Send ACK.
        let ack = buildAckPacket(blockNumber: blockNumber)
        sendPacket(ack, to: from, port: port)
    }

    /// Handle a received ACK packet.
    private func handleAckPacket(data: [UInt8], from: IPAddress, port: UInt16) {
        guard data.count >= 4 else { return }
        let blockNumber = (UInt16(data[2]) << 8) | UInt16(data[3])

        lock.lock()
        guard let state = activeTransfer, !state.isWrite else { lock.unlock(); return }

        if blockNumber == state.blockNumber || (state.blockNumber == 1 && blockNumber == 0) {
            state.retries = 0
            state.remotePort = port

            if state.isComplete {
                let ctx = context
                if let handle = state.handle { ctx?.close(handle: handle) }
                activeTransfer = nil
                lock.unlock()
                return
            }

            state.blockNumber = blockNumber + 1
            lock.unlock()
            sendNextDataBlock()
        } else {
            lock.unlock()
        }
    }

    /// Read and send the next data block.
    private func sendNextDataBlock() {
        lock.lock()
        guard let state = activeTransfer, !state.isWrite else { lock.unlock(); return }
        let ctx = context
        guard let handle = state.handle else { lock.unlock(); return }
        lock.unlock()

        // Read data from file.
        var buffer = [UInt8](repeating: 0, count: TFTPConfig.blockSize)
        let bytesRead = buffer.withUnsafeMutableBytes { ptr -> Int in
            return ctx?.read(handle: handle, buffer: ptr.baseAddress!, maxBytes: TFTPConfig.blockSize) ?? -1
        }

        if bytesRead < 0 {
            // Read error.
            let errPkt = buildErrorPacket(code: .notDefined, message: "Read error")
            lock.lock()
            sendPacket(errPkt, to: state.remoteAddr, port: state.remotePort)
            ctx?.close(handle: handle)
            activeTransfer = nil
            lock.unlock()
            return
        }

        let dataToSend = Array(buffer[0..<bytesRead])

        lock.lock()
        let packet = buildDataPacket(blockNumber: state.blockNumber, data: dataToSend)
        state.lastData = packet

        if bytesRead < TFTPConfig.blockSize {
            state.isComplete = true
        }

        sendPacket(packet, to: state.remoteAddr, port: state.remotePort)
        lock.unlock()
    }

    /// Parse a request packet (RRQ or WRQ) to extract filename and mode.
    private func parseRequestPacket(_ data: [UInt8]) -> (String, String)? {
        guard data.count > 4 else { return nil }

        // Skip opcode (2 bytes).
        var idx = 2
        var filename: String = ""
        var mode: String = ""

        // Read filename (null-terminated).
        var start = idx
        while idx < data.count && data[idx] != 0 { idx += 1 }
        guard idx < data.count else { return nil }
        filename = String(bytes: data[start..<idx], encoding: .utf8) ?? ""
        idx += 1  // Skip null.

        // Read mode (null-terminated).
        start = idx
        while idx < data.count && data[idx] != 0 { idx += 1 }
        mode = String(bytes: data[start..<idx], encoding: .utf8) ?? ""

        return (filename, mode.lowercased())
    }
}

