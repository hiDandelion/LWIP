//
//  PPPTransport.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - HDLC Constants

/// HDLC/PPPoS framing constants
public struct HDLC {
    public static let flag: UInt8    = 0x7E  // Frame delimiter
    public static let escape: UInt8  = 0x7D  // Escape character
    public static let address: UInt8 = 0xFF  // All-stations address
    public static let control: UInt8 = 0x03  // Unnumbered information
    public static let xorMask: UInt8 = 0x20  // XOR mask for escaped bytes
}

/// PPPoS FCS constants.
public extension PPPoS {
    /// FCS-16 initial value.
    static let fcsInitial: UInt16 = 0xFFFF
    /// FCS-16 good final value.
    static let fcsGood: UInt16 = 0xF0B8
}

// MARK: - PPPoS Receive State

public enum PPPoSRecvState: UInt8, Sendable {
    case idle     = 0
    case address  = 1
    case control  = 2
    case protocol1 = 3
    case protocol2 = 4
    case data     = 5
    case escape   = 6
}

// MARK: - PPPoS (PPP over Serial)

/// PPP over Serial transport layer.
///
/// Implements HDLC-like framing for PPP over asynchronous serial links.
/// Handles byte-stuffing, FCS computation, and ACCM (Async Control Character Map).
public final class PPPoS: @unchecked Sendable, PPPTransportProtocol {

    /// FCS-16 lookup table for PPP CRC calculation.
    public static let fcsTable: [UInt16] = {
        var table = [UInt16](repeating: 0, count: 256)
        for i in 0..<256 {
            var fcs: UInt16 = UInt16(i)
            for _ in 0..<8 {
                if (fcs & 1) != 0 {
                    fcs = (fcs >> 1) ^ 0x8408
                } else {
                    fcs >>= 1
                }
            }
            table[i] = fcs
        }
        return table
    }()

    /// Calculate PPP FCS-16 for a single byte.
    public static func fcs16(_ fcs: UInt16, _ byte: UInt8) -> UInt16 {
        return (fcs >> 8) ^ PPPoS.fcsTable[Int((fcs ^ UInt16(byte)) & 0xFF)]
    }

    /// Calculate FCS-16 over a buffer.
    public static func fcs16(initial: UInt16, data: [UInt8]) -> UInt16 {
        var fcs = initial
        for byte in data {
            fcs = PPPoS.fcs16(fcs, byte)
        }
        return fcs
    }

    /// Parent PPP PCB
    public weak var pcb: PPPControlBlock?
    /// Serial I/O device
    public var serialDevice: SerialIO?

    /// Receive state
    private var rxState: PPPoSRecvState = .idle
    /// Receive buffer
    private var rxBuffer: [UInt8] = []
    /// Receive FCS
    private var rxFCS: UInt16 = PPPoS.fcsInitial
    /// Receive protocol (accumulated)
    private var rxProtocol: UInt16 = 0
    /// Flag indicating if in escape state
    private var rxEscaped: Bool = false

    /// TX Async Control Character Map
    public var txACCM: UInt32 = 0xFFFFFFFF
    /// RX Async Control Character Map
    public var rxACCM: UInt32 = 0xFFFFFFFF

    /// Maximum receive buffer size
    public var maxRxSize: Int = 1500 + 4

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    // MARK: - PPPTransportProtocol

    public func connect() {
        rxState = .idle
        rxBuffer = []
        rxFCS = PPPoS.fcsInitial
    }

    public func disconnect() {
        rxState = .idle
        rxBuffer = []
    }

    /// Send a PPP packet over serial with HDLC framing
    public func sendPacket(pbuf: Pbuf, protocol proto: UInt16) {
        guard let sio = serialDevice else { return }

        var fcs: UInt16 = PPPoS.fcsInitial

        // Start flag
        sio.send(HDLC.flag)

        // Address + Control (if not compressed)
        fcs = sendByteEscaped(sio: sio, byte: HDLC.address, fcs: fcs)
        fcs = sendByteEscaped(sio: sio, byte: HDLC.control, fcs: fcs)

        // Protocol
        if proto > 0xFF {
            fcs = sendByteEscaped(sio: sio, byte: UInt8(proto >> 8), fcs: fcs)
        }
        fcs = sendByteEscaped(sio: sio, byte: UInt8(proto & 0xFF), fcs: fcs)

        // Data from pbuf payload via raw pointer
        let payloadPtr = pbuf.payload
        for i in 0..<Int(pbuf.totLen) {
            let byte: UInt8 = payloadPtr[i]
            fcs = sendByteEscaped(sio: sio, byte: byte, fcs: fcs)
        }

        // FCS (complement, LSB first)
        fcs = ~fcs
        sendByteEscapedNoFCS(sio: sio, byte: UInt8(fcs & 0xFF))
        sendByteEscapedNoFCS(sio: sio, byte: UInt8(fcs >> 8))

        // End flag
        sio.send(HDLC.flag)
    }

    /// Send a single byte with HDLC byte-stuffing, updating FCS
    private func sendByteEscaped(sio: SerialIO, byte: UInt8, fcs: UInt16) -> UInt16 {
        let newFCS = PPPoS.fcs16(fcs, byte)

        // Check if byte needs escaping
        if byte < 0x20 && (txACCM & (1 << UInt32(byte))) != 0 {
            sio.send(HDLC.escape)
            sio.send(byte ^ HDLC.xorMask)
        } else if byte == HDLC.flag || byte == HDLC.escape {
            sio.send(HDLC.escape)
            sio.send(byte ^ HDLC.xorMask)
        } else {
            sio.send(byte)
        }
        return newFCS
    }

    /// Send a single byte with HDLC byte-stuffing, without FCS update
    private func sendByteEscapedNoFCS(sio: SerialIO, byte: UInt8) {
        if byte < 0x20 && (txACCM & (1 << UInt32(byte))) != 0 {
            sio.send(HDLC.escape)
            sio.send(byte ^ HDLC.xorMask)
        } else if byte == HDLC.flag || byte == HDLC.escape {
            sio.send(HDLC.escape)
            sio.send(byte ^ HDLC.xorMask)
        } else {
            sio.send(byte)
        }
    }

    // MARK: - Receive

    /// Process received bytes from the serial line
    public func inputBytes(_ data: [UInt8]) {
        for byte in data {
            inputByte(byte)
        }
    }

    /// Process a single received byte
    public func inputByte(_ byte: UInt8) {
        if byte == HDLC.flag {
            if rxBuffer.count >= 2 && rxFCS == PPPoS.fcsGood {
                // Good frame received, strip FCS
                let frameData = Array(rxBuffer.dropLast(2))
                processFrame(frameData)
            }
            // Reset for next frame
            rxBuffer = []
            rxFCS = PPPoS.fcsInitial
            rxEscaped = false
            rxState = .address
            return
        }

        if byte == HDLC.escape {
            rxEscaped = true
            return
        }

        var dataByte = byte
        if rxEscaped {
            dataByte ^= HDLC.xorMask
            rxEscaped = false
        }

        // Check ACCM for control characters
        if dataByte < 0x20 && (rxACCM & (1 << UInt32(dataByte))) != 0 {
            return // Discard
        }

        if rxBuffer.count < maxRxSize {
            rxBuffer.append(dataByte)
            rxFCS = PPPoS.fcs16(rxFCS, dataByte)
        }
    }

    /// Process a complete HDLC frame (after flag bytes and FCS stripped)
    private func processFrame(_ data: [UInt8]) {
        guard data.count >= 2 else { return }
        var offset = 0

        // Skip address/control if present
        if data[offset] == HDLC.address {
            offset += 1
            if offset < data.count && data[offset] == HDLC.control {
                offset += 1
            }
        }

        // Extract protocol
        var proto: UInt16
        if (data[offset] & 1) == 0 {
            proto = UInt16(data[offset]) << 8
            offset += 1
            guard offset < data.count else { return }
            proto |= UInt16(data[offset])
            offset += 1
        } else {
            proto = UInt16(data[offset])
            offset += 1
        }

        let payload = Array(data[offset...])
        pcb?.protocolInput(proto: proto, data: payload)
    }

    // MARK: - Polling

    /// Poll for incoming serial data (non-blocking)
    public func poll() {
        guard let sio = serialDevice else { return }
        var buf = [UInt8](repeating: 0, count: 256)
        while true {
            let n = sio.tryRead(into: &buf, count: 256)
            if n <= 0 { break }
            inputBytes(Array(buf[0..<n]))
        }
    }
}

// MARK: - PPPoE Constants

/// PPPoE packet types
public enum PPPoECode: UInt8, Sendable {
    case padi = 0x09  // Active Discovery Initiation
    case pado = 0x07  // Active Discovery Offer
    case padr = 0x19  // Active Discovery Request
    case pads = 0x65  // Active Discovery Session-confirmation
    case padt = 0xA7  // Active Discovery Terminate
    case session = 0x00  // Session data
}

/// PPPoE tag types
public enum PPPoETag: UInt16, Sendable {
    case endOfList      = 0x0000
    case serviceName    = 0x0101
    case accessConcentratorName    = 0x0102
    case hostUniq                  = 0x0103
    case accessConcentratorCookie  = 0x0104
    case relaySessionID            = 0x0110
    case serviceNameError          = 0x0201
    case accessConcentratorSystemError = 0x0202
    case genericError              = 0x0203
}

/// PPPoE constants.
public extension PPPoE {
    /// PPPoE header size (6 bytes: ver/type, code, session, length).
    static let headerSize: Int = 6
}

// MARK: - PPPoE State

public enum PPPoEState: UInt8, Sendable {
    case initial    = 0
    case padi       = 1
    case padr       = 2
    case session    = 3
    case closing    = 4
}

// MARK: - PPPoE (PPP over Ethernet)

/// PPP over Ethernet transport layer (RFC 2516).
public final class PPPoE: @unchecked Sendable, PPPTransportProtocol {
    /// Parent PPP PCB
    public weak var pcb: PPPControlBlock?
    /// Underlying Ethernet network interface
    public var ethNetif: NetworkInterface?
    /// Session ID
    public var sessionID: UInt16 = 0
    /// Access Concentrator MAC address
    public var acMAC: [UInt8] = [UInt8](repeating: 0, count: 6)
    /// Service name
    public var serviceName: String = ""
    /// Optional access concentrator name filter / last observed AC name.
    public var concentratorName: String = ""
    /// Host unique tag
    public var hostUniq: UInt32 = 0
    /// AC cookie
    public var acCookie: [UInt8] = []
    /// Current state
    public var state: PPPoEState = .initial
    /// Retry counter
    public var retries: Int = 0
    /// Max retries
    public var maxRetries: Int = 5

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
        hostUniq = UInt32.random(in: 0...UInt32.max)
    }

    // MARK: - PPPTransportProtocol

    public func connect() {
        state = .padi
        retries = 0
        sendPADI()
    }

    public func disconnect() {
        if state == .session {
            sendPADT()
        }
        state = .initial
        sessionID = 0
    }

    public func sendPacket(pbuf: Pbuf, protocol proto: UInt16) {
        guard state == .session, sessionID != 0 else { return }

        // Build PPPoE session frame
        var frame = [UInt8]()
        // PPPoE header
        frame.append(0x11) // Version 1, Type 1
        frame.append(PPPoECode.session.rawValue)
        frame.append(UInt8(sessionID >> 8))
        frame.append(UInt8(sessionID & 0xFF))

        let pppLen = 2 + Int(pbuf.totLen) // protocol(2) + data
        frame.append(UInt8(pppLen >> 8))
        frame.append(UInt8(pppLen & 0xFF))

        // PPP protocol
        frame.append(UInt8(proto >> 8))
        frame.append(UInt8(proto & 0xFF))

        // PPP data from pbuf raw pointer
        let payloadPtr = pbuf.payload
        for i in 0..<Int(pbuf.totLen) {
            frame.append(payloadPtr[i])
        }

        guard let outPbuf = Pbuf.alloc(layer: .raw, length: UInt16(frame.count), type: .ram) else { return }
        frame.withUnsafeBufferPointer { buf in
            _ = outPbuf.take(from: buf.baseAddress!, len: UInt16(frame.count))
        }
        _ = ethNetif?.linkOutput?(ethNetif!, outPbuf)
    }

    // MARK: - Discovery

    private func sendPADI() {
        var frame = [UInt8]()
        frame.append(0x11) // Version 1, Type 1
        frame.append(PPPoECode.padi.rawValue)
        frame.append(0x00); frame.append(0x00) // Session ID = 0

        var tags = [UInt8]()
        // Service-Name tag
        appendTag(&tags, type: .serviceName, value: Array(serviceName.utf8))
        // Host-Uniq tag
        var hostUniqBytes = [UInt8](repeating: 0, count: 4)
        hostUniqBytes[0] = UInt8((hostUniq >> 24) & 0xFF)
        hostUniqBytes[1] = UInt8((hostUniq >> 16) & 0xFF)
        hostUniqBytes[2] = UInt8((hostUniq >> 8) & 0xFF)
        hostUniqBytes[3] = UInt8(hostUniq & 0xFF)
        appendTag(&tags, type: .hostUniq, value: hostUniqBytes)

        frame.append(UInt8(tags.count >> 8))
        frame.append(UInt8(tags.count & 0xFF))
        frame.append(contentsOf: tags)

        sendRawFrame(frame)
    }

    private func sendPADR() {
        var frame = [UInt8]()
        frame.append(0x11)
        frame.append(PPPoECode.padr.rawValue)
        frame.append(0x00); frame.append(0x00)

        var tags = [UInt8]()
        appendTag(&tags, type: .serviceName, value: Array(serviceName.utf8))
        appendTag(&tags, type: .hostUniq, value: withUnsafeBytes(of: hostUniq.bigEndian) { Array($0) })
        if !acCookie.isEmpty {
            appendTag(&tags, type: .accessConcentratorCookie, value: acCookie)
        }

        frame.append(UInt8(tags.count >> 8))
        frame.append(UInt8(tags.count & 0xFF))
        frame.append(contentsOf: tags)

        sendRawFrame(frame)
    }

    private func sendPADT() {
        var frame = [UInt8]()
        frame.append(0x11)
        frame.append(PPPoECode.padt.rawValue)
        frame.append(UInt8(sessionID >> 8))
        frame.append(UInt8(sessionID & 0xFF))
        frame.append(0x00); frame.append(0x00) // No payload

        sendRawFrame(frame)
    }

    /// Helper to allocate a pbuf from a byte array and send via link output
    private func sendRawFrame(_ frame: [UInt8]) {
        guard let outPbuf = Pbuf.alloc(layer: .raw, length: UInt16(frame.count), type: .ram) else { return }
        frame.withUnsafeBufferPointer { buf in
            _ = outPbuf.take(from: buf.baseAddress!, len: UInt16(frame.count))
        }
        _ = ethNetif?.linkOutput?(ethNetif!, outPbuf)
    }

    private func appendTag(_ buffer: inout [UInt8], type: PPPoETag, value: [UInt8]) {
        buffer.append(UInt8(type.rawValue >> 8))
        buffer.append(UInt8(type.rawValue & 0xFF))
        buffer.append(UInt8(value.count >> 8))
        buffer.append(UInt8(value.count & 0xFF))
        buffer.append(contentsOf: value)
    }

    /// Handle received PPPoE packet
    public func input(pbuf: Pbuf) {
        guard Int(pbuf.totLen) >= PPPoE.headerSize else { return }

        // Read header bytes from raw pointer
        let payloadPtr = pbuf.payload
        let code = payloadPtr[1]
        let sid = UInt16(payloadPtr[2]) << 8 | UInt16(payloadPtr[3])
        let length = Int(UInt16(payloadPtr[4]) << 8 | UInt16(payloadPtr[5]))

        guard let poeCode = PPPoECode(rawValue: code) else { return }

        switch poeCode {
        case .pado:
            guard state == .padi else { return }
            // Parse AC-Name and AC-Cookie from tags
            var tagBytes = [UInt8]()
            for i in PPPoE.headerSize..<Int(pbuf.totLen) {
                tagBytes.append(payloadPtr[i])
            }
            parseTags(tagBytes)
            state = .padr
            sendPADR()

        case .pads:
            guard state == .padr else { return }
            sessionID = sid
            state = .session
            pcb?.open()

        case .padt:
            state = .initial
            sessionID = 0
            pcb?.linkDown()

        case .session:
            guard state == .session, sid == sessionID else { return }
            // Extract PPP protocol and data
            guard Int(pbuf.totLen) >= PPPoE.headerSize + 2 else { return }
            var pppData = [UInt8]()
            let end = min(Int(pbuf.totLen), PPPoE.headerSize + length)
            for i in PPPoE.headerSize..<end {
                pppData.append(payloadPtr[i])
            }
            guard pppData.count >= 2 else { return }
            let proto = UInt16(pppData[0]) << 8 | UInt16(pppData[1])
            pcb?.protocolInput(proto: proto, data: Array(pppData[2...]))

        default:
            break
        }
    }

    private func parseTags(_ data: [UInt8]) {
        var offset = 0
        while offset + 4 <= data.count {
            let tagType = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            let tagLen = Int(UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3]))
            offset += 4
            guard offset + tagLen <= data.count else { break }

            let tagData = Array(data[offset..<(offset + tagLen)])
            switch PPPoETag(rawValue: tagType) {
            case .accessConcentratorCookie:
                acCookie = tagData
            case .accessConcentratorName:
                concentratorName = String(decoding: tagData, as: UTF8.self)
            default:
                break
            }
            offset += tagLen
        }
    }

    /// Handle timeout (retransmit discovery packets)
    public func timeout() {
        retries += 1
        guard retries <= maxRetries else {
            state = .initial
            pcb?.linkTerminated()
            return
        }
        switch state {
        case .padi: sendPADI()
        case .padr: sendPADR()
        default: break
        }
    }
}

// MARK: - PPPoL2TP (PPP over L2TP)

/// L2TP message types
public struct L2TPMessageType {
    public static let sccrq: UInt16 = 1  // Start-Control-Connection-Request
    public static let sccrp: UInt16 = 2  // Start-Control-Connection-Reply
    public static let scccn: UInt16 = 3  // Start-Control-Connection-Connected
    public static let stopccn: UInt16 = 4
    public static let hello: UInt16 = 6
    public static let icrq: UInt16 = 10  // Incoming-Call-Request
    public static let icrp: UInt16 = 11  // Incoming-Call-Reply
    public static let iccn: UInt16 = 12  // Incoming-Call-Connected
    public static let cdn: UInt16 = 14   // Call-Disconnect-Notify
}

/// PPP over L2TP state
public enum PPPoL2TPState: UInt8, Sendable {
    case initial    = 0
    case sccrq      = 1
    case sccrp      = 2
    case icrq       = 3
    case icrp       = 4
    case open       = 5
    case closing    = 6
}

/// PPP over L2TP transport layer (RFC 2661).
public final class PPPoL2TP: @unchecked Sendable, PPPTransportProtocol {
    /// Parent PPP PCB
    public weak var pcb: PPPControlBlock?
    /// UDP control block for L2TP tunnel
    public var udpControlBlock: UDPControlBlock?
    /// Remote IP address
    public var remoteAddr: IPAddress?
    /// Remote UDP port (default 1701)
    public var remotePort: UInt16 = 1701
    /// Local tunnel ID
    public var localTunnelID: UInt16
    /// Remote tunnel ID
    public var remoteTunnelID: UInt16 = 0
    /// Local session ID
    public var localSessionID: UInt16
    /// Remote session ID
    public var remoteSessionID: UInt16 = 0
    /// Tunnel secret (optional)
    public var tunnelSecret: [UInt8] = []
    /// Current state
    public var state: PPPoL2TPState = .initial
    /// Sequence numbers
    public var nextNs: UInt16 = 0
    public var nextNr: UInt16 = 0

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
        self.localTunnelID = UInt16.random(in: 1...UInt16.max)
        self.localSessionID = UInt16.random(in: 1...UInt16.max)
    }

    // MARK: - PPPTransportProtocol

    public func connect() {
        state = .sccrq
        sendSCCRQ()
    }

    public func disconnect() {
        if state == .open {
            sendCDN()
        }
        state = .initial
    }

    public func sendPacket(pbuf: Pbuf, protocol proto: UInt16) {
        guard state == .open, let udp = udpControlBlock, let remoteAddr = remoteAddr else { return }

        // Build L2TP data header
        var frame = [UInt8]()
        // L2TP header (data message, no sequence)
        frame.append(0x00)
        frame.append(0x02) // Version 2
        frame.append(UInt8(remoteTunnelID >> 8))
        frame.append(UInt8(remoteTunnelID & 0xFF))
        frame.append(UInt8(remoteSessionID >> 8))
        frame.append(UInt8(remoteSessionID & 0xFF))

        // PPP protocol
        if proto > 0xFF {
            frame.append(UInt8(proto >> 8))
        }
        frame.append(UInt8(proto & 0xFF))

        // PPP data from pbuf
        let payloadPtr = pbuf.payload
        for i in 0..<Int(pbuf.totLen) {
            frame.append(payloadPtr[i])
        }

        guard let outPbuf = Pbuf.alloc(layer: .raw, length: UInt16(frame.count), type: .ram) else { return }
        frame.withUnsafeBufferPointer { buf in
            _ = outPbuf.take(from: buf.baseAddress!, len: UInt16(frame.count))
        }
        _ = UDPGlobal.shared.sendTo(udp, pbuf: outPbuf, dstIP: remoteAddr, dstPort: remotePort)
    }

    // MARK: - Control Messages

    private func sendSCCRQ() {
        sendControlMessage(messageType: L2TPMessageType.sccrq, avps: [
            makeAVP(type: 0, value: encodU16(L2TPMessageType.sccrq)), // Message Type
            makeAVP(type: 2, value: [1, 0]), // Protocol Version 1.0
            makeAVP(type: 9, value: encodU16(localTunnelID)), // Assigned Tunnel ID
            makeAVP(type: 10, value: encodU16(1)), // Receive Window Size
            makeAVP(type: 7, value: Array("lwIP".utf8)), // Host Name
        ])
    }

    private func sendCDN() {
        sendControlMessage(messageType: L2TPMessageType.cdn, avps: [
            makeAVP(type: 0, value: encodU16(L2TPMessageType.cdn)),
            makeAVP(type: 14, value: encodU16(localSessionID)),
            makeAVP(type: 1, value: [0, 1, 0, 0]), // Result Code
        ])
    }

    private func sendControlMessage(messageType: UInt16, avps: [[UInt8]]) {
        guard let udp = udpControlBlock, let remoteAddr = remoteAddr else { return }

        var frame = [UInt8]()
        // L2TP control header
        let flagsVersion: UInt16 = 0xC802 // T=1, L=1, S=1, Version=2
        frame.append(UInt8(flagsVersion >> 8))
        frame.append(UInt8(flagsVersion & 0xFF))

        // Length placeholder (fill in later)
        let lenOffset = frame.count
        frame.append(0); frame.append(0)

        // Tunnel ID
        frame.append(UInt8(remoteTunnelID >> 8))
        frame.append(UInt8(remoteTunnelID & 0xFF))

        // Session ID (0 for control)
        frame.append(0); frame.append(0)

        // Ns
        frame.append(UInt8(nextNs >> 8))
        frame.append(UInt8(nextNs & 0xFF))
        nextNs &+= 1

        // Nr
        frame.append(UInt8(nextNr >> 8))
        frame.append(UInt8(nextNr & 0xFF))

        // AVPs
        for avp in avps {
            frame.append(contentsOf: avp)
        }

        // Fill in length
        let totalLen = UInt16(frame.count)
        frame[lenOffset] = UInt8(totalLen >> 8)
        frame[lenOffset + 1] = UInt8(totalLen & 0xFF)

        guard let outPbuf = Pbuf.alloc(layer: .raw, length: totalLen, type: .ram) else { return }
        frame.withUnsafeBufferPointer { buf in
            _ = outPbuf.take(from: buf.baseAddress!, len: totalLen)
        }
        _ = UDPGlobal.shared.sendTo(udp, pbuf: outPbuf, dstIP: remoteAddr, dstPort: remotePort)
    }

    private func makeAVP(type: UInt16, value: [UInt8]) -> [UInt8] {
        var avp = [UInt8]()
        let len = UInt16(6 + value.count)
        let flags: UInt16 = 0x8000 | len // Mandatory bit + length
        avp.append(UInt8(flags >> 8))
        avp.append(UInt8(flags & 0xFF))
        avp.append(0); avp.append(0) // Vendor ID (0 = IETF)
        avp.append(UInt8(type >> 8))
        avp.append(UInt8(type & 0xFF))
        avp.append(contentsOf: value)
        return avp
    }

    private func encodU16(_ val: UInt16) -> [UInt8] {
        return [UInt8(val >> 8), UInt8(val & 0xFF)]
    }

    /// Handle received L2TP packet from UDP
    public func input(pbuf: Pbuf) {
        guard Int(pbuf.totLen) >= 6 else { return }

        // Read from raw pointer
        let payloadPtr = pbuf.payload
        let flagsHi = payloadPtr[0]
        let flagsLo = payloadPtr[1]
        let flags = UInt16(flagsHi) << 8 | UInt16(flagsLo)
        let isControl = (flags & 0x8000) != 0

        // Copy payload bytes to array for processing
        var payloadBytes = [UInt8](repeating: 0, count: Int(pbuf.totLen))
        for i in 0..<Int(pbuf.totLen) {
            payloadBytes[i] = payloadPtr[i]
        }

        if isControl {
            handleControlMessage(payload: payloadBytes)
        } else {
            handleDataMessage(payload: payloadBytes)
        }
    }

    private func handleControlMessage(payload: [UInt8]) {
        guard payload.count >= 12 else { return }

        nextNr &+= 1

        // Parse message type from first AVP
        guard payload.count >= 20 else { return }
        let msgType = UInt16(payload[18]) << 8 | UInt16(payload[19])

        switch msgType {
        case L2TPMessageType.sccrp:
            guard state == .sccrq else { return }
            remoteTunnelID = parseAssignedTunnelID(payload)
            state = .sccrp
            // Send SCCCN
            sendControlMessage(messageType: L2TPMessageType.scccn, avps: [
                makeAVP(type: 0, value: encodU16(L2TPMessageType.scccn))
            ])
            // Now initiate call
            state = .icrq
            sendControlMessage(messageType: L2TPMessageType.icrq, avps: [
                makeAVP(type: 0, value: encodU16(L2TPMessageType.icrq)),
                makeAVP(type: 14, value: encodU16(localSessionID)),
                makeAVP(type: 15, value: encodU16(UInt16.random(in: 1...UInt16.max))), // Call Serial Number
            ])

        case L2TPMessageType.icrp:
            guard state == .icrq else { return }
            remoteSessionID = parseAssignedSessionID(payload)
            state = .icrp
            sendControlMessage(messageType: L2TPMessageType.iccn, avps: [
                makeAVP(type: 0, value: encodU16(L2TPMessageType.iccn)),
            ])
            state = .open
            pcb?.open()

        case L2TPMessageType.cdn:
            state = .initial
            pcb?.linkDown()

        case L2TPMessageType.stopccn:
            state = .initial
            pcb?.linkDown()

        case L2TPMessageType.hello:
            // Send ZLB (Zero Length Body) as acknowledgment
            sendControlMessage(messageType: 0, avps: [])

        default:
            break
        }
    }

    private func handleDataMessage(payload: [UInt8]) {
        guard state == .open, payload.count >= 8 else { return }
        // Skip L2TP data header to get to PPP frame
        var offset = 6 // Minimum data header
        if (payload[0] & 0x40) != 0 { offset += 4 } // Length present
        if (payload[0] & 0x08) != 0 { offset += 4 } // Sequence present

        guard offset < payload.count else { return }
        let pppData = Array(payload[offset...])

        // Extract PPP protocol
        guard pppData.count >= 2 else { return }
        var proto: UInt16
        var dataOffset: Int
        if (pppData[0] & 1) == 0 {
            proto = UInt16(pppData[0]) << 8 | UInt16(pppData[1])
            dataOffset = 2
        } else {
            proto = UInt16(pppData[0])
            dataOffset = 1
        }

        pcb?.protocolInput(proto: proto, data: Array(pppData[dataOffset...]))
    }

    private func parseAssignedTunnelID(_ payload: [UInt8]) -> UInt16 {
        return scanForAVP(type: 9, in: payload) ?? 0
    }

    private func parseAssignedSessionID(_ payload: [UInt8]) -> UInt16 {
        return scanForAVP(type: 14, in: payload) ?? 0
    }

    private func scanForAVP(type searchType: UInt16, in payload: [UInt8]) -> UInt16? {
        var offset = 12 // Start after L2TP header
        while offset + 6 <= payload.count {
            let flags = UInt16(payload[offset]) << 8 | UInt16(payload[offset + 1])
            let avpLen = Int(flags & 0x03FF)
            guard avpLen >= 6 else { break }
            let avpType = UInt16(payload[offset + 4]) << 8 | UInt16(payload[offset + 5])
            if avpType == searchType && avpLen >= 8 {
                return UInt16(payload[offset + 6]) << 8 | UInt16(payload[offset + 7])
            }
            offset += avpLen
        }
        return nil
    }
}
