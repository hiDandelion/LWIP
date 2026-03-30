//
//  NetBIOSNS.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - NetBIOS Constants

/// NetBIOS Name Service constants.
public enum NetBIOSConstants {
    /// Size of a NetBIOS name (16 characters including padding).
    public static let nameLength: Int = 16
    /// Default TTL for NetBIOS name responses (300000 seconds = ~3.5 days).
    public static let nameTTL: UInt32 = 300_000
    /// NetBIOS Name Service UDP port (IANA assigned).
    public static let port: UInt16 = 137
    /// Encoded name length (each character becomes 2 bytes plus length byte).
    public static let encodedNameLength: Int = (nameLength * 2) + 1
    /// Whether to respond to NBSTAT name queries.
    public static var respondToNameQuery: Bool = true
}

// MARK: - NetBIOS Header Flags

/// NetBIOS header flag constants.
internal enum NetBIOSHeaderFlags {
    static let response: UInt16          = 0x8000
    static let opcodeMask: UInt16        = 0x7800
    static let opcodeNameQuery: UInt16   = 0x0000
    static let authoritative: UInt16     = 0x0400
    static let truncated: UInt16         = 0x0200
    static let recursDesired: UInt16     = 0x0100
    static let recursAvailable: UInt16   = 0x0080
    static let broadcast: UInt16         = 0x0010
    static let replyCodeMask: UInt16     = 0x0008
    static let replyCodeNoError: UInt16  = 0x0000
}

// MARK: - NetBIOS Question Types

/// NetBIOS question type constants.
internal enum NetBIOSQuestionType {
    /// Standard name query.
    static let nb: UInt16     = 0x0020
    /// Node status request.
    static let nbstat: UInt16 = 0x0021
}

// MARK: - NetBIOS Name Flags

/// NetBIOS name node type flags.
internal enum NetBIOSNameFlags {
    static let unique: UInt16      = 0x8000
    static let bnodeType: UInt16   = 0x0000
    static let pnodeType: UInt16   = 0x2000
    static let mnodeType: UInt16   = 0x4000
    static let hnodeType: UInt16   = 0x6000
    static let nameIsActive: UInt16   = 0x0400
    static let nameIsPermanent: UInt16 = 0x0200
}

// MARK: - NetBIOS Packet Structures

/// NetBIOS header (12 bytes on the wire).
internal struct NetBIOSHeader {
    var transactionId: UInt16 = 0
    var flags: UInt16 = 0
    var questions: UInt16 = 0
    var answerResourceRecords: UInt16 = 0
    var authorityResourceRecords: UInt16 = 0
    var additionalResourceRecords: UInt16 = 0

    static let size = 12
}

/// NetBIOS question part.
internal struct NetBIOSQuestion {
    var nameType: UInt8 = 0
    var encodedName: [UInt8] = [UInt8](repeating: 0, count: NetBIOSConstants.encodedNameLength)
    var type: UInt16 = 0
    var cls: UInt16 = 0

    static let size = 1 + NetBIOSConstants.encodedNameLength + 4
}

/// NetBIOS name response part.
internal struct NetBIOSNameResponse {
    var nameType: UInt8 = 0
    var encodedName: [UInt8] = [UInt8](repeating: 0, count: NetBIOSConstants.encodedNameLength)
    var type: UInt16 = 0
    var cls: UInt16 = 0
    var ttl: UInt32 = 0
    var dataLength: UInt16 = 0
    var flags: UInt16 = 0
    var address: UInt32 = 0  // IPv4 address in network byte order
}

// MARK: - NetBIOS Name Service Responder

/// NetBIOS Name Service responder.
///
/// Listens on UDP port 137 and responds to name queries for the configured
/// hostname. This allows the device to be discovered by Windows systems and
/// other NetBIOS-aware clients.
///
/// Usage:
/// ```swift
/// let responder = NetBIOSNameService()
/// responder.setName("MYDEVICE")
/// responder.start()
/// // ...later...
/// responder.stop()
/// ```
public final class NetBIOSNameService: @unchecked Sendable {

    // MARK: - Properties

    /// The UDP control block used for listening and responding.
    private var udpControlBlock: UDPControlBlock?

    /// The local NetBIOS name (up to 15 characters, stored uppercase).
    private var localName: String = ""

    /// Lock for thread safety.
    private let lock = NSLock()

    // MARK: - Initialization

    /// Create a new NetBIOS Name Service responder.
    public init() {}

    deinit {
        stop()
    }

    // MARK: - Configuration

    /// Set the NetBIOS name.
    ///
    /// The name must be less than 15 characters. It will be converted to
    /// uppercase as required by the NetBIOS specification.
    ///
    /// - Parameter hostname: The hostname to respond with.
    public func setName(_ hostname: String) {
        lock.lock()
        defer { lock.unlock() }

        let maxLen = NetBIOSConstants.nameLength - 1
        let truncated = String(hostname.prefix(maxLen))
        localName = truncated.uppercased()
    }

    /// Get the current NetBIOS name.
    public var name: String {
        lock.lock()
        defer { lock.unlock() }
        return localName
    }

    // MARK: - Start / Stop

    /// Initialize and start the NetBIOS name service responder.
    ///
    /// Binds to UDP port 137 and begins listening for name queries.
    @discardableResult
    public func start() -> LWIPError {
        lock.lock()
        defer { lock.unlock() }

        guard udpControlBlock == nil else { return .ok }

        let newPCB = UDPGlobal.shared.new()
        // Allow broadcast reception
        newPCB.soOptions |= UInt8(truncatingIfNeeded: SocketOptions.broadcast.rawValue)

        let bindError = UDPGlobal.shared.bind(newPCB, address: .any, port: NetBIOSConstants.port)
        guard bindError == .ok else { return bindError }

        // Set the receive callback
        UDPGlobal.shared.recv(newPCB) { [weak self] (controlBlock, pbuf, addr, port) in
            self?.handleReceive(pcb: controlBlock, pbuf: pbuf, address: addr, port: port)
        }

        udpControlBlock = newPCB
        return .ok
    }

    /// Stop the NetBIOS name service responder and release resources.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }

        if let udpControlBlock {
            UDPGlobal.shared.recv(udpControlBlock, callback: nil)
            UDPGlobal.shared.remove(udpControlBlock)
        }
        udpControlBlock = nil
    }

    // MARK: - Packet Processing

    /// Handle an incoming UDP packet on port 137.
    private func handleReceive(pcb: UDPControlBlock, pbuf: Pbuf, address: IPAddress, port: UInt16) {
        defer { pbuf.free() }

        let totalLen = Int(pbuf.totalLength)

        // Minimum packet size: header + question
        let minSize = NetBIOSHeader.size + NetBIOSQuestion.size
        guard totalLen >= minSize else {
            return
        }

        // Extract the packet bytes
        var bytes = [UInt8](repeating: 0, count: totalLen)
        bytes.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = pbuf.copyPartial(to: UnsafeMutableRawPointer(base),
                                 len: UInt16(totalLen), offset: 0)
        }
        guard bytes.count >= minSize else {
            return
        }

        // Parse the header
        let header = parseHeader(from: bytes)

        // Only respond to name query questions (not responses)
        let flagsHostOrder = header.flags.bigEndian
        let isQuery = (flagsHostOrder & NetBIOSHeaderFlags.response) == 0
        let isNameQuery = (flagsHostOrder & NetBIOSHeaderFlags.opcodeMask) == NetBIOSHeaderFlags.opcodeNameQuery
        let hasOneQuestion = header.questions.bigEndian == 1

        guard isQuery && isNameQuery && hasOneQuestion else {
            return
        }

        // Parse the question
        let questionOffset = NetBIOSHeader.size
        let question = parseQuestion(from: bytes, offset: questionOffset)

        // Decode the NetBIOS name from the question
        guard let queriedName = decodeName(from: question.encodedName) else {
            return
        }

        lock.lock()
        let myName = localName
        lock.unlock()

        let queryType = question.type.bigEndian

        if queryType == NetBIOSQuestionType.nb {
            // Standard name query -- respond if it matches our name
            if queriedName.uppercased() == myName.uppercased() {
                let interface = responderInterface()
                let response = buildNameResponse(
                    transactionId: header.transactionId,
                    question: question,
                    address: interface?.ipAddr ?? .any
                )
                sendResponse(response, to: address, port: port, pcb: pcb)
            }
        } else if queryType == NetBIOSQuestionType.nbstat && NetBIOSConstants.respondToNameQuery {
            // NBSTAT query -- respond if name matches or is wildcard "*"
            let nameMatches = queriedName.uppercased() == myName.uppercased()
            let isWildcard = queriedName == "*"

            if nameMatches || isWildcard {
                let interface = responderInterface()
                let response = buildStatusResponse(
                    transactionId: header.transactionId,
                    question: question,
                    name: myName,
                    macAddress: responderMACAddress(from: interface)
                )
                sendResponse(response, to: address, port: port, pcb: pcb)
            }
        }
    }

    // MARK: - Name Encoding / Decoding

    /// Decode a NetBIOS first-level encoded name to a string.
    ///
    /// Each pair of uppercase characters (A-P) encodes one nibble of the original character.
    ///
    /// - Parameter encodedName: The encoded name bytes (excluding the length prefix).
    /// - Returns: The decoded name, or nil on error.
    internal static func decodeName(from encodedName: [UInt8]) -> String? {
        var decoded: [UInt8] = []

        var i = 0
        while i + 1 < encodedName.count {
            let c1 = encodedName[i]
            let c2 = encodedName[i + 1]

            if c1 == 0 || c1 == UInt8(ascii: ".") { break }

            // Each character must be uppercase A-P
            guard c1 >= UInt8(ascii: "A") && c1 <= UInt8(ascii: "P"),
                  c2 >= UInt8(ascii: "A") && c2 <= UInt8(ascii: "P") else {
                return nil
            }

            let high = (c1 - UInt8(ascii: "A")) << 4
            let low = c2 - UInt8(ascii: "A")
            let ch = high | low

            if ch == UInt8(ascii: " ") {
                // Space is used as padding; stop here
                break
            }
            decoded.append(ch)
            i += 2
        }

        return String(bytes: decoded, encoding: .ascii)
    }

    /// Instance method wrapping the static decode.
    private func decodeName(from encodedName: [UInt8]) -> String? {
        return NetBIOSNameService.decodeName(from: encodedName)
    }

    /// Encode a NetBIOS name to first-level encoding.
    ///
    /// - Parameter name: The plain-text name (max 15 characters).
    /// - Returns: The encoded name bytes (32 bytes).
    internal static func encodeName(_ name: String) -> [UInt8] {
        var encoded = [UInt8](repeating: 0, count: NetBIOSConstants.nameLength * 2)
        let nameBytes = Array(name.uppercased().utf8)

        for i in 0..<NetBIOSConstants.nameLength {
            let ch: UInt8
            if i < nameBytes.count {
                ch = nameBytes[i]
            } else {
                ch = UInt8(ascii: " ")  // Pad with spaces
            }
            encoded[i * 2] = UInt8(ascii: "A") + ((ch >> 4) & 0x0F)
            encoded[i * 2 + 1] = UInt8(ascii: "A") + (ch & 0x0F)
        }

        return encoded
    }

    // MARK: - Packet Parsing

    /// Parse a NetBIOS header from raw bytes.
    private func parseHeader(from bytes: [UInt8]) -> NetBIOSHeader {
        var header = NetBIOSHeader()
        header.transactionId = readUInt16(bytes, offset: 0)
        header.flags = readUInt16(bytes, offset: 2)
        header.questions = readUInt16(bytes, offset: 4)
        header.answerResourceRecords = readUInt16(bytes, offset: 6)
        header.authorityResourceRecords = readUInt16(bytes, offset: 8)
        header.additionalResourceRecords = readUInt16(bytes, offset: 10)
        return header
    }

    /// Parse a NetBIOS question from raw bytes at the given offset.
    private func parseQuestion(from bytes: [UInt8], offset: Int) -> NetBIOSQuestion {
        var question = NetBIOSQuestion()
        guard offset < bytes.count else { return question }

        question.nameType = bytes[offset]

        let nameStart = offset + 1
        let nameEnd = min(nameStart + NetBIOSConstants.encodedNameLength, bytes.count)
        if nameEnd > nameStart {
            question.encodedName = Array(bytes[nameStart..<nameEnd])
        }

        let typeOffset = nameStart + NetBIOSConstants.encodedNameLength
        if typeOffset + 4 <= bytes.count {
            question.type = readUInt16(bytes, offset: typeOffset)
            question.cls = readUInt16(bytes, offset: typeOffset + 2)
        }

        return question
    }

    // MARK: - Response Building

    /// Build a name query response packet.
    private func buildNameResponse(transactionId: UInt16,
                                   question: NetBIOSQuestion,
                                   address: IPv4Address) -> [UInt8] {
        var response = [UInt8]()
        response.reserveCapacity(62)

        // Header
        appendUInt16(&response, transactionId)
        let flags: UInt16 = (NetBIOSHeaderFlags.response |
                             NetBIOSHeaderFlags.opcodeNameQuery |
                             NetBIOSHeaderFlags.authoritative |
                             NetBIOSHeaderFlags.recursDesired)
        appendUInt16(&response, flags.bigEndian)
        appendUInt16(&response, 0)  // questions
        appendUInt16(&response, UInt16(1).bigEndian)  // answerRRs
        appendUInt16(&response, 0)  // authorityRRs
        appendUInt16(&response, 0)  // additionalRRs

        // Name response
        response.append(question.nameType)
        response.append(contentsOf: question.encodedName)
        appendUInt16(&response, question.type)
        appendUInt16(&response, question.cls)
        appendUInt32(&response, NetBIOSConstants.nameTTL.bigEndian)  // TTL
        appendUInt16(&response, UInt16(6).bigEndian)  // data length (flags + IPv4 addr)
        appendUInt16(&response, NetBIOSNameFlags.bnodeType.bigEndian)  // flags

        appendUInt32(&response, address.addr)

        return response
    }

    /// Build a node status response packet.
    private func buildStatusResponse(transactionId: UInt16,
                                     question: NetBIOSQuestion,
                                     name: String,
                                     macAddress: [UInt8]) -> [UInt8] {
        var response = [UInt8]()
        response.reserveCapacity(120)

        // Header
        appendUInt16(&response, transactionId)
        let flags: UInt16 = (NetBIOSHeaderFlags.response |
                             NetBIOSHeaderFlags.opcodeNameQuery |
                             NetBIOSHeaderFlags.authoritative)
        appendUInt16(&response, flags.bigEndian)
        appendUInt16(&response, 0)  // questions
        appendUInt16(&response, UInt16(1).bigEndian)  // answerRRs
        appendUInt16(&response, 0)  // authorityRRs
        appendUInt16(&response, 0)  // additionalRRs

        // Name size and encoded name
        response.append(question.nameType)
        response.append(contentsOf: question.encodedName)

        // Type and class
        appendUInt16(&response, UInt16(0x0021).bigEndian)  // NBSTAT
        appendUInt16(&response, UInt16(1).bigEndian)  // Internet

        // TTL
        appendUInt32(&response, 0)

        // Data length placeholder (will be filled)
        let dataLenOffset = response.count
        appendUInt16(&response, 0)

        let dataStart = response.count

        // Number of names
        response.append(1)

        // Node name (16 bytes, space-padded)
        var nameBytes = Array(name.uppercased().utf8)
        while nameBytes.count < NetBIOSConstants.nameLength {
            nameBytes.append(UInt8(ascii: " "))
        }
        if nameBytes.count > NetBIOSConstants.nameLength {
            nameBytes = Array(nameBytes.prefix(NetBIOSConstants.nameLength))
        }
        response.append(contentsOf: nameBytes)

        // Name flags
        appendUInt16(&response, NetBIOSNameFlags.nameIsActive.bigEndian)

        response.append(contentsOf: Array(macAddress.prefix(6)))
        if macAddress.count < 6 {
            response.append(contentsOf: [UInt8](repeating: 0, count: 6 - macAddress.count))
        }

        // Statistics fields (all zeros)
        // jumpers, test_result
        response.append(0)
        response.append(0)
        // version_number, period_of_statistics
        appendUInt16(&response, 0)
        appendUInt16(&response, 0)
        // Various statistics counters (all zeros)
        for _ in 0..<10 {
            appendUInt16(&response, 0)
        }

        // Fill in data length
        let dataLen = UInt16(response.count - dataStart)
        response[dataLenOffset] = UInt8((dataLen.bigEndian >> 8) & 0xFF)
        response[dataLenOffset + 1] = UInt8(dataLen.bigEndian & 0xFF)

        return response
    }

    // MARK: - Send Response

    /// Send a response packet back to the querier.
    private func sendResponse(_ data: [UInt8], to address: IPAddress, port: UInt16, pcb: UDPControlBlock) {
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(data.count), type: .ram) else { return }
        defer { pbuf.free() }

        data.withUnsafeBufferPointer { buffer in
            if let base = buffer.baseAddress {
                _ = pbuf.take(from: UnsafeRawPointer(base), len: UInt16(data.count))
            }
        }
        _ = UDPGlobal.shared.sendTo(pcb, pbuf: pbuf, dstIP: address, dstPort: port)
    }

    private func responderInterface() -> NetworkInterface? {
        if let defaultNetif = NetworkInterface.defaultInterface,
           defaultNetif.isUp,
           defaultNetif.isLinkUp,
           defaultNetif.ipAddr != .any {
            return defaultNetif
        }

        var current = NetworkInterface.list
        while let netif = current {
            if netif.isUp && netif.isLinkUp && netif.ipAddr != .any {
                return netif
            }
            current = netif.next
        }
        return NetworkInterface.defaultInterface
    }

    private func responderMACAddress(from netif: NetworkInterface?) -> [UInt8] {
        guard let netif, netif.hwAddrLen >= 6 else {
            return [UInt8](repeating: 0, count: 6)
        }
        return Array(netif.hwAddr.prefix(6))
    }

    // MARK: - Byte Helpers

    /// Read a big-endian UInt16 from a byte array.
    private func readUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
        guard offset + 1 < data.count else { return 0 }
        return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    /// Append a UInt16 to a byte array (in its current byte order).
    private func appendUInt16(_ data: inout [UInt8], _ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Append a UInt32 to a byte array (in its current byte order).
    private func appendUInt32(_ data: inout [UInt8], _ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }
}
