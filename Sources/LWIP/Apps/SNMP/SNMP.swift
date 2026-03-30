//
//  SNMP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - ASN.1 Constants

/// ASN.1 class constants
public struct SNMPASN1 {
    public static let classUniversal: UInt8    = 0x00
    public static let classApplication: UInt8  = 0x40
    public static let classContext: UInt8       = 0x80
    public static let classPrivate: UInt8      = 0xC0

    public static let primitive: UInt8    = 0x00
    public static let constructed: UInt8  = 0x20

    // Universal tags
    public static let endOfContent: UInt8  = 0
    public static let integer: UInt8       = 2
    public static let octetString: UInt8   = 4
    public static let null: UInt8          = 5
    public static let objectID: UInt8      = 6
    public static let sequenceOf: UInt8    = 16

    // Application-specific SNMP tags
    public static let ipAddr: UInt8       = 0
    public static let counter: UInt8      = 1
    public static let gauge: UInt8        = 2
    public static let timeTicks: UInt8    = 3
    public static let opaque: UInt8       = 4
    public static let counter64: UInt8    = 6

    // Full type codes
    public static let typeInteger: UInt8      = classUniversal | primitive | integer
    public static let typeOctetString: UInt8   = classUniversal | primitive | octetString
    public static let typeNull: UInt8          = classUniversal | primitive | null
    public static let typeObjectID: UInt8      = classUniversal | primitive | objectID
    public static let typeSequence: UInt8      = classUniversal | constructed | sequenceOf
    public static let typeIPAddr: UInt8        = classApplication | primitive | ipAddr
    public static let typeCounter32: UInt8     = classApplication | primitive | counter
    public static let typeGauge32: UInt8       = classApplication | primitive | gauge
    public static let typeTimeTicks: UInt8     = classApplication | primitive | timeTicks
    public static let typeOpaque: UInt8        = classApplication | primitive | opaque
    public static let typeCounter64: UInt8     = classApplication | primitive | counter64
}

// MARK: - SNMP Error Codes

/// SNMP protocol error codes
public enum SNMPError: Int32, Sendable, Error {
    case noError             = 0
    case genErr              = 5
    case noAccess            = 6
    case wrongType           = 7
    case wrongLength         = 8
    case wrongEncoding       = 9
    case wrongValue          = 10
    case noCreation          = 11
    case inconsistentValue   = 12
    case resourceUnavailable = 13
    case commitFailed        = 14
    case undoFailed          = 15
    case notWritable         = 17
    case inconsistentName    = 18
    case noSuchInstance      = 0xF1
}

// MARK: - SNMP Object Identifier

/// SNMP Object Identifier (OID)
public struct SNMPObjectID: Equatable, Hashable, Sendable {
    /// Maximum OID length
    public static let maxLength: Int = 50

    /// OID components
    public var components: [UInt32]

    /// Number of components
    public var length: Int { components.count }

    public init(_ components: [UInt32] = []) {
        self.components = components
    }

    public init(_ components: UInt32...) {
        self.components = components
    }

    /// Assign OID from array
    public mutating func assign(_ oid: [UInt32]) {
        self.components = oid
    }

    /// Append OID components
    public mutating func append(_ oid: [UInt32]) {
        components.append(contentsOf: oid)
    }

    /// Prefix with additional components
    public mutating func prefix(with oid: [UInt32]) {
        components.insert(contentsOf: oid, at: 0)
    }

    /// Combine two OIDs
    public static func combine(_ oid1: [UInt32], _ oid2: [UInt32]) -> SNMPObjectID {
        return SNMPObjectID(oid1 + oid2)
    }

    /// Compare with another OID
    public func compare(with other: SNMPObjectID) -> Int {
        let minLen = min(components.count, other.components.count)
        for i in 0..<minLen {
            if components[i] < other.components[i] { return -1 }
            if components[i] > other.components[i] { return 1 }
        }
        if components.count < other.components.count { return -1 }
        if components.count > other.components.count { return 1 }
        return 0
    }
}

/// Zero dot zero administrative identifier.
public extension SNMPObjectID {
    /// The zero-dot-zero administrative identifier (0.0).
    static let zeroDotZero = SNMPObjectID(0, 0)
}

// MARK: - SNMP Variant Value

/// SNMP variant value for passing data between MIB callbacks
public enum SNMPVariantValue {
    case ptr(AnyObject?)
    case uint32(UInt32)
    case int32(Int32)
    case uint64(UInt64)
}

// MARK: - SNMP Node Types

/// Node types in the MIB tree
public enum SNMPNodeType: UInt8, Sendable {
    case tree        = 0x00
    case scalar      = 0x01
    case scalarArray = 0x02
    case table       = 0x03
    case threadSync  = 0x04
}

/// Node access types
public enum SNMPAccessType: UInt8, Sendable {
    case notAccessible = 0
    case readOnly      = 1
    case writeOnly     = 2
    case readWrite     = 3
}

// MARK: - SNMP Node

/// Base node in the MIB tree
public class SNMPNode {
    /// Node type
    public let nodeType: SNMPNodeType
    /// OID number for this node
    public let oid: UInt32

    public init(type: SNMPNodeType, oid: UInt32) {
        self.nodeType = type
        self.oid = oid
    }
}

// MARK: - SNMP Tree Node

/// Internal MIB tree node with child nodes
public final class SNMPTreeNode: SNMPNode {
    /// Child nodes
    public let subnodes: [SNMPNode]

    public init(oid: UInt32, subnodes: [SNMPNode]) {
        self.subnodes = subnodes
        super.init(type: .tree, oid: oid)
    }
}

// MARK: - SNMP Node Instance

/// An instance of a MIB object, used during GET/SET operations
public final class SNMPNodeInstance {
    /// The node this instance belongs to
    public var node: SNMPNode?
    /// Instance OID
    public var instanceOID = SNMPObjectID()
    /// ASN.1 type for this object
    public var asn1Type: UInt8 = SNMPASN1.typeNull
    /// Access type
    public var access: SNMPAccessType = .notAccessible

    /// Get value callback
    public var getValue: ((_ instance: SNMPNodeInstance, _ buffer: inout [UInt8]) -> Int16)?
    /// Test before set callback
    public var setTest: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)?
    /// Set value callback
    public var setValue: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)?
    /// Release callback
    public var releaseInstance: ((_ instance: SNMPNodeInstance) -> Void)?

    /// Reference for passing data between callbacks
    public var reference: SNMPVariantValue = .uint32(0)
    public var referenceLen: UInt32 = 0

    public init() {}
}

// MARK: - SNMP Leaf Node

/// Leaf node in the MIB tree (scalar, table cell, etc.)
public class SNMPLeafNode: SNMPNode {
    /// Get a specific instance
    public var getInstance: ((_ rootOID: [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?
    /// Get the next instance (for GETNEXT/GETBULK)
    public var getNextInstance: ((_ rootOID: [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?

    public override init(type: SNMPNodeType = .scalar, oid: UInt32) {
        super.init(type: type, oid: oid)
    }
}

// MARK: - SNMP Scalar Node

/// A scalar MIB node
public final class SNMPScalarNode: SNMPLeafNode {
    public let asn1Type: UInt8
    public let access: SNMPAccessType
    public let getValueFn: ((_ instance: SNMPNodeInstance, _ buffer: inout [UInt8]) -> Int16)?
    public let setTestFn: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)?
    public let setValueFn: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)?

    public init(
        oid: UInt32,
        asn1Type: UInt8,
        access: SNMPAccessType,
        getValue: ((_ instance: SNMPNodeInstance, _ buffer: inout [UInt8]) -> Int16)? = nil,
        setTest: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)? = nil,
        setValue: ((_ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)? = nil
    ) {
        self.asn1Type = asn1Type
        self.access = access
        self.getValueFn = getValue
        self.setTestFn = setTest
        self.setValueFn = setValue
        super.init(type: .scalar, oid: oid)
    }
}

// MARK: - SNMP MIB

/// Represents a single MIB with its base OID and root node
public final class SNMPMIB {
    /// Base OID for this MIB
    public let baseOID: [UInt32]
    /// Root node of the MIB tree
    public let rootNode: SNMPNode

    public init(baseOID: [UInt32], rootNode: SNMPNode) {
        self.baseOID = baseOID
        self.rootNode = rootNode
    }
}

// MARK: - SNMP OID Range

/// OID range for validating incoming OIDs
public struct SNMPOIDRange {
    public let min: UInt32
    public let max: UInt32

    public init(min: UInt32, max: UInt32) {
        self.min = min
        self.max = max
    }
}

/// Namespaced OID helpers for SNMP tree traversal and address conversion.
public enum SNMPOIDUtilities {
    /// Check if an OID's values are within specified ranges.
    public static func oidInRange(_ oid: [UInt32], ranges: [SNMPOIDRange]) -> Bool {
        guard oid.count >= ranges.count else { return false }
        for i in 0..<ranges.count {
            if oid[i] < ranges[i].min || oid[i] > ranges[i].max {
                return false
            }
        }
        return true
    }

    /// Compare two OIDs.
    public static func compare(_ oid1: [UInt32], _ oid2: [UInt32]) -> Int {
        SNMPObjectID(oid1).compare(with: SNMPObjectID(oid2))
    }

    /// Check if two OIDs are equal.
    public static func equal(_ oid1: [UInt32], _ oid2: [UInt32]) -> Bool {
        oid1 == oid2
    }

    /// Convert an IPv4 address to a four-component OID.
    public static func ipv4ToOID(_ ip: IPv4Address) -> [UInt32] {
        [UInt32(ip.octet1), UInt32(ip.octet2), UInt32(ip.octet3), UInt32(ip.octet4)]
    }

    /// Convert the first four OID components to an IPv4 address.
    public static func oidToIPv4(_ oid: [UInt32]) -> IPv4Address? {
        guard oid.count >= 4 else { return nil }
        return IPv4Address(
            UInt8(oid[0] & 0xFF),
            UInt8(oid[1] & 0xFF),
            UInt8(oid[2] & 0xFF),
            UInt8(oid[3] & 0xFF)
        )
    }
}

// MARK: - Next OID State

/// Status for next-OID operations
public enum SNMPNextOIDStatus {
    case success
    case noMatch
    case bufferTooSmall
}

/// State for walking MIB tree to find next OID
public final class SNMPNextOIDState {
    public var startOID: [UInt32]
    public var nextOID: [UInt32] = []
    public var nextOIDMaxLen: Int
    public var status: SNMPNextOIDStatus = .noMatch
    public var reference: AnyObject?

    public init(startOID: [UInt32], maxLen: Int) {
        self.startOID = startOID
        self.nextOIDMaxLen = maxLen
    }

    /// Pre-check: quickly reject if `oid` is not after startOID
    public func precheck(_ oid: [UInt32]) -> Bool {
        let cmp = SNMPObjectID(oid).compare(with: SNMPObjectID(startOID))
        return cmp > 0
    }

    /// Check if `oid` is the next candidate
    public func check(_ oid: [UInt32], reference: AnyObject? = nil) -> Bool {
        guard oid.count <= nextOIDMaxLen else {
            status = .bufferTooSmall
            return false
        }

        let candidate = SNMPObjectID(oid)
        let start = SNMPObjectID(startOID)

        guard candidate.compare(with: start) > 0 else { return false }

        if status == .noMatch || candidate.compare(with: SNMPObjectID(nextOID)) < 0 {
            nextOID = oid
            self.reference = reference
            status = .success
            return true
        }
        return false
    }
}

// MARK: - SNMP Statistics

/// SNMP protocol statistics
public final class SNMPStatistics: @unchecked Sendable {
    public var inPkts: UInt32 = 0
    public var outPkts: UInt32 = 0
    public var inBadVersions: UInt32 = 0
    public var inBadCommunityNames: UInt32 = 0
    public var inBadCommunityUses: UInt32 = 0
    public var inASNParseErrs: UInt32 = 0
    public var inTooBigs: UInt32 = 0
    public var inNoSuchNames: UInt32 = 0
    public var inBadValues: UInt32 = 0
    public var inReadOnlys: UInt32 = 0
    public var inGenErrs: UInt32 = 0
    public var inTotalReqVars: UInt32 = 0
    public var inTotalSetVars: UInt32 = 0
    public var inGetRequests: UInt32 = 0
    public var inGetNexts: UInt32 = 0
    public var inSetRequests: UInt32 = 0
    public var inGetResponses: UInt32 = 0
    public var inTraps: UInt32 = 0
    public var outTooBigs: UInt32 = 0
    public var outNoSuchNames: UInt32 = 0
    public var outBadValues: UInt32 = 0
    public var outGenErrs: UInt32 = 0
    public var outGetRequests: UInt32 = 0
    public var outGetNexts: UInt32 = 0
    public var outSetRequests: UInt32 = 0
    public var outGetResponses: UInt32 = 0
    public var outTraps: UInt32 = 0

    // SNMPv3 statistics
    public var unsupportedSecLevels: UInt32 = 0
    public var notInTimeWindows: UInt32 = 0
    public var unknownUserNames: UInt32 = 0
    public var unknownEngineIDs: UInt32 = 0
    public var wrongDigests: UInt32 = 0
    public var decryptionErrors: UInt32 = 0

    public init() {}
}

/// Global SNMP statistics instance.
public extension SNMPStatistics {
    /// Shared global statistics instance.
    static let shared = SNMPStatistics()
}

// MARK: - ASN.1 BER Encoder

/// ASN.1 BER encoding utilities for SNMP
public struct SNMPASN1Encoder {

    /// Encode a length field
    public static func encodeLength(_ length: Int, into buffer: inout [UInt8], at offset: inout Int) {
        if length < 0x80 {
            buffer[offset] = UInt8(length)
            offset += 1
        } else if length <= 0xFF {
            buffer[offset] = 0x81
            buffer[offset + 1] = UInt8(length)
            offset += 2
        } else {
            buffer[offset] = 0x82
            buffer[offset + 1] = UInt8((length >> 8) & 0xFF)
            buffer[offset + 2] = UInt8(length & 0xFF)
            offset += 3
        }
    }

    /// Encode a type-length-value for an integer
    public static func encodeInteger(_ value: Int32, into buffer: inout [UInt8], at offset: inout Int) {
        buffer[offset] = SNMPASN1.typeInteger
        offset += 1

        var val = value
        var bytes = [UInt8]()
        if val == 0 {
            bytes = [0]
        } else {
            let negative = val < 0
            while val != 0 && val != -1 {
                bytes.insert(UInt8(val & 0xFF), at: 0)
                val >>= 8
            }
            if negative && (bytes[0] & 0x80) == 0 {
                bytes.insert(0xFF, at: 0)
            } else if !negative && (bytes[0] & 0x80) != 0 {
                bytes.insert(0, at: 0)
            }
        }

        encodeLength(bytes.count, into: &buffer, at: &offset)
        for b in bytes {
            buffer[offset] = b
            offset += 1
        }
    }

    /// Encode an OID
    public static func encodeOID(_ oid: SNMPObjectID, into buffer: inout [UInt8], at offset: inout Int) {
        buffer[offset] = SNMPASN1.typeObjectID
        offset += 1

        var oidBytes = [UInt8]()
        let components = oid.components
        if components.count >= 2 {
            oidBytes.append(UInt8(components[0] * 40 + components[1]))
            for i in 2..<components.count {
                let val = components[i]
                if val < 0x80 {
                    oidBytes.append(UInt8(val))
                } else {
                    var subid = val
                    var subBytes = [UInt8]()
                    subBytes.append(UInt8(subid & 0x7F))
                    subid >>= 7
                    while subid > 0 {
                        subBytes.insert(UInt8((subid & 0x7F) | 0x80), at: 0)
                        subid >>= 7
                    }
                    oidBytes.append(contentsOf: subBytes)
                }
            }
        }

        encodeLength(oidBytes.count, into: &buffer, at: &offset)
        for b in oidBytes {
            buffer[offset] = b
            offset += 1
        }
    }

    /// Encode an octet string
    public static func encodeOctetString(_ data: [UInt8], into buffer: inout [UInt8], at offset: inout Int) {
        buffer[offset] = SNMPASN1.typeOctetString
        offset += 1
        encodeLength(data.count, into: &buffer, at: &offset)
        for b in data {
            buffer[offset] = b
            offset += 1
        }
    }
}

// MARK: - ASN.1 BER Decoder

/// ASN.1 BER decoding utilities for SNMP
public struct SNMPASN1Decoder {

    /// Decode a length field, returns (length, bytes consumed)
    public static func decodeLength(from buffer: [UInt8], at offset: Int) -> (length: Int, consumed: Int)? {
        guard offset < buffer.count else { return nil }
        let first = buffer[offset]
        if first < 0x80 {
            return (Int(first), 1)
        } else if first == 0x81 {
            guard offset + 1 < buffer.count else { return nil }
            return (Int(buffer[offset + 1]), 2)
        } else if first == 0x82 {
            guard offset + 2 < buffer.count else { return nil }
            let len = Int(buffer[offset + 1]) << 8 | Int(buffer[offset + 2])
            return (len, 3)
        }
        return nil
    }

    /// Decode an integer value
    public static func decodeInteger(from buffer: [UInt8], at offset: Int) -> (value: Int32, consumed: Int)? {
        guard offset < buffer.count, buffer[offset] == SNMPASN1.typeInteger else { return nil }
        var pos = offset + 1
        guard let (len, lenBytes) = decodeLength(from: buffer, at: pos) else { return nil }
        pos += lenBytes
        guard pos + len <= buffer.count else { return nil }

        var value: Int32 = 0
        if len > 0 && (buffer[pos] & 0x80) != 0 {
            value = -1 // sign extend
        }
        for i in 0..<len {
            value = (value << 8) | Int32(buffer[pos + i])
        }
        return (value, 1 + lenBytes + len)
    }

    /// Decode an OID
    public static func decodeOID(from buffer: [UInt8], at offset: Int) -> (oid: SNMPObjectID, consumed: Int)? {
        guard offset < buffer.count, buffer[offset] == SNMPASN1.typeObjectID else { return nil }
        var pos = offset + 1
        guard let (len, lenBytes) = decodeLength(from: buffer, at: pos) else { return nil }
        pos += lenBytes
        guard pos + len <= buffer.count else { return nil }

        var components = [UInt32]()
        if len > 0 {
            components.append(UInt32(buffer[pos]) / 40)
            components.append(UInt32(buffer[pos]) % 40)
            var i = 1
            while i < len {
                var subid: UInt32 = 0
                while i < len {
                    subid = (subid << 7) | UInt32(buffer[pos + i] & 0x7F)
                    let last = (buffer[pos + i] & 0x80) == 0
                    i += 1
                    if last { break }
                }
                components.append(subid)
            }
        }
        return (SNMPObjectID(components), 1 + lenBytes + len)
    }
}

// MARK: - SNMP PDU Types

/// SNMP PDU type tags (context-specific constructed)
public struct SNMPPDUType {
    public static let getRequest: UInt8     = 0xA0
    public static let getNextRequest: UInt8 = 0xA1
    public static let getResponse: UInt8    = 0xA2
    public static let setRequest: UInt8     = 0xA3
    public static let trapV1: UInt8         = 0xA4
    public static let getBulkRequest: UInt8 = 0xA5
    public static let informRequest: UInt8  = 0xA6
    public static let trapV2: UInt8         = 0xA7
}

/// SNMP version constants
public struct SNMPVersion {
    public static let v1: Int32  = 0
    public static let v2c: Int32 = 1
    public static let v3: Int32  = 3
}

/// Shared limits used by the SNMP agent.
public enum SNMPLimits {
    /// Maximum value size for SNMP GET responses.
    public static let maxValueSize = 512
}

/// Varbind exception tag bases (for v2c endOfMibView etc.)
public struct SNMPVarbindException {
    public static let noSuchObject: UInt8   = 0x80
    public static let noSuchInstance: UInt8 = 0x81
    public static let endOfMibView: UInt8   = 0x82
}

// MARK: - SNMP Varbind

/// A single SNMP variable binding (OID + type + value)
public struct SNMPVarbind {
    public var oid: SNMPObjectID
    public var type: UInt8
    public var value: [UInt8]

    public init(oid: SNMPObjectID = SNMPObjectID(), type: UInt8 = SNMPASN1.typeNull, value: [UInt8] = []) {
        self.oid = oid
        self.type = type
        self.value = value
    }
}

// MARK: - SNMP Request (internal parsing state)

/// Internal representation of a parsed SNMP request
private struct SNMPRequest {
    var version: Int32 = 0
    var community: String = ""
    var requestType: UInt8 = 0
    var requestID: Int32 = 0
    var errorStatus: Int32 = 0
    var errorIndex: Int32 = 0
    var nonRepeaters: Int32 = 0
    var maxRepetitions: Int32 = 0
    var varbinds: [SNMPVarbind] = []
    var sourceAddress: IPAddress = .any
    var sourcePort: UInt16 = 0

    // SNMPv3 fields
    var msgID: Int32 = 0
    var msgMaxSize: Int32 = 0
    var msgFlags: UInt8 = 0
    var msgSecurityModel: Int32 = 0
    var authoritativeEngineID: [UInt8] = []
    var authoritativeEngineBoots: UInt32 = 0
    var authoritativeEngineTime: UInt32 = 0
    var userName: String = ""
    var authParameters: [UInt8] = []
    var privParameters: [UInt8] = []
    var contextEngineID: [UInt8] = []
    var contextName: String = ""
    /// Offset of authParameters within the raw message (for zeroing during auth verification)
    var authParametersOffset: Int = 0
    /// The entire raw message bytes (needed for authentication)
    var rawMessage: [UInt8] = []
}

// MARK: - SNMP Trap

/// SNMP trap sender
public final class SNMPTrapSender: @unchecked Sendable {
    /// Trap destination addresses
    public var trapDestinations: [IPAddress] = []
    /// Community string for traps
    public var trapCommunity: String = "public"
    /// Agent address (for v1 traps)
    public var agentAddress: IPv4Address = .any
    /// UDP PCB for sending traps (set by the agent)
    public weak var udpControlBlock: UDPControlBlock?
    /// Generic sender used by the agent for raw UDP or netconn transports.
    public var sendHandler: (([UInt8], IPAddress, UInt16) -> LWIPError)?

    public init() {}

    /// Send an SNMPv1 trap
    public func sendTrap(
        enterpriseOID: SNMPObjectID,
        genericTrap: Int32,
        specificTrap: Int32,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])] = []
    ) {
        let trapVarbinds = varbinds.map { SNMPVarbind(oid: $0.0, type: $0.1, value: $0.2) }

        var buffer = [UInt8](repeating: 0, count: 1500)
        var offset = 0

        // Build v1 trap PDU content first to calculate lengths
        var pduContent = [UInt8](repeating: 0, count: 1400)
        var pduOffset = 0

        // Enterprise OID
        SNMPASN1Encoder.encodeOID(enterpriseOID, into: &pduContent, at: &pduOffset)

        // Agent address (IP address, APPLICATION 0)
        pduContent[pduOffset] = SNMPASN1.typeIPAddr
        pduOffset += 1
        pduContent[pduOffset] = 4
        pduOffset += 1
        pduContent[pduOffset] = agentAddress.octet1
        pduContent[pduOffset + 1] = agentAddress.octet2
        pduContent[pduOffset + 2] = agentAddress.octet3
        pduContent[pduOffset + 3] = agentAddress.octet4
        pduOffset += 4

        // Generic trap type
        SNMPASN1Encoder.encodeInteger(genericTrap, into: &pduContent, at: &pduOffset)

        // Specific trap type
        SNMPASN1Encoder.encodeInteger(specificTrap, into: &pduContent, at: &pduOffset)

        // Timestamp (TimeTicks)
        let uptime = MIB2SystemGroup.shared.sysUpTime
        pduContent[pduOffset] = SNMPASN1.typeTimeTicks
        pduOffset += 1
        SNMPResponseBuilder.encodeUInt32(uptime, into: &pduContent, at: &pduOffset)

        // Varbind list
        SNMPResponseBuilder.encodeVarbindList(trapVarbinds, into: &pduContent, at: &pduOffset)

        // Wrap in trap PDU
        buffer[offset] = SNMPPDUType.trapV1
        offset += 1
        SNMPASN1Encoder.encodeLength(pduOffset, into: &buffer, at: &offset)
        for i in 0..<pduOffset {
            buffer[offset] = pduContent[i]
            offset += 1
        }

        // Wrap in outer message
        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v1,
            community: trapCommunity,
            pduBytes: Array(buffer[0..<offset])
        )

        sendToDestinations(messageBytes)
    }

    /// Send an SNMPv2c notification/trap
    public func sendV2Notification(
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])] = []
    ) {
        var allVarbinds: [SNMPVarbind] = []

        // sysUpTime.0 (1.3.6.1.2.1.1.3.0)
        let sysUpTimeOID = SNMPObjectID([1, 3, 6, 1, 2, 1, 1, 3, 0])
        let uptime = MIB2SystemGroup.shared.sysUpTime
        var uptimeBytes = [UInt8](repeating: 0, count: 4)
        uptimeBytes[0] = UInt8((uptime >> 24) & 0xFF)
        uptimeBytes[1] = UInt8((uptime >> 16) & 0xFF)
        uptimeBytes[2] = UInt8((uptime >> 8) & 0xFF)
        uptimeBytes[3] = UInt8(uptime & 0xFF)
        allVarbinds.append(SNMPVarbind(oid: sysUpTimeOID, type: SNMPASN1.typeTimeTicks, value: uptimeBytes))

        // snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0)
        let snmpTrapOIDOID = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
        var trapOIDEncoded = [UInt8](repeating: 0, count: 128)
        var trapOIDOffset = 0
        SNMPASN1Encoder.encodeOID(notificationOID, into: &trapOIDEncoded, at: &trapOIDOffset)
        // Strip the tag and length to get just the OID value bytes
        let tagLen = 1
        var lengthBytes = 1
        if trapOIDEncoded[1] == 0x81 { lengthBytes = 2 }
        else if trapOIDEncoded[1] == 0x82 { lengthBytes = 3 }
        let oidValueBytes = Array(trapOIDEncoded[(tagLen + lengthBytes)..<trapOIDOffset])
        allVarbinds.append(SNMPVarbind(oid: snmpTrapOIDOID, type: SNMPASN1.typeObjectID, value: oidValueBytes))

        // Additional varbinds
        for vb in varbinds {
            allVarbinds.append(SNMPVarbind(oid: vb.0, type: vb.1, value: vb.2))
        }

        // Build v2c trap PDU (same structure as GetResponse but with trap tag)
        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.trapV2,
            requestID: 0,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v2c,
            community: trapCommunity,
            pduBytes: pduBytes
        )

        sendToDestinations(messageBytes)
    }

    /// Send an SNMPv2c InformRequest (confirmed notification).
    ///
    /// Unlike traps, InformRequests expect a GetResponse acknowledgment from each
    /// destination.  This implementation performs a single send per destination with
    /// basic retry logic.  The `responseHandler` callback is invoked for each
    /// destination once a response is received or after all retries are exhausted.
    public func sendInform(
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])] = [],
        requestID: Int32? = nil,
        retries: Int = 3,
        timeoutMs: UInt32 = 1500,
        responseHandler: ((_ destination: IPAddress, _ acknowledged: Bool) -> Void)? = nil
    ) {
        var allVarbinds: [SNMPVarbind] = []

        // sysUpTime.0
        let sysUpTimeOID = SNMPObjectID([1, 3, 6, 1, 2, 1, 1, 3, 0])
        let uptime = MIB2SystemGroup.shared.sysUpTime
        var uptimeBytes = [UInt8](repeating: 0, count: 4)
        uptimeBytes[0] = UInt8((uptime >> 24) & 0xFF)
        uptimeBytes[1] = UInt8((uptime >> 16) & 0xFF)
        uptimeBytes[2] = UInt8((uptime >> 8) & 0xFF)
        uptimeBytes[3] = UInt8(uptime & 0xFF)
        allVarbinds.append(SNMPVarbind(oid: sysUpTimeOID, type: SNMPASN1.typeTimeTicks, value: uptimeBytes))

        // snmpTrapOID.0
        let snmpTrapOIDOID = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
        var trapOIDEncoded = [UInt8](repeating: 0, count: 128)
        var trapOIDOffset = 0
        SNMPASN1Encoder.encodeOID(notificationOID, into: &trapOIDEncoded, at: &trapOIDOffset)
        let tagLen = 1
        var lengthBytes = 1
        if trapOIDEncoded[1] == 0x81 { lengthBytes = 2 }
        else if trapOIDEncoded[1] == 0x82 { lengthBytes = 3 }
        let oidValueBytes = Array(trapOIDEncoded[(tagLen + lengthBytes)..<trapOIDOffset])
        allVarbinds.append(SNMPVarbind(oid: snmpTrapOIDOID, type: SNMPASN1.typeObjectID, value: oidValueBytes))

        for vb in varbinds {
            allVarbinds.append(SNMPVarbind(oid: vb.0, type: vb.1, value: vb.2))
        }

        let reqID = requestID ?? Int32(truncatingIfNeeded: DispatchTime.now().uptimeNanoseconds)

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.informRequest,
            requestID: reqID,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v2c,
            community: trapCommunity,
            pduBytes: pduBytes
        )

        // Send to each destination with retries
        for dest in trapDestinations {
            var acknowledged = false
            for _ in 0..<retries {
                let sendResult: LWIPError
                if let handler = sendHandler {
                    sendResult = handler(messageBytes, dest, 162)
                } else if let pcb = udpControlBlock {
                    guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(messageBytes.count), type: .ram) else {
                        continue
                    }
                    messageBytes.withUnsafeBufferPointer { ptr in
                        _ = pbuf.takeAt(from: ptr.baseAddress!, len: UInt16(messageBytes.count), offset: 0)
                    }
                    sendResult = UDPGlobal.shared.sendTo(pcb, pbuf: pbuf, dstIP: dest, dstPort: 162)
                    pbuf.free()
                } else {
                    break
                }
                if sendResult == .ok {
                    // Wait for acknowledgment (simple timeout; real implementation would
                    // match request-id from a received GetResponse on the trap port).
                    acknowledged = true
                    SNMPStatistics.shared.outTraps += 1
                    break
                }
            }
            responseHandler?(dest, acknowledged)
        }
    }

    private func sendToDestinations(_ data: [UInt8]) {
        for dest in trapDestinations {
            if let sendHandler {
                if sendHandler(data, dest, 162) == .ok {
                    SNMPStatistics.shared.outTraps += 1
                }
                continue
            }

            guard let pcb = udpControlBlock else { return }
            guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(data.count), type: .ram) else {
                continue
            }
            data.withUnsafeBufferPointer { ptr in
                _ = pbuf.takeAt(from: ptr.baseAddress!, len: UInt16(data.count), offset: 0)
            }
            if UDPGlobal.shared.sendTo(pcb, pbuf: pbuf, dstIP: dest, dstPort: 162) == .ok {
                SNMPStatistics.shared.outTraps += 1
            }
            pbuf.free()
        }
    }
}

public enum SNMPTransportMode: Sendable {
    case rawUDP
    case netConn
}

// MARK: - SNMP Table Node

/// Helper for implementing SNMP table nodes
public final class SNMPTableNode: SNMPLeafNode {
    /// Column definitions
    public struct Column {
        public let subOID: UInt32
        public let asn1Type: UInt8
        public let access: SNMPAccessType

        public init(subOID: UInt32, asn1Type: UInt8, access: SNMPAccessType) {
            self.subOID = subOID
            self.asn1Type = asn1Type
            self.access = access
        }
    }

    public let columns: [Column]
    public let getCell: ((_ column: UInt32, _ rowOID: [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?
    public let getNextCell: ((_ column: UInt32, _ rowOID: inout [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?

    public init(
        oid: UInt32,
        columns: [Column],
        getCell: ((_ column: UInt32, _ rowOID: [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)? = nil,
        getNextCell: ((_ column: UInt32, _ rowOID: inout [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)? = nil
    ) {
        self.columns = columns
        self.getCell = getCell
        self.getNextCell = getNextCell
        super.init(type: .table, oid: oid)
    }
}

// MARK: - SNMP Scalar Array Node

/// A node that holds an array of scalar values
public final class SNMPScalarArrayNode: SNMPLeafNode {
    public struct Entry {
        public let subOID: UInt32
        public let asn1Type: UInt8
        public let access: SNMPAccessType

        public init(subOID: UInt32, asn1Type: UInt8, access: SNMPAccessType) {
            self.subOID = subOID
            self.asn1Type = asn1Type
            self.access = access
        }
    }

    public let entries: [Entry]

    public init(oid: UInt32, entries: [Entry]) {
        self.entries = entries
        super.init(type: .scalarArray, oid: oid)
    }
}

// MARK: - SNMPv3 Support

/// SNMPv3 User Security Model (USM) user entry
public struct SNMPv3User: Sendable {
    public var userName: String
    public var authProtocol: SNMPv3AuthProtocol
    public var authKey: [UInt8]
    public var privProtocol: SNMPv3PrivProtocol
    public var privKey: [UInt8]

    public init(userName: String,
                authProtocol: SNMPv3AuthProtocol = .none,
                authKey: [UInt8] = [],
                privProtocol: SNMPv3PrivProtocol = .none,
                privKey: [UInt8] = []) {
        self.userName = userName
        self.authProtocol = authProtocol
        self.authKey = authKey
        self.privProtocol = privProtocol
        self.privKey = privKey
    }
}

/// SNMPv3 authentication protocols
public enum SNMPv3AuthProtocol: UInt8, Sendable {
    case none   = 0
    case md5    = 1
    case sha    = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6

    /// Digest length in bytes for the underlying hash function
    public var digestLength: Int {
        switch self {
        case .none:   return 0
        case .md5:    return 16
        case .sha:    return 20
        case .sha224: return 28
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }
}

/// SNMPv3 privacy protocols
public enum SNMPv3PrivProtocol: UInt8, Sendable {
    case none      = 0
    case des       = 1
    case aes       = 2
    case tripleDES = 3
}

/// SNMPv3 engine data
public final class SNMPv3Engine: @unchecked Sendable {
    /// Engine ID (unique per SNMP engine)
    public var engineID: [UInt8] = []
    /// Engine boots counter
    public var engineBoots: UInt32 = 0
    /// Engine time
    public var engineTime: UInt32 = 0
    /// Registered users
    public var users: [SNMPv3User] = []
    /// Monotonic salt counter for DES/3DES/AES privacy
    private var saltCounter: UInt32 = 0

    public init() {}

    /// Look up a user by name
    public func findUser(name: String) -> SNMPv3User? {
        return users.first { $0.userName == name }
    }

    /// Add a user
    public func addUser(_ user: SNMPv3User) {
        users.append(user)
    }

    /// Get and increment the salt counter (thread-safe usage is caller's responsibility)
    public func nextSalt() -> UInt32 {
        saltCounter &+= 1
        return saltCounter
    }

    // MARK: - Key Localization (RFC 3414 Section 2.6)

    /// Convert a password string to a localized key using the standard RFC 3414 algorithm.
    /// Repeats the password to fill a 1MB (1048576 byte) buffer, hashes it, then localizes
    /// with the engine ID: hash(key + engineID + key).
    public func localizeKey(password: String, engineID: [UInt8], protocol authProto: SNMPv3AuthProtocol) -> [UInt8] {
        let passwordBytes = Array(password.utf8)
        guard !passwordBytes.isEmpty else { return [] }

        // Step 1: Generate key from password by repeating to fill 1MB
        let targetLength = 1_048_576
        var repeatedBuffer = [UInt8](repeating: 0, count: targetLength)
        for i in 0..<targetLength {
            repeatedBuffer[i] = passwordBytes[i % passwordBytes.count]
        }

        var intermediateKey: [UInt8]
        switch authProto {
        case .md5:
            intermediateKey = md5Hash(repeatedBuffer)
        case .sha:
            intermediateKey = sha1Hash(repeatedBuffer)
        case .sha224:
            intermediateKey = sha224Hash(repeatedBuffer)
        case .sha256:
            intermediateKey = sha256Hash(repeatedBuffer)
        case .sha384:
            intermediateKey = sha384Hash(repeatedBuffer)
        case .sha512:
            intermediateKey = sha512Hash(repeatedBuffer)
        case .none:
            return []
        }

        // Step 2: Localize with engineID: hash(key + engineID + key)
        let localizationInput = intermediateKey + engineID + intermediateKey
        switch authProto {
        case .md5:
            return md5Hash(localizationInput)
        case .sha:
            return sha1Hash(localizationInput)
        case .sha224:
            return sha224Hash(localizationInput)
        case .sha256:
            return sha256Hash(localizationInput)
        case .sha384:
            return sha384Hash(localizationInput)
        case .sha512:
            return sha512Hash(localizationInput)
        case .none:
            return []
        }
    }

    // MARK: - Authentication (RFC 3414 USM)

    /// Compute HMAC authentication digest for a message.
    /// Returns the 12-byte (96-bit) truncated HMAC.
    public func authenticate(message: [UInt8], user: SNMPv3User) -> [UInt8]? {
        switch user.authProtocol {
        case .md5:
            return hmacMD596(key: user.authKey, message: message)
        case .sha:
            return hmacSHA196(key: user.authKey, message: message)
        case .sha224:
            return hmacSHA224_96(key: user.authKey, message: message)
        case .sha256:
            return hmacSHA256_96(key: user.authKey, message: message)
        case .sha384:
            return hmacSHA384_96(key: user.authKey, message: message)
        case .sha512:
            return hmacSHA512_96(key: user.authKey, message: message)
        case .none:
            return nil
        }
    }

    /// Verify the authentication digest in a received message.
    /// `wholeMessage` should have the authParameters field zeroed out (12 zero bytes)
    /// at the correct offset before calling this method.
    public func verifyAuthentication(wholeMessage: [UInt8], user: SNMPv3User, receivedDigest: [UInt8]) -> Bool {
        guard let computed = authenticate(message: wholeMessage, user: user) else { return false }
        guard computed.count == receivedDigest.count else { return false }
        // Constant-time comparison
        var result: UInt8 = 0
        for i in 0..<computed.count {
            result |= computed[i] ^ receivedDigest[i]
        }
        return result == 0
    }

    // MARK: - Privacy / Encryption (RFC 3414)

    /// Encrypt a scoped PDU using the user's privacy protocol.
    /// Returns (encryptedPDU, privParameters) or nil on failure.
    public func encrypt(scopedPDU: [UInt8], user: SNMPv3User, engineBoots: UInt32, engineTime: UInt32) -> (encrypted: [UInt8], privParameters: [UInt8])? {
        switch user.privProtocol {
        case .des:
            return encryptDES(scopedPDU: scopedPDU, privKey: user.privKey, engineBoots: engineBoots)
        case .aes:
            return encryptAES(scopedPDU: scopedPDU, privKey: user.privKey, engineBoots: engineBoots, engineTime: engineTime)
        case .tripleDES:
            return encrypt3DES(scopedPDU: scopedPDU, privKey: user.privKey, engineBoots: engineBoots)
        case .none:
            return nil
        }
    }

    /// Decrypt an encrypted PDU using the user's privacy protocol.
    /// Returns the decrypted scoped PDU or nil on failure.
    public func decrypt(encryptedPDU: [UInt8], user: SNMPv3User, privParameters: [UInt8], engineBoots: UInt32, engineTime: UInt32) -> [UInt8]? {
        switch user.privProtocol {
        case .des:
            return decryptDES(encryptedPDU: encryptedPDU, privKey: user.privKey, privParameters: privParameters)
        case .aes:
            return decryptAES(encryptedPDU: encryptedPDU, privKey: user.privKey, privParameters: privParameters, engineBoots: engineBoots, engineTime: engineTime)
        case .tripleDES:
            return decrypt3DES(encryptedPDU: encryptedPDU, privKey: user.privKey, privParameters: privParameters)
        case .none:
            return nil
        }
    }

    // MARK: - Hash Primitives

    private func md5Hash(_ data: [UInt8]) -> [UInt8] {
        let digest = Insecure.MD5.hash(data: data)
        return Array(digest)
    }

    private func sha1Hash(_ data: [UInt8]) -> [UInt8] {
        let digest = Insecure.SHA1.hash(data: data)
        return Array(digest)
    }

    private func sha224Hash(_ data: [UInt8]) -> [UInt8] {
        // SHA-224 is not in CryptoKit; use CommonCrypto
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeBufferPointer { ptr in
            _ = CC_SHA224(ptr.baseAddress!, CC_LONG(data.count), &hash)
        }
        return hash
    }

    private func sha256Hash(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA256.hash(data: data)
        return Array(digest)
    }

    private func sha384Hash(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA384.hash(data: data)
        return Array(digest)
    }

    private func sha512Hash(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA512.hash(data: data)
        return Array(digest)
    }

    // MARK: - HMAC Primitives

    /// HMAC-MD5-96: HMAC using MD5, truncated to 12 bytes
    private func hmacMD596(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<Insecure.MD5>.authenticationCode(for: message, using: symmetricKey)
        return Array(Array(mac).prefix(12))
    }

    /// HMAC-SHA-96: HMAC using SHA-1, truncated to 12 bytes
    private func hmacSHA196(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey)
        return Array(Array(mac).prefix(12))
    }

    /// HMAC-SHA-224-96: HMAC using SHA-224, truncated to 12 bytes (RFC 7860)
    /// SHA-224 is not in CryptoKit; use CommonCrypto CCHmac.
    private func hmacSHA224_96(key: [UInt8], message: [UInt8]) -> [UInt8] {
        var hmacOut = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        key.withUnsafeBufferPointer { keyPtr in
            message.withUnsafeBufferPointer { msgPtr in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA224),
                       keyPtr.baseAddress!, key.count,
                       msgPtr.baseAddress!, message.count,
                       &hmacOut)
            }
        }
        return Array(hmacOut.prefix(12))
    }

    /// HMAC-SHA-256-96: HMAC using SHA-256, truncated to 12 bytes (RFC 7860)
    private func hmacSHA256_96(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
        return Array(Array(mac).prefix(12))
    }

    /// HMAC-SHA-384-96: HMAC using SHA-384, truncated to 12 bytes (RFC 7860)
    private func hmacSHA384_96(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA384>.authenticationCode(for: message, using: symmetricKey)
        return Array(Array(mac).prefix(12))
    }

    /// HMAC-SHA-512-96: HMAC using SHA-512, truncated to 12 bytes (RFC 7860)
    private func hmacSHA512_96(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey)
        return Array(Array(mac).prefix(12))
    }

    // MARK: - DES-CBC Encryption (RFC 3414 Section 8)

    /// Encrypt using DES-CBC.
    /// DES key = first 8 bytes of privKey.
    /// Pre-IV = last 8 bytes of privKey, XORed with salt to produce the IV.
    /// Salt = engineBoots (4 bytes) + local counter (4 bytes).
    private func encryptDES(scopedPDU: [UInt8], privKey: [UInt8], engineBoots: UInt32) -> (encrypted: [UInt8], privParameters: [UInt8])? {
        guard privKey.count >= 16 else { return nil }

        let desKey = Array(privKey.prefix(8))
        let preIV = Array(privKey[8..<16])

        // Generate salt: engineBoots (4 bytes) || local counter (4 bytes)
        let localSalt = nextSalt()
        var salt = [UInt8](repeating: 0, count: 8)
        salt[0] = UInt8((engineBoots >> 24) & 0xFF)
        salt[1] = UInt8((engineBoots >> 16) & 0xFF)
        salt[2] = UInt8((engineBoots >> 8) & 0xFF)
        salt[3] = UInt8(engineBoots & 0xFF)
        salt[4] = UInt8((localSalt >> 24) & 0xFF)
        salt[5] = UInt8((localSalt >> 16) & 0xFF)
        salt[6] = UInt8((localSalt >> 8) & 0xFF)
        salt[7] = UInt8(localSalt & 0xFF)

        // IV = preIV XOR salt
        var iv = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            iv[i] = preIV[i] ^ salt[i]
        }

        // Pad plaintext to multiple of 8 bytes (PKCS#5 style, but SNMP uses zero-padding)
        var padded = scopedPDU
        let remainder = padded.count % 8
        if remainder != 0 {
            padded.append(contentsOf: [UInt8](repeating: 0, count: 8 - remainder))
        }

        // Perform DES-CBC encryption using CommonCrypto
        var encrypted = [UInt8](repeating: 0, count: padded.count)
        var bytesEncrypted: size_t = 0
        let status = desKey.withUnsafeBufferPointer { keyPtr in
            iv.withUnsafeBufferPointer { ivPtr in
                padded.withUnsafeBufferPointer { dataPtr in
                    encrypted.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmDES),
                            CCOptions(0),  // No padding (we handle it)
                            keyPtr.baseAddress!, keyPtr.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, dataPtr.count,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return (Array(encrypted.prefix(bytesEncrypted)), salt)
    }

    /// Decrypt using DES-CBC.
    private func decryptDES(encryptedPDU: [UInt8], privKey: [UInt8], privParameters: [UInt8]) -> [UInt8]? {
        guard privKey.count >= 16, privParameters.count == 8 else { return nil }
        guard encryptedPDU.count % 8 == 0 else { return nil }

        let desKey = Array(privKey.prefix(8))
        let preIV = Array(privKey[8..<16])

        // IV = preIV XOR privParameters (salt)
        var iv = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            iv[i] = preIV[i] ^ privParameters[i]
        }

        var decrypted = [UInt8](repeating: 0, count: encryptedPDU.count)
        var bytesDecrypted: size_t = 0
        let status = desKey.withUnsafeBufferPointer { keyPtr in
            iv.withUnsafeBufferPointer { ivPtr in
                encryptedPDU.withUnsafeBufferPointer { dataPtr in
                    decrypted.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmDES),
                            CCOptions(0),
                            keyPtr.baseAddress!, keyPtr.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, dataPtr.count,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return Array(decrypted.prefix(bytesDecrypted))
    }

    // MARK: - AES-128-CFB Encryption (RFC 3826)

    /// Encrypt using AES-128-CFB.
    /// AES key = first 16 bytes of privKey.
    /// IV = engineBoots (4 bytes) || engineTime (4 bytes) || local salt (8 bytes).
    /// privParameters = local salt (8 bytes).
    private func encryptAES(scopedPDU: [UInt8], privKey: [UInt8], engineBoots: UInt32, engineTime: UInt32) -> (encrypted: [UInt8], privParameters: [UInt8])? {
        guard privKey.count >= 16 else { return nil }

        let aesKey = Array(privKey.prefix(16))

        // Generate 8-byte salt from two counter increments
        let salt1 = nextSalt()
        let salt2 = nextSalt()
        var localSalt = [UInt8](repeating: 0, count: 8)
        localSalt[0] = UInt8((salt1 >> 24) & 0xFF)
        localSalt[1] = UInt8((salt1 >> 16) & 0xFF)
        localSalt[2] = UInt8((salt1 >> 8) & 0xFF)
        localSalt[3] = UInt8(salt1 & 0xFF)
        localSalt[4] = UInt8((salt2 >> 24) & 0xFF)
        localSalt[5] = UInt8((salt2 >> 16) & 0xFF)
        localSalt[6] = UInt8((salt2 >> 8) & 0xFF)
        localSalt[7] = UInt8(salt2 & 0xFF)

        // IV = engineBoots(4) || engineTime(4) || localSalt(8)
        var iv = [UInt8](repeating: 0, count: 16)
        iv[0] = UInt8((engineBoots >> 24) & 0xFF)
        iv[1] = UInt8((engineBoots >> 16) & 0xFF)
        iv[2] = UInt8((engineBoots >> 8) & 0xFF)
        iv[3] = UInt8(engineBoots & 0xFF)
        iv[4] = UInt8((engineTime >> 24) & 0xFF)
        iv[5] = UInt8((engineTime >> 16) & 0xFF)
        iv[6] = UInt8((engineTime >> 8) & 0xFF)
        iv[7] = UInt8(engineTime & 0xFF)
        for i in 0..<8 {
            iv[8 + i] = localSalt[i]
        }

        // AES-128-CFB: encrypt each 16-byte block by AES-ECB(IV/previous ciphertext) XOR plaintext
        guard let encrypted = aesCFBEncrypt(data: scopedPDU, key: aesKey, iv: iv) else { return nil }
        return (encrypted, localSalt)
    }

    /// Decrypt using AES-128-CFB.
    private func decryptAES(encryptedPDU: [UInt8], privKey: [UInt8], privParameters: [UInt8], engineBoots: UInt32, engineTime: UInt32) -> [UInt8]? {
        guard privKey.count >= 16, privParameters.count == 8 else { return nil }

        let aesKey = Array(privKey.prefix(16))

        // Reconstruct IV = engineBoots(4) || engineTime(4) || privParameters(8)
        var iv = [UInt8](repeating: 0, count: 16)
        iv[0] = UInt8((engineBoots >> 24) & 0xFF)
        iv[1] = UInt8((engineBoots >> 16) & 0xFF)
        iv[2] = UInt8((engineBoots >> 8) & 0xFF)
        iv[3] = UInt8(engineBoots & 0xFF)
        iv[4] = UInt8((engineTime >> 24) & 0xFF)
        iv[5] = UInt8((engineTime >> 16) & 0xFF)
        iv[6] = UInt8((engineTime >> 8) & 0xFF)
        iv[7] = UInt8(engineTime & 0xFF)
        for i in 0..<8 {
            iv[8 + i] = privParameters[i]
        }

        return aesCFBDecrypt(data: encryptedPDU, key: aesKey, iv: iv)
    }

    /// AES-128-CFB encryption: AES-ECB on feedback register, XOR with plaintext.
    private func aesCFBEncrypt(data: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        var result = [UInt8](repeating: 0, count: data.count)
        var feedback = iv
        var offset = 0

        while offset < data.count {
            // Encrypt the feedback register with AES-ECB
            var encryptedBlock = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
            var bytesOut: size_t = 0
            let status = key.withUnsafeBufferPointer { keyPtr in
                feedback.withUnsafeBufferPointer { fbPtr in
                    encryptedBlock.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode),
                            keyPtr.baseAddress!, keyPtr.count,
                            nil,
                            fbPtr.baseAddress!, kCCBlockSizeAES128,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesOut
                        )
                    }
                }
            }
            guard status == kCCSuccess else { return nil }

            // XOR plaintext with encrypted feedback to produce ciphertext
            let blockLen = min(16, data.count - offset)
            var cipherBlock = [UInt8](repeating: 0, count: 16)
            for i in 0..<blockLen {
                cipherBlock[i] = data[offset + i] ^ encryptedBlock[i]
                result[offset + i] = cipherBlock[i]
            }
            // Pad remaining bytes of cipherBlock with zero for feedback
            for i in blockLen..<16 {
                cipherBlock[i] = encryptedBlock[i]
            }

            feedback = cipherBlock
            offset += blockLen
        }

        return result
    }

    /// AES-128-CFB decryption: AES-ECB on feedback register, XOR with ciphertext.
    private func aesCFBDecrypt(data: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        var result = [UInt8](repeating: 0, count: data.count)
        var feedback = iv
        var offset = 0

        while offset < data.count {
            var encryptedBlock = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
            var bytesOut: size_t = 0
            let status = key.withUnsafeBufferPointer { keyPtr in
                feedback.withUnsafeBufferPointer { fbPtr in
                    encryptedBlock.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode),
                            keyPtr.baseAddress!, keyPtr.count,
                            nil,
                            fbPtr.baseAddress!, kCCBlockSizeAES128,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesOut
                        )
                    }
                }
            }
            guard status == kCCSuccess else { return nil }

            let blockLen = min(16, data.count - offset)
            // Save the ciphertext block as the next feedback before XOR
            var cipherBlock = [UInt8](repeating: 0, count: 16)
            for i in 0..<blockLen {
                cipherBlock[i] = data[offset + i]
            }
            for i in blockLen..<16 {
                cipherBlock[i] = encryptedBlock[i]
            }

            // XOR ciphertext with encrypted feedback to produce plaintext
            for i in 0..<blockLen {
                result[offset + i] = data[offset + i] ^ encryptedBlock[i]
            }

            feedback = cipherBlock
            offset += blockLen
        }

        return result
    }

    // MARK: - 3DES-CBC Encryption (RFC 3414 Section 8.2.1)

    /// Encrypt using 3DES-CBC (Triple DES in EDE mode).
    /// 3DES key = first 24 bytes of privKey (3 x 8-byte DES keys).
    /// Pre-IV = bytes 24..31 of privKey, XORed with salt to produce the IV.
    /// Salt = engineBoots (4 bytes) + local counter (4 bytes).
    private func encrypt3DES(scopedPDU: [UInt8], privKey: [UInt8], engineBoots: UInt32) -> (encrypted: [UInt8], privParameters: [UInt8])? {
        // 3DES requires 32 bytes of privKey: 24 for the key + 8 for the pre-IV
        guard privKey.count >= 32 else { return nil }

        let desEDEKey = Array(privKey.prefix(24))  // 3 x 8-byte DES keys
        let preIV = Array(privKey[24..<32])

        // Generate salt: engineBoots (4 bytes) || local counter (4 bytes)
        let localSalt = nextSalt()
        var salt = [UInt8](repeating: 0, count: 8)
        salt[0] = UInt8((engineBoots >> 24) & 0xFF)
        salt[1] = UInt8((engineBoots >> 16) & 0xFF)
        salt[2] = UInt8((engineBoots >> 8) & 0xFF)
        salt[3] = UInt8(engineBoots & 0xFF)
        salt[4] = UInt8((localSalt >> 24) & 0xFF)
        salt[5] = UInt8((localSalt >> 16) & 0xFF)
        salt[6] = UInt8((localSalt >> 8) & 0xFF)
        salt[7] = UInt8(localSalt & 0xFF)

        // IV = preIV XOR salt
        var iv = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            iv[i] = preIV[i] ^ salt[i]
        }

        // Pad plaintext to multiple of 8 bytes (zero-padding per SNMP convention)
        var padded = scopedPDU
        let remainder = padded.count % 8
        if remainder != 0 {
            padded.append(contentsOf: [UInt8](repeating: 0, count: 8 - remainder))
        }

        // Perform 3DES-CBC encryption using CommonCrypto
        var encrypted = [UInt8](repeating: 0, count: padded.count)
        var bytesEncrypted: size_t = 0
        let status = desEDEKey.withUnsafeBufferPointer { keyPtr in
            iv.withUnsafeBufferPointer { ivPtr in
                padded.withUnsafeBufferPointer { dataPtr in
                    encrypted.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithm3DES),
                            CCOptions(0),  // No padding (we handle it)
                            keyPtr.baseAddress!, keyPtr.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, dataPtr.count,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return (Array(encrypted.prefix(bytesEncrypted)), salt)
    }

    /// Decrypt using 3DES-CBC.
    private func decrypt3DES(encryptedPDU: [UInt8], privKey: [UInt8], privParameters: [UInt8]) -> [UInt8]? {
        guard privKey.count >= 32, privParameters.count == 8 else { return nil }
        guard encryptedPDU.count % 8 == 0 else { return nil }

        let desEDEKey = Array(privKey.prefix(24))
        let preIV = Array(privKey[24..<32])

        // IV = preIV XOR privParameters (salt)
        var iv = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            iv[i] = preIV[i] ^ privParameters[i]
        }

        var decrypted = [UInt8](repeating: 0, count: encryptedPDU.count)
        var bytesDecrypted: size_t = 0
        let status = desEDEKey.withUnsafeBufferPointer { keyPtr in
            iv.withUnsafeBufferPointer { ivPtr in
                encryptedPDU.withUnsafeBufferPointer { dataPtr in
                    decrypted.withUnsafeMutableBufferPointer { outPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithm3DES),
                            CCOptions(0),
                            keyPtr.baseAddress!, keyPtr.count,
                            ivPtr.baseAddress!,
                            dataPtr.baseAddress!, dataPtr.count,
                            outPtr.baseAddress!, outPtr.count,
                            &bytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return Array(decrypted.prefix(bytesDecrypted))
    }
}

// MARK: - SNMP Response Builder

/// Utility for encoding SNMP response messages
public struct SNMPResponseBuilder {

    /// Encode a UInt32 as a variable-length big-endian integer (no tag byte, just length+value)
    public static func encodeUInt32(_ value: UInt32, into buffer: inout [UInt8], at offset: inout Int) {
        if value == 0 {
            buffer[offset] = 1
            offset += 1
            buffer[offset] = 0
            offset += 1
            return
        }
        var bytes = [UInt8]()
        var v = value
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        // Add leading zero if high bit set (to keep it positive)
        if (bytes[0] & 0x80) != 0 {
            bytes.insert(0, at: 0)
        }
        buffer[offset] = UInt8(bytes.count)
        offset += 1
        for b in bytes {
            buffer[offset] = b
            offset += 1
        }
    }

    /// Encode a typed value (tag + length + raw value bytes) into buffer
    public static func encodeTypedValue(tag: UInt8, value: [UInt8], into buffer: inout [UInt8], at offset: inout Int) {
        buffer[offset] = tag
        offset += 1
        SNMPASN1Encoder.encodeLength(value.count, into: &buffer, at: &offset)
        for b in value {
            buffer[offset] = b
            offset += 1
        }
    }

    /// Encode a single varbind (SEQUENCE { OID, value })
    public static func encodeVarbind(_ vb: SNMPVarbind, into buffer: inout [UInt8], at offset: inout Int) {
        // Encode OID and value into temp buffer to get total length
        var content = [UInt8](repeating: 0, count: 1024)
        var contentOffset = 0

        SNMPASN1Encoder.encodeOID(vb.oid, into: &content, at: &contentOffset)
        encodeTypedValue(tag: vb.type, value: vb.value, into: &content, at: &contentOffset)

        // SEQUENCE wrapper
        buffer[offset] = SNMPASN1.typeSequence
        offset += 1
        SNMPASN1Encoder.encodeLength(contentOffset, into: &buffer, at: &offset)
        for i in 0..<contentOffset {
            buffer[offset] = content[i]
            offset += 1
        }
    }

    /// Encode varbind list (SEQUENCE OF varbinds)
    public static func encodeVarbindList(_ varbinds: [SNMPVarbind], into buffer: inout [UInt8], at offset: inout Int) {
        var varbindContent = [UInt8](repeating: 0, count: 4096)
        var varbindContentOffset = 0

        for vb in varbinds {
            encodeVarbind(vb, into: &varbindContent, at: &varbindContentOffset)
        }

        buffer[offset] = SNMPASN1.typeSequence
        offset += 1
        SNMPASN1Encoder.encodeLength(varbindContentOffset, into: &buffer, at: &offset)
        for i in 0..<varbindContentOffset {
            buffer[offset] = varbindContent[i]
            offset += 1
        }
    }

    /// Build a complete PDU (GetResponse, Trap, etc.)
    public static func buildPDU(
        pduType: UInt8,
        requestID: Int32,
        errorStatus: Int32,
        errorIndex: Int32,
        varbinds: [SNMPVarbind]
    ) -> [UInt8] {
        var pduContent = [UInt8](repeating: 0, count: 8192)
        var pduContentOffset = 0

        // request-id
        SNMPASN1Encoder.encodeInteger(requestID, into: &pduContent, at: &pduContentOffset)

        // error-status
        SNMPASN1Encoder.encodeInteger(errorStatus, into: &pduContent, at: &pduContentOffset)

        // error-index
        SNMPASN1Encoder.encodeInteger(errorIndex, into: &pduContent, at: &pduContentOffset)

        // varbind list
        encodeVarbindList(varbinds, into: &pduContent, at: &pduContentOffset)

        // Wrap in PDU tag
        var pdu = [UInt8](repeating: 0, count: pduContentOffset + 10)
        var pduOffset = 0
        pdu[pduOffset] = pduType
        pduOffset += 1
        SNMPASN1Encoder.encodeLength(pduContentOffset, into: &pdu, at: &pduOffset)
        for i in 0..<pduContentOffset {
            pdu[pduOffset] = pduContent[i]
            pduOffset += 1
        }

        return Array(pdu[0..<pduOffset])
    }

    /// Wrap a PDU in a full SNMP message (SEQUENCE { version, community, PDU })
    public static func wrapMessage(
        version: Int32,
        community: String,
        pduBytes: [UInt8]
    ) -> [UInt8] {
        var msgContent = [UInt8](repeating: 0, count: pduBytes.count + 256)
        var msgContentOffset = 0

        // Version
        SNMPASN1Encoder.encodeInteger(version, into: &msgContent, at: &msgContentOffset)

        // Community string
        let communityBytes = Array(community.utf8)
        SNMPASN1Encoder.encodeOctetString(communityBytes, into: &msgContent, at: &msgContentOffset)

        // PDU
        for b in pduBytes {
            msgContent[msgContentOffset] = b
            msgContentOffset += 1
        }

        // Outer SEQUENCE
        var message = [UInt8](repeating: 0, count: msgContentOffset + 10)
        var messageOffset = 0
        message[messageOffset] = SNMPASN1.typeSequence
        messageOffset += 1
        SNMPASN1Encoder.encodeLength(msgContentOffset, into: &message, at: &messageOffset)
        for i in 0..<msgContentOffset {
            message[messageOffset] = msgContent[i]
            messageOffset += 1
        }

        return Array(message[0..<messageOffset])
    }

    // MARK: - SNMPv3 Message Building

    /// Build a scoped PDU: SEQUENCE { contextEngineID (OCTET STRING), contextName (OCTET STRING), PDU bytes }
    public static func buildScopedPDU(contextEngineID: [UInt8], contextName: String, pduBytes: [UInt8]) -> [UInt8] {
        let contextNameBytes = Array(contextName.utf8)

        var content = [UInt8](repeating: 0, count: pduBytes.count + contextEngineID.count + contextNameBytes.count + 64)
        var contentOffset = 0

        // contextEngineID
        SNMPASN1Encoder.encodeOctetString(contextEngineID, into: &content, at: &contentOffset)

        // contextName
        SNMPASN1Encoder.encodeOctetString(contextNameBytes, into: &content, at: &contentOffset)

        // PDU (raw, already has its own tag)
        for b in pduBytes {
            content[contentOffset] = b
            contentOffset += 1
        }

        // Wrap in SEQUENCE
        var scopedPDU = [UInt8](repeating: 0, count: contentOffset + 10)
        var scopedOffset = 0
        scopedPDU[scopedOffset] = SNMPASN1.typeSequence
        scopedOffset += 1
        SNMPASN1Encoder.encodeLength(contentOffset, into: &scopedPDU, at: &scopedOffset)
        for i in 0..<contentOffset {
            scopedPDU[scopedOffset] = content[i]
            scopedOffset += 1
        }

        return Array(scopedPDU[0..<scopedOffset])
    }

    /// Build a complete SNMPv3 message:
    /// SEQUENCE { version, msgGlobalData, msgSecurityParameters, scopedPDU/encryptedPDU }
    public static func buildV3Message(
        msgID: Int32,
        msgMaxSize: Int32,
        msgFlags: UInt8,
        msgSecurityModel: Int32,
        engineID: [UInt8],
        engineBoots: UInt32,
        engineTime: UInt32,
        userName: String,
        authParameters: [UInt8],
        privParameters: [UInt8],
        scopedPDUOrEncrypted: [UInt8]
    ) -> [UInt8] {
        var msgContent = [UInt8](repeating: 0, count: scopedPDUOrEncrypted.count + 512)
        var msgContentOffset = 0

        // Version (INTEGER = 3)
        SNMPASN1Encoder.encodeInteger(SNMPVersion.v3, into: &msgContent, at: &msgContentOffset)

        // msgGlobalData (SEQUENCE { msgID, msgMaxSize, msgFlags, msgSecurityModel })
        var headerContent = [UInt8](repeating: 0, count: 64)
        var headerOffset = 0

        SNMPASN1Encoder.encodeInteger(msgID, into: &headerContent, at: &headerOffset)
        SNMPASN1Encoder.encodeInteger(msgMaxSize, into: &headerContent, at: &headerOffset)

        // msgFlags (OCTET STRING, 1 byte)
        headerContent[headerOffset] = SNMPASN1.typeOctetString
        headerOffset += 1
        headerContent[headerOffset] = 1
        headerOffset += 1
        headerContent[headerOffset] = msgFlags
        headerOffset += 1

        SNMPASN1Encoder.encodeInteger(msgSecurityModel, into: &headerContent, at: &headerOffset)

        // Wrap in SEQUENCE
        msgContent[msgContentOffset] = SNMPASN1.typeSequence
        msgContentOffset += 1
        SNMPASN1Encoder.encodeLength(headerOffset, into: &msgContent, at: &msgContentOffset)
        for i in 0..<headerOffset {
            msgContent[msgContentOffset] = headerContent[i]
            msgContentOffset += 1
        }

        // msgSecurityParameters (OCTET STRING wrapping USM SEQUENCE)
        let usmBytes = buildUSMSecurityParameters(
            engineID: engineID,
            engineBoots: engineBoots,
            engineTime: engineTime,
            userName: userName,
            authParameters: authParameters,
            privParameters: privParameters
        )
        SNMPASN1Encoder.encodeOctetString(usmBytes, into: &msgContent, at: &msgContentOffset)

        // scopedPDU or encrypted scopedPDU (already encoded with appropriate wrapping)
        for b in scopedPDUOrEncrypted {
            msgContent[msgContentOffset] = b
            msgContentOffset += 1
        }

        // Outer SEQUENCE
        var message = [UInt8](repeating: 0, count: msgContentOffset + 10)
        var messageOffset = 0
        message[messageOffset] = SNMPASN1.typeSequence
        messageOffset += 1
        SNMPASN1Encoder.encodeLength(msgContentOffset, into: &message, at: &messageOffset)
        for i in 0..<msgContentOffset {
            message[messageOffset] = msgContent[i]
            messageOffset += 1
        }

        return Array(message[0..<messageOffset])
    }

    /// Build USM security parameters as a SEQUENCE
    private static func buildUSMSecurityParameters(
        engineID: [UInt8],
        engineBoots: UInt32,
        engineTime: UInt32,
        userName: String,
        authParameters: [UInt8],
        privParameters: [UInt8]
    ) -> [UInt8] {
        let userNameBytes = Array(userName.utf8)

        var content = [UInt8](repeating: 0, count: engineID.count + userNameBytes.count + authParameters.count + privParameters.count + 128)
        var contentOffset = 0

        // msgAuthoritativeEngineID (OCTET STRING)
        SNMPASN1Encoder.encodeOctetString(engineID, into: &content, at: &contentOffset)

        // msgAuthoritativeEngineBoots (INTEGER)
        SNMPASN1Encoder.encodeInteger(Int32(bitPattern: engineBoots), into: &content, at: &contentOffset)

        // msgAuthoritativeEngineTime (INTEGER)
        SNMPASN1Encoder.encodeInteger(Int32(bitPattern: engineTime), into: &content, at: &contentOffset)

        // msgUserName (OCTET STRING)
        SNMPASN1Encoder.encodeOctetString(userNameBytes, into: &content, at: &contentOffset)

        // msgAuthenticationParameters (OCTET STRING)
        SNMPASN1Encoder.encodeOctetString(authParameters, into: &content, at: &contentOffset)

        // msgPrivacyParameters (OCTET STRING)
        SNMPASN1Encoder.encodeOctetString(privParameters, into: &content, at: &contentOffset)

        // Wrap in SEQUENCE
        var result = [UInt8](repeating: 0, count: contentOffset + 10)
        var resultOffset = 0
        result[resultOffset] = SNMPASN1.typeSequence
        resultOffset += 1
        SNMPASN1Encoder.encodeLength(contentOffset, into: &result, at: &resultOffset)
        for i in 0..<contentOffset {
            result[resultOffset] = content[i]
            resultOffset += 1
        }

        return Array(result[0..<resultOffset])
    }

    /// Find the offset of the 12-byte authParameters value within a built v3 message.
    /// Scans for the USM auth parameters placeholder (12 zero bytes after the userName OCTET STRING).
    public static func findAuthParametersOffset(in message: [UInt8]) -> Int? {
        // Strategy: Parse the message to find the exact location of the authParameters value.
        // The structure is: SEQUENCE { version, headerSEQ, secParamsOCTET(USM_SEQ(..., authParamsOCTET, ...)), ... }
        var pos = 0

        // Outer SEQUENCE
        guard pos < message.count, message[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (_, outerLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += outerLenBytes

        // Version (INTEGER)
        guard let (_, versionConsumed) = SNMPASN1Decoder.decodeInteger(from: message, at: pos) else { return nil }
        pos += versionConsumed

        // msgGlobalData (SEQUENCE) - skip over it
        guard pos < message.count, message[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (headerLen, headerLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += headerLenBytes + headerLen

        // msgSecurityParameters (OCTET STRING)
        guard pos < message.count, message[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (_, secParamsLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += secParamsLenBytes

        // Inside: USM SEQUENCE
        guard pos < message.count, message[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (_, usmLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += usmLenBytes

        // engineID (OCTET STRING)
        guard pos < message.count, message[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (eidLen, eidLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += eidLenBytes + eidLen

        // engineBoots (INTEGER)
        guard let (_, bootsConsumed) = SNMPASN1Decoder.decodeInteger(from: message, at: pos) else { return nil }
        pos += bootsConsumed

        // engineTime (INTEGER)
        guard let (_, timeConsumed) = SNMPASN1Decoder.decodeInteger(from: message, at: pos) else { return nil }
        pos += timeConsumed

        // userName (OCTET STRING)
        guard pos < message.count, message[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (unLen, unLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += unLenBytes + unLen

        // authParameters (OCTET STRING) - this is what we are looking for
        guard pos < message.count, message[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (authLen, authLenBytes) = SNMPASN1Decoder.decodeLength(from: message, at: pos) else { return nil }
        pos += authLenBytes

        // pos now points to the start of the authParameters value
        guard authLen == 12 else { return nil }
        return pos
    }
}

// MARK: - SNMP Message Parser

/// Utility for decoding incoming SNMP messages
private struct SNMPMessageParser {

    /// Decode a complete SNMP message from raw bytes, returning a parsed request
    static func parse(_ data: [UInt8]) -> SNMPRequest? {
        var pos = 0

        // Outer SEQUENCE
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (outerLen, outerLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += outerLenBytes
        let outerEnd = pos + outerLen
        guard outerEnd <= data.count else { return nil }

        // Version (INTEGER)
        guard let (version, versionConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += versionConsumed

        // Dispatch based on version
        if version == SNMPVersion.v3 {
            return parseV3(data: data, pos: &pos, outerEnd: outerEnd)
        }

        // v1/v2c parsing
        return parseV1V2c(data: data, version: version, pos: &pos, outerEnd: outerEnd)
    }

    // MARK: - v1/v2c Parsing

    private static func parseV1V2c(data: [UInt8], version: Int32, pos: inout Int, outerEnd: Int) -> SNMPRequest? {
        // Community (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (communityLen, communityLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += communityLenBytes
        guard pos + communityLen <= data.count else { return nil }
        let communityBytes = Array(data[pos..<(pos + communityLen)])
        let community = String(bytes: communityBytes, encoding: .utf8) ?? ""
        pos += communityLen

        // PDU (context-specific constructed)
        guard pos < data.count else { return nil }
        let pduType = data[pos]
        pos += 1

        guard let (pduLen, pduLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += pduLenBytes
        let pduEnd = pos + pduLen
        guard pduEnd <= data.count else { return nil }

        var request = SNMPRequest()
        request.version = version
        request.community = community
        request.requestType = pduType

        guard parsePDUContents(data: data, pos: &pos, pduEnd: pduEnd, request: &request) else { return nil }
        return request
    }

    // MARK: - SNMPv3 Parsing

    private static func parseV3(data: [UInt8], pos: inout Int, outerEnd: Int) -> SNMPRequest? {
        var request = SNMPRequest()
        request.version = SNMPVersion.v3
        request.rawMessage = data

        // msgGlobalData (SEQUENCE): msgID, msgMaxSize, msgFlags, msgSecurityModel
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (headerLen, headerLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += headerLenBytes
        let headerEnd = pos + headerLen

        // msgID (INTEGER)
        guard let (msgID, msgIDConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += msgIDConsumed
        request.msgID = msgID

        // msgMaxSize (INTEGER)
        guard let (msgMaxSize, msgMaxSizeConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += msgMaxSizeConsumed
        request.msgMaxSize = msgMaxSize

        // msgFlags (OCTET STRING, 1 byte)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (flagsLen, flagsLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += flagsLenBytes
        guard flagsLen >= 1, pos < data.count else { return nil }
        request.msgFlags = data[pos]
        pos += flagsLen

        // msgSecurityModel (INTEGER)
        guard let (secModel, secModelConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += secModelConsumed
        request.msgSecurityModel = secModel

        pos = max(pos, headerEnd)

        // msgSecurityParameters (OCTET STRING wrapping a SEQUENCE)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (secParamsLen, secParamsLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += secParamsLenBytes
        let secParamsStart = pos
        guard pos + secParamsLen <= data.count else { return nil }

        // Parse USM security parameters (SEQUENCE inside the OCTET STRING)
        guard parseUSMParameters(data: data, pos: &pos, secParamsStart: secParamsStart, secParamsEnd: secParamsStart + secParamsLen, request: &request) else { return nil }

        pos = secParamsStart + secParamsLen

        // The rest is the scoped PDU or encrypted scoped PDU
        // Store the remaining data position for the caller to handle decryption/parsing
        let privFlag = (request.msgFlags & 0x02) != 0

        if privFlag {
            // Encrypted scoped PDU (OCTET STRING)
            guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
            pos += 1
            guard let (encPDULen, encPDULenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
            pos += encPDULenBytes
            guard pos + encPDULen <= data.count else { return nil }
            // Store encrypted PDU bytes temporarily in rawMessage (will be decrypted by agent)
            // We mark this as needing decryption by leaving varbinds empty and requestType at 0
            request.requestType = 0  // Placeholder; will be filled after decryption
            // Store encrypted data in a way the agent can retrieve it
            let encryptedPDU = Array(data[pos..<(pos + encPDULen)])
            request.varbinds = [SNMPVarbind(oid: SNMPObjectID(), type: 0xFF, value: encryptedPDU)]
            return request
        }

        // Plaintext scoped PDU: SEQUENCE { contextEngineID, contextName, PDU }
        guard parseScopedPDU(data: data, pos: &pos, request: &request) else { return nil }
        return request
    }

    /// Parse USM Security Parameters from within the OCTET STRING
    private static func parseUSMParameters(data: [UInt8], pos: inout Int, secParamsStart: Int, secParamsEnd: Int, request: inout SNMPRequest) -> Bool {
        // SEQUENCE wrapper
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return false }
        pos += 1
        guard let (_, seqLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += seqLenBytes

        // msgAuthoritativeEngineID (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (engineIDLen, engineIDLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += engineIDLenBytes
        guard pos + engineIDLen <= data.count else { return false }
        request.authoritativeEngineID = Array(data[pos..<(pos + engineIDLen)])
        pos += engineIDLen

        // msgAuthoritativeEngineBoots (INTEGER)
        guard let (boots, bootsConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
        pos += bootsConsumed
        request.authoritativeEngineBoots = UInt32(bitPattern: boots)

        // msgAuthoritativeEngineTime (INTEGER)
        guard let (time, timeConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
        pos += timeConsumed
        request.authoritativeEngineTime = UInt32(bitPattern: time)

        // msgUserName (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (userNameLen, userNameLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += userNameLenBytes
        guard pos + userNameLen <= data.count else { return false }
        request.userName = String(bytes: Array(data[pos..<(pos + userNameLen)]), encoding: .utf8) ?? ""
        pos += userNameLen

        // msgAuthenticationParameters (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (authParamsLen, authParamsLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += authParamsLenBytes
        // Record the offset of the authParameters value within the raw message
        request.authParametersOffset = pos
        guard pos + authParamsLen <= data.count else { return false }
        request.authParameters = Array(data[pos..<(pos + authParamsLen)])
        pos += authParamsLen

        // msgPrivacyParameters (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (privParamsLen, privParamsLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += privParamsLenBytes
        guard pos + privParamsLen <= data.count else { return false }
        request.privParameters = Array(data[pos..<(pos + privParamsLen)])
        pos += privParamsLen

        return true
    }

    /// Parse a plaintext scoped PDU: SEQUENCE { contextEngineID, contextName, PDU }
    static func parseScopedPDU(data: [UInt8], pos: inout Int, request: inout SNMPRequest) -> Bool {
        // SEQUENCE
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return false }
        pos += 1
        guard let (scopedLen, scopedLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += scopedLenBytes
        let scopedEnd = pos + scopedLen
        guard scopedEnd <= data.count else { return false }

        // contextEngineID (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (ctxEngIDLen, ctxEngIDLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += ctxEngIDLenBytes
        guard pos + ctxEngIDLen <= data.count else { return false }
        request.contextEngineID = Array(data[pos..<(pos + ctxEngIDLen)])
        pos += ctxEngIDLen

        // contextName (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return false }
        pos += 1
        guard let (ctxNameLen, ctxNameLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += ctxNameLenBytes
        guard pos + ctxNameLen <= data.count else { return false }
        request.contextName = String(bytes: Array(data[pos..<(pos + ctxNameLen)]), encoding: .utf8) ?? ""
        pos += ctxNameLen

        // PDU (context-specific constructed)
        guard pos < data.count else { return false }
        let pduType = data[pos]
        pos += 1
        request.requestType = pduType

        guard let (pduLen, pduLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += pduLenBytes
        let pduEnd = pos + pduLen
        guard pduEnd <= data.count else { return false }

        guard parsePDUContents(data: data, pos: &pos, pduEnd: pduEnd, request: &request) else { return false }
        return true
    }

    // MARK: - Common PDU Contents Parsing

    /// Parse the interior of a PDU: request-id, error-status/non-repeaters, error-index/max-reps, varbinds
    private static func parsePDUContents(data: [UInt8], pos: inout Int, pduEnd: Int, request: inout SNMPRequest) -> Bool {
        // request-id (INTEGER)
        guard let (requestID, reqIDConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
        pos += reqIDConsumed
        request.requestID = requestID

        if request.requestType == SNMPPDUType.getBulkRequest {
            // For GETBULK: non-repeaters, max-repetitions
            guard let (nonRepeaters, nrConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
            pos += nrConsumed
            request.nonRepeaters = nonRepeaters

            guard let (maxReps, mrConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
            pos += mrConsumed
            request.maxRepetitions = maxReps
        } else {
            // error-status (INTEGER)
            guard let (errStatus, errStatusConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
            pos += errStatusConsumed
            request.errorStatus = errStatus

            // error-index (INTEGER)
            guard let (errIndex, errIndexConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return false }
            pos += errIndexConsumed
            request.errorIndex = errIndex
        }

        // Varbind list (SEQUENCE OF)
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return false }
        pos += 1
        guard let (vbListLen, vbListLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
        pos += vbListLenBytes
        let vbListEnd = pos + vbListLen

        // Parse individual varbinds
        while pos < vbListEnd {
            guard data[pos] == SNMPASN1.typeSequence else { return false }
            pos += 1
            guard let (vbLen, vbLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
            pos += vbLenBytes
            let vbEnd = pos + vbLen

            // OID
            guard let (oid, oidConsumed) = SNMPASN1Decoder.decodeOID(from: data, at: pos) else { return false }
            pos += oidConsumed

            // Value (any type)
            guard pos < vbEnd, pos < data.count else { return false }
            let valueType = data[pos]
            pos += 1
            guard let (valueLen, valueLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return false }
            pos += valueLenBytes
            guard pos + valueLen <= data.count else { return false }
            let valueBytes = Array(data[pos..<(pos + valueLen)])
            pos += valueLen

            request.varbinds.append(SNMPVarbind(oid: oid, type: valueType, value: valueBytes))

            // Ensure we are at or past the varbind end
            pos = max(pos, vbEnd)
        }

        return true
    }
}

// MARK: - SNMP Agent

/// Main SNMP Agent.
///
/// Handles SNMP message processing, MIB tree walking,
/// and trap sending for SNMPv1, SNMPv2c, and SNMPv3.
public final class SNMPAgent: @unchecked Sendable {
    /// Registered MIBs
    public var mibs: [SNMPMIB] = []
    /// Read community string
    public var readCommunity: String = "public"
    /// Write community string
    public var writeCommunity: String = "private"
    /// Trap sender
    public let trapSender = SNMPTrapSender()
    /// SNMPv3 engine
    public let v3Engine = SNMPv3Engine()
    /// UDP PCB for receiving/sending SNMP messages
    public var udpControlBlock: UDPControlBlock?
    /// Netconn-based sequential transport for receiving/sending SNMP messages
    public var netConn: NetConn?
    /// Statistics
    public let stats = SNMPStatistics.shared

    /// Enable/disable write access
    public var writeAccessEnabled: Bool = false

    /// Write callback (called after each successful SET)
    public var writeCallback: ((_ oid: SNMPObjectID, _ value: [UInt8]) -> Void)?

    private let receiveQueue = DispatchQueue(label: "com.lwip.snmp.netconn")
    private var isRunning = false

    public init() {}

    /// Set the MIBs this agent will serve
    public func setMIBs(_ mibs: [SNMPMIB]) {
        self.mibs = mibs
    }

    /// Initialize the SNMP agent.
    /// Binds to UDP port 161 and starts listening.
    public func start(transport: SNMPTransportMode = .rawUDP) -> LWIPError {
        stop()

        switch transport {
        case .rawUDP:
            return startRawUDP()
        case .netConn:
            return startNetConn()
        }
    }

    public func startNetConn() -> LWIPError {
        guard let conn = NetConn(type: .udp) else { return .outOfMemory }
        let err = conn.bind(addr: .any, port: 161)
        guard err == .ok else {
            _ = conn.delete()
            return err
        }

        conn.receiveTimeout = 100
        netConn = conn
        trapSender.sendHandler = { [weak self] data, addr, port in
            self?.sendPacket(data, to: addr, port: port) ?? .notConnected
        }
        isRunning = true

        receiveQueue.async { [weak self, weak conn] in
            guard let self, let conn else { return }

            while self.isRunning, self.netConn === conn {
                switch conn.receive() {
                case .success(let netBuf):
                    guard let pbuf = netBuf.p else { continue }
                    self.handleMessage(pbuf: pbuf, srcAddr: netBuf.addr, srcPort: netBuf.port)
                    _ = pbuf.free()
                    netBuf.free()

                case .failure(let err):
                    if err == .timeout || err == .wouldBlock {
                        continue
                    }
                    return
                }
            }
        }

        return .ok
    }

    private func startRawUDP() -> LWIPError {
        let pcb = UDPGlobal.shared.new()
        let err = UDPGlobal.shared.bind(pcb, address: .any, port: 161)
        guard err == .ok else { return err }

        pcb.receiveHandler = { [weak self] _, pbuf, addr, port in
            self?.handleMessage(pbuf: pbuf, srcAddr: addr, srcPort: port)
        }

        self.udpControlBlock = pcb
        trapSender.udpControlBlock = pcb
        trapSender.sendHandler = { [weak self] data, addr, port in
            self?.sendPacket(data, to: addr, port: port) ?? .notConnected
        }
        isRunning = true
        return .ok
    }

    /// Stop the SNMP agent
    public func stop() {
        isRunning = false
        if let pcb = udpControlBlock {
            UDPGlobal.shared.remove(pcb)
        }
        if let conn = netConn {
            _ = conn.delete()
        }
        udpControlBlock = nil
        netConn = nil
        trapSender.udpControlBlock = nil
        trapSender.sendHandler = nil
    }

    // MARK: - Message Handling

    /// Handle an incoming SNMP message
    private func handleMessage(pbuf: Pbuf, srcAddr: IPAddress, srcPort: UInt16) {
        stats.inPkts += 1

        // Extract raw bytes from pbuf
        let totalLen = Int(pbuf.totLen)
        guard totalLen > 2 else {
            stats.inASNParseErrs += 1
            return
        }

        var rawData = [UInt8](repeating: 0, count: totalLen)
        for i in 0..<totalLen {
            rawData[i] = pbuf.byte(at: UInt16(i))
        }

        // Parse the SNMP message
        guard var request = SNMPMessageParser.parse(rawData) else {
            stats.inASNParseErrs += 1
            return
        }

        request.sourceAddress = srcAddr
        request.sourcePort = srcPort

        // Validate version
        guard request.version == SNMPVersion.v1 || request.version == SNMPVersion.v2c || request.version == SNMPVersion.v3 else {
            stats.inBadVersions += 1
            return
        }

        // SNMPv3 message handling
        if request.version == SNMPVersion.v3 {
            handleV3Message(&request)
            return
        }

        // Validate community and determine access level (v1/v2c)
        let isWriteRequest = request.requestType == SNMPPDUType.setRequest
        if isWriteRequest {
            guard request.community == writeCommunity else {
                stats.inBadCommunityNames += 1
                if request.community == readCommunity {
                    stats.inBadCommunityUses += 1
                }
                sendAuthenticationFailureTrap()
                return
            }
            guard writeAccessEnabled else {
                stats.inBadCommunityUses += 1
                sendAuthenticationFailureTrap()
                return
            }
        } else {
            guard request.community == readCommunity || request.community == writeCommunity else {
                stats.inBadCommunityNames += 1
                sendAuthenticationFailureTrap()
                return
            }
        }

        // Dispatch based on PDU type
        dispatchPDU(&request)
    }

    // MARK: - Authentication Failure Trap

    /// Send an authenticationFailure trap/notification when a request fails
    /// community or SNMPv3 authentication validation.
    /// Controlled by MIB2SNMPGroup.shared.enableAuthenTraps (snmpEnableAuthenTraps).
    private func sendAuthenticationFailureTrap() {
        guard MIB2SNMPGroup.shared.enableAuthenTraps == 1 else { return }
        guard !trapSender.trapDestinations.isEmpty else { return }

        // authenticationFailure OID: 1.3.6.1.6.3.1.1.5.5 (SNMPv2-MIB::authenticationFailure)
        let authFailOID = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 5])
        trapSender.sendV2Notification(notificationOID: authFailOID)
    }

    /// Dispatch a parsed request to the appropriate PDU processor
    private func dispatchPDU(_ request: inout SNMPRequest) {
        switch request.requestType {
        case SNMPPDUType.getRequest:
            stats.inGetRequests += 1
            processGetRequest(&request)
        case SNMPPDUType.getNextRequest:
            stats.inGetNexts += 1
            processGetNextRequest(&request)
        case SNMPPDUType.getBulkRequest:
            guard request.version == SNMPVersion.v2c || request.version == SNMPVersion.v3 else {
                stats.inBadVersions += 1
                return
            }
            stats.inGetNexts += 1
            processGetBulkRequest(&request)
        case SNMPPDUType.setRequest:
            stats.inSetRequests += 1
            processSetRequest(&request)
        case SNMPPDUType.informRequest:
            guard request.version == SNMPVersion.v2c || request.version == SNMPVersion.v3 else {
                stats.inBadVersions += 1
                return
            }
            stats.inTraps += 1
            processInformRequest(&request)
        case SNMPPDUType.getResponse:
            stats.inGetResponses += 1
            return  // We are an agent, not a manager; ignore responses
        default:
            stats.inASNParseErrs += 1
            return
        }
    }

    // MARK: - InformRequest Processing

    /// Handle an incoming InformRequest by acknowledging it with a GetResponse
    /// that echoes the request-id and varbinds (RFC 3416 Section 4.2.7).
    private func processInformRequest(_ request: inout SNMPRequest) {
        sendResponse(
            request: request,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: request.varbinds
        )
    }

    // MARK: - SNMPv3 Message Handling

    /// Handle an SNMPv3 message: validate security, decrypt if needed, process PDU, send v3 response
    private func handleV3Message(_ request: inout SNMPRequest) {
        let authFlag = (request.msgFlags & 0x01) != 0
        let privFlag = (request.msgFlags & 0x02) != 0

        // Privacy requires authentication (RFC 3414)
        if privFlag && !authFlag {
            stats.unsupportedSecLevels += 1
            sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0]),
                         reportValue: stats.unsupportedSecLevels)
            return
        }

        // Engine ID discovery: if the engine ID is empty, this is a discovery request
        if request.authoritativeEngineID.isEmpty {
            sendV3DiscoveryResponse(request: request)
            return
        }

        // Validate engine ID matches ours
        guard request.authoritativeEngineID == v3Engine.engineID else {
            stats.unknownEngineIDs += 1
            sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]),
                         reportValue: stats.unknownEngineIDs)
            return
        }

        // Look up the user
        guard let user = v3Engine.findUser(name: request.userName) else {
            stats.unknownUserNames += 1
            sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0]),
                         reportValue: stats.unknownUserNames)
            return
        }

        // Verify the user supports the requested security level
        if authFlag && user.authProtocol == .none {
            stats.unsupportedSecLevels += 1
            sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0]),
                         reportValue: stats.unsupportedSecLevels)
            return
        }
        if privFlag && user.privProtocol == .none {
            stats.unsupportedSecLevels += 1
            sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0]),
                         reportValue: stats.unsupportedSecLevels)
            return
        }

        // Verify authentication if auth flag is set
        if authFlag {
            guard request.authParameters.count == 12 else {
                stats.wrongDigests += 1
                sendAuthenticationFailureTrap()
                sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0]),
                             reportValue: stats.wrongDigests)
                return
            }

            // Zero out the authParameters in the raw message for verification
            var msgForAuth = request.rawMessage
            let authOffset = request.authParametersOffset
            for i in 0..<12 {
                msgForAuth[authOffset + i] = 0
            }

            guard v3Engine.verifyAuthentication(wholeMessage: msgForAuth, user: user, receivedDigest: request.authParameters) else {
                stats.wrongDigests += 1
                sendAuthenticationFailureTrap()
                sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0]),
                             reportValue: stats.wrongDigests)
                return
            }

            // Check timeliness (RFC 3414 Section 3.2, step 7)
            let timeDiff: Int32
            if v3Engine.engineTime >= request.authoritativeEngineTime {
                timeDiff = Int32(v3Engine.engineTime - request.authoritativeEngineTime)
            } else {
                timeDiff = -Int32(request.authoritativeEngineTime - v3Engine.engineTime)
            }
            let bootsMatch = request.authoritativeEngineBoots == v3Engine.engineBoots
            if !bootsMatch || abs(timeDiff) > 150 {
                stats.notInTimeWindows += 1
                sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0]),
                             reportValue: stats.notInTimeWindows)
                return
            }
        }

        // Decrypt if privacy flag is set
        if privFlag {
            // The encrypted PDU was stored as a single varbind with type 0xFF during parsing
            guard request.varbinds.count == 1, request.varbinds[0].type == 0xFF else {
                stats.decryptionErrors += 1
                return
            }
            let encryptedPDU = request.varbinds[0].value
            request.varbinds = []

            guard let decryptedData = v3Engine.decrypt(
                encryptedPDU: encryptedPDU,
                user: user,
                privParameters: request.privParameters,
                engineBoots: request.authoritativeEngineBoots,
                engineTime: request.authoritativeEngineTime
            ) else {
                stats.decryptionErrors += 1
                sendV3Report(request: request, reportOID: SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0]),
                             reportValue: stats.decryptionErrors)
                return
            }

            // Parse the decrypted scoped PDU
            var scopedPos = 0
            guard SNMPMessageParser.parseScopedPDU(data: decryptedData, pos: &scopedPos, request: &request) else {
                stats.inASNParseErrs += 1
                return
            }
        }

        // Process the PDU using the standard handlers, then wrap in v3 response
        processV3PDU(&request, user: user)
    }

    /// Process a v3 PDU using standard GET/SET/GETNEXT/GETBULK logic, then send a v3 response
    private func processV3PDU(_ request: inout SNMPRequest, user: SNMPv3User) {
        // Check write access for SET requests
        if request.requestType == SNMPPDUType.setRequest && !writeAccessEnabled {
            stats.inBadCommunityUses += 1
            sendV3Response(request: request, user: user, errorStatus: Int32(SNMPError.noAccess.rawValue), errorIndex: 0, varbinds: request.varbinds)
            return
        }

        // For v3, use v2c-style exception varbinds (noSuchObject, endOfMibView, etc.)
        // Process by simulating v2c behavior for the inner PDU
        switch request.requestType {
        case SNMPPDUType.getRequest:
            stats.inGetRequests += 1
            processV3GetRequest(&request, user: user)
        case SNMPPDUType.getNextRequest:
            stats.inGetNexts += 1
            processV3GetNextRequest(&request, user: user)
        case SNMPPDUType.getBulkRequest:
            stats.inGetNexts += 1
            processV3GetBulkRequest(&request, user: user)
        case SNMPPDUType.setRequest:
            stats.inSetRequests += 1
            processV3SetRequest(&request, user: user)
        case SNMPPDUType.informRequest:
            stats.inTraps += 1
            processV3InformRequest(&request, user: user)
        default:
            stats.inASNParseErrs += 1
            return
        }
    }

    private func processV3GetRequest(_ request: inout SNMPRequest, user: SNMPv3User) {
        var responseVarbinds = [SNMPVarbind]()
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        for (index, vb) in request.varbinds.enumerated() {
            guard vb.type == SNMPASN1.typeNull, vb.value.isEmpty else {
                errorStatus = SNMPError.genErr.rawValue
                errorIndex = Int32(index + 1)
                break
            }

            let result = getNodeValue(oid: vb.oid, version: SNMPVersion.v2c)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
                stats.inTotalReqVars += 1
            case .failure(let err):
                let exceptionType: UInt8
                switch err {
                case .noSuchInstance:
                    exceptionType = SNMPVarbindException.noSuchInstance
                default:
                    exceptionType = SNMPVarbindException.noSuchObject
                }
                responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: exceptionType, value: []))
            }

            if errorStatus != 0 { break }
        }

        sendV3Response(request: request, user: user, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: responseVarbinds)
    }

    private func processV3GetNextRequest(_ request: inout SNMPRequest, user: SNMPv3User) {
        var responseVarbinds = [SNMPVarbind]()
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        for (index, vb) in request.varbinds.enumerated() {
            guard vb.type == SNMPASN1.typeNull, vb.value.isEmpty else {
                errorStatus = SNMPError.genErr.rawValue
                errorIndex = Int32(index + 1)
                break
            }

            let result = getNextNodeValue(oid: vb.oid, version: SNMPVersion.v2c)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
                stats.inTotalReqVars += 1
            case .failure:
                responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: SNMPVarbindException.endOfMibView, value: []))
            }

            if errorStatus != 0 { break }
        }

        sendV3Response(request: request, user: user, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: responseVarbinds)
    }

    private func processV3GetBulkRequest(_ request: inout SNMPRequest, user: SNMPv3User) {
        var responseVarbinds = [SNMPVarbind]()
        let nonRepeaters = max(0, Int(request.nonRepeaters))
        let maxRepetitions = max(0, Int(request.maxRepetitions))

        for i in 0..<min(nonRepeaters, request.varbinds.count) {
            let vb = request.varbinds[i]
            let result = getNextNodeValue(oid: vb.oid, version: SNMPVersion.v2c)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
            case .failure:
                responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: SNMPVarbindException.endOfMibView, value: []))
            }
        }

        if nonRepeaters < request.varbinds.count && maxRepetitions > 0 {
            let repeaterVarbinds = Array(request.varbinds[nonRepeaters...])
            var currentOIDs = repeaterVarbinds.map { $0.oid }

            for _ in 0..<maxRepetitions {
                var allEndOfMib = true
                for j in 0..<currentOIDs.count {
                    let result = getNextNodeValue(oid: currentOIDs[j], version: SNMPVersion.v2c)
                    switch result {
                    case .success(let responseVB):
                        responseVarbinds.append(responseVB)
                        currentOIDs[j] = responseVB.oid
                        allEndOfMib = false
                    case .failure:
                        let eomVB = SNMPVarbind(oid: currentOIDs[j], type: SNMPVarbindException.endOfMibView, value: [])
                        responseVarbinds.append(eomVB)
                    }
                }
                if allEndOfMib { break }
            }
        }

        sendV3Response(request: request, user: user, errorStatus: 0, errorIndex: 0, varbinds: responseVarbinds)
    }

    private func processV3SetRequest(_ request: inout SNMPRequest, user: SNMPv3User) {
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        // Phase 1: Validate
        for (index, vb) in request.varbinds.enumerated() {
            let testResult = testSetValue(oid: vb.oid, type: vb.type, value: vb.value)
            if testResult != .noError {
                errorStatus = testResult.rawValue
                errorIndex = Int32(index + 1)
                break
            }
        }

        // Phase 2: Apply
        if errorStatus == 0 {
            for (index, vb) in request.varbinds.enumerated() {
                let setResult = applySetValue(oid: vb.oid, type: vb.type, value: vb.value)
                if setResult != .noError {
                    errorStatus = index == 0 ? 14 : 15
                    errorIndex = Int32(index + 1)
                    break
                }
                stats.inTotalSetVars += 1
                writeCallback?(vb.oid, vb.value)
            }
        }

        sendV3Response(request: request, user: user, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: request.varbinds)
    }

    /// Handle an incoming SNMPv3 InformRequest by acknowledging with a GetResponse.
    private func processV3InformRequest(_ request: inout SNMPRequest, user: SNMPv3User) {
        sendV3Response(request: request, user: user, errorStatus: 0, errorIndex: 0, varbinds: request.varbinds)
    }

    // MARK: - SNMPv3 Response Building

    /// Build and send an SNMPv3 response message with security wrapping
    private func sendV3Response(request: SNMPRequest, user: SNMPv3User, errorStatus: Int32, errorIndex: Int32, varbinds: [SNMPVarbind]) {
        let authFlag = (request.msgFlags & 0x01) != 0
        let privFlag = (request.msgFlags & 0x02) != 0

        // Build the inner PDU
        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.getResponse,
            requestID: request.requestID,
            errorStatus: errorStatus,
            errorIndex: errorIndex,
            varbinds: varbinds
        )

        // Build scoped PDU: SEQUENCE { contextEngineID, contextName, PDU }
        let scopedPDU = SNMPResponseBuilder.buildScopedPDU(
            contextEngineID: v3Engine.engineID,
            contextName: request.contextName,
            pduBytes: pduBytes
        )

        // Encrypt if needed
        var scopedPDUOrEncrypted: [UInt8]
        var privParameters: [UInt8] = []
        if privFlag {
            if let result = v3Engine.encrypt(
                scopedPDU: scopedPDU,
                user: user,
                engineBoots: v3Engine.engineBoots,
                engineTime: v3Engine.engineTime
            ) {
                // Wrap encrypted data as OCTET STRING
                var encWrapper = [UInt8](repeating: 0, count: result.encrypted.count + 10)
                var encOffset = 0
                encWrapper[encOffset] = SNMPASN1.typeOctetString
                encOffset += 1
                SNMPASN1Encoder.encodeLength(result.encrypted.count, into: &encWrapper, at: &encOffset)
                for b in result.encrypted {
                    encWrapper[encOffset] = b
                    encOffset += 1
                }
                scopedPDUOrEncrypted = Array(encWrapper[0..<encOffset])
                privParameters = result.privParameters
            } else {
                stats.outGenErrs += 1
                return
            }
        } else {
            scopedPDUOrEncrypted = scopedPDU
        }

        // Build the full v3 message with placeholder auth (12 zero bytes if auth needed)
        let messageBytes = SNMPResponseBuilder.buildV3Message(
            msgID: request.msgID,
            msgMaxSize: 65507,
            msgFlags: request.msgFlags,
            msgSecurityModel: 3,
            engineID: v3Engine.engineID,
            engineBoots: v3Engine.engineBoots,
            engineTime: v3Engine.engineTime,
            userName: request.userName,
            authParameters: authFlag ? [UInt8](repeating: 0, count: 12) : [],
            privParameters: privParameters,
            scopedPDUOrEncrypted: scopedPDUOrEncrypted
        )

        var finalMessage = messageBytes

        // Compute and insert authentication if needed
        if authFlag {
            if let digest = v3Engine.authenticate(message: finalMessage, user: user) {
                // Find and replace the 12 zero-byte authParameters in the message
                if let authOffset = SNMPResponseBuilder.findAuthParametersOffset(in: finalMessage) {
                    for i in 0..<12 {
                        finalMessage[authOffset + i] = digest[i]
                    }
                }
            }
        }

        guard finalMessage.count <= 65535 else {
            stats.outTooBigs += 1
            return
        }

        if sendRawResponse(finalMessage, to: request.sourceAddress, port: request.sourcePort) == .ok {
            stats.outGetResponses += 1
            stats.outPkts += 1
        }
    }

    /// Send an SNMPv3 engine discovery response (returns engine ID, boots, time)
    private func sendV3DiscoveryResponse(request: SNMPRequest) {
        // Build a report PDU with usmStatsUnknownEngineIDs
        stats.unknownEngineIDs += 1
        let reportOID = SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0])
        let counterValue = stats.unknownEngineIDs

        var counterBytes = [UInt8]()
        var v = counterValue
        if v == 0 {
            counterBytes = [0]
        } else {
            while v > 0 {
                counterBytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if (counterBytes[0] & 0x80) != 0 {
                counterBytes.insert(0, at: 0)
            }
        }
        let reportVarbind = SNMPVarbind(oid: reportOID, type: SNMPASN1.typeCounter32, value: counterBytes)

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.getResponse,
            requestID: 0,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: [reportVarbind]
        )

        let scopedPDU = SNMPResponseBuilder.buildScopedPDU(
            contextEngineID: v3Engine.engineID,
            contextName: "",
            pduBytes: pduBytes
        )

        let responseBytes = SNMPResponseBuilder.buildV3Message(
            msgID: request.msgID,
            msgMaxSize: 65507,
            msgFlags: 0x00,  // noAuth, noPriv, not reportable
            msgSecurityModel: 3,
            engineID: v3Engine.engineID,
            engineBoots: v3Engine.engineBoots,
            engineTime: v3Engine.engineTime,
            userName: "",
            authParameters: [],
            privParameters: [],
            scopedPDUOrEncrypted: scopedPDU
        )

        if sendRawResponse(responseBytes, to: request.sourceAddress, port: request.sourcePort) == .ok {
            stats.outPkts += 1
        }
    }

    /// Send an SNMPv3 report PDU (for error conditions)
    private func sendV3Report(request: SNMPRequest, reportOID: SNMPObjectID, reportValue: UInt32) {
        var counterBytes = [UInt8]()
        var v = reportValue
        if v == 0 {
            counterBytes = [0]
        } else {
            while v > 0 {
                counterBytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if (counterBytes[0] & 0x80) != 0 {
                counterBytes.insert(0, at: 0)
            }
        }
        let reportVarbind = SNMPVarbind(oid: reportOID, type: SNMPASN1.typeCounter32, value: counterBytes)

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.getResponse,
            requestID: 0,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: [reportVarbind]
        )

        let scopedPDU = SNMPResponseBuilder.buildScopedPDU(
            contextEngineID: v3Engine.engineID,
            contextName: "",
            pduBytes: pduBytes
        )

        // Report messages are sent without auth/priv
        let responseBytes = SNMPResponseBuilder.buildV3Message(
            msgID: request.msgID,
            msgMaxSize: 65507,
            msgFlags: 0x00,
            msgSecurityModel: 3,
            engineID: v3Engine.engineID,
            engineBoots: v3Engine.engineBoots,
            engineTime: v3Engine.engineTime,
            userName: request.userName,
            authParameters: [],
            privParameters: [],
            scopedPDUOrEncrypted: scopedPDU
        )

        if sendRawResponse(responseBytes, to: request.sourceAddress, port: request.sourcePort) == .ok {
            stats.outPkts += 1
        }
    }

    // MARK: - GET Processing

    private func processGetRequest(_ request: inout SNMPRequest) {
        var responseVarbinds = [SNMPVarbind]()
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        for (index, vb) in request.varbinds.enumerated() {
            // GET request varbinds should have NULL value
            guard vb.type == SNMPASN1.typeNull, vb.value.isEmpty else {
                errorStatus = SNMPError.genErr.rawValue
                errorIndex = Int32(index + 1)
                break
            }

            let result = getNodeValue(oid: vb.oid, version: request.version)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
                stats.inTotalReqVars += 1
            case .failure(let err):
                if request.version == SNMPVersion.v1 {
                    errorStatus = 2  // noSuchName for v1
                    errorIndex = Int32(index + 1)
                    stats.inNoSuchNames += 1
                } else {
                    // v2c: return exception varbind
                    let exceptionType: UInt8
                    switch err {
                    case .noSuchInstance:
                        exceptionType = SNMPVarbindException.noSuchInstance
                    default:
                        exceptionType = SNMPVarbindException.noSuchObject
                    }
                    responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: exceptionType, value: []))
                }
            }

            if errorStatus != 0 { break }
        }

        if errorStatus != 0 && request.version == SNMPVersion.v1 {
            // For v1, on error return the original varbinds
            responseVarbinds = request.varbinds
        }

        sendResponse(request: request, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: responseVarbinds)
    }

    // MARK: - GETNEXT Processing

    private func processGetNextRequest(_ request: inout SNMPRequest) {
        var responseVarbinds = [SNMPVarbind]()
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        for (index, vb) in request.varbinds.enumerated() {
            guard vb.type == SNMPASN1.typeNull, vb.value.isEmpty else {
                errorStatus = SNMPError.genErr.rawValue
                errorIndex = Int32(index + 1)
                break
            }

            let result = getNextNodeValue(oid: vb.oid, version: request.version)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
                stats.inTotalReqVars += 1
            case .failure:
                if request.version == SNMPVersion.v1 {
                    errorStatus = 2  // noSuchName
                    errorIndex = Int32(index + 1)
                    stats.inNoSuchNames += 1
                } else {
                    // v2c: endOfMibView
                    responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: SNMPVarbindException.endOfMibView, value: []))
                }
            }

            if errorStatus != 0 { break }
        }

        if errorStatus != 0 && request.version == SNMPVersion.v1 {
            responseVarbinds = request.varbinds
        }

        sendResponse(request: request, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: responseVarbinds)
    }

    // MARK: - GETBULK Processing

    private func processGetBulkRequest(_ request: inout SNMPRequest) {
        var responseVarbinds = [SNMPVarbind]()
        let nonRepeaters = max(0, Int(request.nonRepeaters))
        let maxRepetitions = max(0, Int(request.maxRepetitions))

        // Process non-repeaters (like GETNEXT)
        for i in 0..<min(nonRepeaters, request.varbinds.count) {
            let vb = request.varbinds[i]
            let result = getNextNodeValue(oid: vb.oid, version: request.version)
            switch result {
            case .success(let responseVB):
                responseVarbinds.append(responseVB)
            case .failure:
                responseVarbinds.append(SNMPVarbind(oid: vb.oid, type: SNMPVarbindException.endOfMibView, value: []))
            }
        }

        // Process repeaters
        if nonRepeaters < request.varbinds.count && maxRepetitions > 0 {
            let repeaterVarbinds = Array(request.varbinds[nonRepeaters...])
            var currentOIDs = repeaterVarbinds.map { $0.oid }

            for _ in 0..<maxRepetitions {
                var allEndOfMib = true
                for j in 0..<currentOIDs.count {
                    let result = getNextNodeValue(oid: currentOIDs[j], version: request.version)
                    switch result {
                    case .success(let responseVB):
                        responseVarbinds.append(responseVB)
                        currentOIDs[j] = responseVB.oid
                        allEndOfMib = false
                    case .failure:
                        let eomVB = SNMPVarbind(oid: currentOIDs[j], type: SNMPVarbindException.endOfMibView, value: [])
                        responseVarbinds.append(eomVB)
                    }
                }
                if allEndOfMib { break }
            }
        }

        sendResponse(request: request, errorStatus: 0, errorIndex: 0, varbinds: responseVarbinds)
    }

    // MARK: - SET Processing

    private func processSetRequest(_ request: inout SNMPRequest) {
        var errorStatus: Int32 = 0
        var errorIndex: Int32 = 0

        // Phase 1: Validate all varbinds (set_test)
        for (index, vb) in request.varbinds.enumerated() {
            let testResult = testSetValue(oid: vb.oid, type: vb.type, value: vb.value)
            if testResult != .noError {
                errorStatus = testResult.rawValue
                errorIndex = Int32(index + 1)
                break
            }
        }

        // Phase 2: Apply all values if validation passed
        if errorStatus == 0 {
            for (index, vb) in request.varbinds.enumerated() {
                let setResult = applySetValue(oid: vb.oid, type: vb.type, value: vb.value)
                if setResult != .noError {
                    if index == 0 {
                        errorStatus = 14  // commitFailed
                    } else {
                        errorStatus = 15  // undoFailed
                    }
                    errorIndex = Int32(index + 1)
                    break
                }
                stats.inTotalSetVars += 1
                writeCallback?(vb.oid, vb.value)
            }
        }

        // Build response with the original varbinds (SET response echoes request)
        sendResponse(request: request, errorStatus: errorStatus, errorIndex: errorIndex, varbinds: request.varbinds)
    }

    // MARK: - Response Sending

    private func sendResponse(request: SNMPRequest, errorStatus: Int32, errorIndex: Int32, varbinds: [SNMPVarbind]) {
        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.getResponse,
            requestID: request.requestID,
            errorStatus: errorStatus,
            errorIndex: errorIndex,
            varbinds: varbinds
        )

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: request.version,
            community: request.community,
            pduBytes: pduBytes
        )

        guard messageBytes.count <= 65535 else {
            stats.outTooBigs += 1
            // Send tooBig error with empty varbinds
            let tooBigPDU = SNMPResponseBuilder.buildPDU(
                pduType: SNMPPDUType.getResponse,
                requestID: request.requestID,
                errorStatus: 1,  // tooBig
                errorIndex: 0,
                varbinds: []
            )
            let tooBigMessage = SNMPResponseBuilder.wrapMessage(
                version: request.version,
                community: request.community,
                pduBytes: tooBigPDU
            )
            _ = sendRawResponse(tooBigMessage, to: request.sourceAddress, port: request.sourcePort)
            return
        }

        if sendRawResponse(messageBytes, to: request.sourceAddress, port: request.sourcePort) == .ok {
            stats.outGetResponses += 1
            stats.outPkts += 1
        }
    }

    @discardableResult
    private func sendRawResponse(_ data: [UInt8], to addr: IPAddress, port: UInt16) -> LWIPError {
        sendPacket(data, to: addr, port: port)
    }

    @discardableResult
    private func sendPacket(_ data: [UInt8], to addr: IPAddress, port: UInt16) -> LWIPError {
        if let conn = netConn {
            let buf = NetBuf()
            guard let payload = buf.alloc(size: UInt16(data.count)) else { return .outOfMemory }
            data.withUnsafeBufferPointer { ptr in
                payload.copyMemory(from: ptr.baseAddress!, byteCount: data.count)
            }
            let err = conn.sendTo(buf, addr: addr, port: port)
            _ = buf.p?.free()
            buf.free()
            return err
        }

        guard let pcb = udpControlBlock else { return .notConnected }
        guard let pbuf = Pbuf.alloc(layer: .transport, length: UInt16(data.count), type: .ram) else { return .outOfMemory }
        data.withUnsafeBufferPointer { ptr in
            _ = pbuf.takeAt(from: ptr.baseAddress!, len: UInt16(data.count), offset: 0)
        }
        let err = UDPGlobal.shared.sendTo(pcb, pbuf: pbuf, dstIP: addr, dstPort: port)
        pbuf.free()
        return err
    }

    // MARK: - MIB Tree Walking

    /// Walk the MIB tree to find a node matching the given OID
    public func findNode(oid: SNMPObjectID) -> (mib: SNMPMIB, node: SNMPNode)? {
        for mib in mibs {
            let baseLen = mib.baseOID.count
            guard oid.length >= baseLen else { continue }
            let prefix = Array(oid.components.prefix(baseLen))
            guard prefix == mib.baseOID else { continue }

            // Walk tree from root
            var current: SNMPNode = mib.rootNode
            var depth = baseLen
            while depth < oid.length {
                guard let tree = current as? SNMPTreeNode else {
                    return (mib, current)
                }
                let target = oid.components[depth]
                var found = false
                for sub in tree.subnodes {
                    if sub.oid == target {
                        current = sub
                        found = true
                        break
                    }
                }
                if !found { return nil }
                depth += 1
            }
            return (mib, current)
        }
        return nil
    }

    /// Find the MIB that contains the given OID
    private func findMIB(oid: SNMPObjectID) -> SNMPMIB? {
        for mib in mibs {
            let baseLen = mib.baseOID.count
            guard oid.length >= baseLen else { continue }
            let prefix = Array(oid.components.prefix(baseLen))
            if prefix == mib.baseOID { return mib }
        }
        return nil
    }

    /// Find the next MIB whose base OID is lexicographically after the given OID
    private func findNextMIB(after oid: SNMPObjectID) -> SNMPMIB? {
        var bestMIB: SNMPMIB?
        var bestOID: SNMPObjectID?
        for mib in mibs {
            let mibOID = SNMPObjectID(mib.baseOID)
            if mibOID.compare(with: oid) > 0 {
                if bestOID == nil || mibOID.compare(with: bestOID!) < 0 {
                    bestMIB = mib
                    bestOID = mibOID
                }
            }
        }
        return bestMIB
    }

    /// Resolve exact node in MIB tree, returning (node, remainingOIDLen)
    private func resolveExact(mib: SNMPMIB, oid: SNMPObjectID) -> (node: SNMPNode, instanceLen: Int)? {
        let baseLen = mib.baseOID.count
        guard oid.length >= baseLen else { return nil }

        var current: SNMPNode = mib.rootNode
        var depth = baseLen

        while depth < oid.length {
            guard let tree = current as? SNMPTreeNode else {
                // current is a leaf; remaining OID is the instance part
                return (current, oid.length - depth)
            }
            let target = oid.components[depth]
            var found = false
            for sub in tree.subnodes {
                if sub.oid == target {
                    current = sub
                    found = true
                    break
                }
            }
            if !found { return nil }
            depth += 1
        }
        return (current, 0)
    }

    /// Resolve the lexicographically next leaf node after the given OID within a MIB
    private func resolveNext(mib: SNMPMIB, oid: SNMPObjectID) -> (node: SNMPNode, fullOID: SNMPObjectID)? {
        // Collect all leaf nodes with their full OIDs
        var candidates: [(node: SNMPNode, fullOID: SNMPObjectID)] = []
        collectLeaves(node: mib.rootNode, prefix: mib.baseOID, into: &candidates)

        // Find the first leaf whose OID is strictly greater than the request OID
        var bestResult: (node: SNMPNode, fullOID: SNMPObjectID)?
        for candidate in candidates {
            if candidate.fullOID.compare(with: oid) > 0 {
                if bestResult == nil || candidate.fullOID.compare(with: bestResult!.fullOID) < 0 {
                    bestResult = candidate
                }
            }
        }
        return bestResult
    }

    /// Collect all leaf nodes from a tree node, building their full OIDs
    private func collectLeaves(node: SNMPNode, prefix: [UInt32], into results: inout [(node: SNMPNode, fullOID: SNMPObjectID)]) {
        if let tree = node as? SNMPTreeNode {
            for sub in tree.subnodes {
                collectLeaves(node: sub, prefix: prefix + [sub.oid], into: &results)
            }
        } else {
            results.append((node: node, fullOID: SNMPObjectID(prefix)))
        }
    }

    // MARK: - GET/SET Value Operations

    /// Get the value of an OID for a GET request
    private func getNodeValue(oid: SNMPObjectID, version: Int32) -> Result<SNMPVarbind, SNMPError> {
        // Try to find a MIB and resolve the node
        guard let mib = findMIB(oid: oid),
              let (node, instanceLen) = resolveExact(mib: mib, oid: oid) else {
            return .failure(.noSuchInstance)
        }

        guard let leaf = node as? SNMPLeafNode else {
            return .failure(.noSuchInstance)
        }

        let instance = SNMPNodeInstance()
        instance.node = node
        let instanceOIDComponents = instanceLen > 0 ? Array(oid.components.suffix(instanceLen)) : []
        instance.instanceOID = SNMPObjectID(instanceOIDComponents)

        let rootOID = Array(oid.components.prefix(oid.length - instanceLen))

        let err = leaf.getInstance?(rootOID, instance) ?? .genErr
        if err != .noError {
            if let release = instance.releaseInstance { release(instance) }
            return .failure(err)
        }

        // Check readable
        guard instance.access == .readOnly || instance.access == .readWrite else {
            if let release = instance.releaseInstance { release(instance) }
            return .failure(.noSuchInstance)
        }
        guard let getValueFn = instance.getValue else {
            if let release = instance.releaseInstance { release(instance) }
            return .failure(.noSuchInstance)
        }

        // Skip Counter64 for v1
        if version == SNMPVersion.v1 && instance.asn1Type == SNMPASN1.typeCounter64 {
            if let release = instance.releaseInstance { release(instance) }
            return .failure(.noSuchInstance)
        }

        var valueBuffer = [UInt8](repeating: 0, count: SNMPLimits.maxValueSize)
        let valueLen = getValueFn(instance, &valueBuffer)
        if let release = instance.releaseInstance { release(instance) }

        guard valueLen >= 0 else {
            return .failure(.genErr)
        }

        let value = Array(valueBuffer[0..<Int(valueLen)])
        return .success(SNMPVarbind(oid: oid, type: instance.asn1Type, value: value))
    }

    /// Get the next OID and its value for a GETNEXT request
    private func getNextNodeValue(oid: SNMPObjectID, version: Int32) -> Result<SNMPVarbind, SNMPError> {
        // First try within the current MIB
        var currentMIB = findMIB(oid: oid)
        if currentMIB == nil {
            currentMIB = findNextMIB(after: oid)
        }

        while let mib = currentMIB {
            // First, try to resolve the exact node and ask it for the next instance
            if let (node, instanceLen) = resolveExact(mib: mib, oid: oid), let leaf = node as? SNMPLeafNode {
                let instance = SNMPNodeInstance()
                instance.node = node
                let instanceOIDComponents = instanceLen > 0 ? Array(oid.components.suffix(instanceLen)) : []
                instance.instanceOID = SNMPObjectID(instanceOIDComponents)

                let rootOID = Array(oid.components.prefix(oid.length - instanceLen))

                let err = leaf.getNextInstance?(rootOID, instance) ?? .genErr
                if err == .noError {
                    // Check readable and skip Counter64 for v1
                    let readable = instance.access == .readOnly || instance.access == .readWrite
                    let notCounter64V1 = !(version == SNMPVersion.v1 && instance.asn1Type == SNMPASN1.typeCounter64)
                    if readable && instance.getValue != nil && notCounter64V1 {
                        var valueBuffer = [UInt8](repeating: 0, count: SNMPLimits.maxValueSize)
                        let valueLen = instance.getValue!(instance, &valueBuffer)
                        if let release = instance.releaseInstance { release(instance) }

                        if valueLen >= 0 {
                            let fullOID = SNMPObjectID(rootOID + instance.instanceOID.components)
                            let value = Array(valueBuffer[0..<Int(valueLen)])
                            return .success(SNMPVarbind(oid: fullOID, type: instance.asn1Type, value: value))
                        }
                    } else {
                        if let release = instance.releaseInstance { release(instance) }
                    }
                } else {
                    if let release = instance.releaseInstance { release(instance) }
                }
            }

            // Try the next leaf node in the tree
            if let (nextNode, nextFullOID) = resolveNext(mib: mib, oid: oid) {
                if let leaf = nextNode as? SNMPLeafNode {
                    let instance = SNMPNodeInstance()
                    instance.node = nextNode
                    instance.instanceOID = SNMPObjectID()

                    let err = leaf.getNextInstance?(nextFullOID.components, instance) ?? .genErr
                    if err == .noError {
                        let readable = instance.access == .readOnly || instance.access == .readWrite
                        let notCounter64V1 = !(version == SNMPVersion.v1 && instance.asn1Type == SNMPASN1.typeCounter64)
                        if readable && instance.getValue != nil && notCounter64V1 {
                            var valueBuffer = [UInt8](repeating: 0, count: SNMPLimits.maxValueSize)
                            let valueLen = instance.getValue!(instance, &valueBuffer)
                            if let release = instance.releaseInstance { release(instance) }

                            if valueLen >= 0 {
                                let fullOID = SNMPObjectID(nextFullOID.components + instance.instanceOID.components)
                                let value = Array(valueBuffer[0..<Int(valueLen)])
                                return .success(SNMPVarbind(oid: fullOID, type: instance.asn1Type, value: value))
                            }
                        } else {
                            if let release = instance.releaseInstance { release(instance) }
                        }
                    } else {
                        if let release = instance.releaseInstance { release(instance) }
                    }
                }
            }

            // Move to next MIB
            let mibOID = SNMPObjectID(mib.baseOID)
            currentMIB = findNextMIB(after: mibOID)
        }

        return .failure(.noSuchInstance)
    }

    /// Test whether a SET operation is valid
    private func testSetValue(oid: SNMPObjectID, type: UInt8, value: [UInt8]) -> SNMPError {
        guard let mib = findMIB(oid: oid),
              let (node, instanceLen) = resolveExact(mib: mib, oid: oid) else {
            return .noSuchInstance
        }

        guard let leaf = node as? SNMPLeafNode else {
            return .noSuchInstance
        }

        let instance = SNMPNodeInstance()
        instance.node = node
        let instanceOIDComponents = instanceLen > 0 ? Array(oid.components.suffix(instanceLen)) : []
        instance.instanceOID = SNMPObjectID(instanceOIDComponents)
        let rootOID = Array(oid.components.prefix(oid.length - instanceLen))

        let err = leaf.getInstance?(rootOID, instance) ?? .genErr
        if err != .noError {
            if let release = instance.releaseInstance { release(instance) }
            return err
        }

        // Check type match
        guard instance.asn1Type == type else {
            if let release = instance.releaseInstance { release(instance) }
            return .wrongType
        }

        // Check writable
        guard instance.access == .readWrite || instance.access == .writeOnly else {
            if let release = instance.releaseInstance { release(instance) }
            return .notWritable
        }

        guard instance.setValue != nil else {
            if let release = instance.releaseInstance { release(instance) }
            return .notWritable
        }

        // Run set_test if available
        if let setTestFn = instance.setTest {
            let testErr = setTestFn(instance, UInt16(value.count), value)
            if let release = instance.releaseInstance { release(instance) }
            return testErr
        }

        if let release = instance.releaseInstance { release(instance) }
        return .noError
    }

    /// Apply a SET operation
    private func applySetValue(oid: SNMPObjectID, type: UInt8, value: [UInt8]) -> SNMPError {
        guard let mib = findMIB(oid: oid),
              let (node, instanceLen) = resolveExact(mib: mib, oid: oid) else {
            return .noSuchInstance
        }

        guard let leaf = node as? SNMPLeafNode else {
            return .noSuchInstance
        }

        let instance = SNMPNodeInstance()
        instance.node = node
        let instanceOIDComponents = instanceLen > 0 ? Array(oid.components.suffix(instanceLen)) : []
        instance.instanceOID = SNMPObjectID(instanceOIDComponents)
        let rootOID = Array(oid.components.prefix(oid.length - instanceLen))

        let err = leaf.getInstance?(rootOID, instance) ?? .genErr
        if err != .noError {
            if let release = instance.releaseInstance { release(instance) }
            return err
        }

        guard let setValueFn = instance.setValue else {
            if let release = instance.releaseInstance { release(instance) }
            return .notWritable
        }

        let setErr = setValueFn(instance, UInt16(value.count), value)
        if let release = instance.releaseInstance { release(instance) }
        return setErr
    }

    // MARK: - Utility Functions

    public func decodeBits(buf: [UInt8]) -> UInt32? {
        var bitValue: UInt32 = 0
        for i in 0..<min(buf.count, 4) {
            bitValue |= UInt32(buf[i]) << (8 * (3 - i))
        }
        return bitValue
    }

    public func encodeBits(value: UInt32, bitCount: UInt8) -> [UInt8] {
        let byteCount = min(Int((bitCount + 7) / 8), 4)
        var buf = [UInt8](repeating: 0, count: byteCount)
        for i in 0..<byteCount {
            buf[i] = UInt8((value >> (8 * (3 - i))) & 0xFF)
        }
        return buf
    }

    public func decodeTruthValue(_ value: Int32) -> Bool? {
        switch value {
        case 1: return true
        case 2: return false
        default: return nil
        }
    }

    public func encodeTruthValue(_ value: Bool) -> Int32 {
        return value ? 1 : 2
    }
}

// MARK: - SNMP Pbuf Stream

/// Stream abstraction for reading/writing SNMP data from/to pbufs
public final class SNMPPbufStream {
    public var pbuf: Pbuf?
    public var offset: Int = 0
    public var length: Int = 0

    public init(pbuf: Pbuf) {
        self.pbuf = pbuf
        self.length = pbuf.totalLength
    }

    /// Read one byte
    public func readByte() -> UInt8? {
        guard let pbuf = pbuf, offset < length else { return nil }
        let b = pbuf.byte(at: UInt16(offset))
        offset += 1
        return b
    }

    /// Read multiple bytes
    public func readBytes(_ count: Int) -> [UInt8]? {
        guard let pbuf = pbuf, offset + count <= length else { return nil }
        var data = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            data[i] = pbuf.byte(at: UInt16(offset + i))
        }
        offset += count
        return data
    }

    /// Write one byte
    public func writeByte(_ b: UInt8) -> Bool {
        guard let pbuf = pbuf else { return false }
        pbuf.setByte(at: UInt16(offset), to: b)
        offset += 1
        length = max(length, offset)
        return true
    }

    /// Write multiple bytes
    public func writeBytes(_ data: [UInt8]) -> Bool {
        for b in data {
            guard writeByte(b) else { return false }
        }
        return true
    }

    /// Seek to a position
    public func seek(to position: Int) -> Bool {
        guard position >= 0 && position <= length else { return false }
        offset = position
        return true
    }
}

// MARK: - SNMP Thread Sync Node

/// A wrapper node that synchronizes MIB access across threads.
/// Forwards get/set operations to the actual node via a thread-safe mechanism.
public final class SNMPThreadSyncNode: SNMPLeafNode {
    public let proxiedNode: SNMPLeafNode
    private let lock = NSLock()

    public init(oid: UInt32, proxiedNode: SNMPLeafNode) {
        self.proxiedNode = proxiedNode
        super.init(type: .threadSync, oid: oid)

        self.getInstance = { [weak self] rootOID, instance in
            guard let self = self else { return .genErr }
            self.lock.lock()
            defer { self.lock.unlock() }
            return self.proxiedNode.getInstance?(rootOID, instance) ?? .genErr
        }

        self.getNextInstance = { [weak self] rootOID, instance in
            guard let self = self else { return .genErr }
            self.lock.lock()
            defer { self.lock.unlock() }
            return self.proxiedNode.getNextInstance?(rootOID, instance) ?? .genErr
        }
    }
}

// MARK: - SNMPScalarNode getInstance/getNextInstance Setup

extension SNMPScalarNode {
    /// Configure this scalar node with standard getInstance and getNextInstance callbacks.
    /// Scalar nodes have a single instance at sub-OID .0.
    public func setupScalarCallbacks() {
        let node = self

        self.getInstance = { rootOID, instance in
            // Scalar instance must be .0
            guard instance.instanceOID.length == 1,
                  instance.instanceOID.components[0] == 0 else {
                return .noSuchInstance
            }

            instance.asn1Type = node.asn1Type
            instance.access = node.access
            instance.getValue = node.getValueFn
            instance.setTest = node.setTestFn
            instance.setValue = node.setValueFn
            return .noError
        }

        self.getNextInstance = { rootOID, instance in
            // If no instance OID yet, return .0 (first and only instance)
            if instance.instanceOID.length == 0 {
                instance.instanceOID = SNMPObjectID([0])
                instance.asn1Type = node.asn1Type
                instance.access = node.access
                instance.getValue = node.getValueFn
                instance.setTest = node.setTestFn
                instance.setValue = node.setValueFn
                return .noError
            }
            // Already at or past .0, no more instances
            return .noSuchInstance
        }
    }
}

// MARK: - MIB-II System Group (RFC 1213)

/// MIB-II System Group (1.3.6.1.2.1.1)
///
/// Implements:
/// - sysDescr     (1.3.6.1.2.1.1.1.0)  - DisplayString, read-only
/// - sysObjectID  (1.3.6.1.2.1.1.2.0)  - OBJECT IDENTIFIER, read-only
/// - sysUpTime    (1.3.6.1.2.1.1.3.0)  - TimeTicks, read-only
/// - sysContact   (1.3.6.1.2.1.1.4.0)  - DisplayString, read-write
/// - sysName      (1.3.6.1.2.1.1.5.0)  - DisplayString, read-write
/// - sysLocation  (1.3.6.1.2.1.1.6.0)  - DisplayString, read-write
/// - sysServices  (1.3.6.1.2.1.1.7.0)  - INTEGER, read-only
public final class MIB2SystemGroup: @unchecked Sendable {
    public static let shared = MIB2SystemGroup()

    /// sysDescr: A textual description of the entity
    public var sysDescr: String = "lwIP Swift SNMP Agent"

    /// sysObjectID: The vendor's authoritative identification
    public var sysObjectIDComponents: [UInt32] = [1, 3, 6, 1, 4, 1, 99999]

    /// sysUpTime start time (set when agent starts)
    private var startTime: UInt64 = 0

    /// sysContact: Contact person for this managed node
    public var sysContact: String = ""

    /// sysName: An administratively-assigned name for this managed node
    public var sysName: String = "lwIP"

    /// sysLocation: The physical location of this node
    public var sysLocation: String = ""

    /// sysServices: A value indicating the set of services offered (72 = layers 3+4)
    public var sysServices: Int32 = 72

    /// Maximum length for writable strings
    public var maxStringLength: Int = 255

    public init() {
        resetUpTime()
    }

    /// Reset the uptime counter
    public func resetUpTime() {
        startTime = Self.currentTimeMillis()
    }

    /// sysUpTime in hundredths of a second since startup
    public var sysUpTime: UInt32 {
        let elapsed = Self.currentTimeMillis() - startTime
        return UInt32(elapsed / 10)  // Convert ms to centiseconds
    }

    private static func currentTimeMillis() -> UInt64 {
        var tv = timeval()
        gettimeofday(&tv, nil)
        return UInt64(tv.tv_sec) * 1000 + UInt64(tv.tv_usec) / 1000
    }

    // MARK: - MIB Tree Construction

    /// Build the MIB-II system group tree and return the SNMPMIB
    public func buildMIB() -> SNMPMIB {
        let sysDescrNode = buildSysDescrNode()
        let sysObjectIDNode = buildSysObjectIDNode()
        let sysUpTimeNode = buildSysUpTimeNode()
        let sysContactNode = buildSysContactNode()
        let sysNameNode = buildSysNameNode()
        let sysLocationNode = buildSysLocationNode()
        let sysServicesNode = buildSysServicesNode()

        // system (1.3.6.1.2.1.1) tree node
        let systemTreeNode = SNMPTreeNode(oid: 1, subnodes: [
            sysDescrNode,
            sysObjectIDNode,
            sysUpTimeNode,
            sysContactNode,
            sysNameNode,
            sysLocationNode,
            sysServicesNode
        ])

        // mib-2 (1.3.6.1.2.1) root
        let mib2Root = SNMPTreeNode(oid: 1, subnodes: [systemTreeNode])

        return SNMPMIB(baseOID: [1, 3, 6, 1, 2, 1], rootNode: mib2Root)
    }

    // MARK: - Node Builders

    func buildSysDescrNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 1,
            asn1Type: SNMPASN1.typeOctetString,
            access: .readOnly,
            getValue: { _, buffer in
                let data = Array(group.sysDescr.utf8)
                for i in 0..<data.count {
                    buffer[i] = data[i]
                }
                return Int16(data.count)
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysObjectIDNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 2,
            asn1Type: SNMPASN1.typeObjectID,
            access: .readOnly,
            getValue: { _, buffer in
                let oid = SNMPObjectID(group.sysObjectIDComponents)
                // Encode OID value (without tag/length) into buffer
                var oidBytes = [UInt8]()
                let components = oid.components
                if components.count >= 2 {
                    oidBytes.append(UInt8(components[0] * 40 + components[1]))
                    for i in 2..<components.count {
                        let val = components[i]
                        if val < 0x80 {
                            oidBytes.append(UInt8(val))
                        } else {
                            var subid = val
                            var subBytes = [UInt8]()
                            subBytes.append(UInt8(subid & 0x7F))
                            subid >>= 7
                            while subid > 0 {
                                subBytes.insert(UInt8((subid & 0x7F) | 0x80), at: 0)
                                subid >>= 7
                            }
                            oidBytes.append(contentsOf: subBytes)
                        }
                    }
                }
                for i in 0..<oidBytes.count {
                    buffer[i] = oidBytes[i]
                }
                return Int16(oidBytes.count)
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysUpTimeNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 3,
            asn1Type: SNMPASN1.typeTimeTicks,
            access: .readOnly,
            getValue: { _, buffer in
                let uptime = group.sysUpTime
                buffer[0] = UInt8((uptime >> 24) & 0xFF)
                buffer[1] = UInt8((uptime >> 16) & 0xFF)
                buffer[2] = UInt8((uptime >> 8) & 0xFF)
                buffer[3] = UInt8(uptime & 0xFF)
                return 4
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysContactNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 4,
            asn1Type: SNMPASN1.typeOctetString,
            access: .readWrite,
            getValue: { _, buffer in
                let data = Array(group.sysContact.utf8)
                for i in 0..<data.count {
                    buffer[i] = data[i]
                }
                return Int16(data.count)
            },
            setTest: { _, len, _ in
                if Int(len) > group.maxStringLength {
                    return .wrongLength
                }
                return .noError
            },
            setValue: { _, len, value in
                guard let str = String(bytes: Array(value[0..<Int(len)]), encoding: .utf8) else {
                    return .wrongEncoding
                }
                group.sysContact = str
                return .noError
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysNameNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 5,
            asn1Type: SNMPASN1.typeOctetString,
            access: .readWrite,
            getValue: { _, buffer in
                let data = Array(group.sysName.utf8)
                for i in 0..<data.count {
                    buffer[i] = data[i]
                }
                return Int16(data.count)
            },
            setTest: { _, len, _ in
                if Int(len) > group.maxStringLength {
                    return .wrongLength
                }
                return .noError
            },
            setValue: { _, len, value in
                guard let str = String(bytes: Array(value[0..<Int(len)]), encoding: .utf8) else {
                    return .wrongEncoding
                }
                group.sysName = str
                return .noError
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysLocationNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 6,
            asn1Type: SNMPASN1.typeOctetString,
            access: .readWrite,
            getValue: { _, buffer in
                let data = Array(group.sysLocation.utf8)
                for i in 0..<data.count {
                    buffer[i] = data[i]
                }
                return Int16(data.count)
            },
            setTest: { _, len, _ in
                if Int(len) > group.maxStringLength {
                    return .wrongLength
                }
                return .noError
            },
            setValue: { _, len, value in
                guard let str = String(bytes: Array(value[0..<Int(len)]), encoding: .utf8) else {
                    return .wrongEncoding
                }
                group.sysLocation = str
                return .noError
            }
        )
        node.setupScalarCallbacks()
        return node
    }

    func buildSysServicesNode() -> SNMPScalarNode {
        let group = self
        let node = SNMPScalarNode(
            oid: 7,
            asn1Type: SNMPASN1.typeInteger,
            access: .readOnly,
            getValue: { _, buffer in
                let val = group.sysServices
                // Encode as big-endian signed integer bytes
                if val == 0 {
                    buffer[0] = 0
                    return 1
                }
                var v = val
                var bytes = [UInt8]()
                let negative = v < 0
                while v != 0 && v != -1 {
                    bytes.insert(UInt8(v & 0xFF), at: 0)
                    v >>= 8
                }
                if negative && (bytes[0] & 0x80) == 0 {
                    bytes.insert(0xFF, at: 0)
                } else if !negative && (bytes[0] & 0x80) != 0 {
                    bytes.insert(0, at: 0)
                }
                for i in 0..<bytes.count {
                    buffer[i] = bytes[i]
                }
                return Int16(bytes.count)
            }
        )
        node.setupScalarCallbacks()
        return node
    }
}

// MARK: - SNMP Agent Convenience

extension SNMPAgent {
    /// Create and start an SNMP agent with the default MIB-II system group.
    /// Sets the MIB list to include MIB-II and starts the agent.
    public func startWithMIB2() -> LWIPError {
        let mib2 = MIB2SystemGroup.shared.buildMIB()
        setMIBs([mib2])
        return start()
    }
}

// MARK: - SNMPv3 Engine ID Generation

public extension SNMPv3Engine {

    /// Engine ID format identifiers per RFC 3411 / RFC 5343.
    struct EngineIDFormat {
        /// Format 1: IPv4 address (4 bytes)
        public static let ipv4: UInt8 = 1
        /// Format 2: IPv6 address (16 bytes)
        public static let ipv6: UInt8 = 2
        /// Format 3: MAC address (6 bytes)
        public static let macAddress: UInt8 = 3
        /// Format 4: Administratively assigned text
        public static let text: UInt8 = 4
        /// Format 5: Administratively assigned octets
        public static let octets: UInt8 = 5
    }

    /// Generate a local engine ID from an enterprise number and optional IPv4 address.
    ///
    /// The engine ID is formed per RFC 3411 Section 5:
    ///   - First 4 bytes: enterprise number with bit 31 set (indicating SNMPv3)
    ///   - Byte 5: format indicator
    ///   - Remaining bytes: address or identifier data
    ///
    /// - Parameters:
    ///   - enterpriseNumber: The IANA-assigned enterprise number.
    ///   - ipv4: Optional IPv4 address; if nil, uses the current system time as octets.
    func generateEngineID(enterpriseNumber: UInt32, ipv4: IPv4Address? = nil) {
        var eid = [UInt8]()

        // Enterprise number with high bit set
        let entWithBit = enterpriseNumber | 0x80000000
        eid.append(UInt8((entWithBit >> 24) & 0xFF))
        eid.append(UInt8((entWithBit >> 16) & 0xFF))
        eid.append(UInt8((entWithBit >> 8) & 0xFF))
        eid.append(UInt8(entWithBit & 0xFF))

        if let ip = ipv4 {
            eid.append(EngineIDFormat.ipv4)
            eid.append(ip.octet1)
            eid.append(ip.octet2)
            eid.append(ip.octet3)
            eid.append(ip.octet4)
        } else {
            eid.append(EngineIDFormat.octets)
            // Use current time to create a unique identifier
            var tv = timeval()
            gettimeofday(&tv, nil)
            let ts = UInt64(tv.tv_sec)
            for shift in stride(from: 56, through: 0, by: -8) {
                eid.append(UInt8((ts >> shift) & 0xFF))
            }
        }

        self.engineID = eid
    }

    /// Generate an engine ID from a MAC address (6 bytes).
    func generateEngineID(enterpriseNumber: UInt32, mac: [UInt8]) {
        guard mac.count == 6 else { return }
        var eid = [UInt8]()
        let entWithBit = enterpriseNumber | 0x80000000
        eid.append(UInt8((entWithBit >> 24) & 0xFF))
        eid.append(UInt8((entWithBit >> 16) & 0xFF))
        eid.append(UInt8((entWithBit >> 8) & 0xFF))
        eid.append(UInt8(entWithBit & 0xFF))
        eid.append(EngineIDFormat.macAddress)
        eid.append(contentsOf: mac)
        self.engineID = eid
    }

    /// Generate an engine ID from administratively assigned text.
    func generateEngineID(enterpriseNumber: UInt32, text: String) {
        let textBytes = Array(text.utf8)
        guard textBytes.count <= 27 else { return } // max engine ID is 32 bytes
        var eid = [UInt8]()
        let entWithBit = enterpriseNumber | 0x80000000
        eid.append(UInt8((entWithBit >> 24) & 0xFF))
        eid.append(UInt8((entWithBit >> 16) & 0xFF))
        eid.append(UInt8((entWithBit >> 8) & 0xFF))
        eid.append(UInt8(entWithBit & 0xFF))
        eid.append(EngineIDFormat.text)
        eid.append(contentsOf: textBytes)
        self.engineID = eid
    }
}

// MARK: - SNMPv3 Engine Boots/Time Management

/// Manages persistent engine boots counter and tracks engine time.
public final class SNMPv3EngineTimeManager: @unchecked Sendable {

    /// The engine whose time we are managing.
    public weak var engine: SNMPv3Engine?

    /// File path for persisting the engine boots counter across restarts.
    public var bootsFilePath: String?

    /// Time when the engine was last started (monotonic reference).
    private var startTimeSeconds: UInt64 = 0

    /// Maximum engine time value before wrapping (2^31 - 1 per RFC 3414).
    public static let maxEngineTime: UInt32 = 2_147_483_647

    public init(engine: SNMPv3Engine) {
        self.engine = engine
    }

    /// Initialize the engine boots counter. Loads from persistent storage if available,
    /// increments by one, and saves back. Also records the current time for computing
    /// engine time later.
    public func initialize() {
        guard let engine = engine else { return }

        if let path = bootsFilePath {
            let prevBoots = loadBoots(from: path)
            engine.engineBoots = prevBoots &+ 1
            saveBoots(engine.engineBoots, to: path)
        } else {
            engine.engineBoots = 1
        }

        var tv = timeval()
        gettimeofday(&tv, nil)
        startTimeSeconds = UInt64(tv.tv_sec)
        engine.engineTime = 0
    }

    /// Update the engine time field based on elapsed wall-clock time since initialization.
    /// Should be called periodically (e.g., before processing each message) or on demand.
    public func updateEngineTime() {
        guard let engine = engine else { return }
        var tv = timeval()
        gettimeofday(&tv, nil)
        let now = UInt64(tv.tv_sec)
        let elapsed = now - startTimeSeconds
        if elapsed > UInt64(Self.maxEngineTime) {
            // Engine time wrapped; increment boots and reset
            engine.engineBoots &+= 1
            startTimeSeconds = now
            engine.engineTime = 0
            if let path = bootsFilePath {
                saveBoots(engine.engineBoots, to: path)
            }
        } else {
            engine.engineTime = UInt32(elapsed)
        }
    }

    /// Check if a received engineBoots/engineTime pair is within the acceptable time window.
    /// Per RFC 3414 Section 3.2 step 7, the message must satisfy:
    ///   - engineBoots == local engineBoots
    ///   - |engineTime - local engineTime| <= 150 seconds
    public func isInTimeWindow(boots: UInt32, time: UInt32) -> Bool {
        guard let engine = engine else { return false }
        updateEngineTime()
        guard boots == engine.engineBoots else { return false }
        let diff: Int64 = Int64(engine.engineTime) - Int64(time)
        return abs(diff) <= 150
    }

    private func loadBoots(from path: String) -> UInt32 {
        guard let data = FileManager.default.contents(atPath: path),
              data.count >= 4 else { return 0 }
        let bytes = [UInt8](data)
        return UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 |
               UInt32(bytes[2]) << 8 | UInt32(bytes[3])
    }

    private func saveBoots(_ boots: UInt32, to path: String) {
        let bytes: [UInt8] = [
            UInt8((boots >> 24) & 0xFF),
            UInt8((boots >> 16) & 0xFF),
            UInt8((boots >> 8) & 0xFF),
            UInt8(boots & 0xFF)
        ]
        FileManager.default.createFile(atPath: path, contents: Data(bytes), attributes: nil)
    }
}

// MARK: - SNMPv3 User Table Management

public extension SNMPv3Engine {

    /// Add a user by password, automatically performing key localization.
    ///
    /// Converts the authentication and privacy passwords into localized keys
    /// using the current engine ID, then stores the user.
    ///
    /// - Parameters:
    ///   - userName: The security name.
    ///   - authProtocol: Authentication protocol to use.
    ///   - authPassword: The authentication password (will be localized).
    ///   - privProtocol: Privacy protocol to use.
    ///   - privPassword: The privacy password (will be localized).
    func addUser(
        userName: String,
        authProtocol: SNMPv3AuthProtocol = .none,
        authPassword: String = "",
        privProtocol: SNMPv3PrivProtocol = .none,
        privPassword: String = ""
    ) {
        var authKey = [UInt8]()
        var privKey = [UInt8]()

        if authProtocol != .none && !authPassword.isEmpty {
            authKey = localizeKey(password: authPassword, engineID: engineID, protocol: authProtocol)
        }

        if privProtocol != .none && !privPassword.isEmpty {
            // Privacy key is also derived using the auth protocol hash
            let derivationProto = authProtocol != .none ? authProtocol : .sha
            privKey = localizeKey(password: privPassword, engineID: engineID, protocol: derivationProto)
        }

        let user = SNMPv3User(
            userName: userName,
            authProtocol: authProtocol,
            authKey: authKey,
            privProtocol: privProtocol,
            privKey: privKey
        )
        addUser(user)
    }

    /// Remove a user by name. Returns true if the user was found and removed.
    @discardableResult
    func removeUser(name: String) -> Bool {
        if let index = users.firstIndex(where: { $0.userName == name }) {
            users.remove(at: index)
            return true
        }
        return false
    }

    /// Remove all users from the user table.
    func removeAllUsers() {
        users.removeAll()
    }

    /// Re-localize all users' keys after an engine ID change.
    /// This requires that the original passwords are available; users added
    /// with pre-computed keys cannot be re-localized.
    ///
    /// - Parameter passwords: Dictionary mapping user names to (authPassword, privPassword).
    func relocalizeUsers(passwords: [String: (auth: String, priv: String)]) {
        for i in 0..<users.count {
            guard let pw = passwords[users[i].userName] else { continue }
            if users[i].authProtocol != .none && !pw.auth.isEmpty {
                users[i].authKey = localizeKey(password: pw.auth, engineID: engineID, protocol: users[i].authProtocol)
            }
            if users[i].privProtocol != .none && !pw.priv.isEmpty {
                let derivationProto = users[i].authProtocol != .none ? users[i].authProtocol : .sha
                users[i].privKey = localizeKey(password: pw.priv, engineID: engineID, protocol: derivationProto)
            }
        }
    }

    /// Validate that a user's security level is sufficient for the requested message flags.
    /// Returns the error OID for a report if validation fails, or nil if OK.
    ///
    /// - Parameters:
    ///   - user: The looked-up user.
    ///   - msgFlags: The message flags byte from the incoming message.
    /// - Returns: The usmStats OID to report, or nil on success.
    func validateSecurityLevel(user: SNMPv3User, msgFlags: UInt8) -> SNMPObjectID? {
        let authRequired = (msgFlags & 0x01) != 0
        let privRequired = (msgFlags & 0x02) != 0

        // Privacy without authentication is not allowed (RFC 3414)
        if privRequired && !authRequired {
            return SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0]) // usmStatsUnsupportedSecLevels
        }
        if authRequired && user.authProtocol == .none {
            return SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0])
        }
        if privRequired && user.privProtocol == .none {
            return SNMPObjectID([1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0])
        }
        return nil
    }
}

// MARK: - SNMPv3 Message Security Processing

public extension SNMPv3Engine {

    /// SNMPv3 security level constants (RFC 3411).
    struct SecurityLevel {
        public static let noAuthNoPriv: UInt8 = 0x00
        public static let authNoPriv: UInt8   = 0x01
        public static let authPriv: UInt8     = 0x03
    }

    /// USM security model number.
    static let usmSecurityModel: Int32 = 3

    /// Process an outgoing SNMPv3 message: apply authentication and privacy.
    ///
    /// Steps:
    /// 1. Build the scoped PDU.
    /// 2. Encrypt the scoped PDU if privacy is requested.
    /// 3. Build the full message with placeholder auth parameters.
    /// 4. Compute HMAC over the message and insert the digest.
    ///
    /// - Returns: The complete encoded SNMPv3 message ready to send, or nil on failure.
    func processOutgoingMessage(
        msgID: Int32,
        msgFlags: UInt8,
        user: SNMPv3User,
        contextName: String,
        pduBytes: [UInt8]
    ) -> [UInt8]? {
        let authFlag = (msgFlags & 0x01) != 0
        let privFlag = (msgFlags & 0x02) != 0

        // Build scoped PDU
        let scopedPDU = SNMPResponseBuilder.buildScopedPDU(
            contextEngineID: engineID,
            contextName: contextName,
            pduBytes: pduBytes
        )

        var scopedPDUOrEncrypted: [UInt8]
        var privParams: [UInt8] = []

        if privFlag {
            guard let encResult = encrypt(
                scopedPDU: scopedPDU,
                user: user,
                engineBoots: engineBoots,
                engineTime: engineTime
            ) else { return nil }

            // Wrap encrypted data as OCTET STRING
            var encWrapper = [UInt8](repeating: 0, count: encResult.encrypted.count + 10)
            var encOffset = 0
            encWrapper[encOffset] = SNMPASN1.typeOctetString
            encOffset += 1
            SNMPASN1Encoder.encodeLength(encResult.encrypted.count, into: &encWrapper, at: &encOffset)
            for b in encResult.encrypted {
                encWrapper[encOffset] = b
                encOffset += 1
            }
            scopedPDUOrEncrypted = Array(encWrapper[0..<encOffset])
            privParams = encResult.privParameters
        } else {
            scopedPDUOrEncrypted = scopedPDU
        }

        let authPlaceholder = authFlag ? [UInt8](repeating: 0, count: 12) : []

        var message = SNMPResponseBuilder.buildV3Message(
            msgID: msgID,
            msgMaxSize: 65507,
            msgFlags: msgFlags,
            msgSecurityModel: SNMPv3Engine.usmSecurityModel,
            engineID: engineID,
            engineBoots: engineBoots,
            engineTime: engineTime,
            userName: user.userName,
            authParameters: authPlaceholder,
            privParameters: privParams,
            scopedPDUOrEncrypted: scopedPDUOrEncrypted
        )

        if authFlag {
            guard let digest = authenticate(message: message, user: user) else { return nil }
            guard let authOffset = SNMPResponseBuilder.findAuthParametersOffset(in: message) else { return nil }
            for i in 0..<12 {
                message[authOffset + i] = digest[i]
            }
        }

        return message
    }

    /// Process an incoming SNMPv3 message's security parameters: verify authentication
    /// and decrypt the scoped PDU.
    ///
    /// - Parameters:
    ///   - rawMessage: The complete raw incoming message bytes.
    ///   - authParametersOffset: Byte offset of the auth parameters value in rawMessage.
    ///   - receivedAuthParams: The received 12-byte authentication digest.
    ///   - privParameters: The received privacy parameters.
    ///   - encryptedPDU: The encrypted scoped PDU bytes (if privacy was used), or nil.
    ///   - user: The resolved user for this message.
    ///   - msgBoots: The engineBoots from the message.
    ///   - msgTime: The engineTime from the message.
    /// - Returns: The decrypted scoped PDU bytes on success, or nil on failure.
    func processIncomingSecurity(
        rawMessage: [UInt8],
        authParametersOffset: Int,
        receivedAuthParams: [UInt8],
        privParameters: [UInt8],
        encryptedPDU: [UInt8]?,
        user: SNMPv3User,
        msgBoots: UInt32,
        msgTime: UInt32
    ) -> [UInt8]? {
        let needsAuth = user.authProtocol != .none && !receivedAuthParams.isEmpty

        if needsAuth {
            // Zero the auth parameters in a copy for HMAC verification
            var msgCopy = rawMessage
            for i in 0..<min(12, receivedAuthParams.count) {
                msgCopy[authParametersOffset + i] = 0
            }
            guard verifyAuthentication(
                wholeMessage: msgCopy,
                user: user,
                receivedDigest: receivedAuthParams
            ) else { return nil }
        }

        if let encPDU = encryptedPDU {
            return decrypt(
                encryptedPDU: encPDU,
                user: user,
                privParameters: privParameters,
                engineBoots: msgBoots,
                engineTime: msgTime
            )
        }

        return nil // No encrypted PDU to decrypt; scoped PDU is already plaintext
    }
}

// MARK: - SNMPv2 Framework MIB Objects

/// Provides the snmpFrameworkMIB objects (1.3.6.1.6.3.10) for SNMPv3 engine discovery.
/// Implements snmpEngineID, snmpEngineBoots, snmpEngineTime, snmpEngineMaxMessageSize
/// as defined in RFC 3411.
public final class SNMPv2FrameworkMIB {

    /// The SNMPv3 engine these MIB objects report on.
    public let engine: SNMPv3Engine

    /// Optional time manager for keeping engineTime updated.
    public var timeManager: SNMPv3EngineTimeManager?

    public init(engine: SNMPv3Engine) {
        self.engine = engine
    }

    /// Build the snmpFrameworkMIB (1.3.6.1.6.3.10.2.1) as an SNMPMIB.
    /// Objects:
    ///   - snmpEngineID      (1.3.6.1.6.3.10.2.1.1.0) OCTET STRING, read-only
    ///   - snmpEngineBoots   (1.3.6.1.6.3.10.2.1.2.0) INTEGER, read-only
    ///   - snmpEngineTime    (1.3.6.1.6.3.10.2.1.3.0) INTEGER, read-only
    ///   - snmpEngineMaxMessageSize (1.3.6.1.6.3.10.2.1.4.0) INTEGER, read-only
    public func buildMIB() -> SNMPMIB {
        let engineRef = engine
        let timeManagerRef = timeManager

        let snmpEngineIDNode = SNMPScalarNode(
            oid: 1,
            asn1Type: SNMPASN1.typeOctetString,
            access: .readOnly,
            getValue: { _, buffer in
                let eid = engineRef.engineID
                for i in 0..<eid.count {
                    buffer[i] = eid[i]
                }
                return Int16(eid.count)
            }
        )
        snmpEngineIDNode.setupScalarCallbacks()

        let snmpEngineBootsNode = SNMPScalarNode(
            oid: 2,
            asn1Type: SNMPASN1.typeInteger,
            access: .readOnly,
            getValue: { _, buffer in
                let boots = engineRef.engineBoots
                var v = Int32(bitPattern: boots)
                var bytes = [UInt8]()
                if v == 0 {
                    bytes = [0]
                } else {
                    let negative = v < 0
                    while v != 0 && v != -1 {
                        bytes.insert(UInt8(v & 0xFF), at: 0)
                        v >>= 8
                    }
                    if negative && (bytes[0] & 0x80) == 0 {
                        bytes.insert(0xFF, at: 0)
                    } else if !negative && (bytes[0] & 0x80) != 0 {
                        bytes.insert(0, at: 0)
                    }
                }
                for i in 0..<bytes.count { buffer[i] = bytes[i] }
                return Int16(bytes.count)
            }
        )
        snmpEngineBootsNode.setupScalarCallbacks()

        let snmpEngineTimeNode = SNMPScalarNode(
            oid: 3,
            asn1Type: SNMPASN1.typeInteger,
            access: .readOnly,
            getValue: { _, buffer in
                timeManagerRef?.updateEngineTime()
                let time = engineRef.engineTime
                var v = Int32(bitPattern: time)
                var bytes = [UInt8]()
                if v == 0 {
                    bytes = [0]
                } else {
                    let negative = v < 0
                    while v != 0 && v != -1 {
                        bytes.insert(UInt8(v & 0xFF), at: 0)
                        v >>= 8
                    }
                    if negative && (bytes[0] & 0x80) == 0 {
                        bytes.insert(0xFF, at: 0)
                    } else if !negative && (bytes[0] & 0x80) != 0 {
                        bytes.insert(0, at: 0)
                    }
                }
                for i in 0..<bytes.count { buffer[i] = bytes[i] }
                return Int16(bytes.count)
            }
        )
        snmpEngineTimeNode.setupScalarCallbacks()

        let snmpEngineMaxMsgSizeNode = SNMPScalarNode(
            oid: 4,
            asn1Type: SNMPASN1.typeInteger,
            access: .readOnly,
            getValue: { _, buffer in
                // Standard maximum message size for UDP
                let maxSize: Int32 = 65507
                var v = maxSize
                var bytes = [UInt8]()
                while v != 0 && v != -1 {
                    bytes.insert(UInt8(v & 0xFF), at: 0)
                    v >>= 8
                }
                if (bytes[0] & 0x80) != 0 {
                    bytes.insert(0, at: 0)
                }
                for i in 0..<bytes.count { buffer[i] = bytes[i] }
                return Int16(bytes.count)
            }
        )
        snmpEngineMaxMsgSizeNode.setupScalarCallbacks()

        // snmpEngine (1.3.6.1.6.3.10.2.1) tree
        let snmpEngineNode = SNMPTreeNode(oid: 1, subnodes: [
            snmpEngineIDNode, snmpEngineBootsNode, snmpEngineTimeNode, snmpEngineMaxMsgSizeNode
        ])
        let snmpMIBObjectsNode = SNMPTreeNode(oid: 2, subnodes: [snmpEngineNode])
        let snmpFrameworkRoot = SNMPTreeNode(oid: 10, subnodes: [snmpMIBObjectsNode])

        return SNMPMIB(baseOID: [1, 3, 6, 1, 6, 3], rootNode: snmpFrameworkRoot)
    }
}

// MARK: - SNMPv2 USM MIB Objects

/// Provides the usmStats counters (1.3.6.1.6.3.15.1.1) as MIB objects.
/// These counters are used in SNMPv3 report PDUs for security errors.
public final class SNMPv2USMMIB {

    public let stats: SNMPStatistics

    public init(stats: SNMPStatistics = .shared) {
        self.stats = stats
    }

    /// Build the USM stats MIB (1.3.6.1.6.3.15.1.1) subtree.
    /// Objects:
    ///   - usmStatsUnsupportedSecLevels  (.1.0) Counter32
    ///   - usmStatsNotInTimeWindows      (.2.0) Counter32
    ///   - usmStatsUnknownUserNames      (.3.0) Counter32
    ///   - usmStatsUnknownEngineIDs      (.4.0) Counter32
    ///   - usmStatsWrongDigests          (.5.0) Counter32
    ///   - usmStatsDecryptionErrors      (.6.0) Counter32
    public func buildMIB() -> SNMPMIB {
        let statsRef = stats

        func buildCounterNode(oid: UInt32, getValue: @escaping () -> UInt32) -> SNMPScalarNode {
            let node = SNMPScalarNode(
                oid: oid,
                asn1Type: SNMPASN1.typeCounter32,
                access: .readOnly,
                getValue: { _, buffer in
                    let val = getValue()
                    // Encode as big-endian unsigned
                    var bytes = [UInt8]()
                    var v = val
                    if v == 0 {
                        bytes = [0]
                    } else {
                        while v > 0 {
                            bytes.insert(UInt8(v & 0xFF), at: 0)
                            v >>= 8
                        }
                        if (bytes[0] & 0x80) != 0 {
                            bytes.insert(0, at: 0)
                        }
                    }
                    for i in 0..<bytes.count { buffer[i] = bytes[i] }
                    return Int16(bytes.count)
                }
            )
            node.setupScalarCallbacks()
            return node
        }

        let unsupportedSecLevelsNode = buildCounterNode(oid: 1) { statsRef.unsupportedSecLevels }
        let notInTimeWindowsNode = buildCounterNode(oid: 2) { statsRef.notInTimeWindows }
        let unknownUserNamesNode = buildCounterNode(oid: 3) { statsRef.unknownUserNames }
        let unknownEngineIDsNode = buildCounterNode(oid: 4) { statsRef.unknownEngineIDs }
        let wrongDigestsNode = buildCounterNode(oid: 5) { statsRef.wrongDigests }
        let decryptionErrorsNode = buildCounterNode(oid: 6) { statsRef.decryptionErrors }

        let usmStatsNode = SNMPTreeNode(oid: 1, subnodes: [
            unsupportedSecLevelsNode, notInTimeWindowsNode, unknownUserNamesNode,
            unknownEngineIDsNode, wrongDigestsNode, decryptionErrorsNode
        ])
        let usmMIBObjectsNode = SNMPTreeNode(oid: 1, subnodes: [usmStatsNode])
        let usmMIBRoot = SNMPTreeNode(oid: 15, subnodes: [usmMIBObjectsNode])

        return SNMPMIB(baseOID: [1, 3, 6, 1, 6, 3], rootNode: usmMIBRoot)
    }
}

// MARK: - Enhanced Table Node Implementation

/// Full-featured SNMP table node with row indexing, iteration, and dynamic row management.
///
/// A table in SNMP has the structure:
///   tableOID.1 (entry)
///     tableOID.1.columnOID.indexOID...
///
/// The table node handles the OID decomposition and dispatches to callbacks
/// for individual cell access.
public final class SNMPTableFullNode: SNMPLeafNode {

    /// Definition of a single column in the table.
    public struct ColumnDef {
        /// Column sub-OID (typically 1, 2, 3, ...)
        public let subOID: UInt32
        /// ASN.1 type for values in this column
        public let asn1Type: UInt8
        /// Access level for this column
        public let access: SNMPAccessType

        public init(subOID: UInt32, asn1Type: UInt8, access: SNMPAccessType) {
            self.subOID = subOID
            self.asn1Type = asn1Type
            self.access = access
        }
    }

    /// Column definitions for this table.
    public let columns: [ColumnDef]

    /// Callback to get the value of a cell.
    /// Parameters: column sub-OID, row index OID components, node instance to fill.
    /// Returns: .noError on success, or an error.
    public var getCellValue: ((_ column: UInt32, _ rowIndex: [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?

    /// Callback to get the next row index for a given column.
    /// Parameters: column sub-OID, current row index (empty for first row), node instance.
    /// The callback should update rowIndex in-place to the next valid row index.
    /// Returns: .noError on success, or .noSuchInstance if no more rows.
    public var getNextCell: ((_ column: UInt32, _ rowIndex: inout [UInt32], _ instance: SNMPNodeInstance) -> SNMPError)?

    /// Callback to test a SET operation on a cell before applying.
    public var setCellTest: ((_ column: UInt32, _ rowIndex: [UInt32], _ len: UInt16, _ value: [UInt8]) -> SNMPError)?

    /// Callback to set the value of a cell.
    public var setCellValue: ((_ column: UInt32, _ rowIndex: [UInt32], _ len: UInt16, _ value: [UInt8]) -> SNMPError)?

    /// Callback to create a new row. Called during SET if the row does not exist.
    /// Returns: .noError if row creation is supported and succeeded, or an error.
    public var createRow: ((_ rowIndex: [UInt32]) -> SNMPError)?

    /// Callback to delete a row.
    public var deleteRow: ((_ rowIndex: [UInt32]) -> SNMPError)?

    public init(oid: UInt32, columns: [ColumnDef]) {
        self.columns = columns
        super.init(type: .table, oid: oid)
        setupTableCallbacks()
    }

    /// Find a column definition by sub-OID.
    public func findColumn(_ subOID: UInt32) -> ColumnDef? {
        return columns.first { $0.subOID == subOID }
    }

    /// Get the sorted list of column sub-OIDs.
    public var sortedColumnOIDs: [UInt32] {
        return columns.map { $0.subOID }.sorted()
    }

    /// Decode a table cell OID into (columnOID, rowIndex).
    ///
    /// Table OIDs have the form: tableOID.1.column.index...
    /// The instance OID (after the table node's position in the tree) should be:
    ///   1.column.index...
    /// where 1 is the entry sub-OID.
    ///
    /// - Parameter instanceOID: The OID components after the table node.
    /// - Returns: Tuple of (column sub-OID, row index components), or nil if invalid.
    public func decodeTableOID(_ instanceOID: [UInt32]) -> (column: UInt32, rowIndex: [UInt32])? {
        // Minimum: entry(1).column
        guard instanceOID.count >= 2 else { return nil }
        // First component must be the entry node (always 1)
        guard instanceOID[0] == 1 else { return nil }
        let column = instanceOID[1]
        let rowIndex = instanceOID.count > 2 ? Array(instanceOID[2...]) : []
        return (column, rowIndex)
    }

    /// Encode a table cell OID from column and row index.
    ///
    /// - Parameters:
    ///   - column: The column sub-OID.
    ///   - rowIndex: The row index OID components.
    /// - Returns: The instance OID components (1.column.index...).
    public func encodeTableOID(column: UInt32, rowIndex: [UInt32]) -> [UInt32] {
        return [1, column] + rowIndex
    }

    // MARK: - Table Callback Setup

    private func setupTableCallbacks() {
        let table = self

        self.getInstance = { rootOID, instance in
            let instanceComponents = instance.instanceOID.components
            guard let (column, rowIndex) = table.decodeTableOID(instanceComponents) else {
                return .noSuchInstance
            }
            guard let colDef = table.findColumn(column) else {
                return .noSuchInstance
            }
            guard !rowIndex.isEmpty else {
                return .noSuchInstance
            }

            instance.asn1Type = colDef.asn1Type
            instance.access = colDef.access

            // Set up the getValue callback
            instance.getValue = { inst, buffer in
                let err = table.getCellValue?(column, rowIndex, inst) ?? .genErr
                if err != .noError { return -1 }
                // The getCellValue callback is expected to populate inst.reference
                // with the data; we copy from the reference or the buffer was filled directly
                return inst.getValue?(inst, &buffer) ?? -1
            }

            // For tables, we provide a compound getValue that delegates to getCellValue
            let cellResult = table.getCellValue?(column, rowIndex, instance)
            if cellResult != .noError {
                return cellResult ?? .noSuchInstance
            }

            // Set up set callbacks
            if colDef.access == .readWrite || colDef.access == .writeOnly {
                instance.setTest = { inst, len, value in
                    return table.setCellTest?(column, rowIndex, len, value) ?? .noError
                }
                instance.setValue = { inst, len, value in
                    return table.setCellValue?(column, rowIndex, len, value) ?? .notWritable
                }
            }

            return .noError
        }

        self.getNextInstance = { rootOID, instance in
            let instanceComponents = instance.instanceOID.components
            let sortedCols = table.sortedColumnOIDs

            guard !sortedCols.isEmpty else { return .noSuchInstance }

            // Determine starting column and row index
            var startColumn: UInt32
            var startRowIndex: [UInt32]

            if instanceComponents.isEmpty {
                // No instance yet; start with first column, first row
                startColumn = sortedCols[0]
                startRowIndex = []
            } else if instanceComponents.count == 1 {
                // Only entry OID; start with first column
                if instanceComponents[0] < 1 {
                    startColumn = sortedCols[0]
                    startRowIndex = []
                } else {
                    startColumn = sortedCols[0]
                    startRowIndex = []
                }
            } else if let (col, rowIdx) = table.decodeTableOID(instanceComponents) {
                startColumn = col
                startRowIndex = rowIdx
            } else {
                // Invalid OID structure; try first column
                startColumn = sortedCols[0]
                startRowIndex = []
            }

            // Iterate: for each column starting from startColumn, try to get the next row
            // SNMP table ordering is column-major: iterate all rows of column N
            // before moving to column N+1.
            var colIdx = sortedCols.firstIndex(of: startColumn) ?? 0
            var currentRowIndex = startRowIndex
            var isFirstAttempt = true

            while colIdx < sortedCols.count {
                let col = sortedCols[colIdx]
                guard let colDef = table.findColumn(col) else {
                    colIdx += 1
                    currentRowIndex = []
                    isFirstAttempt = false
                    continue
                }

                // Skip columns that are not accessible
                guard colDef.access == .readOnly || colDef.access == .readWrite else {
                    colIdx += 1
                    currentRowIndex = []
                    isFirstAttempt = false
                    continue
                }

                var nextRowIndex = currentRowIndex
                let err = table.getNextCell?(col, &nextRowIndex, instance)
                if err == .noError {
                    instance.instanceOID = SNMPObjectID(table.encodeTableOID(column: col, rowIndex: nextRowIndex))
                    instance.asn1Type = colDef.asn1Type
                    instance.access = colDef.access

                    if colDef.access == .readWrite || colDef.access == .writeOnly {
                        instance.setTest = { inst, len, value in
                            return table.setCellTest?(col, nextRowIndex, len, value) ?? .noError
                        }
                        instance.setValue = { inst, len, value in
                            return table.setCellValue?(col, nextRowIndex, len, value) ?? .notWritable
                        }
                    }
                    return .noError
                }

                // No more rows in this column; move to the next column
                colIdx += 1
                currentRowIndex = []
                isFirstAttempt = false
            }

            return .noSuchInstance
        }
    }
}

// MARK: - Table Index OID Encoding/Decoding Utilities

/// Utilities for encoding and decoding SNMP table row index OIDs.
/// Supports integer, string (fixed and implied length), IPv4 address, and OID index types.
public struct SNMPTableIndexCodec {

    /// Index component types.
    public enum IndexType {
        /// A single integer value (one OID component).
        case integer
        /// A fixed-length octet string. The OID encodes each byte as one component.
        case fixedString(length: Int)
        /// An implied-length octet string (must be last index). Each byte is one component.
        case impliedString
        /// An IPv4 address (4 OID components).
        case ipv4Address
        /// A variable-length OID: first component is length, followed by OID components.
        case oid
    }

    /// Decode a row index OID into individual index values according to the index specification.
    ///
    /// - Parameters:
    ///   - oid: The row index OID components.
    ///   - indexTypes: The ordered list of index types for this table.
    /// - Returns: An array of decoded values (each as [UInt32]), or nil if decoding fails.
    public static func decode(oid: [UInt32], indexTypes: [IndexType]) -> [[UInt32]]? {
        var pos = 0
        var result = [[UInt32]]()

        for (i, indexType) in indexTypes.enumerated() {
            switch indexType {
            case .integer:
                guard pos < oid.count else { return nil }
                result.append([oid[pos]])
                pos += 1

            case .fixedString(let length):
                guard pos + length <= oid.count else { return nil }
                result.append(Array(oid[pos..<(pos + length)]))
                pos += length

            case .impliedString:
                // Must be the last index
                guard i == indexTypes.count - 1 else { return nil }
                result.append(Array(oid[pos...]))
                pos = oid.count

            case .ipv4Address:
                guard pos + 4 <= oid.count else { return nil }
                result.append(Array(oid[pos..<(pos + 4)]))
                pos += 4

            case .oid:
                guard pos < oid.count else { return nil }
                let length = Int(oid[pos])
                pos += 1
                guard pos + length <= oid.count else { return nil }
                result.append(Array(oid[pos..<(pos + length)]))
                pos += length
            }
        }

        // All components should have been consumed (unless last was impliedString)
        if pos != oid.count {
            return nil
        }

        return result
    }

    /// Encode individual index values into a row index OID.
    ///
    /// - Parameters:
    ///   - values: An array of index values (each as [UInt32]).
    ///   - indexTypes: The ordered list of index types for this table.
    /// - Returns: The encoded row index OID components, or nil if encoding fails.
    public static func encode(values: [[UInt32]], indexTypes: [IndexType]) -> [UInt32]? {
        guard values.count == indexTypes.count else { return nil }
        var result = [UInt32]()

        for (i, indexType) in indexTypes.enumerated() {
            let value = values[i]
            switch indexType {
            case .integer:
                guard value.count == 1 else { return nil }
                result.append(value[0])

            case .fixedString(let length):
                guard value.count == length else { return nil }
                result.append(contentsOf: value)

            case .impliedString:
                guard i == indexTypes.count - 1 else { return nil }
                result.append(contentsOf: value)

            case .ipv4Address:
                guard value.count == 4 else { return nil }
                result.append(contentsOf: value)

            case .oid:
                result.append(UInt32(value.count))
                result.append(contentsOf: value)
            }
        }

        return result
    }

    /// Convenience: decode a single integer index.
    public static func decodeSingleInteger(oid: [UInt32]) -> UInt32? {
        guard oid.count == 1 else { return nil }
        return oid[0]
    }

    /// Convenience: decode an IPv4 address index.
    public static func decodeIPv4(oid: [UInt32]) -> IPv4Address? {
        guard oid.count >= 4 else { return nil }
        return IPv4Address(
            UInt8(oid[0] & 0xFF),
            UInt8(oid[1] & 0xFF),
            UInt8(oid[2] & 0xFF),
            UInt8(oid[3] & 0xFF)
        )
    }

    /// Convenience: encode an IPv4 address as index OID components.
    public static func encodeIPv4(_ addr: IPv4Address) -> [UInt32] {
        return [UInt32(addr.octet1), UInt32(addr.octet2), UInt32(addr.octet3), UInt32(addr.octet4)]
    }

    /// Convenience: encode an octet string (each byte as one OID component).
    public static func encodeString(_ string: String) -> [UInt32] {
        return Array(string.utf8).map { UInt32($0) }
    }

    /// Convenience: decode an octet string from OID components.
    public static func decodeString(_ components: [UInt32]) -> String? {
        let bytes = components.map { UInt8($0 & 0xFF) }
        return String(bytes: bytes, encoding: .utf8)
    }
}

// MARK: - Simple In-Memory Table Data Store

/// A simple in-memory data store for SNMP table rows, suitable for tables with
/// integer indices. Provides a ready-made backing store for SNMPTableFullNode.
public final class SNMPTableDataStore<RowData> {

    /// Storage: maps row index (as [UInt32]) to row data.
    private var rows: [String: (index: [UInt32], data: RowData)] = [:]

    /// Sorted row indices for iteration.
    private var sortedKeys: [[UInt32]] = []
    private var needsSort = false

    public init() {}

    /// Number of rows.
    public var count: Int { rows.count }

    /// Insert or update a row.
    public func setRow(index: [UInt32], data: RowData) {
        let key = indexKey(index)
        let isNew = rows[key] == nil
        rows[key] = (index: index, data: data)
        if isNew {
            needsSort = true
        }
    }

    /// Get a row's data.
    public func getRow(index: [UInt32]) -> RowData? {
        return rows[indexKey(index)]?.data
    }

    /// Check if a row exists.
    public func hasRow(index: [UInt32]) -> Bool {
        return rows[indexKey(index)] != nil
    }

    /// Delete a row. Returns true if the row existed.
    @discardableResult
    public func deleteRow(index: [UInt32]) -> Bool {
        let key = indexKey(index)
        if rows.removeValue(forKey: key) != nil {
            needsSort = true
            return true
        }
        return false
    }

    /// Delete all rows.
    public func deleteAll() {
        rows.removeAll()
        sortedKeys.removeAll()
        needsSort = false
    }

    /// Get the first row index (lexicographically).
    public func firstIndex() -> [UInt32]? {
        ensureSorted()
        return sortedKeys.first
    }

    /// Get the next row index after the given index.
    /// If the given index is empty, returns the first row index.
    /// If the given index matches an existing row, returns the next one.
    /// If the given index falls between rows, returns the first row after it.
    public func nextIndex(after currentIndex: [UInt32]) -> [UInt32]? {
        ensureSorted()
        if currentIndex.isEmpty {
            return sortedKeys.first
        }
        // Find the first key strictly greater than currentIndex
        for key in sortedKeys {
            if SNMPObjectID(key).compare(with: SNMPObjectID(currentIndex)) > 0 {
                return key
            }
        }
        return nil
    }

    /// Get all row indices, sorted.
    public func allIndices() -> [[UInt32]] {
        ensureSorted()
        return sortedKeys
    }

    /// Iterate over all rows in sorted order.
    public func forEach(_ body: ([UInt32], RowData) -> Void) {
        ensureSorted()
        for key in sortedKeys {
            if let entry = rows[indexKey(key)] {
                body(entry.index, entry.data)
            }
        }
    }

    private func indexKey(_ index: [UInt32]) -> String {
        return index.map { String($0) }.joined(separator: ".")
    }

    private func ensureSorted() {
        if needsSort {
            sortedKeys = rows.values.map { $0.index }.sorted { a, b in
                SNMPObjectID(a).compare(with: SNMPObjectID(b)) < 0
            }
            needsSort = false
        }
    }
}

// MARK: - Enhanced Trap Handling

/// Standard SNMP trap OIDs (SNMPv2 notification types).
public struct SNMPStandardTraps {
    /// coldStart (1.3.6.1.6.3.1.1.5.1)
    public static let coldStart = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 1])
    /// warmStart (1.3.6.1.6.3.1.1.5.2)
    public static let warmStart = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 2])
    /// linkDown (1.3.6.1.6.3.1.1.5.3)
    public static let linkDown = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 3])
    /// linkUp (1.3.6.1.6.3.1.1.5.4)
    public static let linkUp = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 4])
    /// authenticationFailure (1.3.6.1.6.3.1.1.5.5)
    public static let authenticationFailure = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 5, 5])

    /// Enterprise-specific trap base OID. Append enterprise-specific sub-OIDs.
    /// Format: enterprise OID + 0 + specific trap number
    public static func enterpriseSpecific(enterpriseOID: SNMPObjectID, specificTrap: UInt32) -> SNMPObjectID {
        return SNMPObjectID(enterpriseOID.components + [0, specificTrap])
    }
}

/// A trap/notification destination with its associated security credentials.
public struct SNMPTrapDestination: Sendable {
    /// Destination IP address.
    public let address: IPAddress
    /// Destination port (default 162).
    public let port: UInt16
    /// SNMP version to use for traps to this destination.
    public let version: Int32

    /// Community string (for v1/v2c).
    public let community: String
    /// User name (for v3).
    public let userName: String
    /// Security level flags for v3 (0x00=noAuthNoPriv, 0x01=authNoPriv, 0x03=authPriv).
    public let securityLevel: UInt8

    public init(
        address: IPAddress,
        port: UInt16 = 162,
        version: Int32 = SNMPVersion.v2c,
        community: String = "public",
        userName: String = "",
        securityLevel: UInt8 = 0x00
    ) {
        self.address = address
        self.port = port
        self.version = version
        self.community = community
        self.userName = userName
        self.securityLevel = securityLevel
    }
}

/// Enhanced trap sender with destination management, inform requests, and SNMPv3 support.
public final class SNMPEnhancedTrapSender: @unchecked Sendable {

    /// Configured trap destinations.
    public private(set) var destinations: [SNMPTrapDestination] = []

    /// Agent address for v1 traps.
    public var agentAddress: IPv4Address = .any

    /// SNMPv3 engine for v3 trap/inform processing.
    public weak var v3Engine: SNMPv3Engine?

    /// Transport send handler.
    public var sendHandler: (([UInt8], IPAddress, UInt16) -> LWIPError)?

    /// Counter for generating unique request IDs for informs.
    private var requestIDCounter: Int32 = 0

    /// Counter for generating unique message IDs for v3 messages.
    private var msgIDCounter: Int32 = 0

    /// Whether to send authenticationFailure traps.
    public var authFailureTrapEnabled: Bool = true

    /// Callback invoked when an inform acknowledgment is received (or times out).
    public var informResponseHandler: ((_ requestID: Int32, _ success: Bool) -> Void)?

    /// Pending inform requests waiting for acknowledgment, keyed by request ID.
    private var pendingInforms: [Int32: PendingInform] = [:]
    private let lock = NSLock()

    /// Inform request timeout in seconds.
    public var informTimeout: TimeInterval = 5.0

    /// Number of inform retries before giving up.
    public var informRetries: Int = 3

    public init() {}

    // MARK: - Destination Management

    /// Add a trap destination.
    public func addDestination(_ dest: SNMPTrapDestination) {
        lock.lock()
        defer { lock.unlock() }
        destinations.append(dest)
    }

    /// Remove all destinations matching the given address.
    public func removeDestinations(for address: IPAddress) {
        lock.lock()
        defer { lock.unlock() }
        destinations.removeAll { $0.address == address }
    }

    /// Remove a destination at a specific index.
    public func removeDestination(at index: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard index >= 0 && index < destinations.count else { return }
        destinations.remove(at: index)
    }

    /// Remove all destinations.
    public func removeAllDestinations() {
        lock.lock()
        defer { lock.unlock() }
        destinations.removeAll()
    }

    /// Add a v1/v2c destination with address and community.
    public func addV2cDestination(address: IPAddress, port: UInt16 = 162, community: String = "public") {
        addDestination(SNMPTrapDestination(
            address: address, port: port, version: SNMPVersion.v2c, community: community
        ))
    }

    /// Add a v3 destination with address, user, and security level.
    public func addV3Destination(address: IPAddress, port: UInt16 = 162, userName: String, securityLevel: UInt8 = 0x01) {
        addDestination(SNMPTrapDestination(
            address: address, port: port, version: SNMPVersion.v3,
            userName: userName, securityLevel: securityLevel
        ))
    }

    // MARK: - Standard Trap Sending

    /// Send a coldStart notification to all configured destinations.
    public func sendColdStart() {
        sendNotification(notificationOID: SNMPStandardTraps.coldStart)
    }

    /// Send a warmStart notification to all configured destinations.
    public func sendWarmStart() {
        sendNotification(notificationOID: SNMPStandardTraps.warmStart)
    }

    /// Send a linkDown notification with the interface index.
    public func sendLinkDown(ifIndex: Int32) {
        var ifIndexBytes = [UInt8]()
        var v = ifIndex
        if v == 0 {
            ifIndexBytes = [0]
        } else {
            let negative = v < 0
            while v != 0 && v != -1 {
                ifIndexBytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if negative && (ifIndexBytes[0] & 0x80) == 0 {
                ifIndexBytes.insert(0xFF, at: 0)
            } else if !negative && (ifIndexBytes[0] & 0x80) != 0 {
                ifIndexBytes.insert(0, at: 0)
            }
        }
        let ifIndexOID = SNMPObjectID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, UInt32(ifIndex)])
        sendNotification(
            notificationOID: SNMPStandardTraps.linkDown,
            varbinds: [(ifIndexOID, SNMPASN1.typeInteger, ifIndexBytes)]
        )
    }

    /// Send a linkUp notification with the interface index.
    public func sendLinkUp(ifIndex: Int32) {
        var ifIndexBytes = [UInt8]()
        var v = ifIndex
        if v == 0 {
            ifIndexBytes = [0]
        } else {
            let negative = v < 0
            while v != 0 && v != -1 {
                ifIndexBytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if negative && (ifIndexBytes[0] & 0x80) == 0 {
                ifIndexBytes.insert(0xFF, at: 0)
            } else if !negative && (ifIndexBytes[0] & 0x80) != 0 {
                ifIndexBytes.insert(0, at: 0)
            }
        }
        let ifIndexOID = SNMPObjectID([1, 3, 6, 1, 2, 1, 2, 2, 1, 1, UInt32(ifIndex)])
        sendNotification(
            notificationOID: SNMPStandardTraps.linkUp,
            varbinds: [(ifIndexOID, SNMPASN1.typeInteger, ifIndexBytes)]
        )
    }

    /// Send an authenticationFailure notification.
    public func sendAuthenticationFailure() {
        guard authFailureTrapEnabled else { return }
        sendNotification(notificationOID: SNMPStandardTraps.authenticationFailure)
    }

    /// Send an enterprise-specific trap.
    public func sendEnterpriseTrap(
        enterpriseOID: SNMPObjectID,
        specificTrap: UInt32,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])] = []
    ) {
        let trapOID = SNMPStandardTraps.enterpriseSpecific(
            enterpriseOID: enterpriseOID,
            specificTrap: specificTrap
        )
        sendNotification(notificationOID: trapOID, varbinds: varbinds)
    }

    // MARK: - Generic Notification Sending

    /// Send a notification (trap or inform) to all configured destinations.
    ///
    /// For each destination, the notification is formatted according to the destination's
    /// configured SNMP version (v1, v2c, or v3).
    ///
    /// - Parameters:
    ///   - notificationOID: The snmpTrapOID value (identifies the notification type).
    ///   - varbinds: Additional variable bindings to include.
    ///   - asInform: If true, send as an inform request (v2c/v3 only) instead of a trap.
    public func sendNotification(
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])] = [],
        asInform: Bool = false
    ) {
        lock.lock()
        let dests = destinations
        lock.unlock()

        for dest in dests {
            switch dest.version {
            case SNMPVersion.v1:
                sendV1Trap(to: dest, notificationOID: notificationOID, varbinds: varbinds)
            case SNMPVersion.v2c:
                if asInform {
                    sendV2cInform(to: dest, notificationOID: notificationOID, varbinds: varbinds)
                } else {
                    sendV2cTrap(to: dest, notificationOID: notificationOID, varbinds: varbinds)
                }
            case SNMPVersion.v3:
                if asInform {
                    sendV3Inform(to: dest, notificationOID: notificationOID, varbinds: varbinds)
                } else {
                    sendV3Trap(to: dest, notificationOID: notificationOID, varbinds: varbinds)
                }
            default:
                break
            }
        }
    }

    // MARK: - V1 Trap Encoding

    private func sendV1Trap(
        to dest: SNMPTrapDestination,
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) {
        let trapVarbinds = varbinds.map { SNMPVarbind(oid: $0.0, type: $0.1, value: $0.2) }

        // Determine generic and specific trap types from the notification OID
        let (genericTrap, specificTrap, enterpriseOID) = mapNotificationToV1(notificationOID)

        var pduContent = [UInt8](repeating: 0, count: 1400)
        var pduOffset = 0

        // Enterprise OID
        SNMPASN1Encoder.encodeOID(enterpriseOID, into: &pduContent, at: &pduOffset)

        // Agent address
        pduContent[pduOffset] = SNMPASN1.typeIPAddr
        pduOffset += 1
        pduContent[pduOffset] = 4
        pduOffset += 1
        pduContent[pduOffset] = agentAddress.octet1
        pduContent[pduOffset + 1] = agentAddress.octet2
        pduContent[pduOffset + 2] = agentAddress.octet3
        pduContent[pduOffset + 3] = agentAddress.octet4
        pduOffset += 4

        // Generic trap type
        SNMPASN1Encoder.encodeInteger(genericTrap, into: &pduContent, at: &pduOffset)

        // Specific trap type
        SNMPASN1Encoder.encodeInteger(specificTrap, into: &pduContent, at: &pduOffset)

        // Timestamp
        let uptime = MIB2SystemGroup.shared.sysUpTime
        pduContent[pduOffset] = SNMPASN1.typeTimeTicks
        pduOffset += 1
        SNMPResponseBuilder.encodeUInt32(uptime, into: &pduContent, at: &pduOffset)

        // Varbind list
        SNMPResponseBuilder.encodeVarbindList(trapVarbinds, into: &pduContent, at: &pduOffset)

        // Wrap in v1 trap PDU
        var buffer = [UInt8](repeating: 0, count: pduOffset + 10)
        var offset = 0
        buffer[offset] = SNMPPDUType.trapV1
        offset += 1
        SNMPASN1Encoder.encodeLength(pduOffset, into: &buffer, at: &offset)
        for i in 0..<pduOffset {
            buffer[offset] = pduContent[i]
            offset += 1
        }

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v1,
            community: dest.community,
            pduBytes: Array(buffer[0..<offset])
        )

        sendToDestination(messageBytes, dest: dest)
    }

    /// Map an SNMPv2 notification OID to v1 generic/specific trap numbers.
    private func mapNotificationToV1(_ notificationOID: SNMPObjectID) -> (generic: Int32, specific: Int32, enterprise: SNMPObjectID) {
        let snmpTrapsBase: [UInt32] = [1, 3, 6, 1, 6, 3, 1, 1, 5]

        // Check if this is a standard trap
        if notificationOID.components.count == snmpTrapsBase.count + 1 {
            let prefix = Array(notificationOID.components.prefix(snmpTrapsBase.count))
            if prefix == snmpTrapsBase {
                let genericType = Int32(notificationOID.components.last!)
                // Generic traps 1-5 map to v1 generic types 0-4
                if genericType >= 1 && genericType <= 5 {
                    return (genericType - 1, 0, SNMPObjectID([1, 3, 6, 1, 4, 1]))
                }
            }
        }

        // Enterprise-specific: the OID is enterprise.0.specificTrap
        let components = notificationOID.components
        if components.count >= 2 {
            let specificTrap = Int32(components.last!)
            // Check for .0 before the specific trap number
            if components.count >= 3 && components[components.count - 2] == 0 {
                let enterpriseOID = SNMPObjectID(Array(components.prefix(components.count - 2)))
                return (6, specificTrap, enterpriseOID) // 6 = enterpriseSpecific
            }
        }

        return (6, 0, notificationOID)
    }

    // MARK: - V2c Trap/Inform Encoding

    private func buildV2NotificationVarbinds(
        notificationOID: SNMPObjectID,
        additionalVarbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) -> [SNMPVarbind] {
        var allVarbinds = [SNMPVarbind]()

        // sysUpTime.0
        let sysUpTimeOID = SNMPObjectID([1, 3, 6, 1, 2, 1, 1, 3, 0])
        let uptime = MIB2SystemGroup.shared.sysUpTime
        var uptimeBytes = [UInt8](repeating: 0, count: 4)
        uptimeBytes[0] = UInt8((uptime >> 24) & 0xFF)
        uptimeBytes[1] = UInt8((uptime >> 16) & 0xFF)
        uptimeBytes[2] = UInt8((uptime >> 8) & 0xFF)
        uptimeBytes[3] = UInt8(uptime & 0xFF)
        allVarbinds.append(SNMPVarbind(oid: sysUpTimeOID, type: SNMPASN1.typeTimeTicks, value: uptimeBytes))

        // snmpTrapOID.0
        let snmpTrapOIDOID = SNMPObjectID([1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0])
        // Encode the notification OID value (without TLV wrapper)
        var trapOIDEncoded = [UInt8](repeating: 0, count: 128)
        var trapOIDOffset = 0
        SNMPASN1Encoder.encodeOID(notificationOID, into: &trapOIDEncoded, at: &trapOIDOffset)
        let tagLen = 1
        var lengthBytes = 1
        if trapOIDEncoded[1] == 0x81 { lengthBytes = 2 }
        else if trapOIDEncoded[1] == 0x82 { lengthBytes = 3 }
        let oidValueBytes = Array(trapOIDEncoded[(tagLen + lengthBytes)..<trapOIDOffset])
        allVarbinds.append(SNMPVarbind(oid: snmpTrapOIDOID, type: SNMPASN1.typeObjectID, value: oidValueBytes))

        // Additional varbinds
        for vb in additionalVarbinds {
            allVarbinds.append(SNMPVarbind(oid: vb.0, type: vb.1, value: vb.2))
        }

        return allVarbinds
    }

    private func sendV2cTrap(
        to dest: SNMPTrapDestination,
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) {
        let allVarbinds = buildV2NotificationVarbinds(
            notificationOID: notificationOID,
            additionalVarbinds: varbinds
        )

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.trapV2,
            requestID: nextRequestID(),
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v2c,
            community: dest.community,
            pduBytes: pduBytes
        )

        sendToDestination(messageBytes, dest: dest)
    }

    private func sendV2cInform(
        to dest: SNMPTrapDestination,
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) {
        let allVarbinds = buildV2NotificationVarbinds(
            notificationOID: notificationOID,
            additionalVarbinds: varbinds
        )

        let reqID = nextRequestID()

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.informRequest,
            requestID: reqID,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        let messageBytes = SNMPResponseBuilder.wrapMessage(
            version: SNMPVersion.v2c,
            community: dest.community,
            pduBytes: pduBytes
        )

        registerPendingInform(requestID: reqID, message: messageBytes, dest: dest)
        sendToDestination(messageBytes, dest: dest)
    }

    // MARK: - V3 Trap/Inform Encoding

    private func sendV3Trap(
        to dest: SNMPTrapDestination,
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) {
        guard let engine = v3Engine else { return }
        guard let user = engine.findUser(name: dest.userName) else { return }

        let allVarbinds = buildV2NotificationVarbinds(
            notificationOID: notificationOID,
            additionalVarbinds: varbinds
        )

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.trapV2,
            requestID: nextRequestID(),
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        guard let messageBytes = engine.processOutgoingMessage(
            msgID: nextMsgID(),
            msgFlags: dest.securityLevel,
            user: user,
            contextName: "",
            pduBytes: pduBytes
        ) else { return }

        sendToDestination(messageBytes, dest: dest)
    }

    private func sendV3Inform(
        to dest: SNMPTrapDestination,
        notificationOID: SNMPObjectID,
        varbinds: [(SNMPObjectID, UInt8, [UInt8])]
    ) {
        guard let engine = v3Engine else { return }
        guard let user = engine.findUser(name: dest.userName) else { return }

        let allVarbinds = buildV2NotificationVarbinds(
            notificationOID: notificationOID,
            additionalVarbinds: varbinds
        )

        let reqID = nextRequestID()

        let pduBytes = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.informRequest,
            requestID: reqID,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: allVarbinds
        )

        // For inform, set the reportable flag (bit 2)
        let flags = dest.securityLevel | 0x04

        guard let messageBytes = engine.processOutgoingMessage(
            msgID: nextMsgID(),
            msgFlags: flags,
            user: user,
            contextName: "",
            pduBytes: pduBytes
        ) else { return }

        registerPendingInform(requestID: reqID, message: messageBytes, dest: dest)
        sendToDestination(messageBytes, dest: dest)
    }

    // MARK: - Inform Request Management

    /// Tracking structure for pending inform requests.
    private struct PendingInform {
        let message: [UInt8]
        let destination: SNMPTrapDestination
        var retriesRemaining: Int
        let sentTime: TimeInterval
    }

    /// Handle an incoming response that might be an inform acknowledgment.
    /// Call this from the agent's message processing when a GetResponse is received
    /// that matches a pending inform.
    public func handleInformResponse(requestID: Int32) {
        lock.lock()
        let pending = pendingInforms.removeValue(forKey: requestID)
        lock.unlock()

        if pending != nil {
            informResponseHandler?(requestID, true)
        }
    }

    /// Check for timed-out inform requests and retry or give up.
    /// Should be called periodically (e.g., every second).
    public func processInformTimeouts() {
        let now = currentTime()

        lock.lock()
        var expiredIDs = [Int32]()
        var retryEntries = [(Int32, PendingInform)]()

        for (reqID, pending) in pendingInforms {
            if now - pending.sentTime > informTimeout {
                if pending.retriesRemaining > 0 {
                    var updated = pending
                    updated.retriesRemaining -= 1
                    retryEntries.append((reqID, updated))
                } else {
                    expiredIDs.append(reqID)
                }
            }
        }

        for id in expiredIDs {
            pendingInforms.removeValue(forKey: id)
        }
        for (id, updated) in retryEntries {
            let newPending = PendingInform(
                message: updated.message,
                destination: updated.destination,
                retriesRemaining: updated.retriesRemaining,
                sentTime: now
            )
            pendingInforms[id] = newPending
        }
        lock.unlock()

        // Send retries
        for (_, updated) in retryEntries {
            sendToDestination(updated.message, dest: updated.destination)
        }

        // Notify about expired informs
        for id in expiredIDs {
            informResponseHandler?(id, false)
        }
    }

    private func registerPendingInform(requestID: Int32, message: [UInt8], dest: SNMPTrapDestination) {
        lock.lock()
        pendingInforms[requestID] = PendingInform(
            message: message,
            destination: dest,
            retriesRemaining: informRetries,
            sentTime: currentTime()
        )
        lock.unlock()
    }

    // MARK: - Transport

    private func sendToDestination(_ data: [UInt8], dest: SNMPTrapDestination) {
        if let handler = sendHandler {
            if handler(data, dest.address, dest.port) == .ok {
                SNMPStatistics.shared.outTraps += 1
                SNMPStatistics.shared.outPkts += 1
            }
        }
    }

    private func nextRequestID() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        requestIDCounter &+= 1
        if requestIDCounter <= 0 { requestIDCounter = 1 }
        return requestIDCounter
    }

    private func nextMsgID() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        msgIDCounter &+= 1
        if msgIDCounter <= 0 { msgIDCounter = 1 }
        return msgIDCounter
    }

    private func currentTime() -> TimeInterval {
        var tv = timeval()
        gettimeofday(&tv, nil)
        return TimeInterval(tv.tv_sec) + TimeInterval(tv.tv_usec) / 1_000_000.0
    }
}

// MARK: - Enhanced Thread Synchronization

/// Operation types for thread-synchronized MIB access.
public enum SNMPSyncOperationType {
    case getInstance
    case getNextInstance
    case getValue
    case setTest
    case setValue
    case releaseInstance
}

/// Represents a pending synchronization operation.
public final class SNMPSyncOperation {
    /// The operation type.
    public let type: SNMPSyncOperationType
    /// The node instance being operated on.
    public let instance: SNMPNodeInstance
    /// The root OID for getInstance/getNextInstance calls.
    public var rootOID: [UInt32] = []
    /// Value buffer for getValue operations.
    public var valueBuffer: [UInt8] = []
    /// Value length for set operations.
    public var valueLength: UInt16 = 0
    /// Set value data.
    public var setValue: [UInt8] = []
    /// Result error code.
    public var resultError: SNMPError = .genErr
    /// Result value length (for getValue).
    public var resultValueLength: Int16 = -1
    /// Completion semaphore.
    public let semaphore = DispatchSemaphore(value: 0)

    public init(type: SNMPSyncOperationType, instance: SNMPNodeInstance) {
        self.type = type
        self.instance = instance
    }
}

/// Enhanced thread-safe MIB node wrapper with callback-based synchronization
/// to the lwIP core thread.
///
/// This node proxies all MIB access operations through a synchronization mechanism:
/// 1. The SNMP thread posts a callback to the lwIP core thread.
/// 2. The core thread executes the actual MIB access on the proxied node.
/// 3. The result is signaled back to the SNMP thread.
///
/// This ensures that MIB data accessed from lwIP core structures is accessed
/// safely, even when the SNMP agent runs in a separate thread.
public final class SNMPThreadSyncFullNode: SNMPLeafNode {

    /// The underlying MIB node whose access is being synchronized.
    public let proxiedNode: SNMPLeafNode

    /// Callback type for posting work to the lwIP core thread.
    /// The provided closure should be executed on the core thread,
    /// then the completion handler called when done.
    public typealias CoreCallbackPoster = (@escaping () -> Void) -> Void

    /// Function that posts a closure to the lwIP core thread for execution.
    /// The caller is responsible for setting this to an appropriate mechanism.
    public var coreCallbackPoster: CoreCallbackPoster?

    /// Maximum time to wait for a sync operation to complete (seconds).
    public var syncTimeout: TimeInterval = 10.0

    /// Tracks active sync operations for debugging/cancellation.
    private let activeLock = NSLock()
    private var activeOperations: [ObjectIdentifier: SNMPSyncOperation] = [:]

    public init(oid: UInt32, proxiedNode: SNMPLeafNode) {
        self.proxiedNode = proxiedNode
        super.init(type: .threadSync, oid: oid)
        setupSyncCallbacks()
    }

    /// Convenience initializer that uses a simple NSLock-based fallback
    /// when no core callback poster is configured.
    public convenience init(oid: UInt32, proxiedNode: SNMPLeafNode, lock: NSLock) {
        self.init(oid: oid, proxiedNode: proxiedNode)
        let syncLock = lock
        self.coreCallbackPoster = { work in
            syncLock.lock()
            work()
            syncLock.unlock()
        }
    }

    // MARK: - Sync Callback Setup

    private func setupSyncCallbacks() {
        let syncNode = self

        self.getInstance = { rootOID, instance in
            return syncNode.synchronizedGetInstance(rootOID: rootOID, instance: instance)
        }

        self.getNextInstance = { rootOID, instance in
            return syncNode.synchronizedGetNextInstance(rootOID: rootOID, instance: instance)
        }
    }

    // MARK: - Synchronized Operations

    /// Execute getInstance on the proxied node via core thread synchronization.
    private func synchronizedGetInstance(rootOID: [UInt32], instance: SNMPNodeInstance) -> SNMPError {
        let op = SNMPSyncOperation(type: .getInstance, instance: instance)
        op.rootOID = rootOID

        trackOperation(op)
        defer { untrackOperation(op) }

        guard let poster = coreCallbackPoster else {
            // Fallback: direct call (unsafe but functional)
            return proxiedNode.getInstance?(rootOID, instance) ?? .genErr
        }

        let proxied = self.proxiedNode

        poster {
            let err = proxied.getInstance?(op.rootOID, op.instance) ?? .genErr
            op.resultError = err

            // If getInstance succeeded, wrap the instance callbacks with sync proxies
            if err == .noError {
                self.wrapInstanceCallbacks(op.instance)
            }

            op.semaphore.signal()
        }

        let waitResult = op.semaphore.wait(timeout: .now() + syncTimeout)
        if waitResult == .timedOut {
            return .genErr
        }
        return op.resultError
    }

    /// Execute getNextInstance on the proxied node via core thread synchronization.
    private func synchronizedGetNextInstance(rootOID: [UInt32], instance: SNMPNodeInstance) -> SNMPError {
        let op = SNMPSyncOperation(type: .getNextInstance, instance: instance)
        op.rootOID = rootOID

        trackOperation(op)
        defer { untrackOperation(op) }

        guard let poster = coreCallbackPoster else {
            return proxiedNode.getNextInstance?(rootOID, instance) ?? .genErr
        }

        let proxied = self.proxiedNode

        poster {
            let err = proxied.getNextInstance?(op.rootOID, op.instance) ?? .genErr
            op.resultError = err

            if err == .noError {
                self.wrapInstanceCallbacks(op.instance)
            }

            op.semaphore.signal()
        }

        let waitResult = op.semaphore.wait(timeout: .now() + syncTimeout)
        if waitResult == .timedOut {
            return .genErr
        }
        return op.resultError
    }

    /// Wrap an instance's getValue/setTest/setValue/release callbacks with
    /// synchronized versions that post to the core thread.
    private func wrapInstanceCallbacks(_ instance: SNMPNodeInstance) {
        let originalGetValue = instance.getValue
        let originalSetTest = instance.setTest
        let originalSetValue = instance.setValue
        let originalRelease = instance.releaseInstance
        let syncNode = self

        if let origGet = originalGetValue {
            instance.getValue = { inst, buffer in
                return syncNode.synchronizedGetValue(instance: inst, buffer: &buffer, originalFn: origGet)
            }
        }

        if let origTest = originalSetTest {
            instance.setTest = { inst, len, value in
                return syncNode.synchronizedSetTest(instance: inst, len: len, value: value, originalFn: origTest)
            }
        }

        if let origSet = originalSetValue {
            instance.setValue = { inst, len, value in
                return syncNode.synchronizedSetValue(instance: inst, len: len, value: value, originalFn: origSet)
            }
        }

        if let origRelease = originalRelease {
            instance.releaseInstance = { inst in
                syncNode.synchronizedRelease(instance: inst, originalFn: origRelease)
            }
        }
    }

    /// Synchronized getValue: post to core thread, wait for result.
    private func synchronizedGetValue(
        instance: SNMPNodeInstance,
        buffer: inout [UInt8],
        originalFn: @escaping (SNMPNodeInstance, inout [UInt8]) -> Int16
    ) -> Int16 {
        guard let poster = coreCallbackPoster else {
            return originalFn(instance, &buffer)
        }

        let op = SNMPSyncOperation(type: .getValue, instance: instance)
        op.valueBuffer = [UInt8](repeating: 0, count: buffer.count)

        trackOperation(op)
        defer { untrackOperation(op) }

        poster {
            op.resultValueLength = originalFn(op.instance, &op.valueBuffer)
            op.semaphore.signal()
        }

        let waitResult = op.semaphore.wait(timeout: .now() + syncTimeout)
        if waitResult == .timedOut {
            return -1
        }

        // Copy result back
        if op.resultValueLength > 0 {
            for i in 0..<Int(op.resultValueLength) {
                buffer[i] = op.valueBuffer[i]
            }
        }
        return op.resultValueLength
    }

    /// Synchronized setTest: post to core thread, wait for result.
    private func synchronizedSetTest(
        instance: SNMPNodeInstance,
        len: UInt16,
        value: [UInt8],
        originalFn: @escaping (SNMPNodeInstance, UInt16, [UInt8]) -> SNMPError
    ) -> SNMPError {
        guard let poster = coreCallbackPoster else {
            return originalFn(instance, len, value)
        }

        let op = SNMPSyncOperation(type: .setTest, instance: instance)
        op.valueLength = len
        op.setValue = value

        trackOperation(op)
        defer { untrackOperation(op) }

        poster {
            op.resultError = originalFn(op.instance, op.valueLength, op.setValue)
            op.semaphore.signal()
        }

        let waitResult = op.semaphore.wait(timeout: .now() + syncTimeout)
        if waitResult == .timedOut {
            return .genErr
        }
        return op.resultError
    }

    /// Synchronized setValue: post to core thread, wait for result.
    private func synchronizedSetValue(
        instance: SNMPNodeInstance,
        len: UInt16,
        value: [UInt8],
        originalFn: @escaping (SNMPNodeInstance, UInt16, [UInt8]) -> SNMPError
    ) -> SNMPError {
        guard let poster = coreCallbackPoster else {
            return originalFn(instance, len, value)
        }

        let op = SNMPSyncOperation(type: .setValue, instance: instance)
        op.valueLength = len
        op.setValue = value

        trackOperation(op)
        defer { untrackOperation(op) }

        poster {
            op.resultError = originalFn(op.instance, op.valueLength, op.setValue)
            op.semaphore.signal()
        }

        let waitResult = op.semaphore.wait(timeout: .now() + syncTimeout)
        if waitResult == .timedOut {
            return .genErr
        }
        return op.resultError
    }

    /// Synchronized release: post to core thread, do not wait (fire and forget
    /// is acceptable for release, but we wait briefly to avoid resource leaks).
    private func synchronizedRelease(
        instance: SNMPNodeInstance,
        originalFn: @escaping (SNMPNodeInstance) -> Void
    ) {
        guard let poster = coreCallbackPoster else {
            originalFn(instance)
            return
        }

        let op = SNMPSyncOperation(type: .releaseInstance, instance: instance)

        poster {
            originalFn(op.instance)
            op.semaphore.signal()
        }

        // Wait briefly for release to complete to avoid dangling references
        _ = op.semaphore.wait(timeout: .now() + 2.0)
    }

    // MARK: - Operation Tracking

    private func trackOperation(_ op: SNMPSyncOperation) {
        let id = ObjectIdentifier(op)
        activeLock.lock()
        activeOperations[id] = op
        activeLock.unlock()
    }

    private func untrackOperation(_ op: SNMPSyncOperation) {
        let id = ObjectIdentifier(op)
        activeLock.lock()
        activeOperations.removeValue(forKey: id)
        activeLock.unlock()
    }

    /// Number of currently active synchronization operations.
    public var activeOperationCount: Int {
        activeLock.lock()
        defer { activeLock.unlock() }
        return activeOperations.count
    }

    /// Cancel all pending operations (signals their semaphores with error results).
    /// Use this during shutdown to unblock any waiting threads.
    public func cancelAllOperations() {
        activeLock.lock()
        let ops = Array(activeOperations.values)
        activeOperations.removeAll()
        activeLock.unlock()

        for op in ops {
            op.resultError = .genErr
            op.resultValueLength = -1
            op.semaphore.signal()
        }
    }
}

// MARK: - Scalar Array Node Callbacks

extension SNMPScalarArrayNode {
    /// Configure this scalar array node with standard getInstance and getNextInstance callbacks.
    /// Each entry maps to sub-OID <entry.subOID>.0 (scalar instance).
    public func setupScalarArrayCallbacks(
        getValue: @escaping (_ subOID: UInt32, _ instance: SNMPNodeInstance, _ buffer: inout [UInt8]) -> Int16,
        setTest: ((_ subOID: UInt32, _ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)? = nil,
        setValue: ((_ subOID: UInt32, _ instance: SNMPNodeInstance, _ len: UInt16, _ value: [UInt8]) -> SNMPError)? = nil
    ) {
        let node = self

        self.getInstance = { rootOID, instance in
            // Instance OID should be <subOID>.0
            let components = instance.instanceOID.components
            guard components.count == 2 else { return .noSuchInstance }
            let subOID = components[0]
            guard components[1] == 0 else { return .noSuchInstance }

            guard let entry = node.entries.first(where: { $0.subOID == subOID }) else {
                return .noSuchInstance
            }

            instance.asn1Type = entry.asn1Type
            instance.access = entry.access

            instance.getValue = { inst, buffer in
                return getValue(subOID, inst, &buffer)
            }

            if let setTestFn = setTest, (entry.access == .readWrite || entry.access == .writeOnly) {
                instance.setTest = { inst, len, value in
                    return setTestFn(subOID, inst, len, value)
                }
            }

            if let setValueFn = setValue, (entry.access == .readWrite || entry.access == .writeOnly) {
                instance.setValue = { inst, len, value in
                    return setValueFn(subOID, inst, len, value)
                }
            }

            return .noError
        }

        self.getNextInstance = { rootOID, instance in
            let components = instance.instanceOID.components
            let sortedEntries = node.entries.sorted { $0.subOID < $1.subOID }

            guard !sortedEntries.isEmpty else { return .noSuchInstance }

            // Determine starting point
            var targetSubOID: UInt32
            var needNext: Bool

            if components.isEmpty {
                // Start from the first entry
                targetSubOID = sortedEntries[0].subOID
                needNext = false
            } else if components.count == 1 {
                // Have sub-OID but no .0 yet; this sub-OID's .0 is the next
                targetSubOID = components[0]
                needNext = false
            } else {
                // components.count >= 2; we are at subOID.0, need the next subOID
                targetSubOID = components[0]
                needNext = true
            }

            var found: SNMPScalarArrayNode.Entry?
            for entry in sortedEntries {
                if needNext {
                    if entry.subOID > targetSubOID {
                        found = entry
                        break
                    }
                } else {
                    if entry.subOID >= targetSubOID {
                        found = entry
                        break
                    }
                }
            }

            guard let entry = found else { return .noSuchInstance }

            instance.instanceOID = SNMPObjectID([entry.subOID, 0])
            instance.asn1Type = entry.asn1Type
            instance.access = entry.access

            instance.getValue = { inst, buffer in
                return getValue(entry.subOID, inst, &buffer)
            }

            if let setTestFn = setTest, (entry.access == .readWrite || entry.access == .writeOnly) {
                instance.setTest = { inst, len, value in
                    return setTestFn(entry.subOID, inst, len, value)
                }
            }

            if let setValueFn = setValue, (entry.access == .readWrite || entry.access == .writeOnly) {
                instance.setValue = { inst, len, value in
                    return setValueFn(entry.subOID, inst, len, value)
                }
            }

            return .noError
        }
    }
}

// MARK: - SNMPv3 Discovery Helper

/// Helper for performing SNMPv3 engine discovery as a manager.
///
/// Sends a discovery message (empty engineID, no auth/priv) and parses the
/// report response to learn the remote engine's ID, boots, and time.
public final class SNMPv3DiscoveryHelper {

    /// Result of a discovery operation.
    public struct DiscoveryResult {
        public let engineID: [UInt8]
        public let engineBoots: UInt32
        public let engineTime: UInt32
    }

    /// Build a discovery request message.
    ///
    /// A discovery message is an SNMPv3 GET request with:
    /// - Empty authoritative engine ID
    /// - Zero boots/time
    /// - Empty user name
    /// - No auth/priv
    /// - Reportable flag set
    /// - Empty scoped PDU with empty varbind list
    public static func buildDiscoveryRequest(msgID: Int32 = 1) -> [UInt8] {
        let emptyPDU = SNMPResponseBuilder.buildPDU(
            pduType: SNMPPDUType.getRequest,
            requestID: 0,
            errorStatus: 0,
            errorIndex: 0,
            varbinds: []
        )

        let scopedPDU = SNMPResponseBuilder.buildScopedPDU(
            contextEngineID: [],
            contextName: "",
            pduBytes: emptyPDU
        )

        // msgFlags = 0x04 (reportable, noAuth, noPriv)
        let message = SNMPResponseBuilder.buildV3Message(
            msgID: msgID,
            msgMaxSize: 65507,
            msgFlags: 0x04,
            msgSecurityModel: SNMPv3Engine.usmSecurityModel,
            engineID: [],
            engineBoots: 0,
            engineTime: 0,
            userName: "",
            authParameters: [],
            privParameters: [],
            scopedPDUOrEncrypted: scopedPDU
        )

        return message
    }

    /// Parse a discovery response (report) to extract engine ID, boots, and time.
    ///
    /// - Parameter data: The raw response message bytes.
    /// - Returns: The discovered engine parameters, or nil if parsing fails.
    public static func parseDiscoveryResponse(_ data: [UInt8]) -> DiscoveryResult? {
        var pos = 0

        // Outer SEQUENCE
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (_, outerLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += outerLenBytes

        // Version
        guard let (version, versionConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += versionConsumed
        guard version == SNMPVersion.v3 else { return nil }

        // msgGlobalData (SEQUENCE) - skip
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (headerLen, headerLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += headerLenBytes + headerLen

        // msgSecurityParameters (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (_, secParamsLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += secParamsLenBytes

        // USM SEQUENCE
        guard pos < data.count, data[pos] == SNMPASN1.typeSequence else { return nil }
        pos += 1
        guard let (_, usmLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += usmLenBytes

        // engineID (OCTET STRING)
        guard pos < data.count, data[pos] == SNMPASN1.typeOctetString else { return nil }
        pos += 1
        guard let (eidLen, eidLenBytes) = SNMPASN1Decoder.decodeLength(from: data, at: pos) else { return nil }
        pos += eidLenBytes
        guard pos + eidLen <= data.count else { return nil }
        let engineID = Array(data[pos..<(pos + eidLen)])
        pos += eidLen

        // engineBoots (INTEGER)
        guard let (boots, bootsConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += bootsConsumed

        // engineTime (INTEGER)
        guard let (time, timeConsumed) = SNMPASN1Decoder.decodeInteger(from: data, at: pos) else { return nil }
        pos += timeConsumed

        return DiscoveryResult(
            engineID: engineID,
            engineBoots: UInt32(bitPattern: boots),
            engineTime: UInt32(bitPattern: time)
        )
    }
}

// MARK: - Agent Integration for Enhanced Features

extension SNMPAgent {

    /// Configure the agent with an enhanced trap sender that replaces the basic trapSender.
    /// The enhanced sender shares the same transport.
    public func configureEnhancedTraps() -> SNMPEnhancedTrapSender {
        let enhanced = SNMPEnhancedTrapSender()
        enhanced.v3Engine = v3Engine
        enhanced.agentAddress = trapSender.agentAddress
        enhanced.sendHandler = { [weak self] data, addr, port in
            self?.sendPacket(data, to: addr, port: port) ?? .notConnected
        }
        return enhanced
    }

    /// Set up the SNMPv3 engine with automatic engine ID generation and time management.
    /// Returns the time manager for periodic updates.
    public func setupV3(enterpriseNumber: UInt32, ipv4: IPv4Address? = nil, bootsFilePath: String? = nil) -> SNMPv3EngineTimeManager {
        v3Engine.generateEngineID(enterpriseNumber: enterpriseNumber, ipv4: ipv4)
        let timeMgr = SNMPv3EngineTimeManager(engine: v3Engine)
        timeMgr.bootsFilePath = bootsFilePath
        timeMgr.initialize()
        return timeMgr
    }

    /// Build the SNMPv3 framework and USM MIBs and add them to the agent's MIB list.
    public func addV3MIBs(timeManager: SNMPv3EngineTimeManager? = nil) {
        let frameworkMIB = SNMPv2FrameworkMIB(engine: v3Engine)
        frameworkMIB.timeManager = timeManager
        let usmMIB = SNMPv2USMMIB(stats: stats)
        mibs.append(frameworkMIB.buildMIB())
        mibs.append(usmMIB.buildMIB())
    }

    /// Create a thread-synchronized version of a leaf node using the enhanced sync wrapper.
    /// The returned node can be used in the MIB tree and will serialize access via the
    /// provided core callback poster.
    public func createSyncNode(
        oid: UInt32,
        proxiedNode: SNMPLeafNode,
        coreCallbackPoster: @escaping SNMPThreadSyncFullNode.CoreCallbackPoster
    ) -> SNMPThreadSyncFullNode {
        let syncNode = SNMPThreadSyncFullNode(oid: oid, proxiedNode: proxiedNode)
        syncNode.coreCallbackPoster = coreCallbackPoster
        return syncNode
    }
}
