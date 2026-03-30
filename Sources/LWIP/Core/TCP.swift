//
//  TCP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - TCP Protocol Constants

/// Namespace for TCP protocol constants.
public enum TCPConstants {
    /// TCP header length excluding options (20 bytes).
    public static let headerLength: UInt16 = 20

    /// Maximum TCP option bytes.
    public static let maxOptionBytes: UInt16 = 40

    // MARK: Write API flags

    /// Copy data into send buffer.
    public static let writeFlagCopy: UInt8 = 0x01
    /// More data to come (suppress PSH).
    public static let writeFlagMore: UInt8 = 0x02

    // MARK: Priority levels

    /// Minimum priority.
    public static let priorityMin: UInt8 = 1
    /// Normal priority.
    public static let priorityNormal: UInt8 = 64
    /// Maximum priority.
    public static let priorityMax: UInt8 = 127

    // MARK: Timer intervals (milliseconds)

    /// Base timer interval.
    public static let timerInterval: UInt32 = 250
    /// Fast timer interval.
    public static let fastInterval: UInt32 = timerInterval
    /// Slow timer interval.
    public static let slowInterval: UInt32 = 2 * timerInterval
    /// FIN_WAIT timeout.
    public static let finWaitTimeout: UInt32 = 20000
    /// SYN_RCVD timeout.
    public static let synReceivedTimeout: UInt32 = 20000
    /// Out-of-sequence timeout (in slow timer ticks).
    public static let outOfSequenceTimeout: UInt32 = 6
    /// Maximum Segment Lifetime.
    public static let maximumSegmentLifetime: UInt32 = 60000

    // MARK: Keepalive defaults (RFC 1122)

    /// Default keepalive idle time (ms).
    public static let keepaliveIdleDefault: UInt32 = 7_200_000
    /// Default keepalive interval (ms).
    public static let keepaliveIntervalDefault: UInt32 = 75_000
    /// Default keepalive probe count.
    public static let keepaliveCountDefault: UInt8 = 9

    // MARK: Local port range

    /// Start of ephemeral port range.
    public static let localPortRangeStart: UInt16 = 0xC000
    /// End of ephemeral port range.
    public static let localPortRangeEnd: UInt16 = 0xFFFF

    // MARK: Retransmission

    /// Default retransmission timeout (ms).
    public static let retransmissionTimeout: Int16 = 3000
    /// Initial Maximum Segment Size (capped at 536).
    public static let initialMaxSegmentSize: UInt16 = 536
    /// Maximum retransmissions.
    public static let maxRetransmissions: UInt8 = 12
    /// Maximum SYN retransmissions.
    public static let synMaxRetransmissions: UInt8 = 6
}

// MARK: - TCP Header Flags (Wire Format)

/// TCP header wire-format flags (OptionSet).
public struct TCPHeaderFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPHeaderFlags(rawValue: 0x01)
    public static let syn = TCPHeaderFlags(rawValue: 0x02)
    public static let rst = TCPHeaderFlags(rawValue: 0x04)
    public static let psh = TCPHeaderFlags(rawValue: 0x08)
    public static let ack = TCPHeaderFlags(rawValue: 0x10)
    public static let urg = TCPHeaderFlags(rawValue: 0x20)
    public static let ece = TCPHeaderFlags(rawValue: 0x40)
    public static let cwr = TCPHeaderFlags(rawValue: 0x80)

    /// Mask covering the 6 standard flags (FIN through URG).
    public static let standardMask = TCPHeaderFlags(rawValue: 0x3F)
}

// MARK: - TCP State

/// TCP finite state machine states.
public enum TCPState: UInt8, Sendable, CustomStringConvertible {
    case closed      = 0
    case listen       = 1
    case synSent     = 2
    case synRcvd     = 3
    case established = 4
    case finWait1    = 5
    case finWait2    = 6
    case closeWait   = 7
    case closing      = 8
    case lastAck     = 9
    case timeWait    = 10

    /// True if the connection is in a closing state (>= finWait1).
    @inlinable
    public var isClosing: Bool { rawValue >= TCPState.finWait1.rawValue }

    public var description: String {
        switch self {
        case .closed:      return "CLOSED"
        case .listen:       return "LISTEN"
        case .synSent:     return "SYN_SENT"
        case .synRcvd:     return "SYN_RCVD"
        case .established: return "ESTABLISHED"
        case .finWait1:    return "FIN_WAIT_1"
        case .finWait2:    return "FIN_WAIT_2"
        case .closeWait:   return "CLOSE_WAIT"
        case .closing:      return "CLOSING"
        case .lastAck:     return "LAST_ACK"
        case .timeWait:    return "TIME_WAIT"
        }
    }
}

// MARK: - TCP Flags (PCB flags, not wire flags)

/// Flags stored on a TCPControlBlock to control behavior.
public struct TCPFlags: OptionSet, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let ackDelay       = TCPFlags(rawValue: 0x0001)
    public static let ackNow         = TCPFlags(rawValue: 0x0002)
    public static let inFastRecovery = TCPFlags(rawValue: 0x0004)
    public static let closePending   = TCPFlags(rawValue: 0x0008)
    public static let rxClosed       = TCPFlags(rawValue: 0x0010)
    public static let fin            = TCPFlags(rawValue: 0x0020)
    public static let noDelay        = TCPFlags(rawValue: 0x0040)
    public static let nagleMemErr    = TCPFlags(rawValue: 0x0080)
    public static let wndScale       = TCPFlags(rawValue: 0x0100)
    public static let backlogPending = TCPFlags(rawValue: 0x0200)
    public static let timestamp      = TCPFlags(rawValue: 0x0400)
    public static let rto            = TCPFlags(rawValue: 0x0800)
    public static let sack           = TCPFlags(rawValue: 0x1000)

    public static let all: TCPFlags  = TCPFlags(rawValue: 0xFFFF)
}

// MARK: - TCP Segment Option Flags

/// Flags on tcp_seg controlling which options to include.
public struct TCPSegOptFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let mss           = TCPSegOptFlags(rawValue: 0x01)
    public static let timestamp     = TCPSegOptFlags(rawValue: 0x02)
    public static let dataChecksummed = TCPSegOptFlags(rawValue: 0x04)
    public static let wndScale      = TCPSegOptFlags(rawValue: 0x08)
    public static let sackPerm      = TCPSegOptFlags(rawValue: 0x10)
}

// MARK: - TCP Header

/// In-memory representation of a TCP header (20 bytes, packed).
public struct TCPHeader: Equatable, Hashable {
    public var sourcePort: UInt16 = 0
    public var destinationPort: UInt16 = 0
    public var sequenceNumber: UInt32 = 0
    public var acknowledgmentNumber: UInt32 = 0
    public var headerLengthReservedFlags: UInt16 = 0
    public var windowSize: UInt16 = 0
    public var checksum: UInt16 = 0
    public var urgentPointer: UInt16 = 0

    public init() {}

    @inlinable
    public var headerLength: UInt8 {
        UInt8((headerLengthReservedFlags >> 12) & 0x0F)
    }

    @inlinable
    public var headerLengthBytes: UInt8 {
        headerLength << 2
    }

    @inlinable
    public var flags: TCPHeaderFlags {
        TCPHeaderFlags(rawValue: UInt8(headerLengthReservedFlags & UInt16(TCPHeaderFlags.standardMask.rawValue)))
    }

    @inlinable
    public mutating func setHeaderLenAndFlags(len: UInt8, flags: TCPHeaderFlags) {
        headerLengthReservedFlags = UInt16(UInt16(len) << 12) | UInt16(flags.rawValue)
    }

    @inlinable
    public mutating func setFlags(_ f: TCPHeaderFlags) {
        headerLengthReservedFlags = (headerLengthReservedFlags & ~UInt16(TCPHeaderFlags.standardMask.rawValue)) | UInt16(f.rawValue)
    }

    @inlinable
    public mutating func addFlags(_ f: TCPHeaderFlags) {
        headerLengthReservedFlags |= UInt16(f.rawValue)
    }

    @inlinable
    public mutating func clearFlags(_ f: TCPHeaderFlags) {
        headerLengthReservedFlags &= ~UInt16(f.rawValue)
    }
}

// MARK: - TCP Option Constants

/// Namespace for TCP option kinds and lengths.
public enum TCPOptionConstants {
    /// End of options list.
    public static let endOfList: UInt8 = 0
    /// No-operation (padding).
    public static let noOperation: UInt8 = 1
    /// Maximum Segment Size option kind.
    public static let maxSegmentSize: UInt8 = 2
    /// Window Scale option kind.
    public static let windowScale: UInt8 = 3
    /// SACK Permitted option kind.
    public static let sackPermitted: UInt8 = 4
    /// Timestamps option kind.
    public static let timestamps: UInt8 = 8

    /// Length of MSS option.
    public static let maxSegmentSizeLength: UInt8 = 4
    /// Length of Timestamps option (on wire).
    public static let timestampsLength: UInt8 = 10
    /// Length of Timestamps option with padding (outgoing).
    public static let timestampsOutputLength: UInt8 = 12
    /// Length of Window Scale option.
    public static let windowScaleLength: UInt8 = 3
    /// Length of Window Scale option with padding (outgoing).
    public static let windowScaleOutputLength: UInt8 = 4
    /// Length of SACK Permitted option.
    public static let sackPermittedLength: UInt8 = 2
    /// Length of SACK Permitted option with padding (outgoing).
    public static let sackPermittedOutputLength: UInt8 = 4
}

extension TCPOptionConstants {
    /// Calculate total option length from segment option flags.
    @inlinable
    public static func optionLength(for flags: TCPSegOptFlags) -> UInt8 {
        var len: UInt8 = 0
        if flags.contains(.mss)       { len += maxSegmentSizeLength }
        if flags.contains(.timestamp) { len += timestampsOutputLength }
        if flags.contains(.wndScale)  { len += windowScaleOutputLength }
        if flags.contains(.sackPerm)  { len += sackPermittedOutputLength }
        return len
    }
}

// MARK: - TCP Sequence Number Arithmetic

/// Namespace for TCP sequence number comparisons with 32-bit wraparound.
public enum TCPSequence {
    /// Returns true if `a` < `b` accounting for 32-bit wraparound.
    @inlinable
    public static func isLessThan(_ a: UInt32, _ b: UInt32) -> Bool {
        (a &- b) & 0x8000_0000 != 0
    }

    /// Returns true if `a` <= `b` accounting for 32-bit wraparound.
    @inlinable
    public static func isLessThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        !isLessThan(b, a)
    }

    /// Returns true if `a` > `b` accounting for 32-bit wraparound.
    @inlinable
    public static func isGreaterThan(_ a: UInt32, _ b: UInt32) -> Bool {
        isLessThan(b, a)
    }

    /// Returns true if `a` >= `b` accounting for 32-bit wraparound.
    @inlinable
    public static func isGreaterThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        isLessThanOrEqual(b, a)
    }

    /// Returns true if `b` <= `a` <= `c` accounting for 32-bit wraparound.
    @inlinable
    public static func isBetween(_ a: UInt32, _ lower: UInt32, _ upper: UInt32) -> Bool {
        isGreaterThanOrEqual(a, lower) && isLessThanOrEqual(a, upper)
    }
}

// MARK: - SACK Range

/// SACK range to include in ACK packets. Invalid if left == right.
public struct TCPSACKRange: Sendable, Equatable, Hashable {
    public var left: UInt32 = 0
    public var right: UInt32 = 0

    public init() {}

    @inlinable
    public var isValid: Bool { left != right }
}

// MARK: - SACK Management

extension TCPControlBlock {
    /// Maximum number of SACK ranges tracked per connection.
    public static let maxSACKNum = 4

    /// Check if SACK at given index is valid (left != right).
    @inlinable
    public func sackIsValid(_ idx: Int) -> Bool {
        rcvSacks[idx].left != rcvSacks[idx].right
    }

    /// Add a new SACK range. Removes overlapping ranges, inserts at index 0.
    public func addSACK(_ left: UInt32, _ right: UInt32) {
        guard flags.contains(.sack), TCPSequence.isLessThan(left, right) else { return }

        // Phase 1: Remove SACKs that overlap with left:right, compact remaining.
        var unusedIdx = 0
        var i = 0
        while i < Self.maxSACKNum && sackIsValid(i) {
            // Keep only if non-overlapping
            if TCPSequence.isLessThanOrEqual(rcvSacks[i].right, left) ||
               TCPSequence.isLessThanOrEqual(right, rcvSacks[i].left) {
                if unusedIdx != i {
                    rcvSacks[unusedIdx] = rcvSacks[i]
                }
                unusedIdx += 1
            }
            i += 1
        }

        // Phase 2: Shift valid entries right by one to make room at index 0.
        i = Self.maxSACKNum - 1
        while i > 0 {
            if i - 1 >= unusedIdx {
                rcvSacks[i] = TCPSACKRange()
            } else {
                rcvSacks[i] = rcvSacks[i - 1]
            }
            i -= 1
        }

        // Phase 3: Store newest SACK at index 0.
        rcvSacks[0].left = left
        rcvSacks[0].right = right
    }

    /// Remove SACK entries that are fully before `seq`. Adjust left edges as needed.
    public func removeSACKsBefore(_ seq: UInt32) {
        var unusedIdx = 0
        var i = 0
        while i < Self.maxSACKNum && sackIsValid(i) {
            if TCPSequence.isGreaterThan(rcvSacks[i].right, seq) {
                if unusedIdx != i {
                    rcvSacks[unusedIdx] = rcvSacks[i]
                }
                if TCPSequence.isLessThan(rcvSacks[unusedIdx].left, seq) {
                    rcvSacks[unusedIdx].left = seq
                }
                unusedIdx += 1
            }
            i += 1
        }
        for j in unusedIdx..<Self.maxSACKNum {
            rcvSacks[j] = TCPSACKRange()
        }
    }

    /// Remove SACK entries that are fully after `seq`. Adjust right edges as needed.
    public func removeSACKsAfter(_ seq: UInt32) {
        var unusedIdx = 0
        var i = 0
        while i < Self.maxSACKNum && sackIsValid(i) {
            if TCPSequence.isLessThan(rcvSacks[i].left, seq) {
                if unusedIdx != i {
                    rcvSacks[unusedIdx] = rcvSacks[i]
                }
                if TCPSequence.isGreaterThan(rcvSacks[unusedIdx].right, seq) {
                    rcvSacks[unusedIdx].right = seq
                }
                unusedIdx += 1
            }
            i += 1
        }
        for j in unusedIdx..<Self.maxSACKNum {
            rcvSacks[j] = TCPSACKRange()
        }
    }
}

// MARK: - TCP Segment

/// Represents a TCP segment on the unsent, unacked, or ooseq queues.
public final class TCPSegment {
    public var next: TCPSegment?
    public var pbuf: Pbuf?
    public var len: UInt16 = 0
    public var optionFlags: TCPSegOptFlags = []
    public var headerFlags: TCPHeaderFlags = []

    // Header fields stored in host byte order after creation
    public var sequenceNumber: UInt32 = 0
    public var acknowledgmentNumber: UInt32 = 0
    public var windowSize: UInt16 = 0
    public var sourcePort: UInt16 = 0
    public var destinationPort: UInt16 = 0
    public var headerLengthWords: UInt8 = 5 // in 32-bit words

    // Checksum-on-copy support
    public var checksum: UInt16 = 0
    public var checksumSwapped: Bool = false

    public init() {}

    /// The TCP length of this segment (data + SYN/FIN flags each count as 1).
    @inlinable
    public var tcpLen: UInt16 {
        var l = len
        if !headerFlags.isDisjoint(with: [.fin, .syn]) {
            l &+= 1
        }
        return l
    }

    /// Create a copy of this segment (shallow: pbuf is ref-counted).
    public func copy() -> TCPSegment? {
        let seg = TCPSegment()
        seg.next = nil
        seg.len = len
        seg.optionFlags = optionFlags
        seg.headerFlags = headerFlags
        seg.sequenceNumber = sequenceNumber
        seg.acknowledgmentNumber = acknowledgmentNumber
        seg.windowSize = windowSize
        seg.sourcePort = sourcePort
        seg.destinationPort = destinationPort
        seg.headerLengthWords = headerLengthWords
        seg.checksum = checksum
        seg.checksumSwapped = checksumSwapped
        if let p = pbuf {
            seg.pbuf = p
            p.ref()
        }
        return seg
    }
}

// MARK: - Free segment chains

extension TCPSegment {
    /// Free a linked list of TCP segments.
    public static func freeChain(_ segment: TCPSegment?) {
        var current = segment
        while let s = current {
            let next = s.next
            s.free()
            current = next
        }
    }

    /// Free this single TCP segment, releasing its pbuf.
    public func free() {
        pbuf?.free()
        pbuf = nil
        next = nil
    }
}

// MARK: - TCP Listen PCB

/// Protocol control block for a listening TCP connection.
public final class TCPListenControlBlock {
    public var next: TCPListenControlBlock?
    public var callbackArg: AnyObject?
    public var state: TCPState = .listen
    public var priority: UInt8 = TCPConstants.priorityNormal
    public var localPort: UInt16 = 0
    public var localIP: IPAddress = .any
    public var netifIdx: UInt8 = 0
    public var ttl: UInt8 = 255
    public var tos: UInt8 = 0
    public var socketOptions: UInt8 = 0

    // Callback
    public var acceptHandler: ((TCPListenControlBlock, TCPControlBlock?, LWIPError) -> LWIPError)?

    // Backlog
    public var backlog: UInt8 = 0xFF
    public var acceptsPending: UInt8 = 0

    /// Extension argument slots for subsystem-specific data.
    public var extArgs: [TCPExtArg] = Array(repeating: TCPExtArg(), count: TCPExtArgManager.maxSlots)

    public init() {}
}

// MARK: - TCP PCB (main connection PCB)

/// The main TCP protocol control block for active connections.
public final class TCPControlBlock {
    // Linked list
    public var next: TCPControlBlock?

    // Callback arg
    public var callbackArg: AnyObject?

    // State
    public var state: TCPState = .closed
    public var priority: UInt8 = TCPConstants.priorityNormal

    // Ports (host byte order)
    public var localPort: UInt16 = 0
    public var remotePort: UInt16 = 0

    // IP addresses
    public var localIP: IPAddress = .any
    public var remoteIP: IPAddress = .any
    public var netifIdx: UInt8 = 0
    public var ttl: UInt8 = 255
    public var tos: UInt8 = 0
    public var socketOptions: UInt8 = 0

    // TCP PCB flags
    public var flags: TCPFlags = []

    // Timers
    public var pollTimer: UInt8 = 0
    public var pollInterval: UInt8 = 0
    public var lastTimer: UInt8 = 0
    public var timer: UInt32 = 0

    // Receiver variables
    public var receiveNext: UInt32 = 0
    public var receiveWindow: UInt32 = 0
    public var receiveAnnouncedWindow: UInt32 = 0
    public var receiveAnnouncedRightEdge: UInt32 = 0

    /// Received urgent pointer offset (0 = no urgent data pending).
    public var urgentPointerReceived: UInt16 = 0

    // SACK ranges
    public var rcvSacks: [TCPSACKRange] = Array(repeating: TCPSACKRange(), count: 4)

    // Retransmission timer
    public var retransmissionTime: Int16 = -1

    // Maximum segment size
    public var maxSegmentSize: UInt16 = TCPConstants.initialMaxSegmentSize

    // RTT estimation (Van Jacobson)
    public var roundTripTimeTest: UInt32 = 0
    public var roundTripTimeSequence: UInt32 = 0
    public var smoothedRoundTripTime: Int16 = 0
    public var roundTripTimeDeviation: Int16 = 0

    // Retransmission timeout
    public var retransmissionTimeout: Int16 = 6 // TCPConstants.retransmissionTimeout / TCPConstants.slowInterval
    public var retransmissionCount: UInt8 = 0

    // Fast retransmit / recovery
    public var duplicateAckCount: UInt8 = 0
    public var lastAcknowledged: UInt32 = 0

    // Congestion control
    public var congestionWindow: UInt32 = 1
    public var slowStartThreshold: UInt32 = 0
    public var acknowledgedBytes: UInt32 = 0

    // RTO end marker
    public var retransmissionTimeoutEnd: UInt32 = 0

    // Sender variables
    public var sendNext: UInt32 = 0
    public var sendWindowUpdateSequence: UInt32 = 0
    public var sendWindowUpdateAck: UInt32 = 0
    public var sendLastByteBuffered: UInt32 = 0
    public var sendWindow: UInt32 = 0
    public var sendWindowMax: UInt32 = 0
    public var sendBufferSpace: UInt32 = 0
    public var sendQueueLength: UInt16 = 0

    // Oversize tracking
    public var unsentOversize: UInt16 = 0

    // Segment queues
    public var unsent: TCPSegment?
    public var unacked: TCPSegment?
    public var ooseq: TCPSegment?

    // Refused data
    public var refusedData: Pbuf?

    // Listener reference
    public weak var listener: TCPListenControlBlock?

    // Callbacks
    public var sentHandler: ((TCPControlBlock, UInt16) -> LWIPError)?
    public var receiveHandler: ((TCPControlBlock, Pbuf?, LWIPError) -> LWIPError)?
    public var connectedHandler: ((TCPControlBlock, LWIPError) -> LWIPError)?
    public var pollHandler: ((TCPControlBlock) -> LWIPError)?
    public var errorHandler: ((LWIPError) -> Void)?

    // Timestamp option
    public var tsLastAckSent: UInt32 = 0
    public var tsRecent: UInt32 = 0

    // Keepalive
    public var keepaliveIdle: UInt32 = TCPConstants.keepaliveIdleDefault
    public var keepaliveInterval: UInt32 = TCPConstants.keepaliveIntervalDefault
    public var keepaliveCount: UInt8 = TCPConstants.keepaliveCountDefault

    // Persist timer
    public var persistCnt: UInt8 = 0
    public var persistBackoff: UInt8 = 0
    public var persistProbe: UInt8 = 0

    // Keepalive counter
    public var keepaliveCountSent: UInt8 = 0

    // Window scale
    public var sendScale: UInt8 = 0
    public var receiveScale: UInt8 = 0

    /// Extension argument slots for subsystem-specific data.
    public var extArgs: [TCPExtArg] = Array(repeating: TCPExtArg(), count: TCPExtArgManager.maxSlots)

    public init() {}

    // MARK: - Effective MSS

    /// MSS accounting for timestamp option overhead.
    @inlinable
    public var effectiveMSS: UInt16 {
        if flags.contains(.timestamp) {
            return maxSegmentSize > 12 ? maxSegmentSize - 12 : 0
        }
        return maxSegmentSize
    }

    /// Available send buffer, capped to UInt16 range.
    @inlinable
    public var sendBufferAvailable: UInt16 {
        UInt16(min(sendBufferSpace, UInt32(UInt16.max)))
    }

    // MARK: - Nagle algorithm

    /// Whether the Nagle algorithm allows sending now.
    @inlinable
    public var nagleCanSend: Bool {
        unacked == nil
            || flags.contains(.noDelay)
            || flags.contains(.inFastRecovery)
            || (unsent != nil && (unsent!.next != nil || unsent!.len >= maxSegmentSize))
            || sendBufferAvailable == 0
            || sendQueueLength >= UInt16(lwipConfig.tcpSndQueueLen)
    }

    // MARK: - Flag helpers

    @inlinable
    public func setFlags(_ f: TCPFlags) {
        flags.insert(f)
    }

    @inlinable
    public func clearFlags(_ f: TCPFlags) {
        flags.remove(f)
    }

    @inlinable
    public func hasFlag(_ f: TCPFlags) -> Bool {
        flags.contains(f)
    }

    // MARK: - Socket Option Convenience API

    /// Enable or disable TCP_NODELAY (Nagle algorithm control).
    ///
    /// When enabled, segments are sent as soon as possible without waiting
    /// to coalesce small writes.
    public func setNodelay(_ enabled: Bool) {
        if enabled {
            flags.insert(.noDelay)
        } else {
            flags.remove(.noDelay)
        }
    }

    /// Whether TCP_NODELAY is currently enabled.
    public var isNodelayEnabled: Bool {
        flags.contains(.noDelay)
    }

    /// Enable or disable TCP keepalive probing.
    ///
    /// When enabled, the connection sends keepalive probes after
    /// `keepaliveIdle` milliseconds of inactivity.
    public func setKeepalive(_ enabled: Bool) {
        if enabled {
            socketOptions |= SocketOptions.keepAlive.rawValue
        } else {
            socketOptions &= ~SocketOptions.keepAlive.rawValue
        }
    }

    /// Whether keepalive probing is currently enabled.
    public var isKeepaliveEnabled: Bool {
        (socketOptions & SocketOptions.keepAlive.rawValue) != 0
    }

    /// Configure keepalive timing parameters.
    ///
    /// - Parameters:
    ///   - idle: Time in milliseconds before the first keepalive probe is sent
    ///     (default 7200000 = 2 hours).
    ///   - interval: Time in milliseconds between keepalive probes
    ///     (default 75000 = 75 seconds).
    ///   - count: Maximum number of unanswered probes before the connection
    ///     is considered dead (default 9).
    public func configureKeepalive(idle: UInt32? = nil, interval: UInt32? = nil, count: UInt8? = nil) {
        if let idle = idle { keepaliveIdle = idle }
        if let interval = interval { keepaliveInterval = interval }
        if let count = count { keepaliveCount = count }
    }

    // MARK: - ACK helpers

    /// Mark a delayed ACK; if already delayed, upgrade to immediate.
    @inlinable
    public func acknowledge() {
        if flags.contains(.ackDelay) {
            flags.remove(.ackDelay)
            flags.insert(.ackNow)
        } else {
            flags.insert(.ackDelay)
        }
    }

    /// Mark that an ACK should be sent immediately.
    @inlinable
    public func acknowledgeNow() {
        flags.insert(.ackNow)
    }

    // MARK: - Receive window advertisement

    /// Notify the TCP stack that `length` bytes of received data have been
    /// consumed by the application, allowing the receive window to grow.
    ///
    /// Call this
    /// after your receive callback has processed data so that the remote
    /// peer is allowed to send more.
    ///
    /// - Parameter length: Number of bytes consumed.
    public func received(_ length: UInt16) {
        let len32 = UInt32(length)
        guard len32 <= receiveWindowMax &- receiveWindow else {
            Debug.assert("tcp received: length too large", false)
            return
        }
        receiveWindow &+= len32
        updateRcvAnnWnd()

        // Trigger an ACK to advertise the new window if the update is significant.
        let minUpdate = min(UInt32(lwipConfig.tcpWnd) / 2, UInt32(maxSegmentSize))
        if receiveWindow > receiveAnnouncedWindow && (receiveWindow &- receiveAnnouncedWindow) >= minUpdate {
            acknowledgeNow()
        }
    }

    // MARK: - Network interface binding

    /// Bind this TCP connection to a specific network interface.
    ///
    /// When bound, all packets for this connection will be sent via the
    /// specified interface, regardless of the routing table. Pass `nil`
    /// to unbind and restore normal routing.
    ///
    /// - Parameter netif: The network interface to bind to, or `nil` to unbind.
    public func bindNetif(_ netif: NetworkInterface?) {
        netifIdx = netif?.num ?? NetworkInterfaceConstants.noIndex
    }

    // MARK: - Receive window update

    /// Update the receivable window announcement.
    /// Returns how much extra window would be advertised if we sent an update now.
    @discardableResult
    public func updateRcvAnnWnd() -> UInt32 {
        let newRightEdge = receiveNext &+ receiveWindow
        let minUpdate = min(UInt32(lwipConfig.tcpWnd) / 2, UInt32(maxSegmentSize))

        if TCPSequence.isGreaterThanOrEqual(newRightEdge, receiveAnnouncedRightEdge &+ minUpdate) {
            receiveAnnouncedWindow = receiveWindow
            return newRightEdge &- receiveAnnouncedRightEdge
        } else {
            if TCPSequence.isGreaterThan(receiveNext, receiveAnnouncedRightEdge) {
                receiveAnnouncedWindow = 0
            } else {
                receiveAnnouncedWindow = receiveAnnouncedRightEdge &- receiveNext
            }
            return 0
        }
    }

    /// The maximum receive window for this PCB.
    @inlinable
    public var receiveWindowMax: UInt32 {
        if flags.contains(.wndScale) {
            return UInt32(lwipConfig.tcpWnd)
        }
        return min(UInt32(lwipConfig.tcpWnd), UInt32(UInt16.max))
    }
}

// MARK: - TCP Global State

/// Manages all TCP PCB lists and global state.
public final class TCPGlobal {
    public static let shared = TCPGlobal()

    /// Incremented every coarse grained timer shot (typically every 500 ms).
    public var ticks: UInt32 = 0

    /// Internal timer counter.
    public var timerCounter: UInt8 = 0

    /// Timer toggle for slow timer.
    public var timer: UInt8 = 0

    /// Active PCBs changed flag (for safe iteration).
    public var activePCBsChanged: Bool = false

    /// The PCB currently being processed by tcp_input.
    public var inputPCB: TCPControlBlock?

    // PCB lists
    public var boundPCBs: TCPControlBlock?
    public var listenPCBs: TCPListenControlBlock?
    public var activePCBs: TCPControlBlock?
    public var timeWaitPCBs: TCPControlBlock?

    // Local port counter
    public var localPort: UInt16 = TCPConstants.localPortRangeStart

    // Retransmission backoff tables
    public let backoff: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7]

    /// Persist timer backoff table (in slow-timer ticks, 500 ms each).
    ///
    /// When the remote advertises a zero window, the persist timer uses
    /// exponential backoff to schedule window probes:
    ///   3 ticks (1.5 s), 6 (3 s), 12 (6 s), 24 (12 s),
    ///   48 (24 s), 96 (48 s), 120 (60 s max).
    ///
    /// The timer is independent of the retransmission timer and is reset
    /// when the window opens (snd_wnd > 0).
    public let persistBackoff: [UInt8] = [3, 6, 12, 24, 48, 96, 120]

    // ISS state
    private var issCounter: UInt32 = 6510

    private init() {}

    // MARK: - Initialization

    /// Initialize the TCP module.
    public func initialize() {
        localPort = TCPConstants.localPortRangeStart
    }

    // MARK: - Port allocation

    /// Allocate a new ephemeral local TCP port.
    public func newPort() -> UInt16 {
        var attempts: UInt32 = 0
        let range = UInt32(TCPConstants.localPortRangeEnd) - UInt32(TCPConstants.localPortRangeStart)

        while true {
            localPort &+= 1
            if localPort == TCPConstants.localPortRangeEnd || localPort < TCPConstants.localPortRangeStart {
                localPort = TCPConstants.localPortRangeStart
            }

            var inUse = false

            // Check bound PCBs
            var pcb = boundPCBs
            while let p = pcb {
                if p.localPort == localPort { inUse = true; break }
                pcb = p.next
            }
            if !inUse {
                // Check listen PCBs
                var lpcb = listenPCBs
                while let l = lpcb {
                    if l.localPort == localPort { inUse = true; break }
                    lpcb = l.next
                }
            }
            if !inUse {
                var apcb = activePCBs
                while let a = apcb {
                    if a.localPort == localPort { inUse = true; break }
                    apcb = a.next
                }
            }
            if !inUse {
                var twpcb = timeWaitPCBs
                while let tw = twpcb {
                    if tw.localPort == localPort { inUse = true; break }
                    twpcb = tw.next
                }
            }

            if !inUse { return localPort }

            attempts += 1
            if attempts > range { return 0 }
        }
    }

    // MARK: - ISS generation

    /// Generate the next initial sequence number for a given connection.
    ///
    /// Delegates to `lwipHooks.generateTCPISN(...)` (RFC 6528 hook).
    /// The hook falls back to `UInt32.random` when no custom generator
    /// is installed.
    public func nextISS(pcb: TCPControlBlock) -> UInt32 {
        return lwipHooks.generateTCPISN(localIP: pcb.localIP, localPort: pcb.localPort,
                                        remoteIP: pcb.remoteIP, remotePort: pcb.remotePort)
    }

    /// Generate the next initial sequence number (legacy, no 4-tuple).
    ///
    /// Retained for call-sites that do not yet have a fully populated PCB.
    /// Uses the old counter-based approach; prefer `nextISS(pcb:)` where
    /// the connection 4-tuple is available.
    public func nextISS() -> UInt32 {
        issCounter &+= ticks
        return issCounter
    }

    // MARK: - PCB List Operations

    /// Register a PCB on a list.
    public func register(_ pcb: TCPControlBlock, list: inout TCPControlBlock?) {
        pcb.next = list
        list = pcb
    }

    /// Remove a PCB from a list.
    public func remove(_ pcb: TCPControlBlock, list: inout TCPControlBlock?) {
        if list === pcb {
            list = pcb.next
        } else {
            var prev = list
            while let p = prev {
                if p.next === pcb {
                    p.next = pcb.next
                    break
                }
                prev = p.next
            }
        }
        pcb.next = nil
    }

    /// Register a PCB on the active list.
    public func registerActive(_ pcb: TCPControlBlock) {
        register(pcb, list: &activePCBs)
        activePCBsChanged = true
    }

    /// Remove a PCB from the active list.
    public func removeActive(_ pcb: TCPControlBlock) {
        remove(pcb, list: &activePCBs)
        activePCBsChanged = true
    }

    /// Register a listen PCB.
    public func registerListen(_ pcb: TCPListenControlBlock) {
        pcb.next = listenPCBs
        listenPCBs = pcb
    }

    /// Remove a listen PCB.
    public func removeListen(_ pcb: TCPListenControlBlock) {
        if listenPCBs === pcb {
            listenPCBs = pcb.next
        } else {
            var prev = listenPCBs
            while let p = prev {
                if p.next === pcb {
                    p.next = pcb.next
                    break
                }
                prev = p.next
            }
        }
        pcb.next = nil
    }

    // MARK: - PCB allocation

    /// Allocate a new TCP PCB.
    public func alloc(priority: UInt8 = TCPConstants.priorityNormal) -> TCPControlBlock? {
        let pcb = TCPControlBlock()
        pcb.priority = priority
        pcb.sendBufferSpace = UInt32(lwipConfig.tcpSndBuf)
        pcb.receiveWindow = min(UInt32(lwipConfig.tcpWnd), UInt32(UInt16.max))
        pcb.receiveAnnouncedWindow = pcb.receiveWindow
        pcb.ttl = UInt8(lwipConfig.tcpTTL)
        pcb.maxSegmentSize = TCPConstants.initialMaxSegmentSize
        pcb.retransmissionTimeout = TCPConstants.retransmissionTimeout / Int16(TCPConstants.slowInterval)
        pcb.roundTripTimeDeviation = pcb.retransmissionTimeout
        pcb.retransmissionTime = -1
        pcb.congestionWindow = 1
        pcb.timer = ticks
        pcb.lastTimer = timerCounter
        pcb.slowStartThreshold = UInt32(lwipConfig.tcpSndBuf)
        pcb.keepaliveIdle = TCPConstants.keepaliveIdleDefault
        pcb.keepaliveInterval = TCPConstants.keepaliveIntervalDefault
        pcb.keepaliveCount = TCPConstants.keepaliveCountDefault

        // Set default recv callback behavior
        pcb.receiveHandler = { [weak pcb] _, pbuf, _ in
            guard let pcb = pcb else { return .invalidArgument }
            if let p = pbuf {
                TCPGlobal.shared.recved(pcb: pcb, len: p.totLen)
            }
            return .ok
        }

        return pcb
    }

    // MARK: - Public API

    /// Create a new TCP PCB.
    public func new() -> TCPControlBlock? {
        return alloc(priority: TCPConstants.priorityNormal)
    }

    /// Bind a PCB to a local address and port.
    public func bind(pcb: TCPControlBlock, address: IPAddress, port: UInt16) -> LWIPError {
        guard pcb.state == .closed else { return .invalidValue }

        var bindPort = port
        if bindPort == 0 {
            bindPort = newPort()
            if bindPort == 0 { return .bufferError }
        } else {
            // Check for port already in use
            var cpcb = boundPCBs
            while let c = cpcb {
                if c.localPort == bindPort {
                    if address == .any || c.localIP == .any || c.localIP == address {
                        return .addressInUse
                    }
                }
                cpcb = c.next
            }
            cpcb = activePCBs
            while let c = cpcb {
                if c.localPort == bindPort {
                    if address == .any || c.localIP == .any || c.localIP == address {
                        return .addressInUse
                    }
                }
                cpcb = c.next
            }
            var lpcb = listenPCBs
            while let l = lpcb {
                if l.localPort == bindPort {
                    if address == .any || l.localIP == .any || l.localIP == address {
                        return .addressInUse
                    }
                }
                lpcb = l.next
            }
        }

        if address != .any {
            pcb.localIP = address
        }
        pcb.localPort = bindPort
        register(pcb, list: &boundPCBs)
        return .ok
    }

    /// Set a PCB to listen state with a given backlog.
    public func listen(pcb: TCPControlBlock, backlog: UInt8 = 0xFF) -> TCPListenControlBlock? {
        guard pcb.state == .closed else { return nil }

        let lpcb = TCPListenControlBlock()
        lpcb.callbackArg = pcb.callbackArg
        lpcb.localPort = pcb.localPort
        lpcb.state = .listen
        lpcb.priority = pcb.priority
        lpcb.socketOptions = pcb.socketOptions
        lpcb.netifIdx = pcb.netifIdx
        lpcb.ttl = pcb.ttl
        lpcb.tos = pcb.tos
        lpcb.localIP = pcb.localIP
        lpcb.backlog = backlog == 0 ? 1 : backlog
        lpcb.acceptsPending = 0

        if pcb.localPort != 0 {
            remove(pcb, list: &boundPCBs)
        }

        registerListen(lpcb)
        return lpcb
    }

    /// Set the accept callback on a listen PCB.
    public func accept(lpcb: TCPListenControlBlock, callback: @escaping (TCPListenControlBlock, TCPControlBlock?, LWIPError) -> LWIPError) {
        lpcb.acceptHandler = callback
    }

    /// Initiate a TCP connection.
    public func connect(pcb: TCPControlBlock, address: IPAddress, port: UInt16,
                        connected: ((TCPControlBlock, LWIPError) -> LWIPError)?) -> LWIPError {
        guard pcb.state == .closed else { return .connectionEstablished }

        pcb.remoteIP = address
        pcb.remotePort = port

        if pcb.localPort == 0 {
            pcb.localPort = newPort()
            if pcb.localPort == 0 { return .bufferError }
        }

        let iss = nextISS(pcb: pcb)
        pcb.receiveNext = 0
        pcb.sendNext = iss
        pcb.lastAcknowledged = iss &- 1
        pcb.sendWindowUpdateAck = iss &- 1
        pcb.sendLastByteBuffered = iss &- 1
        pcb.receiveWindow = min(UInt32(lwipConfig.tcpWnd), UInt32(UInt16.max))
        pcb.receiveAnnouncedWindow = pcb.receiveWindow
        pcb.receiveAnnouncedRightEdge = pcb.receiveNext
        pcb.sendWindow = UInt32(lwipConfig.tcpWnd)
        pcb.maxSegmentSize = TCPConstants.initialMaxSegmentSize
        pcb.congestionWindow = 1
        pcb.connectedHandler = connected

        // Enqueue SYN
        let ret = TCPOutput.shared.enqueueFlags(pcb: pcb, flags: .syn)
        if ret == .ok {
            pcb.state = .synSent
            remove(pcb, list: &boundPCBs)
            registerActive(pcb)
            _ = TCPOutput.shared.output(pcb: pcb)
        }
        return ret
    }

    /// Write data to the send buffer.
    public func write(pcb: TCPControlBlock, data: UnsafeRawPointer, len: UInt16, apiFlags: UInt8 = TCPConstants.writeFlagCopy) -> LWIPError {
        return TCPOutput.shared.write(pcb: pcb, data: data, len: len, apiFlags: apiFlags)
    }

    /// Trigger output of queued data.
    public func output(pcb: TCPControlBlock) -> LWIPError {
        return TCPOutput.shared.output(pcb: pcb)
    }

    /// Inform TCP that data has been consumed by the application.
    public func recved(pcb: TCPControlBlock, len: UInt16) {
        let newWnd = pcb.receiveWindow &+ UInt32(len)
        if newWnd > pcb.receiveWindowMax || newWnd < pcb.receiveWindow {
            pcb.receiveWindow = pcb.receiveWindowMax
        } else {
            pcb.receiveWindow = newWnd
        }

        let wndInflation = pcb.updateRcvAnnWnd()
        let threshold = UInt32(lwipConfig.tcpWndUpdateThreshold)
        if wndInflation >= threshold {
            pcb.acknowledgeNow()
            _ = TCPOutput.shared.output(pcb: pcb)
        }
    }

    /// Close a TCP connection.
    public func close(pcb: TCPControlBlock) -> LWIPError {
        if pcb.state != .listen {
            pcb.flags.insert(.rxClosed)
        }
        return closeShutdown(pcb: pcb, rstOnUnacked: true)
    }

    /// Shutdown one or both sides of a connection.
    public func shutdown(pcb: TCPControlBlock, shutRx: Bool, shutTx: Bool) -> LWIPError {
        if pcb.state == .listen { return .notConnected }

        if shutRx {
            pcb.flags.insert(.rxClosed)
            if shutTx {
                return closeShutdown(pcb: pcb, rstOnUnacked: true)
            }
            pcb.refusedData = nil
        }

        if shutTx {
            switch pcb.state {
            case .synRcvd, .established, .closeWait:
                return closeShutdown(pcb: pcb, rstOnUnacked: shutRx)
            default:
                return .notConnected
            }
        }
        return .ok
    }

    /// Abort a connection, sending RST.
    public func abort(pcb: TCPControlBlock) {
        abandon(pcb: pcb, sendReset: true)
    }

    /// Set the poll callback and interval.
    public func poll(pcb: TCPControlBlock, callback: ((TCPControlBlock) -> LWIPError)?, interval: UInt8) {
        pcb.pollHandler = callback
        pcb.pollInterval = interval
    }

    /// Set connection priority.
    public func setPriority(pcb: TCPControlBlock, priority: UInt8) {
        pcb.priority = priority
    }

    // MARK: - Internal close/shutdown

    private func closeShutdown(pcb: TCPControlBlock, rstOnUnacked: Bool) -> LWIPError {
        if rstOnUnacked && (pcb.state == .established || pcb.state == .closeWait) {
            if pcb.refusedData != nil || pcb.receiveWindow != pcb.receiveWindowMax {
                // Not all data received, send RST
                pcbPurge(pcb)
                removeActive(pcb)
                return .ok
            }
        }

        switch pcb.state {
        case .closed:
            if pcb.localPort != 0 {
                remove(pcb, list: &boundPCBs)
            }
            return .ok
        case .listen:
            return .ok
        case .synSent:
            removeActive(pcb)
            return .ok
        default:
            return closeShutdownFin(pcb: pcb)
        }
    }

    private func closeShutdownFin(pcb: TCPControlBlock) -> LWIPError {
        var err: LWIPError

        switch pcb.state {
        case .synRcvd:
            err = TCPOutput.shared.sendFin(pcb: pcb)
            if err == .ok {
                pcb.state = .finWait1
            }
        case .established:
            err = TCPOutput.shared.sendFin(pcb: pcb)
            if err == .ok {
                pcb.state = .finWait1
            }
        case .closeWait:
            err = TCPOutput.shared.sendFin(pcb: pcb)
            if err == .ok {
                pcb.state = .lastAck
            }
        default:
            return .ok
        }

        if err == .ok {
            _ = TCPOutput.shared.output(pcb: pcb)
        } else if err == .outOfMemory {
            pcb.flags.insert(.closePending)
            return .ok
        }
        return err
    }

    // MARK: - Abandon

    /// Abandon a connection, optionally sending RST.
    public func abandon(pcb: TCPControlBlock, sendReset: Bool) {
        if pcb.state == .timeWait {
            pcbRemove(pcb, list: &timeWaitPCBs)
            return
        }

        let errCallback = pcb.errorHandler
        let errArg = pcb.callbackArg
        let lastState = pcb.state

        if pcb.state == .closed {
            if pcb.localPort != 0 {
                remove(pcb, list: &boundPCBs)
            }
        } else {
            removeActive(pcb)
        }

        // Free segment queues
        TCPSegment.freeChain(pcb.unacked)
        TCPSegment.freeChain(pcb.unsent)
        TCPSegment.freeChain(pcb.ooseq)
        pcb.unacked = nil
        pcb.unsent = nil
        pcb.ooseq = nil

        if sendReset && lastState != .closed {
            // RST would be sent here via TCPOutput
        }

        errCallback?(.aborted)
    }

    // MARK: - PCB purge

    /// Purge all buffered data from a PCB.
    public func pcbPurge(_ pcb: TCPControlBlock) {
        guard pcb.state != .closed && pcb.state != .timeWait && pcb.state != .listen else { return }

        pcb.refusedData = nil
        pcb.retransmissionTime = -1

        TCPSegment.freeChain(pcb.unsent)
        TCPSegment.freeChain(pcb.unacked)
        TCPSegment.freeChain(pcb.ooseq)
        pcb.unsent = nil
        pcb.unacked = nil
        pcb.ooseq = nil
        pcb.unsentOversize = 0
    }

    /// Remove from list, purge, and send delayed ACK.
    public func pcbRemove(_ pcb: TCPControlBlock, list: inout TCPControlBlock?) {
        remove(pcb, list: &list)
        pcbPurge(pcb)

        if pcb.state != .timeWait && pcb.state != .listen && pcb.flags.contains(.ackDelay) {
            pcb.acknowledgeNow()
            _ = TCPOutput.shared.output(pcb: pcb)
        }

        pcb.state = .closed
        pcb.localPort = 0
    }

    // MARK: - Free out-of-sequence queue

    /// Free the ooseq queue and reset SACK state.
    public func freeOoseq(_ pcb: TCPControlBlock) {
        TCPSegment.freeChain(pcb.ooseq)
        pcb.ooseq = nil
        pcb.rcvSacks = Array(repeating: TCPSACKRange(), count: pcb.rcvSacks.count)
    }

    // MARK: - Timer dispatch

    /// Called periodically (every TCPConstants.timerInterval ms) to dispatch TCP timers.
    public func tmr() {
        fastTmr()
        timer &+= 1
        if timer & 1 != 0 {
            slowTmr()
        }
    }

    // MARK: - Fast timer (250 ms)

    /// Process delayed ACKs, pending FINs, and refused data.
    public func fastTmr() {
        timerCounter &+= 1

        var pcb = activePCBs
        while let p = pcb {
            if p.lastTimer != timerCounter {
                p.lastTimer = timerCounter

                // Send delayed ACKs
                if p.flags.contains(.ackDelay) {
                    p.acknowledgeNow()
                    _ = TCPOutput.shared.output(pcb: p)
                    p.flags.remove(.ackDelay)
                    p.flags.remove(.ackNow)
                }

                // Send pending FIN
                if p.flags.contains(.closePending) {
                    p.flags.remove(.closePending)
                    _ = closeShutdownFin(pcb: p)
                }

                let next = p.next

                // Process refused data
                if p.refusedData != nil {
                    activePCBsChanged = false
                    _ = processRefusedData(pcb: p)
                    if activePCBsChanged {
                        // restart iteration
                        pcb = activePCBs
                        continue
                    }
                }
                pcb = next
            } else {
                pcb = p.next
            }
        }
    }

    // MARK: - Slow timer (500 ms)

    /// Handle retransmissions, keepalive, TIME-WAIT cleanup, polling.
    public func slowTmr() {
        ticks &+= 1
        timerCounter &+= 1

        var prev: TCPControlBlock? = nil
        var pcb = activePCBs

        while let p = pcb {
            if p.lastTimer == timerCounter {
                prev = p
                pcb = p.next
                continue
            }
            p.lastTimer = timerCounter

            var shouldRemove = false
            var shouldReset = false

            // Check retransmission limits
            if p.state == .synSent && p.retransmissionCount >= TCPConstants.synMaxRetransmissions {
                shouldRemove = true
            } else if p.retransmissionCount >= TCPConstants.maxRetransmissions {
                shouldRemove = true
            } else {
                if p.persistBackoff > 0 {
                    // Persist timer: independent of the retransmission timer.
                    // Handles the zero-window case where the remote advertised
                    // wnd=0.  We send 1-byte window probes with exponential
                    // backoff (RTO, 2*RTO, ... up to ~60 s via the backoff
                    // table) to discover when the window reopens.
                    //
                    // The persist timer only fires when:
                    //   - We are in a data-transfer state (ESTABLISHED / CLOSE_WAIT)
                    //   - The remote window is still zero
                    //   - There is unsent data queued
                    //
                    // If the window has reopened, reset persist state and let
                    // the normal output path take over.

                    if p.sendWindow > 0 {
                        // Window has opened -- stop persist timer and try to
                        // send queued data through the normal output path.
                        p.persistBackoff = 0
                        p.persistCnt = 0
                        if p.unsent != nil {
                            _ = TCPOutput.shared.output(pcb: p)
                        }
                    } else if p.persistProbe >= TCPConstants.maxRetransmissions {
                        // Too many probes without a response -- give up.
                        shouldRemove = true
                    } else if (p.state == .established || p.state == .closeWait) && p.unsent != nil {
                        // Window is still zero and we have data to send.
                        let backoffIdx = Int(p.persistBackoff &- 1)
                        let backoffCnt = persistBackoff[min(max(backoffIdx, 0), persistBackoff.count - 1)]
                        if p.persistCnt < backoffCnt {
                            p.persistCnt += 1
                        }
                        if p.persistCnt >= backoffCnt {
                            _ = TCPOutput.shared.zeroWindowProbe(pcb: p)
                            p.persistCnt = 0
                            // Exponential backoff: advance to the next entry
                            // in the backoff table (capped at the table size).
                            if p.persistBackoff < UInt8(persistBackoff.count) {
                                p.persistBackoff += 1
                            }
                        }
                    }
                } else {
                    // Retransmission timer
                    if p.retransmissionTime >= 0 && p.retransmissionTime < 0x7FFF {
                        p.retransmissionTime += 1
                    }

                    if p.retransmissionTime >= p.retransmissionTimeout {
                        // RTO fired
                        let prepOk = TCPOutput.shared.rexmitRtoPrepare(pcb: p) == .ok
                        if prepOk || (p.unacked == nil && p.unsent != nil) {
                            if p.state != .synSent {
                                let backoffIdx = min(Int(p.retransmissionCount), backoff.count - 1)
                                let calcRto = ((Int(p.smoothedRoundTripTime) >> 3) + Int(p.roundTripTimeDeviation)) << Int(backoff[backoffIdx])
                                // Clamp to [2, 120] ticks (1s .. 60s at 500ms slow timer)
                                p.retransmissionTimeout = Int16(max(2, min(calcRto, 120)))
                            }
                            p.retransmissionTime = 0

                            // Reduce congestion window
                            let effWnd = min(p.congestionWindow, p.sendWindow)
                            p.slowStartThreshold = effWnd >> 1
                            if p.slowStartThreshold < UInt32(p.maxSegmentSize) << 1 {
                                p.slowStartThreshold = UInt32(p.maxSegmentSize) << 1
                            }
                            p.congestionWindow = UInt32(p.maxSegmentSize)
                            p.acknowledgedBytes = 0

                            if prepOk {
                                TCPOutput.shared.rexmitRtoCommit(pcb: p)
                            }
                        }
                    }
                }
            }

            // FIN_WAIT_2 timeout
            if p.state == .finWait2 && p.flags.contains(.rxClosed) {
                if (ticks &- p.timer) > TCPConstants.finWaitTimeout / TCPConstants.slowInterval {
                    shouldRemove = true
                }
            }

            // Keepalive
            if (p.socketOptions & SocketOptions.keepAlive.rawValue) != 0 && (p.state == .established || p.state == .closeWait) {
                let keepDur = UInt32(p.keepaliveCount) * p.keepaliveInterval
                if (ticks &- p.timer) > (p.keepaliveIdle + keepDur) / TCPConstants.slowInterval {
                    shouldRemove = true
                    shouldReset = true
                } else if (ticks &- p.timer) > (p.keepaliveIdle + UInt32(p.keepaliveCountSent) * p.keepaliveInterval) / TCPConstants.slowInterval {
                    let err = TCPOutput.shared.keepalive(pcb: p)
                    if err == .ok && p.keepaliveCountSent < 0xFF {
                        p.keepaliveCountSent += 1
                    }
                }
            }

            // OOSEQ timeout
            if p.ooseq != nil && (ticks &- p.timer) >= UInt32(p.retransmissionTimeout) * TCPConstants.outOfSequenceTimeout {
                freeOoseq(p)
            }

            // SYN_RCVD timeout
            if p.state == .synRcvd {
                if (ticks &- p.timer) > TCPConstants.synReceivedTimeout / TCPConstants.slowInterval {
                    shouldRemove = true
                }
            }

            // LAST_ACK timeout
            if p.state == .lastAck {
                if (ticks &- p.timer) > 2 * TCPConstants.maximumSegmentLifetime / TCPConstants.slowInterval {
                    shouldRemove = true
                }
            }

            if shouldRemove {
                let errCallback = p.errorHandler
                let errArg = p.callbackArg
                let lastState = p.state

                pcbPurge(p)

                // Remove from active list inline
                if let pr = prev {
                    pr.next = p.next
                } else {
                    activePCBs = p.next
                }

                if shouldReset {
                    // RST would be sent here
                }

                pcb = p.next
                activePCBsChanged = false
                errCallback?(.aborted)
                if activePCBsChanged {
                    prev = nil
                    pcb = activePCBs
                    continue
                }
            } else {
                prev = p
                pcb = p.next

                // Poll
                if let pr = prev {
                    pr.pollTimer &+= 1
                    if pr.pollTimer >= pr.pollInterval {
                        pr.pollTimer = 0
                        activePCBsChanged = false
                        let err = pr.pollHandler?(pr) ?? .ok
                        if activePCBsChanged {
                            prev = nil
                            pcb = activePCBs
                            continue
                        }
                        if err == .ok {
                            _ = TCPOutput.shared.output(pcb: pr)
                        }
                    }
                }
            }
        }

        // TIME-WAIT PCB cleanup
        prev = nil
        pcb = timeWaitPCBs
        while let p = pcb {
            if (ticks &- p.timer) > 2 * TCPConstants.maximumSegmentLifetime / TCPConstants.slowInterval {
                pcbPurge(p)
                if let pr = prev {
                    pr.next = p.next
                } else {
                    timeWaitPCBs = p.next
                }
                pcb = p.next
            } else {
                prev = p
                pcb = p.next
            }
        }
    }

    // MARK: - Process refused data

    /// Pass refused data to the recv callback.
    public func processRefusedData(pcb: TCPControlBlock) -> LWIPError {
        while pcb.refusedData != nil {
            let refusedData = pcb.refusedData!
            pcb.refusedData = nil

            let err = pcb.receiveHandler?(pcb, refusedData, .ok) ?? .ok

            if err == .ok {
                // Data accepted
                continue
            } else if err == .aborted {
                return .aborted
            } else {
                // Still refused
                pcb.refusedData = refusedData
                return .inProgress
            }
        }
        return .ok
    }

    /// Iterate all active PCBs that have nagle memory error and try to output.
    public func txNow() {
        var pcb = activePCBs
        while let p = pcb {
            if p.flags.contains(.nagleMemErr) {
                _ = TCPOutput.shared.output(pcb: p)
            }
            pcb = p.next
        }
    }

    // MARK: - Backlog Management

    /// Mark a connection as pending acceptance in the listener backlog.
    ///
    /// Called when a SYN is received on a listening socket but `accept()` has
    /// not been called yet. Increments the listener's `acceptsPending` counter
    /// and sets `TCPFlags.backlogPending`.
    public func backlogDelayed(pcb: TCPControlBlock) {
        guard !pcb.flags.contains(.backlogPending) else { return }
        guard let listener = pcb.listener else { return }
        listener.acceptsPending &+= 1
        pcb.flags.insert(.backlogPending)
    }

    /// Mark a backlogged connection as accepted by the application.
    ///
    /// Decrements the listener's `acceptsPending` counter and clears
    /// `TCPFlags.backlogPending`. Must be called when a backlogged connection
    /// is accepted or closed to keep backlog accounting in sync.
    public func backlogAccepted(pcb: TCPControlBlock) {
        guard pcb.flags.contains(.backlogPending) else { return }
        guard let listener = pcb.listener else { return }
        if listener.acceptsPending > 0 {
            listener.acceptsPending -= 1
        }
        pcb.flags.remove(.backlogPending)
    }

    // MARK: - Resource Exhaustion Handlers

    /// Kill the oldest TIME-WAIT PCB to free resources.
    ///
    /// Called during PCB allocation when memory is exhausted.
    /// TIME-WAIT connections are safe to kill as the connection is already closed.
    public func killTimewait() {
        var pcb = timeWaitPCBs
        var inactive: TCPControlBlock?
        var inactivity: UInt32 = 0

        while let p = pcb {
            let age = ticks &- p.timer
            if age >= inactivity {
                inactivity = age
                inactive = p
            }
            pcb = p.next
        }

        if let victim = inactive {
            abort(pcb: victim)
        }
    }

    /// Kill the oldest PCB in a specific closing state (CLOSING or LAST_ACK).
    ///
    /// Called during PCB allocation when memory is exhausted. These connections
    /// are already shutting down, so no data is lost. Abandons without sending
    /// RST.
    public func killState(_ state: TCPState) {
        var pcb = activePCBs
        var inactive: TCPControlBlock?
        var inactivity: UInt32 = 0

        while let p = pcb {
            if p.state == state {
                let age = ticks &- p.timer
                if age >= inactivity {
                    inactivity = age
                    inactive = p
                }
            }
            pcb = p.next
        }

        if let victim = inactive {
            abandon(pcb: victim, sendReset: false)
        }
    }

    /// Kill the oldest connection with priority lower than the given value.
    ///
    /// Called during PCB allocation when memory is exhausted and both
    /// TIME-WAIT and closing-state kills have not freed enough resources.
    /// Among connections with the lowest priority, kills the most inactive.
    public func killPrio(_ prio: UInt8) {
        var mprio = min(TCPConstants.priorityMax, prio)
        guard mprio > 0 else { return }
        mprio -= 1

        var pcb = activePCBs
        var inactive: TCPControlBlock?
        var inactivity: UInt32 = 0

        while let p = pcb {
            if p.priority < mprio ||
               (p.priority == mprio && (ticks &- p.timer) >= inactivity) {
                inactivity = ticks &- p.timer
                inactive = p
                mprio = p.priority
            }
            pcb = p.next
        }

        if let victim = inactive {
            abort(pcb: victim)
        }
    }

    /// Process PCBs with pending close (FIN not yet sent due to memory).
    ///
    /// Called after freeing a TIME-WAIT PCB to retry sending FIN on
    /// connections that previously failed.
    public func handleClosePending() {
        var pcb = activePCBs
        while let p = pcb {
            let next = p.next
            if p.flags.contains(.closePending) {
                p.flags.remove(.closePending)
                _ = close(pcb: p)
            }
            pcb = next
        }
    }

    // MARK: - IP Address Change Handling

    /// Abort all TCP connections bound to an old IP address.
    ///
    /// Called when a network interface's IP address changes. Active and bound
    /// connections using the old address are aborted. Listening sockets are
    /// updated to use the new address when one exists.
    public func netifIPAddrChanged(oldAddr: IPAddress, newAddr: IPAddress?) {
        guard !oldAddr.isAnyAddress else { return }

        ipAddrChangedActivePCBList(oldAddr: oldAddr)
        ipAddrChangedBoundList(oldAddr: oldAddr)

        if let newAddr, !newAddr.isAnyAddress {
            var lpcb = listenPCBs
            while let l = lpcb {
                if l.localIP == oldAddr {
                    l.localIP = newAddr
                }
                lpcb = l.next
            }
        }
    }

    /// Abort all connections in the active PCB list that are bound to oldAddr.
    private func ipAddrChangedActivePCBList(oldAddr: IPAddress) {
        var pcb = activePCBs
        while let p = pcb {
            let next = p.next
            if p.localIP == oldAddr {
                abort(pcb: p)
            }
            pcb = next
        }
    }

    /// Abort all connections in the bound PCB list that are bound to oldAddr.
    private func ipAddrChangedBoundList(oldAddr: IPAddress) {
        var pcb = boundPCBs
        while let p = pcb {
            let next = p.next
            if p.localIP == oldAddr {
                abandon(pcb: p, sendReset: false)
            }
            pcb = next
        }
    }
}

// MARK: - TCP Extended Arguments

/// Callback interface for TCP PCB extension arguments.
///
/// Allows subsystems (e.g., TLS) to attach private data to PCBs and
/// receive lifecycle notifications.
public protocol TCPExtArgCallbacks: AnyObject {
    /// Called when a PCB is being destroyed, allowing cleanup of private data.
    func destroy(id: UInt8, data: AnyObject?)
    /// Called when a passive open creates a new PCB from a listener.
    /// Return `.ok` to allow the connection, or an error to reject it.
    func passiveOpen(id: UInt8, listener: TCPListenControlBlock, newPCB: TCPControlBlock) -> LWIPError
}

/// Default implementations for optional callbacks.
public extension TCPExtArgCallbacks {
    func destroy(id: UInt8, data: AnyObject?) {}
    func passiveOpen(id: UInt8, listener: TCPListenControlBlock, newPCB: TCPControlBlock) -> LWIPError { .ok }
}

/// Storage for one extension argument slot on a PCB.
public struct TCPExtArg {
    /// Registered callbacks for this slot.
    public var callbacks: TCPExtArgCallbacks?
    /// Private data stored by the extension.
    public var data: AnyObject?

    public init() {
        self.callbacks = nil
        self.data = nil
    }
}

/// Manager for TCP extension argument IDs.
///
/// Extension argument IDs are allocated globally (one per subsystem) and used
/// to index into per-PCB storage arrays.
public enum TCPExtArgManager {
    /// Maximum number of extension argument slots per PCB.
    public static let maxSlots: Int = 4

    /// Next available ID.
    private static var nextID: UInt8 = 0

    /// Allocate a unique extension argument ID.
    ///
    /// Must be called during initialization. The returned ID is used with
    /// `setCallbacks()` and for accessing `extArgs` on PCBs.
    public static func allocID() -> UInt8 {
        let id = nextID
        nextID += 1
        precondition(Int(nextID) <= maxSlots, "Exceeded TCPExtArgManager.maxSlots")
        return id
    }

    /// Register callbacks for an extension argument on a specific PCB.
    public static func setCallbacks(pcb: TCPControlBlock, id: UInt8, callbacks: TCPExtArgCallbacks) {
        guard Int(id) < pcb.extArgs.count else { return }
        pcb.extArgs[Int(id)].callbacks = callbacks
    }

    /// Store extension-specific data on a PCB.
    public static func setData(pcb: TCPControlBlock, id: UInt8, data: AnyObject?) {
        guard Int(id) < pcb.extArgs.count else { return }
        pcb.extArgs[Int(id)].data = data
    }

    /// Retrieve extension-specific data from a PCB.
    public static func getData(pcb: TCPControlBlock, id: UInt8) -> AnyObject? {
        guard Int(id) < pcb.extArgs.count else { return nil }
        return pcb.extArgs[Int(id)].data
    }

    /// Register callbacks for an extension argument on a listen PCB.
    public static func setCallbacks(listenPcb: TCPListenControlBlock, id: UInt8, callbacks: TCPExtArgCallbacks) {
        guard Int(id) < listenPcb.extArgs.count else { return }
        listenPcb.extArgs[Int(id)].callbacks = callbacks
    }

    /// Store extension-specific data on a listen PCB.
    public static func setData(listenPcb: TCPListenControlBlock, id: UInt8, data: AnyObject?) {
        guard Int(id) < listenPcb.extArgs.count else { return }
        listenPcb.extArgs[Int(id)].data = data
    }

    /// Retrieve extension-specific data from a listen PCB.
    public static func getData(listenPcb: TCPListenControlBlock, id: UInt8) -> AnyObject? {
        guard Int(id) < listenPcb.extArgs.count else { return nil }
        return listenPcb.extArgs[Int(id)].data
    }

    /// Invoke destroy callbacks for all registered extension arguments.
    ///
    /// Called when a PCB is being freed. Each registered extension gets
    /// a chance to clean up its private data.
    public static func invokeCallbacksDestroyed(extArgs: inout [TCPExtArg]) {
        for i in 0..<extArgs.count {
            if let cb = extArgs[i].callbacks {
                cb.destroy(id: UInt8(i), data: extArgs[i].data)
                extArgs[i].data = nil
            }
        }
    }

    /// Invoke passive-open callbacks for a new connection from a listener.
    ///
    /// Returns `.ok` if all callbacks approve the connection. If any
    /// callback returns an error, that error is propagated and the
    /// connection should be rejected.
    public static func invokeCallbacksPassiveOpen(
        listener: TCPListenControlBlock,
        newPCB: TCPControlBlock
    ) -> LWIPError {
        for i in 0..<listener.extArgs.count {
            if let cb = listener.extArgs[i].callbacks {
                let err = cb.passiveOpen(id: UInt8(i), listener: listener, newPCB: newPCB)
                if err != .ok { return err }
            }
        }
        return .ok
    }
}

