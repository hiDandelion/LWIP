//
//  EthARP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for ARP protocol constants.
public enum ARPConstants {
    /// Timer interval in milliseconds (1 second).
    public static let timerInterval: Int = 1000
    /// Table entry maximum age in seconds.
    public static let maximumAge: UInt16 = 300
    /// Maximum pending time before expiring (in seconds).
    public static let maximumPending: UInt16 = 5
    /// Re-request threshold for unicast (seconds before expiry).
    public static let reRequestUnicastAge: UInt16 = 270
    /// Re-request threshold for broadcast (seconds before expiry).
    public static let reRequestBroadcastAge: UInt16 = 285
    /// Size of the ARP header in bytes.
    public static let headerSize: Int = 28
}

/// Namespace for Ethernet constants.
public enum EthernetConstants {
    /// Hardware address length (6 bytes for Ethernet).
    public static let hardwareAddressLength: Int = 6
    /// IANA hardware type for Ethernet.
    public static let ianaHardwareType: UInt16 = 1
    /// Ethernet type for IPv4.
    public static let etherTypeIPv4: UInt16 = 0x0800
    /// Ethernet type for ARP.
    public static let etherTypeARP: UInt16 = 0x0806
}

// MARK: - Ethernet Address

extension EthAddr {
    /// True if this is a group (multicast/broadcast) address.
    @inlinable
    public var isGroup: Bool { (addr.0 & 1) != 0 }
}

// MARK: - ARP Opcode

/// ARP operation codes.
public enum ARPOpcode: UInt16, Sendable {
    case request = 1
    case reply   = 2
}

// MARK: - ARP Header

/// ARP packet header (28 bytes for Ethernet/IPv4).
public struct ARPHeader {
    public var hardwareType: UInt16
    public var proto: UInt16
    public var hardwareLength: UInt8
    public var protoLen: UInt8
    public var opcode: UInt16
    public var senderHWAddr: EthAddr
    public var senderIPAddr: IPv4Address
    public var targetHWAddr: EthAddr
    public var targetIPAddr: IPv4Address

    public init() {
        hardwareType = 0
        proto = 0
        hardwareLength = 0
        protoLen = 0
        opcode = 0
        senderHWAddr = .zero
        senderIPAddr = .any
        targetHWAddr = .zero
        targetIPAddr = .any
    }
}

// MARK: - ARP Entry State

/// ARP table entry states.
public enum ARPEntryState: UInt8, Sendable {
    case empty = 0
    case pending = 1
    case stable = 2
    case stableReRequesting1 = 3
    case stableReRequesting2 = 4
    case staticEntry = 5
}

// MARK: - ARP Queue Entry

/// A single node in the per-entry ARP packet queue (linked list).
/// Used when `lwipConfig.arpQueueing` is `true` so that multiple
/// packets can be queued while an ARP resolution is pending.
public final class ARPQueueEntry {
    /// Next queued entry.
    public var next: ARPQueueEntry?
    /// The packet waiting to be sent.
    public var packet: Pbuf

    public init(packet: Pbuf) {
        self.next = nil
        self.packet = packet
    }
}

// MARK: - ARP Entry

/// A single entry in the ARP table.
public final class ARPEntry {
    /// Queue of pending outgoing packets (linked list, when arpQueueing is enabled).
    /// When arpQueueing is disabled, at most one packet is stored via `singleQueue`.
    public var queue: ARPQueueEntry?

    /// Fallback single-packet queue when `arpQueueing` is disabled.
    public var singleQueue: Pbuf?

    /// The IP address for this entry.
    public var ipAddr: IPv4Address
    /// The associated network interface.
    public var netif: NetworkInterface?
    /// The resolved Ethernet address.
    public var ethAddr: EthAddr
    /// Age counter (in seconds).
    public var ageCounter: UInt16
    /// Entry state.
    public var state: ARPEntryState

    /// True when this entry has any queued packets (regardless of queueing mode).
    public var hasQueue: Bool {
        if lwipConfig.arpQueueing {
            return queue != nil
        } else {
            return singleQueue != nil
        }
    }

    public init() {
        queue = nil
        singleQueue = nil
        ipAddr = .any
        netif = nil
        ethAddr = .zero
        ageCounter = 0
        state = .empty
    }
}

// MARK: - ARP Table

/// ARP protocol implementation with table management.
public enum EthARP {

    /// The ARP table.
    public internal(set) static var table: [ARPEntry] = {
        var t = [ARPEntry]()
        t.reserveCapacity(lwipConfig.arpTableSize)
        for _ in 0..<lwipConfig.arpTableSize {
            t.append(ARPEntry())
        }
        return t
    }()

    /// Cached entry index for fast lookups.
    public internal(set) static var cachedEntry: Int = 0

    /// Initialize or reset the ARP table.
    public static func initialize() {
        table = (0..<lwipConfig.arpTableSize).map { _ in ARPEntry() }
        cachedEntry = 0
    }

    // MARK: - Free Queue

    /// Free a complete queue of `ARPQueueEntry` nodes.
    private static func freeQueue(_ q: ARPQueueEntry?) {
        var current = q
        while let entry = current {
            current = entry.next
            entry.packet.free()
            entry.next = nil
        }
    }

    // MARK: - Free Entry

    /// Free an ARP table entry and its queued packets.
    private static func freeEntry(_ i: Int) {
        if lwipConfig.arpQueueing {
            if table[i].queue != nil {
                freeQueue(table[i].queue)
                table[i].queue = nil
            }
        } else {
            if let q = table[i].singleQueue {
                q.free()
                table[i].singleQueue = nil
            }
        }
        table[i].state = .empty
        table[i].ageCounter = 0
        table[i].netif = nil
        table[i].ipAddr = .any
        table[i].ethAddr = .zero
    }

    // MARK: - Timer

    /// ARP timer. Call every ARP_TMR_INTERVAL (1 second).
    /// Expires old entries and re-requests addresses nearing expiry.
    public static func timer() {
        let tableSize = lwipConfig.arpTableSize
        for i in 0..<tableSize {
            let state = table[i].state
            guard state != .empty && state != .staticEntry else { continue }

            table[i].ageCounter += 1

            if table[i].ageCounter >= UInt16(lwipConfig.arpMaxAge) ||
               (state == .pending && table[i].ageCounter >= ARPConstants.maximumPending) {
                freeEntry(i)
            } else if state == .stableReRequesting1 {
                table[i].state = .stableReRequesting2
            } else if state == .stableReRequesting2 {
                table[i].state = .stable
            } else if state == .pending {
                // Resend ARP query
                if let netif = table[i].netif {
                    let _ = request(netif: netif, ipAddr: table[i].ipAddr)
                }
            }
        }
    }

    // MARK: - Find Entry

    /// Search the ARP table for a matching or new entry.
    ///
    /// - Parameters:
    ///   - ipAddr: IP address to look for (nil = any empty entry).
    ///   - tryHard: Whether to recycle old entries if no empty found.
    ///   - findOnly: Only search, don't create.
    ///   - netif: Associated network interface.
    /// - Returns: Table index, or -1 on failure.
    private static func findEntry(ipAddr: IPv4Address?, tryHard: Bool,
                                   findOnly: Bool, netif: NetworkInterface?) -> Int {
        let tableSize = lwipConfig.arpTableSize
        var oldPending = tableSize
        var oldStable = tableSize
        var oldQueue = tableSize
        var empty = tableSize
        var agePending: UInt16 = 0
        var ageStable: UInt16 = 0
        var ageQueue: UInt16 = 0

        for i in 0..<tableSize {
            let state = table[i].state
            if state == .empty && empty == tableSize {
                empty = i
            } else if state != .empty {
                if let ip = ipAddr, ip == table[i].ipAddr {
                    return i
                }

                if state == .pending {
                    if table[i].hasQueue {
                        if table[i].ageCounter >= ageQueue {
                            oldQueue = i
                            ageQueue = table[i].ageCounter
                        }
                    } else {
                        if table[i].ageCounter >= agePending {
                            oldPending = i
                            agePending = table[i].ageCounter
                        }
                    }
                } else if state.rawValue >= ARPEntryState.stable.rawValue && state != .staticEntry {
                    if table[i].ageCounter >= ageStable {
                        oldStable = i
                        ageStable = table[i].ageCounter
                    }
                }
            }
        }

        // No match found
        if findOnly || (empty == tableSize && !tryHard) {
            return -1
        }

        // Select entry to use
        let i: Int
        if empty < tableSize {
            i = empty
        } else if oldStable < tableSize {
            i = oldStable
            freeEntry(i)
        } else if oldPending < tableSize {
            i = oldPending
            freeEntry(i)
        } else if oldQueue < tableSize {
            i = oldQueue
            freeEntry(i)
        } else {
            return -1
        }

        if let ip = ipAddr {
            table[i].ipAddr = ip
        }
        table[i].ageCounter = 0
        return i
    }

    // MARK: - Update Entry

    /// Update or insert an IP/MAC pair in the ARP cache.
    @discardableResult
    private static func updateEntry(netif: NetworkInterface, ipAddr: IPv4Address,
                                     ethAddr: EthAddr, tryHard: Bool,
                                     isStatic: Bool = false) -> LWIPError {
        // Don't cache non-unicast addresses
        guard !ipAddr.isAny && !ipAddr.isBroadcast(on: netif) && !ipAddr.isMulticast else {
            return .invalidArgument
        }

        let i = findEntry(ipAddr: ipAddr, tryHard: tryHard, findOnly: !tryHard, netif: netif)
        guard i >= 0 else { return .outOfMemory }

        if isStatic {
            table[i].state = .staticEntry
        } else if table[i].state == .staticEntry {
            return .invalidValue
        } else {
            table[i].state = .stable
        }

        table[i].netif = netif
        table[i].ethAddr = ethAddr
        table[i].ageCounter = 0

        // Send queued packets
        if lwipConfig.arpQueueing {
            // Walk the linked list, send each packet, free the queue entry
            while let qEntry = table[i].queue {
                let p = qEntry.packet
                table[i].queue = qEntry.next
                qEntry.next = nil
                _ = Ethernet.output(netif, p, dst: ethAddr, ethType: .ipv4)
                p.free()
            }
        } else {
            if let p = table[i].singleQueue {
                table[i].singleQueue = nil
                _ = Ethernet.output(netif, p, dst: ethAddr, ethType: .ipv4)
                p.free()
            }
        }

        return .ok
    }

    // MARK: - Cleanup

    /// Remove all ARP entries for the given network interface.
    public static func cleanupNetif(_ netif: NetworkInterface) {
        let tableSize = lwipConfig.arpTableSize
        for i in 0..<tableSize {
            if table[i].state != .empty && table[i].netif === netif {
                freeEntry(i)
            }
        }
    }

    // MARK: - Find Address

    /// Look up a stable ARP entry by IP address.
    ///
    /// - Returns: The Ethernet address and IP address pair, or nil if not found.
    public static func findAddr(netif: NetworkInterface, ipAddr: IPv4Address) -> (ethAddr: EthAddr, ipAddr: IPv4Address)? {
        let i = findEntry(ipAddr: ipAddr, tryHard: false, findOnly: true, netif: netif)
        guard i >= 0 && table[i].state.rawValue >= ARPEntryState.stable.rawValue else {
            return nil
        }
        return (table[i].ethAddr, table[i].ipAddr)
    }

    /// Iterate over stable ARP table entries.
    public static func getEntry(index: Int) -> (ipAddr: IPv4Address, netif: NetworkInterface, ethAddr: EthAddr)? {
        guard index < lwipConfig.arpTableSize,
              table[index].state.rawValue >= ARPEntryState.stable.rawValue,
              let netif = table[index].netif else {
            return nil
        }
        return (table[index].ipAddr, netif, table[index].ethAddr)
    }

    // MARK: - Input

    /// Process an incoming ARP packet.
    ///
    /// - Parameters:
    ///   - p: The ARP packet.
    ///   - netif: The receiving network interface.
    public static func input(_ p: Pbuf, netif: NetworkInterface) {
        guard p.len >= UInt16(ARPConstants.headerSize) else {
            p.free()
            return
        }

        let hdr = p.readARPHeader()

        // Validate: Ethernet, IPv4
        guard hdr.hardwareType == EthernetConstants.ianaHardwareType.bigEndian,
              hdr.hardwareLength == UInt8(EthernetConstants.hardwareAddressLength),
              hdr.protoLen == 4,
              hdr.proto == EthernetConstants.etherTypeIPv4.bigEndian else {
            p.free()
            return
        }

        // ACD processing
        if lwipConfig.acd {
            ACD.arpReply(netif: netif, hdr: hdr)
        }

        let sipAddr = hdr.senderIPAddr
        let dipAddr = hdr.targetIPAddr

        let forUs: Bool
        let fromUs: Bool

        if netif.ipAddr.isAny {
            forUs = false
            fromUs = false
        } else {
            forUs = dipAddr == netif.ipAddr
            fromUs = sipAddr == netif.ipAddr
        }

        // Update ARP cache from sender info
        updateEntry(netif: netif, ipAddr: sipAddr, ethAddr: hdr.senderHWAddr,
                    tryHard: forUs)

        // Process based on opcode
        let opcode = hdr.opcode.bigEndian
        switch opcode {
        case ARPOpcode.request.rawValue:
            if forUs && !fromUs {
                // Send ARP reply
                let _ = sendRaw(netif: netif,
                                ethSrc: netif.hwAddrAsEth, ethDst: hdr.senderHWAddr,
                                hwSrc: netif.hwAddrAsEth, ipSrc: netif.ipAddr,
                                hwDst: hdr.senderHWAddr, ipDst: sipAddr,
                                opcode: .reply)
            }

        case ARPOpcode.reply.rawValue:
            // Already updated cache above
            break

        default:
            break
        }

        p.free()
    }

    // MARK: - Output

    /// Resolve and send an IP packet via Ethernet with ARP resolution.
    ///
    /// For broadcast/multicast destinations, sends directly. For unicast,
    /// looks up the ARP cache or queues the packet while an ARP request is made.
    ///
    /// - Parameters:
    ///   - netif: The output network interface.
    ///   - q: The IP packet to send.
    ///   - ipAddr: The destination IP address.
    /// - Returns: `.ok` on success, `.routingError` if no route, `.outOfMemory` if allocation fails.
    public static func output(netif: NetworkInterface, q: Pbuf, ipAddr: IPv4Address) -> LWIPError {
        // Broadcast?
        if ipAddr.isBroadcast(on: netif) {
            return Ethernet.output(netif, q, dst: .broadcast, ethType: .ipv4)
        }

        // Multicast?
        if ipAddr.isMulticast {
            let mcastAddr = EthAddr(
                0x01, 0x00, 0x5E,
                ipAddr.octet2 & 0x7F,
                ipAddr.octet3,
                ipAddr.octet4
            )
            return Ethernet.output(netif, q, dst: mcastAddr, ethType: .ipv4)
        }

        // Unicast - determine actual destination (might be gateway)
        var dstAddr = ipAddr
        if !ipAddr.isOnNetwork(as: netif.ipAddr, mask: netif.netmask) && !ipAddr.isLinkLocal {
            guard !netif.gateway.isAny else { return .routingError }
            dstAddr = netif.gateway
        }

        // Fast path: check cached entry
        let tableSize = lwipConfig.arpTableSize
        if cachedEntry < tableSize &&
           table[cachedEntry].state.rawValue >= ARPEntryState.stable.rawValue &&
           table[cachedEntry].ipAddr == dstAddr {
            return outputToIndex(netif: netif, q: q, idx: cachedEntry)
        }

        // Search table for stable entry
        for i in 0..<tableSize {
            if table[i].state.rawValue >= ARPEntryState.stable.rawValue &&
               table[i].ipAddr == dstAddr {
                cachedEntry = i
                return outputToIndex(netif: netif, q: q, idx: i)
            }
        }

        // No stable entry found: query (will queue the packet)
        return query(netif: netif, ipAddr: dstAddr, q: q)
    }

    /// Send a queued packet via the ARP table entry at the given index.
    ///
    /// Checks whether the entry is about to expire and, if so, proactively
    /// re-requests the mapping (unicast first, then broadcast) to avoid
    /// interrupting active connections.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - q:     The packet to send.
    ///   - idx:   Index into the ARP table (must point to a stable entry).
    /// - Returns: The result of `Ethernet.output()`.
    @discardableResult
    public static func outputToARPIndex(netif: NetworkInterface, q: Pbuf, idx: Int) -> LWIPError {
        return outputToIndex(netif: netif, q: q, idx: idx)
    }

    /// Send a packet to a known ARP table entry (internal implementation).
    private static func outputToIndex(netif: NetworkInterface, q: Pbuf, idx: Int) -> LWIPError {
        // Check if entry needs re-requesting
        if table[idx].state == .stable {
            if table[idx].ageCounter >= ARPConstants.reRequestBroadcastAge {
                if request(netif: netif, ipAddr: table[idx].ipAddr) == .ok {
                    table[idx].state = .stableReRequesting1
                }
            } else if table[idx].ageCounter >= ARPConstants.reRequestUnicastAge {
                if requestDst(netif: netif, ipAddr: table[idx].ipAddr, hwDst: table[idx].ethAddr) == .ok {
                    table[idx].state = .stableReRequesting1
                }
            }
        }

        return Ethernet.output(netif, q, dst: table[idx].ethAddr, ethType: .ipv4)
    }

    // MARK: - Query

    /// Send an ARP request and/or queue a packet for resolution.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - ipAddr: The IP address to resolve.
    ///   - q: Optional packet to queue (or send if already resolved).
    /// - Returns: `.ok` on success.
    public static func query(netif: NetworkInterface, ipAddr: IPv4Address, q: Pbuf?) -> LWIPError {
        guard !ipAddr.isAny && !ipAddr.isBroadcast(on: netif) && !ipAddr.isMulticast else {
            return .invalidArgument
        }

        let i = findEntry(ipAddr: ipAddr, tryHard: true, findOnly: false, netif: netif)
        guard i >= 0 else { return .outOfMemory }

        var isNewEntry = false
        if table[i].state == .empty {
            isNewEntry = true
            table[i].state = .pending
            table[i].netif = netif
        }

        // Send ARP request if new or explicit query
        if isNewEntry || q == nil {
            let result = request(netif: netif, ipAddr: ipAddr)
            if result == .ok && table[i].state == .pending && !isNewEntry {
                table[i].ageCounter = 0
            }
            if q == nil {
                return result
            }
        }

        guard let packet = q else { return .ok }

        // Stable entry? Send immediately
        if table[i].state.rawValue >= ARPEntryState.stable.rawValue {
            cachedEntry = i
            return Ethernet.output(netif, packet, dst: table[i].ethAddr, ethType: .ipv4)
        }

        // Pending: queue the packet
        if table[i].state == .pending {
            // Check if the packet needs to be copied (volatile/ref pbufs)
            let p: Pbuf?
            var copyNeeded = false
            var check: Pbuf? = packet
            while let c = check {
                if c.type.needsCopy {
                    copyNeeded = true
                    break
                }
                check = c.next
            }

            if copyNeeded {
                p = Pbuf.clone(layer: .link, type: .ram, source: packet)
            } else {
                packet.ref()
                p = packet
            }

            guard let queuedPbuf = p else {
                return .outOfMemory
            }

            if lwipConfig.arpQueueing {
                // Linked-list queue: append new entry at the tail,
                // enforce maximum queue length by dropping the oldest entry.
                let newEntry = ARPQueueEntry(packet: queuedPbuf)
                if let head = table[i].queue {
                    var tail = head
                    var qLen: Int = 1
                    while let next = tail.next {
                        tail = next
                        qLen += 1
                    }
                    tail.next = newEntry

                    // Enforce maximum queue length
                    let maxQueueLen = lwipConfig.arpQueueLen
                    if maxQueueLen > 0 && qLen >= maxQueueLen {
                        // Drop the oldest (head) entry
                        let old = table[i].queue!
                        table[i].queue = old.next
                        old.next = nil
                        old.packet.free()
                    }
                } else {
                    table[i].queue = newEntry
                }
            } else {
                // Single-packet queue: replace the existing queued packet.
                if let existing = table[i].singleQueue {
                    existing.free()
                }
                table[i].singleQueue = queuedPbuf
            }
            return .ok
        }

        return .outOfMemory
    }

    // MARK: - Raw ARP Send

    /// Send a raw ARP packet (opcode and all addresses can be modified).
    ///
    /// This is the low-level ARP packet constructor. It allocates a pbuf,
    /// fills in the ARP header fields, and sends the frame via
    /// `Ethernet.output()`.
    ///
    /// - Parameters:
    ///   - netif:  The network interface to send on.
    ///   - ethSrc: Source MAC address for the Ethernet header.
    ///   - ethDst: Destination MAC address for the Ethernet header.
    ///   - hwSrc:  Source MAC address for the ARP protocol header.
    ///   - ipSrc:  Source IP address for the ARP protocol header.
    ///   - hwDst:  Destination MAC address for the ARP protocol header.
    ///   - ipDst:  Destination IP address for the ARP protocol header.
    ///   - opcode: ARP operation (.request or .reply).
    /// - Returns: `.ok` on success, `.outOfMemory` if pbuf allocation fails.
    @discardableResult
    public static func sendRaw(netif: NetworkInterface,
                                ethSrc: EthAddr, ethDst: EthAddr,
                                hwSrc: EthAddr, ipSrc: IPv4Address,
                                hwDst: EthAddr, ipDst: IPv4Address,
                                opcode: ARPOpcode) -> LWIPError {
        guard let p = Pbuf.alloc(layer: .link, length: UInt16(ARPConstants.headerSize), type: .ram) else {
            return .outOfMemory
        }

        var hdr = ARPHeader()
        hdr.opcode = opcode.rawValue.bigEndian
        hdr.senderHWAddr = hwSrc
        hdr.senderIPAddr = ipSrc
        hdr.targetHWAddr = hwDst
        hdr.targetIPAddr = ipDst
        hdr.hardwareType = EthernetConstants.ianaHardwareType.bigEndian
        hdr.proto = EthernetConstants.etherTypeIPv4.bigEndian
        hdr.hardwareLength = UInt8(EthernetConstants.hardwareAddressLength)
        hdr.protoLen = 4
        p.writeARPHeader(hdr)

        // For link-local source addresses, callers provide a broadcast Ethernet
        // destination per RFC 3927. ethernetOutput adds the ARP EtherType header.
        _ = Ethernet.output(netif, p, src: ethSrc, dst: ethDst, ethType: .arp)

        p.free()
        return .ok
    }

    /// Send an ARP request to a specific hardware destination.
    ///
    /// Used for unicast ARP requests to refresh entries before they expire,
    /// as well as for gratuitous ARP (destination = own address).
    ///
    /// - Parameters:
    ///   - netif:  The network interface to send on.
    ///   - ipAddr: The IP address to resolve.
    ///   - hwDst:  The Ethernet destination for the ARP frame.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func requestDst(netif: NetworkInterface, ipAddr: IPv4Address,
                                   hwDst: EthAddr) -> LWIPError {
        return sendRaw(netif: netif,
                       ethSrc: netif.hwAddrAsEth, ethDst: hwDst,
                       hwSrc: netif.hwAddrAsEth, ipSrc: netif.ipAddr,
                       hwDst: .zero, ipDst: ipAddr,
                       opcode: .request)
    }

    // MARK: - Public Request

    /// Send a broadcast ARP request for the given IP address.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - ipAddr: The IP address to resolve.
    /// - Returns: `.ok` on success.
    @discardableResult
    public static func request(netif: NetworkInterface, ipAddr: IPv4Address) -> LWIPError {
        return requestDst(netif: netif, ipAddr: ipAddr, hwDst: .broadcast)
    }

    /// Send a gratuitous ARP for the interface's own IP address.
    ///
    /// A gratuitous ARP is an ARP packet sent by a node to spontaneously
    /// cause other nodes to update an entry in their ARP cache.
    /// (See RFC 3220 "IP Mobility Support for IPv4", section 4.6.)
    @discardableResult
    public static func gratuitous(netif: NetworkInterface) -> LWIPError {
        return request(netif: netif, ipAddr: netif.ipAddr)
    }

    // MARK: - ACD Support

    /// Send an ARP probe for address conflict detection.
    public static func acdProbe(netif: NetworkInterface, ipAddr: IPv4Address) -> LWIPError {
        return sendRaw(netif: netif,
                       ethSrc: netif.hwAddrAsEth, ethDst: .broadcast,
                       hwSrc: netif.hwAddrAsEth, ipSrc: .any,
                       hwDst: .zero, ipDst: ipAddr,
                       opcode: .request)
    }

    /// Send an ARP announce for address conflict detection.
    public static func acdAnnounce(netif: NetworkInterface, ipAddr: IPv4Address) -> LWIPError {
        return sendRaw(netif: netif,
                       ethSrc: netif.hwAddrAsEth, ethDst: .broadcast,
                       hwSrc: netif.hwAddrAsEth, ipSrc: ipAddr,
                       hwDst: .zero, ipDst: ipAddr,
                       opcode: .request)
    }

    // MARK: - Static Entry Management

    /// Add a static entry to the ARP table.
    public static func addStaticEntry(ipAddr: IPv4Address, ethAddr: EthAddr) -> LWIPError {
        guard let netif = IPv4.route(dest: ipAddr) else { return .routingError }
        return updateEntry(netif: netif, ipAddr: ipAddr, ethAddr: ethAddr,
                           tryHard: true, isStatic: true)
    }

    /// Remove a static entry from the ARP table.
    public static func removeStaticEntry(ipAddr: IPv4Address) -> LWIPError {
        let i = findEntry(ipAddr: ipAddr, tryHard: false, findOnly: true, netif: nil)
        guard i >= 0 else { return .outOfMemory }
        guard table[i].state == .staticEntry else { return .invalidArgument }
        freeEntry(i)
        return .ok
    }
}
