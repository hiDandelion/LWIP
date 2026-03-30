//
//  ND6.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - Constants

/// Namespace for Neighbor Discovery constants.
public enum ND6Constants {
    /// Timer interval in milliseconds (1 second).
    public static let timerInterval: UInt32 = 1000
    /// Router solicitation interval in milliseconds.
    public static let routerSolicitationInterval: UInt32 = 4000
    /// Maximum hop limit required for all ND packets.
    public static let maximumHopLimit: UInt8 = 255
    /// Two hours in seconds.
    public static let twoHoursInSeconds: UInt32 = 7200
}

// MARK: - ND6 Send Flags

/// Flags for controlling ND6 message destination.
public struct ND6SendFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let multicastDest = ND6SendFlags(rawValue: 0x01)
    public static let allNodesDest  = ND6SendFlags(rawValue: 0x02)
    public static let anySrc        = ND6SendFlags(rawValue: 0x04)
    /// NA solicited flag (used when constructing NA messages).
    public static let solicited     = ND6SendFlags(rawValue: 0x40)
    /// NA override flag.
    public static let overrideFlag  = ND6SendFlags(rawValue: 0x20)
}

/// Neighbor Advertisement flags.
public struct NAFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let router    = NAFlags(rawValue: 0x80)
    public static let solicited = NAFlags(rawValue: 0x40)
    public static let overrideFlag = NAFlags(rawValue: 0x20)
}

// MARK: - Neighbor Cache Entry State

/// States for neighbor cache entries.
public enum ND6NeighborState: UInt8, Sendable {
    case noEntry    = 0
    case incomplete = 1
    case reachable  = 2
    case stale      = 3
    case delay      = 4
    case probe      = 5
}

// MARK: - Neighbor Cache Entry

/// A neighbor cache entry for IPv6 Neighbor Discovery.
public final class ND6NeighborCacheEntry: @unchecked Sendable {
    public var nextHopAddress: IPv6Address = .any
    public var netif: NetworkInterface?
    public var linkLayerAddress: [UInt8]
    public var state: ND6NeighborState = .noEntry
    public var isRouter: Bool = false
    /// Pending outgoing packet (single-packet mode, used when `nd6Queueing` is disabled).
    public var pendingQueue: Pbuf?
    /// Linked-list queue of pending outgoing packets (used when `nd6Queueing` is enabled).
    public var queue: ND6QueueEntry?
    /// Counter used differently per state (reachable_time, delay_time, probes_sent, stale_time).
    public var counter: UInt32 = 0

    public init(hwAddrLen: Int = 6) {
        self.linkLayerAddress = [UInt8](repeating: 0, count: hwAddrLen)
    }
}

// MARK: - Destination Cache Entry

/// A destination cache entry mapping destination to next-hop.
public final class ND6DestinationCacheEntry: @unchecked Sendable {
    public var destinationAddr: IPv6Address = .any
    public var nextHopAddr: IPv6Address = .any
    public var pmtu: UInt16 = 0
    public var cachedNeighborIdx: Int = 0
    public var age: UInt32 = 0

    public init() {}
}

// MARK: - Prefix List Entry

/// An on-link prefix list entry.
public final class ND6PrefixListEntry: @unchecked Sendable {
    public var prefix: IPv6Address = .any
    public var netif: NetworkInterface?
    public var invalidationTimer: UInt32 = 0

    public init() {}
}

// MARK: - Router List Entry

/// A default router list entry.
public final class ND6RouterListEntry: @unchecked Sendable {
    public var neighborEntry: ND6NeighborCacheEntry?
    public var invalidationTimer: UInt32 = 0
    public var flags: UInt8 = 0

    public init() {}
}

// MARK: - RA Flags

/// Router advertisement flag constants.
public enum ND6RAFlag {
    public static let managedAddressConfig: UInt8 = 0x80
    public static let otherConfig: UInt8          = 0x40
}

// MARK: - ND6 Option Types

/// ND6 option type constants.
public enum ND6OptionType: UInt8, Sendable {
    case sourceLLAddr  = 1
    case targetLLAddr  = 2
    case prefixInfo    = 3
    case redirectedHdr = 4
    case mtu           = 5
    case routeInfo     = 24
    case rdnss         = 25
}

/// Prefix option flags.
public enum ND6PrefixFlag {
    public static let onLink: UInt8     = 0x80
    public static let autonomous: UInt8 = 0x40
}


// MARK: - ND6 Queue Entry

/// A queued outgoing packet for a neighbor cache entry (used when `nd6Queueing` is enabled).
public final class ND6QueueEntry: @unchecked Sendable {
    /// Next entry in the linked list.
    public var next: ND6QueueEntry?
    /// The packet waiting to be sent.
    public var packet: Pbuf

    public init(packet: Pbuf) {
        self.next = nil
        self.packet = packet
    }
}

// MARK: - ND6 Module

/// IPv6 Neighbor Discovery protocol processing.
public enum ND6 {

    // MARK: - Tables

    /// Neighbor cache table.
    public static var neighborCache: [ND6NeighborCacheEntry] = {
        (0..<LWIPConfig.nd6NumNeighbors).map { _ in ND6NeighborCacheEntry() }
    }()

    /// Destination cache table.
    public static var destinationCache: [ND6DestinationCacheEntry] = {
        (0..<LWIPConfig.nd6NumDestinations).map { _ in ND6DestinationCacheEntry() }
    }()

    /// On-link prefix list.
    public static var prefixList: [ND6PrefixListEntry] = {
        (0..<LWIPConfig.nd6NumPrefixes).map { _ in ND6PrefixListEntry() }
    }()

    /// Default router list.
    public static var defaultRouterList: [ND6RouterListEntry] = {
        (0..<LWIPConfig.nd6NumRouters).map { _ in ND6RouterListEntry() }
    }()

    /// Default reachable time (can be updated by RA).
    public static var reachableTime: UInt32 = 30000
    /// Default retransmission timer (can be updated by RA).
    public static var retransTimer: UInt32 = 1000

    private static var cachedDestIdx: Int = 0
    private static var rsTimerReduction: UInt8 = 0
    /// Number of queue entries currently allocated (for pool size tracking).
    private static var nd6QueueSize: UInt8 = 0

    /// Initialize or reset ND6 caches.
    public static func initialize() {
        neighborCache = (0..<LWIPConfig.nd6NumNeighbors).map { _ in ND6NeighborCacheEntry() }
        destinationCache = (0..<LWIPConfig.nd6NumDestinations).map { _ in ND6DestinationCacheEntry() }
        prefixList = (0..<LWIPConfig.nd6NumPrefixes).map { _ in ND6PrefixListEntry() }
        defaultRouterList = (0..<LWIPConfig.nd6NumRouters).map { _ in ND6RouterListEntry() }
        reachableTime = 30000
        retransTimer = 1000
        cachedDestIdx = 0
        rsTimerReduction = 0
        nd6QueueSize = 0
        lastRouter = 0
    }

    // MARK: - Input

    /// Process an incoming ND6 message.
    public static func input(_ pbuf: Pbuf, on inputNetif: NetworkInterface) {
        guard pbuf.length >= 1 else {
            pbuf.free()
            return
        }

        let msgType = pbuf.payload.load(fromByteOffset: 0, as: UInt8.self)
        _ = IPv6.currentContext

        switch msgType {
        case ICMPv6Type.neighborAdvertisement.rawValue:
            processNA(pbuf, on: inputNetif)

        case ICMPv6Type.neighborSolicitation.rawValue:
            processNS(pbuf, on: inputNetif)

        case ICMPv6Type.routerAdvertisement.rawValue:
            processRA(pbuf, on: inputNetif)

        case ICMPv6Type.redirect.rawValue:
            processRedirect(pbuf, on: inputNetif)

        case ICMPv6Type.packetTooBig.rawValue:
            processPTB(pbuf, on: inputNetif)

        default:
            break
        }

        pbuf.free()
    }

    // MARK: - NA Processing

    private static func processNA(_ pbuf: Pbuf, on inp: NetworkInterface) {
        // Minimal NA header: type(1) + code(1) + checksum(2) + flags(1) + reserved(3) + target(16) = 24
        guard pbuf.length >= 24 else { return }
        let ctx = IPv6.currentContext
        let p = pbuf.payload

        let flags = p.load(fromByteOffset: 4, as: UInt8.self)
        let targetAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )

        // Validate hop limit and code
        guard let hdr = ctx.currentHeader,
              hdr.hopLimit == ND6Constants.maximumHopLimit,
              p.load(fromByteOffset: 1, as: UInt8.self) == 0,
              !targetAddress.isMulticast else { return }

        // Check for DAD
        if ctx.currentDest.isMulticast {
            // Unsolicited NA
            for i in 0..<inp.ipv6AddressCount {
                if inp.ipv6AddressIsValid(index: i) && targetAddress == inp.ipv6Address(at: i) {
                    inp.setIPv6AddressState(index: i, state: .duplicated)
                    return
                }
            }

            // Update existing neighbor
            if let idx = findNeighborCacheEntry(for: targetAddress) {
                if flags & NAFlags.overrideFlag.rawValue != 0 && pbuf.length >= 26 {
                    let optLen = Int(p.load(fromByteOffset: 25, as: UInt8.self)) << 3
                    if pbuf.length >= 24 + optLen && optLen >= 8 {
                        for j in 0..<min(Int(inp.hwAddrLen), neighborCache[idx].linkLayerAddress.count) {
                            neighborCache[idx].linkLayerAddress[j] = p.load(fromByteOffset: 26 + j, as: UInt8.self)
                        }
                    }
                }
            }
        } else {
            // Solicited NA
            guard let idx = findNeighborCacheEntry(for: targetAddress) else { return }

            // Update link-layer address if override or incomplete
            if (flags & NAFlags.overrideFlag.rawValue != 0) ||
               neighborCache[idx].state == .incomplete {
                if pbuf.length >= 26 {
                    let optLen = Int(p.load(fromByteOffset: 25, as: UInt8.self)) << 3
                    if pbuf.length >= 24 + optLen && optLen >= 8 {
                        for j in 0..<min(Int(inp.hwAddrLen), neighborCache[idx].linkLayerAddress.count) {
                            neighborCache[idx].linkLayerAddress[j] = p.load(fromByteOffset: 26 + j, as: UInt8.self)
                        }
                    }
                }
            }

            neighborCache[idx].netif = inp
            neighborCache[idx].state = .reachable
            neighborCache[idx].counter = reachableTime

            // Send queued packets
            if hasQueuedPackets(idx) {
                sendQueuedPackets(idx)
            }
        }
    }

    // MARK: - NS Processing

    private static func processNS(_ pbuf: Pbuf, on inp: NetworkInterface) {
        guard pbuf.length >= 24 else { return }
        let ctx = IPv6.currentContext
        let p = pbuf.payload

        let targetAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )

        guard let hdr = ctx.currentHeader,
              hdr.hopLimit == ND6Constants.maximumHopLimit,
              p.load(fromByteOffset: 1, as: UInt8.self) == 0,
              !targetAddress.isMulticast else { return }

        // Check if target matches any of our addresses
        var accepted = false
        for i in 0..<inp.ipv6AddressCount {
            if (inp.ipv6AddressIsValid(index: i) ||
                (inp.ipv6AddressIsTentative(index: i) && ctx.currentSrc.isAny)) &&
                targetAddress == inp.ipv6Address(at: i) {
                accepted = true
                break
            }
        }
        guard accepted else { return }

        // DAD check
        if ctx.currentSrc.isAny {
            for i in 0..<inp.ipv6AddressCount {
                if inp.ipv6AddressIsValid(index: i) && targetAddress == inp.ipv6Address(at: i) {
                    sendNA(on: inp, target: inp.ipv6Address(at: i),
                           flags: [.overrideFlag, .allNodesDest])
                    if inp.ipv6AddressIsTentative(index: i) {
                        inp.setIPv6AddressState(index: i, state: .duplicated)
                    }
                }
            }
        } else {
            // Normal NS: send solicited NA
            sendNA(on: inp, target: targetAddress, flags: [.solicited, .overrideFlag])

            // Add or update neighbor cache
            if let idx = findNeighborCacheEntry(for: ctx.currentSrc) {
                if neighborCache[idx].state == .incomplete {
                    neighborCache[idx].netif = inp
                    if pbuf.length >= 26 {
                        for j in 0..<min(Int(inp.hwAddrLen), neighborCache[idx].linkLayerAddress.count) {
                            neighborCache[idx].linkLayerAddress[j] = p.load(fromByteOffset: 26 + j, as: UInt8.self)
                        }
                    }
                    neighborCache[idx].state = .delay
                    neighborCache[idx].counter = LWIPConfig.nd6DelayFirstProbeTime / ND6Constants.timerInterval
                }
            } else if let idx = newNeighborCacheEntry() {
                neighborCache[idx].netif = inp
                neighborCache[idx].nextHopAddress = ctx.currentSrc
                if pbuf.length >= 26 {
                    for j in 0..<min(Int(inp.hwAddrLen), neighborCache[idx].linkLayerAddress.count) {
                        neighborCache[idx].linkLayerAddress[j] = p.load(fromByteOffset: 26 + j, as: UInt8.self)
                    }
                }
                neighborCache[idx].state = .delay
                neighborCache[idx].counter = LWIPConfig.nd6DelayFirstProbeTime / ND6Constants.timerInterval
            }
        }
    }

    // MARK: - RA Processing

    private static func processRA(_ pbuf: Pbuf, on inp: NetworkInterface) {
        // RA header: type(1)+code(1)+cksum(2)+curHopLim(1)+flags(1)+routerLifetime(2)+reachTime(4)+retransTimer(4) = 16
        guard pbuf.length >= 16 else { return }
        let ctx = IPv6.currentContext
        let p = pbuf.payload

        guard ctx.currentSrc.isLinkLocal,
              let hdr = ctx.currentHeader,
              hdr.hopLimit == ND6Constants.maximumHopLimit,
              p.load(fromByteOffset: 1, as: UInt8.self) == 0 else { return }

        let raFlags = p.load(fromByteOffset: 5, as: UInt8.self)
        let routerLifetime = p.loadUnaligned(fromByteOffset: 6, as: UInt16.self).bigEndian
        let raReachableTime = p.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian
        let raRetransTimer = p.loadUnaligned(fromByteOffset: 12, as: UInt32.self).bigEndian

        // Stop sending RS
        inp.routerSolicitationCount = 0

        // Get or create router entry
        var routerIdx = getRouter(ctx.currentSrc, on: inp)
        if routerIdx == nil {
            routerIdx = newRouter(ctx.currentSrc, on: inp)
        }
        guard let rIdx = routerIdx else { return }

        defaultRouterList[rIdx].invalidationTimer = UInt32(routerLifetime)
        defaultRouterList[rIdx].flags = raFlags

        // Update timers
        if raRetransTimer > 0 { retransTimer = raRetransTimer }
        if raReachableTime > 0 { reachableTime = raReachableTime }

        // Trigger DHCPv6 if flags set
        if LWIPConfig.ipv6DHCPv6 {
            DHCPv6.nd6RATrigger(on: inp,
                                managedAddrConfig: raFlags & ND6RAFlag.managedAddressConfig != 0,
                                otherConfig: raFlags & ND6RAFlag.otherConfig != 0)
        }

        // Process options
        var offset = 16
        while offset + 2 <= pbuf.totalLength {
            let optType = pbuf.getByte(at: offset)
            let optLen8 = Int(pbuf.getByte(at: offset + 1))
            guard optLen8 > 0 else { break }
            let optLen = optLen8 << 3
            guard offset + optLen <= pbuf.totalLength else { break }

            switch optType {
            case ND6OptionType.sourceLLAddr.rawValue:
                if let entry = defaultRouterList[rIdx].neighborEntry,
                   entry.state == .incomplete,
                   optLen >= 2 + Int(inp.hwAddrLen) {
                    for j in 0..<Int(inp.hwAddrLen) {
                        entry.linkLayerAddress[j] = pbuf.getByte(at: offset + 2 + j)
                    }
                    entry.state = .reachable
                    entry.counter = reachableTime
                }

            case ND6OptionType.mtu.rawValue:
                if optLen >= 8 {
                    let mtu32 = pbuf.getUInt32(at: offset + 4)
                    if mtu32 >= UInt32(IPv6HeaderConstants.minimumMTU) && mtu32 <= 0xFFFF {
                        inp.mtuIPv6 = UInt16(min(UInt32(inp.mtu), mtu32))
                    }
                }

            case ND6OptionType.prefixInfo.rawValue:
                if optLen >= 32 {
                    let prefixLength = pbuf.getByte(at: offset + 2)
                    let prefixFlags = pbuf.getByte(at: offset + 3)
                    let validLifetime = pbuf.getUInt32(at: offset + 4)
                    let preferredLifetime = pbuf.getUInt32(at: offset + 8)
                    let prefAddr = IPv6Address(
                        pbuf.getUInt32NetworkOrder(at: offset + 16),
                        pbuf.getUInt32NetworkOrder(at: offset + 20),
                        pbuf.getUInt32NetworkOrder(at: offset + 24),
                        pbuf.getUInt32NetworkOrder(at: offset + 28)
                    )
                    if !prefAddr.isLinkLocal {
                        if prefixFlags & ND6PrefixFlag.onLink != 0 && prefixLength == 64 {
                            if let pIdx = getOnLinkPrefix(prefAddr, on: inp) {
                                prefixList[pIdx].invalidationTimer = validLifetime
                            } else if validLifetime > 0 {
                                if let pIdx = newOnLinkPrefix(prefAddr, on: inp) {
                                    prefixList[pIdx].invalidationTimer = validLifetime
                                }
                            }
                        }
                        // Perform SLAAC processing if autonomous flag is set.
                        if LWIPConfig.ipv6Autoconfig &&
                           prefixFlags & ND6PrefixFlag.autonomous != 0 {
                            processAutoconfigPrefix(
                                on: inp, prefixAddr: prefAddr,
                                prefixLength: prefixLength,
                                validLifetime: validLifetime,
                                preferredLifetime: preferredLifetime)
                        }
                    }
                }

            default:
                break
            }

            offset += optLen
        }
    }

    // MARK: - Autoconfig Prefix Processing

    /// Process a Router Advertisement prefix option with the autonomous flag set.
    /// Implements stateless address autoconfiguration (SLAAC) per RFC 4862 Sec. 5.5.3.
    private static func processAutoconfigPrefix(
        on netif: NetworkInterface,
        prefixAddr: IPv6Address,
        prefixLength: UInt8,
        validLifetime: UInt32,
        preferredLifetime: UInt32
    ) {
        // RFC 4862 Sec. 5.5.3 checks (c) and (d).
        if preferredLifetime > validLifetime || prefixLength != 64 {
            return // silently ignore
        }

        let twoHours = ND6Constants.twoHoursInSeconds

        // Check if an autogenerated address already exists for this prefix.
        // If so, update its lifetimes. Skip slot 0 (link-local address).
        for i in 1..<netif.ipv6AddressCount {
            let addrState = netif.ipv6AddressState(index: i)
            if !addrState.isInvalid && !netif.ipv6AddressIsStatic(index: i) &&
               prefixAddr.matchesSubnet(of: netif.ipv6Address(at: i)) {
                // Update valid lifetime per RFC 4862 Sec. 5.5.3 point (e).
                let remainingLife = netif.ipv6AddressValidLifetime[i]
                if validLifetime > twoHours || validLifetime > remainingLife {
                    netif.ipv6AddressValidLifetime[i] = validLifetime
                } else if remainingLife > twoHours {
                    netif.ipv6AddressValidLifetime[i] = twoHours
                }
                // Update preferred lifetime. Un-deprecate if needed.
                if preferredLifetime > 0 && addrState == .deprecated {
                    netif.setIPv6AddressState(index: i, state: .preferred)
                }
                netif.ipv6AddressPreferredLifetime[i] = preferredLifetime
                return // at most one matching address
            }
        }

        // No autogenerated address exists for this prefix yet. Check conditions.
        let addr0State = netif.ipv6AddressState(index: 0)
        if !netif.ip6AutoconfigEnabled ||
           validLifetime == IPv6AddressLifetime.static ||
           addr0State.isInvalid || addr0State.isDuplicated {
            return
        }

        // Construct the new address: prefix + interface ID from link-local (slot 0).
        let llAddr = netif.ipv6Address(at: 0)
        let newAddr = IPv6Address(prefixAddr.addr.0, prefixAddr.addr.1,
                                  llAddr.addr.2, llAddr.addr.3)

        // Check if this address already exists (may have been added manually).
        var freeIdx = 0
        for i in 1..<netif.ipv6AddressCount {
            if !netif.ipv6AddressState(index: i).isInvalid {
                if newAddr == netif.ipv6Address(at: i) {
                    return // formed address already exists
                }
            } else if freeIdx == 0 {
                freeIdx = i
            }
        }
        if freeIdx == 0 {
            return // no address slots available
        }

        // Assign the new address.
        netif.setIPv6Address(newAddr, at: freeIdx)
        netif.ipv6AddressValidLifetime[freeIdx] = validLifetime
        netif.ipv6AddressPreferredLifetime[freeIdx] = preferredLifetime
        netif.setIPv6AddressState(index: freeIdx, state: .tentative)
    }

    // MARK: - Prefix Update

    /// Update or create a prefix list entry from a Router Advertisement.
    /// Can be called externally for prefix management.
    public static func prefixUpdate(on netif: NetworkInterface,
                                    prefix: IPv6Address,
                                    prefixLength: UInt8,
                                    validLifetime: UInt32,
                                    preferredLifetime: UInt32) {
        guard prefixLength == 64, !prefix.isLinkLocal else { return }

        // Update or create on-link prefix entry.
        if let pIdx = getOnLinkPrefix(prefix, on: netif) {
            prefixList[pIdx].invalidationTimer = validLifetime
        } else if validLifetime > 0 {
            if let pIdx = newOnLinkPrefix(prefix, on: netif) {
                prefixList[pIdx].invalidationTimer = validLifetime
            }
        }

        // Perform SLAAC processing if autoconfig is enabled.
        if LWIPConfig.ipv6Autoconfig {
            processAutoconfigPrefix(on: netif, prefixAddr: prefix,
                                    prefixLength: prefixLength,
                                    validLifetime: validLifetime,
                                    preferredLifetime: preferredLifetime)
        }
    }

    // MARK: - Redirect Processing

    private static func processRedirect(_ pbuf: Pbuf, on inp: NetworkInterface) {
        // redirect: type(1)+code(1)+cksum(2)+reserved(4)+target(16)+dest(16) = 40
        let redirectHeaderSize = 40
        guard pbuf.length >= redirectHeaderSize else { return }
        let ctx = IPv6.currentContext
        let p = pbuf.payload

        guard ctx.currentSrc.isLinkLocal,
              let hdr = ctx.currentHeader,
              hdr.hopLimit == ND6Constants.maximumHopLimit,
              p.load(fromByteOffset: 1, as: UInt8.self) == 0 else { return }

        let destAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 24, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 28, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 32, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 36, as: UInt32.self)
        )
        guard !destAddress.isMulticast else { return }

        // Parse optional Target Link-Layer Address option after the redirect header
        var llAddrOpt: UnsafeRawPointer? = nil
        var llAddrOptLen: Int = 0
        if pbuf.length >= redirectHeaderSize + 2 {
            let optType = p.load(fromByteOffset: redirectHeaderSize, as: UInt8.self)
            let optLen = Int(p.load(fromByteOffset: redirectHeaderSize + 1, as: UInt8.self)) << 3
            if optLen > 0 && pbuf.length >= redirectHeaderSize + optLen {
                if optType == ND6OptionType.targetLLAddr.rawValue {
                    llAddrOpt = UnsafeRawPointer(p.advanced(by: redirectHeaderSize))
                    llAddrOptLen = optLen
                }
            }
        }

        guard let dIdx = findDestinationCacheEntry(for: destAddress) else { return }

        let targetAddress = IPv6Address(
            p.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 16, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
        )
        destinationCache[dIdx].nextHopAddr = targetAddress

        // If a Target Link-Layer Address option was present, update or create
        // a neighbor cache entry for the redirect target.
        if let llOpt = llAddrOpt, llAddrOptLen >= 2 + Int(inp.hwAddrLen) {
            let hwLen = Int(inp.hwAddrLen)
            if var idx = findNeighborCacheEntry(for: targetAddress) {
                if neighborCache[idx].state == .incomplete {
                    for j in 0..<min(hwLen, neighborCache[idx].linkLayerAddress.count) {
                        neighborCache[idx].linkLayerAddress[j] = llOpt.load(fromByteOffset: 2 + j, as: UInt8.self)
                    }
                    neighborCache[idx].state = .delay
                    neighborCache[idx].counter = LWIPConfig.nd6DelayFirstProbeTime / ND6Constants.timerInterval
                }
            } else if let idx = newNeighborCacheEntry() {
                neighborCache[idx].netif = inp
                neighborCache[idx].nextHopAddress = targetAddress
                for j in 0..<min(hwLen, neighborCache[idx].linkLayerAddress.count) {
                    neighborCache[idx].linkLayerAddress[j] = llOpt.load(fromByteOffset: 2 + j, as: UInt8.self)
                }
                neighborCache[idx].state = .delay
                neighborCache[idx].counter = LWIPConfig.nd6DelayFirstProbeTime / ND6Constants.timerInterval
            }
        }
    }

    // MARK: - Packet Too Big Processing

    private static func processPTB(_ pbuf: Pbuf, on inp: NetworkInterface) {
        // ICMPv6 header(8) + embedded IPv6 header(40) = 48 minimum
        guard pbuf.length >= 48 else { return }
        let p = pbuf.payload

        let pmtu = p.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
        let embeddedDest = IPv6Address(
            p.loadUnaligned(fromByteOffset: 32, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 36, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 40, as: UInt32.self),
            p.loadUnaligned(fromByteOffset: 44, as: UInt32.self)
        )

        guard let dIdx = findDestinationCacheEntry(for: embeddedDest) else { return }
        destinationCache[dIdx].pmtu = UInt16(min(pmtu, 0xFFFF))
    }

    // MARK: - Timer

    /// Periodic ND6 timer (call every `ND6Constants.timerInterval` ms).
    public static func timer() {
        // Process neighbor entries
        for i in 0..<neighborCache.count {
            switch neighborCache[i].state {
            case .incomplete:
                if neighborCache[i].counter >= UInt32(LWIPConfig.nd6MaxMulticastSolicit) &&
                   !neighborCache[i].isRouter {
                    freeNeighborCacheEntry(i)
                } else {
                    neighborCache[i].counter += 1
                    sendNS(on: neighborCache[i].netif!, target: neighborCache[i].nextHopAddress,
                           flags: .multicastDest)
                }
            case .reachable:
                if hasQueuedPackets(i) {
                    sendQueuedPackets(i)
                }
                if neighborCache[i].counter <= ND6Constants.timerInterval {
                    neighborCache[i].state = .stale
                    neighborCache[i].counter = 0
                } else {
                    neighborCache[i].counter -= ND6Constants.timerInterval
                }
            case .stale:
                neighborCache[i].counter += 1
            case .delay:
                if neighborCache[i].counter <= 1 {
                    neighborCache[i].state = .probe
                    neighborCache[i].counter = 0
                } else {
                    neighborCache[i].counter -= 1
                }
            case .probe:
                if neighborCache[i].counter >= UInt32(LWIPConfig.nd6MaxMulticastSolicit) &&
                   !neighborCache[i].isRouter {
                    freeNeighborCacheEntry(i)
                } else {
                    neighborCache[i].counter += 1
                    if let netif = neighborCache[i].netif {
                        sendNS(on: netif, target: neighborCache[i].nextHopAddress, flags: [])
                    }
                }
            case .noEntry:
                break
            }
        }

        // Age destination entries
        for i in 0..<destinationCache.count {
            destinationCache[i].age += 1
        }

        // Process router entries
        for i in 0..<defaultRouterList.count {
            if defaultRouterList[i].neighborEntry != nil {
                if defaultRouterList[i].invalidationTimer <= ND6Constants.timerInterval / 1000 {
                    // Clear destination cache entries pointing to this router
                    if let entry = defaultRouterList[i].neighborEntry {
                        for j in 0..<destinationCache.count {
                            if destinationCache[j].nextHopAddr == entry.nextHopAddress {
                                destinationCache[j].destinationAddr = .any
                            }
                        }
                        entry.isRouter = false
                    }
                    defaultRouterList[i].neighborEntry = nil
                    defaultRouterList[i].invalidationTimer = 0
                    defaultRouterList[i].flags = 0
                } else {
                    defaultRouterList[i].invalidationTimer -= ND6Constants.timerInterval / 1000
                }
            }
        }

        // Process prefix entries
        for i in 0..<prefixList.count {
            if prefixList[i].netif != nil {
                if prefixList[i].invalidationTimer <= ND6Constants.timerInterval / 1000 {
                    prefixList[i].invalidationTimer = 0
                    prefixList[i].netif = nil
                } else {
                    prefixList[i].invalidationTimer -= ND6Constants.timerInterval / 1000
                }
            }
        }

        // Process DAD and address lifetimes
        var netif = NetworkInterface.list
        while let n = netif {
            for i in 0..<n.ipv6AddressCount {
                let state = n.ipv6AddressState(index: i)
                if state.isTentative {
                    let tentativeCount = Int(state.rawValue & IPv6AddressState.tentativeCountMask.rawValue)
                    if tentativeCount >= LWIPConfig.ipv6DupDetectAttempts {
                        n.setIPv6AddressState(index: i, state: .preferred)
                    } else if n.isUp && n.isLinkUp {
                        n.incrementIPv6TentativeCount(index: i)
                        sendNS(on: n, target: n.ipv6Address(at: i),
                               flags: [.multicastDest, .anySrc])
                    }
                }
            }
            netif = n.next
        }

        // Send router solicitations
        if LWIPConfig.ipv6SendRouterSolicit {
            if rsTimerReduction == 0 {
                rsTimerReduction = UInt8((ND6Constants.routerSolicitationInterval / ND6Constants.timerInterval) - 1)
                var n = NetworkInterface.list
                while let netif = n {
                    if netif.routerSolicitationCount > 0 && netif.isUp && netif.isLinkUp &&
                       netif.ipv6AddressIsValid(index: 0) {
                        if sendRS(on: netif) == .ok {
                            netif.routerSolicitationCount -= 1
                        }
                    }
                    n = netif.next
                }
            } else {
                rsTimerReduction -= 1
            }
        }
    }

    // MARK: - Routing

    /// Find a route to a destination via on-link prefix or default router.
    public static func findRoute(for dest: IPv6Address) -> NetworkInterface? {
        // Check on-link prefixes
        for i in 0..<prefixList.count {
            if let netif = prefixList[i].netif,
               dest.matchesSubnet(of: prefixList[i].prefix),
               netif.isUp && netif.isLinkUp {
                return netif
            }
        }

        // Check default routers
        if let rIdx = selectRouter(for: dest, on: nil) {
            return defaultRouterList[rIdx].neighborEntry?.netif
        }
        return nil
    }

    /// Get the Path MTU for a destination.
    ///
    /// Checks the destination cache first for a stored PMTU. Falls back to the
    /// interface MTU, or the IPv6 minimum MTU (1280) if no interface is provided.
    /// Matches the C `nd6_get_destination_mtu()`.
    public static func getDestinationMTU(for dest: IPv6Address,
                                         on netif: NetworkInterface?) -> UInt16 {
        if let dIdx = findDestinationCacheEntry(for: dest), destinationCache[dIdx].pmtu > 0 {
            return destinationCache[dIdx].pmtu
        }
        if let netif = netif {
            return netif.mtuIPv6
        }
        return IPv6HeaderConstants.minimumMTU
    }

    /// Get the next hop address or queue the packet for later resolution.
    public static func getNextHopAddrOrQueue(on netif: NetworkInterface,
                                             pbuf: Pbuf,
                                             dest: IPv6Address) -> (LWIPError, UnsafePointer<UInt8>?) {
        let nhResult = getNextHopEntry(for: dest, on: netif)
        guard let nIdx = nhResult else {
            return (.routingError, nil)
        }

        // If STALE, switch to DELAY state per RFC 4861 Sec. 7.3.3.
        if neighborCache[nIdx].state == .stale {
            neighborCache[nIdx].state = .delay
            neighborCache[nIdx].counter = LWIPConfig.nd6DelayFirstProbeTime / ND6Constants.timerInterval
        }

        switch neighborCache[nIdx].state {
        case .reachable, .delay, .probe:
            return (.ok, neighborCache[nIdx].linkLayerAddress.withUnsafeBufferPointer { $0.baseAddress })
        case .incomplete:
            let _ = queuePacket(nIdx, pbuf: pbuf)
            return (.ok, nil)
        default:
            return (.routingError, nil)
        }
    }

    /// Clear the entire destination cache.
    public static func clearDestinationCache() {
        for i in 0..<destinationCache.count {
            destinationCache[i].destinationAddr = .any
        }
    }

    /// Remove all prefix, neighbor cache, and router entries of the specified netif.
    /// Also clears the destination cache since many entries may become invalid.
    public static func cleanupNetif(_ netif: NetworkInterface) {
        // Clear prefix entries first.
        for i in 0..<prefixList.count {
            if prefixList[i].netif === netif {
                prefixList[i].netif = nil
                prefixList[i].invalidationTimer = 0
            }
        }
        // Clear neighbor entries, removing associated router entries first.
        for i in 0..<neighborCache.count {
            if neighborCache[i].netif === netif {
                // Remove any default router entries that reference this neighbor.
                for rIdx in 0..<defaultRouterList.count {
                    if defaultRouterList[rIdx].neighborEntry === neighborCache[i] {
                        defaultRouterList[rIdx].neighborEntry = nil
                        defaultRouterList[rIdx].invalidationTimer = 0
                        defaultRouterList[rIdx].flags = 0
                    }
                }
                // Must clear isRouter before freeNeighborCacheEntry will proceed.
                neighborCache[i].isRouter = false
                freeNeighborCacheEntry(i)
            }
        }
        // Clear the destination cache since many entries may now be invalid.
        clearDestinationCache()
    }

    /// Restart ND6 on a netif (e.g., after link up).
    public static func restartNetif(_ netif: NetworkInterface) {
        netif.routerSolicitationCount = UInt8(LWIPConfig.nd6MaxMulticastSolicit)
    }

    // MARK: - Send Neighbor Cache Probe

    /// Send a neighbor solicitation for a neighbor cache entry.
    static func sendNeighborCacheProbe(_ entry: ND6NeighborCacheEntry, flags: ND6SendFlags) {
        guard let netif = entry.netif else { return }
        sendNS(on: netif, target: entry.nextHopAddress, flags: flags)
    }

    // MARK: - Send NS

    static func sendNS(on netif: NetworkInterface, target: IPv6Address, flags: ND6SendFlags) {
        var srcAddr: IPv6Address = .any
        var lladdrOptLen: Int = 0

        if !flags.contains(.anySrc) {
            // Find a valid source address on the same subnet
            for i in 0..<netif.ipv6AddressCount {
                if netif.ipv6AddressIsValid(index: i) &&
                   target.matchesSubnet(of: netif.ipv6Address(at: i)) {
                    srcAddr = netif.ipv6Address(at: i)
                    break
                }
            }
            if srcAddr.isAny { return }
            lladdrOptLen = ((Int(netif.hwAddrLen) + 2) + 7) >> 3
        }

        let totalLen = 24 + (lladdrOptLen << 3) // NS header(24) + optional LLADDR
        guard let pbuf = Pbuf.alloc(layer: .ip, length: UInt16(totalLen), type: .ram) else {
            return
        }

        let p = pbuf.payload
        p.storeBytes(of: ICMPv6Type.neighborSolicitation.rawValue, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: UInt32(0).bigEndian, toByteOffset: 4, as: UInt32.self)
        target.writeNetworkBytes(to: p.advanced(by: 8))

        if lladdrOptLen > 0 {
            let optP = p.advanced(by: 24)
            optP.storeBytes(of: ND6OptionType.sourceLLAddr.rawValue, toByteOffset: 0, as: UInt8.self)
            optP.storeBytes(of: UInt8(lladdrOptLen), toByteOffset: 1, as: UInt8.self)
            for j in 0..<Int(netif.hwAddrLen) {
                optP.storeBytes(of: netif.hwAddr[j], toByteOffset: 2 + j, as: UInt8.self)
            }
        }

        // Compute destination
        var destAddr: IPv6Address
        if flags.contains(.multicastDest) {
            destAddr = IPv6Address.solicitedNodeMulticast(for: target)
        } else {
            destAddr = target
        }

        // Checksum (respects per-netif offload flags)
        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf, proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.length),
                src: srcAddr, dest: destAddr)
            p.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        IPv6.outputIf(pbuf, src: srcAddr.isAny ? nil : srcAddr, dest: destAddr,
                      hopLimit: ND6Constants.maximumHopLimit, trafficClass: 0,
                      nextHeader: IPv6NextHeader.icmpv6.rawValue, netif: netif)
        pbuf.free()
    }

    // MARK: - Send NA

    static func sendNA(on netif: NetworkInterface, target: IPv6Address,
                       flags: ND6SendFlags) {
        let naFlags = flags
        let lladdrOptLen = ((Int(netif.hwAddrLen) + 2) + 7) >> 3
        let totalLen = 24 + (lladdrOptLen << 3)

        guard let pbuf = Pbuf.alloc(layer: .ip, length: UInt16(totalLen), type: .ram) else {
            return
        }

        let p = pbuf.payload
        p.storeBytes(of: ICMPv6Type.neighborAdvertisement.rawValue, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self)
        // flags byte
        var flagByte: UInt8 = 0
        if naFlags.contains(.solicited) { flagByte |= NAFlags.solicited.rawValue }
        if naFlags.contains(.overrideFlag) { flagByte |= NAFlags.overrideFlag.rawValue }
        p.storeBytes(of: flagByte, toByteOffset: 4, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 5, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 6, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 7, as: UInt8.self)
        target.writeNetworkBytes(to: p.advanced(by: 8))

        // Target link-layer address option
        let optP = p.advanced(by: 24)
        optP.storeBytes(of: ND6OptionType.targetLLAddr.rawValue, toByteOffset: 0, as: UInt8.self)
        optP.storeBytes(of: UInt8(lladdrOptLen), toByteOffset: 1, as: UInt8.self)
        for j in 0..<Int(netif.hwAddrLen) {
            optP.storeBytes(of: netif.hwAddr[j], toByteOffset: 2 + j, as: UInt8.self)
        }

        let destAddr: IPv6Address
        if naFlags.contains(.multicastDest) {
            destAddr = IPv6Address.solicitedNodeMulticast(for: target)
        } else if naFlags.contains(.allNodesDest) {
            destAddr = IPv6Address.allNodesLinkLocal
        } else {
            destAddr = IPv6.currentContext.currentSrc
        }

        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf, proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.length),
                src: target, dest: destAddr)
            p.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        IPv6.outputIf(pbuf, src: target, dest: destAddr,
                      hopLimit: ND6Constants.maximumHopLimit, trafficClass: 0,
                      nextHeader: IPv6NextHeader.icmpv6.rawValue, netif: netif)
        pbuf.free()
    }

    // MARK: - Send RS

    @discardableResult
    static func sendRS(on netif: NetworkInterface) -> LWIPError {
        let srcAddr: IPv6Address
        var lladdrOptLen: Int = 0

        if netif.ipv6AddressIsValid(index: 0) {
            srcAddr = netif.ipv6Address(at: 0)
            lladdrOptLen = ((Int(netif.hwAddrLen) + 2) + 7) >> 3
        } else {
            srcAddr = .any
        }

        let allRouters = IPv6Address.allRoutersLinkLocal
        let totalLen = 8 + (lladdrOptLen << 3)
        guard let pbuf = Pbuf.alloc(layer: .ip, length: UInt16(totalLen), type: .ram) else {
            return .bufferError
        }

        let p = pbuf.payload
        p.storeBytes(of: ICMPv6Type.routerSolicitation.rawValue, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: UInt8(0), toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: UInt32(0).bigEndian, toByteOffset: 4, as: UInt32.self)

        if lladdrOptLen > 0 {
            let optP = p.advanced(by: 8)
            optP.storeBytes(of: ND6OptionType.sourceLLAddr.rawValue, toByteOffset: 0, as: UInt8.self)
            optP.storeBytes(of: UInt8(lladdrOptLen), toByteOffset: 1, as: UInt8.self)
            for j in 0..<Int(netif.hwAddrLen) {
                optP.storeBytes(of: netif.hwAddr[j], toByteOffset: 2 + j, as: UInt8.self)
            }
        }

        if LWIPConfig.checksumGenICMPv6 && netif.isChecksumEnabled(.genICMP6) {
            let cksum = InetChecksum.checksumPseudoIPv6(
                pbuf, proto: IPv6NextHeader.icmpv6.rawValue,
                protoLen: UInt16(pbuf.length),
                src: srcAddr, dest: allRouters)
            p.storeBytes(of: cksum.bigEndian, toByteOffset: 2, as: UInt16.self)
        }

        let err = IPv6.outputIf(pbuf, src: srcAddr.isAny ? nil : srcAddr, dest: allRouters,
                                hopLimit: ND6Constants.maximumHopLimit, trafficClass: 0,
                                nextHeader: IPv6NextHeader.icmpv6.rawValue, netif: netif)
        pbuf.free()
        return err
    }

    // MARK: - Cache Helpers

    static func findNeighborCacheEntry(for addr: IPv6Address) -> Int? {
        for i in 0..<neighborCache.count {
            if addr == neighborCache[i].nextHopAddress {
                return i
            }
        }
        return nil
    }

    static func newNeighborCacheEntry() -> Int? {
        // Find empty
        for i in 0..<neighborCache.count {
            if neighborCache[i].state == .noEntry { return i }
        }
        // Recycle stale
        for i in 0..<neighborCache.count {
            if neighborCache[i].state == .stale && !neighborCache[i].isRouter {
                freeNeighborCacheEntry(i)
                return i
            }
        }
        // Recycle probe
        for i in 0..<neighborCache.count {
            if neighborCache[i].state == .probe && !neighborCache[i].isRouter {
                freeNeighborCacheEntry(i)
                return i
            }
        }
        // Recycle delay
        for i in 0..<neighborCache.count {
            if neighborCache[i].state == .delay && !neighborCache[i].isRouter {
                freeNeighborCacheEntry(i)
                return i
            }
        }
        return nil
    }

    static func freeNeighborCacheEntry(_ i: Int) {
        guard i >= 0 && i < neighborCache.count else { return }
        guard !neighborCache[i].isRouter else { return }

        // Free the packet queue.
        if lwipConfig.nd6Queueing {
            freeQueue(neighborCache[i].queue)
            neighborCache[i].queue = nil
        } else {
            neighborCache[i].pendingQueue?.free()
            neighborCache[i].pendingQueue = nil
        }

        neighborCache[i].state = .noEntry
        neighborCache[i].isRouter = false
        neighborCache[i].netif = nil
        neighborCache[i].counter = 0
        neighborCache[i].nextHopAddress = .any
    }

    /// Free a linked list of ND6 queue entries.
    private static func freeQueue(_ q: ND6QueueEntry?) {
        var current = q
        while let entry = current {
            current = entry.next
            entry.packet.free()
            entry.next = nil
            nd6QueueSize -= 1
        }
    }

    /// Free a single ND6 queue entry (and its chain).
    private static func freeQueueEntry(_ q: ND6QueueEntry) {
        var current: ND6QueueEntry? = q
        while let entry = current {
            current = entry.next
            entry.packet.free()
            entry.next = nil
            nd6QueueSize -= 1
        }
    }

    /// Check whether a neighbor cache entry has any packets queued.
    static func hasQueuedPackets(_ neighborIdx: Int) -> Bool {
        guard neighborIdx >= 0 && neighborIdx < neighborCache.count else { return false }
        if lwipConfig.nd6Queueing {
            return neighborCache[neighborIdx].queue != nil
        } else {
            return neighborCache[neighborIdx].pendingQueue != nil
        }
    }

    static func findDestinationCacheEntry(for addr: IPv6Address) -> Int? {
        for i in 0..<destinationCache.count {
            if addr == destinationCache[i].destinationAddr { return i }
        }
        return nil
    }

    static func newDestinationCacheEntry() -> Int? {
        // Find empty
        for i in 0..<destinationCache.count {
            if destinationCache[i].destinationAddr.isAny { return i }
        }
        // Find oldest
        var oldest = 0
        var maxAge: UInt32 = 0
        for i in 0..<destinationCache.count {
            if destinationCache[i].age > maxAge {
                oldest = i
                maxAge = destinationCache[i].age
            }
        }
        return oldest
    }

    /// Last router index used for round-robin selection of incomplete routers.
    private static var lastRouter: Int = 0

    static func selectRouter(for dest: IPv6Address, on netif: NetworkInterface?) -> Int? {
        // Look for valid routers. A reachable router is preferred.
        // Also consider router preference (high > medium > low) from RA flags.
        var validRouter: Int? = nil
        var validRouterReachable = false
        var validRouterPref: Int = -2  // lower than any real preference
        for i in 0..<defaultRouterList.count {
            guard let entry = defaultRouterList[i].neighborEntry,
                  let routerNetif = entry.netif else { continue }
            let netifOk = (netif == nil)
                ? (routerNetif.isUp && routerNetif.isLinkUp)
                : (netif === routerNetif)
            if netifOk && entry.state != .incomplete {
                let pref = routerPreference(flags: defaultRouterList[i].flags)
                if entry.state == .reachable {
                    // Reachable is best; among reachable, prefer higher preference.
                    if !validRouterReachable || pref > validRouterPref {
                        validRouter = i
                        validRouterReachable = true
                        validRouterPref = pref
                    }
                } else if !validRouterReachable {
                    // Not reachable, but valid. Prefer higher preference.
                    if validRouter == nil || pref > validRouterPref {
                        validRouter = i
                        validRouterPref = pref
                    }
                }
            }
        }
        if let vr = validRouter {
            return vr
        }

        // No valid (non-incomplete) router found.
        // Round-robin selection of incomplete routers as recommended by RFC 4861 Sec. 6.3.6.
        if netif == nil {
            lastRouter += 1
            if lastRouter >= defaultRouterList.count {
                lastRouter = 0
            }
        }
        var idx = lastRouter
        for _ in 0..<defaultRouterList.count {
            if let entry = defaultRouterList[idx].neighborEntry,
               let routerNetif = entry.netif {
                let netifOk = (netif == nil)
                    ? (routerNetif.isUp && routerNetif.isLinkUp)
                    : (netif === routerNetif)
                if netifOk {
                    return idx
                }
            }
            idx += 1
            if idx >= defaultRouterList.count {
                idx = 0
            }
        }

        return nil
    }

    /// Map RA flags to a router preference value. Higher is more preferred.
    /// Bits 3-4 of the RA flags encode the default router preference (RFC 4191):
    ///   01 = high (1), 00 = medium (0), 11 = low (-1).
    private static func routerPreference(flags: UInt8) -> Int {
        let prf = (flags >> 3) & 0x03
        switch prf {
        case 0x01: return 1   // high
        case 0x03: return -1  // low
        default:   return 0   // medium (0x00) or reserved (0x02, treat as medium)
        }
    }

    static func getRouter(_ addr: IPv6Address, on netif: NetworkInterface) -> Int? {
        for i in 0..<defaultRouterList.count {
            if let entry = defaultRouterList[i].neighborEntry,
               entry.netif === netif,
               addr == entry.nextHopAddress {
                return i
            }
        }
        return nil
    }

    static func newRouter(_ addr: IPv6Address, on netif: NetworkInterface) -> Int? {
        // Find or create neighbor entry
        var nIdx = findNeighborCacheEntry(for: addr)
        if nIdx == nil {
            nIdx = newNeighborCacheEntry()
            guard let ni = nIdx else { return nil }
            neighborCache[ni].nextHopAddress = addr
            neighborCache[ni].netif = netif
            neighborCache[ni].state = .incomplete
            neighborCache[ni].counter = 1
            sendNS(on: netif, target: addr, flags: .multicastDest)
        }

        guard let ni = nIdx else { return nil }
        neighborCache[ni].isRouter = true

        // Find free router slot
        for i in (0..<defaultRouterList.count).reversed() {
            if defaultRouterList[i].neighborEntry === neighborCache[ni] { return i }
            if defaultRouterList[i].neighborEntry == nil {
                defaultRouterList[i].neighborEntry = neighborCache[ni]
                return i
            }
        }

        neighborCache[ni].isRouter = false
        return nil
    }

    static func getOnLinkPrefix(_ prefix: IPv6Address, on netif: NetworkInterface) -> Int? {
        for i in 0..<prefixList.count {
            if prefixList[i].prefix.matchesSubnet(of: prefix) && prefixList[i].netif === netif {
                return i
            }
        }
        return nil
    }

    static func newOnLinkPrefix(_ prefix: IPv6Address, on netif: NetworkInterface) -> Int? {
        for i in 0..<prefixList.count {
            if prefixList[i].netif == nil || prefixList[i].invalidationTimer == 0 {
                prefixList[i].netif = netif
                prefixList[i].prefix = prefix
                return i
            }
        }
        return nil
    }

    static func getNextHopEntry(for dest: IPv6Address, on netif: NetworkInterface) -> Int? {
        // Check destination cache
        if let dIdx = findDestinationCacheEntry(for: dest) {
            let entry = destinationCache[dIdx]
            if let nIdx = findNeighborCacheEntry(for: entry.nextHopAddr) {
                entry.age = 0
                return nIdx
            }
        }

        // Create new destination entry
        guard let dIdx = newDestinationCacheEntry() else { return nil }
        destinationCache[dIdx].destinationAddr = dest
        destinationCache[dIdx].age = 0

        if dest.isLinkLocal || isPrefixInNetif(dest, on: netif) {
            destinationCache[dIdx].pmtu = netif.mtuIPv6
            destinationCache[dIdx].nextHopAddr = dest
        } else {
            guard let rIdx = selectRouter(for: dest, on: netif),
                  let routerEntry = defaultRouterList[rIdx].neighborEntry else {
                destinationCache[dIdx].destinationAddr = .any
                return nil
            }
            destinationCache[dIdx].pmtu = netif.mtuIPv6
            destinationCache[dIdx].nextHopAddr = routerEntry.nextHopAddress
        }

        // Find or create neighbor for next hop
        if let nIdx = findNeighborCacheEntry(for: destinationCache[dIdx].nextHopAddr) {
            return nIdx
        }
        guard let nIdx = newNeighborCacheEntry() else { return nil }
        neighborCache[nIdx].nextHopAddress = destinationCache[dIdx].nextHopAddr
        neighborCache[nIdx].isRouter = false
        neighborCache[nIdx].netif = netif
        neighborCache[nIdx].state = .incomplete
        neighborCache[nIdx].counter = 1
        sendNS(on: netif, target: neighborCache[nIdx].nextHopAddress, flags: .multicastDest)
        return nIdx
    }

    static func isPrefixInNetif(_ addr: IPv6Address, on netif: NetworkInterface) -> Bool {
        for i in 0..<prefixList.count {
            if prefixList[i].netif === netif &&
               prefixList[i].invalidationTimer > 0 &&
               addr.matchesSubnet(of: prefixList[i].prefix) {
                return true
            }
        }
        for i in 0..<netif.ipv6AddressCount {
            if netif.ipv6AddressIsValid(index: i) &&
               netif.ipv6AddressIsStatic(index: i) &&
               addr.matchesSubnet(of: netif.ipv6Address(at: i)) {
                return true
            }
        }
        return false
    }

    static func queuePacket(_ neighborIdx: Int, pbuf: Pbuf) -> LWIPError {
        guard neighborIdx >= 0 && neighborIdx < neighborCache.count else { return .invalidArgument }

        // Determine if we need to copy the packet (volatile buffers must be cloned).
        var p: Pbuf?
        var needsCopy = false
        var walk: Pbuf? = pbuf
        while let w = walk {
            if w.type.needsCopy {
                needsCopy = true
                break
            }
            walk = w.next
        }

        if needsCopy {
            p = Pbuf.clone(layer: .link, type: .ram, source: pbuf)
            // If clone fails, try freeing oldest queued packet to make room.
            if lwipConfig.nd6Queueing {
                while p == nil && neighborCache[neighborIdx].queue != nil {
                    let oldest = neighborCache[neighborIdx].queue!
                    neighborCache[neighborIdx].queue = oldest.next
                    oldest.next = nil
                    freeQueueEntry(oldest)
                    p = Pbuf.clone(layer: .link, type: .ram, source: pbuf)
                }
            } else {
                while p == nil && neighborCache[neighborIdx].pendingQueue != nil {
                    neighborCache[neighborIdx].pendingQueue!.free()
                    neighborCache[neighborIdx].pendingQueue = nil
                    p = Pbuf.clone(layer: .link, type: .ram, source: pbuf)
                }
            }
        } else {
            // Referencing the existing pbuf is sufficient.
            p = pbuf
            pbuf.ref()
        }

        guard let packet = p else { return .outOfMemory }

        if lwipConfig.nd6Queueing {
            // Allocate a new queue entry.
            var newEntry: ND6QueueEntry?
            if nd6QueueSize < UInt8(lwipConfig.arpQueuePoolCount) {
                newEntry = ND6QueueEntry(packet: packet)
                nd6QueueSize += 1
            }
            // If allocation failed, free oldest to make room.
            if newEntry == nil && neighborCache[neighborIdx].queue != nil {
                let oldest = neighborCache[neighborIdx].queue!
                neighborCache[neighborIdx].queue = oldest.next
                oldest.next = nil
                freeQueueEntry(oldest)
                newEntry = ND6QueueEntry(packet: packet)
                nd6QueueSize += 1
            }
            if let entry = newEntry {
                entry.next = nil
                entry.packet = packet
                // Append to end of queue.
                if var tail = neighborCache[neighborIdx].queue {
                    while tail.next != nil {
                        tail = tail.next!
                    }
                    tail.next = entry
                } else {
                    neighborCache[neighborIdx].queue = entry
                }
                return .ok
            } else {
                // Could not allocate queue entry.
                packet.free()
                return .outOfMemory
            }
        } else {
            // Single-packet queue mode: replace any existing queued packet.
            if neighborCache[neighborIdx].pendingQueue != nil {
                neighborCache[neighborIdx].pendingQueue!.free()
            }
            neighborCache[neighborIdx].pendingQueue = packet
            return .ok
        }
    }

    static func sendQueuedPackets(_ neighborIdx: Int) {
        guard neighborIdx >= 0 && neighborIdx < neighborCache.count else { return }
        guard let netif = neighborCache[neighborIdx].netif else { return }

        if lwipConfig.nd6Queueing {
            while let entry = neighborCache[neighborIdx].queue {
                neighborCache[neighborIdx].queue = entry.next
                let _ = netif.outputIPv6(entry.packet,
                                         to: neighborCache[neighborIdx].nextHopAddress)
                entry.packet.free()
                entry.next = nil
                nd6QueueSize -= 1
            }
        } else {
            if let q = neighborCache[neighborIdx].pendingQueue {
                neighborCache[neighborIdx].pendingQueue = nil
                let _ = netif.outputIPv6(q, to: neighborCache[neighborIdx].nextHopAddress)
                q.free()
            }
        }
    }

    /// Provide a reachability hint from upper layers (e.g., TCP receiving an ACK).
    /// Looks up the destination in the destination cache first to find the correct
    /// next-hop neighbor, then updates the neighbor state to reachable.
    public static func reachabilityHint(for addr: IPv6Address) {
        // Find destination in cache (check cached index first for speed).
        let dstIdx: Int?
        if addr == destinationCache[cachedDestIdx].destinationAddr {
            dstIdx = cachedDestIdx
        } else {
            dstIdx = findDestinationCacheEntry(for: addr)
        }
        guard let dIdx = dstIdx else { return }

        // Find the next-hop neighbor for this destination.
        let dest = destinationCache[dIdx]
        let nIdx: Int?
        if dest.nextHopAddr == neighborCache[dest.cachedNeighborIdx].nextHopAddress {
            nIdx = dest.cachedNeighborIdx
        } else {
            nIdx = findNeighborCacheEntry(for: dest.nextHopAddr)
        }
        guard let i = nIdx else { return }

        // For safety: don't set as reachable if we don't have a LL address yet.
        if neighborCache[i].state == .incomplete || neighborCache[i].state == .noEntry {
            return
        }

        // Set reachability state.
        neighborCache[i].state = .reachable
        neighborCache[i].counter = reachableTime
    }

    /// Adjust MLD membership when an address state changes.
    ///
    /// Determines whether the interface was, and should be, a member of the
    /// solicited-node multicast group for the address at `addrIdx`. For tentative
    /// addresses the group is not joined until the address enters TENTATIVE_1
    /// (or a VALID state). Only transitions between member/non-member trigger
    /// a join or leave.
    public static func adjustMLDMembership(on netif: NetworkInterface,
                                           addrIdx: Int, newState: UInt8) {
        let oldState = netif.ipv6AddressState(index: addrIdx).rawValue

        // Determine whether we were, and should be, a member of the solicited-node
        // multicast group for this address. For tentative addresses, the group is
        // not joined until the address enters the TENTATIVE_1 (or VALID) state.
        let oldMember: Bool = (oldState != IPv6AddressState.invalid.rawValue &&
                               oldState != IPv6AddressState.duplicated.rawValue &&
                               oldState != IPv6AddressState.tentative.rawValue)
        let newMember: Bool = (newState != IPv6AddressState.invalid.rawValue &&
                               newState != IPv6AddressState.duplicated.rawValue &&
                               newState != IPv6AddressState.tentative.rawValue)

        if oldMember != newMember {
            let addr = netif.ipv6Address(at: addrIdx)
            let solNode = IPv6Address.solicitedNodeMulticast(for: addr)

            if newMember {
                MLD6.joinGroup(on: netif, groupAddr: solNode)
            } else {
                MLD6.leaveGroup(on: netif, groupAddr: solNode)
            }
        }
    }

}
