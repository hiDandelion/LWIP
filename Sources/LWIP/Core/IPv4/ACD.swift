//
//  ACD.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

// MARK: - ACD Constants

/// Namespace for Address Conflict Detection constants.
public enum ACDConstants {
    /// Timer interval in milliseconds.
    public static let timerInterval: Int = 100
    /// Ticks per second based on timer interval.
    public static let ticksPerSecond: UInt16 = UInt16(1000 / timerInterval)

    // RFC 5227 and RFC 3927 timing constants
    /// Seconds of initial random delay before probing.
    public static let probeWait: UInt16         = 1
    /// Minimum seconds between repeated probes.
    public static let probeMinimum: UInt16      = 1
    /// Maximum seconds between repeated probes.
    public static let probeMaximum: UInt16      = 2
    /// Number of probe packets.
    public static let probeCount: UInt8         = 3
    /// Number of announcement packets.
    public static let announceCount: UInt8      = 2
    /// Seconds between announcements.
    public static let announceInterval: UInt16  = 2
    /// Seconds to wait before announcing.
    public static let announceWait: UInt16      = 2
    /// Maximum conflicts before rate limiting.
    public static let maximumConflicts: UInt8   = 10
    /// Seconds between rate-limited attempts.
    public static let rateLimitInterval: UInt16 = 60
    /// Minimum seconds between defensive ARPs.
    public static let defendInterval: UInt8     = 10
}

// MARK: - ACD State

/// ACD state machine states.
public enum ACDState: UInt8, Sendable {
    /// Module is off
    case off = 0
    /// Waiting before probing can start
    case probeWait = 1
    /// Actively probing the address
    case probing = 2
    /// Waiting before announcing the probed address
    case announceWait = 3
    /// Announcing the new address
    case announcing = 4
    /// Performing ongoing conflict detection (with defend capability)
    case ongoing = 5
    /// Passive ongoing detection (no defend, used for background LL addresses)
    case passiveOngoing = 6
    /// Rate limited due to too many conflicts
    case rateLimit = 7
}

// MARK: - ACD Callback State

/// Callback states from ACD to the user module.
public enum ACDCallbackState: UInt8, Sendable {
    /// Address is OK, no conflicts found
    case ipOK = 0
    /// Conflict detected, client should try again
    case restartClient = 1
    /// Decline the address (rate limiting)
    case decline = 2
}

// MARK: - ACD Conflict Callback Type

/// Callback function type for ACD conflict notifications.
public typealias ACDConflictHandler = (NetworkInterface, ACDCallbackState) -> Void

// MARK: - Address Conflict Detection

/// ACD state information for one address on one interface.
public final class AddressConflictDetection {
    /// Next ACD module in the interface's list.
    public var next: AddressConflictDetection?
    /// The IP address being checked.
    public var ipAddr: IPv4Address = .any
    /// Current state.
    public var state: ACDState = .off
    /// Number of probes or announces sent (depends on state).
    public var sentNum: UInt8 = 0
    /// Ticks to wait (each tick = ACDConstants.timerInterval).
    public var ticksToWait: UInt16 = 0

    /// Ticks until a conflict can be defended again.
    public var lastConflict: UInt8 = 0
    /// Total number of conflicts encountered.
    public var numConflicts: UInt8 = 0
    /// Callback to notify the user of conflict status.
    public var conflictCallback: ACDConflictHandler?

    public init() {}
}

// MARK: - ACD Module

/// Address Conflict Detection implementation.
public enum ACD {

    // MARK: - Random Helpers

    /// Random probe wait time (0 to ACDConstants.probeWait seconds in ticks).
    @inlinable
    static func randomProbeWait(netif: NetworkInterface, acd: AddressConflictDetection) -> UInt16 {
        let max = ACDConstants.probeWait * ACDConstants.ticksPerSecond
        guard max > 0 else { return 0 }
        return UInt16.random(in: 0..<max)
    }

    /// Random probe interval (ACDConstants.probeMinimum to ACDConstants.probeMaximum seconds in ticks).
    @inlinable
    static func randomProbeInterval(netif: NetworkInterface, acd: AddressConflictDetection) -> UInt16 {
        let minTicks = ACDConstants.probeMinimum * ACDConstants.ticksPerSecond
        let range = (ACDConstants.probeMaximum - ACDConstants.probeMinimum) * ACDConstants.ticksPerSecond
        guard range > 0 else { return minTicks }
        return UInt16.random(in: 0..<range) + minTicks
    }

    // MARK: - Add / Remove

    /// Add an ACD client to the interface's ACD list and set its callback.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - acd: The ACD instance to add.
    ///   - callback: Conflict notification callback.
    /// - Returns: `.ok`
    @discardableResult
    public static func add(to netif: NetworkInterface, acd: AddressConflictDetection,
                            callback: @escaping ACDConflictHandler) -> LWIPError {
        acd.conflictCallback = callback

        // Check if already in list
        var existing = netif.acdList
        while let e = existing {
            if e === acd { return .ok }
            existing = e.next
        }

        // Add to front of list
        acd.next = netif.acdList
        netif.acdList = acd

        return .ok
    }

    /// Remove an ACD client from the interface's ACD list.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - acd: The ACD instance to remove.
    public static func remove(from netif: NetworkInterface, acd: AddressConflictDetection) {
        var prev: AddressConflictDetection? = nil
        var current = netif.acdList

        while let c = current {
            if c === acd {
                if let p = prev {
                    p.next = acd.next
                } else {
                    netif.acdList = acd.next
                }
                return
            }
            prev = c
            current = c.next
        }
    }

    // MARK: - Start / Stop

    /// Start ACD probing for an IP address.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - acd: The ACD instance.
    ///   - ipAddr: The IP address to check.
    /// - Returns: `.ok`
    @discardableResult
    public static func start(on netif: NetworkInterface, acd: AddressConflictDetection,
                              ipAddr: IPv4Address) -> LWIPError {
        acd.sentNum = 0
        acd.lastConflict = 0
        acd.ipAddr = ipAddr
        acd.state = .probeWait
        acd.ticksToWait = randomProbeWait(netif: netif, acd: acd)
        return .ok
    }

    /// Stop ACD processing.
    ///
    /// - Parameter acd: The ACD instance to stop.
    /// - Returns: `.ok`
    @discardableResult
    public static func stop(_ acd: AddressConflictDetection) -> LWIPError {
        acd.state = .off
        return .ok
    }

    // MARK: - Network Changed

    /// Inform all ACD modules on an interface that the link went down.
    public static func networkChangedLinkDown(on netif: NetworkInterface) {
        var acd = netif.acdList
        while let a = acd {
            let _ = stop(a)
            acd = a.next
        }
    }

    // MARK: - Timer

    /// ACD timer function. Call every ACD_TMR_INTERVAL milliseconds.
    ///
    /// Handles the state machine for all ACD instances on all interfaces.
    public static func timer() {
        var netif = IPv4.netifList
        while let n = netif {
            var acd = n.acdList
            while let a = acd {
                // Decrement last conflict counter
                if a.lastConflict > 0 {
                    a.lastConflict -= 1
                }

                // Decrement time-to-wait
                if a.ticksToWait > 0 {
                    a.ticksToWait -= 1
                }

                switch a.state {
                case .probeWait, .probing:
                    if a.ticksToWait == 0 {
                        a.state = .probing
                        let _ = EthARP.acdProbe(netif: n, ipAddr: a.ipAddr)
                        a.sentNum += 1

                        if a.sentNum >= ACDConstants.probeCount {
                            // All probes sent, switch to announce wait
                            a.state = .announceWait
                            a.sentNum = 0
                            a.ticksToWait = ACDConstants.announceWait * ACDConstants.ticksPerSecond
                        } else {
                            // Schedule next probe
                            a.ticksToWait = randomProbeInterval(netif: n, acd: a)
                        }
                    }

                case .announceWait, .announcing:
                    if a.ticksToWait == 0 {
                        if a.sentNum == 0 {
                            a.state = .announcing
                            a.numConflicts = 0
                        }

                        let _ = EthARP.acdAnnounce(netif: n, ipAddr: a.ipAddr)
                        a.ticksToWait = ACDConstants.announceInterval * ACDConstants.ticksPerSecond
                        a.sentNum += 1

                        if a.sentNum >= ACDConstants.announceCount {
                            // All announces sent, address is good
                            a.state = .ongoing
                            a.sentNum = 0
                            a.ticksToWait = 0
                            a.conflictCallback?(n, .ipOK)
                        }
                    }

                case .rateLimit:
                    if a.ticksToWait == 0 {
                        let _ = stop(a)
                        a.conflictCallback?(n, .restartClient)
                    }

                case .off, .ongoing, .passiveOngoing:
                    // Nothing to do
                    break
                }

                acd = a.next
            }
            netif = n.next
        }
    }

    // MARK: - ARP Reply Handling

    /// Handle incoming ARP packets for conflict detection.
    ///
    /// Called by the ARP module for every incoming ARP packet.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - hdr: The ARP header from the received packet.
    public static func arpReply(netif: NetworkInterface, hdr: ARPHeader) {
        let sipAddr = hdr.senderIPAddr
        let dipAddr = hdr.targetIPAddr
        let netifAddr = netif.hwAddrAsEth

        var acd = netif.acdList
        while let a = acd {
            switch a.state {
            case .off, .rateLimit:
                // Do nothing
                break

            case .probeWait, .probing, .announceWait:
                // RFC 5227 Section 2.1.1:
                // Conflict if:
                //   ip.src == our IP (someone already using it)
                //   OR ip.dst == our IP && hw.src != our hw (someone else probing)
                if sipAddr == a.ipAddr ||
                   (sipAddr.isAny && dipAddr == a.ipAddr && hdr.senderHWAddr != netifAddr) {
                    restart(netif: netif, acd: a)
                }

            case .announcing, .ongoing, .passiveOngoing:
                // RFC 5227 Section 2.4:
                // Conflict if ip.src == our IP && hw.src != our hw
                if sipAddr == a.ipAddr && hdr.senderHWAddr != netifAddr {
                    handleARPConflict(netif: netif, acd: a)
                }
            }

            acd = a.next
        }
    }

    // MARK: - Address Change Notification

    /// Notify ACD modules of an address change on the interface.
    ///
    /// When changing from a link-local to a routable address, puts the
    /// LL ACD module into passive mode.
    ///
    /// - Parameters:
    ///   - netif: The network interface.
    ///   - oldAddr: The previous IP address.
    ///   - newAddr: The new IP address.
    public static func netifIPAddrChanged(on netif: NetworkInterface,
                                           oldAddr: IPv4Address, newAddr: IPv4Address) {
        if oldAddr.isAny || newAddr.isAny { return }

        var acd = netif.acdList
        while let a = acd {
            if a.ipAddr == oldAddr {
                // Changed from link-local to routable?
                if oldAddr.isLinkLocal && !newAddr.isLinkLocal {
                    putInPassiveMode(netif: netif, acd: a)
                }
            }
            acd = a.next
        }
    }

    // MARK: - Private Helpers

    /// Restart ACD after a conflict is detected.
    private static func restart(netif: NetworkInterface, acd: AddressConflictDetection) {
        acd.numConflicts += 1

        // Notify user of decline
        acd.conflictCallback?(netif, .decline)

        // If too many conflicts, rate limit
        if acd.numConflicts >= ACDConstants.maximumConflicts {
            acd.state = .rateLimit
            acd.ticksToWait = ACDConstants.rateLimitInterval * ACDConstants.ticksPerSecond
        } else {
            let _ = stop(acd)
            acd.conflictCallback?(netif, .restartClient)
        }
    }

    /// Handle an ARP conflict during ongoing detection.
    private static func handleARPConflict(netif: NetworkInterface, acd: AddressConflictDetection) {
        if acd.state == .passiveOngoing {
            // Immediately back off in passive mode
            let _ = stop(acd)
            acd.conflictCallback?(netif, .decline)
        } else {
            if acd.lastConflict > 0 {
                // Recent conflict: retreat
                restart(netif: netif, acd: acd)
            } else {
                // No recent conflict: defend with an announcement
                let _ = EthARP.acdAnnounce(netif: netif, ipAddr: acd.ipAddr)
                acd.lastConflict = ACDConstants.defendInterval * UInt8(ACDConstants.ticksPerSecond)
            }
        }
    }

    /// Put an ACD module into passive ongoing mode.
    private static func putInPassiveMode(netif: NetworkInterface, acd: AddressConflictDetection) {
        switch acd.state {
        case .off, .passiveOngoing:
            break

        case .probeWait, .probing, .announceWait, .rateLimit:
            let _ = stop(acd)
            acd.conflictCallback?(netif, .decline)

        case .announcing, .ongoing:
            acd.state = .passiveOngoing
        }
    }
}
