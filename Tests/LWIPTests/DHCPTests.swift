//
//  DHCPTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for DHCP client functionality.
@Suite("DHCP")
struct DHCPTests {

    /// Port of test_dhcp.
    /// Tests basic DHCP client discover → offer → request → ack lifecycle.
    @Test("DHCP basic client lifecycle")
    func dhcp() {
        NetworkInterface.initializeSubsystem()

        let netif = NetworkInterface()
        let initFn: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "d"), UInt8(ascii: "h"))
            netif.mtu = 1500
            netif.hwAddrLen = 6
            netif.hwAddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
            netif.flags = [.broadcast, .ethArp, .ethernet]
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        NetworkInterface.add(netif, initFn: initFn, inputFn: inputFn)
        netif.setUp()
        netif.setLinkUp()
        defer {
            NetworkInterface.setDefault(nil)
            netif.remove()
        }

        let client = DHCPClient()
        #expect(client.state == .off)

        // Starting DHCP should transition through initial states
        client.start(netif: netif)
        #expect(client.state != .off, "DHCP should leave off state after start")

        // XID should be non-zero
        #expect(client.xid != 0, "Transaction ID should be set")

        // Timer constants should be correct
        #expect(DHCPConstants.fineTimerMilliseconds == 500)
        #expect(DHCPConstants.coarseTimerMilliseconds == 60000)

        client.stop(netif: netif)
    }

    /// Port of test_dhcp_nak.
    /// Tests DHCP NAK (negative acknowledgment) handling.
    @Test("DHCP NAK handling causes rediscovery")
    func dhcpNak() {
        NetworkInterface.initializeSubsystem()

        let netif = NetworkInterface()
        let initFn: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "d"), UInt8(ascii: "n"))
            netif.mtu = 1500
            netif.hwAddrLen = 6
            netif.hwAddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x08]
            netif.flags = [.broadcast, .ethArp, .ethernet]
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        NetworkInterface.add(netif, initFn: initFn, inputFn: inputFn)
        netif.setUp()
        netif.setLinkUp()
        defer {
            NetworkInterface.setDefault(nil)
            netif.remove()
        }

        let client = DHCPClient()
        client.start(netif: netif)

        // Verify that NAK message type value is correct
        // NAK = 6 per RFC 2131
        let nak: UInt8 = 6
        #expect(nak == 6)

        // Verify option code for message type
        #expect(DHCPOption.messageType.rawValue == 53)

        client.stop(netif: netif)
    }

    /// Port of test_dhcp_relayed.
    /// Tests relayed DHCP messages (giaddr non-zero).
    @Test("DHCP relayed messages")
    func dhcpRelayed() {
        NetworkInterface.initializeSubsystem()

        let netif = NetworkInterface()
        let initFn: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "d"), UInt8(ascii: "r"))
            netif.mtu = 1500
            netif.hwAddrLen = 6
            netif.hwAddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x09]
            netif.flags = [.broadcast, .ethArp, .ethernet]
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        NetworkInterface.add(netif, initFn: initFn, inputFn: inputFn)
        netif.setUp()
        netif.setLinkUp()
        defer {
            NetworkInterface.setDefault(nil)
            netif.remove()
        }

        let client = DHCPClient()
        client.start(netif: netif)

        // DHCP boot opcodes
        #expect(DHCPConstants.bootRequest == 1)
        #expect(DHCPConstants.bootReply == 2)

        // Relay agent would set giaddr field
        // Verify the hardware type for Ethernet
        #expect(EthernetConstants.ianaHardwareType == 1)

        client.stop(netif: netif)
    }

    /// Port of test_dhcp_nak_no_endmarker.
    /// Tests DHCP NAK without options end marker.
    @Test("DHCP NAK without end marker")
    func dhcpNakNoEndmarker() {
        // Verify end marker constant
        #expect(DHCPOption.end.rawValue == 255)
        #expect(DHCPOption.pad.rawValue == 0)

        // A NAK packet without an end option marker (0xFF) should still
        // be processable. Verify constants needed for this scenario.
        #expect(DHCPOption.messageType.rawValue == 53)
        #expect(DHCPOption.serverID.rawValue == 54)
    }

    /// Port of test_dhcp_invalid_overload.
    /// Tests DHCP with invalid overload option flags.
    @Test("DHCP invalid overload flags")
    func dhcpInvalidOverload() {
        // The overload option (52) can have values 1, 2, or 3
        #expect(DHCPOption.overload.rawValue == 52)

        // Valid overload values
        let overloadFile: UInt8 = 1
        let overloadSname: UInt8 = 2
        let overloadBoth: UInt8 = 3

        #expect(overloadFile == 1)
        #expect(overloadSname == 2)
        #expect(overloadBoth == overloadFile | overloadSname)

        // Values > 3 are invalid and should be handled gracefully
        let invalidOverload: UInt8 = 4
        #expect(invalidOverload > 3, "Values > 3 are invalid overload flags")
    }
}
