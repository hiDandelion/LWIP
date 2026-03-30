//
//  EthARPTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for Ethernet ARP table management.
@Suite("EthARP")
struct EthARPTests {

    /// Port of test_etharp_table.
    @Test("ARP table: dynamic entries can be added and found")
    func etharpTable() {
        EthARP.initialize()

        let netif = NetworkInterface()
        let initFn: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "a"), UInt8(ascii: "t"))
            netif.mtu = 1500
            netif.hwAddrLen = 6
            netif.hwAddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
            netif.flags = [.up, .linkUp, .broadcast, .ethArp, .ethernet]
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        NetworkInterface.add(netif, ipAddr: IPv4Address(192, 168, 0, 1),
                 netmask: IPv4Address(255, 255, 255, 0),
                 gateway: .any, state: nil, initFn: initFn, inputFn: inputFn)
        netif.setUp()
        netif.setLinkUp()
        NetworkInterface.setDefault(netif)

        defer {
            NetworkInterface.setDefault(nil)
            netif.remove()
        }

        let testIP = IPv4Address(192, 168, 0, 100)
        let result = EthARP.findAddr(netif: netif, ipAddr: testIP)
        #expect(result == nil, "ARP table should be empty initially for unknown IP")

        let staticIP = IPv4Address(192, 168, 0, 200)
        let staticMac = EthAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        let addErr = EthARP.addStaticEntry(ipAddr: staticIP, ethAddr: staticMac)
        #expect(addErr == .ok, "Adding static ARP entry should succeed")

        let found = EthARP.findAddr(netif: netif, ipAddr: staticIP)
        if let (ethAddr, _) = found {
            #expect(ethAddr == staticMac, "Found MAC should match static entry")
        }

        for _ in 0..<300 {
            EthARP.timer()
        }

        let stillFound = EthARP.findAddr(netif: netif, ipAddr: staticIP)
        #expect(stillFound != nil, "Static ARP entry should not time out")

        let removeErr = EthARP.removeStaticEntry(ipAddr: staticIP)
        #expect(removeErr == .ok)

        let afterRemove = EthARP.findAddr(netif: netif, ipAddr: staticIP)
        #expect(afterRemove == nil, "Removed static entry should not be found")
    }
}
