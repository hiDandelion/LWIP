//
//  NetifTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for NetworkInterface management.
@Suite("Netif")
struct NetifTests {

    /// Port of test_netif_extcallbacks.
    @Test("Extended callback fires on add and remove")
    func extCallbacks() {
        NetworkInterface.initializeSubsystem()

        var reasons: [NetifNSCReason] = []
        let callback = NetifExtCallback()
        NetworkInterface.addExtCallback(callback) { _, reason, _ in
            reasons.append(reason)
        }

        let netif = NetworkInterface()
        let initFn: NetifAPI.InitializationHandler = { iface in
            iface.mtu = 1500
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        let added = NetworkInterface.add(netif, initFn: initFn, inputFn: inputFn)
        #expect(added != nil)
        #expect(reasons.contains(.netifAdded))

        let countAfterAdd = reasons.count

        netif.remove()
        #expect(reasons.count > countAfterAdd)
        #expect(reasons.contains(.netifRemoved))

        NetworkInterface.removeExtCallback(callback)
    }

    /// Port of test_netif_flag_set.
    @Test("Network interface flag setting")
    func flagSet() {
        let netif = NetworkInterface()

        #expect(!netif.flags.contains(.up))
        #expect(!netif.flags.contains(.linkUp))

        netif.flags.insert(.up)
        #expect(netif.flags.contains(.up))

        netif.flags.insert(.linkUp)
        #expect(netif.flags.contains(.linkUp))

        netif.flags.remove(.up)
        #expect(!netif.flags.contains(.up))
        #expect(netif.flags.contains(.linkUp))
    }

    /// Port of test_netif_find.
    @Test("Find network interface by name")
    func find() {
        NetworkInterface.initializeSubsystem()

        let netif = NetworkInterface()
        netif.name = (UInt8(ascii: "c"), UInt8(ascii: "h"))

        let initFn: NetifAPI.InitializationHandler = { iface in
            iface.mtu = 1500
            iface.hwAddrLen = 6
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        let added = NetworkInterface.add(netif, initFn: initFn, inputFn: inputFn)
        #expect(added != nil)

        let found = NetworkInterface.find("ch\(netif.num)")
        #expect(found != nil)
        #expect(found === netif)

        let notFound = NetworkInterface.find("ch\(netif.num &+ 1)")
        #expect(notFound == nil)

        let wrongPrefix = NetworkInterface.find("en\(netif.num)")
        #expect(wrongPrefix == nil)

        #expect(NetworkInterface.find("ch") == nil)
        #expect(NetworkInterface.find("") == nil)

        netif.remove()
    }
}
