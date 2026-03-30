//
//  DNSTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for DNS server configuration.
@Suite("DNS")
struct DNSTests {

    /// Port of test_dns_set_get_server.
    @Test("Set and get DNS servers at valid and invalid indices")
    func setAndGetDNSServer() {
        let dns = DNS.shared
        dns.initialize()

        // All servers should initially be any-address
        for i in 0..<DNSConstants.maxServers {
            #expect(dns.getServer(index: i).isAnyAddress)
        }

        // Set server at each valid index and verify round-trip
        for i in 0..<DNSConstants.maxServers {
            let addr = IPAddress.v4(IPv4Address(10, 0, 0, UInt8(truncatingIfNeeded: i + 1)))
            dns.setServer(index: i, address: addr)
            let retrieved = dns.getServer(index: i)
            #expect(retrieved == addr)
        }

        // Setting at an out-of-bounds index should be silently ignored
        let outOfBounds = IPAddress.v4(IPv4Address(99, 99, 99, 99))
        dns.setServer(index: DNSConstants.maxServers, address: outOfBounds)
        dns.setServer(index: 255, address: outOfBounds)
        dns.setServer(index: -1, address: outOfBounds)

        // Getting from an out-of-bounds index should return any-address
        #expect(dns.getServer(index: DNSConstants.maxServers).isAnyAddress)
        #expect(dns.getServer(index: 255).isAnyAddress)
        #expect(dns.getServer(index: -1).isAnyAddress)

        // Clean up: reset servers back to any
        for i in 0..<DNSConstants.maxServers {
            dns.setServer(index: i, address: .any)
        }
    }
}
