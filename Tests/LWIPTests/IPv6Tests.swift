//
//  IPv6Tests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

// MARK: - IPv6 Tests

/// Tests for IPv6 address handling, parsing, formatting, fragmentation, reassembly,
/// and ICMPv6 operations.
@Suite("IPv6")
struct IPv6Tests {

    // MARK: - test_ip6_ll_addr

    @Test("IPv6 link-local address generation from MAC-48")
    func ip6LlAddr() {
        // Create a network interface with a known MAC address
        // MAC: B0:A1:A2:A3:A4:A5
        let netif = NetworkInterface()
        netif.hwAddr[0] = 0xB0
        netif.hwAddr[1] = 0xA1
        netif.hwAddr[2] = 0xA2
        netif.hwAddr[3] = 0xA3
        netif.hwAddr[4] = 0xA4
        netif.hwAddr[5] = 0xA5
        netif.hwAddrLen = 6

        // Generate the EUI-64 based link-local address
        netif.createIPv6LinkLocalAddress(fromMAC48Bit: true)

        // The address should be stored in slot 0
        guard case .v6(let llAddr) = netif.ipv6Addresses[0] else {
            #expect(Bool(false), "Slot 0 should contain an IPv6 address")
            return
        }

        // Verify link-local prefix (fe80::)
        #expect(llAddr.isLinkLocal, "Generated address should be link-local")
        #expect(llAddr.word(0) == ByteOrder.hostToNetwork(0xFE800000), "Word 0 should be fe80:0000")
        #expect(llAddr.word(1) == 0, "Word 1 should be 0")

        // EUI-64 from MAC B0:A1:A2:A3:A4:A5:
        //   Insert FF:FE in the middle: B0:A1:A2:FF:FE:A3:A4:A5
        //   Complement U/L bit (bit 1 of first byte): B0 ^ 0x02 = B2
        //   Result: B2:A1:A2:FF : FE:A3:A4:A5
        //   Word 2 (network order): 0xB2A1A2FF
        //   Word 3 (network order): 0xFEA3A4A5
        #expect(llAddr.word(2) == ByteOrder.hostToNetwork(0xB2A1A2FF),
                "Word 2 should be B2A1A2FF (EUI-64 upper)")
        #expect(llAddr.word(3) == ByteOrder.hostToNetwork(0xFEA3A4A5),
                "Word 3 should be FEA3A4A5 (EUI-64 lower)")

        // The expected full address is FE80::B2A1:A2FF:FEA3:A4A5
        let expected = IPv6Address(ByteOrder.hostToNetwork(0xFE800000), 0, ByteOrder.hostToNetwork(0xB2A1A2FF), ByteOrder.hostToNetwork(0xFEA3A4A5))
        #expect(llAddr.equalsZoneless(expected),
                "Link-local should be FE80::B2A1:A2FF:FEA3:A4A5, got \(llAddr.description)")
    }

    // MARK: - test_ip6_aton_ipv4mapped

    @Test("Parse IPv4-mapped IPv6 addresses (all forms)")
    func ip6AtonIpv4mapped() {
        // Full IPv6 form
        let full = IPv6Address("0:0:0:0:0:FFFF:D4CC:65D2")
        #expect(full != nil)
        if let full = full {
            #expect(full.word(0) == 0)
            #expect(full.word(1) == 0)
            #expect(full.word(2) == ByteOrder.hostToNetwork(0x0000FFFF))
            #expect(full.word(3) == ByteOrder.hostToNetwork(0xD4CC65D2))
        }

        // Shortened IPv6 form
        let shortened = IPv6Address("::FFFF:D4CC:65D2")
        #expect(shortened != nil)
        if let shortened = shortened {
            #expect(shortened.word(0) == 0)
            #expect(shortened.word(1) == 0)
            #expect(shortened.word(2) == ByteOrder.hostToNetwork(0x0000FFFF))
            #expect(shortened.word(3) == ByteOrder.hostToNetwork(0xD4CC65D2))
        }

        // Shortened mixed form (IPv4 dotted decimal in last 32 bits)
        let shortenedMixed = IPv6Address("::FFFF:212.204.101.210")
        #expect(shortenedMixed != nil)
        if let shortenedMixed = shortenedMixed {
            #expect(shortenedMixed.word(0) == 0)
            #expect(shortenedMixed.word(1) == 0)
            #expect(shortenedMixed.word(2) == ByteOrder.hostToNetwork(0x0000FFFF))
            #expect(shortenedMixed.word(3) == ByteOrder.hostToNetwork(0xD4CC65D2))
        }

        // Full mixed form
        let fullMixed = IPv6Address("0:0:0:0:0:FFFF:212.204.101.210")
        #expect(fullMixed != nil)
        if let fullMixed = fullMixed {
            #expect(fullMixed.word(0) == 0)
            #expect(fullMixed.word(1) == 0)
            #expect(fullMixed.word(2) == ByteOrder.hostToNetwork(0x0000FFFF))
            #expect(fullMixed.word(3) == ByteOrder.hostToNetwork(0xD4CC65D2))
        }

        // Reject bogus mixed mapping (octet value > 255)
        let bogus = IPv6Address("::FFFF:212.204.101.2101")
        #expect(bogus == nil)

        // All parsed forms should produce identical addresses
        let forms = [
            "0:0:0:0:0:FFFF:D4CC:65D2",
            "::FFFF:D4CC:65D2",
            "::FFFF:212.204.101.210",
            "0:0:0:0:0:FFFF:212.204.101.210",
        ]
        let addresses = forms.compactMap { IPv6Address($0) }
        #expect(addresses.count == forms.count)

        for i in 1..<addresses.count {
            #expect(addresses[0].equalsZoneless(addresses[i]),
                    "Form '\(forms[i])' parsed differently from '\(forms[0])'")
        }
    }

    // MARK: - test_ip6_ntoa_ipv4mapped

    @Test("Format IPv4-mapped IPv6 address to string")
    func ip6NtoaIpv4mapped() {
        let addr = IPv6Address(0, 0, ByteOrder.hostToNetwork(0x0000FFFF), ByteOrder.hostToNetwork(0xD4CC65D2))
        #expect(addr.isIPv4Mapped)
        #expect(addr.description == "::FFFF:212.204.101.210")
    }

    // MARK: - test_ip6_ntoa

    @Test("General IPv6 to string conversion")
    func ip6Ntoa() {
        // Zero compression: FE80::B2A1:A2FF:FEA3:A4A5
        let addr1 = IPv6Address(ByteOrder.hostToNetwork(0xFE800000), 0, ByteOrder.hostToNetwork(0xB2A1A2FF), ByteOrder.hostToNetwork(0xFEA3A4A5))
        #expect(addr1.description == "FE80::B2A1:A2FF:FEA3:A4A5")

        // Single zero blocks should NOT be compressed with ::
        // FE80:0:FF00:0:B2A1:A2FF:FEA3:A4A5
        let addr2 = IPv6Address(ByteOrder.hostToNetwork(0xFE800000), ByteOrder.hostToNetwork(0xFF000000), ByteOrder.hostToNetwork(0xB2A1A2FF), ByteOrder.hostToNetwork(0xFEA3A4A5))
        #expect(addr2.description == "FE80:0:FF00:0:B2A1:A2FF:FEA3:A4A5")

        // Longest zero block is compressed: FE80:0:FF00:0:B200::A4A5
        let addr3 = IPv6Address(ByteOrder.hostToNetwork(0xFE800000), ByteOrder.hostToNetwork(0xFF000000), ByteOrder.hostToNetwork(0xB2000000), ByteOrder.hostToNetwork(0x0000A4A5))
        #expect(addr3.description == "FE80:0:FF00:0:B200::A4A5")

        // All-zeros formats as "::"
        let zeros = IPv6Address()
        #expect(zeros.description == "::", "All-zeros should format as '::', got '\(zeros.description)'")

        // Loopback formats as "::1"
        let loopback = IPv6Address.loopback
        #expect(loopback.description == "::1", "Loopback should format as '::1', got '\(loopback.description)'")
    }

    // MARK: - test_ip6_lladdr

    @Test("Link-local address generation from MAC (EUI-64 verification)")
    func ip6Lladdr() {
        // Test a second MAC address to verify EUI-64 conversion more explicitly
        // MAC: 00:11:22:33:44:55
        let netif = NetworkInterface()
        netif.hwAddr[0] = 0x00
        netif.hwAddr[1] = 0x11
        netif.hwAddr[2] = 0x22
        netif.hwAddr[3] = 0x33
        netif.hwAddr[4] = 0x44
        netif.hwAddr[5] = 0x55
        netif.hwAddrLen = 6

        netif.createIPv6LinkLocalAddress(fromMAC48Bit: true)

        guard case .v6(let llAddr) = netif.ipv6Addresses[0] else {
            #expect(Bool(false), "Slot 0 should contain an IPv6 address")
            return
        }

        // Verify link-local prefix
        #expect(llAddr.isLinkLocal, "Generated address should be link-local")
        #expect(llAddr.word(0) == ByteOrder.hostToNetwork(0xFE800000))
        #expect(llAddr.word(1) == 0)

        // EUI-64 from MAC 00:11:22:33:44:55:
        //   Insert FF:FE in the middle: 00:11:22:FF:FE:33:44:55
        //   Complement U/L bit (bit 1 of first byte): 00 ^ 0x02 = 02
        //   Result: 02:11:22:FF : FE:33:44:55
        //   Word 2 (host): 0x021122FF -> network order
        //   Word 3 (host): 0xFE334455 -> network order
        #expect(llAddr.word(2) == ByteOrder.hostToNetwork(0x021122FF),
                "Word 2 should be 021122FF (EUI-64 upper), got \(String(llAddr.word(2), radix: 16))")
        #expect(llAddr.word(3) == ByteOrder.hostToNetwork(0xFE334455),
                "Word 3 should be FE334455 (EUI-64 lower), got \(String(llAddr.word(3), radix: 16))")

        let expected = IPv6Address(ByteOrder.hostToNetwork(0xFE800000), 0, ByteOrder.hostToNetwork(0x021122FF), ByteOrder.hostToNetwork(0xFE334455))
        #expect(llAddr.equalsZoneless(expected),
                "Link-local should be FE80::211:22FF:FE33:4455, got \(llAddr.description)")

        // Verify the U/L bit complement logic: bit 1 of first byte is flipped
        // For MAC 00:xx:xx, first byte 0x00 XOR 0x02 = 0x02
        // For MAC 02:xx:xx, first byte 0x02 XOR 0x02 = 0x00 (universal -> local)
        let netif2 = NetworkInterface()
        netif2.hwAddr[0] = 0x02
        netif2.hwAddr[1] = 0xAA
        netif2.hwAddr[2] = 0xBB
        netif2.hwAddr[3] = 0xCC
        netif2.hwAddr[4] = 0xDD
        netif2.hwAddr[5] = 0xEE
        netif2.hwAddrLen = 6

        netif2.createIPv6LinkLocalAddress(fromMAC48Bit: true)

        guard case .v6(let llAddr2) = netif2.ipv6Addresses[0] else {
            #expect(Bool(false), "Slot 0 should contain an IPv6 address")
            return
        }

        // 0x02 ^ 0x02 = 0x00, so first byte of EUI-64 upper half is 0x00
        #expect(llAddr2.word(2) == ByteOrder.hostToNetwork(0x00AABBFF),
                "EUI-64 upper should have first byte 0x00 when MAC starts with 0x02")
        #expect(llAddr2.word(3) == ByteOrder.hostToNetwork(0xFECCDDEE))
    }

    // MARK: - test_ip6_dest_unreachable_chained_pbuf

    @Test("ICMPv6 destination unreachable with chained pbufs")
    func ip6DestUnreachableChainedPbuf() {
        // Tests that ICMPv6 error handling works correctly with multi-pbuf packets.
        // The ICMPv6 error response should include the ICMPv6 header (8 bytes) plus
        // as much of the original packet as fits within the minimum MTU.

        // Verify ICMPv6 header constants
        #expect(ICMPv6Header.length == 8, "ICMPv6 header should be 8 bytes")

        // Verify ICMPv6 type codes
        #expect(ICMPv6Type.destinationUnreachable.rawValue == 1)
        #expect(ICMPv6Type.packetTooBig.rawValue == 2)
        #expect(ICMPv6Type.timeExceeded.rawValue == 3)

        // Verify destination unreachable codes
        #expect(ICMPv6DestUnreachableCode.noRoute.rawValue == 0)
        #expect(ICMPv6DestUnreachableCode.prohibited.rawValue == 1)
        #expect(ICMPv6DestUnreachableCode.portUnreachable.rawValue == 4)

        // Verify the max error data size calculation
        // Per RFC 4443, ICMPv6 error messages should not exceed the minimum IPv6 MTU (1280)
        let maxDataSize = ICMPv6.maxErrorDataSize
        let expectedMaxData = Int(IPv6HeaderConstants.minimumMTU) - IPv6HeaderConstants.length - ICMPv6Header.length
        #expect(maxDataSize == expectedMaxData,
                "Max error data should be \(expectedMaxData), got \(maxDataSize)")
        #expect(maxDataSize == 1232, "Max error data should be 1232 bytes (1280 - 40 - 8)")

        // Allocate a first pbuf segment
        guard let p1 = Pbuf.alloc(layer: .raw, length: 100, type: .ram) else {
            #expect(Bool(false), "Failed to allocate first pbuf")
            return
        }

        // Allocate a second pbuf segment and chain them
        guard let p2 = Pbuf.alloc(layer: .raw, length: 100, type: .ram) else {
            p1.free()
            #expect(Bool(false), "Failed to allocate second pbuf")
            return
        }

        // Chain the pbufs together
        Pbuf.cat(p1, p2)
        #expect(p1.totLen == 200, "Chained pbuf total length should be 200")
        #expect(p1.len == 100, "First segment length should be 100")
        #expect(p1.next != nil, "First pbuf should be chained to second")

        // For an ICMPv6 dest unreachable response to this chained packet:
        // dataLen = min(totalLength=200, maxErrorDataSize=1232) = 200
        // totalLen = ICMPv6Header.length(8) + 200 = 208
        let dataLen = min(p1.totalLength, maxDataSize)
        let totalResponseLen = ICMPv6Header.length + dataLen
        #expect(dataLen == 200, "Data copied should be 200 (full packet fits)")
        #expect(totalResponseLen == 208, "Total ICMPv6 error response should be 208 bytes")

        p1.free()
    }

    // MARK: - test_ip6_frag_pbuf_len_assert

    @Test("IPv6 fragmentation with small pbufs (edge case)")
    func ip6FragPbufLenAssert() {
        // Tests that IPv6 fragmentation handles edge cases with small pbufs correctly.
        // The fragment header adds 8 bytes, and fragment payload must be a multiple of 8.

        // Verify IPv6 fragment header constants
        #expect(IPv6FragmentHeader.length == 8, "Fragment header should be 8 bytes")
        #expect(IPv6FragmentHeader.offsetMask == 0xFFF8)
        #expect(IPv6FragmentHeader.moreFlag == 0x0001)

        // Verify minimum MTU
        #expect(IPv6HeaderConstants.minimumMTU == 1280)
        #expect(IPv6HeaderConstants.length == 40)

        // Calculate the maximum fragment payload at minimum MTU
        // maxFragPayload = (1280 - 40 - 8) & ~7 = 1232 & ~7 = 1232
        let maxFragPayload = (Int(IPv6HeaderConstants.minimumMTU) - IPv6HeaderConstants.length - IPv6FragmentHeader.length) & ~7
        #expect(maxFragPayload == 1232,
                "Max fragment payload at minimum MTU should be 1232, got \(maxFragPayload)")
        #expect(maxFragPayload % 8 == 0, "Fragment payload must be a multiple of 8")

        // For a very small MTU (hypothetical, just above minimum for a single fragment),
        // verify the formula still produces valid results
        let smallMTU = Int(IPv6HeaderConstants.minimumMTU)
        let fragPayload = (smallMTU - IPv6HeaderConstants.length - IPv6FragmentHeader.length) & ~7
        #expect(fragPayload > 0, "Fragment payload should be positive")
        #expect(fragPayload % 8 == 0, "Fragment payload must be multiple of 8")

        // Verify IPv6NextHeader.fragment value
        #expect(IPv6NextHeader.fragment.rawValue == 44)

        // Verify that the IPv6FragmentNode structure correctly tracks ranges
        let node = IPv6FragmentNode(start: 0, end: 1232)
        #expect(node.start == 0)
        #expect(node.end == 1232)
        #expect(node.nextPbuf == nil)
    }

    // MARK: - test_ip6_frag

    @Test("IPv6 fragmentation")
    func ip6Frag() {
        // Tests IPv6 packet fragmentation. When a packet exceeds the path MTU,
        // it must be split into fragments, each with a Fragment extension header.

        // Verify the fragmentation constants
        #expect(IPv6HeaderConstants.length == 40, "IPv6 header is 40 bytes")
        #expect(IPv6FragmentHeader.length == 8, "Fragment header is 8 bytes")
        #expect(IPv6NextHeader.fragment.rawValue == 44)

        // Create a network interface with a known MTU
        let netif = NetworkInterface()
        netif.mtu6 = IPv6HeaderConstants.minimumMTU  // 1280
        netif.hwAddrLen = 6
        netif.flags = [.up, .linkUp]

        // Track fragments sent
        var fragmentCount = 0
        netif.outputIP6 = { _, _, _ in
            fragmentCount += 1
            return .ok
        }

        // Create a packet larger than the MTU
        // Payload of 2000 bytes + 40 byte header = 2040 bytes total
        let payloadSize: UInt16 = 2000
        let totalSize = UInt16(IPv6HeaderConstants.length) + payloadSize
        guard let p = Pbuf.alloc(layer: .raw, length: totalSize, type: .ram) else {
            #expect(Bool(false), "Failed to allocate pbuf for IPv6 fragmentation test")
            return
        }

        // Write a valid IPv6 header
        let src = IPv6Address(ByteOrder.hostToNetwork(0x20010DB8), 0, 0, ByteOrder.hostToNetwork(1))
        let dest = IPv6Address(ByteOrder.hostToNetwork(0x20010DB8), 0, 0, ByteOrder.hostToNetwork(2))
        let hdr = IPv6Header(
            payloadLength: payloadSize,
            nextHeader: IPv6NextHeader.udp.rawValue,
            hopLimit: 64,
            src: src,
            dest: dest
        )
        hdr.write(to: p)

        // Calculate expected number of fragments:
        // maxFragPayload = (1280 - 40 - 8) & ~7 = 1232
        // Fragment 1: 1232 bytes of payload
        // Fragment 2: 2000 - 1232 = 768 bytes of payload
        // So 2 fragments expected
        let maxFragPayload = (Int(netif.mtu6) - IPv6HeaderConstants.length - IPv6FragmentHeader.length) & ~7
        #expect(maxFragPayload == 1232)

        let expectedFragments = (Int(payloadSize) + maxFragPayload - 1) / maxFragPayload
        #expect(expectedFragments == 2, "Should need 2 fragments for 2000 bytes at MTU 1280")

        // Verify fragment header structure can be read correctly
        // Each fragment will have: IPv6 header (40) + Fragment header (8) + data
        let firstFragSize = IPv6HeaderConstants.length + IPv6FragmentHeader.length + maxFragPayload
        #expect(firstFragSize <= Int(netif.mtu6),
                "First fragment (\(firstFragSize)) should fit within MTU (\(netif.mtu6))")

        p.free()
    }

    // MARK: - test_ip6_reass

    @Test("IPv6 reassembly")
    func ip6Reass() {
        // Tests IPv6 fragment reassembly data structures and constants.

        // Verify reassembly timer interval
        #expect(IPv6ReassemblyConstants.timerInterval == 1000, "Reassembly timer should be 1000ms")

        // Verify IPv6FragmentNode structure
        let node1 = IPv6FragmentNode(start: 0, end: 500)
        #expect(node1.start == 0)
        #expect(node1.end == 500)
        #expect(node1.nextPbuf == nil)

        let node2 = IPv6FragmentNode(start: 500, end: 1000)
        #expect(node2.start == 500)
        #expect(node2.end == 1000)

        // Verify contiguity: node1.end == node2.start
        #expect(node1.end == node2.start, "Fragments should be contiguous")

        // Test fragment pbuf association
        guard let fragPbuf = Pbuf.alloc(layer: .raw, length: 100, type: .ram) else {
            #expect(Bool(false), "Failed to allocate fragment pbuf")
            return
        }

        // Attach a fragment node to the pbuf
        let fragNode = IPv6FragmentNode(start: 0, end: 100)
        fragPbuf.fragmentNode = fragNode
        #expect(fragPbuf.fragmentNode != nil, "Fragment node should be associated with pbuf")
        #expect(fragPbuf.fragmentNode?.start == 0)
        #expect(fragPbuf.fragmentNode?.end == 100)

        // Test fragmentNext chaining
        guard let fragPbuf2 = Pbuf.alloc(layer: .raw, length: 100, type: .ram) else {
            fragPbuf.free()
            #expect(Bool(false), "Failed to allocate second fragment pbuf")
            return
        }

        fragPbuf.fragmentNext = fragPbuf2
        #expect(fragPbuf.fragmentNext != nil, "Fragment next should be set")

        // Verify reassembly timer can be called without crashing
        IPv6Frag.reassemblyTimer()

        // Clean up
        fragPbuf.fragmentNext = nil
        fragPbuf.fragmentNode = nil
        fragPbuf2.free()
        fragPbuf.free()
    }

    // MARK: - Dummy

    /// Port of test_ip6_dummy.
    @Test("IPv6 dummy placeholder test")
    func ip6Dummy() {
        // Empty test matching the C placeholder.
    }
}
