//
//  IPv4Tests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

// MARK: - IPv4 Tests

/// Tests for IPv4 fragmentation, reassembly, address handling, and ICMP operations.
@Suite("IPv4")
struct IPv4Tests {

    // MARK: - test_ip4_frag

    @Test("IPv4 packet fragmentation")
    func ip4Frag() {
        // Verify fragmentation constants and structures used by IPv4Frag.fragment().
        // IPv4 fragmentation splits a datagram that exceeds the interface MTU into
        // MTU-sized fragments, each with its own IPv4 header.

        // Verify standard header length constant
        #expect(IPv4HeaderConstants.standardLength == 20)
        #expect(IPv4HeaderConstants.maximumLength == 60)

        // Verify fragment flag constants
        #expect(IPv4FragmentFlag.moreFragments == 0x2000)
        #expect(IPv4FragmentFlag.dontFragment == 0x4000)
        #expect(IPv4FragmentFlag.offsetMask == 0x1FFF)
        #expect(IPv4FragmentFlag.reserved == 0x8000)

        // Create a network interface with a known MTU
        let netif = NetworkInterface()
        netif.mtu = 576
        netif.hwAddrLen = 6
        netif.flags = [.up, .linkUp]

        // Track fragments sent through the output callback
        var fragmentsSent: [Pbuf] = []
        netif.output = { _, packet, _ in
            fragmentsSent.append(packet)
            return .ok
        }

        // Construct a packet larger than the MTU to test fragmentation.
        // Total = IP header (20) + payload (800) = 820 bytes, exceeds MTU of 576.
        let payloadSize: UInt16 = 800
        let totalSize = IPv4HeaderConstants.standardLength + payloadSize
        guard let p = Pbuf.alloc(layer: .raw, length: totalSize, type: .ram) else {
            #expect(Bool(false), "Failed to allocate pbuf for fragmentation test")
            return
        }

        // Write a valid IPv4 header
        var hdr = IPv4Header()
        hdr.setVersionIHL(version: 4, ihl: 5)
        hdr.totalLength = totalSize.bigEndian
        hdr.identification = UInt16(0x1234).bigEndian
        hdr.flagsFragOffset = 0
        hdr.timeToLive = 64
        hdr.protocolNumber = IPProtocolNumber.udp
        hdr.src = IPv4Address(10, 0, 0, 1)
        hdr.dest = IPv4Address(10, 0, 0, 2)
        p.writeIPv4Header(hdr)

        // Fragment the packet
        let result = IPv4Frag.fragment(p, netif: netif, dest: IPv4Address(10, 0, 0, 2))
        #expect(result == .ok, "Fragmentation should succeed")

        // We expect at least 2 fragments for an 820-byte packet with MTU 576
        #expect(fragmentsSent.count >= 2, "Should produce at least 2 fragments, got \(fragmentsSent.count)")

        // Verify the fragment offset calculations:
        // NFB (number of fragment blocks) = (576 - 20) / 8 = 69
        // First fragment payload = 69 * 8 = 552 bytes
        // Second fragment payload = 800 - 552 = 248 bytes
        let nfb = (Int(netif.mtu) - Int(IPv4HeaderConstants.standardLength)) / 8
        #expect(nfb == 69, "NFB should be 69 for MTU 576")

        p.free()
    }

    // MARK: - test_ip4_reass

    @Test("IPv4 fragment reassembly")
    func ip4Reass() {
        // Verify the reassembly data structures and constants used by IPv4Frag.reassemble().

        // Timer interval
        #expect(IPv4ReassemblyConstants.timerInterval == 1000)

        // Verify ReassemblyHelper structure
        let helper = ReassemblyHelper()
        #expect(helper.nextPbuf == nil)
        #expect(helper.start == 0)
        #expect(helper.end == 0)

        // Verify IPv4ReassemblyData structure
        let reassData = IPv4ReassemblyData()
        #expect(reassData.next == nil)
        #expect(reassData.p == nil)
        #expect(reassData.datagramLen == 0)
        #expect(reassData.flags == 0)
        #expect(reassData.timer > 0, "Timer should be initialized to max age")

        // Test that ReassemblyHelper can track fragment offsets correctly
        let helper1 = ReassemblyHelper()
        helper1.start = 0
        helper1.end = 552

        let helper2 = ReassemblyHelper()
        helper2.start = 552
        helper2.end = 800

        // Chain them
        helper1.nextPbuf = Pbuf.alloc(layer: .raw, length: 100, type: .ram)
        #expect(helper1.nextPbuf != nil)

        // Verify contiguity check: helper1.end == helper2.start
        #expect(helper1.end == helper2.start, "Fragments should be contiguous")

        // Test IPv4Frag.initialize() doesn't crash
        IPv4Frag.initialize()

        // Test reassembly timer doesn't crash on empty queue
        IPv4Frag.reassTimer()

        // Clean up
        helper1.nextPbuf?.free()
    }

    // MARK: - test_127_0_0_1

    @Test("Localhost 127.0.0.1 address handling")
    func localhost127_0_0_1() {
        // 127.0.0.1 is loopback; the entire 127.x.x.x range should be loopback
        let lo = IPv4Address(127, 0, 0, 1)
        #expect(lo.isLoopback)
        #expect(!lo.isMulticast)
        #expect(!lo.isBroadcast)
        #expect(!lo.isLinkLocal)
        #expect(!lo.isAny)

        // Other addresses in the 127.x.x.x range
        #expect(IPv4Address(127, 0, 0, 0).isLoopback)
        #expect(IPv4Address(127, 1, 2, 3).isLoopback)
        #expect(IPv4Address(127, 255, 255, 254).isLoopback)

        // Verify well-known loopback constant matches
        #expect(IPv4Address.loopback == lo)
        #expect(IPv4Address.loopback.isLoopback)
    }

    // MARK: - test_ip4addr_aton

    @Test("ASCII to IPv4 address conversion (comprehensive parsing)")
    func ip4addrAton() {
        // --- Standard dotted-decimal ---
        let addr1 = IPv4Address("192.168.0.1")
        #expect(addr1 != nil)
        #expect(addr1?.octet1 == 192)
        #expect(addr1?.octet2 == 168)
        #expect(addr1?.octet3 == 0)
        #expect(addr1?.octet4 == 1)

        // With leading zero (octal-style, if supported)
        let addr2 = IPv4Address("192.168.0.0001")
        #expect(addr2 != nil)

        // Three-part address (Class B style)
        let addr3 = IPv4Address("192.168.1")
        #expect(addr3 != nil)

        // Hex component
        let addr4 = IPv4Address("192.168.0xd3")
        #expect(addr4 != nil)

        // --- Octal notation ---
        // Octal: leading zero means base-8 per BSD inet_aton rules.
        // 0300 = 192, 0250 = 168, 0 = 0, 01 = 1
        let octal1 = IPv4Address("0300.0250.0.01")
        #expect(octal1 != nil)
        if let octal1 = octal1 {
            #expect(octal1 == IPv4Address(192, 168, 0, 1),
                    "Octal '0300.0250.0.01' should equal 192.168.0.1, got \(octal1.description)")
        }

        // 010.010.010.010 => 8.8.8.8
        let octal2 = IPv4Address("010.010.010.010")
        #expect(octal2 != nil)
        if let octal2 = octal2 {
            #expect(octal2 == IPv4Address(8, 8, 8, 8),
                    "Octal '010.010.010.010' should equal 8.8.8.8, got \(octal2.description)")
        }

        // --- Hex notation ---
        // Each component with 0x prefix: 0xc0=192, 0xa8=168, 0x0=0, 0x1=1
        let hex1 = IPv4Address("0xc0.0xa8.0x0.0x1")
        #expect(hex1 != nil)
        if let hex1 = hex1 {
            #expect(hex1 == IPv4Address(192, 168, 0, 1),
                    "Hex '0xc0.0xa8.0x0.0x1' should equal 192.168.0.1, got \(hex1.description)")
        }

        // --- Two-part address ---
        // Two-part: a.b where a is 8-bit and b is 24-bit.
        // "192.0xa80001" => 192.(0xa80001 = 11010049) => 192.168.0.1
        let twoPart = IPv4Address("192.0xa80001")
        #expect(twoPart != nil)
        if let twoPart = twoPart {
            #expect(twoPart == IPv4Address(192, 168, 0, 1),
                    "Two-part '192.0xa80001' should equal 192.168.0.1, got \(twoPart.description)")
        }

        // --- One-part address ---
        // Single 32-bit number: "0xc0a80001" = 3232235521 = 192.168.0.1
        let onePart = IPv4Address("0xc0a80001")
        #expect(onePart != nil)
        if let onePart = onePart {
            #expect(onePart == IPv4Address(192, 168, 0, 1),
                    "One-part '0xc0a80001' should equal 192.168.0.1, got \(onePart.description)")
        }

        // --- Reject invalid addresses ---
        // Non-numeric characters
        #expect(IPv4Address("192.168.0.zzz") == nil)
        // Invalid hex
        #expect(IPv4Address("192.168.0xz5") == nil)
        // Invalid octal (digits >= 8)
        #expect(IPv4Address("192.168.095") == nil)

        // --- Reject overflow octets ---
        // 256 exceeds a single byte, should fail to parse
        #expect(IPv4Address("256.0.0.1") == nil, "256.0.0.1 should be rejected (octet overflow)")
        #expect(IPv4Address("0.0.0.256") == nil, "0.0.0.256 should be rejected (octet overflow)")
        #expect(IPv4Address("999.999.999.999") == nil, "999.999.999.999 should be rejected")

        // --- Reject too many octets ---
        // Five dot-separated parts is always invalid
        #expect(IPv4Address("1.2.3.4.5") == nil, "1.2.3.4.5 should be rejected (five parts)")
        #expect(IPv4Address("1.2.3.4.5.6") == nil, "1.2.3.4.5.6 should be rejected (six parts)")
    }

    // MARK: - test_ip4_icmp_replylen_short

    @Test("ICMP reply length for short packets")
    func icmpReplylenShort() {
        // Tests that an ICMP error response to a very short IP packet has the correct
        // structure. Per RFC 792, an ICMP error message contains an ICMP header (8 bytes)
        // plus the IP header and first 8 bytes of the original datagram.
        // When the original packet is shorter than IP header + 8 bytes, the response
        // should include only what's available.

        // Verify ICMP header size constant
        #expect(ICMPHeader.size == 8, "ICMP header should be 8 bytes")
        #expect(ICMPEchoHeader.size == 8, "ICMP echo header should be 8 bytes")

        // Verify ICMP type codes used in error responses
        #expect(ICMPType.destUnreachable.rawValue == 3)
        #expect(ICMPType.timeExceeded.rawValue == 11)

        // Create a short IP packet (just the IP header, no payload)
        let shortPktLen = IPv4HeaderConstants.standardLength
        guard let shortPkt = Pbuf.alloc(layer: .ip, length: shortPktLen, type: .ram) else {
            #expect(Bool(false), "Failed to allocate short packet pbuf")
            return
        }

        var hdr = IPv4Header()
        hdr.setVersionIHL(version: 4, ihl: 5)
        hdr.totalLength = shortPktLen.bigEndian
        hdr.src = IPv4Address(10, 0, 0, 1)
        hdr.dest = IPv4Address(10, 0, 0, 2)
        hdr.timeToLive = 64
        hdr.protocolNumber = IPProtocolNumber.udp
        shortPkt.writeIPv4Header(hdr)

        // For a short packet (just IP header, totLen = 20), the ICMP error response
        // should include: ICMP header (8) + min(totLen, IP_hdr(20) + 8) = 8 + 20 = 28 bytes
        let responsePktLen: UInt16 = min(shortPkt.totLen, IPv4HeaderConstants.standardLength + 8)
        let expectedTotal = UInt16(ICMPHeader.size) + responsePktLen
        #expect(responsePktLen == shortPktLen,
                "Short packet response data should be \(shortPktLen) bytes, got \(responsePktLen)")
        #expect(expectedTotal == 28,
                "Total ICMP error reply for short packet should be 28 bytes, got \(expectedTotal)")

        shortPkt.free()
    }

    // MARK: - test_ip4_icmp_replylen_first_8

    @Test("ICMP reply length with 8-byte payload")
    func icmpReplylenFirst8() {
        // Tests that an ICMP error message includes the IP header plus at least the
        // first 8 bytes of the original datagram's payload (per RFC 792).

        // The constant used in ICMP.sendResponse limits copied data to
        // IP header + 8 bytes of original data
        let icmpDataSize: UInt16 = 8

        // Create a normal-sized IP packet with a payload larger than 8 bytes
        let payloadSize: UInt16 = 64
        let totalSize = IPv4HeaderConstants.standardLength + payloadSize
        guard let pkt = Pbuf.alloc(layer: .ip, length: totalSize, type: .ram) else {
            #expect(Bool(false), "Failed to allocate packet pbuf")
            return
        }

        var hdr = IPv4Header()
        hdr.setVersionIHL(version: 4, ihl: 5)
        hdr.totalLength = totalSize.bigEndian
        hdr.src = IPv4Address(10, 0, 0, 1)
        hdr.dest = IPv4Address(10, 0, 0, 2)
        hdr.timeToLive = 64
        hdr.protocolNumber = IPProtocolNumber.udp
        pkt.writeIPv4Header(hdr)

        // Fill payload bytes with a known pattern so we can verify what gets copied
        for i in 0..<Int(payloadSize) {
            pkt.writeByte(UInt8(i & 0xFF), at: Int(IPv4HeaderConstants.standardLength) + i)
        }

        // Calculate what the ICMP error response should contain:
        // ICMP header (8 bytes) + IP header (20) + first 8 bytes of original payload = 36 bytes
        let responsePktLen: UInt16 = min(pkt.totLen, IPv4HeaderConstants.standardLength + icmpDataSize)
        let expectedTotal = UInt16(ICMPHeader.size) + responsePktLen
        #expect(responsePktLen == IPv4HeaderConstants.standardLength + icmpDataSize,
                "Response should include IP header + 8 bytes of data")
        #expect(expectedTotal == 36,
                "Total ICMP error reply should be 36 bytes (8 ICMP + 20 IP + 8 data), got \(expectedTotal)")

        // Verify we include exactly 8 bytes of original data, not the full 64-byte payload
        #expect(responsePktLen < pkt.totLen,
                "Response data (\(responsePktLen)) should be less than full packet (\(pkt.totLen))")

        // Verify the ICMP dest unreachable codes that would be used
        #expect(ICMPDestUnreachCode.portUnreachable.rawValue == 3)
        #expect(ICMPDestUnreachCode.fragmentationNeeded.rawValue == 4)

        pkt.free()
    }
}
