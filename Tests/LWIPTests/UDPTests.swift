//
//  UDPTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for UDP protocol control block management.
@Suite("UDP", .serialized)
struct UDPTests {

    /// Port of test_udp_new_remove.
    @Test("UDP PCB creation and removal")
    func newRemove() {
        let udp = UDPGlobal.shared
        let pcb = udp.new()

        #expect(pcb.localPort == 0)
        #expect(pcb.remotePort == 0)

        udp.remove(pcb)
    }

    /// Port of test_udp_broadcast_rx_with_2_netifs.
    @Test("UDP broadcast receive delivers to correct PCB with 2 netifs")
    func broadcastRxWith2Netifs() {
        let udp = UDPGlobal.shared
        let port: UInt16 = 12345

        let netif1 = NetworkInterface()
        let netif2 = NetworkInterface()
        let ip1 = IPv4Address(192, 168, 0, 1)
        let mask1 = IPv4Address(255, 255, 255, 0)
        let ip2 = IPv4Address(192, 168, 1, 1)
        let mask2 = IPv4Address(255, 255, 255, 0)

        let initFn1: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "n"), UInt8(ascii: "1"))
            netif.mtu = 1500
            netif.flags = [.up, .linkUp, .broadcast, .ethArp, .ethernet]
            return .ok
        }
        let initFn2: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "n"), UInt8(ascii: "2"))
            netif.mtu = 1500
            netif.flags = [.up, .linkUp, .broadcast, .ethArp, .ethernet]
            return .ok
        }
        let inputFn: NetifAPI.InputHandler = { _, _ in .ok }

        NetworkInterface.add(netif1, ipAddr: ip1, netmask: mask1, gateway: .any,
                 state: nil, initFn: initFn1, inputFn: inputFn)
        netif1.setUp()
        netif1.setLinkUp()

        NetworkInterface.add(netif2, ipAddr: ip2, netmask: mask2, gateway: .any,
                 state: nil, initFn: initFn2, inputFn: inputFn)
        netif2.setUp()
        netif2.setLinkUp()

        defer {
            netif1.remove()
            netif2.remove()
        }

        let pcb1 = udp.new()
        let pcb2 = udp.new()
        defer {
            udp.remove(pcb1)
            udp.remove(pcb2)
        }

        let err1 = udp.bind(pcb1, address: .v4(ip1), port: port)
        let err2 = udp.bind(pcb2, address: .v4(ip2), port: port)
        #expect(err1 == .ok)
        #expect(err2 == .ok)

        var rx1Count = 0
        var rx2Count = 0

        udp.recv(pcb1) { _, pbuf, _, _ in
            rx1Count += 1
            _ = Pbuf.free(pbuf)
        }
        udp.recv(pcb2) { _, pbuf, _, _ in
            rx2Count += 1
            _ = Pbuf.free(pbuf)
        }

        // Unicast to netif1's address
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: ip1) {
            let _ = IPDispatch.input(p, netif1)
            #expect(rx1Count == 1, "pcb1 should receive unicast to its address")
            #expect(rx2Count == 0, "pcb2 should not receive unicast to netif1")
        }
        rx1Count = 0; rx2Count = 0

        // Unicast to netif2's address
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: ip2) {
            let _ = IPDispatch.input(p, netif2)
            #expect(rx2Count == 1, "pcb2 should receive unicast to its address")
            #expect(rx1Count == 0, "pcb1 should not receive unicast to netif2")
        }
        rx1Count = 0; rx2Count = 0

        // Broadcast to netif1's subnet broadcast, input on netif2.
        let netif1Broadcast = IPv4Address(networkOrder: ip1.addr | ~mask1.addr)
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: netif1Broadcast) {
            let _ = IPDispatch.input(p, netif2)
            #expect(rx1Count == 1, "pcb1 should receive netif1-directed broadcast")
            #expect(rx2Count == 0, "pcb2 should not receive netif1-directed broadcast")
        }
        rx1Count = 0; rx2Count = 0

        // Broadcast to netif2's subnet broadcast, input on netif1.
        let netif2Broadcast = IPv4Address(networkOrder: ip2.addr | ~mask2.addr)
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: netif2Broadcast) {
            let _ = IPDispatch.input(p, netif1)
            #expect(rx2Count == 1, "pcb2 should receive netif2-directed broadcast")
            #expect(rx1Count == 0, "pcb1 should not receive netif2-directed broadcast")
        }
        rx1Count = 0; rx2Count = 0

        // Global broadcast to netif1
        let globalBroadcast = IPv4Address(255, 255, 255, 255)
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: globalBroadcast) {
            let _ = IPDispatch.input(p, netif1)
            #expect(rx1Count == 1, "pcb1 should receive global broadcast on netif1")
            #expect(rx2Count == 0, "pcb2 should not receive global broadcast on netif1")
        }
        rx1Count = 0; rx2Count = 0

        // Global broadcast to netif2
        if let p = createUDPTestPacket(payloadLen: 16, dstPort: port, dstAddr: globalBroadcast) {
            let _ = IPDispatch.input(p, netif2)
            #expect(rx2Count == 1, "pcb2 should receive global broadcast on netif2")
            #expect(rx1Count == 0, "pcb1 should not receive global broadcast on netif2")
        }
    }

    /// Port of test_udp_bind.
    @Test("UDP socket binding with various address types")
    func bind() {
        let udp = UDPGlobal.shared

        // Bind IPv4 and IPv6 on same port should succeed
        let pcb1 = udp.new()
        let pcb2 = udp.new()
        let err1 = udp.bind(pcb1, address: .v4(.any), port: 2105)
        let err2 = udp.bind(pcb2, address: .v6(.any), port: 2105)
        #expect(err1 == .ok)
        #expect(err2 == .ok)
        udp.remove(pcb1)
        udp.remove(pcb2)

        // Bind same IPv4 type on same port should fail
        let pcb3 = udp.new()
        let pcb4 = udp.new()
        let err3 = udp.bind(pcb3, address: .v4(.any), port: 2106)
        let err4 = udp.bind(pcb4, address: .v4(.any), port: 2106)
        #expect(err3 == .ok)
        #expect(err4 == .addressInUse)
        udp.remove(pcb3)
        udp.remove(pcb4)

        // Bind different IP addresses on same port should succeed
        let pcb5 = udp.new()
        let pcb6 = udp.new()
        let err5 = udp.bind(pcb5, address: .v4(IPv4Address(1, 2, 3, 4)), port: 2108)
        let err6 = udp.bind(pcb6, address: .v4(IPv4Address(4, 3, 2, 1)), port: 2108)
        #expect(err5 == .ok)
        #expect(err6 == .ok)
        udp.remove(pcb5)
        udp.remove(pcb6)

        // Bind same port with SO_REUSEADDR enabled on all contenders should succeed.
        let pcb7 = udp.new()
        let pcb8 = udp.new()
        pcb7.soOptions = SocketOptions.reuseAddr.rawValue
        pcb8.soOptions = SocketOptions.reuseAddr.rawValue
        let err7 = udp.bind(pcb7, address: .v4(.any), port: 2109)
        let err8 = udp.bind(pcb8, address: .v4(.any), port: 2109)
        #expect(err7 == .ok)
        #expect(err8 == .ok)
        udp.remove(pcb7)
        udp.remove(pcb8)
    }

    // MARK: - Helpers

    private func createUDPTestPacket(payloadLen: Int, dstPort: UInt16, dstAddr: IPv4Address) -> Pbuf? {
        let udpHdrLen = 8
        let ipHdrLen = 20
        let totalLen = ipHdrLen + udpHdrLen + payloadLen

        guard let p = Pbuf.alloc(layer: .raw, length: UInt16(totalLen), type: .ram) else {
            return nil
        }

        let srcAddr = IPv4Address(192, 168, 0, 100)
        let srcPort: UInt16 = 54321

        var ipHeader = IPv4Header()
        ipHeader.versionIHL = 0x45
        ipHeader.typeOfService = 0
        ipHeader.totalLength = UInt16(totalLen).bigEndian
        ipHeader.timeToLive = 64
        ipHeader.protocolNumber = IPProtocolNumber.udp
        ipHeader.src = srcAddr
        ipHeader.dest = dstAddr
        p.writeIPv4Header(ipHeader)
        ipHeader.checksum = InetChecksum.checksum(UnsafeRawPointer(p.payload), len: UInt16(ipHdrLen))
        p.writeIPv4Header(ipHeader)

        var udpBytes = [UInt8](repeating: 0, count: udpHdrLen)
        udpBytes[0] = UInt8(srcPort >> 8); udpBytes[1] = UInt8(srcPort & 0xFF)
        udpBytes[2] = UInt8(dstPort >> 8); udpBytes[3] = UInt8(dstPort & 0xFF)
        let udpLen = UInt16(udpHdrLen + payloadLen)
        udpBytes[4] = UInt8(udpLen >> 8); udpBytes[5] = UInt8(udpLen & 0xFF)

        let payload = [UInt8](repeating: 0xAA, count: payloadLen)

        p.writeBytes(udpBytes + payload, at: ipHdrLen)

        return p
    }
}
