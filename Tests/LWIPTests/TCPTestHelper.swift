//
//  TCPTestHelper.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
@testable import LWIP

// MARK: - TCP Test Constants

enum TCPTestConstants {
    static let localIP = IPv4Address(192, 168, 1, 1)
    static let remoteIP = IPv4Address(192, 168, 1, 2)
    static let netmask = IPv4Address(255, 255, 255, 0)
    static let remotePort: UInt16 = 0x100
    static let localPort: UInt16 = 0x101
}

// MARK: - TCP Test Counters

/// Tracks receive/error callbacks for testing.
final class TCPTestCounters {
    var recvCalls: Int = 0
    var recvedBytes: Int = 0
    var recvCallsAfterClose: Int = 0
    var recvedBytesAfterClose: Int = 0
    var closeCalls: Int = 0
    var errCalls: Int = 0
    var lastErr: LWIPError = .ok
    var expectedData: [UInt8]? = nil
    var expectedDataLen: Int = 0

    func reset() {
        recvCalls = 0
        recvedBytes = 0
        recvCallsAfterClose = 0
        recvedBytesAfterClose = 0
        closeCalls = 0
        errCalls = 0
        lastErr = .ok
        expectedData = nil
        expectedDataLen = 0
    }
}

// MARK: - TCP TX Test Counters

/// Tracks transmitted packets for testing.
final class TCPTxCounters {
    var numTxCalls: Int = 0
    var numTxBytes: Int = 0
    var copyTxPackets: Bool = false
    var txPackets: [Pbuf] = []

    func reset() {
        numTxCalls = 0
        numTxBytes = 0
        txPackets = []
    }
}

// MARK: - TCP Test Helper Functions

enum TCPTestHelper {
    /// Remove all TCP PCBs from all lists and clean up default netif.
    static func removeAll() {
        let tcp = TCPGlobal.shared
        while let pcb = tcp.activePCBs {
            tcp.removeActive(pcb)
            tcp.pcbPurge(pcb)
        }
        while let pcb = tcp.timeWaitPCBs {
            tcp.remove(pcb, list: &tcp.timeWaitPCBs)
            tcp.pcbPurge(pcb)
        }
        while let lpcb = tcp.listenPCBs {
            tcp.removeListen(lpcb)
        }
        while let pcb = tcp.boundPCBs {
            tcp.remove(pcb, list: &tcp.boundPCBs)
            tcp.pcbPurge(pcb)
        }
        // Clean up any remaining test netifs
        NetworkInterface.setDefault(nil)
    }

    /// Create a TCP segment for injection into a PCB's input path.
    static func createRxSegment(
        pcb: TCPControlBlock,
        data: [UInt8]?,
        dataLen: UInt16,
        seqnoOffset: UInt32,
        acknoOffset: UInt32,
        headerFlags: TCPHeaderFlags,
        window: UInt16 = UInt16(lwipConfig.tcpWnd)
    ) -> Pbuf? {
        return createSegment(
            srcIP: pcb.remoteIP,
            dstIP: pcb.localIP,
            srcPort: pcb.remotePort,
            dstPort: pcb.localPort,
            data: data,
            dataLen: dataLen,
            seqno: pcb.receiveNext &+ seqnoOffset,
            ackno: pcb.sendLastByteBuffered &+ 1 &+ acknoOffset,
            headerFlags: headerFlags,
            window: window
        )
    }

    /// Create a raw TCP/IP segment pbuf.
    static func createSegment(
        srcIP: IPAddress,
        dstIP: IPAddress,
        srcPort: UInt16,
        dstPort: UInt16,
        data: [UInt8]?,
        dataLen: UInt16,
        seqno: UInt32,
        ackno: UInt32,
        headerFlags: TCPHeaderFlags,
        window: UInt16
    ) -> Pbuf? {
        let tcpHdrLen = UInt16(MemoryLayout<TCPHeader>.size)
        let totalLen = tcpHdrLen + dataLen

        guard let p = Pbuf.alloc(layer: .transport, length: totalLen, type: .ram) else {
            return nil
        }

        // Build TCP header in network byte order.
        // TCPInput reads all fields as big-endian from the pbuf, so we must
        // store everything in big-endian (network) byte order.
        var hdr = TCPHeader()
        hdr.sourcePort = ByteOrder.hostToNetwork(srcPort)
        hdr.destinationPort = ByteOrder.hostToNetwork(dstPort)
        hdr.sequenceNumber = ByteOrder.hostToNetwork(seqno)
        hdr.acknowledgmentNumber = ByteOrder.hostToNetwork(ackno)
        // headerLengthReservedFlags must be big-endian on the wire
        let hdrLenFlags: UInt16 = (UInt16(5) << 12) | UInt16(headerFlags.rawValue)
        hdr.headerLengthReservedFlags = ByteOrder.hostToNetwork(hdrLenFlags)
        hdr.windowSize = ByteOrder.hostToNetwork(window)
        hdr.checksum = 0
        hdr.urgentPointer = 0

        // Copy header into pbuf
        withUnsafeBytes(of: &hdr) { headerBytes in
            p.payload.copyMemory(from: headerBytes.baseAddress!, byteCount: Int(tcpHdrLen))
        }

        // Copy data after header
        if let data = data, dataLen > 0 {
            let dataPtr = p.payload.advanced(by: Int(tcpHdrLen))
            data.withUnsafeBufferPointer { buf in
                dataPtr.copyMemory(from: buf.baseAddress!, byteCount: Int(dataLen))
            }
        }

        // Calculate TCP checksum over the pseudo-header + TCP segment
        let chksum = InetChecksum.checksumPseudo(
            p, proto: IPProtocolNumber.tcp,
            protoLen: p.totLen,
            src: srcIP, dest: dstIP
        )
        // Write the computed checksum into the TCP header's checksum field.
        // rawChecksum reads bytes in big-endian order, so store in big-endian.
        let checksumOffset = MemoryLayout<TCPHeader>.offset(of: \TCPHeader.checksum)!
        p.payload.storeBytes(of: chksum.bigEndian, toByteOffset: checksumOffset, as: UInt16.self)

        return p
    }

    /// Create a new PCB with test counters attached.
    static func newCountersPCB(counters: TCPTestCounters) -> TCPControlBlock? {
        guard let pcb = TCPGlobal.shared.new() else { return nil }

        pcb.receiveHandler = { pcb, pbuf, err in
            if let pbuf = pbuf {
                counters.recvCalls += 1
                counters.recvedBytes += Int(pbuf.totLen)
                TCPGlobal.shared.recved(pcb: pcb, len: pbuf.totLen)
                _ = Pbuf.free(pbuf)
            } else {
                counters.closeCalls += 1
            }
            return .ok
        }

        pcb.errorHandler = { err in
            counters.errCalls += 1
            counters.lastErr = err
        }

        return pcb
    }

    /// Initialize a test network interface with output counting.
    /// Properly adds the netif to the global list so TCP can route through it.
    @discardableResult
    static func initTestNetif(
        netif: NetworkInterface,
        txCounters: TCPTxCounters,
        ipAddr: IPv4Address,
        netmask: IPv4Address
    ) -> NetworkInterface {
        let initFn: NetifAPI.InitializationHandler = { netif in
            netif.name = (UInt8(ascii: "t"), UInt8(ascii: "x"))
            netif.mtu = 1500
            netif.hwAddrLen = 6
            netif.hwAddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
            netif.flags = [.up, .linkUp, .broadcast, .ethArp, .ethernet]
            netif.output = { netif, p, ipaddr in
                return netif.linkOutput?(netif, p) ?? .ok
            }
            netif.linkOutput = { netif, p in
                txCounters.numTxCalls += 1
                txCounters.numTxBytes += Int(p.totLen)
                if txCounters.copyTxPackets {
                    if let clone = Pbuf.clone(layer: .raw, type: .ram, source: p) {
                        txCounters.txPackets.append(clone)
                    }
                }
                return .ok
            }
            return .ok
        }

        let inputFn: NetifAPI.InputHandler = { p, netif in
            return .ok
        }

        NetworkInterface.add(netif, ipAddr: ipAddr, netmask: netmask, gateway: .any,
                 state: nil, initFn: initFn, inputFn: inputFn)
        netif.setUp()
        netif.setLinkUp()
        NetworkInterface.setDefault(netif)
        return netif
    }

    /// Remove and clean up a test netif.
    static func removeTestNetif(_ netif: NetworkInterface) {
        NetworkInterface.setDefault(nil)
        netif.remove()
    }

    /// Set up a PCB in a specific TCP state.
    static func setState(
        pcb: TCPControlBlock,
        state: TCPState,
        localIP: IPv4Address = TCPTestConstants.localIP,
        remoteIP: IPv4Address = TCPTestConstants.remoteIP,
        localPort: UInt16 = TCPTestConstants.localPort,
        remotePort: UInt16 = TCPTestConstants.remotePort
    ) {
        pcb.state = state
        pcb.localIP = .v4(localIP)
        pcb.remoteIP = .v4(remoteIP)
        pcb.localPort = localPort
        pcb.remotePort = remotePort

        let tcp = TCPGlobal.shared
        switch state {
        case .closed:
            break
        case .timeWait:
            tcp.register(pcb, list: &tcp.timeWaitPCBs)
        default:
            tcp.registerActive(pcb)
        }
    }

    /// Run the TCP fast timer and alternating slow timer.
    static func runTCPTimer() {
        TCPGlobal.shared.fastTmr()
        if TCPGlobal.shared.timerCounter % 2 == 0 {
            TCPGlobal.shared.slowTmr()
        }
        TCPGlobal.shared.timerCounter &+= 1
    }

    /// Inject a TCP segment directly into the TCP input path.
    /// This bypasses IP processing and feeds the segment directly to TCPInput.
    static func testTCPInput(
        _ p: Pbuf,
        srcIP: IPAddress,
        dstIP: IPAddress,
        netif: NetworkInterface
    ) {
        TCPInput.shared.input(pbuf: p, netif: netif, srcIP: srcIP, dstIP: dstIP)
    }

    /// Create and inject a TCP segment into a PCB's input path.
    static func injectRxSegment(
        pcb: TCPControlBlock,
        data: [UInt8]?,
        dataLen: UInt16,
        seqnoOffset: UInt32,
        acknoOffset: UInt32,
        headerFlags: TCPHeaderFlags,
        netif: NetworkInterface,
        window: UInt16 = UInt16(lwipConfig.tcpWnd)
    ) {
        guard let seg = createRxSegment(
            pcb: pcb, data: data, dataLen: dataLen,
            seqnoOffset: seqnoOffset, acknoOffset: acknoOffset,
            headerFlags: headerFlags, window: window
        ) else { return }

        testTCPInput(seg, srcIP: pcb.remoteIP, dstIP: pcb.localIP, netif: netif)
    }

    /// Count segments in a segment chain.
    static func segmentCount(_ head: TCPSegment?) -> Int {
        var count = 0
        var seg = head
        while seg != nil {
            count += 1
            seg = seg?.next
        }
        return count
    }

    /// Get sequence numbers from a segment chain.
    static func sequenceNumbers(_ head: TCPSegment?) -> [UInt32] {
        var seqnos: [UInt32] = []
        var seg = head
        while let s = seg {
            seqnos.append(s.sequenceNumber)
            seg = s.next
        }
        return seqnos
    }
}
