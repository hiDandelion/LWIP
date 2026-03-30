//
//  SLIP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - SLIP Constants

/// SLIP special bytes
public enum SLIPByte {
    /// Start and end of every packet
    public static let end: UInt8     = 0xC0
    /// Escape character
    public static let esc: UInt8     = 0xDB
    /// Escaped END byte (after ESC)
    public static let escEnd: UInt8  = 0xDC
    /// Escaped ESC byte (after ESC)
    public static let escEsc: UInt8  = 0xDD
}

/// SLIP interface constants.
public extension SLIPInterface {
    /// Maximum SLIP frame size.
    static let maxFrameSize: UInt16 = 1500
}

// MARK: - SLIP Receive State

/// State machine states for SLIP reception
public enum SLIPRecvState: UInt8 {
    case normal = 0
    case escape = 1
}

// MARK: - Serial I/O Protocol

/// Protocol for serial I/O operations required by SLIP and PPPoS.
/// Platform-specific implementations must conform to this protocol.
public protocol SerialIO: AnyObject {
    /// Open a serial device by number
    func open(deviceNum: UInt8) -> Bool

    /// Send a single byte
    func send(_ byte: UInt8)

    /// Blocking read of up to `count` bytes. Returns number of bytes actually read.
    func read(into buffer: inout [UInt8], count: Int) -> Int

    /// Non-blocking read of up to `count` bytes. Returns number of bytes actually read.
    func tryRead(into buffer: inout [UInt8], count: Int) -> Int
}

// MARK: - SLIP Private Data

/// Private state for a SLIP network interface
public final class SLIPPrivate: @unchecked Sendable {
    /// Serial I/O handle
    public var serialDevice: SerialIO?
    /// Current receive pbuf (tail of chain being filled)
    public var currentPbuf: Pbuf?
    /// Head of receive pbuf chain
    public var chainHead: Pbuf?
    /// Receive state machine state
    public var state: SLIPRecvState = .normal
    /// Current write index within currentPbuf
    public var writeIndex: UInt16 = 0
    /// Total bytes received in current packet
    public var receivedBytes: UInt16 = 0
    /// Queue of completed packets (for ISR mode)
    public var rxPackets: Pbuf?

    public init() {}
}

// MARK: - SLIPInterface

/// SLIP (Serial Line Internet Protocol) network interface.
///
/// Provides IP connectivity over a serial line using byte-stuffing
/// encoding per RFC 1055. Supports three usage modes:
/// 1. RX thread that blocks on serial read
/// 2. Polling from main loop via poll()
/// 3. ISR-based reception with receivedByte()/processRxQueue()
public final class SLIPInterface: @unchecked Sendable {

    /// Private SLIP state
    public let priv = SLIPPrivate()
    /// The network interface
    public var netif: NetworkInterface?

    public init() {}

    // MARK: - Output

    /// Send a pbuf with SLIP encapsulation over the serial line.
    public func output(netif: NetworkInterface, pbuf: Pbuf) -> LWIPError {
        guard let sio = priv.serialDevice else { return .interfaceError }

        // Start delimiter
        sio.send(SLIPByte.end)

        // Encode each byte from the pbuf payload using raw pointer subscript
        let payloadPtr = pbuf.payload
        for i in 0..<Int(pbuf.totLen) {
            let c: UInt8 = payloadPtr[i]
            switch c {
            case SLIPByte.end:
                sio.send(SLIPByte.esc)
                sio.send(SLIPByte.escEnd)
            case SLIPByte.esc:
                sio.send(SLIPByte.esc)
                sio.send(SLIPByte.escEsc)
            default:
                sio.send(c)
            }
        }

        // End delimiter
        sio.send(SLIPByte.end)
        return .ok
    }

    /// IPv4 output wrapper (ignores destination IP since it's point-to-point)
    public func outputIPv4(netif: NetworkInterface, pbuf: Pbuf, ipaddr: IPv4Address) -> LWIPError {
        return output(netif: netif, pbuf: pbuf)
    }

    /// IPv6 output wrapper (ignores destination IP since it's point-to-point)
    public func outputIPv6(netif: NetworkInterface, pbuf: Pbuf, ipaddr: IPv6Address) -> LWIPError {
        return output(netif: netif, pbuf: pbuf)
    }

    // MARK: - Input (Byte-by-Byte)

    /// Process one received byte through the SLIP state machine.
    public func rxByte(_ c: UInt8) -> Pbuf? {
        var byte = c

        switch priv.state {
        case .normal:
            switch byte {
            case SLIPByte.end:
                if priv.receivedBytes > 0 {
                    // Complete packet received
                    let packet = priv.chainHead
                    priv.currentPbuf = nil
                    priv.chainHead = nil
                    priv.writeIndex = 0
                    priv.receivedBytes = 0
                    return packet
                }
                return nil
            case SLIPByte.esc:
                priv.state = .escape
                return nil
            default:
                break
            }

        case .escape:
            switch byte {
            case SLIPByte.escEnd:
                byte = SLIPByte.end
            case SLIPByte.escEsc:
                byte = SLIPByte.esc
            default:
                break
            }
            priv.state = .normal
        }

        // Store the byte
        if priv.currentPbuf == nil {
            // Allocate a new pbuf
            guard let newPbuf = Pbuf.alloc(layer: .raw, length: SLIPInterface.maxFrameSize, type: .pool) else {
                return nil
            }
            priv.currentPbuf = newPbuf

            if let head = priv.chainHead {
                Pbuf.cat(head, newPbuf)
            } else {
                priv.chainHead = newPbuf
            }
        }

        if priv.receivedBytes <= SLIPInterface.maxFrameSize {
            priv.currentPbuf?.setByte(at: priv.writeIndex, to: byte)
            priv.receivedBytes += 1
            priv.writeIndex += 1

            if let current = priv.currentPbuf, priv.writeIndex >= current.len {
                priv.writeIndex = 0
                priv.currentPbuf = current.next
            }
        }

        return nil
    }

    /// Process a received byte and pass completed packets to the netif input
    public func rxByteInput(_ c: UInt8) {
        if let p = rxByte(c) {
            if let netif = self.netif {
                _ = netif.input?(p, netif)
            }
        }
    }

    // MARK: - Initialization

    /// Initialize the SLIP network interface.
    public func initialize(netif: NetworkInterface, serialDevice: SerialIO, deviceNum: UInt8) -> LWIPError {
        self.netif = netif

        netif.name = (UInt8(ascii: "s"), UInt8(ascii: "l"))
        netif.mtu = SLIPInterface.maxFrameSize

        guard serialDevice.open(deviceNum: deviceNum) else {
            return .interfaceError
        }
        priv.serialDevice = serialDevice

        netif.linkOutput = { [weak self] netif, pbuf in
            self?.output(netif: netif, pbuf: pbuf) ?? .interfaceError
        }

        return .ok
    }

    // MARK: - Polling

    /// Poll the serial device for incoming data.
    public func poll() {
        guard let sio = priv.serialDevice else { return }
        var buf = [UInt8](repeating: 0, count: 1)
        while sio.tryRead(into: &buf, count: 1) > 0 {
            rxByteInput(buf[0])
        }
    }

    // MARK: - ISR Mode

    /// Process a single received byte in ISR mode.
    public func receivedByte(_ data: UInt8) {
        if let p = rxByte(data) {
            if priv.rxPackets == nil {
                priv.rxPackets = p
            } else {
                // Append to queue
                var tail = priv.rxPackets
                while tail?.next != nil { tail = tail?.next }
                tail?.next = p
            }
        }
    }

    /// Process multiple received bytes in ISR mode.
    public func receivedBytes(_ data: [UInt8]) {
        for byte in data {
            receivedByte(byte)
        }
    }

    /// Process queued packets from ISR reception.
    public func processRxQueue() {
        while let p = priv.rxPackets {
            priv.rxPackets = p.next
            p.next = nil
            if let netif = self.netif {
                _ = netif.input?(p, netif)
            }
        }
    }

    // MARK: - RX Thread

    /// Run the SLIP receive loop (blocking).
    public func rxLoop() {
        guard let sio = priv.serialDevice else { return }
        var buf = [UInt8](repeating: 0, count: 1)
        while true {
            if sio.read(into: &buf, count: 1) > 0 {
                rxByteInput(buf[0])
            }
        }
    }
}
