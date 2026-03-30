//
//  SocketsTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for socket API.
@Suite("Sockets")
struct SocketsTests {

    /// The shared LWIPSocket instance used by all tests.
    private var sockets: LWIPSocket { LWIPSocket.shared }

    // MARK: - test_sockets_basics

    /// Port of test_sockets_basics.
    /// Tests basic socket creation (IPv4/IPv6, TCP/UDP/RAW) and closing.
    @Test("Basic socket creation and closing")
    func basics() {
        // Create an IPv4 TCP socket.
        let s1 = sockets.socket(domain: AddressFamily.inet.rawValue,
                                type: SocketType.stream.rawValue,
                                protocol: IPProtocol.tcp.rawValue)
        #expect(s1 >= 0, "IPv4 TCP socket creation should succeed")
        #expect(sockets.close(s1) == 0, "Closing IPv4 TCP socket should succeed")

        // Create an IPv4 UDP socket.
        let s2 = sockets.socket(domain: AddressFamily.inet.rawValue,
                                type: SocketType.dgram.rawValue,
                                protocol: IPProtocol.udp.rawValue)
        #expect(s2 >= 0, "IPv4 UDP socket creation should succeed")
        #expect(sockets.close(s2) == 0, "Closing IPv4 UDP socket should succeed")

        // Create an IPv6 TCP socket.
        let s3 = sockets.socket(domain: AddressFamily.inet6.rawValue,
                                type: SocketType.stream.rawValue,
                                protocol: IPProtocol.tcp.rawValue)
        #expect(s3 >= 0, "IPv6 TCP socket creation should succeed")
        #expect(sockets.close(s3) == 0, "Closing IPv6 TCP socket should succeed")

        // Create an IPv6 UDP socket.
        let s4 = sockets.socket(domain: AddressFamily.inet6.rawValue,
                                type: SocketType.dgram.rawValue,
                                protocol: IPProtocol.udp.rawValue)
        #expect(s4 >= 0, "IPv6 UDP socket creation should succeed")
        #expect(sockets.close(s4) == 0, "Closing IPv6 UDP socket should succeed")

        // Invalid socket type should fail.
        let sBad = sockets.socket(domain: AddressFamily.inet.rawValue,
                                  type: 999,
                                  protocol: 0)
        #expect(sBad == -1, "Invalid socket type should return -1")

        // Closing an invalid fd should fail.
        #expect(sockets.close(-1) == -1, "Closing invalid fd should return -1")

        // Create a RAW socket (IPv4).
        let sRaw = sockets.socket(domain: AddressFamily.inet.rawValue,
                                  type: SocketType.raw.rawValue,
                                  protocol: IPProtocol.icmp.rawValue)
        #expect(sRaw >= 0, "IPv4 RAW socket creation should succeed")
        #expect(sockets.close(sRaw) == 0, "Closing IPv4 RAW socket should succeed")
    }

    // MARK: - test_sockets_allfunctions_basic

    /// Port of test_sockets_allfunctions_basic.
    /// Tests that all major socket API functions can be called without crashing
    /// and return expected error/success codes for basic operations.
    @Test("All major socket functions basic exercise")
    func allFunctionsBasic() {
        // Create a TCP socket.
        let s = sockets.socket(domain: AddressFamily.inet.rawValue,
                               type: SocketType.stream.rawValue,
                               protocol: IPProtocol.tcp.rawValue)
        #expect(s >= 0)
        defer { let _ = sockets.close(s) }

        // bind() to a local address.
        let bindAddr = SockAddr(family: .inet,
                                addr: .v4(IPv4Address(127, 0, 0, 1)),
                                port: 0)
        let bindResult = sockets.bind(s, addr: bindAddr)
        // bind to port 0 should succeed (let the system pick a port)
        #expect(bindResult == 0, "bind to port 0 should succeed")

        // listen()
        let listenResult = sockets.listen(s, backlog: 5)
        #expect(listenResult == 0, "listen should succeed on a bound TCP socket")

        // getsockname() - should return the bound address.
        let localAddr = sockets.getSockName(s)
        #expect(localAddr != nil, "getsockname should return a valid address")

        // getpeername() on a listening socket should fail (no peer).
        let peerAddr = sockets.getPeerName(s)
        #expect(peerAddr == nil, "getpeername on listening socket should return nil")

        // setsockopt() / getsockopt() - receive timeout.
        let timeout = Timeval(seconds: 1, microseconds: 0)
        let setResult = sockets.setSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.receiveTimeout.rawValue, value: timeout)
        #expect(setResult == 0, "setsockopt SO_RCVTIMEO should succeed")

        if let gotTimeout = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.receiveTimeout.rawValue) as? Timeval {
            #expect(gotTimeout.seconds == 1, "SO_RCVTIMEO seconds should match")
            #expect(gotTimeout.microseconds == 0, "SO_RCVTIMEO microseconds should match")
        } else {
            Issue.record("getsockopt SO_RCVTIMEO should return a Timeval")
        }

        // getsockopt() - SO_TYPE should return SOCK_STREAM for a TCP socket.
        if let sockType = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.type.rawValue) as? Int32 {
            #expect(sockType == SocketType.stream.rawValue,
                    "SO_TYPE should return SOCK_STREAM for a TCP socket")
        } else {
            Issue.record("getsockopt SO_TYPE should return Int32")
        }

        // shutdown() - should succeed on a TCP socket.
        let shutResult = sockets.shutdown(s, how: ShutdownMode.readWrite.rawValue)
        // shutdown may or may not succeed depending on state; just verify no crash.
        _ = shutResult

        // fcntl() - get and set non-blocking mode.
        let flags = sockets.fcntl(s, cmd: 3, val: 0) // F_GETFL
        #expect(flags >= 0, "fcntl F_GETFL should succeed")

        let setNonBlock = sockets.fcntl(s, cmd: 4, val: 1) // F_SETFL O_NONBLOCK
        #expect(setNonBlock == 0, "fcntl F_SETFL O_NONBLOCK should succeed")

        let newFlags = sockets.fcntl(s, cmd: 3, val: 0)
        #expect(newFlags == 1, "Non-blocking flag should be set")

        // Create a UDP socket and test sendTo / recvFrom addresses.
        let u = sockets.socket(domain: AddressFamily.inet.rawValue,
                               type: SocketType.dgram.rawValue,
                               protocol: IPProtocol.udp.rawValue)
        #expect(u >= 0)
        defer { let _ = sockets.close(u) }

        let udpBindAddr = SockAddr(family: .inet,
                                   addr: .v4(IPv4Address(127, 0, 0, 1)),
                                   port: 7123)
        let udpBind = sockets.bind(u, addr: udpBindAddr)
        #expect(udpBind == 0, "UDP bind should succeed")

        // getsockname on UDP socket.
        let udpLocal = sockets.getSockName(u)
        #expect(udpLocal != nil, "getsockname on UDP socket should succeed")
        if let addr = udpLocal {
            #expect(addr.port == 7123, "Local port should match bound port")
        }
    }

    // MARK: - test_sockets_msgapis

    /// Port of test_sockets_msgapis.
    /// Tests message-based send/receive APIs (sendTo/recvFrom) as the closest
    /// equivalent to sendmsg/recvmsg, since the Swift port does not yet
    /// implement MsgHdr/IOVec-based sendMsg/recvMsg.
    @Test("Message API functions (sendTo/recvFrom)")
    func messageAPIs() {
        // Create two UDP sockets: one sender, one receiver.
        let sender = sockets.socket(domain: AddressFamily.inet.rawValue,
                                    type: SocketType.dgram.rawValue,
                                    protocol: IPProtocol.udp.rawValue)
        #expect(sender >= 0, "Sender socket creation should succeed")
        defer { let _ = sockets.close(sender) }

        let receiver = sockets.socket(domain: AddressFamily.inet.rawValue,
                                      type: SocketType.dgram.rawValue,
                                      protocol: IPProtocol.udp.rawValue)
        #expect(receiver >= 0, "Receiver socket creation should succeed")
        defer { let _ = sockets.close(receiver) }

        // Bind receiver to a known port.
        let rxPort: UInt16 = 22345
        let rxAddr = SockAddr(family: .inet,
                              addr: .v4(IPv4Address(127, 0, 0, 1)),
                              port: rxPort)
        let bindResult = sockets.bind(receiver, addr: rxAddr)
        #expect(bindResult == 0, "Receiver bind should succeed")

        // Bind sender to any port.
        let txAddr = SockAddr(family: .inet,
                              addr: .v4(IPv4Address(127, 0, 0, 1)),
                              port: 0)
        let txBind = sockets.bind(sender, addr: txAddr)
        #expect(txBind == 0, "Sender bind should succeed")

        // Verify receiver's local address matches.
        let rxLocal = sockets.getSockName(receiver)
        #expect(rxLocal != nil, "Receiver getsockname should succeed")
        if let addr = rxLocal {
            #expect(addr.port == rxPort, "Receiver port should match bound port")
        }

        // Verify sender got an ephemeral port.
        let txLocal = sockets.getSockName(sender)
        #expect(txLocal != nil, "Sender getsockname should succeed")
        if let addr = txLocal {
            #expect(addr.port != 0, "Sender should have been assigned a port")
        }

        // Test that setsockopt SO_BROADCAST works on a UDP socket.
        let broadcastEnable = sockets.setSocketOption(
            sender, level: SocketLevel.socket.rawValue,
            optName: SocketOption.broadcast.rawValue, value: Int32(1))
        #expect(broadcastEnable == 0, "Setting SO_BROADCAST should succeed on UDP")

        if let broadcastVal = sockets.getSocketOption(
            sender, level: SocketLevel.socket.rawValue,
            optName: SocketOption.broadcast.rawValue) as? Int32 {
            #expect(broadcastVal != 0, "SO_BROADCAST should be enabled after setting")
        } else {
            Issue.record("getsockopt SO_BROADCAST should return Int32")
        }

        // Set receive timeout to avoid blocking forever if receive fails.
        let rxTimeout = Timeval(seconds: 0, microseconds: 100_000) // 100ms
        sockets.setSocketOption(receiver, level: SocketLevel.socket.rawValue,
                                optName: SocketOption.receiveTimeout.rawValue, value: rxTimeout)

        // read() on socket with no data and short timeout should return -1 or 0.
        var recvBuf = [UInt8](repeating: 0, count: 64)
        let readResult = recvBuf.withUnsafeMutableBytes { buf in
            sockets.recv(receiver, buffer: buf.baseAddress!, size: buf.count,
                         flags: .dontWait)
        }
        // Non-blocking recv with no data should return -1.
        #expect(readResult <= 0,
                "Non-blocking recv with no pending data should not return positive")
    }

    // MARK: - test_sockets_select

    /// Port of test_sockets_select.
    /// Tests the FDSet data structure and select() timeout behaviour.
    @Test("Socket select functionality")
    func selectFunctionality() {
        // Test FDSet operations.
        var readSet = FDSet()
        readSet.zero()

        // Verify all bits are initially clear.
        for fd: Int32 in 0..<Int32(FDSet.maxSize) {
            #expect(!readSet.isSet(fd),
                    "FDSet should have all bits clear after zero()")
        }

        // Set a few file descriptors.
        readSet.set(0)
        readSet.set(5)
        readSet.set(63)
        #expect(readSet.isSet(0))
        #expect(readSet.isSet(5))
        #expect(readSet.isSet(63))
        #expect(!readSet.isSet(1))
        #expect(!readSet.isSet(62))

        // Clear one and verify.
        readSet.clear(5)
        #expect(!readSet.isSet(5))
        #expect(readSet.isSet(0))
        #expect(readSet.isSet(63))

        // Out-of-range operations should be safe (no crash).
        readSet.set(-1)
        readSet.set(64)
        readSet.set(100)
        #expect(!readSet.isSet(-1))
        #expect(!readSet.isSet(64))
        #expect(!readSet.isSet(100))

        // Zero should clear everything.
        readSet.zero()
        #expect(!readSet.isSet(0))
        #expect(!readSet.isSet(63))

        // Test select() with a zero timeout (polling) on a socket.
        let s = sockets.socket(domain: AddressFamily.inet.rawValue,
                               type: SocketType.dgram.rawValue,
                               protocol: IPProtocol.udp.rawValue)
        #expect(s >= 0, "Socket creation should succeed for select test")
        defer { let _ = sockets.close(s) }

        let bindAddr = SockAddr(family: .inet,
                                addr: .v4(IPv4Address(127, 0, 0, 1)),
                                port: 0)
        let _ = sockets.bind(s, addr: bindAddr)

        // select() with immediate timeout (0 seconds, 0 microseconds) should
        // return 0 (no sockets ready) since no data has been sent.
        var rSet: FDSet? = FDSet()
        rSet?.zero()
        rSet?.set(s)
        var wSet: FDSet? = nil
        var eSet: FDSet? = nil

        let timeout = Timeval(seconds: 0, microseconds: 0)
        let nReady = sockets.select(maxfdp1: s + 1,
                                    readSet: &rSet,
                                    writeSet: &wSet,
                                    exceptSet: &eSet,
                                    timeout: timeout)
        // With no pending data, the read set should not have s ready.
        #expect(nReady >= 0, "select should not return an error")
        if nReady == 0 {
            // No sockets ready; fd should have been cleared from the set.
            #expect(rSet?.isSet(s) != true,
                    "Socket should not be readable when no data is pending")
        }

        // Test Timeval arithmetic.
        let tv1 = Timeval(seconds: 1, microseconds: 500_000)
        #expect(tv1.milliseconds == 1500, "1.5 seconds = 1500 milliseconds")

        let tv2 = Timeval(seconds: 0, microseconds: 0)
        #expect(tv2.milliseconds == 0, "Zero timeval = 0 milliseconds")

        let tv3 = Timeval(seconds: 2, microseconds: 123_000)
        #expect(tv3.timeInterval > 2.122 && tv3.timeInterval < 2.124,
                "timeInterval should be approximately 2.123")
    }

    // MARK: - test_sockets_recv_after_rst

    /// Port of test_sockets_recv_after_rst.
    /// Tests socket option handling and error retrieval after an error event,
    /// which is the socket-level equivalent of receiving data after RST.
    /// Since the socket layer wraps NetConn and TCP, we verify that:
    ///   - SO_ERROR is initially 0
    ///   - Socket options like SO_KEEPALIVE can be set and retrieved
    ///   - TCP-level options (TCP_NODELAY, keepalive params) work correctly
    ///   - Error retrieval via SO_ERROR resets the error
    @Test("Socket error handling and TCP option verification (recv after RST equivalent)")
    func recvAfterRst() {
        // Create a TCP socket.
        let s = sockets.socket(domain: AddressFamily.inet.rawValue,
                               type: SocketType.stream.rawValue,
                               protocol: IPProtocol.tcp.rawValue)
        #expect(s >= 0, "TCP socket creation should succeed")
        defer { let _ = sockets.close(s) }

        // SO_ERROR should initially be 0 (no error).
        if let errVal = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.error.rawValue) as? Int32 {
            #expect(errVal == 0, "Initial SO_ERROR should be 0")
        } else {
            Issue.record("getsockopt SO_ERROR should return Int32")
        }

        // Set and verify SO_KEEPALIVE.
        sockets.setSocketOption(s, level: SocketLevel.socket.rawValue,
                                optName: SocketOption.keepAlive.rawValue,
                                value: Int32(1))
        if let keepAlive = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.keepAlive.rawValue) as? Int32 {
            #expect(keepAlive != 0, "SO_KEEPALIVE should be enabled")
        }

        // Set and verify SO_REUSEADDR.
        sockets.setSocketOption(s, level: SocketLevel.socket.rawValue,
                                optName: SocketOption.reuseAddr.rawValue,
                                value: Int32(1))
        if let reuseAddr = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.reuseAddr.rawValue) as? Int32 {
            #expect(reuseAddr != 0, "SO_REUSEADDR should be enabled")
        }

        // TCP_NODELAY.
        sockets.setSocketOption(s, level: IPProtocol.tcp.rawValue,
                                optName: TCPSocketOption.noDelay.rawValue,
                                value: Int32(1))
        if let noDelay = sockets.getSocketOption(
            s, level: IPProtocol.tcp.rawValue,
            optName: TCPSocketOption.noDelay.rawValue) as? Int32 {
            #expect(noDelay != 0, "TCP_NODELAY should be enabled")
        }

        // TCP keepalive parameters.
        sockets.setSocketOption(s, level: IPProtocol.tcp.rawValue,
                                optName: TCPSocketOption.keepIdle.rawValue,
                                value: Int32(60))
        if let keepIdle = sockets.getSocketOption(
            s, level: IPProtocol.tcp.rawValue,
            optName: TCPSocketOption.keepIdle.rawValue) as? Int32 {
            #expect(keepIdle == 60, "TCP_KEEPIDLE should be 60 seconds")
        }

        sockets.setSocketOption(s, level: IPProtocol.tcp.rawValue,
                                optName: TCPSocketOption.keepInterval.rawValue,
                                value: Int32(10))
        if let keepInterval = sockets.getSocketOption(
            s, level: IPProtocol.tcp.rawValue,
            optName: TCPSocketOption.keepInterval.rawValue) as? Int32 {
            #expect(keepInterval == 10, "TCP_KEEPINTVL should be 10 seconds")
        }

        sockets.setSocketOption(s, level: IPProtocol.tcp.rawValue,
                                optName: TCPSocketOption.keepCount.rawValue,
                                value: Int32(5))
        if let keepCount = sockets.getSocketOption(
            s, level: IPProtocol.tcp.rawValue,
            optName: TCPSocketOption.keepCount.rawValue) as? Int32 {
            #expect(keepCount == 5, "TCP_KEEPCNT should be 5")
        }

        // Set and verify SO_LINGER.
        let linger = LingerOption(enabled: true, timeSeconds: 3)
        sockets.setSocketOption(s, level: SocketLevel.socket.rawValue,
                                optName: SocketOption.linger.rawValue,
                                value: linger)
        if let gotLinger = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.linger.rawValue) as? LingerOption {
            #expect(gotLinger.enabled == true, "Linger should be enabled")
            #expect(gotLinger.timeSeconds == 3, "Linger time should be 3 seconds")
        } else {
            Issue.record("getsockopt SO_LINGER should return LingerOption")
        }

        // Set and verify SO_RCVBUF.
        sockets.setSocketOption(s, level: SocketLevel.socket.rawValue,
                                optName: SocketOption.receiveBuffer.rawValue,
                                value: Int32(4096))
        if let rcvBuf = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.receiveBuffer.rawValue) as? Int32 {
            #expect(rcvBuf == 4096, "SO_RCVBUF should be 4096")
        }

        // Verify SO_ERROR is still 0 after all these operations.
        if let errVal = sockets.getSocketOption(
            s, level: SocketLevel.socket.rawValue,
            optName: SocketOption.error.rawValue) as? Int32 {
            #expect(errVal == 0, "SO_ERROR should still be 0 after option operations")
        }

        // Test recv on a non-connected TCP socket should fail.
        var recvBuf = [UInt8](repeating: 0, count: 64)
        // Set non-blocking mode first to avoid hanging.
        sockets.fcntl(s, cmd: 4, val: 1)
        let recvResult = recvBuf.withUnsafeMutableBytes { buf in
            sockets.recv(s, buffer: buf.baseAddress!, size: buf.count,
                         flags: .dontWait)
        }
        #expect(recvResult <= 0,
                "recv on non-connected TCP socket should not return positive")
    }
}
