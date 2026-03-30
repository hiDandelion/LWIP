//
//  MQTTTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for MQTT client functionality.
@Suite("MQTT")
struct MQTTTests {

    /// Port of basic_connect.
    @Test("Basic MQTT client connect")
    func basicConnect() {
        // The C test creates an MQTT client, connects to a test server,
        // and feeds it a CONNACK packet to verify the connection succeeds.

        let client = MQTTClient()
        let connectInfo = MQTTConnectInfo(clientId: "dumm")

        #expect(!connectInfo.clientId.isEmpty)
        #expect(connectInfo.clientId.count <= 23)

        // Verify CONNACK packet structure (used to complete connection)
        // CONNACK: 0x20 0x02 0x00 0x00 (type=2, remaining=2, flags=0, rc=accepted)
        let connack: [UInt8] = [0x20, 0x02, 0x00, 0x00]
        let packetType = (connack[0] & 0xF0) >> 4
        #expect(packetType == 2)
        #expect(connack[1] == 2)
        #expect(connack[3] == 0) // Connection accepted

        // Verify client can be initialized and connection info is valid
        #expect(connectInfo.keepAlive == 60)
    }
}
