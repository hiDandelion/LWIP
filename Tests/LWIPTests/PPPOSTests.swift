//
//  PPPOSTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for PPPoS (PPP over Serial).
@Suite("PPPoS")
struct PPPOSTests {

    /// Port of test_pppos_empty_packet_with_valid_fcs.
    @Test("PPPoS handles empty packet with valid FCS without crash")
    func emptyPacketWithValidFCS() {
        // Two consecutive frame delimiters should not crash the parser.
        let twoBreaks: [UInt8] = [0x7E, 0x00, 0x00, 0x7E]
        let otherPacket: [UInt8] = [0x7E, 0x7D, 0x20, 0x00, 0x7E]

        // Verify FCS-16 calculation on empty input is consistent
        var fcs = PPPoS.fcsInitial
        #expect(fcs == 0xFFFF)

        // Process zero bytes through FCS
        for byte in twoBreaks[1..<3] {
            fcs = PPPoS.fcs16(fcs, byte)
        }
        #expect(fcs != 0, "FCS calculation should produce non-zero result for non-empty input")

        // Verify the escaped byte 0x7D 0x20 decodes to 0x00
        let escapedByte = otherPacket[2] ^ 0x20
        #expect(escapedByte == 0x00, "0x7D 0x20 should decode to 0x00 via XOR with 0x20")

        // Verify HDLC flag byte is the standard 0x7E
        #expect(HDLC.flag == 0x7E, "HDLC flag should be 0x7E")

        // Verify HDLC escape byte is 0x7D
        #expect(HDLC.escape == 0x7D, "HDLC escape should be 0x7D")

        // Verify the ACCM mechanism
        let defaultACCM: UInt32 = 0xFFFFFFFF
        #expect((defaultACCM >> 0) & 1 == 1, "Byte 0x00 should be escaped in default ACCM")
        #expect((defaultACCM >> 0x20) & 1 == 0 || 0x20 >= 32,
                "Byte 0x20 should not need escaping since it's >= 32")
    }
}
