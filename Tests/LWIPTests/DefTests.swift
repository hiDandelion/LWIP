//
//  DefTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for definition utilities.
@Suite("Def")
struct DefTests {

    /// Port of test_def_lwip_itoa.
    @Test("lwip_itoa: String integer conversion produces expected results")
    func lwipItoa() {
        #expect(String(fromInteger: 0) == "0")
        #expect(String(fromInteger: 1) == "1")
        #expect(String(fromInteger: -1) == "-1")
        #expect(String(fromInteger: 15) == "15")
        #expect(String(fromInteger: -15) == "-15")
        #expect(String(fromInteger: 156) == "156")
        #expect(String(fromInteger: 1192) == "1192")
        #expect(String(fromInteger: -156) == "-156")
    }
}
