//
//  TimerTests.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation
import Testing
@testable import LWIP

/// Tests for the timeout and timer management system.
@Suite("Timers")
struct TimerTests {

    /// Port of test_timers.
    @Test("Timers expire in correct order", arguments: [UInt32(0), UInt32(0xFFFFFFF0)])
    func timers(offset: UInt32) {
        let timeouts = Timeouts()
        var currentTime = offset
        timeouts.systemTimeMilliseconds = { currentTime }
        timeouts.initialize()

        var fired = [false, false, false]

        timeouts.setTimeout(msecs: 10, handler: { fired[0] = true }, name: "t0")
        #expect(timeouts.sleepTime() == 10)

        timeouts.setTimeout(msecs: 20, handler: { fired[1] = true }, name: "t1")
        #expect(timeouts.sleepTime() == 10)

        timeouts.setTimeout(msecs: 5, handler: { fired[2] = true }, name: "t2")
        #expect(timeouts.sleepTime() == 5)

        currentTime = offset &+ 4
        timeouts.checkTimeouts()
        #expect(fired[2] == false)

        currentTime = offset &+ 5
        timeouts.checkTimeouts()
        #expect(fired[2] == true)

        currentTime = offset &+ 9
        timeouts.checkTimeouts()
        #expect(fired[0] == false)

        currentTime = offset &+ 10
        timeouts.checkTimeouts()
        #expect(fired[0] == true)

        currentTime = offset &+ 19
        timeouts.checkTimeouts()
        #expect(fired[1] == false)

        currentTime = offset &+ 20
        timeouts.checkTimeouts()
        #expect(fired[1] == true)
    }

    /// Port of test_bug52748.
    @Test("Bug #52748: timeout ordering after mid-sequence registration")
    func bug52748() {
        let timeouts = Timeouts()
        var currentTime: UInt32 = 50
        timeouts.systemTimeMilliseconds = { currentTime }
        timeouts.initialize()

        var fired = [false, false, false]

        timeouts.setTimeout(msecs: 20, handler: { fired[0] = true }, name: "t0")
        timeouts.setTimeout(msecs: 5, handler: { fired[2] = true }, name: "t2")

        currentTime = 55
        timeouts.checkTimeouts()
        #expect(fired[0] == false)
        #expect(fired[1] == false)
        #expect(fired[2] == true)

        currentTime = 60
        timeouts.setTimeout(msecs: 10, handler: { fired[1] = true }, name: "t1")
        timeouts.checkTimeouts()
        #expect(fired[0] == false)
        #expect(fired[1] == false)

        currentTime = 70
        timeouts.checkTimeouts()
        #expect(fired[0] == true)
        #expect(fired[1] == true)
        #expect(fired[2] == true)
    }

    /// Port of test_cyclic_timers.
    @Test("Cyclic timers re-schedule after expiry", arguments: [UInt32(0), UInt32(0xFFFFFFF0)])
    func cyclicTimers(offset: UInt32) {
        let timeouts = Timeouts()
        var currentTime = offset
        timeouts.systemTimeMilliseconds = { currentTime }

        let interval: UInt32 = 10
        let handlerExecutionTime: UInt32 = 5
        var cyclicFired = false

        let cyclicTimer = CyclicTimer(intervalMs: interval, handler: {
            cyclicFired = true
            currentTime = currentTime &+ handlerExecutionTime
        })
        timeouts.initialize(cyclicTimers: [cyclicTimer])

        currentTime = offset
        timeouts.setTimeout(msecs: interval, handler: {
            cyclicFired = true
            currentTime = currentTime &+ handlerExecutionTime
        }, name: "cyclic")

        cyclicFired = false
        timeouts.checkTimeouts()
        #expect(cyclicFired == false)

        currentTime = offset &+ interval
        timeouts.checkTimeouts()
        #expect(cyclicFired == true)
    }

    /// Port of test_long_timer.
    @Test("Long timer with UINT32_MAX/4 duration does not fire early")
    func longTimer() {
        let timeouts = Timeouts()
        var currentTime: UInt32 = 0
        timeouts.systemTimeMilliseconds = { currentTime }
        timeouts.initialize()

        var fired = false
        let longDelay: UInt32 = TimeoutConstants.maximumTimeout / 4

        timeouts.setTimeout(msecs: longDelay, handler: { fired = true }, name: "long")
        #expect(timeouts.sleepTime() == longDelay)

        currentTime = 1000
        timeouts.checkTimeouts()
        #expect(fired == false)

        currentTime = longDelay / 2
        timeouts.checkTimeouts()
        #expect(fired == false)

        currentTime = longDelay - 1
        timeouts.checkTimeouts()
        #expect(fired == false)

        currentTime = longDelay
        timeouts.checkTimeouts()
        #expect(fired == true)
    }
}
