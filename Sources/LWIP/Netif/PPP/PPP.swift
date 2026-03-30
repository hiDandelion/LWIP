//
//  PPP.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - PPP Constants

/// PPP protocol numbers
public struct PPPProtocol {
    public static let ip: UInt16         = 0x0021
    public static let ipv6: UInt16       = 0x0057
    public static let vj: UInt16         = 0x002D
    public static let vjUncomp: UInt16   = 0x002F
    public static let comp: UInt16       = 0x00FD
    public static let ipcp: UInt16       = 0x8021
    public static let atcp: UInt16       = 0x8029
    public static let ipv6cp: UInt16     = 0x8057
    public static let ccp: UInt16        = 0x80FD
    public static let ecp: UInt16        = 0x8053
    public static let lcp: UInt16        = 0xC021
    public static let pap: UInt16        = 0xC023
    public static let lqr: UInt16        = 0xC025
    public static let chap: UInt16       = 0xC223
    public static let cbcp: UInt16       = 0xC029
    public static let eap: UInt16        = 0xC227
}

/// PPP phases
public enum PPPPhase: UInt8, Sendable {
    case dead         = 0
    case initialize   = 1
    case serialConnection = 2
    case dormant      = 3
    case establish    = 4
    case authenticate = 5
    case callback     = 6
    case network      = 7
    case running      = 8
    case terminate    = 9
    case disconnect   = 10
    case holdoff      = 11
    case master       = 12
}

/// PPP authentication protocols
public enum PPPAuthProto: UInt16, Sendable {
    case none = 0
    case pap  = 0xC023
    case chap = 0xC223
    case eap  = 0xC227
}

/// PPP link constants.
public extension PPPControlBlock {
    /// Maximum Receive Unit.
    static let defaultMRU: UInt16 = 1500
    /// Maximum Transmission Unit.
    static let defaultMTU: UInt16 = 1500
    /// HDLC flag byte.
    static let flagByte: UInt8 = 0x7E
    /// HDLC escape byte.
    static let escapeByte: UInt8 = 0x7D
    /// Maximum packet length.
    static let maxMRU: UInt16 = 1500
}

// MARK: - FSM (Finite State Machine)

/// FSM states (RFC 1661)
public enum FSMState: UInt8, Sendable {
    case initial              = 0
    case starting             = 1
    case closed               = 2
    case stopped              = 3
    case closing              = 4
    case stopping             = 5
    case requestSent          = 6
    case acknowledgmentReceived = 7
    case acknowledgmentSent   = 8
    case opened               = 9
}

/// Swift-facing alias for the PPP finite-state machine state.
public typealias PPPFiniteStateMachineState = FSMState

/// FSM packet codes
public enum FSMCode: UInt8, Sendable {
    case configureRequest              = 1
    case configureAcknowledgment       = 2
    case configureNegativeAcknowledgment = 3
    case configureReject               = 4
    case terminateRequest              = 5
    case terminateAcknowledgment       = 6
    case codeReject                    = 7
}

/// Swift-facing alias for PPP finite-state machine packet codes.
public typealias PPPFiniteStateMachineCode = FSMCode

/// Swift-facing alias for the PPP finite-state machine type.
public typealias PPPFiniteStateMachine = FSM

/// FSM callbacks for protocol-specific behavior
public protocol FSMCallbacks: AnyObject {
    var protocolName: String { get }
    func resetCI(_ fsm: FSM)
    func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int
    func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool
    func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool
    func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool
    func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode
    func up(_ fsm: FSM)
    func down(_ fsm: FSM)
    func starting(_ fsm: FSM)
    func finished(_ fsm: FSM)
    func extCode(_ fsm: FSM, code: UInt8, id: UInt8, data: [UInt8]) -> Bool
}

/// Swift-facing callback surface for PPP finite-state machines.
///
/// Conformers can adopt this protocol and implement the more descriptive
/// method names while the legacy `FSMCallbacks` entry points continue to work.
public protocol PPPFiniteStateMachineCallbacks: FSMCallbacks {
    var protocolDisplayName: String { get }
    func resetConfigurationOptions(_ stateMachine: PPPFiniteStateMachine)
    func appendConfigurationOptions(_ stateMachine: PPPFiniteStateMachine, to buffer: inout [UInt8]) -> Int
    func acceptConfigureAcknowledgment(_ stateMachine: PPPFiniteStateMachine, data: [UInt8]) -> Bool
    func applyConfigureNegativeAcknowledgment(
        _ stateMachine: PPPFiniteStateMachine,
        data: [UInt8],
        treatAsReject: Bool
    ) -> Bool
    func applyConfigureReject(_ stateMachine: PPPFiniteStateMachine, data: [UInt8]) -> Bool
    func handleConfigureRequest(
        _ stateMachine: PPPFiniteStateMachine,
        data: [UInt8],
        reject: inout [UInt8]
    ) -> PPPFiniteStateMachineCode
    func didOpen(_ stateMachine: PPPFiniteStateMachine)
    func didClose(_ stateMachine: PPPFiniteStateMachine)
    func willStart(_ stateMachine: PPPFiniteStateMachine)
    func didFinish(_ stateMachine: PPPFiniteStateMachine)
    func handleExtensionCode(
        _ stateMachine: PPPFiniteStateMachine,
        code: UInt8,
        id: UInt8,
        data: [UInt8]
    ) -> Bool
}

/// Default implementations for optional FSM callbacks
public extension FSMCallbacks {
    func extCode(_ fsm: FSM, code: UInt8, id: UInt8, data: [UInt8]) -> Bool { return false }

    var protocolDisplayName: String { protocolName }

    func resetConfigurationOptions(_ stateMachine: PPPFiniteStateMachine) {
        resetCI(stateMachine)
    }

    func appendConfigurationOptions(_ stateMachine: PPPFiniteStateMachine, to buffer: inout [UInt8]) -> Int {
        addCI(stateMachine, buffer: &buffer)
    }

    func acceptConfigureAcknowledgment(_ stateMachine: PPPFiniteStateMachine, data: [UInt8]) -> Bool {
        ackCI(stateMachine, data: data)
    }

    func applyConfigureNegativeAcknowledgment(
        _ stateMachine: PPPFiniteStateMachine,
        data: [UInt8],
        treatAsReject: Bool
    ) -> Bool {
        nakCI(stateMachine, data: data, treatAsReject: treatAsReject)
    }

    func applyConfigureReject(_ stateMachine: PPPFiniteStateMachine, data: [UInt8]) -> Bool {
        rejCI(stateMachine, data: data)
    }

    func handleConfigureRequest(
        _ stateMachine: PPPFiniteStateMachine,
        data: [UInt8],
        reject: inout [UInt8]
    ) -> PPPFiniteStateMachineCode {
        reqCI(stateMachine, data: data, reject: &reject)
    }

    func didOpen(_ stateMachine: PPPFiniteStateMachine) {
        up(stateMachine)
    }

    func didClose(_ stateMachine: PPPFiniteStateMachine) {
        down(stateMachine)
    }

    func willStart(_ stateMachine: PPPFiniteStateMachine) {
        starting(stateMachine)
    }

    func didFinish(_ stateMachine: PPPFiniteStateMachine) {
        finished(stateMachine)
    }

    func handleExtensionCode(
        _ stateMachine: PPPFiniteStateMachine,
        code: UInt8,
        id: UInt8,
        data: [UInt8]
    ) -> Bool {
        extCode(stateMachine, code: code, id: id, data: data)
    }
}

public extension PPPFiniteStateMachineCallbacks {
    var protocolName: String { protocolDisplayName }

    func resetCI(_ fsm: FSM) {
        resetConfigurationOptions(fsm)
    }

    func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        appendConfigurationOptions(fsm, to: &buffer)
    }

    func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        acceptConfigureAcknowledgment(fsm, data: data)
    }

    func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        applyConfigureNegativeAcknowledgment(fsm, data: data, treatAsReject: treatAsReject)
    }

    func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        applyConfigureReject(fsm, data: data)
    }

    func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        handleConfigureRequest(fsm, data: data, reject: &reject)
    }

    func up(_ fsm: FSM) {
        didOpen(fsm)
    }

    func down(_ fsm: FSM) {
        didClose(fsm)
    }

    func starting(_ fsm: FSM) {
        willStart(fsm)
    }

    func finished(_ fsm: FSM) {
        didFinish(fsm)
    }

    func extCode(_ fsm: FSM, code: UInt8, id: UInt8, data: [UInt8]) -> Bool {
        handleExtensionCode(fsm, code: code, id: id, data: data)
    }

    func handleExtensionCode(
        _ stateMachine: PPPFiniteStateMachine,
        code: UInt8,
        id: UInt8,
        data: [UInt8]
    ) -> Bool {
        false
    }
}

/// Finite State Machine for PPP control protocols (LCP, IPCP, etc.)
public final class FSM: @unchecked Sendable {
    /// Parent PPP connection
    public weak var pcb: PPPControlBlock?
    /// Current state
    public var state: FSMState = .initial
    /// Flags
    public var flags: UInt8 = 0
    /// Protocol-specific callbacks
    public var callbacks: FSMCallbacks?
    /// Packet identifier counter
    public var id: UInt8 = 0
    /// Request identifier for matching responses
    public var reqID: UInt8 = 0
    /// Restart counter (retransmissions remaining)
    public var retransmits: Int = 0
    /// Maximum retransmissions for configure
    public var maxConfReqTransmits: Int = 10
    /// Maximum retransmissions for terminate
    public var maxTermTransmits: Int = 2
    /// Number of Nak before treating as reject
    public var maxNakLoops: Int = 5
    /// Nak counter
    public var nakCount: Int = 0
    /// Timeout value in seconds
    public var timeoutTime: UInt32 = 3
    /// Protocol number (LCP, IPCP, etc.)
    public var protocolNumber: UInt16 = 0

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    /// Initialize the FSM
    public func initialize() {
        state = .initial
        flags = 0
        id = 0
    }

    /// Lower layer is up (e.g., link established)
    public func lowerUp() {
        switch state {
        case .initial:
            state = .closed
        case .starting:
            state = .requestSent
            retransmits = maxConfReqTransmits
            sendConfReq(retransmit: false)
        default:
            break
        }
    }

    /// Lower layer is down
    public func lowerDown() {
        switch state {
        case .closed:
            state = .initial
        case .stopped:
            state = .starting
            callbacks?.starting(self)
        case .closing:
            state = .initial
        case .stopping, .requestSent, .acknowledgmentReceived, .acknowledgmentSent:
            state = .starting
        case .opened:
            callbacks?.down(self)
            state = .starting
        default:
            break
        }
    }

    /// Open the FSM (administrative open)
    public func open() {
        switch state {
        case .initial:
            state = .starting
            callbacks?.starting(self)
        case .closed:
            state = .requestSent
            retransmits = maxConfReqTransmits
            sendConfReq(retransmit: false)
        default:
            break
        }
    }

    /// Close the FSM (administrative close)
    public func close(reason: String? = nil) {
        switch state {
        case .starting:
            state = .initial
            callbacks?.finished(self)
        case .stopped:
            state = .closed
        case .stopping:
            state = .closing
        case .requestSent, .acknowledgmentReceived, .acknowledgmentSent, .opened:
            if state == .opened {
                callbacks?.down(self)
            }
            state = .closing
            retransmits = maxTermTransmits
            sendTermReq()
        default:
            break
        }
    }

    /// Handle timeout (retransmission timer expired)
    public func timeout() {
        switch state {
        case .closing, .stopping:
            if retransmits <= 0 {
                state = (state == .closing) ? .closed : .stopped
                callbacks?.finished(self)
            } else {
                retransmits -= 1
                sendTermReq()
            }
        case .requestSent, .acknowledgmentReceived, .acknowledgmentSent:
            if retransmits <= 0 {
                state = .stopped
                callbacks?.finished(self)
            } else {
                retransmits -= 1
                sendConfReq(retransmit: true)
                if state == .acknowledgmentReceived {
                    state = .requestSent
                }
            }
        default:
            break
        }
    }

    /// Handle received packet
    public func input(code: UInt8, id: UInt8, data: [UInt8]) {
        guard let fsmCode = FSMCode(rawValue: code) else {
            // Unknown code
            if let cb = callbacks, !cb.extCode(self, code: code, id: id, data: data) {
                sendCodeReject(id: id, data: data)
            }
            return
        }

        switch fsmCode {
        case .configureRequest:
            receiveConfReq(id: id, data: data)
        case .configureAcknowledgment:
            receiveConfAck(id: id, data: data)
        case .configureNegativeAcknowledgment, .configureReject:
            receiveConfNakRej(code: fsmCode, id: id, data: data)
        case .terminateRequest:
            receiveTermReq(id: id, data: data)
        case .terminateAcknowledgment:
            receiveTermAck()
        case .codeReject:
            receiveCodeReject(data: data)
        }
    }

    // MARK: - Private Methods

    private func sendConfReq(retransmit: Bool) {
        guard let pcb = pcb else { return }

        if !retransmit {
            callbacks?.resetCI(self)
            nakCount = 0
            id &+= 1
            reqID = id
        }

        var buffer = [UInt8](repeating: 0, count: Int(PPPControlBlock.defaultMRU))
        let len = callbacks?.addCI(self, buffer: &buffer) ?? 0

        pcb.sendProtocolPacket(
            protocol: protocolNumber,
            code: FSMCode.configureRequest.rawValue,
            id: reqID,
            data: Array(buffer[0..<len])
        )
    }

    private func sendTermReq() {
        guard let pcb = pcb else { return }
        id &+= 1
        pcb.sendProtocolPacket(protocol: protocolNumber, code: FSMCode.terminateRequest.rawValue, id: id, data: [])
    }

    private func sendTermAck(id: UInt8) {
        pcb?.sendProtocolPacket(protocol: protocolNumber, code: FSMCode.terminateAcknowledgment.rawValue, id: id, data: [])
    }

    private func sendCodeReject(id: UInt8, data: [UInt8]) {
        pcb?.sendProtocolPacket(protocol: protocolNumber, code: FSMCode.codeReject.rawValue, id: id, data: data)
    }

    private func receiveConfReq(id: UInt8, data: [UInt8]) {
        switch state {
        case .closed:
            sendTermAck(id: id)
            return
        case .closing, .stopping:
            return
        case .opened:
            callbacks?.down(self)
            sendConfReq(retransmit: false)
            state = .requestSent
        default:
            break
        }

        var reject = [UInt8]()
        let response = callbacks?.reqCI(self, data: data, reject: &reject) ?? .configureReject

        pcb?.sendProtocolPacket(
            protocol: protocolNumber,
            code: response.rawValue,
            id: id,
            data: response == .configureAcknowledgment ? data : reject
        )

        switch state {
        case .stopped:
            state = (response == .configureAcknowledgment) ? .acknowledgmentSent : .requestSent
            sendConfReq(retransmit: false)
        case .requestSent:
            state = (response == .configureAcknowledgment) ? .acknowledgmentSent : .requestSent
        case .acknowledgmentReceived:
            if response == .configureAcknowledgment {
                state = .opened
                callbacks?.up(self)
            }
        case .acknowledgmentSent:
            state = (response == .configureAcknowledgment) ? .acknowledgmentSent : .requestSent
        default:
            break
        }
    }

    private func receiveConfAck(id: UInt8, data: [UInt8]) {
        guard id == reqID else { return }
        guard callbacks?.ackCI(self, data: data) == true else { return }

        switch state {
        case .requestSent:
            state = .acknowledgmentReceived
        case .acknowledgmentSent:
            state = .opened
            callbacks?.up(self)
        case .opened:
            callbacks?.down(self)
            sendConfReq(retransmit: false)
            state = .requestSent
        default:
            break
        }
    }

    private func receiveConfNakRej(code: FSMCode, id: UInt8, data: [UInt8]) {
        guard id == reqID else { return }

        let treatAsReject = code == .configureReject
        let result: Bool
        if treatAsReject {
            result = callbacks?.rejCI(self, data: data) ?? false
        } else {
            result = callbacks?.nakCI(self, data: data, treatAsReject: nakCount >= maxNakLoops) ?? false
        }
        guard result else { return }

        if !treatAsReject {
            nakCount += 1
        }

        switch state {
        case .requestSent, .acknowledgmentSent:
            sendConfReq(retransmit: false)
        case .acknowledgmentReceived:
            state = .requestSent
            sendConfReq(retransmit: false)
        case .opened:
            callbacks?.down(self)
            sendConfReq(retransmit: false)
            state = .requestSent
        default:
            break
        }
    }

    private func receiveTermReq(id: UInt8, data: [UInt8]) {
        switch state {
        case .acknowledgmentReceived, .acknowledgmentSent:
            state = .requestSent
        case .opened:
            callbacks?.down(self)
            state = .stopping
            // Start restart timer
        default:
            break
        }
        sendTermAck(id: id)
    }

    private func receiveTermAck() {
        switch state {
        case .closing:
            state = .closed
            callbacks?.finished(self)
        case .stopping:
            state = .stopped
            callbacks?.finished(self)
        case .acknowledgmentReceived:
            state = .requestSent
        case .opened:
            callbacks?.down(self)
            sendConfReq(retransmit: false)
            state = .requestSent
        default:
            break
        }
    }

    private func receiveCodeReject(data: [UInt8]) {
        // If the rejected code is critical, close down
        switch state {
        case .acknowledgmentReceived:
            state = .requestSent
        default:
            break
        }
    }
}

// MARK: - LCP Option Types

/// LCP configuration item type codes (RFC 1661, RFC 1990).
private enum LCPOptionType {
    static let mru: UInt8             = 1
    static let asyncMap: UInt8        = 2
    static let authType: UInt8        = 3
    static let quality: UInt8         = 4
    static let magicNumber: UInt8     = 5
    static let pfc: UInt8             = 7
    static let acfc: UInt8            = 8
    // Multilink PPP options (RFC 1990)
    static let mrru: UInt8            = 17  // Maximum Receive Reconstructed Unit
    static let ssnhf: UInt8           = 18  // Short Sequence Number Header Format
    static let epdisc: UInt8          = 19  // Endpoint Discriminator
}

/// LCP configuration item lengths.
private enum LCPOptionLength {
    static let voidOption: Int   = 2
    static let shortOption: Int  = 4
    static let chap: Int         = 5
    static let longOption: Int   = 6
    static let lqr: Int          = 8
}

/// Minimum MRU we will accept from a peer.
private let pppMinMRU: UInt16 = 128

// MARK: - LCP Options

/// LCP configuration options
public struct LCPOptions: Sendable {
    // -- Negotiation flags (true = include this option in ConfReq / allow from peer) --
    /// Negotiate MRU (only if mru differs from default 1500).
    public var negotiateMRU: Bool = true
    /// Negotiate Async Control Character Map.
    public var negotiateAsyncMap: Bool = true
    /// Negotiate Magic Number.
    public var negotiateMagicNumber: Bool = true
    /// Negotiate Protocol Field Compression.
    public var negotiatePFC: Bool = true
    /// Negotiate Address/Control Field Compression.
    public var negotiateACFC: Bool = true
    /// Negotiate PAP authentication.
    public var negotiatePAP: Bool = false
    /// Negotiate CHAP authentication.
    public var negotiateCHAP: Bool = false
    /// Negotiate EAP authentication.
    public var negotiateEAP: Bool = false
    /// Negotiate Link Quality Reporting (LQR).
    public var negotiateLQR: Bool = false

    // -- Option values --
    /// Maximum Receive Unit
    public var mru: UInt16 = 1500
    /// Async Control Character Map
    public var asyncMap: UInt32 = 0xFFFFFFFF
    /// Authentication protocol
    public var authProtocol: PPPAuthProto = .none
    /// CHAP algorithm (MD5=5, MSv1=128, MSv2=129)
    public var chapAlgorithm: UInt8 = 5
    /// Magic number (for loop detection)
    public var magicNumber: UInt32 = 0
    /// Protocol Field Compression
    internal var hasPFC: Bool = false
    /// Address and Control Field Compression
    internal var hasACFC: Bool = false
    /// LQR reporting period in hundredths of a second (0 = peer chooses).
    public var lqrPeriod: UInt32 = 0

    public init() {}

    /// Generate a random magic number.
    public static func randomMagic() -> UInt32 {
        return UInt32.random(in: 1...UInt32.max)
    }
}

// MARK: - LCP

/// Link Control Protocol implementation
public final class LCP: @unchecked Sendable, FSMCallbacks {
    public let protocolName = "LCP"
    public var fsm: FSM
    /// Options we want to negotiate.
    public var wantOptions = LCPOptions()
    /// Options we will actually request (adjusted through NAK/REJ).
    public var gotOptions = LCPOptions()
    /// Options we allow the peer to request.
    public var allowOptions = LCPOptions()
    /// Options the peer is using (set from peer's ConfReq).
    public var hisOptions = LCPOptions()
    /// Echo request interval (seconds, 0 = disabled)
    public var echoInterval: UInt32 = 0
    /// Echo failure threshold
    public var echoFails: UInt32 = 0
    private var echoFailCount: UInt32 = 0
    private var echoNumber: UInt32 = 0

    public init(pcb: PPPControlBlock) {
        self.fsm = FSM(pcb: pcb)
        fsm.protocolNumber = PPPProtocol.lcp
        fsm.callbacks = self

        // Default allow options: allow peer to request most things
        allowOptions.negotiateMRU = true
        allowOptions.mru = PPPControlBlock.defaultMRU
        allowOptions.negotiateAsyncMap = true
        allowOptions.asyncMap = 0
        allowOptions.negotiateMagicNumber = true
        allowOptions.negotiatePFC = true
        allowOptions.negotiateACFC = true
        allowOptions.negotiatePAP = true
        allowOptions.negotiateCHAP = true
        allowOptions.negotiateEAP = true
        allowOptions.negotiateLQR = true
        allowOptions.lqrPeriod = 0  // Allow any period

        // Default want options: request reasonable features
        wantOptions.negotiateMRU = true
        wantOptions.mru = PPPControlBlock.defaultMRU
        wantOptions.negotiateAsyncMap = true
        wantOptions.asyncMap = 0
        wantOptions.negotiateMagicNumber = true
        wantOptions.magicNumber = LCPOptions.randomMagic()
        wantOptions.negotiatePFC = true
        wantOptions.hasPFC = true
        wantOptions.negotiateACFC = true
        wantOptions.hasACFC = true
    }

    // MARK: - FSMCallbacks

    public func resetCI(_ fsm: FSM) {
        gotOptions = wantOptions
        // Generate a fresh magic number each time we reset
        if gotOptions.negotiateMagicNumber {
            gotOptions.magicNumber = LCPOptions.randomMagic()
        }
    }

    /// Build our Configure-Request options into the buffer.
    public func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        let go = gotOptions
        var offset = 0

        // MRU (type 1, length 4) -- only if not default
        if go.negotiateMRU && go.mru != PPPControlBlock.defaultMRU {
            buffer[offset] = LCPOptionType.mru; offset += 1
            buffer[offset] = 4; offset += 1
            buffer[offset] = UInt8(go.mru >> 8); offset += 1
            buffer[offset] = UInt8(go.mru & 0xFF); offset += 1
        }

        // Async Map (type 2, length 6) -- only if not default 0xFFFFFFFF
        if go.negotiateAsyncMap && go.asyncMap != 0xFFFFFFFF {
            buffer[offset] = LCPOptionType.asyncMap; offset += 1
            buffer[offset] = 6; offset += 1
            buffer[offset] = UInt8((go.asyncMap >> 24) & 0xFF); offset += 1
            buffer[offset] = UInt8((go.asyncMap >> 16) & 0xFF); offset += 1
            buffer[offset] = UInt8((go.asyncMap >> 8) & 0xFF); offset += 1
            buffer[offset] = UInt8(go.asyncMap & 0xFF); offset += 1
        }

        // Authentication -- EAP > CHAP > PAP preference order
        if go.negotiateEAP {
            buffer[offset] = LCPOptionType.authType; offset += 1
            buffer[offset] = 4; offset += 1
            buffer[offset] = UInt8(PPPProtocol.eap >> 8); offset += 1
            buffer[offset] = UInt8(PPPProtocol.eap & 0xFF); offset += 1
        } else if go.negotiateCHAP {
            buffer[offset] = LCPOptionType.authType; offset += 1
            buffer[offset] = 5; offset += 1
            buffer[offset] = UInt8(PPPProtocol.chap >> 8); offset += 1
            buffer[offset] = UInt8(PPPProtocol.chap & 0xFF); offset += 1
            buffer[offset] = go.chapAlgorithm; offset += 1
        } else if go.negotiatePAP {
            buffer[offset] = LCPOptionType.authType; offset += 1
            buffer[offset] = 4; offset += 1
            buffer[offset] = UInt8(PPPProtocol.pap >> 8); offset += 1
            buffer[offset] = UInt8(PPPProtocol.pap & 0xFF); offset += 1
        }

        // Magic Number (type 5, length 6)
        if go.negotiateMagicNumber {
            buffer[offset] = LCPOptionType.magicNumber; offset += 1
            buffer[offset] = 6; offset += 1
            buffer[offset] = UInt8((go.magicNumber >> 24) & 0xFF); offset += 1
            buffer[offset] = UInt8((go.magicNumber >> 16) & 0xFF); offset += 1
            buffer[offset] = UInt8((go.magicNumber >> 8) & 0xFF); offset += 1
            buffer[offset] = UInt8(go.magicNumber & 0xFF); offset += 1
        }

        // PFC (type 7, length 2)
        if go.negotiatePFC {
            buffer[offset] = LCPOptionType.pfc; offset += 1
            buffer[offset] = 2; offset += 1
        }

        // ACFC (type 8, length 2)
        if go.negotiateACFC {
            buffer[offset] = LCPOptionType.acfc; offset += 1
            buffer[offset] = 2; offset += 1
        }

        return offset
    }

    /// Validate that the peer's Configure-Ack matches exactly what we sent.
    public func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = gotOptions
        var p = 0
        let len = data.count

        // Helper to read a UInt16 big-endian
        func getShort() -> UInt16? {
            guard p + 2 <= len else { return nil }
            let v = (UInt16(data[p]) << 8) | UInt16(data[p + 1])
            p += 2
            return v
        }
        // Helper to read a UInt32 big-endian
        func getLong() -> UInt32? {
            guard p + 4 <= len else { return nil }
            let v = (UInt32(data[p]) << 24) | (UInt32(data[p+1]) << 16)
                  | (UInt32(data[p+2]) << 8) | UInt32(data[p+3])
            p += 4
            return v
        }

        // MRU -- must match if we sent it
        if go.negotiateMRU && go.mru != PPPControlBlock.defaultMRU {
            guard p + LCPOptionLength.shortOption <= len else { return false }
            guard data[p] == LCPOptionType.mru, data[p+1] == 4 else { return false }
            p += 2
            guard let val = getShort(), val == go.mru else { return false }
        }

        // Async Map
        if go.negotiateAsyncMap && go.asyncMap != 0xFFFFFFFF {
            guard p + LCPOptionLength.longOption <= len else { return false }
            guard data[p] == LCPOptionType.asyncMap, data[p+1] == 6 else { return false }
            p += 2
            guard let val = getLong(), val == go.asyncMap else { return false }
        }

        // Auth -- EAP
        if go.negotiateEAP {
            guard p + LCPOptionLength.shortOption <= len else { return false }
            guard data[p] == LCPOptionType.authType, data[p+1] == 4 else { return false }
            p += 2
            guard let val = getShort(), val == PPPProtocol.eap else { return false }
        } else if go.negotiateCHAP {
            guard p + LCPOptionLength.chap <= len else { return false }
            guard data[p] == LCPOptionType.authType, data[p+1] == 5 else { return false }
            p += 2
            guard let proto = getShort(), proto == PPPProtocol.chap else { return false }
            guard p < len, data[p] == go.chapAlgorithm else { return false }
            p += 1
        } else if go.negotiatePAP {
            guard p + LCPOptionLength.shortOption <= len else { return false }
            guard data[p] == LCPOptionType.authType, data[p+1] == 4 else { return false }
            p += 2
            guard let val = getShort(), val == PPPProtocol.pap else { return false }
        }

        // Magic Number
        if go.negotiateMagicNumber {
            guard p + LCPOptionLength.longOption <= len else { return false }
            guard data[p] == LCPOptionType.magicNumber, data[p+1] == 6 else { return false }
            p += 2
            guard let val = getLong(), val == go.magicNumber else { return false }
        }

        // PFC
        if go.negotiatePFC {
            guard p + LCPOptionLength.voidOption <= len else { return false }
            guard data[p] == LCPOptionType.pfc, data[p+1] == 2 else { return false }
            p += 2
        }

        // ACFC
        if go.negotiateACFC {
            guard p + LCPOptionLength.voidOption <= len else { return false }
            guard data[p] == LCPOptionType.acfc, data[p+1] == 2 else { return false }
            p += 2
        }

        // No remaining CIs allowed
        return p == len
    }

    /// Process a Configure-Nak from the peer. Adjust our options based on
    /// their suggestions. If treatAsReject is true (too many NAKs), treat
    /// NAK'd options as rejected.
    public func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        let go = gotOptions
        let wo = wantOptions
        var try_ = go
        var p = 0
        let len = data.count
        var loopedBack = false

        // Track which options we have already seen NAK'd (detect duplicates)
        struct Seen {
            var mru = false, asyncMap = false, auth = false
            var magic = false, hasPFC = false, hasACFC = false
        }
        var seen = Seen()

        // --- Process NAK'd options in same order we sent them ---

        // MRU
        if go.negotiateMRU && go.mru != PPPControlBlock.defaultMRU
            && p + LCPOptionLength.shortOption <= len
            && data[p] == LCPOptionType.mru && data[p+1] == UInt8(LCPOptionLength.shortOption) {
            let nakMRU = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            p += LCPOptionLength.shortOption
            seen.mru = true
            if treatAsReject {
                try_.negotiateMRU = false
            } else if nakMRU <= wo.mru || nakMRU <= PPPControlBlock.defaultMRU {
                try_.mru = nakMRU
            }
        }

        // Async Map
        if go.negotiateAsyncMap && go.asyncMap != 0xFFFFFFFF
            && p + LCPOptionLength.longOption <= len
            && data[p] == LCPOptionType.asyncMap && data[p+1] == UInt8(LCPOptionLength.longOption) {
            let nakMap = (UInt32(data[p+2]) << 24) | (UInt32(data[p+3]) << 16)
                       | (UInt32(data[p+4]) << 8) | UInt32(data[p+5])
            p += LCPOptionLength.longOption
            seen.asyncMap = true
            if treatAsReject {
                try_.negotiateAsyncMap = false
            } else {
                try_.asyncMap = go.asyncMap | nakMap
            }
        }

        // Authentication protocol NAK
        let authActive = go.negotiateEAP || go.negotiateCHAP || go.negotiatePAP
        if authActive
            && p + LCPOptionLength.shortOption <= len
            && data[p] == LCPOptionType.authType
            && data[p+1] >= UInt8(LCPOptionLength.shortOption)
            && Int(data[p+1]) <= (len - p) {
            let cilen = Int(data[p+1])
            seen.auth = true
            let suggestedProto = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            if treatAsReject {
                try_.negotiateEAP = false
                try_.negotiateCHAP = false
                try_.negotiatePAP = false
            } else if suggestedProto == PPPProtocol.pap && cilen == LCPOptionLength.shortOption {
                // Peer suggests PAP
                if go.negotiateEAP { try_.negotiateEAP = false }
                else if go.negotiateCHAP { try_.negotiateCHAP = false }
                // They suggested PAP and we were asking PAP already => bad nak, but tolerate
            } else if suggestedProto == PPPProtocol.chap && cilen == LCPOptionLength.chap {
                // Peer suggests CHAP with a specific digest
                let suggestedDigest = data[p+4]
                if go.negotiateEAP {
                    try_.negotiateEAP = false
                    try_.negotiateCHAP = true
                    try_.chapAlgorithm = suggestedDigest
                } else if go.negotiateCHAP {
                    if suggestedDigest != go.chapAlgorithm {
                        try_.chapAlgorithm = suggestedDigest
                    }
                } else {
                    try_.negotiatePAP = false
                    try_.negotiateCHAP = true
                    try_.chapAlgorithm = suggestedDigest
                }
            } else if suggestedProto == PPPProtocol.eap && cilen == LCPOptionLength.shortOption {
                // Peer suggests EAP -- unusual Nak
                if !go.negotiateEAP {
                    try_.negotiateEAP = true
                }
            } else {
                // Unknown auth suggestion -- stop asking for what we were asking
                if go.negotiateEAP { try_.negotiateEAP = false }
                else if go.negotiateCHAP { try_.negotiateCHAP = false }
                else { try_.negotiatePAP = false }
            }
            p += cilen
        }

        // Magic Number
        if go.negotiateMagicNumber
            && p + LCPOptionLength.longOption <= len
            && data[p] == LCPOptionType.magicNumber && data[p+1] == UInt8(LCPOptionLength.longOption) {
            p += LCPOptionLength.longOption
            seen.magic = true
            // Peer NAK'd our magic -- probably loop detection; regenerate
            try_.magicNumber = LCPOptions.randomMagic()
            loopedBack = true
        }

        // PFC -- NAK for void option means reject
        if go.negotiatePFC
            && p + LCPOptionLength.voidOption <= len
            && data[p] == LCPOptionType.pfc && data[p+1] == UInt8(LCPOptionLength.voidOption) {
            p += LCPOptionLength.voidOption
            seen.hasPFC = true
            try_.negotiatePFC = false
        }

        // ACFC -- NAK for void option means reject
        if go.negotiateACFC
            && p + LCPOptionLength.voidOption <= len
            && data[p] == LCPOptionType.acfc && data[p+1] == UInt8(LCPOptionLength.voidOption) {
            p += LCPOptionLength.voidOption
            seen.hasACFC = true
            try_.negotiateACFC = false
        }

        // --- Process any remaining unsolicited NAK options ---
        while p + LCPOptionLength.voidOption <= len {
            let citype = data[p]
            let cilen = Int(data[p+1])
            guard cilen >= LCPOptionLength.voidOption && p + cilen <= len else { return false }
            let next = p + cilen

            switch citype {
            case LCPOptionType.mru:
                if (go.negotiateMRU && go.mru != PPPControlBlock.defaultMRU)
                    || seen.mru || cilen != LCPOptionLength.shortOption { return false }
                let nakMRU = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
                if nakMRU < PPPControlBlock.defaultMRU {
                    try_.negotiateMRU = true
                    try_.mru = nakMRU
                }
            case LCPOptionType.asyncMap:
                if (go.negotiateAsyncMap && go.asyncMap != 0xFFFFFFFF)
                    || seen.asyncMap || cilen != LCPOptionLength.longOption { return false }
            case LCPOptionType.authType:
                if authActive || seen.auth { return false }
            case LCPOptionType.magicNumber:
                if go.negotiateMagicNumber || seen.magic || cilen != LCPOptionLength.longOption { return false }
            case LCPOptionType.pfc:
                if go.negotiatePFC || seen.hasPFC || cilen != LCPOptionLength.voidOption { return false }
            case LCPOptionType.acfc:
                if go.negotiateACFC || seen.hasACFC || cilen != LCPOptionLength.voidOption { return false }
            default:
                break // Unknown options are ignored
            }
            p = next
        }

        // Update state only if FSM is not opened
        if fsm.state != .opened {
            if loopedBack {
                // Could track loop count here; for now just note it
            }
            gotOptions = try_
        }
        return true
    }

    /// Process a Configure-Reject from the peer. Remove rejected options.
    public func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = gotOptions
        var try_ = go
        var p = 0
        let len = data.count

        // MRU
        if go.negotiateMRU && go.mru != PPPControlBlock.defaultMRU
            && p + LCPOptionLength.shortOption <= len
            && data[p] == LCPOptionType.mru && data[p+1] == UInt8(LCPOptionLength.shortOption) {
            let rejMRU = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            guard rejMRU == go.mru else { return false }
            p += LCPOptionLength.shortOption
            try_.negotiateMRU = false
        }

        // Async Map
        if go.negotiateAsyncMap && go.asyncMap != 0xFFFFFFFF
            && p + LCPOptionLength.longOption <= len
            && data[p] == LCPOptionType.asyncMap && data[p+1] == UInt8(LCPOptionLength.longOption) {
            let rejMap = (UInt32(data[p+2]) << 24) | (UInt32(data[p+3]) << 16)
                       | (UInt32(data[p+4]) << 8) | UInt32(data[p+5])
            guard rejMap == go.asyncMap else { return false }
            p += LCPOptionLength.longOption
            try_.negotiateAsyncMap = false
        }

        // Auth -- EAP > CHAP > PAP (same order we send)
        if go.negotiateEAP
            && p + LCPOptionLength.shortOption <= len
            && data[p] == LCPOptionType.authType && data[p+1] == UInt8(LCPOptionLength.shortOption) {
            let rejProto = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            guard rejProto == PPPProtocol.eap else { return false }
            p += LCPOptionLength.shortOption
            try_.negotiateEAP = false
            try_.negotiateCHAP = false
            try_.negotiatePAP = false
        } else if go.negotiateCHAP
            && p + LCPOptionLength.chap <= len
            && data[p] == LCPOptionType.authType && data[p+1] == UInt8(LCPOptionLength.chap) {
            let rejProto = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            guard rejProto == PPPProtocol.chap else { return false }
            guard data[p+4] == go.chapAlgorithm else { return false }
            p += LCPOptionLength.chap
            try_.negotiateCHAP = false
            try_.negotiatePAP = false
        } else if go.negotiatePAP
            && p + LCPOptionLength.shortOption <= len
            && data[p] == LCPOptionType.authType && data[p+1] == UInt8(LCPOptionLength.shortOption) {
            let rejProto = (UInt16(data[p+2]) << 8) | UInt16(data[p+3])
            guard rejProto == PPPProtocol.pap else { return false }
            p += LCPOptionLength.shortOption
            try_.negotiatePAP = false
        }

        // Magic Number
        if go.negotiateMagicNumber
            && p + LCPOptionLength.longOption <= len
            && data[p] == LCPOptionType.magicNumber && data[p+1] == UInt8(LCPOptionLength.longOption) {
            let rejMagic = (UInt32(data[p+2]) << 24) | (UInt32(data[p+3]) << 16)
                         | (UInt32(data[p+4]) << 8) | UInt32(data[p+5])
            guard rejMagic == go.magicNumber else { return false }
            p += LCPOptionLength.longOption
            try_.negotiateMagicNumber = false
        }

        // PFC
        if go.negotiatePFC
            && p + LCPOptionLength.voidOption <= len
            && data[p] == LCPOptionType.pfc && data[p+1] == UInt8(LCPOptionLength.voidOption) {
            p += LCPOptionLength.voidOption
            try_.negotiatePFC = false
        }

        // ACFC
        if go.negotiateACFC
            && p + LCPOptionLength.voidOption <= len
            && data[p] == LCPOptionType.acfc && data[p+1] == UInt8(LCPOptionLength.voidOption) {
            p += LCPOptionLength.voidOption
            try_.negotiateACFC = false
        }

        // No remaining CIs should be present
        guard p == len else { return false }

        if fsm.state != .opened {
            gotOptions = try_
        }
        return true
    }

    /// Process the peer's Configure-Request. Validate each option and build
    /// a NAK or REJ response as needed.
    public func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        let ao = allowOptions
        var ho = LCPOptions()
        // Clear all negotiation flags on ho -- we'll set them as we accept options
        ho.negotiateMRU = false
        ho.negotiateAsyncMap = false
        ho.negotiateMagicNumber = false
        ho.negotiatePFC = false
        ho.negotiateACFC = false
        ho.negotiatePAP = false
        ho.negotiateCHAP = false
        ho.negotiateEAP = false

        var rc: FSMCode = .configureAcknowledgment
        var nakBuffer = [UInt8]()
        var rejBuffer = [UInt8]()

        var p = 0
        let totalLen = data.count

        while p < totalLen {
            guard p + 2 <= totalLen else {
                // Malformed -- reject rest
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject
                break
            }

            let citype = data[p]
            let cilen = Int(data[p+1])
            guard cilen >= 2 && p + cilen <= totalLen else {
                // Bad CI length -- reject rest of packet
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject
                break
            }

            let ciStart = p
            let ciEnd = p + cilen
            let ciData = Array(data[ciStart..<ciEnd])
            p += 2 // skip type + length
            var orc: FSMCode = .configureAcknowledgment

            switch citype {
            case LCPOptionType.mru:
                guard ao.negotiateMRU && cilen == LCPOptionLength.shortOption else {
                    orc = .configureReject; break
                }
                let peerMRU = (UInt16(data[p]) << 8) | UInt16(data[p+1])
                if peerMRU < pppMinMRU {
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(LCPOptionType.mru)
                    nakBuffer.append(4)
                    nakBuffer.append(UInt8(pppMinMRU >> 8))
                    nakBuffer.append(UInt8(pppMinMRU & 0xFF))
                } else {
                    ho.negotiateMRU = true
                    ho.mru = peerMRU
                }

            case LCPOptionType.asyncMap:
                guard ao.negotiateAsyncMap && cilen == LCPOptionLength.longOption else {
                    orc = .configureReject; break
                }
                let peerMap = (UInt32(data[p]) << 24) | (UInt32(data[p+1]) << 16)
                            | (UInt32(data[p+2]) << 8) | UInt32(data[p+3])
                // Peer's map must include all bits we require
                if (ao.asyncMap & ~peerMap) != 0 {
                    orc = .configureNegativeAcknowledgment
                    let suggestedMap = ao.asyncMap | peerMap
                    nakBuffer.append(LCPOptionType.asyncMap)
                    nakBuffer.append(6)
                    nakBuffer.append(UInt8((suggestedMap >> 24) & 0xFF))
                    nakBuffer.append(UInt8((suggestedMap >> 16) & 0xFF))
                    nakBuffer.append(UInt8((suggestedMap >> 8) & 0xFF))
                    nakBuffer.append(UInt8(suggestedMap & 0xFF))
                } else {
                    ho.negotiateAsyncMap = true
                    ho.asyncMap = peerMap
                }

            case LCPOptionType.authType:
                guard cilen >= LCPOptionLength.shortOption else { orc = .configureReject; break }
                let wantAnyAuth = ao.negotiatePAP || ao.negotiateCHAP || ao.negotiateEAP
                guard wantAnyAuth else { orc = .configureReject; break }

                let peerProto = (UInt16(data[p]) << 8) | UInt16(data[p+1])

                if peerProto == PPPProtocol.pap {
                    guard cilen == LCPOptionLength.shortOption else { orc = .configureReject; break }
                    // Already accepted CHAP or EAP?
                    if ho.negotiateCHAP || ho.negotiateEAP {
                        orc = .configureReject; break
                    }
                    if !ao.negotiatePAP {
                        orc = .configureNegativeAcknowledgment
                        nakBuffer.append(LCPOptionType.authType)
                        if ao.negotiateEAP {
                            nakBuffer.append(4)
                            nakBuffer.append(UInt8(PPPProtocol.eap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.eap & 0xFF))
                        } else if ao.negotiateCHAP {
                            nakBuffer.append(5)
                            nakBuffer.append(UInt8(PPPProtocol.chap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.chap & 0xFF))
                            nakBuffer.append(ao.chapAlgorithm)
                        }
                    } else {
                        ho.negotiatePAP = true
                        ho.authProtocol = .pap
                    }

                } else if peerProto == PPPProtocol.chap {
                    guard cilen == LCPOptionLength.chap else { orc = .configureReject; break }
                    if ho.negotiatePAP || ho.negotiateEAP {
                        orc = .configureReject; break
                    }
                    if !ao.negotiateCHAP {
                        orc = .configureNegativeAcknowledgment
                        nakBuffer.append(LCPOptionType.authType)
                        if ao.negotiateEAP {
                            nakBuffer.append(4)
                            nakBuffer.append(UInt8(PPPProtocol.eap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.eap & 0xFF))
                        } else if ao.negotiatePAP {
                            nakBuffer.append(4)
                            nakBuffer.append(UInt8(PPPProtocol.pap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.pap & 0xFF))
                        }
                    } else {
                        let digest = data[p + 2]
                        // Verify we can handle this digest type
                        ho.negotiateCHAP = true
                        ho.authProtocol = .chap
                        ho.chapAlgorithm = digest
                    }

                } else if peerProto == PPPProtocol.eap {
                    guard cilen == LCPOptionLength.shortOption else { orc = .configureReject; break }
                    if ho.negotiateCHAP || ho.negotiatePAP {
                        orc = .configureReject; break
                    }
                    if !ao.negotiateEAP {
                        orc = .configureNegativeAcknowledgment
                        nakBuffer.append(LCPOptionType.authType)
                        if ao.negotiateCHAP {
                            nakBuffer.append(5)
                            nakBuffer.append(UInt8(PPPProtocol.chap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.chap & 0xFF))
                            nakBuffer.append(ao.chapAlgorithm)
                        } else if ao.negotiatePAP {
                            nakBuffer.append(4)
                            nakBuffer.append(UInt8(PPPProtocol.pap >> 8))
                            nakBuffer.append(UInt8(PPPProtocol.pap & 0xFF))
                        }
                    } else {
                        ho.negotiateEAP = true
                        ho.authProtocol = .eap
                    }

                } else {
                    // Unknown auth protocol -- NAK with something we support
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(LCPOptionType.authType)
                    if ao.negotiateEAP {
                        nakBuffer.append(4)
                        nakBuffer.append(UInt8(PPPProtocol.eap >> 8))
                        nakBuffer.append(UInt8(PPPProtocol.eap & 0xFF))
                    } else if ao.negotiateCHAP {
                        nakBuffer.append(5)
                        nakBuffer.append(UInt8(PPPProtocol.chap >> 8))
                        nakBuffer.append(UInt8(PPPProtocol.chap & 0xFF))
                        nakBuffer.append(ao.chapAlgorithm)
                    } else if ao.negotiatePAP {
                        nakBuffer.append(4)
                        nakBuffer.append(UInt8(PPPProtocol.pap >> 8))
                        nakBuffer.append(UInt8(PPPProtocol.pap & 0xFF))
                    }
                }

            case LCPOptionType.quality:
                guard ao.negotiateLQR && cilen == LCPOptionLength.lqr else {
                    orc = .configureReject; break
                }
                let peerProto = (UInt16(data[p]) << 8) | UInt16(data[p+1])
                guard peerProto == PPPProtocol.lqr else {
                    orc = .configureReject; break
                }
                let peerPeriod = (UInt32(data[p+2]) << 24) | (UInt32(data[p+3]) << 16)
                               | (UInt32(data[p+4]) << 8) | UInt32(data[p+5])
                ho.negotiateLQR = true
                ho.lqrPeriod = peerPeriod

            case LCPOptionType.magicNumber:
                guard (ao.negotiateMagicNumber || gotOptions.negotiateMagicNumber)
                    && cilen == LCPOptionLength.longOption else {
                    orc = .configureReject; break
                }
                let peerMagic = (UInt32(data[p]) << 24) | (UInt32(data[p+1]) << 16)
                              | (UInt32(data[p+2]) << 8) | UInt32(data[p+3])
                // Detect loop: peer's magic must differ from ours
                if gotOptions.negotiateMagicNumber && peerMagic == gotOptions.magicNumber {
                    let suggestedMagic = LCPOptions.randomMagic()
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(LCPOptionType.magicNumber)
                    nakBuffer.append(6)
                    nakBuffer.append(UInt8((suggestedMagic >> 24) & 0xFF))
                    nakBuffer.append(UInt8((suggestedMagic >> 16) & 0xFF))
                    nakBuffer.append(UInt8((suggestedMagic >> 8) & 0xFF))
                    nakBuffer.append(UInt8(suggestedMagic & 0xFF))
                } else {
                    ho.negotiateMagicNumber = true
                    ho.magicNumber = peerMagic
                }

            case LCPOptionType.pfc:
                guard ao.negotiatePFC && cilen == LCPOptionLength.voidOption else {
                    orc = .configureReject; break
                }
                ho.negotiatePFC = true
                ho.hasPFC = true

            case LCPOptionType.acfc:
                guard ao.negotiateACFC && cilen == LCPOptionLength.voidOption else {
                    orc = .configureReject; break
                }
                ho.negotiateACFC = true
                ho.hasACFC = true

            default:
                // Unknown option -- reject it
                orc = .configureReject
            }

            // Advance past this CI's data
            p = ciEnd

            // Combine per-option result with overall result
            if orc == .configureAcknowledgment && rc != .configureAcknowledgment {
                continue // Good option but earlier option wasn't -- skip
            }
            if orc == .configureNegativeAcknowledgment {
                if rc == .configureReject { continue } // Already rejecting -- skip NAKs
                rc = .configureNegativeAcknowledgment
            }
            if orc == .configureReject {
                rc = .configureReject
                rejBuffer.append(contentsOf: ciData)
            }
        }

        // Build the output based on overall result
        switch rc {
        case .configureAcknowledgment:
            reject = data  // Echo back original data
        case .configureNegativeAcknowledgment:
            reject = nakBuffer
        case .configureReject:
            reject = rejBuffer
        default:
            reject = data
        }

        // Derive the auth protocol from ho for hisOptions
        if ho.negotiatePAP { ho.authProtocol = .pap }
        else if ho.negotiateCHAP { ho.authProtocol = .chap }
        else if ho.negotiateEAP { ho.authProtocol = .eap }
        else { ho.authProtocol = .none }

        hisOptions = ho
        return rc
    }

    public func up(_ fsm: FSM) {
        guard let pcb = fsm.pcb else { return }

        // If we didn't negotiate magic, clear it
        if !gotOptions.negotiateMagicNumber { gotOptions.magicNumber = 0 }
        if !hisOptions.negotiateMagicNumber { hisOptions.magicNumber = 0 }

        // Derive authProtocol from negotiation flags
        if gotOptions.negotiateEAP { gotOptions.authProtocol = .eap }
        else if gotOptions.negotiateCHAP { gotOptions.authProtocol = .chap }
        else if gotOptions.negotiatePAP { gotOptions.authProtocol = .pap }
        else { gotOptions.authProtocol = .none }

        pcb.phase = .authenticate

        // Determine MTU/MRU from negotiation
        let mtu = hisOptions.negotiateMRU ? hisOptions.mru : PPPControlBlock.defaultMRU
        let mru = gotOptions.negotiateMRU
            ? max(wantOptions.mru, gotOptions.mru) : PPPControlBlock.defaultMRU
        pcb.negotiatedMTU = min(min(mtu, mru), allowOptions.mru)
        pcb.peerPFC = hisOptions.hasPFC
        pcb.peerACFC = hisOptions.hasACFC

        // Notify PAP that the lower layer is up
        pcb.upap.lowerUp()

        // Start LQR if negotiated
        if hisOptions.negotiateLQR {
            pcb.lqm.start(period: hisOptions.lqrPeriod)
        }

        // Start CBCP if callback phase is needed
        pcb.cbcp.lowerUp()

        // Start authentication or proceed to network phase
        if hisOptions.authProtocol == .none && gotOptions.authProtocol == .none {
            pcb.phase = .network
            pcb.startNetworkProtocols()
        } else {
            pcb.startAuthentication()
        }

        // Start LCP echo if configured
        if echoInterval > 0 {
            echoFailCount = 0
        }

        // Notify demand dialer of phase transition
        pcb.demandDialer?.handlePhaseTransition(newPhase: pcb.phase)
    }

    public func down(_ fsm: FSM) {
        guard let pcb = fsm.pcb else { return }
        pcb.upap.lowerDown()
        pcb.chap.lowerDown()
        pcb.lqm.stop()
        pcb.cbcp.lowerDown()
        pcb.phase = .establish

        // Notify demand dialer
        pcb.demandDialer?.handlePhaseTransition(newPhase: .establish)
    }

    public func starting(_ fsm: FSM) {
        fsm.pcb?.linkRequired()
    }

    public func finished(_ fsm: FSM) {
        fsm.pcb?.linkTerminated()
    }

    /// Send LCP echo request
    public func sendEchoRequest() {
        guard fsm.state == .opened else { return }
        echoNumber += 1
        var data = [UInt8](repeating: 0, count: 4)
        data[0] = UInt8((gotOptions.magicNumber >> 24) & 0xFF)
        data[1] = UInt8((gotOptions.magicNumber >> 16) & 0xFF)
        data[2] = UInt8((gotOptions.magicNumber >> 8) & 0xFF)
        data[3] = UInt8(gotOptions.magicNumber & 0xFF)
        fsm.pcb?.sendProtocolPacket(protocol: PPPProtocol.lcp, code: 9, id: fsm.id &+ 1, data: data)
    }

    /// Handle LCP echo reply
    public func receiveEchoReply(data: [UInt8]) {
        echoFailCount = 0
    }

    /// Echo timer tick
    public func echoTimerTick() {
        guard echoInterval > 0 && fsm.state == .opened else { return }
        echoFailCount += 1
        if echoFailCount >= echoFails {
            // Link appears to be dead
            fsm.pcb?.linkDown()
        } else {
            sendEchoRequest()
        }
    }
}

// MARK: - IPCP Option Types

/// IPCP configuration item type codes.
private enum IPCPOptionType {
    static let addresses: UInt8     = 1   // Old-style IP addresses (deprecated)
    static let compressType: UInt8  = 2   // IP compression type (VJ)
    static let address: UInt8       = 3   // IP address
    static let primaryDns: UInt8    = 129 // MS primary DNS
    static let secondaryDns: UInt8  = 131 // MS secondary DNS
    static let primaryNbns: UInt8   = 130 // MS primary WINS/NBNS
    static let secondaryNbns: UInt8 = 132 // MS secondary WINS/NBNS
}

/// IPCP configuration item lengths.
private enum IPCPOptionLength {
    static let voidOption: Int  = 2
    static let addr: Int        = 6  // type(1) + len(1) + IPv4(4)
}

// MARK: - IPCP Options

/// IP Control Protocol configuration options
public struct IPCPOptions: Sendable {
    // -- Negotiation flags --
    /// Negotiate our IP address.
    public var negotiateAddress: Bool = true
    /// Accept peer-assigned local address.
    public var acceptLocal: Bool = true
    /// Accept peer-assigned remote address.
    public var acceptRemote: Bool = true
    /// Request primary DNS from peer.
    public var requestDns1: Bool = true
    /// Request secondary DNS from peer.
    public var requestDns2: Bool = true
    /// Request primary NBNS from peer.
    public var requestNBNS1: Bool = false
    /// Request secondary NBNS from peer.
    public var requestNBNS2: Bool = false
    /// Negotiate VJ compression.
    public var negotiateVJ: Bool = false

    // -- Option values --
    /// Our IP address
    public var ourAddress: IPv4Address = .any
    /// His IP address
    public var hisAddress: IPv4Address = .any
    /// Primary DNS server
    public var primaryDns: IPv4Address = .any
    /// Secondary DNS server
    public var secondaryDns: IPv4Address = .any
    /// Primary NBNS/WINS server
    public var primaryNbns: IPv4Address = .any
    /// Secondary NBNS/WINS server
    public var secondaryNbns: IPv4Address = .any
    /// VJ compression parameters
    public var vjMaxSlotID: UInt8 = 15
    public var vjCompSlotID: Bool = true

    /// Whether we want the peer to send us their address.
    public var requestPeerAddress: Bool = true

    public init() {}
}

// MARK: - IPCP

/// IP Control Protocol implementation
public final class IPCP: @unchecked Sendable, FSMCallbacks {
    public let protocolName = "IPCP"
    public var fsm: FSM
    /// Options we want to negotiate.
    public var wantOptions = IPCPOptions()
    /// Options we will actually request (adjusted through NAK/REJ).
    public var gotOptions = IPCPOptions()
    /// Options we allow the peer to request.
    public var allowOptions = IPCPOptions()
    /// Options the peer is using.
    public var hisOptions = IPCPOptions()

    public init(pcb: PPPControlBlock) {
        self.fsm = FSM(pcb: pcb)
        fsm.protocolNumber = PPPProtocol.ipcp
        fsm.callbacks = self

        // Allow options defaults
        allowOptions.negotiateAddress = true
        allowOptions.acceptLocal = true
        allowOptions.acceptRemote = true
        allowOptions.primaryDns = .any // Will be set by server configuration
        allowOptions.secondaryDns = .any
    }

    // MARK: - FSMCallbacks

    public func resetCI(_ fsm: FSM) {
        gotOptions = wantOptions
    }

    /// Build our IPCP Configure-Request options.
    public func addCI(_ fsm: FSM, buffer: inout [UInt8]) -> Int {
        let go = gotOptions
        var offset = 0

        /// Helper to append an address option (type + 6-byte TLV).
        func addAddrOption(type: UInt8, addr: IPv4Address) {
            buffer[offset] = type; offset += 1
            buffer[offset] = 6; offset += 1
            buffer[offset] = addr.byte(at: 0); offset += 1
            buffer[offset] = addr.byte(at: 1); offset += 1
            buffer[offset] = addr.byte(at: 2); offset += 1
            buffer[offset] = addr.byte(at: 3); offset += 1
        }

        // IP Address (type 3)
        if go.negotiateAddress {
            addAddrOption(type: IPCPOptionType.address, addr: go.ourAddress)
        }

        // Primary DNS (type 129)
        if go.requestDns1 {
            addAddrOption(type: IPCPOptionType.primaryDns, addr: go.primaryDns)
        }

        // Secondary DNS (type 131)
        if go.requestDns2 {
            addAddrOption(type: IPCPOptionType.secondaryDns, addr: go.secondaryDns)
        }

        // Primary NBNS (type 130)
        if go.requestNBNS1 {
            addAddrOption(type: IPCPOptionType.primaryNbns, addr: go.primaryNbns)
        }

        // Secondary NBNS (type 132)
        if go.requestNBNS2 {
            addAddrOption(type: IPCPOptionType.secondaryNbns, addr: go.secondaryNbns)
        }

        return offset
    }

    /// Validate the peer's Configure-Ack matches exactly what we sent.
    public func ackCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = gotOptions
        var p = 0
        let len = data.count

        /// Helper to read an IPv4 address from data at current position.
        func readAddr() -> IPv4Address? {
            guard p + 4 <= len else { return nil }
            let a = IPv4Address(data[p], data[p+1], data[p+2], data[p+3])
            p += 4
            return a
        }

        /// Helper to verify an address option matches what we sent.
        func verifyAddrOption(type: UInt8, addr: IPv4Address) -> Bool {
            guard p + IPCPOptionLength.addr <= len else { return false }
            guard data[p] == type, data[p+1] == 6 else { return false }
            p += 2
            guard let acked = readAddr() else { return false }
            return acked.addr == addr.addr
        }

        // IP Address
        if go.negotiateAddress {
            guard verifyAddrOption(type: IPCPOptionType.address, addr: go.ourAddress) else { return false }
        }

        // Primary DNS
        if go.requestDns1 {
            guard verifyAddrOption(type: IPCPOptionType.primaryDns, addr: go.primaryDns) else { return false }
        }

        // Secondary DNS
        if go.requestDns2 {
            guard verifyAddrOption(type: IPCPOptionType.secondaryDns, addr: go.secondaryDns) else { return false }
        }

        // Primary NBNS
        if go.requestNBNS1 {
            guard verifyAddrOption(type: IPCPOptionType.primaryNbns, addr: go.primaryNbns) else { return false }
        }

        // Secondary NBNS
        if go.requestNBNS2 {
            guard verifyAddrOption(type: IPCPOptionType.secondaryNbns, addr: go.secondaryNbns) else { return false }
        }

        return p == len
    }

    /// Process a Configure-Nak -- peer suggests different values for our options.
    public func nakCI(_ fsm: FSM, data: [UInt8], treatAsReject: Bool) -> Bool {
        let go = gotOptions
        var try_ = go
        var p = 0
        let len = data.count

        struct Seen {
            var addr = false, dns1 = false, dns2 = false
            var nbns1 = false, nbns2 = false
        }
        var seen = Seen()

        /// Helper to read an IPv4 address.
        func readAddr(at pos: Int) -> IPv4Address {
            return IPv4Address(data[pos], data[pos+1], data[pos+2], data[pos+3])
        }

        // IP Address
        if go.negotiateAddress
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.address && data[p+1] == 6 {
            seen.addr = true
            let suggested = readAddr(at: p + 2)
            p += IPCPOptionLength.addr
            if treatAsReject {
                try_.negotiateAddress = false
            } else if go.acceptLocal && suggested != .any {
                try_.ourAddress = suggested
            }
        }

        // Primary DNS
        if go.requestDns1
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.primaryDns && data[p+1] == 6 {
            seen.dns1 = true
            let suggested = readAddr(at: p + 2)
            p += IPCPOptionLength.addr
            if treatAsReject {
                try_.requestDns1 = false
            } else {
                try_.primaryDns = suggested
            }
        }

        // Secondary DNS
        if go.requestDns2
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.secondaryDns && data[p+1] == 6 {
            seen.dns2 = true
            let suggested = readAddr(at: p + 2)
            p += IPCPOptionLength.addr
            if treatAsReject {
                try_.requestDns2 = false
            } else {
                try_.secondaryDns = suggested
            }
        }

        // Primary NBNS
        if go.requestNBNS1
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.primaryNbns && data[p+1] == 6 {
            seen.nbns1 = true
            let suggested = readAddr(at: p + 2)
            p += IPCPOptionLength.addr
            if treatAsReject {
                try_.requestNBNS1 = false
            } else {
                try_.primaryNbns = suggested
            }
        }

        // Secondary NBNS
        if go.requestNBNS2
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.secondaryNbns && data[p+1] == 6 {
            seen.nbns2 = true
            let suggested = readAddr(at: p + 2)
            p += IPCPOptionLength.addr
            if treatAsReject {
                try_.requestNBNS2 = false
            } else {
                try_.secondaryNbns = suggested
            }
        }

        // Process remaining unsolicited NAK options
        while p + IPCPOptionLength.voidOption <= len {
            let citype = data[p]
            let cilen = Int(data[p+1])
            guard cilen >= IPCPOptionLength.voidOption && p + cilen <= len else { return false }
            let next = p + cilen

            switch citype {
            case IPCPOptionType.address:
                if go.negotiateAddress || seen.addr || cilen != IPCPOptionLength.addr { return false }
                let suggested = readAddr(at: p + 2)
                if go.acceptLocal && suggested != .any {
                    try_.ourAddress = suggested
                }
                if try_.ourAddress != .any {
                    try_.negotiateAddress = true
                }
                seen.addr = true

            case IPCPOptionType.primaryDns:
                if go.requestDns1 || seen.dns1 || cilen != IPCPOptionLength.addr { return false }
                try_.primaryDns = readAddr(at: p + 2)
                try_.requestDns1 = true
                seen.dns1 = true

            case IPCPOptionType.secondaryDns:
                if go.requestDns2 || seen.dns2 || cilen != IPCPOptionLength.addr { return false }
                try_.secondaryDns = readAddr(at: p + 2)
                try_.requestDns2 = true
                seen.dns2 = true

            default:
                break
            }
            p = next
        }

        if fsm.state != .opened {
            gotOptions = try_
        }
        return true
    }

    /// Process a Configure-Reject -- remove rejected options.
    public func rejCI(_ fsm: FSM, data: [UInt8]) -> Bool {
        let go = gotOptions
        var try_ = go
        var p = 0
        let len = data.count

        /// Helper to verify a rejected address option matches what we sent.
        func verifyRejAddr(at pos: Int, expected: IPv4Address) -> Bool {
            guard pos + 4 <= len else { return false }
            let addr = IPv4Address(data[pos], data[pos+1], data[pos+2], data[pos+3])
            return addr.addr == expected.addr
        }

        // IP Address
        if go.negotiateAddress
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.address && data[p+1] == 6 {
            guard verifyRejAddr(at: p + 2, expected: go.ourAddress) else { return false }
            p += IPCPOptionLength.addr
            try_.negotiateAddress = false
        }

        // Primary DNS
        if go.requestDns1
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.primaryDns && data[p+1] == 6 {
            guard verifyRejAddr(at: p + 2, expected: go.primaryDns) else { return false }
            p += IPCPOptionLength.addr
            try_.requestDns1 = false
        }

        // Secondary DNS
        if go.requestDns2
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.secondaryDns && data[p+1] == 6 {
            guard verifyRejAddr(at: p + 2, expected: go.secondaryDns) else { return false }
            p += IPCPOptionLength.addr
            try_.requestDns2 = false
        }

        // Primary NBNS
        if go.requestNBNS1
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.primaryNbns && data[p+1] == 6 {
            guard verifyRejAddr(at: p + 2, expected: go.primaryNbns) else { return false }
            p += IPCPOptionLength.addr
            try_.requestNBNS1 = false
        }

        // Secondary NBNS
        if go.requestNBNS2
            && p + IPCPOptionLength.addr <= len
            && data[p] == IPCPOptionType.secondaryNbns && data[p+1] == 6 {
            guard verifyRejAddr(at: p + 2, expected: go.secondaryNbns) else { return false }
            p += IPCPOptionLength.addr
            try_.requestNBNS2 = false
        }

        // No remaining CIs should be present
        guard p == len else { return false }

        if fsm.state != .opened {
            gotOptions = try_
        }
        return true
    }

    /// Process the peer's Configure-Request for IPCP options.
    public func reqCI(_ fsm: FSM, data: [UInt8], reject: inout [UInt8]) -> FSMCode {
        let wo = wantOptions
        let ao = allowOptions
        var ho = IPCPOptions()
        ho.negotiateAddress = false
        ho.requestDns1 = false
        ho.requestDns2 = false

        var rc: FSMCode = .configureAcknowledgment
        var nakBuffer = [UInt8]()
        var rejBuffer = [UInt8]()

        var p = 0
        let totalLen = data.count

        while p < totalLen {
            guard p + 2 <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject
                break
            }

            let citype = data[p]
            let cilen = Int(data[p+1])
            guard cilen >= 2 && p + cilen <= totalLen else {
                rejBuffer.append(contentsOf: data[p...])
                rc = .configureReject
                break
            }

            let ciStart = p
            let ciEnd = p + cilen
            let ciData = Array(data[ciStart..<ciEnd])
            p += 2
            var orc: FSMCode = .configureAcknowledgment

            switch citype {
            case IPCPOptionType.address:
                guard ao.negotiateAddress && cilen == IPCPOptionLength.addr else {
                    orc = .configureReject; break
                }
                let peerAddr = IPv4Address(data[p], data[p+1], data[p+2], data[p+3])

                if peerAddr.addr != wo.hisAddress.addr
                    && (peerAddr == .any || !wo.acceptRemote) {
                    // Peer's address doesn't match what we want -- NAK
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(IPCPOptionType.address)
                    nakBuffer.append(6)
                    nakBuffer.append(wo.hisAddress.byte(at: 0))
                    nakBuffer.append(wo.hisAddress.byte(at: 1))
                    nakBuffer.append(wo.hisAddress.byte(at: 2))
                    nakBuffer.append(wo.hisAddress.byte(at: 3))
                } else if peerAddr == .any && wo.hisAddress == .any {
                    // Neither knows the address -- reject
                    orc = .configureReject
                } else {
                    ho.negotiateAddress = true
                    ho.hisAddress = peerAddr
                }

            case IPCPOptionType.primaryDns, IPCPOptionType.secondaryDns:
                let isSecondary = (citype == IPCPOptionType.secondaryDns)
                let dnsAddr = isSecondary ? ao.secondaryDns : ao.primaryDns
                guard cilen == IPCPOptionLength.addr else { orc = .configureReject; break }

                // If we don't have a DNS address configured, reject
                if dnsAddr == .any {
                    orc = .configureReject; break
                }

                let peerDNS = IPv4Address(data[p], data[p+1], data[p+2], data[p+3])
                if peerDNS.addr != dnsAddr.addr {
                    // NAK with our DNS address
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(citype)
                    nakBuffer.append(6)
                    nakBuffer.append(dnsAddr.byte(at: 0))
                    nakBuffer.append(dnsAddr.byte(at: 1))
                    nakBuffer.append(dnsAddr.byte(at: 2))
                    nakBuffer.append(dnsAddr.byte(at: 3))
                }
                // else: accept (confAck)

            case IPCPOptionType.primaryNbns, IPCPOptionType.secondaryNbns:
                let isSecondary = (citype == IPCPOptionType.secondaryNbns)
                let nbnsAddr = isSecondary ? ao.secondaryNbns : ao.primaryNbns
                guard cilen == IPCPOptionLength.addr else { orc = .configureReject; break }

                if nbnsAddr == .any {
                    orc = .configureReject; break
                }

                let peerNBNS = IPv4Address(data[p], data[p+1], data[p+2], data[p+3])
                if peerNBNS.addr != nbnsAddr.addr {
                    orc = .configureNegativeAcknowledgment
                    nakBuffer.append(citype)
                    nakBuffer.append(6)
                    nakBuffer.append(nbnsAddr.byte(at: 0))
                    nakBuffer.append(nbnsAddr.byte(at: 1))
                    nakBuffer.append(nbnsAddr.byte(at: 2))
                    nakBuffer.append(nbnsAddr.byte(at: 3))
                }

            default:
                orc = .configureReject
            }

            p = ciEnd

            // Combine results
            if orc == .configureAcknowledgment && rc != .configureAcknowledgment {
                continue
            }
            if orc == .configureNegativeAcknowledgment {
                if rc == .configureReject { continue }
                rc = .configureNegativeAcknowledgment
            }
            if orc == .configureReject {
                rc = .configureReject
                rejBuffer.append(contentsOf: ciData)
            }
        }

        // If we want the peer to send their address and they didn't, NAK to request it
        if rc != .configureReject && !ho.negotiateAddress && wo.requestPeerAddress {
            if rc == .configureAcknowledgment {
                rc = .configureNegativeAcknowledgment
            }
            nakBuffer.append(IPCPOptionType.address)
            nakBuffer.append(6)
            nakBuffer.append(wo.hisAddress.byte(at: 0))
            nakBuffer.append(wo.hisAddress.byte(at: 1))
            nakBuffer.append(wo.hisAddress.byte(at: 2))
            nakBuffer.append(wo.hisAddress.byte(at: 3))
        }

        switch rc {
        case .configureAcknowledgment:
            reject = data
        case .configureNegativeAcknowledgment:
            reject = nakBuffer
        case .configureReject:
            reject = rejBuffer
        default:
            reject = data
        }

        hisOptions = ho
        return rc
    }

    public func up(_ fsm: FSM) {
        guard let pcb = fsm.pcb else { return }
        // Configure the network interface with negotiated addresses
        pcb.setIPAddresses(
            local: gotOptions.ourAddress,
            remote: hisOptions.hisAddress,
            primaryDns: gotOptions.primaryDns,
            secondaryDns: gotOptions.secondaryDns
        )
        pcb.networkUp()
    }

    public func down(_ fsm: FSM) {
        fsm.pcb?.networkDown()
    }

    public func starting(_ fsm: FSM) {}
    public func finished(_ fsm: FSM) {}
}

// MARK: - PAP (Password Authentication Protocol)

/// PAP packet codes.
public enum UPAPCode: UInt8, Sendable {
    case authRequest = 1
    case authAck     = 2
    case authNak     = 3
}

/// PAP client-side authentication state.
public enum PAPClientState: UInt8, Sendable {
    /// Connection starting, awaiting lower layer.
    case initial  = 0
    /// Lower layer up, no auth started.
    case closed   = 1
    /// Auth configured, waiting for lower layer.
    case pending  = 2
    /// Auth-Request sent, awaiting response.
    case authReq  = 3
    /// Auth-Ack received, authentication succeeded.
    case open     = 4
    /// Auth-Nak received or max retransmits exceeded.
    case badAuth  = 5
}

/// PAP server-side authentication state.
public enum PAPServerState: UInt8, Comparable, Sendable {
    /// Connection starting, awaiting lower layer.
    case initial  = 0
    /// Lower layer up, no auth started.
    case closed   = 1
    /// Auth configured, waiting for lower layer.
    case pending  = 2
    /// Waiting for peer's Auth-Request.
    case listen   = 3
    /// Auth-Request validated, authentication succeeded.
    case open     = 4
    /// Authentication failed.
    case badAuth  = 5

    public static func < (lhs: PAPServerState, rhs: PAPServerState) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// PAP header length: code(1) + id(1) + length(2).
private let upapHeaderLength = 4

/// Password Authentication Protocol (PAP) implementation.
///
/// Implements RFC 1334 PAP with full client and server state machines,
/// retransmission timers, lower-layer notifications, and protocol
/// rejection handling.
public final class UPAP: @unchecked Sendable {
    public weak var pcb: PPPControlBlock?

    /// Client-side state machine.
    public var clientState: PAPClientState = .initial
    /// Server-side state machine.
    public var serverState: PAPServerState = .initial
    /// Current packet ID counter.
    public var id: UInt8 = 0
    /// Number of auth-request transmissions so far.
    public var transmits: UInt8 = 0

    /// Explicit username (overrides pcb.ourName if non-empty).
    public var username: String = ""
    /// Explicit password (overrides pcb.passwd if non-empty).
    public var password: String = ""

    /// Timer handle for client retransmission timeout.
    private var retransmitTimer: DispatchWorkItem?
    /// Timer handle for server request timeout.
    private var requestTimer: DispatchWorkItem?
    /// Dispatch queue used for scheduling timeouts.
    private let timerQueue = DispatchQueue(label: "ppp.upap.timer", qos: .utility)

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    // MARK: - Initialization

    /// Reset PAP state to initial values.
    public func initialize() {
        clientState = .initial
        serverState = .initial
        id = 0
        transmits = 0
        cancelRetransmitTimer()
        cancelRequestTimer()
    }

    // MARK: - Client API

    /// Start PAP client authentication with the peer.
    ///
    /// Stores the given credentials and sends an Authenticate-Request if
    /// the lower layer (LCP) is already up. If not, defers to PENDING state
    /// until `lowerUp()` is called.
    ///
    /// - Parameters:
    ///   - user: Username to authenticate with.
    ///   - password: Password to authenticate with.
    public func authWithPeer(user: String? = nil, password: String? = nil) {
        if let user = user { self.username = user }
        if let password = password { self.password = password }
        transmits = 0

        // If lower layer isn't up yet, defer
        if clientState == .initial || clientState == .pending {
            clientState = .pending
            return
        }

        sendAuthRequest()
    }

    // MARK: - Server API

    /// Start PAP server authentication -- wait for the peer to authenticate.
    ///
    /// If the lower layer is already up, transitions to LISTEN and optionally
    /// starts a request timeout. Otherwise defers to PENDING state.
    public func authPeer() {
        // If lower layer isn't up yet, defer
        if serverState == .initial || serverState == .pending {
            serverState = .pending
            return
        }

        serverState = .listen
        startRequestTimer()
    }

    // MARK: - Lower Layer Notifications

    /// Called when the lower layer (LCP) comes up.
    ///
    /// If authentication was deferred (PENDING state), the request is
    /// sent (client) or the server enters LISTEN state.
    public func lowerUp() {
        if clientState == .initial {
            clientState = .closed
        } else if clientState == .pending {
            sendAuthRequest()
        }

        if serverState == .initial {
            serverState = .closed
        } else if serverState == .pending {
            serverState = .listen
            startRequestTimer()
        }
    }

    /// Called when the lower layer (LCP) goes down.
    ///
    /// Cancels all pending timeouts and resets state machines to INITIAL.
    public func lowerDown() {
        cancelRetransmitTimer()
        cancelRequestTimer()

        clientState = .initial
        serverState = .initial
    }

    /// Called when the peer rejects the PAP protocol.
    ///
    /// Signals authentication failure and resets state.
    public func protocolReject() {
        if clientState == .authReq {
            pcb?.authenticationFailed()
        }
        if serverState == .listen {
            pcb?.authenticationFailed()
        }
        lowerDown()
    }

    // MARK: - Packet Input

    /// Handle a received PAP packet.
    ///
    /// Dispatches to the appropriate handler based on the packet code.
    ///
    /// - Parameters:
    ///   - code: The PAP packet code (1=AuthReq, 2=AuthAck, 3=AuthNak).
    ///   - id: The packet identifier.
    ///   - data: The packet payload (after the 4-byte PAP header).
    public func input(code: UInt8, id: UInt8, data: [UInt8]) {
        guard let papCode = UPAPCode(rawValue: code) else { return }

        switch papCode {
        case .authRequest:
            handleAuthRequest(id: id, data: data)
        case .authAck:
            handleAuthAck(id: id, data: data)
        case .authNak:
            handleAuthNak(id: id, data: data)
        }
    }

    // MARK: - Timeout Handling

    /// Called when the client retransmission timer fires.
    ///
    /// Resends the Authenticate-Request or gives up after max transmits.
    public func timeout() {
        guard clientState == .authReq else { return }
        guard let pcb = pcb else { return }

        let maxTransmits = pcb.settings.papMaxTransmits
        if transmits >= maxTransmits {
            clientState = .badAuth
            pcb.authenticationFailed()
            return
        }

        sendAuthRequest()
    }

    /// Called when the server request timer fires (peer didn't send auth-req).
    public func requestTimeout() {
        guard serverState == .listen else { return }

        serverState = .badAuth
        pcb?.authenticationFailed()
    }

    // MARK: - Private: Sending

    /// Build and send an Authenticate-Request packet.
    private func sendAuthRequest() {
        guard let pcb = pcb else { return }

        id &+= 1
        let effectiveUsername = username.isEmpty ? pcb.ourName : username
        let effectivePassword = password.isEmpty ? pcb.passwd : password
        let userBytes = Array(effectiveUsername.utf8)
        let passBytes = Array(effectivePassword.utf8)

        var data = [UInt8]()
        data.reserveCapacity(2 + userBytes.count + passBytes.count)
        data.append(UInt8(min(userBytes.count, 255)))
        data.append(contentsOf: userBytes.prefix(255))
        data.append(UInt8(min(passBytes.count, 255)))
        data.append(contentsOf: passBytes.prefix(255))

        pcb.sendProtocolPacket(protocol: PPPProtocol.pap,
                               code: UPAPCode.authRequest.rawValue,
                               id: id, data: data)

        transmits &+= 1
        clientState = .authReq
        startRetransmitTimer()
    }

    /// Send an Authenticate-Ack or Authenticate-Nak response.
    private func sendResponse(code: UPAPCode, id: UInt8, message: String) {
        guard let pcb = pcb else { return }

        let msgBytes = Array(message.utf8)
        var data = [UInt8]()
        data.append(UInt8(min(msgBytes.count, 255)))
        data.append(contentsOf: msgBytes.prefix(255))

        pcb.sendProtocolPacket(protocol: PPPProtocol.pap,
                               code: code.rawValue,
                               id: id, data: data)
    }

    // MARK: - Private: Receiving

    /// Handle a received Authenticate-Request (server side).
    private func handleAuthRequest(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb else { return }

        // Only process in states where we expect auth-requests
        guard serverState >= .listen else { return }

        // If we already decided, re-send the same result for duplicate requests
        if serverState == .open {
            sendResponse(code: .authAck, id: id, message: "")
            return
        }
        if serverState == .badAuth {
            sendResponse(code: .authNak, id: id, message: "")
            return
        }

        // Parse user/passwd from payload
        guard !data.isEmpty else { return }
        let userLen = Int(data[0])
        guard data.count >= 1 + userLen + 1 else { return }
        let user = String(bytes: data[1..<(1 + userLen)], encoding: .utf8) ?? ""

        let passLen = Int(data[1 + userLen])
        guard data.count >= 2 + userLen + passLen else { return }
        let pass = String(bytes: data[(2 + userLen)..<(2 + userLen + passLen)],
                          encoding: .utf8) ?? ""

        // Validate credentials
        if pcb.validateCredentials(user: user, password: pass) {
            serverState = .open
            sendResponse(code: .authAck, id: id, message: "Welcome")
            pcb.peerName = user
            pcb.authenticationSucceeded()
        } else {
            serverState = .badAuth
            sendResponse(code: .authNak, id: id, message: "Authentication failed")
            pcb.authenticationFailed()
        }

        cancelRequestTimer()
    }

    /// Handle a received Authenticate-Ack (client side).
    private func handleAuthAck(id: UInt8, data: [UInt8]) {
        guard clientState == .authReq else { return }

        cancelRetransmitTimer()
        clientState = .open
        pcb?.authenticationSucceeded()
    }

    /// Handle a received Authenticate-Nak (client side).
    private func handleAuthNak(id: UInt8, data: [UInt8]) {
        guard clientState == .authReq else { return }

        cancelRetransmitTimer()
        clientState = .badAuth
        pcb?.authenticationFailed()
    }

    // MARK: - Private: Timers

    private func startRetransmitTimer() {
        cancelRetransmitTimer()
        guard let pcb = pcb else { return }
        let interval = pcb.settings.papTimeoutTime
        guard interval > 0 else { return }

        let item = DispatchWorkItem { [weak self] in
            self?.timeout()
        }
        retransmitTimer = item
        timerQueue.asyncAfter(deadline: .now() + .seconds(Int(interval)), execute: item)
    }

    private func cancelRetransmitTimer() {
        retransmitTimer?.cancel()
        retransmitTimer = nil
    }

    private func startRequestTimer() {
        cancelRequestTimer()
        guard let pcb = pcb else { return }
        let interval = pcb.settings.papRequestTimeout
        guard interval > 0 else { return }

        let item = DispatchWorkItem { [weak self] in
            self?.requestTimeout()
        }
        requestTimer = item
        timerQueue.asyncAfter(deadline: .now() + .seconds(Int(interval)), execute: item)
    }

    private func cancelRequestTimer() {
        requestTimer?.cancel()
        requestTimer = nil
    }
}

// MARK: - PPP PCB (Protocol Control Block)

/// PPP Protocol Control Block - main PPP connection state
public final class PPPControlBlock: @unchecked Sendable {

    /// Current PPP phase
    public var phase: PPPPhase = .dead {
        didSet {
            guard phase != oldValue else { return }
            notifyPhaseCallback?(self, phase)
        }
    }
    /// Network interface
    public var netif: NetworkInterface?

    /// Link Control Protocol
    public lazy var lcp: LCP = LCP(pcb: self)
    /// IP Control Protocol (IPv4)
    public lazy var ipcp: IPCP = IPCP(pcb: self)
    /// PAP authentication
    public lazy var upap: UPAP = UPAP(pcb: self)
    /// CHAP authentication
    public lazy var chap: CHAP = CHAP(pcb: self)
    /// EAP authentication
    public lazy var eap: EAP = EAP(pcb: self)
    /// CBCP callback control
    public lazy var cbcp: CBCP = CBCP(pcb: self)
    /// Link Quality Monitor
    public lazy var lqm: LinkQualityMonitor = LinkQualityMonitor(pcb: self)
    /// Demand dialer (optional, set when demand dialing is enabled)
    public var demandDialer: DemandDialer?

    /// Authentication credentials
    public var ourName: String = ""
    public var passwd: String = ""
    /// Peer's name (from authentication)
    public var peerName: String = ""

    /// Negotiated link parameters (set by LCP up)
    public var negotiatedMTU: UInt16 = PPPControlBlock.defaultMTU
    /// Whether peer negotiated Protocol Field Compression.
    public var peerPFC: Bool = false
    /// Whether peer negotiated Address/Control Field Compression.
    public var peerACFC: Bool = false

    /// Settings
    public var settings = PPPSettings()

    /// Link status callback
    public var linkStatusCallback: ((_ pcb: PPPControlBlock, _ err: LWIPError) -> Void)?
    /// Optional phase-notification callback, matching lwIP's PPP notify-phase hook.
    public var notifyPhaseCallback: ((_ pcb: PPPControlBlock, _ phase: PPPPhase) -> Void)?

    /// Transport layer (PPPoS, PPPoE, PPPoL2TP)
    public var transport: PPPTransportProtocol?

    /// CCP handler (optional, set when compression/encryption is configured)
    public var compressionHandler: CCP?
    /// ECP handler (optional, set when ECP encryption is configured)
    public var encryptionHandler: ECP?
    /// IPv6CP handler (optional, set when IPv6 is configured)
    public var ipv6cp: IPv6CP?
    /// Multilink PPP handler (optional)
    public var multilink: MultilinkPPP?

    public init() {}

    // MARK: - Connection Management

    /// Open the PPP connection
    public func open() {
        phase = .establish
        lcp.fsm.lowerUp()
        lcp.fsm.open()
    }

    /// Close the PPP connection
    public func close() {
        phase = .terminate
        lcp.fsm.close()
    }

    /// Free the PPP connection
    public func free() {
        phase = .dead
        transport = nil
    }

    // MARK: - Link Management

    public func linkRequired() {
        transport?.connect()
    }

    public func linkTerminated() {
        lqm.stop()
        demandDialer?.handlePhaseTransition(newPhase: .dead)
        phase = .dead
        linkStatusCallback?(self, .ok)
    }

    public func linkDown() {
        lqm.stop()
        lcp.fsm.lowerDown()
        demandDialer?.handlePhaseTransition(newPhase: .dead)
        phase = .dead
    }

    // MARK: - Authentication

    public func startAuthentication() {
        phase = .authenticate

        // Notify auth handlers that the lower layer is up
        upap.lowerUp()
        chap.lowerUp()

        if lcp.hisOptions.authProtocol != .none {
            switch lcp.hisOptions.authProtocol {
            case .pap:
                upap.authWithPeer()
            case .chap:
                let algorithm = CHAPAlgorithm(rawValue: lcp.hisOptions.chapAlgorithm) ?? .md5
                chap.authWithPeer(algorithm: algorithm)
            case .eap:
                eap.authWithPeer()
            case .none:
                break
            }
            return
        }

        switch lcp.gotOptions.authProtocol {
        case .pap:
            upap.authPeer()
        case .chap:
            let algorithm = CHAPAlgorithm(rawValue: lcp.gotOptions.chapAlgorithm) ?? .md5
            chap.authPeer(algorithm: algorithm)
        case .eap:
            eap.authPeer()
        case .none:
            authenticationSucceeded()
        }
    }

    public func authenticationSucceeded() {
        phase = .network
        startNetworkProtocols()
    }

    public func authenticationFailed() {
        lcp.fsm.close(reason: "Authentication failed")
    }

    public func validateCredentials(user: String, password: String) -> Bool {
        return user == ourName && password == passwd
    }

    // MARK: - Network Protocols

    public func startNetworkProtocols() {
        phase = .network
        ipcp.fsm.lowerUp()
        ipcp.fsm.open()
    }

    public func setIPAddresses(local: IPv4Address, remote: IPv4Address,
                               primaryDns: IPv4Address, secondaryDns: IPv4Address) {
        // Configure the network interface with negotiated addresses
        netif?.ipAddr = local
        netif?.gateway = remote
        if remote != .any {
            netif?.netmask = .broadcast
        }
        if primaryDns != .any {
            DNS.shared.setServer(index: 0, address: .v4(primaryDns))
        }
        if secondaryDns != .any {
            DNS.shared.setServer(index: 1, address: .v4(secondaryDns))
        }
    }

    public func networkUp() {
        phase = .running
        if let netif {
            netif.setLinkUp()
            netif.setUp()
            if settings.useDefaultRoute {
                NetworkInterface.setDefault(netif)
            }
        }

        // Start IPv6CP negotiation if configured
        if let ipv6cp = ipv6cp {
            ipv6cp.lowerUp()
            ipv6cp.open()
        }

        // Start CCP negotiation if configured
        if let ccp = compressionHandler {
            ccp.lowerUp()
            ccp.open()
        }

        // Start ECP negotiation if configured
        if let ecp = encryptionHandler {
            ecp.lowerUp()
            ecp.open()
        }

        // Notify demand dialer
        demandDialer?.handlePhaseTransition(newPhase: .running) { [weak self] data in
            guard let self = self, let transport = self.transport else { return }
            guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(data.count), type: .ram) else { return }
            data.withUnsafeBufferPointer { buf in
                _ = pbuf.take(from: buf.baseAddress!, len: UInt16(data.count))
            }
            transport.sendPacket(pbuf: pbuf, protocol: PPPProtocol.ip)
        }

        linkStatusCallback?(self, .ok)
    }

    public func networkDown() {
        phase = .network

        // Stop NCP protocols
        ipv6cp?.lowerDown()
        compressionHandler?.lowerDown()
        encryptionHandler?.lowerDown()

        if let netif {
            if NetworkInterface.defaultInterface === netif {
                NetworkInterface.setDefault(nil)
            }
            netif.setDown()
            netif.setLinkDown()
        }

        // Notify demand dialer
        demandDialer?.handlePhaseTransition(newPhase: .network)
    }

    // MARK: - Packet I/O

    /// Send a fully-formed network-layer packet over the active PPP transport.
    @discardableResult
    public func sendNetworkPacket(_ pbuf: Pbuf, protocol proto: UInt16) -> LWIPError {
        guard let transport else {
            return .notConnected
        }

        // Record outgoing packet for LQR
        lqm.recordOutgoingPacket(octets: UInt32(pbuf.totLen) + 4)

        // Mark activity for demand dialing idle detection
        demandDialer?.markActive()

        transport.sendPacket(pbuf: pbuf, protocol: proto)
        return .ok
    }

    /// Send a PPP control protocol packet
    public func sendProtocolPacket(protocol proto: UInt16, code: UInt8, id: UInt8, data: [UInt8]) {
        var packet = [UInt8]()
        // Code + ID + Length (2 bytes) + data
        packet.append(code)
        packet.append(id)
        let totalLen = UInt16(4 + data.count)
        packet.append(UInt8(totalLen >> 8))
        packet.append(UInt8(totalLen & 0xFF))
        packet.append(contentsOf: data)

        guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(packet.count), type: .ram) else {
            return
        }
        packet.withUnsafeBufferPointer { buf in
            _ = pbuf.take(from: buf.baseAddress!, len: UInt16(packet.count))
        }
        transport?.sendPacket(pbuf: pbuf, protocol: proto)
    }

    /// Handle received PPP protocol data
    public func protocolInput(proto: UInt16, data: [UInt8]) {
        // Record incoming packet for LQR
        lqm.recordIncomingPacket(octets: UInt32(data.count + 4))

        // Update demand dialer activity
        demandDialer?.markActive()

        guard data.count >= 4 else { return }
        let code = data[0]
        let id = data[1]
        let payload = Array(data[4...])

        switch proto {
        case PPPProtocol.lcp:
            if code == 9 { // Echo-Request
                // Reply with echo-reply (code 10)
                var reply = [UInt8](repeating: 0, count: 4)
                reply[0] = UInt8((lcp.gotOptions.magicNumber >> 24) & 0xFF)
                reply[1] = UInt8((lcp.gotOptions.magicNumber >> 16) & 0xFF)
                reply[2] = UInt8((lcp.gotOptions.magicNumber >> 8) & 0xFF)
                reply[3] = UInt8(lcp.gotOptions.magicNumber & 0xFF)
                sendProtocolPacket(protocol: PPPProtocol.lcp, code: 10, id: id, data: reply)
            } else if code == 10 { // Echo-Reply
                lcp.receiveEchoReply(data: payload)
            } else if code == 11 { // Discard-Request
                // Silently discard per RFC 1661
            } else {
                lcp.fsm.input(code: code, id: id, data: payload)
            }
        case PPPProtocol.ipcp:
            ipcp.fsm.input(code: code, id: id, data: payload)
        case PPPProtocol.pap:
            upap.input(code: code, id: id, data: payload)
        case PPPProtocol.chap:
            chap.input(code: code, id: id, data: payload)
        case PPPProtocol.eap:
            eap.input(code: code, id: id, data: payload)
        case PPPProtocol.cbcp:
            cbcp.input(code: code, id: id, data: payload)
        case PPPProtocol.ccp:
            // CCP packets include the 4-byte header in the data
            // Forward the full data to CCP which handles code/id internally
            // CCP.input expects the full packet including code+id+length
            // but our data already starts at code
            if let ccp = compressionHandler {
                ccp.input(data: data)
            }
        case PPPProtocol.ecp:
            if let ecp = encryptionHandler {
                ecp.input(data: data)
            }
        case PPPProtocol.ipv6cp:
            ipv6cp?.input(data: data)
        case PPPProtocol.lqr:
            lqm.receiveLQR(data)
        case PPPProtocol.ip:
            // Forward to IP input
            guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(data.count), type: .ram) else { return }
            data.withUnsafeBufferPointer { buf in
                _ = pbuf.take(from: buf.baseAddress!, len: UInt16(data.count))
            }
            if let netif = netif {
                _ = netif.input?(pbuf, netif)
            }
        case PPPProtocol.ipv6:
            // Forward to IPv6 input
            guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(data.count), type: .ram) else { return }
            data.withUnsafeBufferPointer { buf in
                _ = pbuf.take(from: buf.baseAddress!, len: UInt16(data.count))
            }
            if let netif = netif {
                _ = netif.input?(pbuf, netif)
            }
        case PPPProtocol.comp:
            // Compressed data -- decompress via CCP
            if let ccp = compressionHandler {
                if let decompressed = ccp.decompressPacket(data) {
                    // Extract protocol from decompressed data and recurse
                    guard decompressed.count >= 2 else { return }
                    var innerProto: UInt16
                    var dataOffset: Int
                    if (decompressed[0] & 1) == 0 {
                        innerProto = UInt16(decompressed[0]) << 8 | UInt16(decompressed[1])
                        dataOffset = 2
                    } else {
                        innerProto = UInt16(decompressed[0])
                        dataOffset = 1
                    }
                    protocolInput(proto: innerProto, data: Array(decompressed[dataOffset...]))
                }
            }
        default:
            // Protocol reject
            sendProtocolReject(proto: proto, data: data)
        }
    }

    private func sendProtocolReject(proto: UInt16, data: [UInt8]) {
        var rejData = [UInt8]()
        rejData.append(UInt8(proto >> 8))
        rejData.append(UInt8(proto & 0xFF))
        rejData.append(contentsOf: data.prefix(Int(PPPControlBlock.defaultMRU) - 6))
        sendProtocolPacket(protocol: PPPProtocol.lcp, code: 8, id: lcp.fsm.id &+ 1, data: rejData)
    }
}

// MARK: - PPP Settings

/// PPP connection settings
public struct PPPSettings: Sendable {
    /// Authentication protocol to require from peer
    public var authRequired: PPPAuthProto = .none
    /// Refuse PAP authentication
    public var refusePAP: Bool = false
    /// Refuse CHAP authentication
    public var refuseCHAP: Bool = false
    /// Refuse EAP authentication
    public var refuseEAP: Bool = false
    /// Use default route through PPP
    public var useDefaultRoute: Bool = true
    /// MRU we want
    public var mru: UInt16 = 1500
    /// MTU we want
    public var mtu: UInt16 = 1500
    /// Request DNS addresses
    public var usepeerdns: Bool = true
    /// Idle timeout (seconds, 0 = no timeout)
    public var idleTimeout: UInt32 = 0
    /// Maximum connect time (seconds, 0 = unlimited)
    public var maxConnectTime: UInt32 = 0

    // PAP settings (pap-restart, pap-max-authreq, pap-timeout equivalents)

    /// PAP retransmission timeout in seconds (pap-restart).
    /// Controls how long to wait before retransmitting an Auth-Request.
    public var papTimeoutTime: UInt32 = 3
    /// Maximum number of PAP Authenticate-Request transmissions (pap-max-authreq).
    /// After this many transmissions without a response, authentication fails.
    public var papMaxTransmits: UInt8 = 10
    /// Server-side timeout (seconds) waiting for peer's Auth-Request (pap-timeout).
    /// If the peer doesn't send an Auth-Request within this time, authentication fails.
    /// A value of 0 means no timeout.
    public var papRequestTimeout: UInt32 = 30
    /// Whether PAP password should be hidden in log messages.
    public var papHidePassword: Bool = true

    // CHAP settings

    /// CHAP challenge retransmission timeout in seconds.
    public var chapTimeoutTime: UInt32 = 3
    /// Maximum number of CHAP challenge transmissions before giving up.
    public var chapMaxTransmits: UInt8 = 10
    /// Rechallenge interval in seconds (0 = no rechallenge after initial auth).
    public var chapRechallengeTime: UInt32 = 0

    public init() {}
}

// MARK: - PPP Transport Protocol

/// Protocol for PPP transport layers (PPPoS, PPPoE, PPPoL2TP)
public protocol PPPTransportProtocol: AnyObject {
    /// Connect the transport layer
    func connect()
    /// Disconnect the transport layer
    func disconnect()
    /// Send a PPP packet over the transport
    func sendPacket(pbuf: Pbuf, protocol proto: UInt16)
}

// MARK: - CBCP (Callback Control Protocol)

/// CBCP packet codes.
public enum CBCPCode: UInt8, Sendable {
    case callbackRequest  = 1
    case callbackResponse = 2
    case callbackAck      = 3
}

/// CBCP callback types (action codes).
public enum CBCPAction: UInt8, Sendable {
    /// No callback.
    case noCallback        = 1
    /// Callback to a user-specified number.
    case userSpecified     = 2
    /// Callback to a pre-specified (admin-set) number.
    case adminSpecified    = 3
    /// Callback to a list of numbers.
    case listOfNumbers     = 4
}

/// CBCP delay values.
public struct CBCPDelay {
    /// No delay.
    public static let noDelay: UInt8 = 0
}

/// CBCP option for a callback action.
public struct CBCPOption {
    /// The callback action type.
    public var action: CBCPAction = .noCallback
    /// Delay in seconds before the callback.
    public var delay: UInt8 = 0
    /// Callback phone number (for user-specified or list-of-numbers).
    public var phoneNumber: String = ""

    public init() {}
}

/// CBCP FSM state.
public enum CBCPState: UInt8, Sendable {
    case initial     = 0
    case requestSent = 1
    case responseSent = 2
    case ackReceived = 3
    case open        = 4
    case closed      = 5
}

/// Callback Control Protocol (CBCP) implementation.
///
/// Implements CBCP for PPP callback negotiation. When the server offers
/// a callback option, the client can accept and provide a phone number
/// for the server to call back.
///
/// The protocol flow is:
/// 1. Server sends Callback-Request with available callback options
/// 2. Client sends Callback-Response selecting a callback option
/// 3. Server sends Callback-Ack confirming the selection
/// 4. PPP phase transitions to callback, link is dropped, server calls back
public final class CBCP: @unchecked Sendable {

    /// Parent PPP connection.
    public weak var pcb: PPPControlBlock?

    /// Current CBCP state.
    public var state: CBCPState = .initial

    /// Current packet ID.
    public var id: UInt8 = 0

    /// Our preferred callback action.
    public var preferredAction: CBCPAction = .noCallback

    /// Our callback phone number (for user-specified callback).
    public var callbackNumber: String = ""

    /// The callback option negotiated with the peer.
    public var negotiatedOption: CBCPOption?

    /// Available callback options offered by the server.
    public var serverOptions: [CBCPOption] = []

    /// Callback invoked when CBCP negotiation succeeds.
    public var callbackHandler: ((_ option: CBCPOption) -> Void)?

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    /// Initialize CBCP state.
    public func initialize() {
        state = .initial
        id = 0
        negotiatedOption = nil
        serverOptions.removeAll()
    }

    /// Lower layer is up -- CBCP can begin if the peer initiates.
    public func lowerUp() {
        if state == .initial {
            state = .initial  // Wait for server to send Callback-Request
        }
    }

    /// Lower layer is down.
    public func lowerDown() {
        state = .initial
        negotiatedOption = nil
    }

    /// Handle received CBCP packet.
    ///
    /// - Parameters:
    ///   - code: The CBCP packet code.
    ///   - id: The packet identifier.
    ///   - data: The packet payload (after the 4-byte header).
    public func input(code: UInt8, id: UInt8, data: [UInt8]) {
        guard let cbcpCode = CBCPCode(rawValue: code) else { return }

        switch cbcpCode {
        case .callbackRequest:
            handleCallbackRequest(id: id, data: data)
        case .callbackResponse:
            handleCallbackResponse(id: id, data: data)
        case .callbackAck:
            handleCallbackAck(id: id, data: data)
        }
    }

    /// Handle protocol rejection for CBCP.
    public func protocolReject() {
        // If callback was required, this is an error
        if preferredAction != .noCallback {
            PPP.debugLog(.warning, "CBCP: peer rejected callback protocol")
        }
        state = .closed
        // Proceed without callback
        pcb?.phase = .network
        pcb?.startNetworkProtocols()
    }

    // MARK: - Request Handling (Client Side)

    /// Handle a Callback-Request from the server (we are the client).
    private func handleCallbackRequest(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb else { return }

        // Parse available callback options
        serverOptions = parseCallbackOptions(data)

        // Select the best matching option
        let selectedOption = selectCallbackOption(serverOptions)

        // Build and send Callback-Response
        self.id = id
        var responseData = [UInt8]()
        responseData.append(selectedOption.action.rawValue)
        responseData.append(selectedOption.delay)
        if selectedOption.action == .userSpecified && !callbackNumber.isEmpty {
            let numberBytes = Array(callbackNumber.utf8)
            responseData.append(UInt8(numberBytes.count))
            responseData.append(contentsOf: numberBytes)
        }

        pcb.sendProtocolPacket(
            protocol: PPPProtocol.cbcp,
            code: CBCPCode.callbackResponse.rawValue,
            id: id, data: responseData
        )
        state = .responseSent
        negotiatedOption = selectedOption
    }

    /// Handle a Callback-Response from the client (we are the server).
    private func handleCallbackResponse(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb else { return }

        // Parse the selected option
        guard !data.isEmpty else { return }
        let action = CBCPAction(rawValue: data[0]) ?? .noCallback

        var option = CBCPOption()
        option.action = action
        if data.count >= 2 {
            option.delay = data[1]
        }
        if action == .userSpecified && data.count >= 3 {
            let numLen = Int(data[2])
            if data.count >= 3 + numLen {
                option.phoneNumber = String(bytes: data[3..<(3 + numLen)], encoding: .utf8) ?? ""
            }
        }

        negotiatedOption = option

        // Send Callback-Ack
        pcb.sendProtocolPacket(
            protocol: PPPProtocol.cbcp,
            code: CBCPCode.callbackAck.rawValue,
            id: id, data: data
        )
        state = .open

        // Invoke callback handler
        callbackHandler?(option)
    }

    /// Handle a Callback-Ack from the server (we are the client).
    private func handleCallbackAck(id: UInt8, data: [UInt8]) {
        state = .ackReceived

        // Transition to callback phase
        if let option = negotiatedOption, option.action != .noCallback {
            pcb?.phase = .callback
            callbackHandler?(option)
        } else {
            // No callback -- proceed to network phase
            pcb?.phase = .network
            pcb?.startNetworkProtocols()
        }
    }

    // MARK: - Option Parsing

    /// Parse callback options from CBCP packet data.
    private func parseCallbackOptions(_ data: [UInt8]) -> [CBCPOption] {
        var options = [CBCPOption]()
        var offset = 0

        while offset < data.count {
            var option = CBCPOption()
            option.action = CBCPAction(rawValue: data[offset]) ?? .noCallback
            offset += 1

            if offset < data.count {
                option.delay = data[offset]
                offset += 1
            }

            // Parse phone number if present
            if (option.action == .userSpecified || option.action == .listOfNumbers)
                && offset < data.count {
                let numLen = Int(data[offset])
                offset += 1
                if offset + numLen <= data.count {
                    option.phoneNumber = String(bytes: data[offset..<(offset + numLen)],
                                                encoding: .utf8) ?? ""
                    offset += numLen
                }
            }

            options.append(option)
        }

        return options
    }

    /// Select the best callback option from the server's offerings.
    private func selectCallbackOption(_ options: [CBCPOption]) -> CBCPOption {
        // Prefer our preferred action if available
        if let match = options.first(where: { $0.action == preferredAction }) {
            var selected = match
            if preferredAction == .userSpecified {
                selected.phoneNumber = callbackNumber
            }
            return selected
        }

        // Fall back to admin-specified if available
        if let adminOption = options.first(where: { $0.action == .adminSpecified }) {
            return adminOption
        }

        // Fall back to no-callback
        if let noCallback = options.first(where: { $0.action == .noCallback }) {
            return noCallback
        }

        // Accept whatever is offered
        return options.first ?? CBCPOption()
    }
}

// MARK: - LQR (Link Quality Reporting, RFC 1989)

/// LQR packet data structure.
///
/// Represents the counters in a Link Quality Report as defined by RFC 1989.
/// Each LQR packet carries cumulative counters for the link, allowing
/// both sides to compute the percentage of packets/octets successfully
/// delivered.
public struct LQRPacket: Sendable {

    /// Magic number of the sender (identifies the peer).
    public var magicNumber: UInt32 = 0

    // -- "Last" counters: the most recent values received from the peer --

    /// LastOutLQRs: peer's PeerOutLQRs from last received LQR.
    public var lastOutLQRs: UInt32 = 0
    /// LastOutPackets: peer's PeerOutPackets from last received LQR.
    public var lastOutPackets: UInt32 = 0
    /// LastOutOctets: peer's PeerOutOctets from last received LQR.
    public var lastOutOctets: UInt32 = 0

    // -- "Peer" counters: what we know about data arriving from the peer --

    /// PeerInLQRs: number of valid LQR packets we received.
    public var peerInLQRs: UInt32 = 0
    /// PeerInPackets: total packets received from the peer.
    public var peerInPackets: UInt32 = 0
    /// PeerInDiscards: packets received but discarded.
    public var peerInDiscards: UInt32 = 0
    /// PeerInErrors: packets received with errors.
    public var peerInErrors: UInt32 = 0
    /// PeerInOctets: total octets received from the peer.
    public var peerInOctets: UInt32 = 0
    /// PeerOutLQRs: number of LQR packets we have sent.
    public var peerOutLQRs: UInt32 = 0
    /// PeerOutPackets: total packets we have sent.
    public var peerOutPackets: UInt32 = 0
    /// PeerOutOctets: total octets we have sent.
    public var peerOutOctets: UInt32 = 0

    /// Size of an LQR packet on the wire (48 bytes).
    public static let packetSize: Int = 48

    public init() {}

    /// Serialize the LQR packet to wire format (48 bytes, big-endian).
    public func serialize() -> [UInt8] {
        var data = [UInt8](repeating: 0, count: LQRPacket.packetSize)
        var offset = 0

        func put32(_ val: UInt32) {
            data[offset]     = UInt8((val >> 24) & 0xFF)
            data[offset + 1] = UInt8((val >> 16) & 0xFF)
            data[offset + 2] = UInt8((val >> 8) & 0xFF)
            data[offset + 3] = UInt8(val & 0xFF)
            offset += 4
        }

        put32(magicNumber)
        put32(lastOutLQRs)
        put32(lastOutPackets)
        put32(lastOutOctets)
        put32(peerInLQRs)
        put32(peerInPackets)
        put32(peerInDiscards)
        put32(peerInErrors)
        put32(peerInOctets)
        put32(peerOutLQRs)
        put32(peerOutPackets)
        put32(peerOutOctets)

        return data
    }

    /// Deserialize an LQR packet from wire format.
    ///
    /// - Parameter data: The raw received LQR data (must be at least 48 bytes).
    /// - Returns: The parsed LQR packet, or nil if data is too short.
    public static func deserialize(_ data: [UInt8]) -> LQRPacket? {
        guard data.count >= packetSize else { return nil }
        var pkt = LQRPacket()
        var offset = 0

        func get32() -> UInt32 {
            let val = (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16)
                    | (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
            offset += 4
            return val
        }

        pkt.magicNumber    = get32()
        pkt.lastOutLQRs    = get32()
        pkt.lastOutPackets = get32()
        pkt.lastOutOctets  = get32()
        pkt.peerInLQRs     = get32()
        pkt.peerInPackets  = get32()
        pkt.peerInDiscards = get32()
        pkt.peerInErrors   = get32()
        pkt.peerInOctets   = get32()
        pkt.peerOutLQRs    = get32()
        pkt.peerOutPackets = get32()
        pkt.peerOutOctets  = get32()

        return pkt
    }
}

/// Link Quality Monitor for PPP.
///
/// Implements RFC 1989 Link Quality Reporting. Periodically sends LQR
/// packets containing cumulative link counters and evaluates the quality
/// of the link based on received reports. If the link quality drops
/// below a configurable threshold for a sustained period, the link
/// is taken down.
public final class LinkQualityMonitor: @unchecked Sendable {

    /// Parent PPP connection.
    public weak var pcb: PPPControlBlock?

    /// Whether LQR is currently active (negotiated and running).
    internal var isActive: Bool = false

    /// LQR reporting period in hundredths of a second.
    /// A value of 0 means the peer didn't specify, so we use a default.
    public var reportingPeriod: UInt32 = 3000  // Default 30 seconds (in 1/100s)

    /// Minimum acceptable link quality percentage (0..100).
    /// If the computed quality drops below this threshold for
    /// `failureThreshold` consecutive reports, the link is taken down.
    public var qualityThreshold: UInt32 = 50

    /// Number of consecutive poor-quality reports before taking down the link.
    public var failureThreshold: UInt32 = 5

    /// Number of consecutive poor-quality reports seen so far.
    private var failureCount: UInt32 = 0

    // -- Our cumulative counters --

    /// Total LQR packets sent.
    public var outLQRs: UInt32 = 0
    /// Total packets sent on this link.
    public var outPackets: UInt32 = 0
    /// Total octets sent on this link.
    public var outOctets: UInt32 = 0

    /// Total LQR packets received.
    public var inLQRs: UInt32 = 0
    /// Total packets received on this link.
    public var inPackets: UInt32 = 0
    /// Total octets received on this link.
    public var inOctets: UInt32 = 0
    /// Total packets received but discarded.
    public var inDiscards: UInt32 = 0
    /// Total packets received with errors.
    public var inErrors: UInt32 = 0

    // -- Last received values from the peer (saved from the last LQR we got) --

    /// Last received peer outgoing LQR count.
    private var lastPeerOutLQRs: UInt32 = 0
    /// Last received peer outgoing packet count.
    private var lastPeerOutPackets: UInt32 = 0
    /// Last received peer outgoing octet count.
    private var lastPeerOutOctets: UInt32 = 0

    // -- Saved peer counters from the previous LQR for delta computation --

    /// Previous peer outgoing packet count (for computing delivery rate).
    private var prevPeerOutPackets: UInt32 = 0
    /// Previous peer outgoing LQR count.
    private var prevPeerOutLQRs: UInt32 = 0
    /// Previous inbound packet count (for computing delivery rate).
    private var prevInPackets: UInt32 = 0
    /// Previous inbound LQR count.
    private var prevInLQRs: UInt32 = 0

    /// The most recently computed link quality percentage (0..100).
    public var currentQuality: UInt32 = 100

    /// Timer tick counter for LQR period management.
    private var tickCounter: UInt32 = 0

    /// Initialize a link quality monitor.
    ///
    /// - Parameter pcb: The parent PPP connection.
    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    /// Start LQR monitoring with the given reporting period.
    ///
    /// Called when LCP negotiation completes and the peer has requested
    /// or agreed to LQR.
    ///
    /// - Parameter period: Reporting period in hundredths of a second.
    ///   If 0, a default period is used.
    public func start(period: UInt32) {
        reportingPeriod = (period > 0) ? period : 3000
        isActive = true
        failureCount = 0
        currentQuality = 100
        tickCounter = 0

        // Reset all counters
        outLQRs = 0
        outPackets = 0
        outOctets = 0
        inLQRs = 0
        inPackets = 0
        inOctets = 0
        inDiscards = 0
        inErrors = 0
        lastPeerOutLQRs = 0
        lastPeerOutPackets = 0
        lastPeerOutOctets = 0
        prevPeerOutPackets = 0
        prevPeerOutLQRs = 0
        prevInPackets = 0
        prevInLQRs = 0

        // Send the first LQR immediately
        sendLQR()
    }

    /// Stop LQR monitoring.
    public func stop() {
        isActive = false
        failureCount = 0
    }

    /// Called periodically (e.g., every 100ms or every second) to manage
    /// the LQR timer. When enough ticks have elapsed to match the
    /// reporting period, an LQR packet is sent.
    ///
    /// - Parameter elapsedHundredths: Time elapsed since last call, in
    ///   hundredths of a second.
    public func timerTick(elapsedHundredths: UInt32) {
        guard isActive else { return }
        tickCounter += elapsedHundredths
        if tickCounter >= reportingPeriod {
            tickCounter = 0
            sendLQR()
        }
    }

    /// Build and send an LQR packet to the peer.
    public func sendLQR() {
        guard let pcb = pcb, isActive else { return }

        outLQRs += 1

        var report = LQRPacket()
        report.magicNumber = pcb.lcp.gotOptions.magicNumber

        // Fill in "Last" fields from the most recent LQR we received
        report.lastOutLQRs    = lastPeerOutLQRs
        report.lastOutPackets = lastPeerOutPackets
        report.lastOutOctets  = lastPeerOutOctets

        // Fill in "Peer" fields with our own receive/send counters
        report.peerInLQRs     = inLQRs
        report.peerInPackets  = inPackets
        report.peerInDiscards = inDiscards
        report.peerInErrors   = inErrors
        report.peerInOctets   = inOctets
        report.peerOutLQRs    = outLQRs
        report.peerOutPackets = outPackets
        report.peerOutOctets  = outOctets

        let data = report.serialize()

        // Account for this packet in our counters
        outPackets += 1
        outOctets += UInt32(data.count + 4)  // +4 for PPP protocol header

        guard let pbuf = Pbuf.alloc(layer: .raw, length: UInt16(data.count), type: .ram) else {
            return
        }
        data.withUnsafeBufferPointer { buf in
            _ = pbuf.take(from: buf.baseAddress!, len: UInt16(data.count))
        }
        pcb.transport?.sendPacket(pbuf: pbuf, protocol: PPPProtocol.lqr)
    }

    /// Process a received LQR packet from the peer.
    ///
    /// Updates counters, saves the peer's outgoing counters, and computes
    /// the current link quality. If quality is below threshold for too
    /// many consecutive reports, signals the link to be taken down.
    ///
    /// - Parameter data: The raw LQR packet data.
    public func receiveLQR(_ data: [UInt8]) {
        guard isActive else { return }
        guard let report = LQRPacket.deserialize(data) else {
            PPP.debugLog(.warning, "LQR: received malformed report (\(data.count) bytes)")
            return
        }

        // Update our receive counters
        inLQRs += 1
        inPackets += 1
        inOctets += UInt32(data.count + 4)

        // Save the peer's outgoing counters so we can echo them back
        lastPeerOutLQRs    = report.peerOutLQRs
        lastPeerOutPackets = report.peerOutPackets
        lastPeerOutOctets  = report.peerOutOctets

        // Compute link quality based on packet delivery rate.
        //
        // Quality = (packets we received from peer in this interval) /
        //           (packets peer claims to have sent in this interval) * 100
        //
        // We use delta values between consecutive reports.
        let deltaPeerOut = report.peerOutPackets &- prevPeerOutPackets
        let deltaIn = inPackets &- prevInPackets

        if deltaPeerOut > 0 {
            // Clamp to 100% in case of counter wrapping
            let quality = min((deltaIn * 100) / deltaPeerOut, 100)
            currentQuality = quality

            if quality < qualityThreshold {
                failureCount += 1
                PPP.debugLog(.warning,
                    "LQR: quality \(quality)% below threshold \(qualityThreshold)% "
                    + "(failure \(failureCount)/\(failureThreshold))")

                if failureCount >= failureThreshold {
                    PPP.debugLog(.error, "LQR: link quality too low, taking down link")
                    isActive = false
                    pcb?.linkDown()
                    return
                }
            } else {
                // Quality is acceptable -- reset failure counter
                failureCount = 0
            }
        }

        // Save current values as previous for the next delta computation
        prevPeerOutPackets = report.peerOutPackets
        prevPeerOutLQRs    = report.peerOutLQRs
        prevInPackets      = inPackets
        prevInLQRs         = inLQRs
    }

    /// Record an outgoing packet for LQR accounting.
    ///
    /// - Parameter octets: The number of octets in the packet (including PPP header).
    public func recordOutgoingPacket(octets: UInt32) {
        guard isActive else { return }
        outPackets += 1
        outOctets += octets
    }

    /// Record an incoming packet for LQR accounting.
    ///
    /// - Parameter octets: The number of octets in the packet (including PPP header).
    public func recordIncomingPacket(octets: UInt32) {
        guard isActive else { return }
        inPackets += 1
        inOctets += octets
    }

    /// Record a discarded incoming packet.
    public func recordDiscard() {
        guard isActive else { return }
        inDiscards += 1
    }

    /// Record an incoming packet error.
    public func recordError() {
        guard isActive else { return }
        inErrors += 1
    }

    /// Get a human-readable summary of the link quality state.
    public func statusDescription() -> String {
        return "LQR: quality=\(currentQuality)% "
             + "out=\(outPackets)/\(outOctets) in=\(inPackets)/\(inOctets) "
             + "lqr_out=\(outLQRs) lqr_in=\(inLQRs) "
             + "discards=\(inDiscards) errors=\(inErrors) "
             + "failures=\(failureCount)/\(failureThreshold)"
    }
}
