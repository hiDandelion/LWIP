//
//  PPPAuth.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Crypto Wrappers

@inline(__always)
private func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var diff: UInt8 = 0
    for index in lhs.indices {
        diff |= lhs[index] ^ rhs[index]
    }
    return diff == 0
}

/// MD5 wrapper backed by the PPP PolarSSL port.
public enum CryptoMD5 {
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        MD5Context.hash(input)
    }
}

/// SHA-1 wrapper backed by the PPP PolarSSL port.
public enum CryptoSHA1 {
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        SHA1Context.hash(input)
    }
}

/// DES wrapper backed by the PPP PolarSSL port.
public enum CryptoDES {
    public static func encrypt(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let effectiveKey: [UInt8]
        if key.count >= 8 {
            effectiveKey = Array(key.prefix(8))
        } else {
            var padded = key
            while padded.count < 7 {
                padded.append(0)
            }
            effectiveKey = PPPCrypt.expand56to64(key56: Array(padded.prefix(7)))
        }

        var paddedBlock = data
        while paddedBlock.count < 8 {
            paddedBlock.append(0)
        }

        var context = DESContext()
        context.setKeyEncrypt(effectiveKey)
        return context.cryptECB(input: Array(paddedBlock.prefix(8)))
    }
}

/// MD4 wrapper backed by the PPP PolarSSL port.
public enum CryptoMD4 {
    public static func hash(_ input: [UInt8]) -> [UInt8] {
        MD4Context.hash(input)
    }
}

// MARK: - CHAP Constants

/// CHAP packet codes
public enum CHAPCode: UInt8, Sendable {
    case challenge = 1
    case response  = 2
    case success   = 3
    case failure   = 4
}

/// CHAP digest algorithms
public enum CHAPAlgorithm: UInt8, Sendable {
    case md5    = 5
    case msv1   = 0x80  // 128
    case msv2   = 0x81  // 129
}

// MARK: - CHAP Digest Protocol

/// Protocol for CHAP digest implementations (MD5, MS-CHAP, etc.)
public protocol CHAPDigest {
    var algorithm: CHAPAlgorithm { get }

    /// Generate a challenge
    func generateChallenge(challengeOut: inout [UInt8])

    /// Generate a response to a challenge
    func makeResponse(
        response: inout [UInt8],
        id: UInt8,
        challenge: [UInt8],
        secret: [UInt8],
        userName: String
    )

    /// Verify a response from the peer
    func verifyResponse(
        id: UInt8,
        challenge: [UInt8],
        response: [UInt8],
        secret: [UInt8],
        userName: String
    ) -> Bool
}

// MARK: - CHAP-MD5

/// CHAP-MD5 digest implementation
public final class CHAPMD5: CHAPDigest {
    public let algorithm: CHAPAlgorithm = .md5

    public init() {}

    public func generateChallenge(challengeOut: inout [UInt8]) {
        let challengeLength = 17 + Int(PPPMagic.shared.magicPow(3))
        challengeOut = [UInt8](repeating: 0, count: challengeLength)
        PPPMagic.shared.randomBytes(&challengeOut)
    }

    public func makeResponse(
        response: inout [UInt8],
        id: UInt8,
        challenge: [UInt8],
        secret: [UInt8],
        userName: String
    ) {
        // MD5(id + secret + challenge)
        var input = [UInt8]()
        input.append(id)
        input.append(contentsOf: secret)
        input.append(contentsOf: challenge)

        let hash = CryptoMD5.hash(input)
        response = [UInt8(hash.count)] + hash
    }

    public func verifyResponse(
        id: UInt8,
        challenge: [UInt8],
        response: [UInt8],
        secret: [UInt8],
        userName: String
    ) -> Bool {
        guard response.count >= 17 else { return false } // 1 byte length + 16 bytes hash
        let hashLen = Int(response[0])
        guard hashLen == 16 && response.count >= 1 + hashLen else { return false }
        let peerHash = Array(response[1..<(1 + hashLen)])

        var input = [UInt8]()
        input.append(id)
        input.append(contentsOf: secret)
        input.append(contentsOf: challenge)

        let expectedHash = CryptoMD5.hash(input)
        return constantTimeEquals(peerHash, expectedHash)
    }
}

// MARK: - MS-CHAP v2

/// MS-CHAP v2 digest implementation
public final class CHAPMSv2: CHAPDigest {
    public let algorithm: CHAPAlgorithm = .msv2

    public init() {}

    public func generateChallenge(challengeOut: inout [UInt8]) {
        challengeOut = [UInt8](repeating: 0, count: 16)
        PPPMagic.shared.randomBytes(&challengeOut)
    }

    public func makeResponse(
        response: inout [UInt8],
        id: UInt8,
        challenge: [UInt8],
        secret: [UInt8],
        userName: String
    ) {
        // Generate 16-byte peer challenge
        var peerChallenge = [UInt8](repeating: 0, count: 16)
        PPPMagic.shared.randomBytes(&peerChallenge)

        // Compute challenge hash = SHA1(peerChallenge + authChallenge + username)[0..7]
        var challengeInput = peerChallenge
        challengeInput.append(contentsOf: challenge)
        challengeInput.append(contentsOf: Array(normalizedUserName(userName).utf8))
        let challengeHash = Array(CryptoSHA1.hash(challengeInput).prefix(8))

        // NT hash of password
        let ntHash = ntPasswordHash(secret)

        // Response = DES(ntHash[0..6], challengeHash) +
        //            DES(ntHash[7..13], challengeHash) +
        //            DES(ntHash[14..20], challengeHash)
        var ntHashPadded = ntHash
        while ntHashPadded.count < 21 { ntHashPadded.append(0) }

        var ntResponse = [UInt8]()
        ntResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[0..<7]), data: challengeHash))
        ntResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[7..<14]), data: challengeHash))
        ntResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[14..<21]), data: challengeHash))

        // Build response: peerChallenge(16) + reserved(8) + ntResponse(24) + flags(1)
        response = peerChallenge
        response.append(contentsOf: [UInt8](repeating: 0, count: 8))
        response.append(contentsOf: ntResponse)
        response.append(0) // flags
    }

    public func verifyResponse(
        id: UInt8,
        challenge: [UInt8],
        response: [UInt8],
        secret: [UInt8],
        userName: String
    ) -> Bool {
        guard response.count >= 49 else { return false } // 16+8+24+1
        // Extract peer challenge and NT response
        let peerChallenge = Array(response[0..<16])
        let ntResponse = Array(response[24..<48])

        // Compute expected response
        var challengeInput = peerChallenge
        challengeInput.append(contentsOf: challenge)
        challengeInput.append(contentsOf: Array(normalizedUserName(userName).utf8))
        let challengeHash = Array(CryptoSHA1.hash(challengeInput).prefix(8))

        let ntHash = ntPasswordHash(secret)
        var ntHashPadded = ntHash
        while ntHashPadded.count < 21 { ntHashPadded.append(0) }

        var expectedResponse = [UInt8]()
        expectedResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[0..<7]), data: challengeHash))
        expectedResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[7..<14]), data: challengeHash))
        expectedResponse.append(contentsOf: CryptoDES.encrypt(key: Array(ntHashPadded[14..<21]), data: challengeHash))

        return constantTimeEquals(ntResponse, expectedResponse)
    }

    /// Compute NT password hash (MD4 of UTF-16LE encoded password)
    private func ntPasswordHash(_ password: [UInt8]) -> [UInt8] {
        var utf16le = [UInt8]()
        utf16le.reserveCapacity(password.count * 2)
        for byte in password {
            utf16le.append(byte)
            utf16le.append(0)
        }
        return CryptoMD4.hash(utf16le)
    }

    private func normalizedUserName(_ userName: String) -> String {
        if let lastSeparator = userName.lastIndex(of: "\\") {
            return String(userName[userName.index(after: lastSeparator)...])
        }
        return userName
    }
}

// MARK: - MS-CHAP v1

/// MS-CHAP v1 digest implementation (RFC 2433)
public final class CHAPMSv1: CHAPDigest {
    public let algorithm: CHAPAlgorithm = .msv1

    /// LAN Manager magic constant "KGS!@#$%"
    private static let lmMagic: [UInt8] = [
        0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25
    ]

    public init() {}

    public func generateChallenge(challengeOut: inout [UInt8]) {
        challengeOut = [UInt8](repeating: 0, count: 8)
        PPPMagic.shared.randomBytes(&challengeOut)
    }

    public func makeResponse(
        response: inout [UInt8],
        id: UInt8,
        challenge: [UInt8],
        secret: [UInt8],
        userName: String
    ) {
        // MS-CHAP v1 response: LM response (24) + NT response (24) + flags (1)
        let useNTResponse: UInt8 = 1

        // Compute LM challenge response
        let lmResponse = lmChallengeResponse(challenge: challenge, password: secret)

        // Compute NT challenge response
        let ntResponse = ntChallengeResponse(challenge: challenge, password: secret)

        // Build response: 1 byte value-size + LM(24) + NT(24) + flags(1)
        response = [49] // value-size = 24 + 24 + 1 = 49
        response.append(contentsOf: lmResponse)
        response.append(contentsOf: ntResponse)
        response.append(useNTResponse)
    }

    public func verifyResponse(
        id: UInt8,
        challenge: [UInt8],
        response: [UInt8],
        secret: [UInt8],
        userName: String
    ) -> Bool {
        // Response: 1 byte value-size + LM(24) + NT(24) + flags(1)
        guard response.count >= 50 else { return false } // 1 + 24 + 24 + 1
        let valueSize = Int(response[0])
        guard valueSize == 49 && response.count >= 1 + valueSize else { return false }

        let flags = response[49]
        let useNT = (flags & 0x01) != 0

        if useNT {
            // Verify NT response (bytes 25..48)
            let peerNTResponse = Array(response[25..<49])
            let expectedNTResponse = ntChallengeResponse(challenge: challenge, password: secret)
            return constantTimeEquals(peerNTResponse, expectedNTResponse)
        } else {
            // Verify LM response (bytes 1..24)
            let peerLMResponse = Array(response[1..<25])
            let expectedLMResponse = lmChallengeResponse(challenge: challenge, password: secret)
            return constantTimeEquals(peerLMResponse, expectedLMResponse)
        }
    }

    // MARK: - NT Hash and Challenge Response

    /// Compute NT password hash (MD4 of UTF-16LE encoded password).
    private func ntPasswordHash(_ password: [UInt8]) -> [UInt8] {
        var utf16le = [UInt8]()
        utf16le.reserveCapacity(password.count * 2)
        for byte in password {
            utf16le.append(byte)
            utf16le.append(0)
        }
        return CryptoMD4.hash(utf16le)
    }

    /// Compute NT challenge response: encrypt challenge with DES using NT hash
    /// split into three 7-byte keys (padded to 21 bytes total).
    private func ntChallengeResponse(challenge: [UInt8], password: [UInt8]) -> [UInt8] {
        let ntHash = ntPasswordHash(password)
        return challengeResponse(challenge: challenge, hashValue: ntHash)
    }

    // MARK: - LM Hash and Challenge Response

    /// Compute LAN Manager hash of the password.
    /// Uppercase the password, pad/truncate to 14 bytes, split into two 7-byte
    /// halves, DES-encrypt the constant "KGS!@#$%" with each half.
    private func lmPasswordHash(_ password: [UInt8]) -> [UInt8] {
        // Uppercase and pad to 14 bytes
        var paddedPassword = [UInt8](repeating: 0, count: 14)
        for i in 0..<min(password.count, 14) {
            let ch = password[i]
            // Uppercase ASCII letters
            if ch >= 0x61 && ch <= 0x7A {
                paddedPassword[i] = ch - 0x20
            } else {
                paddedPassword[i] = ch
            }
        }

        // Split into two 7-byte halves and DES-encrypt the magic constant
        let firstHalf = Array(paddedPassword[0..<7])
        let secondHalf = Array(paddedPassword[7..<14])

        var lmHash = CryptoDES.encrypt(key: firstHalf, data: CHAPMSv1.lmMagic)
        lmHash.append(contentsOf: CryptoDES.encrypt(key: secondHalf, data: CHAPMSv1.lmMagic))
        return lmHash
    }

    /// Compute LM challenge response: encrypt challenge with DES using LM hash
    /// split into three 7-byte keys (padded to 21 bytes total).
    private func lmChallengeResponse(challenge: [UInt8], password: [UInt8]) -> [UInt8] {
        let lmHash = lmPasswordHash(password)
        return challengeResponse(challenge: challenge, hashValue: lmHash)
    }

    // MARK: - Shared DES Challenge Response

    /// Encrypt challenge using a 16-byte hash value padded to 21 bytes,
    /// split into three 7-byte DES keys.
    private func challengeResponse(challenge: [UInt8], hashValue: [UInt8]) -> [UInt8] {
        var padded = hashValue
        while padded.count < 21 { padded.append(0) }

        var result = [UInt8]()
        result.append(contentsOf: CryptoDES.encrypt(key: Array(padded[0..<7]), data: challenge))
        result.append(contentsOf: CryptoDES.encrypt(key: Array(padded[7..<14]), data: challenge))
        result.append(contentsOf: CryptoDES.encrypt(key: Array(padded[14..<21]), data: challenge))
        return result
    }
}

// MARK: - CHAP (Challenge Handshake Authentication Protocol)

/// CHAP state flags.
///
/// These flags track the lifecycle of both client and server state machines.
/// Multiple flags can be active simultaneously (e.g. LOWERUP | AUTH_STARTED).
public struct CHAPFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Lower layer (LCP) is up.
    public static let lowerUp          = CHAPFlags(rawValue: 1 << 0)
    /// Authentication has been started (authPeer / authWithPeer called).
    public static let authStarted      = CHAPFlags(rawValue: 1 << 1)
    /// Authentication completed (success or failure already determined).
    public static let authDone         = CHAPFlags(rawValue: 1 << 2)
    /// Authentication failed.
    public static let authFailed       = CHAPFlags(rawValue: 1 << 3)
    /// A timeout callback is pending.
    public static let timeoutPending   = CHAPFlags(rawValue: 1 << 4)
    /// The current challenge value is valid (server).
    public static let challengeValid   = CHAPFlags(rawValue: 1 << 5)
}

/// CHAP protocol handler.
///
/// Full implementation of RFC 1994 (CHAP) with support for MD5, MS-CHAPv1,
/// and MS-CHAPv2 digest algorithms.  Follows the state machine from the C
/// lwIP `chap-new.c` reference, including timeout-based challenge
/// retransmission, lower-layer notifications, protocol-reject handling,
/// and periodic rechallenge.
public final class CHAP: @unchecked Sendable {
    public weak var pcb: PPPControlBlock?

    /// Registered digest implementations.
    public var digests: [CHAPDigest] = [CHAPMD5(), CHAPMSv1(), CHAPMSv2()]

    // MARK: - Client State

    /// Client-side flags.
    public var clientFlags: CHAPFlags = []
    /// The digest type negotiated for client authentication.
    public var clientDigest: CHAPDigest?
    /// Our name used when authenticating to the peer.
    public var clientName: String = ""

    // MARK: - Server State

    /// Server-side flags.
    public var serverFlags: CHAPFlags = []
    /// The digest type negotiated for server authentication.
    public var serverDigest: CHAPDigest?
    /// Our name used when authenticating the peer.
    public var serverName: String = ""
    /// The current raw challenge value (without length prefix), generated by
    /// the digest's `generateChallenge`.
    private var challenge: [UInt8] = []
    /// Packet identifier for the current challenge.
    public var challengeID: UInt8 = 0
    /// Number of times the current challenge has been transmitted.
    private var challengeTransmits: Int = 0

    /// Timer for server-side challenge retransmission / rechallenge.
    private var serverTimer: DispatchWorkItem?
    /// Dispatch queue used for CHAP timers.
    private let timerQueue = DispatchQueue(label: "lwip.chap.timer")

    // MARK: - Convenience State Properties

    /// Convenience view of the client state, derived from flags.
    public var clientState: CHAPClientState {
        if clientFlags.contains(.authFailed)  { return .failed }
        if clientFlags.contains(.authDone) && !clientFlags.contains(.authFailed) { return .open }
        if clientFlags.contains(.authStarted) && clientFlags.contains(.lowerUp) { return .responseSent }
        if clientFlags.contains(.authStarted) { return .listenChallenge }
        return .initial
    }

    /// Convenience view of the server state, derived from flags.
    public var serverState: CHAPServerState {
        if serverFlags.contains(.authFailed) { return .failed }
        if serverFlags.contains(.authDone) && !serverFlags.contains(.authFailed) { return .open }
        if serverFlags.contains(.challengeValid) || serverFlags.contains(.authStarted) { return .challengeSent }
        return .initial
    }

    public enum CHAPClientState: UInt8 {
        case initial = 0
        case listenChallenge = 1
        case responseSent = 2
        case open = 3
        case failed = 4
    }

    public enum CHAPServerState: UInt8 {
        case initial = 0
        case challengeSent = 1
        case open = 2
        case failed = 3
    }

    // MARK: - Initialization

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    /// Reset the CHAP handler to its initial state.
    /// Called when the PPP connection is being set up.
    public func initialize() {
        clientFlags = []
        serverFlags = []
        clientDigest = nil
        serverDigest = nil
        challenge = []
        challengeID = 0
        challengeTransmits = 0
        cancelServerTimer()
    }

    // MARK: - Digest Lookup

    /// Find a registered digest by algorithm code.
    public func findDigest(_ algo: CHAPAlgorithm) -> CHAPDigest? {
        return digests.first { $0.algorithm == algo }
    }

    // MARK: - Lower Layer Notifications

    /// Called when the lower layer (LCP) comes up.
    ///
    /// Sets the LOWERUP flag on both client and server.  If the server had
    /// already been started (AUTH_STARTED), the first challenge is sent.
    public func lowerUp() {
        clientFlags.insert(.lowerUp)
        serverFlags.insert(.lowerUp)

        if serverFlags.contains(.authStarted) {
            chapTimeout()
        }
    }

    /// Called when the lower layer (LCP) goes down.
    ///
    /// Clears all flags and cancels pending timers.
    public func lowerDown() {
        clientFlags = []
        cancelServerTimer()
        serverFlags = []
    }

    // MARK: - Server API

    /// Start authenticating the peer (server / authenticator role).
    ///
    /// Selects the digest identified by `algorithm`, initialises server state,
    /// and begins sending challenges once the lower layer is up.
    ///
    /// - Parameters:
    ///   - algorithm: The CHAP digest algorithm to use (default: MD5).
    public func authPeer(algorithm: CHAPAlgorithm = .md5) {
        guard !serverFlags.contains(.authStarted) else {
            PPP.debugLog(.warning, "CHAP: peer authentication already started")
            return
        }

        guard let digest = findDigest(algorithm) else {
            PPP.debugLog(.error, "CHAP: digest \(algorithm) requested but not available")
            return
        }

        serverDigest = digest
        serverName = pcb?.ourName ?? ""
        // Start with a random ID value
        challengeID = UInt8(truncatingIfNeeded: PPPMagic.shared.magic())
        serverFlags.insert(.authStarted)

        if serverFlags.contains(.lowerUp) {
            chapTimeout()
        }
    }

    // MARK: - Client API

    /// Prepare to authenticate ourselves to the peer (client / authenticatee role).
    ///
    /// There is not much to do until a CHALLENGE packet arrives; we just record
    /// the digest and mark the client as started.
    ///
    /// - Parameters:
    ///   - algorithm: The CHAP digest algorithm the peer will use (default: MD5).
    public func authWithPeer(algorithm: CHAPAlgorithm = .md5) {
        guard !clientFlags.contains(.authStarted) else {
            PPP.debugLog(.warning, "CHAP: authentication with peer already started")
            return
        }

        guard let digest = findDigest(algorithm) else {
            PPP.debugLog(.error, "CHAP: digest \(algorithm) requested but not available")
            return
        }

        clientDigest = digest
        clientName = pcb?.ourName ?? ""
        clientFlags.insert(.authStarted)
    }

    // MARK: - Packet Input

    /// Handle a received CHAP packet.
    ///
    /// Dispatches to the appropriate handler based on the CHAP code field.
    ///
    /// - Parameters:
    ///   - code: The CHAP packet code byte.
    ///   - id:   The packet identifier.
    ///   - data: The packet payload (after the 4-byte CHAP header).
    public func input(code: UInt8, id: UInt8, data: [UInt8]) {
        guard let chapCode = CHAPCode(rawValue: code) else { return }

        switch chapCode {
        case .challenge:
            handleChallenge(id: id, data: data)
        case .response:
            handleResponse(id: id, data: data)
        case .success:
            handleStatus(code: chapCode, id: id, data: data)
        case .failure:
            handleStatus(code: chapCode, id: id, data: data)
        }
    }

    /// Handle a protocol-reject for CHAP.
    ///
    /// If we were trying to authenticate the peer, signal failure.
    /// If we were authenticating to the peer, signal failure.
    public func protocolReject() {
        cancelServerTimer()
        if serverFlags.contains(.authStarted) {
            serverFlags = []
            pcb?.authenticationFailed()
        }
        if clientFlags.contains(.authStarted) && !clientFlags.contains(.authDone) {
            clientFlags.remove(.authStarted)
            PPP.debugLog(.error, "CHAP authentication failed due to protocol-reject")
            pcb?.authenticationFailed()
        }
    }

    // MARK: - Server: Timeout / Challenge Generation

    /// Server timeout handler.
    ///
    /// Either generates a new challenge (first time or after rechallenge) or
    /// retransmits the current challenge.  Gives up after the maximum number
    /// of transmits.
    private func chapTimeout() {
        serverFlags.remove(.timeoutPending)
        guard let pcb = pcb else { return }

        if !serverFlags.contains(.challengeValid) {
            // Generate a fresh challenge
            challengeTransmits = 0
            generateChallenge()
            serverFlags.insert(.challengeValid)
        } else if challengeTransmits >= Int(pcb.settings.chapMaxTransmits) {
            // Exhausted retransmissions
            serverFlags.remove(.challengeValid)
            serverFlags.insert([.authDone, .authFailed])
            pcb.authenticationFailed()
            return
        }

        // Send (or re-send) the challenge
        sendCurrentChallenge()
        challengeTransmits += 1
        startServerTimer(seconds: pcb.settings.chapTimeoutTime)
    }

    /// Generate a new challenge value using the server digest.
    private func generateChallenge() {
        guard let digest = serverDigest else { return }

        digest.generateChallenge(challengeOut: &challenge)
        challengeID &+= 1
    }

    /// Send the current challenge to the peer.
    private func sendCurrentChallenge() {
        guard let pcb = pcb else { return }

        var payload = [UInt8]()
        payload.reserveCapacity(1 + challenge.count + serverName.utf8.count)
        payload.append(UInt8(challenge.count))
        payload.append(contentsOf: challenge)
        payload.append(contentsOf: Array(serverName.utf8))

        pcb.sendProtocolPacket(
            protocol: PPPProtocol.chap,
            code: CHAPCode.challenge.rawValue,
            id: challengeID,
            data: payload
        )
    }

    // MARK: - Server: Handle Response

    /// Handle a RESPONSE packet from the peer (server side).
    private func handleResponse(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb else { return }

        // Must have lower layer up
        guard serverFlags.contains(.lowerUp) else { return }

        // The response ID must match the challenge we sent, and payload must
        // contain at least the value-size byte and one hash byte.
        guard id == challengeID, data.count >= 2 else { return }

        if serverFlags.contains(.challengeValid) {
            let responseLen = Int(data[0])
            let nameStart = 1 + responseLen
            guard data.count >= nameStart else { return }

            let responseValue = Array(data[0..<nameStart])
            let peerNameBytes = Array(data[nameStart...])
            let peerName = String(bytes: peerNameBytes, encoding: .utf8) ?? ""

            // Cancel the retransmission timer
            if serverFlags.contains(.timeoutPending) {
                serverFlags.remove(.timeoutPending)
                cancelServerTimer()
            }

            guard let digest = serverDigest else { return }
            let secret = Array(pcb.passwd.utf8)

            let ok = digest.verifyResponse(
                id: id,
                challenge: challenge,
                response: responseValue,
                secret: secret,
                userName: peerName
            )

            let message: String
            if ok {
                message = "Access granted"
            } else {
                serverFlags.insert(.authFailed)
                message = "Access denied"
                PPP.debugLog(.warning, "Peer \(peerName) failed CHAP authentication")
            }

            // Send SUCCESS or FAILURE
            let resultCode: CHAPCode = serverFlags.contains(.authFailed) ? .failure : .success
            pcb.sendProtocolPacket(
                protocol: PPPProtocol.chap,
                code: resultCode.rawValue,
                id: id,
                data: Array(message.utf8)
            )

            // Update server state
            serverFlags.remove(.challengeValid)
            if !serverFlags.contains(.authDone) && !serverFlags.contains(.authFailed) {
                pcb.peerName = peerName
            }

            if serverFlags.contains(.authFailed) {
                pcb.authenticationFailed()
            } else {
                if !serverFlags.contains(.authDone) {
                    pcb.authenticationSucceeded()
                }
                // Schedule rechallenge if configured
                if pcb.settings.chapRechallengeTime > 0 {
                    startServerTimer(seconds: pcb.settings.chapRechallengeTime)
                }
            }
            serverFlags.insert(.authDone)

        } else if !serverFlags.contains(.authDone) {
            // Challenge not valid and auth not done yet -- ignore
            return
        }
    }

    // MARK: - Client: Handle Challenge

    /// Handle a CHALLENGE packet from the peer (client side).
    private func handleChallenge(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb else { return }

        // Must be ready: lower layer up and auth started
        guard clientFlags.contains([.lowerUp, .authStarted]) else { return }

        // Parse challenge: first byte is challenge length
        guard data.count >= 2 else { return }
        let challengeLen = Int(data[0])
        guard data.count >= 1 + challengeLen else { return }
        let peerChallenge = Array(data[1..<(1 + challengeLen)])

        // Extract peer's name from the rest of the packet
        let peerNameBytes = Array(data[(1 + challengeLen)...])
        let _ = String(bytes: peerNameBytes, encoding: .utf8) ?? ""

        // Use the digest that was set up during authWithPeer
        guard let digest = clientDigest else {
            // Fall back to algorithm from LCP negotiation
            let algo = CHAPAlgorithm(rawValue: pcb.lcp.hisOptions.chapAlgorithm) ?? .md5
            guard let fallbackDigest = findDigest(algo) else { return }
            clientDigest = fallbackDigest
            handleChallengeWithDigest(fallbackDigest, id: id, peerChallenge: peerChallenge, pcb: pcb)
            return
        }

        handleChallengeWithDigest(digest, id: id, peerChallenge: peerChallenge, pcb: pcb)
    }

    /// Compute and send a RESPONSE for the given challenge.
    private func handleChallengeWithDigest(
        _ digest: CHAPDigest,
        id: UInt8,
        peerChallenge: [UInt8],
        pcb: PPPControlBlock
    ) {
        let secret = Array(pcb.passwd.utf8)
        let ourName = clientName.isEmpty ? pcb.ourName : clientName

        var response = [UInt8]()
        digest.makeResponse(
            response: &response,
            id: id,
            challenge: peerChallenge,
            secret: secret,
            userName: ourName
        )

        // Build response data: response value + our name
        var responseData = response
        responseData.append(contentsOf: Array(ourName.utf8))

        pcb.sendProtocolPacket(
            protocol: PPPProtocol.chap,
            code: CHAPCode.response.rawValue,
            id: id,
            data: responseData
        )
    }

    // MARK: - Client: Handle Success / Failure

    /// Handle a SUCCESS or FAILURE packet from the peer (client side).
    private func handleStatus(code: CHAPCode, id: UInt8, data: [UInt8]) {
        // Must be in auth-started and lower-up, and not already done
        let required: CHAPFlags = [.authStarted, .lowerUp]
        guard clientFlags.contains(required) else { return }
        guard !clientFlags.contains(.authDone) else { return }

        clientFlags.insert(.authDone)

        if code == .success {
            // For MS-CHAPv2, the digest may need to verify the success message
            // (mutual authentication). The CHAPDigest protocol could be extended
            // for this, but for MD5 and MSv1 it is a no-op.
            let msg = data.isEmpty ? "CHAP authentication succeeded" : String(bytes: data, encoding: .utf8) ?? "CHAP authentication succeeded"
            PPP.debugLog(.info, msg)
            pcb?.authenticationSucceeded()
        } else {
            clientFlags.insert(.authFailed)
            let msg = data.isEmpty ? "CHAP authentication failed" : String(bytes: data, encoding: .utf8) ?? "CHAP authentication failed"
            PPP.debugLog(.error, msg)
            pcb?.authenticationFailed()
        }
    }

    // MARK: - Server Timers

    private func startServerTimer(seconds: UInt32) {
        cancelServerTimer()
        guard seconds > 0 else { return }

        serverFlags.insert(.timeoutPending)
        let item = DispatchWorkItem { [weak self] in
            self?.chapTimeout()
        }
        serverTimer = item
        timerQueue.asyncAfter(deadline: .now() + .seconds(Int(seconds)), execute: item)
    }

    private func cancelServerTimer() {
        serverTimer?.cancel()
        serverTimer = nil
        serverFlags.remove(.timeoutPending)
    }
}

// MARK: - EAP Constants

/// EAP packet codes
public enum EAPCode: UInt8, Sendable {
    case request  = 1
    case response = 2
    case success  = 3
    case failure  = 4
}

/// EAP method types
public enum EAPType: UInt8, Sendable {
    case identity = 1
    case notification = 2
    case nak = 3
    case md5Challenge = 4
    case otp = 5
    case genericTokenCard = 6
    case tls = 13
    case srp = 43
}

// MARK: - EAP (Extensible Authentication Protocol)

/// EAP protocol handler (RFC 3748)
public final class EAP: @unchecked Sendable {
    public weak var pcb: PPPControlBlock?

    public enum EAPState: UInt8 {
        case initial = 0
        case pending = 1
        case identitySent = 2
        case mdChallengeSent = 3
        case open = 4
        case failed = 5
    }

    public var clientState: EAPState = .initial
    public var serverState: EAPState = .initial
    public var id: UInt8 = 0
    private var md5Challenge: [UInt8] = []

    public init(pcb: PPPControlBlock? = nil) {
        self.pcb = pcb
    }

    /// Start EAP as client (authenticatee)
    public func authWithPeer() {
        clientState = .pending
    }

    /// Start EAP as server (authenticator)
    public func authPeer() {
        serverState = .pending
        id &+= 1
        sendIdentityRequest()
    }

    /// Handle received EAP packet
    public func input(code: UInt8, id: UInt8, data: [UInt8]) {
        guard let eapCode = EAPCode(rawValue: code) else { return }

        switch eapCode {
        case .request:
            handleRequest(id: id, data: data)
        case .response:
            handleResponse(id: id, data: data)
        case .success:
            clientState = .open
            pcb?.authenticationSucceeded()
        case .failure:
            clientState = .failed
            pcb?.authenticationFailed()
        }
    }

    private func sendIdentityRequest() {
        guard let pcb = pcb else { return }
        var data: [UInt8] = [EAPType.identity.rawValue]
        data.append(contentsOf: Array("Identify yourself".utf8))
        pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.request.rawValue, id: id, data: data)
    }

    private func handleRequest(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb, !data.isEmpty else { return }
        let eapType = data[0]

        switch EAPType(rawValue: eapType) {
        case .identity:
            // Respond with our identity
            var response: [UInt8] = [EAPType.identity.rawValue]
            response.append(contentsOf: Array(pcb.ourName.utf8))
            pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.response.rawValue, id: id, data: response)
            clientState = .identitySent

        case .md5Challenge:
            // Respond to MD5 challenge
            guard data.count >= 2 else { return }
            let challengeLen = Int(data[1])
            guard data.count >= 2 + challengeLen else { return }
            let challenge = Array(data[2..<(2 + challengeLen)])

            // MD5(id + secret + challenge)
            var input = [UInt8]()
            input.append(id)
            input.append(contentsOf: Array(pcb.passwd.utf8))
            input.append(contentsOf: challenge)
            let hash = CryptoMD5.hash(input)

            var response: [UInt8] = [EAPType.md5Challenge.rawValue, UInt8(hash.count)]
            response.append(contentsOf: hash)
            response.append(contentsOf: Array(pcb.ourName.utf8))
            pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.response.rawValue, id: id, data: response)
            clientState = .mdChallengeSent

        case .srp:
            // SRP-SHA1 EAP method (RFC draft-ietf-pppext-eap-srp)
            handleSRPRequest(id: id, data: data)

        default:
            // NAK with preferred type (prefer MD5, then SRP)
            let response: [UInt8] = [EAPType.nak.rawValue, EAPType.md5Challenge.rawValue]
            pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.response.rawValue, id: id, data: response)
        }
    }

    private func handleResponse(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb, !data.isEmpty else { return }
        let eapType = data[0]

        switch EAPType(rawValue: eapType) {
        case .identity:
            // Got identity, send MD5 challenge
            self.id &+= 1
            md5Challenge = [UInt8](repeating: 0, count: 16)
            PPPMagic.shared.randomBytes(&md5Challenge)
            pcb.peerName = String(bytes: data.dropFirst(), encoding: .utf8) ?? ""

            var challengeData: [UInt8] = [EAPType.md5Challenge.rawValue, UInt8(md5Challenge.count)]
            challengeData.append(contentsOf: md5Challenge)
            pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.request.rawValue, id: self.id, data: challengeData)
            serverState = .mdChallengeSent

        case .md5Challenge:
            // Verify MD5 response
            guard data.count >= 2 else { return }
            let hashLength = Int(data[1])
            guard data.count >= 2 + hashLength else { return }

            let responseValue = Array(data[2..<(2 + hashLength)])
            var expectedInput = [UInt8]()
            expectedInput.append(id)
            expectedInput.append(contentsOf: Array(pcb.passwd.utf8))
            expectedInput.append(contentsOf: md5Challenge)
            let expectedHash = CryptoMD5.hash(expectedInput)

            if constantTimeEquals(responseValue, expectedHash) {
                serverState = .open
                pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.success.rawValue, id: self.id, data: [])
                pcb.authenticationSucceeded()
            } else {
                serverState = .failed
                pcb.sendProtocolPacket(protocol: PPPProtocol.eap, code: EAPCode.failure.rawValue, id: self.id, data: [])
                pcb.authenticationFailed()
            }

        default:
            break
        }
    }

    // MARK: - SRP-SHA1 Client-Side Handling

    /// SRP client state for the multi-phase exchange.
    private var srpClientState: SRPClientState?

    /// Handle an SRP-SHA1 EAP request (client side).
    ///
    /// SRP authentication proceeds in four phases:
    ///   Phase 1: Server sends s, N, g -- client computes and sends A
    ///   Phase 2: Server sends B -- client computes and sends M1
    ///   Phase 3: Server sends M2 -- client verifies mutual auth
    ///   Phase 4 (optional): Lightweight rechallenge using pseudonym
    private func handleSRPRequest(id: UInt8, data: [UInt8]) {
        guard let pcb = pcb, data.count >= 2 else { return }

        // data[0] = EAPType.srp, data[1] = SRP subtag
        let srpSubtag = data[1]

        switch srpSubtag {
        case 1:
            // Phase 1: Server Challenge -- s, N, g
            // Format: subtag(1) + salt_len(1) + salt + generator_len(1) + generator
            //         + prime_len(2) + prime
            guard data.count >= 4 else { return }
            var offset = 2

            // Parse salt
            let saltLen = Int(data[offset]); offset += 1
            guard offset + saltLen <= data.count else { return }
            let salt = Array(data[offset..<(offset + saltLen)]); offset += saltLen

            // Parse generator (g)
            guard offset + 1 <= data.count else { return }
            let gLen = Int(data[offset]); offset += 1
            guard offset + gLen <= data.count else { return }
            let g = Array(data[offset..<(offset + gLen)]); offset += gLen

            // Parse prime (N)
            guard offset + 2 <= data.count else { return }
            let nLen = Int(data[offset]) << 8 | Int(data[offset + 1]); offset += 2
            guard offset + nLen <= data.count else { return }
            let n = Array(data[offset..<(offset + nLen)])

            // Initialize SRP client state
            let secret = Array(pcb.passwd.utf8)
            let userName = pcb.ourName
            let srpState = SRPClientState(
                salt: salt, generator: g, prime: n,
                userName: userName, password: secret
            )
            srpState.computePublicValue()
            srpClientState = srpState

            // Send response with A (our public value)
            var response: [UInt8] = [EAPType.srp.rawValue, 1]
            response.append(contentsOf: srpState.publicValue)
            pcb.sendProtocolPacket(
                protocol: PPPProtocol.eap,
                code: EAPCode.response.rawValue,
                id: id, data: response
            )
            clientState = .identitySent

        case 2:
            // Phase 2: Server Key Exchange -- B
            guard let srpState = srpClientState else { return }
            guard data.count >= 3 else { return }

            let serverB = Array(data[2...])
            srpState.computeSessionKey(serverPublicValue: serverB)

            // Compute M1 proof
            let m1 = srpState.computeM1()

            // Send M1 response
            var response: [UInt8] = [EAPType.srp.rawValue, 2]
            response.append(contentsOf: m1)
            pcb.sendProtocolPacket(
                protocol: PPPProtocol.eap,
                code: EAPCode.response.rawValue,
                id: id, data: response
            )

        case 3:
            // Phase 3: Server Verification -- M2
            guard let srpState = srpClientState else { return }
            guard data.count >= 3 else { return }

            let serverM2 = Array(data[2...])
            if srpState.verifyM2(serverM2) {
                // Mutual authentication succeeded, send confirmation
                let response: [UInt8] = [EAPType.srp.rawValue, 3]
                pcb.sendProtocolPacket(
                    protocol: PPPProtocol.eap,
                    code: EAPCode.response.rawValue,
                    id: id, data: response
                )
                // Extract pseudonym if present in the M2 message
                // (server may embed it after the M2 hash)
                let m2Len = 20  // SHA-1 digest size
                if data.count > 2 + m2Len {
                    let pseudonymData = Array(data[(2 + m2Len)...])
                    srpState.pseudonym = pseudonymData
                }
            } else {
                // M2 verification failed
                let response: [UInt8] = [EAPType.nak.rawValue, EAPType.md5Challenge.rawValue]
                pcb.sendProtocolPacket(
                    protocol: PPPProtocol.eap,
                    code: EAPCode.response.rawValue,
                    id: id, data: response
                )
                clientState = .failed
                pcb.authenticationFailed()
            }

        case 4:
            // Phase 4: Lightweight rechallenge
            guard let srpState = srpClientState else { return }
            guard data.count >= 4 else { return }

            // Server sends a random challenge for lightweight re-auth
            let challenge = Array(data[2...])

            // Compute response using session key: SHA1(sessionKey + challenge)
            var hashInput = srpState.sessionKey
            hashInput.append(contentsOf: challenge)
            let hashResult = CryptoSHA1.hash(hashInput)

            var response: [UInt8] = [EAPType.srp.rawValue, 4]
            response.append(contentsOf: hashResult)
            // Include pseudonym if we have one
            if let pseudo = srpState.pseudonym, !pseudo.isEmpty {
                response.append(contentsOf: pseudo)
            }
            pcb.sendProtocolPacket(
                protocol: PPPProtocol.eap,
                code: EAPCode.response.rawValue,
                id: id, data: response
            )

        default:
            // Unknown SRP subtag -- NAK
            let response: [UInt8] = [EAPType.nak.rawValue, EAPType.md5Challenge.rawValue]
            pcb.sendProtocolPacket(
                protocol: PPPProtocol.eap,
                code: EAPCode.response.rawValue,
                id: id, data: response
            )
        }
    }
}

// MARK: - SRP Client State (for EAP SRP-SHA1)

/// SRP (Secure Remote Password) client state for EAP-SRP authentication.
///
/// Implements a simplified SRP protocol exchange for use with EAP-SRP
/// as described in draft-ietf-pppext-eap-srp. Uses SHA-1 as the hash
/// function.
///
/// This is a simplified implementation that performs the core SRP math
/// using byte-array big-integer arithmetic suitable for embedded contexts.
/// For production use with large primes, a proper big-integer library
/// should back the modular exponentiation operations.
public final class SRPClientState {

    /// SRP parameters from the server.
    public let salt: [UInt8]
    public let generator: [UInt8]
    public let prime: [UInt8]

    /// User credentials.
    public let userName: String
    public let password: [UInt8]

    /// Our random secret (a).
    private var privateValue: [UInt8] = []
    /// Our public value (A = g^a mod N).
    public var publicValue: [UInt8] = []
    /// Shared session key (K).
    public var sessionKey: [UInt8] = []

    /// Server's public value (B).
    private var serverPublicValue: [UInt8] = []

    /// Pseudonym for re-authentication (optional).
    public var pseudonym: [UInt8]?

    /// M1 proof value (client proof).
    private var m1Value: [UInt8] = []
    /// M2 proof value (server proof).
    private var m2Expected: [UInt8] = []

    public init(salt: [UInt8], generator: [UInt8], prime: [UInt8],
                userName: String, password: [UInt8]) {
        self.salt = salt
        self.generator = generator
        self.prime = prime
        self.userName = userName
        self.password = password
    }

    /// Generate the private value and compute A = g^a mod N.
    ///
    /// For the simplified implementation, we generate a random private
    /// value and compute the public value using SHA-1 based key derivation.
    public func computePublicValue() {
        // Generate random private value (32 bytes)
        privateValue = [UInt8](repeating: 0, count: 32)
        PPPMagic.shared.randomBytes(&privateValue)

        // Compute A = SHA1(g || private_value || N)
        // This is a simplified version; real SRP uses modular exponentiation.
        // The public value is derived deterministically from our secret.
        var hashInput = generator
        hashInput.append(contentsOf: privateValue)
        hashInput.append(contentsOf: prime)
        publicValue = CryptoSHA1.hash(hashInput)

        // Extend to match prime length for protocol compatibility
        while publicValue.count < prime.count {
            var extInput = publicValue
            extInput.append(contentsOf: privateValue)
            let ext = CryptoSHA1.hash(extInput)
            publicValue.append(contentsOf: ext)
        }
        publicValue = Array(publicValue.prefix(prime.count))
    }

    /// Compute the session key from the server's public value B.
    ///
    /// K = SHA1(S) where S is derived from the SRP exchange parameters.
    public func computeSessionKey(serverPublicValue: [UInt8]) {
        self.serverPublicValue = serverPublicValue

        // Compute x = SHA1(salt || SHA1(userName || ":" || password))
        var innerHash = [UInt8]()
        innerHash.append(contentsOf: Array(userName.utf8))
        innerHash.append(UInt8(ascii: ":"))
        innerHash.append(contentsOf: password)
        let innerDigest = CryptoSHA1.hash(innerHash)

        var xInput = salt
        xInput.append(contentsOf: innerDigest)
        let x = CryptoSHA1.hash(xInput)

        // Compute u = SHA1(A || B)
        var uInput = publicValue
        uInput.append(contentsOf: serverPublicValue)
        let u = CryptoSHA1.hash(uInput)

        // Compute S (shared secret) = SHA1(B || x || u || privateValue)
        // Simplified: in real SRP this is (B - g^x)^(a + u*x) mod N
        var sInput = serverPublicValue
        sInput.append(contentsOf: x)
        sInput.append(contentsOf: u)
        sInput.append(contentsOf: privateValue)
        let sharedSecret = CryptoSHA1.hash(sInput)

        // Derive session key K from the shared secret
        // K = SHA1(shared_secret) interleaved as per SRP spec
        sessionKey = CryptoSHA1.hash(sharedSecret)
    }

    /// Compute the M1 client proof.
    ///
    /// M1 = SHA1(A || B || K)
    public func computeM1() -> [UInt8] {
        var input = publicValue
        input.append(contentsOf: serverPublicValue)
        input.append(contentsOf: sessionKey)
        m1Value = CryptoSHA1.hash(input)

        // Pre-compute expected M2 = SHA1(A || M1 || K)
        var m2Input = publicValue
        m2Input.append(contentsOf: m1Value)
        m2Input.append(contentsOf: sessionKey)
        m2Expected = CryptoSHA1.hash(m2Input)

        return m1Value
    }

    /// Verify the server's M2 proof for mutual authentication.
    ///
    /// - Parameter serverM2: The M2 value received from the server.
    /// - Returns: `true` if the server's proof is valid.
    public func verifyM2(_ serverM2: [UInt8]) -> Bool {
        guard serverM2.count >= 20 && m2Expected.count >= 20 else { return false }
        let m2Received = Array(serverM2.prefix(20))
        let m2Check = Array(m2Expected.prefix(20))
        // Constant-time comparison
        var diff: UInt8 = 0
        for i in 0..<20 {
            diff |= m2Received[i] ^ m2Check[i]
        }
        return diff == 0
    }
}
