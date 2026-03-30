//
//  LWIPError.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

/// lwIP error codes.
public enum LWIPError: Int8, Error, Sendable, Equatable, Hashable, CustomStringConvertible {
    /// No error, everything OK.
    case ok          =   0
    /// Out of memory error.
    case outOfMemory           =  -1
    /// Buffer error.
    case bufferError           =  -2
    /// Timeout.
    case timeout               =  -3
    /// Routing problem.
    case routingError          =  -4
    /// Operation in progress.
    case inProgress            =  -5
    /// Illegal value.
    case invalidValue          =  -6
    /// Operation would block.
    case wouldBlock            =  -7
    /// Address in use.
    case addressInUse          =  -8
    /// Already connecting.
    case already               =  -9
    /// Connection already established.
    case connectionEstablished = -10
    /// Not connected.
    case notConnected          = -11
    /// Low-level netif error.
    case interfaceError        = -12
    /// Connection aborted.
    case aborted               = -13
    /// Connection reset.
    case reset                 = -14
    /// Connection closed.
    case closed                = -15
    /// Illegal argument.
    case invalidArgument       = -16

    // MARK: - CustomStringConvertible

    public var description: String {
        switch self {
        case .ok:                     return "Ok."
        case .outOfMemory:            return "Out of memory error."
        case .bufferError:            return "Buffer error."
        case .timeout:                return "Timeout."
        case .routingError:           return "Routing problem."
        case .inProgress:             return "Operation in progress."
        case .invalidValue:           return "Illegal value."
        case .wouldBlock:             return "Operation would block."
        case .addressInUse:           return "Address in use."
        case .already:                return "Already connecting."
        case .connectionEstablished:  return "Already connected."
        case .notConnected:           return "Not connected."
        case .interfaceError:         return "Low-level netif error."
        case .aborted:                return "Connection aborted."
        case .reset:                  return "Connection reset."
        case .closed:                 return "Connection closed."
        case .invalidArgument:        return "Illegal argument."
        }
    }

    // MARK: - Conversion to POSIX errno

    /// Map an lwIP error to the closest POSIX errno value.
    public var posixErrno: Int32 {
        switch self {
        case .ok:                     return 0
        case .outOfMemory:            return ENOMEM
        case .bufferError:            return ENOBUFS
        case .timeout:                return EWOULDBLOCK
        case .routingError:           return EHOSTUNREACH
        case .inProgress:             return EINPROGRESS
        case .invalidValue:           return EINVAL
        case .wouldBlock:             return EWOULDBLOCK
        case .addressInUse:           return EADDRINUSE
        case .already:                return EALREADY
        case .connectionEstablished:  return EISCONN
        case .notConnected:           return ENOTCONN
        case .interfaceError:         return -1
        case .aborted:                return ECONNABORTED
        case .reset:                  return ECONNRESET
        case .closed:                 return ENOTCONN
        case .invalidArgument:        return EIO
        }
    }

    // MARK: - Helpers

    /// Returns `true` when this error represents success (.ok).
    @inlinable
    public var isOk: Bool { self == .ok }

    /// Returns `true` when this error represents a fatal / non-recoverable condition.
    @inlinable
    public var isFatal: Bool {
        switch self {
        case .aborted, .reset, .closed, .notConnected:
            return true
        default:
            return false
        }
    }
}

// MARK: - Raw Value Conversion

extension Int8 {
    /// Convert a raw `Int8` value to the corresponding `LWIPError`.
    /// Returns `nil` if the raw value does not correspond to a known error.
    @inlinable
    public var asLWIPError: LWIPError? {
        LWIPError(rawValue: self)
    }
}
