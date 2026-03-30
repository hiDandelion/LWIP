//
//  IfAPI.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Interface Name Size

/// Interface identification constants.
public extension IfAPI {
    /// Maximum length of an interface name (matching NetworkInterfaceConstants.nameSize).
    static let nameMaxLength = 6
}

// MARK: - IfAPI

/// Interface identification API (RFC 3493 Section 4).
///
/// Thread-safe functions for mapping between interface names and indices.
public enum IfAPI {

    /// Convert an interface index to its corresponding name.
    ///
    /// - Parameter ifIndex: The interface index.
    /// - Returns: The interface name, or `nil` if not found.
    public static func indexToName(_ ifIndex: UInt) -> String? {
        guard ifIndex <= 0xFF else { return nil }

        switch NetifAPI.indexToName(UInt8(ifIndex)) {
        case .success(let name):
            return name.isEmpty ? nil : name
        case .failure:
            return nil
        }
    }

    /// Convert an interface name to its corresponding index.
    ///
    /// - Parameter ifName: The interface name (e.g. "en0").
    /// - Returns: The interface index, or 0 if not found.
    public static func nameToIndex(_ ifName: String) -> UInt {
        switch NetifAPI.nameToIndex(ifName) {
        case .success(let idx):
            return UInt(idx)
        case .failure:
            return 0
        }
    }
}


