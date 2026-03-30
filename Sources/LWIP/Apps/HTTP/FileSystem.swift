//
//  FileSystem.swift
//  LWIP
//
//  Created by Argsment Limited on 4/3/26.
//

import Foundation

// MARK: - Filesystem Configuration

/// HTTP filesystem configuration constants.
public enum HTTPFileSystemConfig {
    /// Whether to support custom (dynamic) files.
    public static var supportCustomFiles: Bool = false
    /// Whether to support dynamic file reading (vs. memory-mapped ROM).
    public static var dynamicFileRead: Bool = true
    /// Whether to support async file reads.
    public static var asyncRead: Bool = false
    /// Whether files carry a per-file state object.
    public static var fileState: Bool = false
    /// Whether files carry a user extension pointer.
    public static var fileExtension: Bool = false
    /// Whether checksums are pre-calculated for built-in files.
    public static var precalculatedChecksum: Bool = false
    /// Return value indicating end-of-file.
    public static let readEOF: Int = -1
    /// Return value indicating an asynchronous read is pending.
    public static let readDelayed: Int = -2
}

// MARK: - File Flags

/// Flags describing properties of a filesystem file.
public struct HTTPFileFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// File data should be included in server-sent-includes processing.
    public static let ssi             = HTTPFileFlags(rawValue: 0x01)
    /// File is gzip-compressed.
    public static let gzipEncoded     = HTTPFileFlags(rawValue: 0x02)
    /// File is served from a custom (dynamic) handler.
    public static let custom          = HTTPFileFlags(rawValue: 0x04)
    /// File header is already included in the data.
    public static let headerIncluded  = HTTPFileFlags(rawValue: 0x08)
    /// File header persistence across connections.
    public static let headerPersistent = HTTPFileFlags(rawValue: 0x10)
    /// File header is already in the HTTP response.
    public static let headerHttpOk    = HTTPFileFlags(rawValue: 0x20)
}

// MARK: - File Checksum Entry

/// Pre-calculated checksum for a region of a file (for zero-copy transmit).
public struct HTTPFileChecksum: Sendable {
    /// Offset into the file data.
    public var offset: UInt32
    /// Length of the checksummed region.
    public var length: UInt16
    /// Pre-calculated checksum value.
    public var checksum: UInt16

    public init(offset: UInt32 = 0, length: UInt16 = 0, checksum: UInt16 = 0) {
        self.offset = offset
        self.length = length
        self.checksum = checksum
    }
}

// MARK: - FSDataFile (ROM filesystem entry)

/// A single entry in the compiled-in (ROM) filesystem.
///
/// Forms a singly-linked list. Each entry holds the file's name,
/// data, length, and flags.
public final class FSDataFile: @unchecked Sendable {
    /// Next file in the linked list.
    public var next: FSDataFile?
    /// File path/name (e.g., "/index.html").
    public let name: String
    /// Raw file data.
    public let data: [UInt8]
    /// File length in bytes.
    public let length: Int
    /// File property flags.
    public let flags: HTTPFileFlags
    /// Pre-calculated checksums (if enabled).
    public var checksums: [HTTPFileChecksum] = []
    /// Custom HTTP headers for this file (appended to the response).
    public var customHeaders: String?

    public init(name: String, data: [UInt8], flags: HTTPFileFlags = [],
                customHeaders: String? = nil) {
        self.name = name
        self.data = data
        self.length = data.count
        self.flags = flags
        self.customHeaders = customHeaders
    }
}

// MARK: - HTTPFile (open file handle)

/// An open file handle for reading from the HTTP filesystem.
///
/// Tracks the current read position within the file data.
///
/// We use `index` as the read cursor for all access modes, so ROM files
/// set `index = 0` for the readable copy and track the full data length
/// separately.
public final class HTTPFile: @unchecked Sendable {
    /// Pointer to the file data (from ROM or custom source).
    public var data: [UInt8]
    /// Total file length in bytes.
    public let length: Int
    /// Current read position (index into data) for dynamic reads via `fs_read`.
    /// For ROM files, this starts at `length` because the server accesses
    /// `data` directly. For custom files, starts at 0.
    public var index: Int
    /// File property flags.
    public var flags: HTTPFileFlags
    /// Pre-calculated checksums (if enabled).
    public var checksums: [HTTPFileChecksum]
    /// Per-file extension pointer (if enabled).
    public var extensionData: AnyObject?
    /// Per-file state object (if enabled).
    public var state: AnyObject?
    /// Custom HTTP headers for this file.
    public var customHeaders: String?

    /// Number of bytes remaining to be read (via dynamic fs_read).
    public var bytesLeft: Int {
        return length - index
    }

    /// Whether the file has been fully read (via dynamic fs_read).
    public var isEOF: Bool {
        return index >= length
    }

    public init(data: [UInt8] = [],
                flags: HTTPFileFlags = [],
                checksums: [HTTPFileChecksum] = []) {
        self.data = data
        self.length = data.count
        self.index = 0
        self.flags = flags
        self.checksums = checksums
    }

    /// Initialize from a ROM filesystem entry.
    ///
    /// Sets `index = length` for ROM files: the data is accessed directly
    /// via the `data` array, and `index` is set to `length` to indicate that
    /// dynamic fs_read would report EOF. The server accesses `data` directly
    /// rather than going through `read()`.
    internal init(fromFSData file: FSDataFile) {
        self.data = file.data
        self.length = file.length
        self.index = file.length  // ROM files: index = len (EOF for dynamic reads)
        self.flags = file.flags
        self.checksums = file.checksums
        self.customHeaders = file.customHeaders
    }
}

// MARK: - Custom File System Protocol

/// Protocol for providing custom (dynamic) file handling.
///
/// Implement this protocol to serve files from custom sources (e.g.,
/// database, network, generated content).
public protocol HTTPCustomFileSystem: AnyObject, Sendable {
    /// Open a custom file by name.
    ///
    /// - Parameters:
    ///   - file: The file handle to populate with data.
    ///   - name: The requested file path.
    /// - Returns: `true` if the file was found and opened.
    func open(_ file: HTTPFile, name: String) -> Bool

    /// Close a custom file and release resources.
    ///
    /// - Parameter file: The file handle to close.
    func close(_ file: HTTPFile)

    /// Read data from a custom file.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - buffer: Destination buffer.
    ///   - count: Maximum bytes to read.
    /// - Returns: Number of bytes read, or `HTTPFileSystemConfig.readEOF` on EOF.
    func read(_ file: HTTPFile, into buffer: inout [UInt8], count: Int) -> Int

    /// Check if more data can be read without blocking.
    ///
    /// - Parameter file: The open file handle.
    /// - Returns: `true` if data is available immediately.
    func canRead(_ file: HTTPFile) -> Bool

    /// Asynchronous file read. Returns the number of bytes read, or
    /// `FS_READ_DELAYED` if the read will complete asynchronously
    /// (the callback will be called later when data is ready).
    ///
    /// When the return value is `FS_READ_DELAYED`, the server pauses
    /// sending and resumes when `callback` is invoked.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - buffer: Destination buffer.
    ///   - count: Maximum bytes to read.
    ///   - callback: Closure invoked when data becomes available.
    /// - Returns: Number of bytes read, `HTTPFileSystemConfig.readEOF` on EOF,
    ///   or `HTTPFileSystemConfig.readDelayed` if the read is asynchronous.
    func readAsync(_ file: HTTPFile, into buffer: inout [UInt8], count: Int,
                   callback: @escaping () -> Void) -> Int

    /// Check if a file has data ready, registering a callback if not.
    ///
    /// When the file is not ready, the callback will be invoked once data
    /// is available, allowing the server to resume sending.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - callback: Closure invoked when the file becomes ready.
    /// - Returns: `true` if data is available immediately, `false` if
    ///   the callback has been registered for later notification.
    func isFileReadyAsync(_ file: HTTPFile, callback: @escaping () -> Void) -> Bool
}

/// Default implementations for optional custom file system methods.
public extension HTTPCustomFileSystem {
    func canRead(_ file: HTTPFile) -> Bool { return true }

    func readAsync(_ file: HTTPFile, into buffer: inout [UInt8], count: Int,
                   callback: @escaping () -> Void) -> Int {
        // Default: perform synchronous read, never delayed.
        return read(file, into: &buffer, count: count)
    }

    func isFileReadyAsync(_ file: HTTPFile, callback: @escaping () -> Void) -> Bool {
        // Default: always ready.
        return canRead(file)
    }
}

// MARK: - Async Read Callback

extension HTTPFileSystem {
    /// Callback invoked when an async file read completes.
    public typealias WaitHandler = @Sendable () -> Void
}

// MARK: - Content Type Inference

extension HTTPFileSystem {
    /// Infer the MIME content type from a file path extension.
    ///
    /// Supports common web content types: HTML, CSS, JavaScript, JSON,
    /// XML, images, fonts, and binary formats.
    ///
    /// - Parameter path: The file path or name.
    /// - Returns: The MIME type string.
    public static func contentType(forPath path: String) -> String {
        // Strip query parameters.
        let basePath: String
        if let qIdx = path.firstIndex(of: "?") {
            basePath = String(path[path.startIndex..<qIdx])
        } else {
            basePath = path
        }

        // Extract extension.
        let ext: String
        if let dotIdx = basePath.lastIndex(of: ".") {
            ext = String(basePath[basePath.index(after: dotIdx)...]).lowercased()
        } else {
            ext = ""
        }

        switch ext {
        case "html", "htm":         return "text/html"
        case "shtml", "shtm", "ssi": return "text/html"
        case "css":                 return "text/css"
        case "js":                  return "application/javascript"
        case "json":                return "application/json"
        case "xml":                 return "application/xml"
        case "txt":                 return "text/plain"
        case "csv":                 return "text/csv"
        case "png":                 return "image/png"
        case "jpg", "jpeg":         return "image/jpeg"
        case "gif":                 return "image/gif"
        case "svg":                 return "image/svg+xml"
        case "ico":                 return "image/x-icon"
        case "webp":                return "image/webp"
        case "bmp":                 return "image/bmp"
        case "woff":                return "font/woff"
        case "woff2":               return "font/woff2"
        case "ttf":                 return "font/ttf"
        case "otf":                 return "font/otf"
        case "eot":                 return "application/vnd.ms-fontobject"
        case "pdf":                 return "application/pdf"
        case "zip":                 return "application/zip"
        case "gz", "gzip":          return "application/gzip"
        case "tar":                 return "application/x-tar"
        case "mp3":                 return "audio/mpeg"
        case "ogg":                 return "audio/ogg"
        case "wav":                 return "audio/wav"
        case "mp4":                 return "video/mp4"
        case "webm":                return "video/webm"
        case "bin":                 return "application/octet-stream"
        default:                    return "application/octet-stream"
        }
    }

    /// Check if a file extension indicates SSI processing is needed.
    ///
    /// - Parameter path: The file path or name.
    /// - Returns: `true` if the file should be processed for SSI tags.
    public static func isSSIExtension(_ path: String) -> Bool {
        let basePath: String
        if let qIdx = path.firstIndex(of: "?") {
            basePath = String(path[path.startIndex..<qIdx])
        } else {
            basePath = path
        }
        let lower = basePath.lowercased()
        return lower.hasSuffix(".shtml") || lower.hasSuffix(".shtm") ||
               lower.hasSuffix(".ssi")
    }
}

// MARK: - HTTP File System

/// HTTP server virtual filesystem.
///
/// Provides open/read/close operations for the HTTP server. Files are
/// first looked up in the compiled-in (ROM) filesystem, then in a
/// custom file handler if configured.
///
/// Usage:
/// ```swift
/// let fs = HTTPFileSystem()
/// // Add ROM files
/// fs.addFile(FSDataFile(name: "/index.html", data: htmlBytes))
/// // Open and read
/// if let file = fs.open("/index.html") {
///     // For ROM files, access file.data directly
///     let content = file.data
///     fs.close(file: file)
/// }
/// ```
public final class HTTPFileSystem: @unchecked Sendable {

    // MARK: - Properties

    /// Head of the ROM filesystem linked list.
    private var root: FSDataFile?

    /// Custom file system handler.
    public var customFileSystem: HTTPCustomFileSystem?

    /// Lock for thread safety.
    private let lock = NSLock()

    // MARK: - Initialization

    /// Create a new HTTP filesystem.
    public init() {}

    // MARK: - ROM File Management

    /// Add a file to the ROM filesystem.
    ///
    /// - Parameter file: The filesystem data file entry.
    public func addFile(_ file: FSDataFile) {
        lock.lock()
        defer { lock.unlock() }
        file.next = root
        root = file
    }

    /// Add a file by name and data (convenience).
    ///
    /// - Parameters:
    ///   - name: File path (e.g. "/index.html").
    ///   - data: File content bytes.
    ///   - flags: File property flags.
    ///   - customHeaders: Optional custom HTTP headers.
    public func addFile(name: String, data: [UInt8], flags: HTTPFileFlags = [],
                        customHeaders: String? = nil) {
        let entry = FSDataFile(name: name, data: data, flags: flags,
                               customHeaders: customHeaders)
        addFile(entry)
    }

    /// Add a file by name and string content (convenience).
    ///
    /// - Parameters:
    ///   - name: File path (e.g. "/index.html").
    ///   - content: File content as a string.
    ///   - flags: File property flags.
    ///   - customHeaders: Optional custom HTTP headers.
    public func addFile(name: String, content: String, flags: HTTPFileFlags = [],
                        customHeaders: String? = nil) {
        addFile(name: name, data: Array(content.utf8), flags: flags,
                customHeaders: customHeaders)
    }

    /// Set the complete ROM filesystem root.
    ///
    /// - Parameter root: The head of the filesystem linked list.
    public func setRoot(_ root: FSDataFile?) {
        lock.lock()
        defer { lock.unlock() }
        self.root = root
    }

    /// Return the number of files in the ROM filesystem.
    public var fileCount: Int {
        lock.lock()
        defer { lock.unlock() }
        var count = 0
        var entry = root
        while entry != nil {
            count += 1
            entry = entry?.next
        }
        return count
    }

    // MARK: - File Operations

    /// Open a file by name.
    ///
    /// Searches the custom filesystem first (if enabled), then the ROM filesystem.
    ///
    /// - Parameter name: The file path to open (e.g., "/index.html").
    /// - Returns: An open file handle, or nil if the file was not found.
    public func open(_ name: String) -> HTTPFile? {
        // Try custom filesystem first.
        if HTTPFileSystemConfig.supportCustomFiles, let customFS = customFileSystem {
            let file = HTTPFile()
            if customFS.open(file, name: name) {
                file.flags.insert(.custom)
                return file
            }
        }

        // Search ROM filesystem.
        lock.lock()
        var entry = root
        lock.unlock()

        while let current = entry {
            if current.name == name {
                let handle = HTTPFile(fromFSData: current)
                if HTTPFileSystemConfig.fileExtension {
                    handle.extensionData = nil
                }
                if HTTPFileSystemConfig.fileState {
                    // handle.state = fsStateInit(handle, name)
                }
                return handle
            }
            entry = current.next
        }

        // File not found.
        return nil
    }

    /// Close an open file.
    ///
    /// Releases resources associated with the file handle.
    ///
    /// - Parameter file: The file handle to close.
    public func close(file: HTTPFile) {
        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            customFileSystem?.close(file)
        }
        if HTTPFileSystemConfig.fileState {
            // fsStateFree(file, file.state)
        }
        file.data = []
        file.state = nil
        file.extensionData = nil
    }

    /// Read data from an open file.
    ///
    /// For ROM files, copies data from the in-memory buffer starting at `index`.
    /// For custom files, delegates to the custom file system handler.
    ///
    /// ROM files opened via `open()` will have `isEOF == true` for
    /// `read()`, and the server should access `data` directly.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - count: Maximum number of bytes to read.
    /// - Returns: The bytes read, or an empty array on EOF.
    public func read(file: HTTPFile, count: Int) -> [UInt8] {
        guard !file.isEOF else { return [] }

        // Custom file handling.
        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            if let customFS = customFileSystem {
                var buffer = [UInt8](repeating: 0, count: count)
                let bytesRead = customFS.read(file, into: &buffer, count: count)
                if bytesRead <= 0 { return [] }
                return Array(buffer.prefix(bytesRead))
            }
            return []
        }

        // ROM file: copy from memory (used only in dynamic-file-read mode).
        let available = file.length - file.index
        let toRead = min(available, count)
        guard toRead > 0 else { return [] }

        let result = Array(file.data[file.index..<(file.index + toRead)])
        file.index += toRead
        return result
    }

    /// Read data from an open file into a buffer.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - buffer: Destination buffer to fill.
    ///   - count: Maximum bytes to read.
    /// - Returns: Number of bytes read, or `HTTPFileSystemConfig.readEOF` on EOF.
    public func read(file: HTTPFile, into buffer: inout [UInt8], count: Int) -> Int {
        guard !file.isEOF else { return HTTPFileSystemConfig.readEOF }

        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            if let customFS = customFileSystem {
                return customFS.read(file, into: &buffer, count: count)
            }
            return HTTPFileSystemConfig.readEOF
        }

        let available = file.length - file.index
        let toRead = min(available, count)
        guard toRead > 0 else { return HTTPFileSystemConfig.readEOF }

        for i in 0..<toRead {
            if i < buffer.count {
                buffer[i] = file.data[file.index + i]
            }
        }
        file.index += toRead
        return toRead
    }

    /// Asynchronous file read.
    ///
    /// For custom files with async support enabled, delegates to the custom
    /// file system's `readAsync` method, which may return `readDelayed` to
    /// indicate that data is not yet available and the callback will fire
    /// later. For ROM files (or when async is disabled), falls through to
    /// the synchronous read path.
    ///
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - buffer: Destination buffer to fill.
    ///   - count: Maximum bytes to read.
    ///   - callback: Closure invoked when data becomes available (async case).
    /// - Returns: Number of bytes read, `readEOF` on EOF, or `readDelayed`
    ///   if the read will complete asynchronously.
    public func readAsync(file: HTTPFile, into buffer: inout [UInt8], count: Int,
                          callback: @escaping () -> Void) -> Int {
        guard !file.isEOF else { return HTTPFileSystemConfig.readEOF }

        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            if let customFS = customFileSystem {
                return customFS.readAsync(file, into: &buffer, count: count,
                                          callback: callback)
            }
            return HTTPFileSystemConfig.readEOF
        }

        // ROM file: synchronous read, never delayed.
        return read(file: file, into: &buffer, count: count)
    }

    /// Check if a file has data ready to read.
    ///
    /// For ROM files, always returns true. For custom files, delegates
    /// to the custom file system handler.
    ///
    /// - Parameter file: The open file handle.
    /// - Returns: True if data is available to read.
    public func isFileReady(_ file: HTTPFile) -> Bool {
        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            return customFileSystem?.canRead(file) ?? true
        }
        return true
    }

    /// Check if a file is ready for reading, with async callback registration.
    ///
    /// When async reads are enabled and the file is not ready, the callback
    /// is registered so the server can resume sending when data becomes
    /// available.
    ///
    /// - Parameters:
    ///   - file: The open file handle.
    ///   - callback: Closure invoked when the file becomes ready.
    /// - Returns: `true` if data is available immediately, `false` if the
    ///   callback was registered for later notification.
    public func isFileReadyAsync(_ file: HTTPFile, callback: @escaping () -> Void) -> Bool {
        if HTTPFileSystemConfig.supportCustomFiles && file.flags.contains(.custom) {
            if let customFS = customFileSystem {
                return customFS.isFileReadyAsync(file, callback: callback)
            }
        }
        return true
    }

    /// Get the number of bytes remaining in a file.
    ///
    /// - Parameter file: The open file handle.
    /// - Returns: Number of bytes left to read.
    public func bytesLeft(file: HTTPFile) -> Int {
        return file.bytesLeft
    }

    /// Get the content type for a file path.
    ///
    /// - Parameter path: The file path.
    /// - Returns: The MIME content type.
    public func contentType(forPath path: String) -> String {
        return HTTPFileSystem.contentType(forPath: path)
    }
}

// MARK: - FSData Builder

/// Build-time utility for generating ROM filesystem data from a directory.
///
/// Scans a directory and creates
/// `FSDataFile` entries suitable for embedding in the HTTP server.
///
/// Usage:
/// ```swift
/// let files = FSDataBuilder.buildFromDirectory(at: "/path/to/www")
/// let fs = HTTPFileSystem()
/// for file in files {
///     fs.addFile(file)
/// }
/// ```
public enum FSDataBuilder {

    /// Scan a directory recursively and create `FSDataFile` entries.
    ///
    /// File paths are relativised to `directoryPath` and prefixed with `/`.
    /// The content of each file is read into memory.
    ///
    /// - Parameters:
    ///   - directoryPath: Absolute path to the root directory to scan.
    ///   - includeHidden: Whether to include hidden files (default: `false`).
    /// - Returns: An array of `FSDataFile` entries, or an empty array on error.
    public static func buildFromDirectory(at directoryPath: String,
                                           includeHidden: Bool = false) -> [FSDataFile] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: directoryPath) else { return [] }

        var files: [FSDataFile] = []

        while let relativePath = enumerator.nextObject() as? String {
            // Skip hidden files unless requested.
            if !includeHidden {
                let components = relativePath.split(separator: "/")
                if components.contains(where: { $0.hasPrefix(".") }) {
                    continue
                }
            }

            let fullPath = (directoryPath as NSString).appendingPathComponent(relativePath)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: fullPath, isDirectory: &isDir), !isDir.boolValue else {
                continue
            }

            guard let data = fm.contents(atPath: fullPath) else { continue }

            let webPath = "/" + relativePath
            let flags = inferFlags(for: relativePath)
            let entry = FSDataFile(name: webPath, data: Array(data), flags: flags)
            files.append(entry)
        }

        return files
    }

    /// Infer HTTP file flags from a file extension.
    private static func inferFlags(for path: String) -> HTTPFileFlags {
        let ext = (path as NSString).pathExtension.lowercased()
        var flags: HTTPFileFlags = []

        // Mark SSI-capable files.
        switch ext {
        case "shtml", "shtm", "ssi", "xml", "json":
            flags.insert(.ssi)
        default:
            break
        }

        // Mark compressible text formats as candidates for pre-compression.
        switch ext {
        case "html", "htm", "shtml", "shtm", "ssi", "css", "js", "json", "xml", "svg", "txt":
            break // text types, potentially compressible
        default:
            break
        }

        return flags
    }
}
