// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Logging

/// Thread-safe append-only sink for a single log file shared by all ``FileLogHandler`` instances.
final class FileLogSink: @unchecked Sendable {
    private let lock = NSLock()
    private let handle: FileHandle

    init(url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        self.handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
    }

    func writeLine(_ line: String) {
        let data = Data(line.utf8)
        lock.lock()
        defer { lock.unlock() }
        try? handle.write(contentsOf: data)
    }
}

/// Writes swift-log output to a file (same format family as ``StreamLogHandler``).
struct FileLogHandler: LogHandler {
    var logLevel: Logger.Level = .info
    var metadata = Logger.Metadata()

    private let label: String
    private let sink: FileLogSink

    init(label: String, sink: FileLogSink) {
        self.label = label
        self.sink = sink
    }

    subscript(metadataKey metadataKey: Logger.Metadata.Key) -> Logger.Metadata.Value? {
        get { metadata[metadataKey] }
        set { metadata[metadataKey] = newValue }
    }

    func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata explicitMetadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        let line = "\(Self.timestamp()) \(level) \(label): [\(source)] \(message)\n"
        sink.writeLine(line)
    }

    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }
}

enum LoggingBootstrap {
    /// Installs a logging backend that mirrors stderr **and** appends to `logFileURL`.
    /// Must run before any ``Logger`` is created (once per process).
    static func bootstrapStderrAndFile(logFileURL: URL) throws {
        let sink = try FileLogSink(url: logFileURL)
        LoggingSystem.bootstrap { label in
            MultiplexLogHandler([
                StreamLogHandler.standardError(label: label),
                FileLogHandler(label: label, sink: sink),
            ])
        }
    }
}
