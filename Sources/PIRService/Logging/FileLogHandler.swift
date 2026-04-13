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

#if os(Windows)
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Thread-safe append-only sink. 선택 시 **크기 기준**으로 `path`, `path.1` … `path.N` 형태로 자체 회전한다.
final class FileLogSink: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: FileHandle
    private let url: URL
    private let maxBytesPerFile: Int?
    private let maxRotatedFiles: Int
    private var bytesInCurrentFile: Int

    /// - Parameters:
    ///   - maxBytesPerFile: 이 크기(바이트)를 넘기면 회전. `nil`이면 무한 append.
    ///   - maxRotatedFiles: `path.1` … `path.{maxRotatedFiles}` 까지 보관(현재 `path` 제외).
    init(url: URL, maxBytesPerFile: Int? = nil, maxRotatedFiles: Int = 5) throws {
        self.url = url
        self.maxBytesPerFile = maxBytesPerFile
        self.maxRotatedFiles = max(1, maxRotatedFiles)

        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: url.path) {
            guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
                throw FileLogSinkError.couldNotCreateFile(url)
            }
        }
        self.handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        let size =
            (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
        self.bytesInCurrentFile = max(0, size)

        if let max = maxBytesPerFile, max > 0, size > max {
            try rotateUnlocked()
        }
    }

    func writeLine(_ line: String) {
        let data = Data(line.utf8)
        lock.lock()
        defer { lock.unlock() }
        if let max = maxBytesPerFile, max > 0, bytesInCurrentFile + data.count > max, bytesInCurrentFile > 0 {
            try? rotateUnlocked()
        }
        try? handle.write(contentsOf: data)
        bytesInCurrentFile += data.count
    }

    /// `lock` 잡힌 상태에서만 호출.
    private func rotateUnlocked() throws {
        try handle.close()

        let path = url.path
        let fm = FileManager.default
        let n = maxRotatedFiles

        let oldest = URL(fileURLWithPath: "\(path).\(n)")
        if fm.fileExists(atPath: oldest.path) {
            try fm.removeItem(at: oldest)
        }

        for i in stride(from: n, through: 2, by: -1) {
            let from = URL(fileURLWithPath: "\(path).\(i - 1)")
            let to = URL(fileURLWithPath: "\(path).\(i)")
            if fm.fileExists(atPath: from.path) {
                if fm.fileExists(atPath: to.path) {
                    try fm.removeItem(at: to)
                }
                try fm.moveItem(at: from, to: to)
            }
        }

        let firstRotated = URL(fileURLWithPath: "\(path).1")
        if fm.fileExists(atPath: url.path) {
            if fm.fileExists(atPath: firstRotated.path) {
                try fm.removeItem(at: firstRotated)
            }
            try fm.moveItem(at: url, to: firstRotated)
        }

        guard fm.createFile(atPath: url.path, contents: nil) else {
            throw FileLogSinkError.couldNotCreateFile(url)
        }
        handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        bytesInCurrentFile = 0
    }
}

enum FileLogSinkError: Error {
    case couldNotCreateFile(URL)
}

/// Writes swift-log output to a file (same format family as ``StreamLogHandler``).
struct FileLogHandler: LogHandler {
    var logLevel: Logger.Level = .info

    var metadataProvider: Logger.MetadataProvider?

    private var prettyMetadata: String?
    var metadata = Logger.Metadata() {
        didSet {
            self.prettyMetadata = Self.prettify(self.metadata)
        }
    }

    private let label: String
    private let sink: FileLogSink

    init(label: String, sink: FileLogSink, metadataProvider: Logger.MetadataProvider? = nil) {
        self.label = label
        self.sink = sink
        self.metadataProvider = metadataProvider ?? LoggingSystem.metadataProvider
        self.prettyMetadata = Self.prettify(self.metadata)
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
        let effectiveMetadata = Self.prepareMetadata(
            base: self.metadata,
            provider: self.metadataProvider,
            explicit: explicitMetadata
        )

        let prettyLine: String?
        if let effectiveMetadata {
            prettyLine = Self.prettify(effectiveMetadata)
        } else {
            prettyLine = self.prettyMetadata
        }

        let line =
            "\(Self.timestamp()) \(level)\(self.label.isEmpty ? "" : " ")\(self.label):\(prettyLine.map { " \($0)" } ?? "") [\(source)] \(message)\n"
        sink.writeLine(line)
    }

    /// ``StreamLogHandler`` 와 동일한 규칙 (swift-log `StreamLogHandler.prepareMetadata` 와 대응).
    private static func prepareMetadata(
        base: Logger.Metadata,
        provider: Logger.MetadataProvider?,
        explicit: Logger.Metadata?
    ) -> Logger.Metadata? {
        var metadata = base

        let provided = provider?.get() ?? [:]

        guard !provided.isEmpty || !((explicit ?? [:]).isEmpty) else {
            return nil
        }

        if !provided.isEmpty {
            metadata.merge(provided, uniquingKeysWith: { _, provided in provided })
        }

        if let explicit, !explicit.isEmpty {
            metadata.merge(explicit, uniquingKeysWith: { _, explicit in explicit })
        }

        return metadata
    }

    private static func prettify(_ metadata: Logger.Metadata) -> String? {
        if metadata.isEmpty {
            return nil
        }
        return metadata.lazy.sorted(by: { $0.key < $1.key }).map { "\($0)=\($1)" }.joined(separator: " ")
    }

    /// ``StreamLogHandler`` 의 타임스탬프와 동일 (`%Y-%m-%dT%H:%M:%S%z`, 로컬 타임존).
    private static func timestamp() -> String {
        var buffer = [Int8](repeating: 0, count: 255)
        #if os(Windows)
        var timestamp = __time64_t()
        _ = _time64(&timestamp)

        var localTime = tm()
        _ = _localtime64_s(&localTime, &timestamp)

        _ = strftime(&buffer, buffer.count, "%Y-%m-%dT%H:%M:%S%z", &localTime)
        #else
        var timestamp = time(nil)
        guard let localTime = localtime(&timestamp) else {
            return " "
        }
        strftime(&buffer, buffer.count, "%Y-%m-%dT%H:%M:%S%z", localTime)
        #endif
        return buffer.withUnsafeBufferPointer {
            $0.withMemoryRebound(to: CChar.self) {
                String(cString: $0.baseAddress!)
            }
        }
    }
}

enum LoggingBootstrap {
    /// stderr만 사용 (파일 없음). 프로세스당 한 번만 호출 가능.
    static func bootstrapStderrOnly() {
        LoggingSystem.bootstrap { label in
            StreamLogHandler.standardError(label: label)
        }
    }

    /// stderr와 동일한 내용을 파일에도 쓴다. `maxBytesPerFile`이 있으면 크기 초과 시 자체 회전.
    /// 프로세스당 한 번만 호출 가능.
    static func bootstrapStderrAndFile(
        logFileURL: URL,
        maxBytesPerFile: Int? = nil,
        maxRotatedFiles: Int = 5
    ) throws {
        let sink = try FileLogSink(
            url: logFileURL,
            maxBytesPerFile: maxBytesPerFile,
            maxRotatedFiles: maxRotatedFiles)
        LoggingSystem.bootstrap { label in
            MultiplexLogHandler([
                StreamLogHandler.standardError(label: label),
                FileLogHandler(label: label, sink: sink),
            ])
        }
    }
}
