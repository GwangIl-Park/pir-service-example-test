import Foundation
import Crypto
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import Logging
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

// NOTE: 이 파일의 코드는 swift-homomorphic-encryption 패키지의
// Sources/PIRProcessDatabase/main.swift 에 있는 로직을 이 서비스 안에서
// 직접 호출할 수 있도록 최소한으로 옮겨온 것입니다.

enum InternalPIRProcessDatabase {
    enum TableSizeOption: Codable, Equatable, Hashable {
        case allowExpansion(targetLoadFactor: Double?, expansionFactor: Double?)
        case fixedSize(bucketCount: Int)

        static let defaultTargetLoadFactor = 0.9
        static let defaultExpansionFactor = 1.1
    }

    struct SymmetricPirArguments: Codable, Hashable {
        let databaseEncryptionKeyFilePath: String?
        let configType: SymmetricPirConfigType?
        let outputDatabaseEncryptionKeyFilePath: String?

        func resolve() throws -> SymmetricPirConfig {
            if outputDatabaseEncryptionKeyFilePath != nil, databaseEncryptionKeyFilePath != nil {
                throw ValidationError(message:
                    """
                    Both `databaseEncryptionKeyFilePath` and `outputDatabaseEncryptionKeyFilePath` \
                    can not be present in `symmetricPirArguments`.
                    """)
            }
            let configType = configType ?? .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128
            if let databaseEncryptionKeyFilePath {
                do {
                    let secretKeyString = try String(contentsOfFile: databaseEncryptionKeyFilePath, encoding: .utf8)
                    guard let secretKey = Array(hexEncoded: secretKeyString) else {
                        throw PirError.invalidOPRFHexSecretKey
                    }
                    try configType.validateEncryptionKey(secretKey)
                    return try SymmetricPirConfig(oprfSecretKey: Secret(value: secretKey), configType: configType)
                } catch {
                    throw PirError.failedToLoadOPRFKey(underlyingError: "\(error)", filePath: databaseEncryptionKeyFilePath)
                }
            }
            if let outputDatabaseEncryptionKeyFilePath {
                switch configType {
                case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128:
                    let secretKey = [UInt8](P384._VOPRF.PrivateKey().rawRepresentation)
                    try secretKey.hexString.write(
                        toFile: outputDatabaseEncryptionKeyFilePath,
                        atomically: true,
                        encoding: String.Encoding.utf8)
                    return try SymmetricPirConfig(
                        oprfSecretKey: Secret(value: secretKey),
                        configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
                }
            }
            throw ValidationError(message:
                """
                One of `databaseEncryptionKeyFilePath` or `outputDatabaseEncryptionKeyFilePath`\
                should be present in `symmetricPirArguments`.
                """)
        }

        struct ValidationError: Error {
            let message: String
        }
    }

    struct CuckooTableArguments: Codable, Equatable, Hashable {
        let hashFunctionCount: Int?
        let maxEvictionCount: Int?
        let maxSerializedBucketSize: Int?
        let bucketCount: TableSizeOption?
        let slotCount: Int?

        func resolve(maxSerializedBucketSize: Int) throws -> CuckooTableConfig {
            let bucketCountConfig: CuckooTableConfig.BucketCountConfig = {
                switch bucketCount {
                case let .allowExpansion(targetLoadFactor, expansionFactor):
                    return .allowExpansion(
                        expansionFactor: expansionFactor ?? TableSizeOption.defaultExpansionFactor,
                        targetLoadFactor: targetLoadFactor ?? TableSizeOption.defaultTargetLoadFactor)
                case let .fixedSize(bucketCount):
                    return .fixedSize(bucketCount: bucketCount)
                case nil:
                    return .allowExpansion(
                        expansionFactor: TableSizeOption.defaultExpansionFactor,
                        targetLoadFactor: TableSizeOption.defaultTargetLoadFactor)
                }
            }()

            let hashFunctionCount = hashFunctionCount ?? 2
            let maxEvictionCount = maxEvictionCount ?? 100
            if let slotCount {
                return try CuckooTableConfig(
                    hashFunctionCount: hashFunctionCount,
                    maxEvictionCount: maxEvictionCount,
                    maxSerializedBucketSize: maxSerializedBucketSize,
                    bucketCount: bucketCountConfig,
                    slotCount: slotCount)
            }
            return try CuckooTableConfig(
                hashFunctionCount: hashFunctionCount,
                maxEvictionCount: maxEvictionCount,
                maxSerializedBucketSize: maxSerializedBucketSize,
                bucketCount: bucketCountConfig)
        }
    }

    struct Arguments: Codable, Equatable, Hashable, Sendable {
        let inputDatabase: String
        let outputDatabase: String
        let outputPirParameters: String
        let rlweParameters: PredefinedRlweParameters
        let outputEvaluationKeyConfig: String?
        var sharding: Sharding?
        var shardingFunction: ShardingFunction?
        var cuckooTableArguments: CuckooTableArguments?
        var algorithm: PirAlgorithm?
        var keyCompression: PirKeyCompressionStrategy?
        var useMaxSerializedBucketSize: Bool?
        var symmetricPirArguments: SymmetricPirArguments?
        var trialsPerShard: Int?

        func resolve<Scheme: HeScheme>(for database: [KeywordValuePair],
                                       scheme _: Scheme.Type) throws -> ResolvedArguments
        {
            let cuckooTableArguments = cuckooTableArguments ?? CuckooTableArguments(
                hashFunctionCount: nil,
                maxEvictionCount: nil,
                maxSerializedBucketSize: nil,
                bucketCount: nil,
                slotCount: nil)

            // HashBucket.serializedSize 는 패키지 내부 접근자라 여기서 쓸 수 없으므로,
            // 원본 구현과 비슷한 크기 수준으로만 근사합니다.
            let bytesPerPlaintext = try EncryptionParameters<Scheme>(from: rlweParameters).bytesPerPlaintext
            let defaultMaxSize = bytesPerPlaintext / 2
            let maxSerializedBucketSize = try cuckooTableArguments.maxSerializedBucketSize ?? defaultMaxSize

            let cuckooTableConfig = try cuckooTableArguments.resolve(maxSerializedBucketSize: maxSerializedBucketSize)

            return try ResolvedArguments(
                inputDatabase: inputDatabase,
                outputDatabase: outputDatabase,
                outputPirParameters: outputPirParameters,
                outputEvaluationKeyConfig: outputEvaluationKeyConfig,
                sharding: sharding ?? Sharding.shardCount(1),
                shardingFunction: shardingFunction ?? .sha256,
                cuckooTableConfig: cuckooTableConfig,
                rlweParameters: rlweParameters,
                algorithm: algorithm ?? .mulPir,
                keyCompression: keyCompression ?? .noCompression,
                useMaxSerializedBucketSize: useMaxSerializedBucketSize ?? false,
                symmetricPirConfig: symmetricPirArguments?.resolve(),
                trialsPerShard: trialsPerShard ?? 1)
        }

        struct ValidationError: Error {
            let message: String
        }
    }

    struct ResolvedArguments {
        let inputDatabase: String
        let outputDatabase: String
        let outputPirParameters: String
        let outputEvaluationKeyConfig: String?
        let sharding: Sharding
        let shardingFunction: ShardingFunction
        let cuckooTableConfig: CuckooTableConfig
        let rlweParameters: PredefinedRlweParameters
        let algorithm: PirAlgorithm
        let keyCompression: PirKeyCompressionStrategy
        let useMaxSerializedBucketSize: Bool
        let symmetricPirConfig: SymmetricPirConfig?
        let trialsPerShard: Int

        init(
            inputDatabase: String,
            outputDatabase: String,
            outputPirParameters: String,
            outputEvaluationKeyConfig: String?,
            sharding: Sharding,
            shardingFunction: ShardingFunction,
            cuckooTableConfig: CuckooTableConfig,
            rlweParameters: PredefinedRlweParameters,
            algorithm: PirAlgorithm,
            keyCompression: PirKeyCompressionStrategy,
            useMaxSerializedBucketSize: Bool,
            symmetricPirConfig: SymmetricPirConfig?,
            trialsPerShard: Int) throws
        {
            self.inputDatabase = inputDatabase
            self.outputDatabase = outputDatabase
            self.outputPirParameters = outputPirParameters
            self.outputEvaluationKeyConfig = outputEvaluationKeyConfig
            self.sharding = sharding
            self.shardingFunction = shardingFunction
            self.cuckooTableConfig = cuckooTableConfig
            self.rlweParameters = rlweParameters
            self.algorithm = algorithm
            self.keyCompression = keyCompression
            self.useMaxSerializedBucketSize = useMaxSerializedBucketSize
            self.symmetricPirConfig = symmetricPirConfig
            self.trialsPerShard = trialsPerShard

            try validate()
        }

        func validate() throws {
            guard sharding == Sharding.shardCount(1) || outputPirParameters.contains("SHARD_ID") else {
                throw ValidationError(message: "'outputPirParameters' must contain 'SHARD_ID', found \(outputPirParameters)")
            }
            guard sharding == Sharding.shardCount(1) || outputDatabase.contains("SHARD_ID") else {
                throw ValidationError(message: "'outputPirDatabase' must contain 'SHARD_ID', found \(outputDatabase)")
            }
            guard algorithm == .mulPir else {
                throw ValidationError(message: "'algorithm' must be 'mulPir', found \(algorithm)")
            }
        }

        struct ValidationError: Error {
            let message: String
        }
    }

    private static let logger = Logger(label: "PIRProcessDatabase")

    /// JSON에 적힌 상대 경로를 **설정 파일이 있는 디렉터리** 기준 절대 경로로 바꾼다 (`dataPath` 사용 시 그 트리와 일치).
    private static func resolveRelativePath(_ path: String, relativeTo baseDirectory: URL) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return path }
        if (trimmed as NSString).isAbsolutePath {
            return trimmed
        }
        return baseDirectory.standardizedFileURL
            .appendingPathComponent(trimmed)
            .standardizedFileURL
            .path
    }

    private static func argumentsWithPathsResolved(
        _ arguments: Arguments,
        relativeTo baseDirectory: URL
    ) -> Arguments {
        let base = baseDirectory.standardizedFileURL
        let r = { resolveRelativePath($0, relativeTo: base) }
        let symResolved: SymmetricPirArguments?
        if let sym = arguments.symmetricPirArguments {
            symResolved = SymmetricPirArguments(
                databaseEncryptionKeyFilePath: sym.databaseEncryptionKeyFilePath.map { r($0) },
                configType: sym.configType,
                outputDatabaseEncryptionKeyFilePath: sym.outputDatabaseEncryptionKeyFilePath.map { r($0) })
        } else {
            symResolved = nil
        }
        return Arguments(
            inputDatabase: r(arguments.inputDatabase),
            outputDatabase: r(arguments.outputDatabase),
            outputPirParameters: r(arguments.outputPirParameters),
            rlweParameters: arguments.rlweParameters,
            outputEvaluationKeyConfig: arguments.outputEvaluationKeyConfig.map { r($0) },
            sharding: arguments.sharding,
            shardingFunction: arguments.shardingFunction,
            cuckooTableArguments: arguments.cuckooTableArguments,
            algorithm: arguments.algorithm,
            keyCompression: arguments.keyCompression,
            useMaxSerializedBucketSize: arguments.useMaxSerializedBucketSize,
            symmetricPirArguments: symResolved,
            trialsPerShard: arguments.trialsPerShard)
    }

    /// `outputDatabase` / `outputPirParameters`에서 마지막 경로 조각의 `...-SHARD_ID...` 접두를 `fileStem`에 맞춥니다.
    /// 예: `url-SHARD_ID.bin` + fileStem `fixed` → `fixed-SHARD_ID.bin`
    ///
    /// `URL(fileURLWithPath:)`는 상대 경로를 **현재 작업 디렉터리 기준 절대 경로**로 만들어,
    /// 이후 `relativePathBaseDirectory` / `dataPath` 해석이 깨지므로 `NSString`만 사용한다.
    private static func rewriteShardPathForFileStem(_ path: String, fileStem: String) -> String {
        guard path.contains("SHARD_ID") else { return path }
        let nsPath = path as NSString
        let last = nsPath.lastPathComponent
        guard let shardRange = last.range(of: "SHARD_ID") else { return path }
        let suffix = String(last[shardRange.lowerBound...])
        let newLast = "\(fileStem)-\(suffix)"
        let dir = nsPath.deletingLastPathComponent
        if dir.isEmpty || dir == "." {
            return newLast
        }
        return (dir as NSString).appendingPathComponent(newLast)
    }

    /// - Parameter outputFileStem: 지정 시 JSON의 출력 파일명 stem을 이 값으로 맞춥니다(예: `url-` → `{fileStem}-`).
    /// - Parameter relativePathBaseDirectory: JSON 안의 상대 경로를 이 디렉터리 기준으로 절대 경로로 만든다.
    ///   `nil`이면 설정 JSON 파일이 있는 디렉터리(`…/stem-config.json`의 부모)를 쓴다.
    static func run(
        configFilePath: String,
        outputFileStem: String? = nil,
        parallel: Bool = true,
        relativePathBaseDirectory: String? = nil
    ) async throws {
        do {
            let configURL = URL(fileURLWithPath: configFilePath)
            let configData = try Data(contentsOf: configURL)
            var config = try JSONDecoder().decode(Arguments.self, from: configData)
            if let stem = outputFileStem {
                config = Arguments(
                    inputDatabase: config.inputDatabase,
                    outputDatabase: rewriteShardPathForFileStem(config.outputDatabase, fileStem: stem),
                    outputPirParameters: rewriteShardPathForFileStem(config.outputPirParameters, fileStem: stem),
                    rlweParameters: config.rlweParameters,
                    outputEvaluationKeyConfig: config.outputEvaluationKeyConfig,
                    sharding: config.sharding,
                    shardingFunction: config.shardingFunction,
                    cuckooTableArguments: config.cuckooTableArguments,
                    algorithm: config.algorithm,
                    keyCompression: config.keyCompression,
                    useMaxSerializedBucketSize: config.useMaxSerializedBucketSize,
                    symmetricPirArguments: config.symmetricPirArguments,
                    trialsPerShard: config.trialsPerShard)
            }
            let pathBase: URL
            if let override = relativePathBaseDirectory?.trimmingCharacters(in: .whitespacesAndNewlines),
               !override.isEmpty
            {
                pathBase = URL(fileURLWithPath: override, isDirectory: true).standardizedFileURL
            } else {
                pathBase = configURL.deletingLastPathComponent()
            }
            config = argumentsWithPathsResolved(config, relativeTo: pathBase)
            if config.rlweParameters.supportsScalar(UInt32.self) {
                try await process(config: config, scheme: Bfv<UInt32>.self, parallel: parallel)
            } else {
                try await process(config: config, scheme: Bfv<UInt64>.self, parallel: parallel)
            }
        } catch {
            logger.error("Failed in InternalPIRProcessDatabase.run", metadata: [
            "path": "\(configFilePath)",
            "error": "\(error)"
        ])
        throw error
        }
    }

    /// `process`가 출력을 쓰기 전에 기존 산출물을 지운다. 샤드 수가 줄었을 때 남는 오래된 샤드 파일도 제거한다.
    private static func removeStaleOutputsBeforeProcessing(config: Arguments) throws {
        let fm = FileManager.default

        func removeIfExists(_ path: String) throws {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else { return }
            guard !isDir.boolValue else {
                logger.warning("Skipped removing output path because it is a directory: \(path)")
                return
            }
            try fm.removeItem(atPath: path)
            logger.info("Removed stale output: \(path)")
        }

        if !config.outputDatabase.contains("SHARD_ID") {
            try removeIfExists(config.outputDatabase)
            try removeIfExists(config.outputPirParameters)
            if let path = config.outputEvaluationKeyConfig {
                try removeIfExists(path)
            }
            return
        }

        try removeShardPatternFiles(templatePath: config.outputDatabase, fileManager: fm)
        try removeShardPatternFiles(templatePath: config.outputPirParameters, fileManager: fm)
        if let path = config.outputEvaluationKeyConfig {
            try removeIfExists(path)
        }
    }

    /// `…/stem-SHARD_ID.suffix` 형태일 때 같은 디렉터리의 `stem-*` + 동일 접미 파일을 모두 삭제한다.
    private static func removeShardPatternFiles(templatePath: String, fileManager: FileManager) throws {
        let ns = templatePath as NSString
        let last = ns.lastPathComponent
        guard let range = last.range(of: "SHARD_ID") else { return }
        let prefix = String(last[..<range.lowerBound])
        let suffix = String(last[range.upperBound...])
        guard !prefix.isEmpty else {
            logger.warning("Skipping shard output cleanup: empty prefix before SHARD_ID in \(templatePath)")
            return
        }
        let parent = ns.deletingLastPathComponent
        guard fileManager.fileExists(atPath: parent) else { return }
        let names = try fileManager.contentsOfDirectory(atPath: parent)
        for name in names where name.hasPrefix(prefix) && name.hasSuffix(suffix)
            && name.count > prefix.count + suffix.count
        {
            let full = (parent as NSString).appendingPathComponent(name)
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
            try fileManager.removeItem(atPath: full)
            logger.info("Removed stale shard output: \(full)")
        }
    }

    private static func process<Scheme: HeScheme>(
        config: Arguments,
        scheme: Scheme.Type,
        parallel: Bool) async throws
    {
        try removeStaleOutputsBeforeProcessing(config: config)
        let database: [KeywordValuePair] =
            try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: config.inputDatabase).native()

        let resolved = try config.resolve(for: database, scheme: scheme)
        logger.info("Processing database")
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: resolved.cuckooTableConfig,
            unevenDimensions: true,
            keyCompression: resolved.keyCompression,
            useMaxSerializedBucketSize: resolved.useMaxSerializedBucketSize,
            shardingFunction: resolved.shardingFunction,
            symmetricPirClientConfig: resolved.symmetricPirConfig?.clientConfig())

        let databaseConfig = KeywordDatabaseConfig(
            sharding: resolved.sharding,
            keywordPirConfig: keywordConfig)

        let encryptionParameters = try EncryptionParameters<Scheme>(from: resolved.rlweParameters)
        let processArgs = try ProcessKeywordDatabase.Arguments<Scheme>(
            databaseConfig: databaseConfig,
            encryptionParameters: encryptionParameters,
            algorithm: resolved.algorithm,
            keyCompression: resolved.keyCompression,
            trialsPerShard: resolved.trialsPerShard,
            symmetricPirConfig: resolved.symmetricPirConfig)
        let context = try Context(encryptionParameters: processArgs.encryptionParameters)
        let keywordDatabase = try KeywordDatabase(
            rows: database,
            sharding: processArgs.databaseConfig.sharding,
            shardingFunction: resolved.shardingFunction,
            symmetricPirConfig: processArgs.symmetricPirConfig)
        logger.info("Sharded database into \(keywordDatabase.shards.count) shards")
        let shards = keywordDatabase.shards.sorted { $0.0.localizedStandardCompare($1.0) == .orderedAscending }
        var evaluationKeyConfig = EvaluationKeyConfig()

        if parallel {
            try await withThrowingTaskGroup(of: EvaluationKeyConfig.self) { group in
                for (shardID, shard) in shards {
                    group.addTask {
                        try await processShard(
                            shardID: shardID,
                            shard: shard,
                            config: resolved,
                            context: context,
                            processArgs: processArgs)
                    }
                }

                for try await processedEvaluationKeyConfig in group {
                    evaluationKeyConfig = [evaluationKeyConfig, processedEvaluationKeyConfig].union()
                }
            }
        } else {
            for (shardID, shard) in shards {
                let processedEvaluationKeyConfig = try await processShard(
                    shardID: shardID,
                    shard: shard,
                    config: resolved,
                    context: context,
                    processArgs: processArgs)
                evaluationKeyConfig = [evaluationKeyConfig, processedEvaluationKeyConfig].union()
            }
        }

        if let evaluationKeyConfigFile = resolved.outputEvaluationKeyConfig {
            let protoEvaluationKeyConfig = try evaluationKeyConfig.proto(encryptionParameters: encryptionParameters)
            try protoEvaluationKeyConfig.save(to: evaluationKeyConfigFile)
            logger.info("Saved evaluation key configuration to \(evaluationKeyConfigFile)")
        }
    }

    private static func processShard<Scheme: HeScheme>(
        shardID: String,
        shard: KeywordDatabaseShard,
        config: ResolvedArguments,
        context: Context<Scheme>,
        processArgs: ProcessKeywordDatabase.Arguments<Scheme>) async throws -> EvaluationKeyConfig
    {
        var logger = self.logger
        logger[metadataKey: "shardID"] = .string(shardID)

        func logEvent(event: ProcessKeywordDatabase.ProcessShardEvent) throws {
            switch event {
            case let .cuckooTableEvent(.createdTable(table)):
                let summary = try table.summarize()
                logger.info("Created cuckoo table \(summary)")
            case let .cuckooTableEvent(.expandingTable(table)):
                let summary = try table.summarize()
                logger.info("Expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.finishedExpandingTable(table)):
                let summary = try table.summarize()
                logger.info("Finished expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.insertedKeywordValuePair(index, _)):
                let reportingPercentage = 10
                let shardFraction = shard.rows.count / reportingPercentage
                if shardFraction > 0, (index + 1).isMultiple(of: shardFraction) {
                    let percentage = Float(reportingPercentage * (index + 1)) / Float(shardFraction)
                    logger.info("Inserted \(index + 1) / \(shard.rows.count) keywords \(percentage)%")
                }
            }
        }

        logger.info("Processing shard with \(shard.rows.count) rows")
        let processed = try ProcessKeywordDatabase.processShard(
            shard: shard,
            with: processArgs,
            onEvent: logEvent)

        let outputDatabaseFilename = config.outputDatabase.replacingOccurrences(
            of: "SHARD_ID",
            with: String(shardID))
        try processed.database.save(to: outputDatabaseFilename)
        logger.info("Saved shard to \(outputDatabaseFilename)")

        let shardPirParameters = try processed.proto(context: context)
        let outputParametersFilename = config.outputPirParameters.replacingOccurrences(
            of: "SHARD_ID",
            with: String(shardID))
        try shardPirParameters.save(to: outputParametersFilename)
        logger.info("Saved shard PIR parameters to \(outputParametersFilename)")

        return processed.evaluationKeyConfig
    }
}

