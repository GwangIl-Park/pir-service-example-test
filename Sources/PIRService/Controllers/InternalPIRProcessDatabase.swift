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

    static func run(configFilePath: String, parallel: Bool = true) async throws {
        do {
            let configURL = URL(fileURLWithPath: configFilePath)
            let configData = try Data(contentsOf: configURL)
            let config = try JSONDecoder().decode(Arguments.self, from: configData)
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

    private static func process<Scheme: HeScheme>(
        config: Arguments,
        scheme: Scheme.Type,
        parallel: Bool) async throws
    {
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

