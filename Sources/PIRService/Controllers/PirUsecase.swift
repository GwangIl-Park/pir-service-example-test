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
import HomomorphicEncryption
import Logging
import HomomorphicEncryptionProtobuf
import Hummingbird
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf
import Util

enum LoadingError: Error {
    case invalidParameters(shard: String, got: String, expected: String)
    /// `fileStem-<n>.params.txtpb`와 `fileStem-<n>.bin`이 0부터 연속으로 존재하지 않음.
    case shardFileLayout(fileStem: String, message: String)
}

extension LoadingError {
    static func invalidParameters<Scheme: HeScheme>(
        shard: String,
        got: EncryptionParameters<Scheme>,
        expected: EncryptionParameters<Scheme>) -> Self
    {
        .invalidParameters(shard: shard, got: got.description, expected: expected.description)
    }
}

extension LoadingError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .invalidParameters(shard, got, expected):
            "Invalid PIR parameters for shard \(shard): got \(got), expected \(expected)."
        case let .shardFileLayout(_, message):
            message
        }
    }
}

enum SymmetricPirError: Error, Codable, Hashable {
    case symmetricPirNotConfigured
}

extension SymmetricPirError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .symmetricPirNotConfigured:
            "SymmetricPIR not configured."
        }
    }
}

struct PirUsecase<PirScheme: IndexPirServer>: Usecase {
    typealias Scheme = PirScheme.Scheme
    let context: Context<Scheme>
    let keywordParams: KeywordPirParameter
    let shards: [KeywordPirServer<PirScheme>]
    let symmetricPirConfig: SymmetricPirConfig?

    init(
        context: Context<Scheme>,
        keywordParams: KeywordPirParameter,
        shards: [KeywordPirServer<PirScheme>],
        symmetricPirConfig: SymmetricPirConfig? = nil)
    {
        self.context = context
        self.keywordParams = keywordParams
        self.shards = shards
        self.symmetricPirConfig = symmetricPirConfig
    }

    /// - Parameter dataDirectory: `nil`이면 현재 작업 디렉터리 기준 파일명만 사용. 지정 시 그 디렉터리 아래의 params/bin을 읽는다.
    init(usecase: ServerConfiguration.Usecase, dataDirectory: String? = nil) throws {
        func pathJoin(_ fileName: String) -> String {
            guard let dir = dataDirectory, !dir.isEmpty else {
                return fileName
            }
            return URL(fileURLWithPath: dir, isDirectory: true).appendingPathComponent(fileName).path
        }

        let parameterPath = pathJoin("\(usecase.fileStem)-0.params.txtpb")
        let params = try Apple_SwiftHomomorphicEncryption_Pir_V1_PirParameters(from: parameterPath)
        let encryptionParams: EncryptionParameters<Scheme> = try params.encryptionParameters.native()
        let context: Context<Scheme> = try Context(encryptionParameters: encryptionParams)
        self.context = context
        self.keywordParams = try params.keywordPirParams.nativeWithSymmetricPirClientConfig()
        self.symmetricPirConfig = try usecase.symmetricPirArguments?.resolve()
        let fileManager = FileManager.default
        var diskShardCount = 0
        while fileManager.fileExists(atPath: pathJoin("\(usecase.fileStem)-\(diskShardCount).params.txtpb")),
              fileManager.fileExists(atPath: pathJoin("\(usecase.fileStem)-\(diskShardCount).bin"))
        {
            diskShardCount += 1
        }
        guard diskShardCount > 0 else {
            throw LoadingError.shardFileLayout(
                fileStem: usecase.fileStem,
                message:
                    """
                    No complete PIR shard file pairs found for stem \"\(usecase.fileStem)\". \
                    Expected consecutive \"\(usecase.fileStem)-<n>.params.txtpb\" and \"\(usecase.fileStem)-<n>.bin\" \
                    starting at n=0.
                    """)
        }

        Logger(label: "PIRService.PirUsecase").info(
            "PIR shard files on disk [usecase: \(usecase.name), fileStem: \(usecase.fileStem), ShardCount: \(diskShardCount)]")

        self.shards = try (0..<diskShardCount).map { shardIndex in
            let parameterPath = pathJoin("\(usecase.fileStem)-\(shardIndex).params.txtpb")
            let databasePath = pathJoin("\(usecase.fileStem)-\(shardIndex).bin")
            let pirParams = try Apple_SwiftHomomorphicEncryption_Pir_V1_PirParameters(from: parameterPath)
            let encryptionParams: EncryptionParameters<Scheme> = try pirParams.encryptionParameters.native()
            guard encryptionParams == context.encryptionParameters else {
                throw LoadingError.invalidParameters(
                    shard: parameterPath,
                    got: encryptionParams,
                    expected: context.encryptionParameters)
            }

            let database = try ProcessedDatabase(from: databasePath, context: context)
            let processed = try ProcessedDatabaseWithParameters(
                database: database,
                algorithm: pirParams.algorithm.native(),
                evaluationKeyConfig: pirParams.evaluationKeyConfig.native(),
                pirParameter: pirParams.native(),
                keywordPirParameter: pirParams.keywordPirParams.nativeWithSymmetricPirClientConfig())
            return try KeywordPirServer(context: context, processed: processed)
        }
    }

    @_specialize(where PirScheme == MulPirServer<Bfv<UInt32>>)
    @_specialize(where PirScheme == MulPirServer<Bfv<UInt64>>)
    func process(
        request: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request,
        evaluationKey: Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKey) async throws
        -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response
    {
        let pirRequest = request.pirRequest
        guard !pirRequest.hasShardID else {
            throw HTTPError(.notImplemented, message: "overloading shard index with ShardID is not supported")
        }
        let shard = shards[Int(pirRequest.shardIndex)]
        let query: KeywordPirServer<PirScheme>.Query = try pirRequest.query.native(context: context)
        let evaluationKey: EvaluationKey<Scheme> = try evaluationKey.evaluationKey.native(context: context)
        let response = try shard.computeResponse(to: query, using: evaluationKey)
        return try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response.with { apiResponse in
            apiResponse.pirResponse = try response.proto()
        }
    }

    func config() throws -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config {
        var pirConfig = Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRConfig()
        pirConfig.encryptionParameters = try context.encryptionParameters.proto()
        guard let firstShard = shards.first else {
            throw HTTPError(.internalServerError, message: "Empty shards")
        }

        pirConfig.keywordPirParams = keywordParams.proto()
        pirConfig.algorithm = .mulPir
        pirConfig.batchSize = UInt64(firstShard.indexPirParameter.batchSize)
        pirConfig.evaluationKeyConfigHash = try evaluationKeyConfig().sha256()
        pirConfig.shardConfigs = shards.map { shard in
            shard.indexPirParameter.proto()
        }
        let allShardsSame = shards.count > 1 && shards.dropFirst().allSatisfy { shard in
            shard.indexPirParameter == firstShard.indexPirParameter
        }
        if allShardsSame {
            pirConfig.pirShardConfigs = Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRShardConfigs
                .with { shardConfigs in
                    shardConfigs.repeatedShardConfig = Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRFixedShardConfig
                        .with { fixedShardConfig in
                            fixedShardConfig.shardCount = UInt32(shards.count)
                            fixedShardConfig.shardConfig = firstShard.indexPirParameter.proto()
                        }
                }
            pirConfig.shardConfigs = []
        }

        return try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config.with { config in
            config.pirConfig = pirConfig
            config.configID = try pirConfig.sha256()
        }
    }

    func evaluationKeyConfig() throws -> Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig {
        try shards.map(\.evaluationKeyConfig).union().proto(encryptionParameters: context.encryptionParameters)
    }

    @_specialize(where PirScheme == MulPirServer<Bfv<UInt32>>)
    @_specialize(where PirScheme == MulPirServer<Bfv<UInt64>>)
    func processOprf(request: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest) async throws ->
        Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response
    {
        guard let symmetricPirConfig else {
            throw SymmetricPirError.symmetricPirNotConfigured
        }
        let oprfResponse = try OprfServer(symmetricPirConfig: symmetricPirConfig).computeResponse(
            query: request.native())
        return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response.with { apiResponse in
            apiResponse.oprfResponse = oprfResponse.proto()
        }
    }
}
