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
import HomomorphicEncryptionProtobuf
import Hummingbird
import Logging
import NIO
import PrivateInformationRetrieval
import Util

/// `PirUsecase` 로드 시 베이스 params 파일이 없고, DB 생성용 JSON 경로도 없을 때 발생합니다.
enum PirUsecaseLoadError: Error, LocalizedError {
    case missingParametersFile(String)

    var errorDescription: String? {
        switch self {
        case .missingParametersFile(let path):
            "PIR parameters file not found at \(path). If needed, generate PIR inputs by running InternalPIRProcessDatabase with `<usecase.fileStem>-config.json` next to service-config-file."
        }
    }
}

struct AppContext: IdentifiedRequestContext, AuthenticatedRequestContext, PlatformRequestContext, RequestContext {
    var coreContext: CoreRequestContextStorage
    var userIdentifier: UserIdentifier
    var userTier: UserTier
    var platform: Platform?

    // override upload size to 10MiB, the default 2MiB limit is too small for some evaluation keys.
    var maxUploadSize: Int {
        10 * 1024 * 1024
    }

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
        self.platform = nil
        self.userIdentifier = UserIdentifier(identifier: "")
        self.userTier = .tier1
    }
}

/// - Parameters:
///   - processDatabaseConfigPath: `InternalPIRProcessDatabase`용 JSON 경로. 베이스
///     `\(fileStem)-0.params.txtpb`가 없을 때 한 번 `InternalPIRProcessDatabase.run`을 호출합니다.
func loadUsecase(
    usecase: ServerConfiguration.Usecase,
    processDatabaseConfigPath: String?,
    dataDirectory: String? = nil,
    logger: Logger? = nil
) async throws -> Usecase {
    let baseParamsPath: String
    if let dir = dataDirectory {
        baseParamsPath = URL(fileURLWithPath: dir, isDirectory: true)
            .appendingPathComponent("\(usecase.fileStem)-0.params.txtpb").path
    } else {
        baseParamsPath = "\(usecase.fileStem)-0.params.txtpb"
    }
    if !FileManager.default.fileExists(atPath: baseParamsPath) {
        guard let processDatabaseConfigPath else {
            throw PirUsecaseLoadError.missingParametersFile(baseParamsPath)
        }
        let log = logger ?? Logger(label: "PIRService.loadUsecase")
        log.info(
            "Missing PIR parameters at \(baseParamsPath); running InternalPIRProcessDatabase with \(processDatabaseConfigPath)")
        let pathResolutionBase: String
        if let dir = dataDirectory {
            pathResolutionBase = URL(fileURLWithPath: dir, isDirectory: true).standardizedFileURL.path
        } else {
            pathResolutionBase = URL(fileURLWithPath: processDatabaseConfigPath).deletingLastPathComponent()
                .standardizedFileURL.path
        }
        try await InternalPIRProcessDatabase.run(
            configFilePath: processDatabaseConfigPath,
            outputFileStem: usecase.fileStem,
            parallel: true,
            relativePathBaseDirectory: pathResolutionBase)
    }
    do {
        return try PirUsecase<MulPirServer<Bfv<UInt32>>>(usecase: usecase, dataDirectory: dataDirectory)
    } catch {
        return try PirUsecase<MulPirServer<Bfv<UInt64>>>(usecase: usecase, dataDirectory: dataDirectory)
    }
}

func buildApplication(
    configuration: ApplicationConfiguration = .init(),
    usecaseStore: UsecaseStore = UsecaseStore(),
    prefilterStore: PrefilterStore = PrefilterStore(),
    privacyPassState: PrivacyPassState<UserAuthenticator>? = nil,
    evaluationKeyStore: some PersistDriver = MemoryPersistDriver()) async throws -> some ApplicationProtocol
{
    let router = Router(context: AppContext.self)
    router.middlewares.add(LogRequestsMiddleware(.info, includeHeaders: .none))
    router.middlewares.add(LogErrorsMiddleware())

    let pirServiceController = PIRServiceController(usecases: usecaseStore, evaluationKeyStore: evaluationKeyStore)
    let pirGroup = router.group()

    if let privacyPassState {
        let controller = PrivacyPassController(state: privacyPassState)
        controller.addRoutes(to: router.group())
        let userTierAuthenticator = AuthenticateUserTierMiddleware(AppContext.self, state: privacyPassState)
        pirGroup.add(middleware: userTierAuthenticator)
    }

    pirServiceController.addRoutes(to: pirGroup)

    let processDatabaseController = PIRProcessDatabaseController()
    processDatabaseController.addRoutes(to: router.group())
    let prefilterController = PrefilterController(store: prefilterStore)
    prefilterController.addRoutes(to: router.group())

    var application = Application(router: router, configuration: configuration)
    application.addServices(evaluationKeyStore)

    return application
}
