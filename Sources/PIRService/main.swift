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

import ArgumentParser
import Foundation
import Hummingbird
import ServiceLifecycle

/// `buildApplication` 시점에는 `ReloadService`가 아직 없어서, 나중에 주입해 `performReload` 클로저가 호출되게 한다.
private final class ReloadServiceHolder: @unchecked Sendable {
    var reloadService: ReloadService!
}

// This executable is used in tests, which breaks `swift test -c release` when used with `@main`.
// So we avoid using `@main` here.
struct ServerCommand: AsyncParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRService")

    @Option var hostname: String = "0.0.0.0"
    @Option(name: .customLong("http-port")) var httpPort: Int = 8080
    @Option(name: .customLong("tcp-port")) var tcpPort: Int = 9000
    @Option(
        name: .customLong("log-file"),
        help: """
        로그를 append할 파일 경로 (부모 디렉터리·파일이 없으면 생성, stderr에도 동일 출력). \
        기본: logs/pir-service.log. '-' 를 주면 stderr만 씁니다.
        """)
    var logFile: String = "logs/pir-service.log"
    @Option(
        name: .customLong("log-max-bytes"))
    var logMaxBytes: Int = 1073741824
    @Option(
        name: .customLong("log-max-archives"),
        help: "회전 시 보관할 이전 파일 개수 (app.log.1 … app.log.N).")
    var logMaxArchives: Int = 99
    @Option(name: .customLong("service-config-file")) var serviceConfigFile: String

    func run() async throws {
        if logFile == "-" {
            LoggingBootstrap.bootstrapStderrOnly()
        } else {
            try LoggingBootstrap.bootstrapStderrAndFile(
                logFileURL: URL(fileURLWithPath: logFile),
                maxBytesPerFile: logMaxBytes > 0 ? logMaxBytes : nil,
                maxRotatedFiles: logMaxArchives)
        }

        let usecaseStore = UsecaseStore()
        let prefilterStore = PrefilterStore()
        let privacyPassState = try PrivacyPassState(userAuthenticator: UserAuthenticator())

        let reloadHolder = ReloadServiceHolder()
        let app = try await buildApplication(
            configuration: .init(address: .hostname(hostname, port: httpPort)),
            usecaseStore: usecaseStore,
            prefilterStore: prefilterStore,
            privacyPassState: privacyPassState,
            performReloadConfiguration: { try await reloadHolder.reloadService.reloadConfiguration() })

        let reloadService = ReloadService(
            configFile: URL(fileURLWithPath: serviceConfigFile),
            usecaseStore: usecaseStore,
            prefilterStore: prefilterStore,
            privacyPassState: privacyPassState,
            logger: app.logger)
        reloadHolder.reloadService = reloadService

        let tcpService = PIRProcessDatabaseTCPService(
            host: hostname,
            port: tcpPort,
            configFile: URL(fileURLWithPath: serviceConfigFile),
            logger: app.logger,
            performReloadConfiguration: { try await reloadHolder.reloadService.reloadConfiguration() })

        try await reloadService.reloadConfiguration()

        let serviceGroup = ServiceGroup(configuration: .init(services: [app, reloadService, tcpService], logger: app.logger))
        try await serviceGroup.run()
    }
}

// workaround to call the async main, but without using a top-level `await` to not break `swift test -c release`.
let group = DispatchGroup()
group.enter()
let task = Task.detached(priority: .userInitiated) {
    defer { group.leave() }
    await ServerCommand.main()
}

group.wait()
