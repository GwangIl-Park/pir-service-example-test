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

// This executable is used in tests, which breaks `swift test -c release` when used with `@main`.
// So we avoid using `@main` here.
struct ServerCommand: AsyncParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRService")

    @Option var hostname: String = "0.0.0.0"
    @Option(name: .customLong("http-port")) var httpPort: Int = 8080
    @Option(name: .customLong("tcp-port")) var tcpPort: Int = 9000
    @Option(name: .customLong("log-file"), help: "Append logs to this path (stderr unchanged). Omit to log to stderr only.")
    var logFile: String = ""
    @Option(name: .customLong("service-config-file")) var serviceConfigFile: String
    @Option(name: .customLong("url-config-file")) var urlConfigFile: String

    func run() async throws {
        if !logFile.isEmpty {
            try LoggingBootstrap.bootstrapStderrAndFile(logFileURL: URL(fileURLWithPath: logFile))
        }

        let usecaseStore = UsecaseStore()
        let prefilterStore = PrefilterStore()
        let privacyPassState = try PrivacyPassState(userAuthenticator: UserAuthenticator())

        let app = try await buildApplication(
            configuration: .init(address: .hostname(hostname, port: httpPort)),
            usecaseStore: usecaseStore,
            prefilterStore: prefilterStore,
            privacyPassState: privacyPassState)

        let reloadService = ReloadService(
            configFile: URL(fileURLWithPath: serviceConfigFile),
            processDatabaseConfigPath: urlConfigFile,
            usecaseStore: usecaseStore,
            prefilterStore: prefilterStore,
            privacyPassState: privacyPassState,
            logger: app.logger)

        let tcpService = PIRProcessDatabaseTCPService(
            host: hostname,
            port: tcpPort,
            configFile: URL(fileURLWithPath: urlConfigFile),
            logger: app.logger)

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
