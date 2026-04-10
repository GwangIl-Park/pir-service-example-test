import Foundation
import Logging
import NIO

/// TCP 기반으로 PIR 데이터베이스 처리 요청을 받기 위한 핸들러의 골격입니다.
/// 현재는 HTTP 컨트롤러(`PIRProcessDatabaseController`)와 동일한 내부 처리기
/// (`InternalPIRProcessDatabase`)를 사용하도록 설계되어 있습니다.
///
/// - 텍스트 프로토콜:
///   - `PROCESS`: 미리 지정된 설정 파일로 DB 처리
///   - `RELOAD`: `ReloadService.reloadConfiguration()` 직접 호출
///   - 성공 시: `"OK\n"`, 실패 시: `"ERROR: ...\n"`
final class PIRProcessDatabaseTCPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let configFile: URL
    let logger: Logger
    private let performReloadConfiguration: @Sendable () async throws -> Void

    init(
        configFile: URL,
        logger: Logger,
        performReloadConfiguration: @escaping @Sendable () async throws -> Void
    ) {
        self.configFile = configFile
        self.logger = logger
        self.performReloadConfiguration = performReloadConfiguration
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)
        guard let received = buffer.readString(length: buffer.readableBytes)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !received.isEmpty
        else {
            return
        }

        logger.info("PIRProcessDatabaseTCPHandler received", metadata: [
            "remoteAddress": "\(context.remoteAddress?.description ?? "unknown")",
            "payload": "\(received)"
        ])

        let loop = context.eventLoop
        let channel = context.channel
        let allocator = channel.allocator
        loop.makeFutureWithTask {
            self.logger.info("PIRProcessDatabaseTCPHandler task started", metadata: ["payload": "\(received)"])
            if received == "PROCESS" {
                // 서비스 설정의 `dataPath`(없으면 `<서비스설정>/data`)를 루트로,
                // `{resourceRoot}/{fileStem}-config.json` + JSON 내 상대 경로 입·출력도 같은 루트에 맞춘다.
                let configData = try Data(contentsOf: self.configFile)
                let config = try JSONDecoder().decode(ServerConfiguration.self, from: configData)

                let resourceRoot = config.resolvedDataRootURL(relativeTo: self.configFile)
                    ?? config.defaultProcessConfigDataDirectoryURL(relativeTo: self.configFile)

                for usecase in config.usecases {
                    let derivedConfigURL = resourceRoot.appendingPathComponent("\(usecase.fileStem)-config.json")
                    self.logger.info(
                        "TCP PROCESS: running InternalPIRProcessDatabase",
                        metadata: [
                            "usecase": .string(usecase.name),
                            "configFilePath": .string(derivedConfigURL.path),
                            "resourceRoot": .string(resourceRoot.path),
                        ])
                    try await InternalPIRProcessDatabase.run(
                        configFilePath: derivedConfigURL.path,
                        outputFileStem: usecase.fileStem,
                        parallel: true,
                        relativePathBaseDirectory: resourceRoot.path)
                }
            } else if received == "RELOAD" {
                self.logger.info("PIRProcessDatabaseTCPHandler RELOAD: calling reloadConfiguration()")
                try await self.performReloadConfiguration()
                self.logger.info("PIRProcessDatabaseTCPHandler RELOAD: reloadConfiguration() finished")
            } else {
                throw PIRProcessDatabaseTCPError.invalidCommand
            }
        }.whenComplete { result in
            // Linux 등에서 완료 콜백이 채널 이벤트 루프가 아닌 스레드에서 호출될 수 있어,
            // writeAndFlush는 반드시 loop에서 실행한다.
            loop.execute {
                switch result {
                case .success:
                    let okBuffer = allocator.buffer(string: "OK\n")
                    channel.writeAndFlush(okBuffer, promise: nil)
                case .failure(let error):
                    let errorBuffer = allocator.buffer(string: "ERROR: \(error.localizedDescription)\n")
                    channel.writeAndFlush(errorBuffer, promise: nil)
                }
            }
        }
    }
}

enum PIRProcessDatabaseTCPError: Error {
    case invalidCommand
}

