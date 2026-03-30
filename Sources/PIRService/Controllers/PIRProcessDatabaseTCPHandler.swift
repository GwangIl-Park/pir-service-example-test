import Foundation
import NIO
import Logging
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// TCP 기반으로 PIR 데이터베이스 처리 요청을 받기 위한 핸들러의 골격입니다.
/// 현재는 HTTP 컨트롤러(`PIRProcessDatabaseController`)와 동일한 내부 처리기
/// (`InternalPIRProcessDatabase`)를 사용하도록 설계되어 있습니다.
///
/// - 텍스트 프로토콜:
///   - `PROCESS`: 미리 지정된 설정 파일로 DB 처리
///   - `RELOAD`: SIGHUP을 발생시켜 ReloadService 트리거
///   - 성공 시: `"OK\n"`, 실패 시: `"ERROR: ...\n"`
final class PIRProcessDatabaseTCPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let configFile: URL
    let logger: Logger

    init(configFile: URL, logger: Logger) {
        self.configFile = configFile
        self.logger = logger
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

        context.eventLoop.makeFutureWithTask {
            if received == "PROCESS" {
                try await InternalPIRProcessDatabase.run(configFilePath: self.configFile.path, parallel: true)
            } else if received == "RELOAD" {
                let result = raise(SIGHUP)
                if result != 0 {
                    let code = Int(errno)
                    throw PIRProcessDatabaseTCPError.reloadFailed(code)
                }
            } else {
                throw PIRProcessDatabaseTCPError.invalidCommand
            }
        }.whenComplete { result in
            switch result {
            case .success:
                let okBuffer = context.channel.allocator.buffer(string: "OK\n")
                context.writeAndFlush(self.wrapOutboundOut(okBuffer), promise: nil)
            case .failure(let error):
                let errorBuffer = context.channel.allocator.buffer(
                    string: "ERROR: \(error.localizedDescription)\n")
                context.writeAndFlush(self.wrapOutboundOut(errorBuffer), promise: nil)
            }
        }
    }
}

enum PIRProcessDatabaseTCPError: Error {
    case invalidCommand
    case reloadFailed(Int)
}

