import Foundation
import Logging
import NIO
import ServiceLifecycle

/// PIRProcessDatabaseTCPHandler 를 사용하여 TCP 포트에서 요청을 받는 ServiceLifecycle 서비스.
struct PIRProcessDatabaseTCPService: Service {
    let host: String
    let port: Int
    let configFile: URL
    let logger: Logger
    let performReloadConfiguration: @Sendable () async throws -> Void

    func run() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

        let bootstrap = ServerBootstrap(group: group)
            // 서버 채널 옵션
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            // 연결마다 핸들러 추가
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(
                    PIRProcessDatabaseTCPHandler(
                        configFile: self.configFile,
                        logger: self.logger,
                        performReloadConfiguration: self.performReloadConfiguration))
            }
            // 자식 채널 옵션
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
            .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())

        let channel = try await bootstrap.bind(host: host, port: port).get()
        logger.info("PIRProcessDatabase TCP server listening on \(host):\(port)")

        // 채널이 닫힐 때까지 대기 (ServiceLifecycle 가 취소하면 closeFuture 가 완료되도록 구성)
        try await channel.closeFuture.get()

        // 이벤트 루프 그룹 비동기 종료
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            group.shutdownGracefully { error in
                if let error {
                    self.logger.error("Failed to shutdown TCP eventLoopGroup: \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

