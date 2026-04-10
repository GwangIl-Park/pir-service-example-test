import Foundation
import Hummingbird

struct PIRProcessDatabaseController {
    /// `POST /reload-database` 시 `ReloadService.reloadConfiguration()`에 연결. 테스트에서는 nil.
    private let performReloadConfiguration: (@Sendable () async throws -> Void)?

    init(performReloadConfiguration: (@Sendable () async throws -> Void)? = nil) {
        self.performReloadConfiguration = performReloadConfiguration
    }

    /// 기본 설정 파일 경로 (요청 바디가 없을 때 사용). 환경변수 `PIR_PROCESS_DATABASE_CONFIG` 또는 data/url-config.json
    private static var defaultConfigPath: String {
        ProcessInfo.processInfo.environment["PIR_PROCESS_DATABASE_CONFIG"]
            ?? "url-config.json"
    }

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.post("/process-database", use: processDatabase)
        group.post("/reload-database", use: reloadDatabase)
    }

    @Sendable
    func processDatabase(_ request: Request, context _: AppContext) async throws -> HTTPResponse.Status {
        let configPath: String
        var bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)
        if let bytes = bodyBuffer.readBytes(length: bodyBuffer.readableBytes), !bytes.isEmpty {
            let tempURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("pir-process-config-\(UUID().uuidString).json")
            try Data(bytes).write(to: tempURL)
            defer { try? FileManager.default.removeItem(at: tempURL) }
            configPath = tempURL.path
        } else {
            configPath = Self.defaultConfigPath
        }

        // 외부 실행파일을 띄우지 않고, 패키지 내부 로직을 직접 호출
        try await InternalPIRProcessDatabase.run(configFilePath: configPath, parallel: true)
        return .ok
    }

    @Sendable
    func reloadDatabase(_ request: Request, context _: AppContext) async throws -> HTTPResponse.Status {
        _ = request
        guard let performReloadConfiguration else {
            throw HTTPError(.serviceUnavailable, message: "reload-database is not configured (tests / missing wiring)")
        }
        try await performReloadConfiguration()
        return .accepted
    }
}

enum ProcessDatabaseError: Error, HTTPResponseError {
    case executableNotFound(String)

    var status: HTTPResponse.Status {
        switch self {
        case .executableNotFound: return .internalServerError
        }
    }

    func response(from _: Request, context _: some RequestContext) throws -> Response {
        let message: String
        switch self {
        case let .executableNotFound(path):
            message = "PIRProcessDatabase executable not found: \(path)"
        }
        return Response(status: status, body: ResponseBody(byteBuffer: ByteBuffer(string: message)))
    }
}