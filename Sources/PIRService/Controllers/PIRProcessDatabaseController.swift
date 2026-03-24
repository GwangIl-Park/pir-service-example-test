import Foundation
import Hummingbird
import Darwin

struct PIRProcessDatabaseController {
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
        _ = request // 현재는 요청 바디를 사용하지 않음

        // 현재 프로세스를 종료하지 않고, SIGHUP 시그널만 발생시켜
        // 이미 등록된 ReloadService가 설정/데이터를 다시 로드하도록 합니다.
        let result = raise(SIGHUP)
        if result != 0 {
            let code = Int(errno)
            throw ProcessDatabaseError.nonZeroExit(code)
        }

        // ReloadService가 비동기로 새 데이터를 로드하는 동안
        // UsecaseStore는 버전별로 유지되므로, 완료 전까지는 기존 데이터가 사용됩니다.
        return .accepted
    }
}

enum ProcessDatabaseError: Error, HTTPResponseError {
    case executableNotFound(String)
    case nonZeroExit(Int)

    var status: HTTPResponse.Status {
        switch self {
        case .executableNotFound: return .internalServerError
        case .nonZeroExit: return .internalServerError
        }
    }

    func response(from _: Request, context _: some RequestContext) throws -> Response {
        let message: String
        switch self {
        case let .executableNotFound(path):
            message = "PIRProcessDatabase executable not found: \(path)"
        case let .nonZeroExit(code):
            message = "PIRProcessDatabase exited with code \(code)"
        }
        return Response(status: status, body: ResponseBody(byteBuffer: ByteBuffer(string: message)))
    }
}