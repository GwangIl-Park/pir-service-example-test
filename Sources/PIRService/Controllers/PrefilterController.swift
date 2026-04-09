import Foundation
import Hummingbird
import NIO

struct PrefilterController {
    let store: PrefilterStore

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.get("/prefilter/meta", use: getPrefilter)
        group.get("/prefilter/data", use: getPrefilterData)
    }

    @Sendable
    func getPrefilter(_ request: Request, context _: AppContext) async throws -> Response {
        guard
            let usecase = extractUsecase(from: request),
            !usecase.isEmpty
        else {
            return Response(
                status: .badRequest,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Query parameter 'usecase' is required")))
        }
        guard let snapshot = await store.get(usecase: usecase) else {
            return Response(
                status: .notFound,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Prefilter metadata not found for usecase '\(usecase)'")))
        }

        let outputURL = URL(fileURLWithPath: snapshot.outputFile)
        guard FileManager.default.fileExists(atPath: outputURL.path) else {
            return Response(
                status: .notFound,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Prefilter JSON not found for usecase '\(usecase)'")))
        }
        let data = try Data(contentsOf: outputURL)
        return Response(
            status: .ok,
            headers: [.contentType: "application/json"],
            body: ResponseBody(byteBuffer: ByteBuffer(bytes: data)))
    }

    @Sendable
    func getPrefilterData(_ request: Request, context _: AppContext) async throws -> Response {
        guard
            let usecase = extractUsecase(from: request),
            !usecase.isEmpty
        else {
            return Response(
                status: .badRequest,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Query parameter 'usecase' is required")))
        }
        guard let snapshot = await store.get(usecase: usecase) else {
            return Response(
                status: .notFound,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Prefilter metadata not found for usecase '\(usecase)'")))
        }

        let outputURL = URL(fileURLWithPath: snapshot.outputFile)
        let datURL = outputURL.deletingPathExtension().appendingPathExtension("dat")
        guard FileManager.default.fileExists(atPath: datURL.path) else {
            return Response(
                status: .notFound,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Prefilter data file not found for usecase '\(usecase)'")))
        }
        let data = try Data(contentsOf: datURL)
        return Response(
            status: .ok,
            headers: [.contentType: "application/octet-stream"],
            body: ResponseBody(byteBuffer: ByteBuffer(bytes: data)))
    }

    private func extractUsecase(from request: Request) -> String? {
        guard
            let rawQuery = request.uri.query,
            !rawQuery.isEmpty
        else {
            return nil
        }
        for pair in rawQuery.split(separator: "&", omittingEmptySubsequences: true) {
            let pieces = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pieces.count == 2 else { continue }
            guard pieces[0] == "usecase" else { continue }
            return String(pieces[1]).removingPercentEncoding ?? String(pieces[1])
        }
        return nil
    }
}
