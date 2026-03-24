import Foundation
import Hummingbird
import NIO

struct PrefilterController {
    let store: PrefilterStore

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.get("/prefilter", use: getPrefilter)
    }

    @Sendable
    func getPrefilter(_ request: Request, context _: AppContext) async throws -> Response {
        _ = request
        guard let snapshot = await store.get() else {
            return Response(
                status: .notFound,
                body: ResponseBody(byteBuffer: ByteBuffer(string: "Prefilter has not been generated yet")))
        }

        let payload = PrefilterResponse(
            generatedAt: snapshot.generatedAt,
            sourceURLCount: snapshot.sourceURLCount,
            sourceFile: snapshot.sourceFile,
            outputFile: snapshot.outputFile,
            bloomFilter: snapshot.filter)
        let data = try JSONEncoder().encode(payload)
        return Response(
            status: .ok,
            headers: [.contentType: "application/json"],
            body: ResponseBody(byteBuffer: ByteBuffer(bytes: data)))
    }
}

struct PrefilterResponse: Codable {
    let generatedAt: Date
    let sourceURLCount: Int
    let sourceFile: String
    let outputFile: String
    let bloomFilter: BloomFilter
}
