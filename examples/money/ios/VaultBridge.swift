/// Carries the core's requests to the network and its finished calls back to whoever awaits them.
final class VaultBridge: @unchecked Sendable {
    private let lock = NSLock()
    private var calls: [String: CheckedContinuation<String, Error>] = [:]
    weak var core: MoneyCore?
    /// Sends one request with the person's token: method, path, body, headers; answers the status and body.
    var send: (@Sendable (String, String, Data?, [String: String]) async -> (Int, Data))?

    func hold(_ id: String, _ continuation: CheckedContinuation<String, Error>) {
        lock.lock(); calls[id] = continuation; lock.unlock()
    }
    func finish(_ id: String, ok: Bool, payload: String) {
        lock.lock(); let continuation = calls.removeValue(forKey: id); lock.unlock()
        if ok { continuation?.resume(returning: payload) } else { continuation?.resume(throwing: MoneyError.refused(payload)) }
    }
    func request(id: String, method: String, path: String, body: String, headers: String) {
        let data = body.isEmpty ? nil : Data(base64Encoded: body)
        let fields = (try? JSONDecoder().decode([String: String].self, from: Data(headers.utf8))) ?? [:]
        let send = self.send
        Task { [weak self] in
            let (status, answer) = await send?(method, path, data, fields) ?? (0, Data())
            await self?.core?.vaultAnswer(id, status: status, body: answer)
        }
    }
}
