/// AES-256-GCM for locked text in Private's format: "v1." and base64url of the nonce, ciphertext and
/// tag, which is CryptoKit's combined box. The key is base64url; the text and its binding are UTF-8.
enum VaultCipher {
    enum Failure: Error { case format }
    static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func data(_ base64url: String) throws -> Data {
        var text = base64url.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        text += String(repeating: "=", count: (4 - text.count % 4) % 4)
        guard let data = Data(base64Encoded: text) else { throw Failure.format }
        return data
    }
    static func lock(key: String, text: String, aad: String) throws -> String {
        let box = try AES.GCM.seal(Data(text.utf8), using: SymmetricKey(data: try data(key)), nonce: AES.GCM.Nonce(), authenticating: Data(aad.utf8))
        guard let combined = box.combined else { throw Failure.format }
        return "v1." + base64url(combined)
    }
    static func unlock(key: String, locked: String, aad: String) throws -> String {
        guard locked.hasPrefix("v1.") else { throw Failure.format }
        let box = try AES.GCM.SealedBox(combined: try data(String(locked.dropFirst(3))))
        let plain = try AES.GCM.open(box, using: SymmetricKey(data: try data(key)), authenticating: Data(aad.utf8))
        return String(decoding: plain, as: UTF8.self)
    }
}
