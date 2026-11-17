enum VaultKeychain {
    private static let service = (Bundle.main.bundleIdentifier ?? "com.0001.money") + ".vault"
    private struct Kept: Codable { let publicKey: String; let key: String }

    static func read(for publicKey: String) -> String? {
        var result: CFTypeRef?
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: "records",
            kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne,
        ]
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data,
              let kept = try? JSONDecoder().decode(Kept.self, from: data), kept.publicKey == publicKey else { return nil }
        return kept.key
    }
    static func write(_ key: String?, for publicKey: String = "") {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: "records"]
        SecItemDelete(query as CFDictionary)
        guard let key, let data = try? JSONEncoder().encode(Kept(publicKey: publicKey, key: key)) else { return }
        var add = query
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
}
