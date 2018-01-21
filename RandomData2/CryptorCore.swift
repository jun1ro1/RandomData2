
//
//  CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

typealias CryptorKeyType = Data

enum CryptorError: Error {
    case unexpected
    case outOfRange
    case invalidCharacter
    case wrongPassword
    case notOpened
    case opened
    case SecItemBroken
    case CCCryptError(error: CCCryptorStatus)
    case SecItemError(error: OSStatus)
}

extension CryptorError: LocalizedError {
    /// Returns a description of the error.
    public var errorDescription: String?  {
        switch self {
        case .unexpected:
            return "Unexpected Error"
        case .outOfRange:
            return "Out of Range"
        case .invalidCharacter:
            return "Invalid Character"
        case .wrongPassword:
            return "Wrong Password"
        case .notOpened:
            return "Cryptor is not Opened"
        case .opened:
            return "Cryptor is Opened"
        case .SecItemBroken:
            return "SecItem is broken"
        case .CCCryptError(let error):
            return "CCCrypt Error(\(error))"
        case .SecItemError(let error):
            return "SecItem Error(\(error))"
        }
    }
}

// https://stackoverflow.com/questions/39972512/cannot-invoke-xctassertequal-with-an-argument-list-errortype-xmpperror
extension CryptorError: Equatable {
    /// Returns a Boolean value indicating whether two values are equal.
    ///
    /// - Parameters:
    ///   - lhs: A left hand side expression.
    ///   - rhs: A right hand side expression.
    /// - Returns: `True` if `lhs` equals `rhs`, otherwise `false`.
    static func == (lhs: CryptorError, rhs: CryptorError) -> Bool {
        switch (lhs, rhs) {
        case (.unexpected,       .unexpected),
             (.outOfRange,       .outOfRange),
             (.invalidCharacter, .invalidCharacter),
             (.wrongPassword,    .wrongPassword),
             (.notOpened,        .notOpened),
             (.opened,           .opened):
            return true
        case (.CCCryptError(let error1), .CCCryptError(let error2)):
            return error1 == error2
        default:
            return false
        }
    }
}

fileprivate extension Data {
    func encrypt(with key: CryptorKeyType) throws -> Data {
        var cipher = Data(count: self.count + kCCKeySizeAES256)
        #if DEBUG_ERROR_CCCRYPT
            cipher = Data(count:1)
        #endif
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                self.withUnsafeBytes { ptrPlain in
                    cipher.withUnsafeMutableBytes { ptrCipher in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrPlain, self.count,
                            ptrCipher, cipher.count,
                            &dataOutMoved)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Encrypt) status=", status)
        #endif
        if status == kCCSuccess {
            cipher.removeSubrange(dataOutMoved..<cipher.count)
            return cipher
        }
        else {
            throw CryptorError.CCCryptError(error: status)
        }
    }

    func decrypt(with key: CryptorKeyType) throws -> Data {
        var plain = Data(count: self.count + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                self.withUnsafeBytes { ptrCipher in
                    plain.withUnsafeMutableBytes { ptrPlain in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrCipher, self.count,
                            ptrPlain, plain.count,
                            &dataOutMoved)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Decrypt) status=", status)
        #endif
        if status == kCCSuccess {
            plain.removeSubrange(dataOutMoved..<plain.count)
            return plain
        }
        else {
            throw CryptorError.CCCryptError(error: status)
        }
    }

    func hash() -> Data {
        var hashed = Data(count:Int(CC_SHA256_DIGEST_LENGTH))
        _ = self.withUnsafeBytes { ptrData in
            hashed.withUnsafeMutableBytes { ptrHashed in
                CC_SHA256(ptrData, CC_LONG(self.count), ptrHashed)
            }
        }
        return hashed
    }

    mutating func reset() {
        self.resetBytes(in: self.startIndex..<self.endIndex)
    }
} // extension Data


fileprivate extension String {
    func decrypt(with key: CryptorKeyType) throws -> CryptorKeyType {
        guard let data = CryptorKeyType(base64Encoded: self, options: .ignoreUnknownCharacters) else {
            throw CryptorError.invalidCharacter
        }
        return try data.decrypt(with: key)
    }

    func encrypt(with key: CryptorKeyType) throws -> String {
        guard let data = self.data(using: .utf8, allowLossyConversion: false) else {
            throw CryptorError.invalidCharacter
        }
        return try data.encrypt(with: key).base64EncodedString()
    }

    func decrypt(with key: CryptorKeyType) throws -> String {
        guard var data = Data(base64Encoded: self, options: []) else {
            throw CryptorError.invalidCharacter
        }
        defer { data.reset() }
        return String(data: try data.decrypt(with: key), encoding: .utf8)!
    }
} // extension String


// MARK: -
class SecureStore {
    private var query: [String: Any]

    var dateCreated: Date? {
        return self.query[kSecAttrCreationDate as String] as? Date
    }

    var dateModified: Date? {
        return self.query[kSecAttrModificationDate as String] as? Date
    }

    init() {
        self.query = [:]
    }

    static var shared = SecureStore()

    private func prepare(label: String) {
        self.query = [
            kSecClass              as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: kCFBooleanTrue,
            kSecAttrAccount        as String: label,
        ]
        #if DEBUG
        self.query[kSecAttrDescription as String] = "PasswortTresorTEST"
        #else
        self.query[kSecAttrDescription as String] = "PasswortTresor"
        #endif
    }

    func read(label: String) throws -> Data? {
        self.prepare(label: label)
        self.query[ kSecReturnData       as String] = kCFBooleanTrue
        self.query[ kSecMatchLimit       as String] = kSecMatchLimitOne
        self.query[ kSecReturnAttributes as String] = kCFBooleanTrue
        self.query[ kSecReturnData       as String] = kCFBooleanTrue

        var result: AnyObject?
        let status = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(self.query as CFDictionary, UnsafeMutablePointer($0))
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) SecItemCopyMatching = \(status)")
        #endif
        guard status != errSecItemNotFound else {
            return nil
        }
        guard status == noErr else {
            throw CryptorError.SecItemError(error: status)
        }
        guard let items = result as? Dictionary<String, AnyObject> else {
            throw CryptorError.SecItemBroken
        }
        guard let data = items[kSecValueData as String] as? Data else {
            throw CryptorError.SecItemBroken
        }

        print("kSecValueData = ", data as NSData)
        return data
    }

    func write(label: String, _ data: Data) throws {
        self.prepare(label: label)
        self.query[kSecValueData  as String] = data
        let status = SecItemAdd(self.query as CFDictionary, nil)
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) SecItemAdd = \(status)")
        #endif
        guard status == noErr else {
            throw CryptorError.SecItemError(error: status)
        }
    }

    func update(label: String, _ data: Data) throws {
        self.prepare(label: label)
        let attr: [String: AnyObject] = [kSecValueData as String: data as AnyObject]
        let status = SecItemUpdate(self.query as CFDictionary, attr as CFDictionary)
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) SecItemUpdate = \(status)")
        #endif
        guard status == noErr else {
            throw CryptorError.SecItemError(error: status)
        }
    }

    func delete(label: String) throws {
        self.prepare(label: label)
        let status = SecItemDelete(self.query as NSDictionary)
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) SecItemDelete = \(status)")
        #endif
        guard status == noErr else {
            throw CryptorError.SecItemError(error: status)
        }
    }
}

// MARK: -
struct CryptorSeed {
    var version: String
    var salt:         CryptorKeyType?
    var rounds:       UInt32
    var key:          CryptorKeyType?
    var dateCreated:  Date?
    var dateModified: Date?

    static let label: String = "CryptorSeed"

    init() {
        self.version      = "0"
        self.salt         = nil
        self.rounds       = 1
        self.key          = nil
        self.dateCreated  = nil
        self.dateModified = nil
    }

    init(version: String, salt: CryptorKeyType) {
        self.init()
        self.version = version
        self.salt    = salt
        if self.version == "1" {
            self.rounds = 10000
        }
    }

    init(version: String, salt: CryptorKeyType, key: CryptorKeyType) {
        self.init(version: version, salt: salt)
        self.key = key
     }

    init?(_ str: String) {
        let ary = str.split(separator: ":")
        guard ary.count == 3 else {
            return nil
        }
        let version = String(ary[0])
        let salt    = Data(base64Encoded: String(ary[1]))
        let key     = Data(base64Encoded: String(ary[2]))
        self.init(version: version, salt: salt!, key: key!)
    }

    mutating func reset() {
        self.version      = "0"
        self.salt         = nil
        self.rounds       = 1
        self.key          = nil
        self.dateCreated  = nil
        self.dateModified = nil
    }

    var string: String {
        return [
            self.version,
            self.salt?.base64EncodedString() ?? "",
            self.key?.base64EncodedString() ?? "",
        ].joined(separator: ":")
    }

    static func read() throws -> CryptorSeed? {
        guard var data = try SecureStore.shared.read(label: CryptorSeed.label) else {
            return nil
        }
        defer { data.reset() }

        // get a CryptorSeed string value from SecItem
        guard var str = String(data: data, encoding: .utf8) else {
            throw CryptorError.SecItemBroken
        }
        defer{ str = "" }

        guard var seed = CryptorSeed(str) else {
            throw CryptorError.SecItemBroken
        }
        seed.dateCreated  = SecureStore.shared.dateCreated
        seed.dateModified = SecureStore.shared.dateModified
        return seed
    }

    static func write(_ seed: CryptorSeed) throws {
        guard var data = seed.string.data(using: .utf8) else {
            throw CryptorError.unexpected
        }
        defer { data.reset() }
        try SecureStore.shared.write(label: CryptorSeed.label, data)
    }

} // CryptorSeed

// MARK: -
fileprivate class Validator {
    var hashedMark:    CryptorKeyType? = nil
    var encryptedMark: CryptorKeyType? = nil

    static let label: String = "Validator"

    init?(_ str: String) {
        let ary = str.split(separator: ":")
        guard ary.count == 2 else {
            return nil
        }
        self.hashedMark     = Data(base64Encoded: String(ary[0]))
        self.encryptedMark  = Data(base64Encoded: String(ary[1]))
    }

    init?(key: CryptorKeyType) {
        guard var mark: CryptorKeyType = try? RandomData.shared.get(count: 16) else {
            return nil
        }
        defer { mark.reset() }

        // get a hashed mark
        self.hashedMark = mark.hash()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) mark   =", mark as NSData)
            print(String(reflecting: type(of: self)), "\(#function) hshMark=", self.hashedMark! as NSData)
        #endif

        self.encryptedMark = try? mark.encrypt(with: key)
        guard self.encryptedMark != nil else {
            return nil
        }

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) encryptedMark=", self.encryptedMark! as NSData)
        #endif
    }

    func reset() {
        self.hashedMark?.reset()
        self.encryptedMark?.reset()
    }

    var string: String {
        return [
            self.hashedMark?.base64EncodedString() ?? "",
            self.encryptedMark?.base64EncodedString() ?? "",
            ].joined(separator: ":")
    }

    func validate(key: CryptorKeyType) -> Bool {
        guard self.hashedMark != nil && self.encryptedMark != nil else {
            return false
        }

        do {
            // get binary Mark
            var decryptedMark: CryptorKeyType = try self.encryptedMark!.decrypt(with: key)
            defer { decryptedMark.reset() }

            var hashedDecryptedMark: CryptorKeyType = decryptedMark.hash()
            defer { hashedDecryptedMark.reset() }

            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) hashedMark          =", hashedMark! as NSData)
                print(String(reflecting: type(of: self)), "\(#function) hashedDecryptedMark =", hashedDecryptedMark as NSData)
            #endif

            return hashedMark == hashedDecryptedMark
        } catch {
            return false
        }
    }

    static func read() throws -> Validator? {
        guard var data = try SecureStore.shared.read(label: Validator.label) else {
            throw CryptorError.SecItemBroken
        }
        defer { data.reset() }

        guard var str = String(data: data, encoding: .utf8) else {
            throw CryptorError.SecItemBroken
        }
        defer { str = "" }

        guard let validator = Validator(str) else {
            throw CryptorError.SecItemBroken
        }
        return validator
    }

    static func write(_ validator: Validator) throws {
        guard var data = validator.string.data(using: .utf8) else {
            throw CryptorError.unexpected
        }
        defer { data.reset() }
        try SecureStore.shared.write(label: Validator.label, data)
    }
} // Validator

// MARK: -
class CryptorCore {
    // constants
    static let MaxPasswordLength = 1000

    // instance variables
    struct Session {
        var cryptor: Cryptor
        var binITK:  CryptorKeyType  // Inter key: the KEK(Key kncryption Key) encrypted with SEK(Session Key)

        init(cryptor: Cryptor, key: CryptorKeyType) {
            self.cryptor = cryptor
            self.binITK  = key
        }
    }
    var sessions: [Int: Session]

    static var shared = CryptorCore()

    init() {
        self.sessions = [:]
    }

    // MARK: - methods
    private func getKEK(password: String, seed: CryptorSeed) throws -> CryptorKeyType {
        // check password
        guard case 1...CryptorCore.MaxPasswordLength = password.count else {
            throw CryptorError.outOfRange
        }

        // convert the password to a Data
        guard var binPASS = password.data(using: .utf8, allowLossyConversion: true) else {
            throw CryptorError.invalidCharacter
        }
        defer { binPASS.reset() }

        // derivate an CEK with the password and the SALT
        guard var salt: CryptorKeyType = seed.salt else {
            throw CryptorError.SecItemBroken
        }
        defer { salt.reset() }

        var kek = CryptorKeyType(count: Int(kCCKeySizeAES256))
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        // https://stackoverflow.com/questions/35749197/how-to-use-common-crypto-and-or-calculate-sha256-in-swift-2-3
        status =
            salt.withUnsafeBytes { ptrSALT in
                binPASS.withUnsafeBytes { ptrPASS in
                    kek.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             UnsafePointer<Int8>(ptrPASS), binPASS.count,
                                             UnsafePointer<UInt8>(ptrSALT), salt.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             seed.rounds,
                                             ptrKEK, kek.count)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) KEK   =", kek as NSData)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            throw CryptorError.CCCryptError(error: status)
        }
        return kek
    }

    func prepare(password: String) throws {
        if var seed = try CryptorSeed.read() {
            var validator = try Validator.read()
            defer { validator?.reset() }

             // get a CEK encrypted with a KEK
            guard var cekEnc = seed.key else {
                throw CryptorError.SecItemBroken
            }
            defer{ cekEnc.reset() }

            // derivate a KEK with the password and the SALT
            var kek = try self.getKEK(password: password, seed: seed)
            defer{ kek.reset() }

            // get a CEK
            var cek = try cekEnc.decrypt(with: kek)
            defer{ cek.reset() }

            guard validator?.validate(key: cek) == true else {
                throw CryptorError.wrongPassword
            }
        }
        else {
            // convert the password to a Data
            guard var binPASS: CryptorKeyType = password.data(using: .utf8, allowLossyConversion: true) else {
                throw CryptorError.invalidCharacter
            }
            defer { binPASS.reset() }

            // create a salt
            var salt: CryptorKeyType = try RandomData.shared.get(count: 16)
            defer { salt.reset() }

            // create a CryptorSeed
            var seed = CryptorSeed(version: "1", salt: salt)

            // derivate a KEK with the password and the SALT
            var kek = try self.getKEK(password: password, seed: seed)
            defer { kek.reset() }

            // create a CEK
            var cek: CryptorKeyType = try RandomData.shared.get(count: Int(kCCKeySizeAES256))
            defer { cek.reset() }

            // create a Validator
            guard var validator = Validator(key: cek) else {
                throw CryptorError.unexpected
            }
            defer { validator.reset() }

            // encrypt the CEK with the KEK
            // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
            // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
            var cekEnc: CryptorKeyType = try cek.encrypt(with: kek)
            defer { cekEnc.reset() }
            seed.key = cekEnc

            try CryptorSeed.write(seed)
            try Validator.write(validator)

            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) salt  =", salt as NSData)
                print(String(reflecting: type(of: self)), "\(#function) kek   =", kek as NSData)
                print(String(reflecting: type(of: self)), "\(#function) cek   =", cek as NSData)
                print(String(reflecting: type(of: self)), "\(#function) cekEnc=", cekEnc as NSData)
            #endif
        }
    }

//    func create(password: String) throws {
//        // convert the password to a Data
//        guard var binPASS: CryptorKeyType = password.data(using: .utf8, allowLossyConversion: true) else {
//            throw CryptorError.invalidCharacter
//        }
//        defer { binPASS.reset() }
//
//        // create SALT
//        var binSALT: CryptorKeyType = try RandomData.shared.get(count: 16)
//        defer { binSALT.reset() }
//
//        // derivate a KEK with the password and the SALT
//        let binKEK = try self.getKEK(password: password, salt: binSALT)
//
//        // create a CEK
//        var binCEK: CryptorKeyType = try RandomData.shared.get(count: Int(kCCKeySizeAES256))
//        defer { binCEK.reset() }
//
//        // encrypt the CEK with the KEK
//        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
//        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
//        var binEncCEK: CryptorKeyType = try binCEK.encrypt(with: binKEK)
//        defer { binEncCEK.reset() }
//
//        // store a validator, a salt and an encrypted CEK
//        self.validator = Validator(key: binCEK)
//        self.strSALT = binSALT.base64EncodedString()
//        self.strEncCEK = binEncCEK.base64EncodedString()
//
//        #if DEBUG
//            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT as NSData)
//            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK as NSData)
//            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK as NSData)
//            print(String(reflecting: type(of: self)), "\(#function) binEncCEK=", binEncCEK as NSData)
//        #endif
//    }

    func open(password: String, cryptor: Cryptor) throws -> CryptorKeyType {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)

        // get a seed
        guard var seed = try CryptorSeed.read() else {
            throw CryptorError.unexpected  // not prepared
        }
        defer { seed.reset() }

        guard var validator = try Validator.read() else {
            throw CryptorError.unexpected // not prepared
        }
        defer { validator.reset() }

        // get a CEK encrypted with a KEK
        guard var cekEnc = seed.key else {
            throw CryptorError.SecItemBroken
        }
        defer{ cekEnc.reset() }

        // derivate a KEK with the password and the SALT
        var kek = try self.getKEK(password: password, seed: seed)
        defer{ kek.reset() }

        // get a CEK
        var cek = try cekEnc.decrypt(with: kek)
        defer{ cek.reset() }

        guard validator.validate(key: cek) == true else {
            throw CryptorError.wrongPassword
        }

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) cek   =", cek as NSData)
        #endif

        // check CEK
        guard validator.validate(key: cek) == true else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            throw CryptorError.wrongPassword
        }

        var binSEK: CryptorKeyType = try RandomData.shared.get(count: kCCKeySizeAES256)
        defer { binSEK.reset() }

        var binKEKEncryptedWithSEK: CryptorKeyType = try kek.encrypt(with: binSEK)
        defer { binKEKEncryptedWithSEK.reset() }

        self.sessions[ObjectIdentifier(cryptor).hashValue] = Session(cryptor: cryptor, key: binKEKEncryptedWithSEK)
        return binSEK
    }


    func close(cryptor: Cryptor) throws {
        guard self.sessions.removeValue(forKey: ObjectIdentifier(cryptor).hashValue) != nil else {
            throw CryptorError.notOpened
        }
    }

    func closeAll() throws {
        let cryptors = self.sessions.values
        try cryptors.forEach { try self.close(cryptor: $0.cryptor) }
    }

/*
    func change(password oldpass: String, to newpass: String) throws {
        // get SALT
        guard var binSALT = CryptorKeyType(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            throw CryptorError.invalidCharacter
        }
        defer { binSALT.reset() }

        // get KEK from SALT, password
        var binKEK = try self.getKEK(password: oldpass, salt: binSALT)
        defer { binKEK.reset() }

        // get CEK with KEK
        var binCEK: CryptorKeyType = try self.strEncCEK.decrypt(with: binKEK)
        defer { binCEK.reset() }

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncCEK=", self.strEncCEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK as NSData)
        #endif

        // check CEK
        guard self.validator?.validate(key: binCEK) == true else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            throw CryptorError.wrongPassword
        }

        // change KEK
        var binNewKEK = try self.getKEK(password: newpass, salt: binSALT)
        defer { binNewKEK.reset() }

        // crypt a CEK with a new KEK
        var binNewEncCEK: CryptorKeyType = try binCEK.encrypt(with: binNewKEK)
        defer { binNewEncCEK.reset() }

        // store a new encrypted CEK
        self.strEncCEK = binNewEncCEK.base64EncodedString()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binNewKEK    =", binNewKEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binCEK       =", binCEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binNewEncCEK =", binNewEncCEK as NSData)
        #endif
    }
*/

    func encrypt(cryptor: Cryptor, plain: Data) throws -> Data {
        guard let sek = cryptor.key else {
            throw CryptorError.notOpened
        }
        var kek: CryptorKeyType =
            (try self.sessions[ObjectIdentifier(cryptor).hashValue]?.binITK.decrypt(with: sek))!
        defer { kek.reset() }

        // get a seed
        guard var seed = try CryptorSeed.read() else {
            throw CryptorError.unexpected  // not prepared
        }
        defer { seed.reset() }

       // get a CEK encrypted with a KEK
        guard var cekEnc = seed.key else {
            throw CryptorError.SecItemBroken
        }
        defer{ cekEnc.reset() }

        var cek: CryptorKeyType = try cekEnc.decrypt(with: kek)
        defer { cek.reset() }

        return try plain.encrypt(with: cek)
    }

    func decrypt(cryptor: Cryptor, cipher: Data) throws -> Data {
        guard let sek = cryptor.key else {
            throw CryptorError.notOpened
        }
        var kek: CryptorKeyType =
            (try self.sessions[ObjectIdentifier(cryptor).hashValue]?.binITK.decrypt(with: sek))!
        defer { kek.reset() }

        // get a seed
        guard var seed = try CryptorSeed.read() else {
            throw CryptorError.unexpected  // not prepared
        }
        defer { seed.reset() }

        // get a CEK encrypted with a KEK
        guard var cekEnc = seed.key else {
            throw CryptorError.SecItemBroken
        }
        defer{ cekEnc.reset() }

        var cek: CryptorKeyType = try cekEnc.decrypt(with: kek)
        defer { cek.reset() }

        return try cipher.decrypt(with: cek)
    }

    func encrypt(cryptor: Cryptor, plain: String) throws -> String {
        guard let sek = cryptor.key else {
            throw CryptorError.notOpened
        }
        var kek: CryptorKeyType =
            (try self.sessions[ObjectIdentifier(cryptor).hashValue]?.binITK.decrypt(with: sek))!
        defer { kek.reset() }

        // get a seed
        guard var seed = try CryptorSeed.read() else {
            throw CryptorError.unexpected  // not prepared
        }
        defer { seed.reset() }

        // get a CEK encrypted with a KEK
        guard var cekEnc = seed.key else {
            throw CryptorError.SecItemBroken
        }
        defer{ cekEnc.reset() }

        var cek: CryptorKeyType = try cekEnc.decrypt(with: kek)
        defer { cek.reset() }

        return try plain.encrypt(with: cek)
    }

    func decrypt(cryptor: Cryptor, cipher: String) throws -> String {
        guard let sek = cryptor.key else {
            throw CryptorError.notOpened
        }
        var kek: CryptorKeyType =
            (try self.sessions[ObjectIdentifier(cryptor).hashValue]?.binITK.decrypt(with: sek))!
        defer { kek.reset() }

        // get a seed
        guard var seed = try CryptorSeed.read() else {
            throw CryptorError.unexpected  // not prepared
        }
        defer { seed.reset() }

        // get a CEK encrypted with a KEK
        guard var cekEnc = seed.key else {
            throw CryptorError.SecItemBroken
        }
        defer{ cekEnc.reset() }

        var cek: CryptorKeyType = try cekEnc.decrypt(with: kek)
        defer { cek.reset() }

        return try cipher.decrypt(with: cek)
    }
}

