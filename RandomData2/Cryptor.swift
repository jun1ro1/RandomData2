//
//  Cryptor.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/05.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

public class Cryptor {
    static var core: CryptorCore = CryptorCore.shared
    var key: CryptorKeyType?
    
    init() {
        self.key = nil
    }
    
    func open(password: String) throws {
        self.key = try Cryptor.core.open(password: password, cryptor: self)
    }
    
    func close() throws {
        try Cryptor.core.close(cryptor: self)
        self.key = nil
    }
    
    func open(password: String, _ body:() -> Void ) throws {
        try self.open(password: password)
        defer {
            try? self.close()
        }
        body()
    }

    /*
    func change(password oldpass: String, to newpass: String) throws {
        guard self.key == nil else {
            throw CryptorError.opened
        }
        return try Cryptor.core.change(password: oldpass, to: newpass)
    }
*/
    
    func encrypt(plain: Data) throws -> Data {
        guard self.key != nil else {
            throw CryptorError.opened
        }
        return try Cryptor.core.encrypt(cryptor: self, plain: plain)
    }

    func decrypt(cipher: Data) throws -> Data {
        guard self.key != nil else {
            throw CryptorError.opened
        }
        return try Cryptor.core.decrypt(cryptor: self, cipher: cipher)
    }

    func encrypt(plain: String) throws -> String {
        guard self.key != nil else {
            throw CryptorError.opened
        }
        return try Cryptor.core.encrypt(cryptor: self, plain: plain)
    }

    func decrypt(cipher: String) throws -> String {
        guard self.key != nil else {
            throw CryptorError.opened
        }
        return try Cryptor.core.decrypt(cryptor: self, cipher: cipher)
    }
}
