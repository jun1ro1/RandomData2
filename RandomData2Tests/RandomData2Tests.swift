//
//  RandomData2Tests.swift
//  RandomData2Tests
//
//  Created by OKU Junichirou on 2018/01/04.
//  Copyright © 2018年 OKU Junichirou. All rights reserved.
//

import XCTest
import Foundation
@testable import RandomData2

class RandomData2Tests: XCTestCase {

    // MARK: - Constant Definitions

    let Deutsch = """
https://ja.wikipedia.org/wiki/歓喜の歌

An die Freude
   Johann Christoph Friedrich von Schiller

O Freunde, nicht diese Töne!
Sondern laßt uns angenehmere
anstimmen und freudenvollere.

Freude, schöner Götterfunken,
Tochter aus Elysium
Wir betreten feuertrunken.
Himmlische, dein Heiligtum!

Deine Zauber binden wieder,
Was die Mode streng geteilt;
Alle Menschen werden Brüder,
Wo dein sanfter Flügel weilt.

Wem der große Wurf gelungen,
Eines Freundes Freund zu sein,
Wer ein holdes Weib errungen,
Mische seinen Jubel ein!

Ja, wer auch nur eine Seele
Sein nennt auf dem Erdenrund!
Und wer's nie gekonnt, der stehle
Weinend sich aus diesem Bund!

Freude trinken alle Wesen
An den Brüsten der Natur;
Alle Guten, alle Bösen
Folgen ihrer Rosenspur.

Küsse gab sie uns und Reben,
Einen Freund, geprüft im Tod;
Wollust ward dem Wurm gegeben,
und der Cherub steht vor Gott.

Froh, wie seine Sonnen fliegen
Durch des Himmels prächt'gen Plan,
Laufet, Brüder, eure Bahn,
Freudig, wie ein Held zum Siegen.

Seid umschlungen, Millionen!
Diesen Kuss der ganzen Welt!
Brüder, über'm Sternenzelt
Muß ein lieber Vater wohnen.

Ihr stürzt nieder, Millionen?
Ahnest du den Schöpfer, Welt?
Such' ihn über'm Sternenzelt!
Über Sternen muß er wohnen.
"""

    let Japanisch = """
https://ja.wikipedia.org/wiki/歓喜の歌

「歓喜に寄せて」
   ヨーハン・クリストフ・フリードリヒ・フォン・シラー

おお友よ、このような音ではない！
我々はもっと心地よい
もっと歓喜に満ち溢れる歌を歌おうではないか

歓喜よ、神々の麗しき霊感よ
天上の楽園の乙女よ
我々は火のように酔いしれて
崇高な汝（歓喜）の聖所に入る

汝が魔力は再び結び合わせる
時流が強く切り離したものを
すべての人々は兄弟となる
汝の柔らかな翼が留まる所で

ひとりの友の友となるという
大きな成功を勝ち取った者
心優しき妻を得た者は
彼の歓声に声を合わせよ

そうだ、地上にただ一人だけでも
心を分かち合う魂があると言える者も歓呼せよ
そしてそれがどうしてもできなかった者は
この輪から泣く泣く立ち去るがよい

すべての被造物は
創造主の乳房から歓喜を飲み、
すべての善人とすべての悪人は
創造主の薔薇の踏み跡をたどる。

口づけと葡萄酒と死の試練を受けた友を
創造主は我々に与えた
快楽は虫けらのような弱い人間にも与えられ
智天使ケルビムは神の御前に立つ

天の星々がきらびやかな天空を
飛びゆくように、楽しげに
兄弟たちよ、自らの道を進め
英雄のように喜ばしく勝利を目指せ

抱擁を受けよ、諸人（もろびと）よ！
この口づけを全世界に！
兄弟よ、この星空の上に
ひとりの父なる神が住んでおられるに違いない

諸人よ、ひざまずいたか
世界よ、創造主を予感するか
星空の彼方に神を求めよ
星々の上に、神は必ず住みたもう
"""

    var allChars = ""

    let Primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
        353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
        467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
        547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
        607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
        661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
        739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
        811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
        877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
        947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
        1019, 1021
    ]
    var counts: [Int] = []
    let counts_error: [Int] = [0, -1, RandomData.COUNT_MAX + 1, Int.min, Int.max]
    let cypherCharSet: [CypherCharacterSet] =
        CypherCharacterSet.StandardCharacterSet + [.AllCharactersSet]

    // MARK: Set up and Tear down

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        allChars  = "0123456789"
        allChars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        allChars += "abcdefghijklmnopqrstuvwxyz"
        allChars += "!#$%&'()*+,-./"
        allChars += ":;<>=?@"
        allChars += "[]^_`{}|~"
        allChars += "\"" + "\\"
        counts = { ( Primes + [1, 8, 10, 16, 32, 64, 256, 1024] ).sorted() }()
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    // MARK: - Test Methods
    func testCryptor_async_closeAll() {
        print("\n\(#function):\(#line)")
        try? CryptorSeed.delete()
        try? Validator.delete()

        let password = "The quick brown fox jumps over the lazy white dog."
        XCTAssertNoThrow( try Cryptor.prepare(password: password) )

        var count = 0
        var stop  = false
        let group = DispatchGroup()
        let mutex = NSLock()
        let count_max = 64
        (0..<count_max).forEach { _ in
            Thread.sleep(forTimeInterval: 0.1)
            DispatchQueue.global().async(group: group, qos: .background) {
                mutex.lock()
                count += 1
                let c = count
                mutex.unlock()

                Thread.current.name = "THRD" + String(format:"%02d", c)
                print("thread=\(Thread.current.name!) count=\(c)")

                let sleep = (c % 2 == 0) ? 2.0 : 3.0
                let cryptor = Cryptor()
                var cont    = true
                while cont {
                    do {
                        var plainText   = ""
                        var cipherText  = ""
                        var replainText = ""
                        do {
                            plainText = try RandomData.shared.get(count: 1023, in: .AllCharactersSet)
                        }
                        catch let error {
                            XCTFail("thread=\(Thread.current.name!) count=\(c) exception=\(error)")
                            break
                        }
                        try cryptor.open(password: password) {
                            Thread.sleep(forTimeInterval: sleep)
                            do {
                                cipherText  = try cryptor.encrypt(plain: plainText)
                            }
                            catch CryptorError.notOpened {
                                print("thread=\(Thread.current.name!) count=\(c) notOpend")
                                return
                            }
                            catch let error {
                                XCTFail("thread=\(Thread.current.name!) count=\(c) exception=\(error)")
                                return
                            }

                            Thread.sleep(forTimeInterval: sleep)
                            do {
                                replainText = try cryptor.decrypt(cipher: cipherText)
                            }
                            catch CryptorError.notOpened {
                                print("thread=\(Thread.current.name!) count=\(c) notOpend")
                                return
                            }
                            catch let error {
                                XCTFail("thread=\(Thread.current.name!) count=\(c) exception=\(error)")
                                return
                            }

                            XCTAssertEqual(plainText, replainText)
                            Thread.sleep(forTimeInterval: sleep)
                        }
                    }
                    catch CryptorError.notOpened {
                        print("thread=\(Thread.current.name!) count=\(c) notOpend")
                        break
                    }
                    catch let error {
                        XCTFail("thread=\(Thread.current.name!) count=\(c) exception=\(error)")
                        break
                    }
                    mutex.lock()
                    cont = !stop
                    mutex.unlock()
                }
                print("thread=\(Thread.current.name!) END")
            }
        }
        var c = 0
        while c < count_max {
            Thread.sleep(forTimeInterval: 5.0)
            mutex.lock()
            c = count
            mutex.unlock()
            print("thread count = \(c)")
        }
        print("*** CLOSE ALL ***")
        mutex.lock()
        stop = true
        mutex.unlock()
        XCTAssertNoThrow( try CryptorCore.shared.closeAll() )
        group.wait()
    }

    func testCryptor_async() {
        print("\n\(#function):\(#line)")
        try? CryptorSeed.delete()
        try? Validator.delete()

        let password = "The quick brown fox jumps over the lazy white dog."
        XCTAssertNoThrow( try Cryptor.prepare(password: password) )

        let count_max = 10000
        var count = 0
        let group = DispatchGroup()
        let mutex = NSLock()
        (0..<count_max).forEach { (c) in
            DispatchQueue.global().async(group: group) {
                do {
                    let cryptor = Cryptor()
                    var r: String = ""
                    XCTAssertNoThrow(
                        r = try RandomData.shared.get(count: 1023, in: .AllCharactersSet)
                    )
                    XCTAssertNoThrow(
                        try cryptor.open(password: password) {
                            let plainText   = r
                            let cipherText  = try cryptor.encrypt(plain: plainText)
                            let replainText = try cryptor.decrypt(cipher: cipherText)
                            XCTAssertEqual(plainText, replainText)
                        }
                    )
                    // dummy code to depress a warning
                    if c > count_max {
                        throw CryptorError.unexpected
                    }
                }
                catch let error {
                    print("exception = \(error)")
                }
                mutex.lock()
                count += 1
                print("count = \(count)")
                mutex.unlock()
            }
        }
        group.wait()
        print("count = \(count)")
    }

    func testCryptor_error() {
        print("\n\(#function):\(#line) delete SecItem")
        try? CryptorSeed.delete()
        try? Validator.delete()

        let password       = "The quick brown fox jumps over the lazy white dog."
        let password_wrong = "The quick brown fox jumps over the lazy white dog"
        let cryptor = Cryptor()

        print("\n\(#function):\(#line) not prepared")
        XCTAssertThrowsError( try cryptor.open(password: password_wrong) ) {
            error in
            print("error='\(error.localizedDescription)'")
            XCTAssertEqual(error as! CryptorError, CryptorError.notPrepared)
        }

        print("\n\(#function):\(#line) prepare")
        XCTAssertNoThrow( try Cryptor.prepare(password: password) )

        print("\n\(#function):\(#line) wrong password")
        XCTAssertThrowsError( try cryptor.open(password: password_wrong) ) {
            error in
            print("error='\(error.localizedDescription)'")
            XCTAssertEqual(error as! CryptorError, CryptorError.wrongPassword)
        }

        print("\n\(#function):\(#line) not opened")
        XCTAssertThrowsError( try cryptor.close() ) {
            error in
            print("error='\(error.localizedDescription)'")
            XCTAssertEqual(error as! CryptorError, CryptorError.notOpened)
        }

        print("\n\(#function):\(#line) open")
        XCTAssertNoThrow( try cryptor.open(password: password) )

        print("\n\(#function):\(#line) close")
        XCTAssertNoThrow( try cryptor.close() )

        XCTAssertThrowsError( try cryptor.close() ) {
            error in
            print("error='\(error.localizedDescription)'")
            XCTAssertEqual(error as! CryptorError, CryptorError.notOpened)
        }
    }

    func testCryptor() {
        print("delete SecItem")
        try? CryptorSeed.delete()
        try? Validator.delete()

        print("cryptor.open, cryptor.close")
        var password = "The quick brown fox jumps over the lazy white dog."
        XCTAssertNoThrow( try Cryptor.prepare(password: password) )

        var plainText   = "The plain text. very long long 123456789012345678901234567890"
        var cipherText  = ""
        var replainText = ""
        let cryptor = Cryptor()
        XCTAssertNoThrow( try cryptor.open(password: password) )
        XCTAssertNoThrow( cipherText  = try cryptor.encrypt(plain: plainText) )
        XCTAssertNoThrow( replainText = try cryptor.decrypt(cipher: cipherText) )
        XCTAssertNoThrow( try cryptor.close() )
        print("plainText   =", plainText)
        print("cipherText  =", cipherText)
        print("replainTExt =", replainText)
        XCTAssertEqual(plainText, replainText)

        print("cryptor.open closure Deutsch")
        XCTAssertNoThrow( try cryptor.open(password: password) {
            plainText   = Deutsch
            cipherText  = try! cryptor.encrypt(plain: plainText)
            replainText = try! cryptor.decrypt(cipher: cipherText)
            print("plainText   =", plainText)
            print("cipherText  =", cipherText)
            print("replainTExt =", replainText)
            XCTAssertEqual(plainText, replainText)
            }
        )

        print("cryptor.open closure Japanisch")
        XCTAssertNoThrow( try cryptor.open(password: password) {
            plainText   = Japanisch
            cipherText  = try! cryptor.encrypt(plain: plainText)
            replainText = try! cryptor.decrypt(cipher: cipherText)
            print("plainText   =", plainText)
            print("cipherText  =", cipherText)
            print("replainTExt =", replainText)
            XCTAssertEqual(plainText, replainText)
            }
        )


        print("cryptor.change")
        let newpassword = "pass"
        XCTAssertNoThrow( try cryptor.change(password: password, to: newpassword) )
        password = newpassword

        print("cryptor.open closure Deutsch")
        XCTAssertNoThrow( try cryptor.open(password: password) {
            plainText   = Deutsch
            cipherText  = try! cryptor.encrypt(plain: plainText)
            replainText = try! cryptor.decrypt(cipher: cipherText)
            print("plainText   =", plainText)
            print("cipherText  =", cipherText)
            print("replainTExt =", replainText)
            XCTAssertEqual(plainText, replainText)
            }
        )

        print("cryptor.open closure Japanisch")
        XCTAssertNoThrow( try cryptor.open(password: password) {
            plainText   = Japanisch
            cipherText  = try! cryptor.encrypt(plain: plainText)
            replainText = try! cryptor.decrypt(cipher: cipherText)
            print("----------")
            print("plainText   =", plainText)
            print("cipherText  =", cipherText)
            print("replainTExt =", replainText)
            XCTAssertEqual(plainText, replainText)
            }
        )

        print("cryptor.open closure random strings")
        for c in counts {
            print(c, " ", separator: "", terminator: "")
            var r = ""
            XCTAssertNoThrow(r = try RandomData.shared.get(count: c, in: .AllCharactersSet))
            XCTAssertEqual(r.count, c, "length error r.count=\(r.count) c=\(c)")
            XCTAssertNoThrow( try cryptor.open(password: password) {
                plainText   = r
                cipherText  = try! cryptor.encrypt(plain: plainText)
                replainText = try! cryptor.decrypt(cipher: cipherText)
                print("----------")
                print("plainText   =", plainText)
                print("cipherText  =", cipherText)
                print("replainTExt =", replainText)
                XCTAssertEqual(plainText, replainText)
                }
            )
        }

        print("delete SecItem")
        try? CryptorSeed.delete()
        try? Validator.delete()
    }

    func testCypherCharacterSet() {
        print("CypherCharacterSet All Characters")
        var i: UInt32 = 1
        var chars = ""
        for c in CypherCharacterSet.iterator {
            let str = c.string
            let dsc = c.description
            print(String(format:"%08x", c.rawValue), str, dsc, separator: " : ")
            XCTAssertEqual(c.rawValue, i)
            XCTAssertFalse(str.uppercased().contains("UNKNOWN"))
            XCTAssertFalse(dsc.uppercased().contains("UNKNOWN"))
            i <<= 1
            chars += c.string
        }
        print()
        let chars_sorted = chars.unicodeScalars.sorted()
        print("CypherCharacterSet all characters = \(chars_sorted)")
        XCTAssertEqual(chars_sorted, allChars.unicodeScalars.sorted())

        print("CypherCharacterSet Summation")
        var s: CypherCharacterSet = []
        for c in CypherCharacterSet.iterator {
            s.insert(c)
            let str = s.string
            let dsc = s.description
            print(String(format:"%08x", s.rawValue), str, dsc, separator: " : ")
            XCTAssertFalse(str.uppercased().contains("UNKNOWN"))
            XCTAssertFalse(dsc.uppercased().contains("UNKNOWN"))
        }
        print()
    }

    func testRandomDataGet_distribution() {
        print("RandomData.shared.get -> String Distribution Test")
        for s in cypherCharSet {
            print("Cypher Charcter Set in \(s.string)")
            var counts: [Character: Int] = Dictionary(uniqueKeysWithValues: s.string.map { ($0, 0) })
            let c = counts.count * 10
            var r = ""
            XCTAssertNoThrow(r = try RandomData.shared.get(count: c, in: s))
            r.forEach { counts[$0]! += 1 }
            var count = 1
            counts.keys.sorted().forEach {
                print($0, ":", String(format:"%3d", counts[$0] ?? -1),
                      separator: "", terminator: ((count % 10 == 0) || (count == counts.count) ? "\n" : "   "))
                count += 1
            }
            let sum = counts.reduce(0) { $0 + $1.value }
            print("sum = \(sum)")
            counts.values.forEach {
                XCTAssertNotNil($0)
                XCTAssertNotEqual($0, 0)
            }
            XCTAssertEqual(sum, c)
        }
    }

    func testRandomDataGet() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.

        print("RandomData.shared.get -> Data")
        for c in counts {
            print(c, " ", separator: "", terminator: "")
            var r = Data()
            XCTAssertNoThrow(r = try RandomData.shared.get(count: c))
            XCTAssertEqual(r.count, c, "length error r.count=\(r.count) c=\(c)")
        }
        print()

        print("RandomData.shared.get -> String")
        for c in counts {
            print(c, " ", separator: "", terminator: "")
            for s in cypherCharSet {
                var r = ""
                XCTAssertNoThrow(r = try RandomData.shared.get(count: c, in: s))
                XCTAssertEqual(r.count, c, "length error r.count=\(r.count) c=\(c)")
            }
        }
        print()
    }

    func testRandomDataGet_error() {
        print("RandomData.shared.get -> Data")
        for c in counts_error {
            XCTAssertThrowsError(_ = try RandomData.shared.get(count: c)) {
                error in
                print("error='\(error.localizedDescription)' count=\(c)")
                XCTAssertEqual(error as! RandomDataError, RandomDataError.outOfRange)
            }
        }

        print("RandomData.shared.get -> String")
        for c in counts_error {
            for s in cypherCharSet {
                XCTAssertThrowsError(_ = try RandomData.shared.get(count: c, in: s)) {
                    error in
                    print("error='\(error.localizedDescription)' count=\(c) in=\(s.description)")
                    XCTAssertEqual(error as! RandomDataError, RandomDataError.outOfRange)
                }
            }
        }
    }

    // MARK: Performance Test

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
