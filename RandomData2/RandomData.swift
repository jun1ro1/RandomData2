//
//  RandomData.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/10/07.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation
import Darwin

// MARK: - Structure
/// A set of characters to get a randaom string.
public struct CypherCharacterSet: OptionSet, Hashable {
    // MARK: Properties
    /// The corresponding value of the raw type.
    public let rawValue:  UInt32

    /// The hash value.
    public var hashValue: Int     { return Int(self.rawValue) }

    /// An iterator over the sets of characters.
    public static var iterator: AnyIterator<CypherCharacterSet> {
        var value: CypherCharacterSet.RawValue = 1
        return AnyIterator {
            guard value != CypherCharacterSet.TypeEnd.rawValue else {
                return nil
            }
            let r = CypherCharacterSet(rawValue: value)
            value <<= 1
            return r
        }
    }

    /// Retuns a string representation.
    public var string: String {
        return CypherCharacterSet.iterator.flatMap {
            self.contains($0) ? $0.tostr : nil
            }.joined()
    }

    /// Retuns a description.
    public var description: String {
        var val = self
        var strArray: [String] = []

        // 1st: standard character set
        let standardSets = [
            CypherCharacterSet.DecimalDigits: "0-9",
            CypherCharacterSet.UppercaseLatinAlphabets: "A-Z",
            CypherCharacterSet.LowercaseLatinAlphabets: "a-z",
            CypherCharacterSet.UpperCaseLettersSet: "0-9A-Z",
            CypherCharacterSet.LowerCaseLettersSet: "0-9a-z",
            CypherCharacterSet.AlphaNumericsSet: "0-9A-Za-z",
            CypherCharacterSet.Base64Set: "0-9A-Za-z +/",
            CypherCharacterSet.ArithmeticCharactersSet: "0-9A-Za-z +-*/",
            CypherCharacterSet.AlphaNumericSymbolsSet: "0-9A-Za-z +-*/= !#$%&?@^_|~"
            ].sorted(by: {$0.key.count > $1.key.count})
        assert(CypherCharacterSet.StandardCharacterSet.count ==  standardSets.count,
               "StandardCharacterSet.count(\(CypherCharacterSet.StandardCharacterSet.count))"
                + " != "
                + "standardSets.count(\(standardSets.count))")
        standardSets.forEach { e in
            if val.contains(e.key) {
                strArray.append(e.value)
                val.remove(e.key)
            }
        }

        // 2nd: other characters
        strArray.append(val.string)

        return strArray.joined(separator: " ")
    }

    // MARK: Initializers
    /// Creates a new instance with the specified raw value.
    public init(rawValue: UInt32) {self.rawValue = rawValue }

    // MARK: Constants
    /// The following constant specifies character sets used with `get(count:in:)`.
    /// Exclamation Mark             "!"
    public static let ExclamationMark         = CypherCharacterSet(rawValue: 0x00000001) // "!"
    /// Quotation Mark               '"'
    public static let QuotationMark           = CypherCharacterSet(rawValue: 0x00000002) // '"'
    /// Number Sign                  "#"
    public static let NumberSign              = CypherCharacterSet(rawValue: 0x00000004) // "#"
    /// Dollar Sign                  "$"
    public static let DollarSign              = CypherCharacterSet(rawValue: 0x00000008) // "$"
    /// Percent Sign                 "%"
    public static let PercentSign             = CypherCharacterSet(rawValue: 0x00000010) // "%"
    /// Ampersand                    "&"
    public static let Ampersand               = CypherCharacterSet(rawValue: 0x00000020) // "&"
    /// Apostrophe                   "'"
    public static let Apostrophe              = CypherCharacterSet(rawValue: 0x00000040) // "'"
    /// Parenthesises                "(", ")"
    public static let Parenthesises           = CypherCharacterSet(rawValue: 0x00000080) // "(", ")"
    /// Asterisk                     "*"
    public static let Asterisk                = CypherCharacterSet(rawValue: 0x00000100) // "*"
    /// Plus Sign                    "+"
    public static let PlusSign                = CypherCharacterSet(rawValue: 0x00000200) // "+"
    /// Comma                        ","
    public static let Comma                   = CypherCharacterSet(rawValue: 0x00000400) // ","
    /// Hyphen Minus                 "-"
    public static let HyphenMinus             = CypherCharacterSet(rawValue: 0x00000800) // "-"
    /// FullStop                     "."
    public static let FullStop                = CypherCharacterSet(rawValue: 0x00001000) // "."
    /// Solidus                      "/"
    public static let Solidus                 = CypherCharacterSet(rawValue: 0x00002000) // "/"
    /// Decimal Digits               "0".."9"
    public static let DecimalDigits           = CypherCharacterSet(rawValue: 0x00004000) // "0".."9"
    /// Colon                        ":"
    public static let Colon                   = CypherCharacterSet(rawValue: 0x00008000) // ":"
    /// Semicolon                    ";"
    public static let Semicolon               = CypherCharacterSet(rawValue: 0x00010000) // ";"
    /// Less an dGreater than Signs  "<", ">"
    public static let LessAndGreaterThanSigns = CypherCharacterSet(rawValue: 0x00020000) // "<", ">"
    /// Equals Sign                  "="
    public static let EqualsSign              = CypherCharacterSet(rawValue: 0x00040000) // "="
    /// Question Mark                "?"
    public static let QuestionMark            = CypherCharacterSet(rawValue: 0x00080000) // "?"
    /// Commercial At                "@"
    public static let CommercialAt            = CypherCharacterSet(rawValue: 0x00100000) // "@"
    /// UppercaseLatin Alphabets     "A".."Z"
    public static let UppercaseLatinAlphabets = CypherCharacterSet(rawValue: 0x00200000) // "A".."Z"
    /// Square Brackets              "[", "]"
    public static let SquareBrackets          = CypherCharacterSet(rawValue: 0x00400000) // "[", "]"
    /// Reverse Solidus              "\"
    public static let ReverseSolidus          = CypherCharacterSet(rawValue: 0x00800000) // "\"
    /// Circumflex Accent            "^"
    public static let CircumflexAccent        = CypherCharacterSet(rawValue: 0x01000000) // "^"
    /// Low Line                     "_"
    public static let LowLine                 = CypherCharacterSet(rawValue: 0x02000000) // "_"
    /// Grave Accent                 "`"
    public static let GraveAccent             = CypherCharacterSet(rawValue: 0x04000000) // "`"
    /// Lowercase Latin Alphabets     "a".."z"
    public static let LowercaseLatinAlphabets = CypherCharacterSet(rawValue: 0x08000000) // "a".."z"
    /// Curly Brackets               "{", "}"
    public static let CurlyBrackets           = CypherCharacterSet(rawValue: 0x10000000) // "{", "}"
    /// Vertica Line                 "|"
    public static let VerticalLine            = CypherCharacterSet(rawValue: 0x20000000) // "|"
    /// Tilde                        "~"
    public static let Tilde                   = CypherCharacterSet(rawValue: 0x40000000) // "~"
    /// Type End: A sentinel name
    public static let TypeEnd                 = CypherCharacterSet(rawValue: 0x80000000) // Type End

    /// Upper case letters character set: "0".."9", "A".."Z"
    public static let UpperCaseLettersSet:     CypherCharacterSet =
        [.DecimalDigits, .UppercaseLatinAlphabets]
    /// Lower case letters character set: "0".."9", "a".."z"
    public static let LowerCaseLettersSet:     CypherCharacterSet =
        [.DecimalDigits, .LowercaseLatinAlphabets]
    /// Alpha Numerics character set: "0".."9", "A".."Z", "a".."z"
    public static let AlphaNumericsSet:        CypherCharacterSet = [.DecimalDigits, .UppercaseLatinAlphabets, .LowercaseLatinAlphabets] // 0..9 A-Za-z
    /// BASE64 character set: "0".."9", "A".."Z", "+", "/"
    public static let Base64Set:               CypherCharacterSet =
        [.AlphaNumericsSet, .PlusSign, .Solidus] // 0..9 A-Za-z + /
    /// Arithmetic character set: "0".."9", "A".."Z", "+", "-", "*", "/"
    public static let ArithmeticCharactersSet: CypherCharacterSet = [.AlphaNumericsSet, .PlusSign, .HyphenMinus, .Asterisk, .Solidus]
    /// Alpha Numerics and Symbols character set
    public static let AlphaNumericSymbolsSet:  CypherCharacterSet = [
        .AlphaNumericsSet,
        .ExclamationMark,
        .NumberSign,
        .DollarSign,
        .PercentSign,
        .Ampersand,
        .Asterisk,
        .PlusSign,
        .HyphenMinus,
        .Solidus,
        .DecimalDigits,
        .EqualsSign,
        .QuestionMark,
        .CommercialAt,
        .CircumflexAccent,
        .LowLine,
        .VerticalLine,
        .Tilde
    ]
    /// All character set
    public static let AllCharactersSet =
        CypherCharacterSet(rawValue: CypherCharacterSet.TypeEnd.rawValue - 1)
    public static let StandardCharacterSet = [
        DecimalDigits,
        UppercaseLatinAlphabets,
        LowercaseLatinAlphabets,
        UpperCaseLettersSet,
        LowerCaseLettersSet,
        AlphaNumericsSet,
        Base64Set,
        ArithmeticCharactersSet,
        AlphaNumericSymbolsSet,
    ]

    fileprivate var count: Int {
        // count bits whose value is "1"
        return self.makeIterator().map {_ in 1}.reduce(0) {$0 + $1}
    }

    fileprivate var tostr: String {
        let s: String
        switch self {
        case .ExclamationMark:         s = "!"
        case .QuotationMark:           s = "\""
        case .NumberSign:              s = "#"
        case .DollarSign:              s = "$"
        case .PercentSign:             s = "%"
        case .Ampersand:               s = "&"
        case .Apostrophe:              s = "'"
        case .Parenthesises:           s = "()"
        case .Asterisk:                s = "*"
        case .PlusSign:                s = "+"
        case .Comma:                   s = ","
        case .HyphenMinus:             s = "-"
        case .FullStop:                s = "."
        case .Solidus:                 s = "/"
        case .DecimalDigits:           s = "0123456789"
        case .Colon:                   s = ":"
        case .Semicolon:               s = ";"
        case .LessAndGreaterThanSigns: s = "<>"
        case .EqualsSign:              s = "="
        case .QuestionMark:            s = "?"
        case .CommercialAt:            s = "@"
        case .UppercaseLatinAlphabets: s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        case .SquareBrackets:          s = "[]"
        case .ReverseSolidus:          s = "\\"
        case .CircumflexAccent:        s = "^"
        case .LowLine:                 s = "_"
        case .GraveAccent:             s = "`"
        case .LowercaseLatinAlphabets: s = "abcdefghijklmnopqrstuvwxyz"
        case .CurlyBrackets:           s = "{}"
        case .VerticalLine:            s = "|"
        case .Tilde:                   s = "~"
        default:                       s = "UNKNOWN rawValue=\(self.rawValue) "
        }
        return s
    }

    // MARK: Methods
    /// Returns an iterator over the sets of characters.
    public func makeIterator() -> AnyIterator<CypherCharacterSet> {
        var bit: UInt32 = 1
        return AnyIterator {
            while bit < CypherCharacterSet.TypeEnd.rawValue &&
                !self.contains(CypherCharacterSet(rawValue: bit)) {
                    bit <<= 1
            }
            guard bit < CypherCharacterSet.TypeEnd.rawValue else {
                return nil
            }
            let r = CypherCharacterSet(rawValue: bit)
            bit <<= 1
            return r
        }
    }
}

/// Errors that `RandomData` functions return
///
/// - outOfRange: Parameter `count` is less than 1 or greater than `COUNT_MAX`.
/// - unexpected: An unexpected error occurrs.
/// - OSError: OS API returns an error.
enum RandomDataError: Error {
    case outOfRange
    case unexpected
    case OSError(error: OSStatus)
}

// https://stackoverflow.com/questions/39176196/how-to-provide-a-localized-description-with-an-error-type-in-swift
extension RandomDataError: LocalizedError {
    /// Returns a description of the error.
    public var errorDescription: String?  {
        switch self {
        case .outOfRange:
            return "Out of Range"
        case .unexpected:
            return "Unexpected Error"
        case .OSError(let error):
            return "SecRandomCopyBytes Error(\(error))"
        }
    }
}

// https://stackoverflow.com/questions/39972512/cannot-invoke-xctassertequal-with-an-argument-list-errortype-xmpperror
extension RandomDataError: Equatable {
    /// Returns a Boolean value indicating whether two values are equal.
    ///
    /// - Parameters:
    ///   - lhs: A left hand side expression.
    ///   - rhs: A right hand side expression.
    /// - Returns: `True` if `lhs` equals `rhs`, otherwise `false`.
    static func == (lhs: RandomDataError, rhs: RandomDataError) -> Bool {
        switch (lhs, rhs) {
        case (.outOfRange, .outOfRange),
             (.unexpected, .unexpected):
            return true
        case (.OSError(let error1), .OSError(let error2)):
            return error1 == error2
        default:
            return false
        }
    }
}

// MARK: - Class
/// Gets a random value as a type `Data` or `String`.
class RandomData {
    // MARK: Properties
    /// Returns a shared singleton object.    
    static let shared    = RandomData()

    // MARK: Constants
    /// Maximum value for the parameter `count`
    static let COUNT_MAX = 1024

    // MARK: Methods
    /// Get a random data as type `Data` whose size is `count`.
    ///
    /// - Parameter count: returned data size in bytes.
    /// - Returns: a random data as a type `Data`.
    /// - Throws: OSError
    func get(count: Int) throws -> Data {
        guard case 1...RandomData.COUNT_MAX = count else {
            throw RandomDataError.outOfRange
        }
        
        // http://blog.sarabande.jp/post/92199466318
        // allocate zeroed memory area whose size is "count"
        var data = Data(count: count)
        
        // generate a random data and write to the buffer
        var error: OSStatus = errSecSuccess
        data.withUnsafeMutableBytes { bytes in
            error = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
        }
        guard error == errSecSuccess else {
            throw RandomDataError.OSError(error: error)
        }
        return data
    }
    
    ///  Get a random data as a type `String` whose size is `count`.
    ///
    /// - Parameter count: Returned string size in bytes.
    /// - Parameter in: A set of characters to get a randaom string.
    /// - Returns: A random data as a type `String`.
    /// - Throws: unexpected, OSError
    func get(count: Int, in charSet: CypherCharacterSet) throws -> String {
        guard case 1...RandomData.COUNT_MAX = count else {
            throw RandomDataError.outOfRange
        }
        
        var charArray: [Character] = charSet.string.map { $0 }
        let charCount = charArray.count
        let indexTotalCount: Int = {
            var b = 1
            var n = 0 // n bits are needed to represent charCount
            while b < charCount {
                b <<= 1
                n +=  1
            }
            return (n * count + 7) / 8  // how many bytes are needed to represent charArray
        }()
        
        var string = ""
        string.reserveCapacity(count)
        while string.count < count {
            let indexCount = min(indexTotalCount, RandomData.COUNT_MAX)
            // RandomData.get generates count bytes random data
            // calculate the enough size of random data

            let rand = try self.get(count: indexCount)

            // let rand = Data(count: indexCount) // when DEBUG
            let indecies = rand.als(radix: UInt8(charCount))

            let str = String( indecies.map { charArray[Int($0)] } )
            guard str.count > 0 else {
                assertionFailure()
                throw RandomDataError.unexpected
            }
            string  += str
        }
        if string.count > count {
            string.removeLast(string.count - count) // adjust length
        }
        return string
    }
}

// https://qiita.com/masanori-inukai/items/663e23f2390bf52fcffd
