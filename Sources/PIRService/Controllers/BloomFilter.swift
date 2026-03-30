import Foundation

public enum BloomFilterError: Error {
    case invalidParameters(message: String?)
    case encodingIssue(message: String?)
}

public struct BloomFilter: @unchecked Sendable {
    public let itemCount: Int
    public let falsePositiveTolerance: Double
    public let murmurSeed: UInt32
    public let bitCount: UInt32
    public let byteCount: Int
    public let hashCount: UInt32
    public var data: Data? {
        Data(bits)
    }

    private var bits: Data

    public init(items: [String], falsePositiveTolerance: Double = 0.001) throws {
        try self.init(items: items, falsePositiveTolerance: falsePositiveTolerance, murmurSeed: UInt32.random(in: 0...UInt32.max))
    }

    init(items: [String], falsePositiveTolerance: Double = 0.001, murmurSeed: UInt32) throws {
        let itemCount = items.count
        guard itemCount > 0 else {
            throw BloomFilterError.invalidParameters(message: "items must not be empty")
        }
        guard falsePositiveTolerance > 0.0 && falsePositiveTolerance < 1.0 else {
            throw BloomFilterError.invalidParameters(message: "falsePositiveTolerance must be greater than zero and less than one")
        }

        self.itemCount = itemCount
        self.falsePositiveTolerance = falsePositiveTolerance
        self.murmurSeed = murmurSeed
        bitCount = Self.calculateBitCount(itemCount: itemCount, falsePositiveTolerance: falsePositiveTolerance)
        hashCount = Self.calculateHashCount(itemCount: itemCount, bitCount: bitCount)
        byteCount = Self.calculateByteCount(bitCount: bitCount)
        bits = Data(count: byteCount)

        for item in items {
            try insert(value: item)
        }
    }

    static func calculateBitCount(itemCount: Int, falsePositiveTolerance: Double) -> UInt32 {
        let itemCountD = Double(itemCount)
        return UInt32((ceil(-(itemCountD * log(falsePositiveTolerance) / pow(M_LN2, 2.0)))))
    }

    static func calculateHashCount(itemCount: Int, bitCount: UInt32) -> UInt32 {
        let itemCountD = Double(itemCount)
        let bitCountD = Double(bitCount)
        return UInt32(ceil((bitCountD / itemCountD) * M_LN2))
    }

    static func calculateByteCount(bitCount: UInt32) -> Int {
        Int((bitCount + 7) / 8)
    }

    fileprivate mutating func insert(value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw BloomFilterError.encodingIssue(message: "Unable to encode string '\(value)' to UTF8")
        }

        for count in 0..<hashCount {
            let fnv = data.fnvHash()
            let murmur = data.murmurHash3(seed: murmurSeed)
            let index = Int((fnv &+ count &* murmur) % bitCount)
            bits.setBit(at: index, to: true)
        }
    }
}

extension BloomFilter: Codable, Hashable {
    enum CodingKeys: String, CodingKey {
        case itemCount
        case falsePositiveTolerance
        case murmurSeed
        case bitCount
        case byteCount
        case hashCount
        case bits = "data"
    }
}

extension BloomFilter: CustomStringConvertible {
    public var description: String {
        "<BloomFilter itemCount: \(itemCount), falsePositiveTolerance: \(falsePositiveTolerance), murmurSeed: \(murmurSeed), bitCount: \(bitCount), byteCount: \(byteCount), hashCount: \(hashCount) data bytes: \(bits.count) >"
    }
}

extension Data {
    public mutating func setBit(at index: Int, to value: Bool) {
        let byteIndex = index / 8
        guard byteIndex >= self.startIndex && byteIndex < self.endIndex else {
            return
        }

        let bitPosition = index % 8
        if value {
            self[byteIndex] |= (1 << bitPosition)
        } else {
            self[byteIndex] &= ~(1 << bitPosition)
        }
    }

    public func bit(at index: Int) -> Bool {
        guard index >= 0 && index < count * 8 else {
            return false
        }

        let byteIndex = index / 8
        let bitIndex = index % 8
        let mask = 1 << bitIndex
        return (self[byteIndex] & UInt8(mask)) != 0
    }

    public func fnvHash() -> UInt32 {
        var fnvHash: UInt32 = 0x811c9dc5
        let fnvPrime: UInt32 = 0x01000193
        for byte in self {
            fnvHash = fnvPrime &* (fnvHash ^ UInt32(byte))
        }
        return fnvHash
    }

    public func murmurHash3(seed: UInt32) -> UInt32 {
        let length = self.count
        var hash1 = seed
        let const1: UInt32 = 0xcc9e2d51
        let const2: UInt32 = 0x1b873593

        let nblocks = length / 4
        for index in 0..<nblocks {
            var block: UInt32 = self.block(at: index)
            block &*= const1
            block = block.rotateLeft(15)
            block &*= const2
            hash1 ^= block
            hash1 = hash1.rotateLeft(13)
            hash1 = hash1 &* 5 &+ 0xe6546b64
        }

        var block: UInt32 = 0
        let blockedLength = length / 4 * 4
        let remainingLength = length - blockedLength
        switch remainingLength {
        case 3:
            block ^= UInt32(self[blockedLength + 2]) << 16
            fallthrough
        case 2:
            block ^= UInt32(self[blockedLength + 1]) << 8
            fallthrough
        case 1:
            block ^= UInt32(self[blockedLength])
            block &*= const1
            block = block.rotateLeft(15)
            block &*= const2
            hash1 ^= block
        default:
            break
        }

        hash1 ^= UInt32(length)
        hash1 = hash1.fmix()
        return hash1
    }

    fileprivate func block<T: FixedWidthInteger>(at index: Int) -> T {
        var block: T = 0
        for byteIndex in 0..<MemoryLayout<T>.size {
            block |= T(self[index * MemoryLayout<T>.size + byteIndex]) << (byteIndex * 8)
        }
        return block
    }
}

extension UInt32 {
    fileprivate func rotateLeft(_ bitCount: UInt32) -> UInt32 {
        guard bitCount <= 32 else {
            return self
        }
        return (self << bitCount) | (self >> (32 - bitCount))
    }

    fileprivate func fmix() -> UInt32 {
        var hash = UInt32(self)
        hash ^= hash >> 16
        hash &*= 0x85ebca6b
        hash ^= hash >> 13
        hash &*= 0xc2b2ae35
        hash ^= hash >> 16
        return hash
    }
}
