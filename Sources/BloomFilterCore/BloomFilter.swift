import Foundation

/// A Bloom filter implementation using FNV-1a and MurmurHash3 with double hashing
public final class BloomFilter: @unchecked Sendable, CustomStringConvertible, Codable {
    private var bitArray: Data
    private let numberOfBits: Int
    private let numberOfHashes: Int
    private let falsePositiveTolerance: Double
    private let numberOfItems: Int
    private let murmurSeed: UInt32

    enum CodingKeys: String, CodingKey {
        case itemCount
        case falsePositiveTolerance
        case murmurSeed
        case bitCount
        case byteCount
        case hashCount
        case data
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(numberOfItems, forKey: .itemCount)
        try container.encode(falsePositiveTolerance, forKey: .falsePositiveTolerance)
        try container.encode(murmurSeed, forKey: .murmurSeed)
        try container.encode(UInt32(numberOfBits), forKey: .bitCount)
        try container.encode((numberOfBits + 7) / 8, forKey: .byteCount)
        try container.encode(UInt32(numberOfHashes), forKey: .hashCount)
        try container.encode(bitArray, forKey: .data)
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let itemCount = try container.decode(Int.self, forKey: .itemCount)
        let fp = try container.decode(Double.self, forKey: .falsePositiveTolerance)
        let seed = try container.decode(UInt32.self, forKey: .murmurSeed)
        let bitsU = try container.decode(UInt32.self, forKey: .bitCount)
        _ = try container.decode(Int.self, forKey: .byteCount)
        let hashesU = try container.decode(UInt32.self, forKey: .hashCount)
        let data = try container.decode(Data.self, forKey: .data)
        self.init(
            data: data,
            falsePositiveTolerance: fp,
            numberOfItems: itemCount,
            numberOfBits: Int(bitsU),
            numberOfHashes: Int(hashesU),
            murmurSeed: seed)
    }

    // MARK: - Hash Functions

    /// 32-bit FNV-1a hash function
    private func fnv1a(_ data: String) -> UInt32 {
        let fnvPrime: UInt32 = 0x0100_0193
        let fnvOffsetBasis: UInt32 = 0x811c9dc5

        var hash = fnvOffsetBasis
        for byte in data.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* fnvPrime
        }
        return hash
    }

    /// 32-bit MurmurHash3 hash function
    private func murmurHash3(_ data: String, seed: UInt32) -> UInt32 {
        let murmurConstant1: UInt32 = 0xcc9e2d51
        let murmurConstant2: UInt32 = 0x1b87_3593
        let rotationBits1: UInt32 = 15
        let rotationBits2: UInt32 = 13
        let multiplier: UInt32 = 5
        let additionConstant: UInt32 = 0xe6546b64

        var hashValue = seed
        let inputBytes = Array(data.utf8)
        let dataLength = inputBytes.count

        let numberOfChunks = dataLength / 4
        for chunkIndex in 0..<numberOfChunks {
            let startIndex = chunkIndex * 4
            var chunkValue: UInt32 = 0
            chunkValue |= UInt32(inputBytes[startIndex])
            chunkValue |= UInt32(inputBytes[startIndex + 1]) << 8
            chunkValue |= UInt32(inputBytes[startIndex + 2]) << 16
            chunkValue |= UInt32(inputBytes[startIndex + 3]) << 24

            chunkValue = chunkValue &* murmurConstant1
            chunkValue = (chunkValue << rotationBits1) | (chunkValue >> (32 - rotationBits1))
            chunkValue = chunkValue &* murmurConstant2

            hashValue ^= chunkValue
            hashValue = ((hashValue << rotationBits2) | (hashValue >> (32 - rotationBits2)))
            hashValue = hashValue &* multiplier &+ additionConstant
        }

        let remainingBytes = dataLength % 4
        if remainingBytes > 0 {
            var remainderValue: UInt32 = 0
            let remainderStartIndex = numberOfChunks * 4

            if remainingBytes >= 3 {
                remainderValue |= UInt32(inputBytes[remainderStartIndex + 2]) << 16
            }
            if remainingBytes >= 2 {
                remainderValue |= UInt32(inputBytes[remainderStartIndex + 1]) << 8
            }
            if remainingBytes >= 1 {
                remainderValue |= UInt32(inputBytes[remainderStartIndex])
            }

            remainderValue = remainderValue &* murmurConstant1
            remainderValue =
                (remainderValue << rotationBits1) | (remainderValue >> (32 - rotationBits1))
            remainderValue = remainderValue &* murmurConstant2
            hashValue ^= remainderValue
        }

        hashValue ^= UInt32(dataLength)
        hashValue ^= hashValue >> 16
        hashValue = hashValue &* 0x85ebca6b
        hashValue ^= hashValue >> 13
        hashValue = hashValue &* 0xc2b2ae35
        hashValue ^= hashValue >> 16

        return hashValue
    }

    // MARK: - Double Hashing

    private func getHashIndices(for item: String) -> [Int] {
        let hash1 = fnv1a(item)
        let hash2 = murmurHash3(item, seed: murmurSeed)

        var indices: [Int] = []
        for i in 0..<numberOfHashes {
            let index = Int((hash1 &+ UInt32(i) &* hash2) % UInt32(numberOfBits))
            indices.append(index)
        }
        return indices
    }

    // MARK: - Bit Operations

    private func setBit(at index: Int) {
        let byteIndex = index / 8
        let bitIndex = index % 8

        if byteIndex < bitArray.count {
            bitArray[byteIndex] |= (1 << bitIndex)
        }
    }

    private func isBitSet(at index: Int) -> Bool {
        let byteIndex = index / 8
        let bitIndex = index % 8

        guard byteIndex < bitArray.count else { return false }
        return (bitArray[byteIndex] & (1 << bitIndex)) != 0
    }

    // MARK: - Initializers

    public init(
        items: [String],
        falsePositiveTolerance: Double = 0.001,
        murmurSeed: UInt32 = 0x9747b28c
    ) {
        precondition(
            falsePositiveTolerance > 0.0 && falsePositiveTolerance < 1.0,
            "False positive tolerance must be between 0.0 and 1.0 (exclusive)"
        )
        precondition(!items.isEmpty, "Items array must not be empty")

        self.numberOfItems = items.count
        self.falsePositiveTolerance = falsePositiveTolerance
        self.murmurSeed = murmurSeed

        let n = Double(numberOfItems)
        let p = falsePositiveTolerance
        let bitsCalculation = -n * log(p) / (log(2) * log(2))

        self.numberOfBits = max(1, Int(ceil(bitsCalculation)))

        let hashesCalculation = (Double(numberOfBits) / n) * log(2)
        self.numberOfHashes = max(1, Int(ceil(hashesCalculation)))

        let byteCount = (numberOfBits + 7) / 8
        self.bitArray = Data(count: byteCount)

        for item in items {
            add(item)
        }
    }

    public init(
        data: Data,
        falsePositiveTolerance: Double,
        numberOfItems: Int,
        numberOfBits: Int,
        numberOfHashes: Int,
        murmurSeed: UInt32
    ) {
        precondition(
            falsePositiveTolerance > 0.0 && falsePositiveTolerance < 1.0,
            "False positive tolerance must be between 0.0 and 1.0 (exclusive)"
        )
        precondition(numberOfItems >= 0, "Number of items must be non-negative")
        precondition(!data.isEmpty, "Data cannot be empty")

        self.bitArray = data
        self.falsePositiveTolerance = falsePositiveTolerance
        self.numberOfItems = numberOfItems
        self.murmurSeed = murmurSeed
        self.numberOfBits = numberOfBits
        self.numberOfHashes = numberOfHashes
    }

    public init(
        numberOfBits: Int,
        numberOfHashes: Int,
        numberOfItems: Int,
        falsePositiveTolerance: Double,
        murmurSeed: UInt32
    ) {
        precondition(numberOfBits > 0, "Number of bits must be positive")
        precondition(numberOfHashes > 0, "Number of hashes must be positive")
        precondition(numberOfItems >= 0, "Number of items must be non-negative")
        precondition(
            falsePositiveTolerance > 0.0 && falsePositiveTolerance < 1.0,
            "False positive tolerance must be between 0.0 and 1.0 (exclusive)"
        )

        self.numberOfBits = numberOfBits
        self.numberOfHashes = numberOfHashes
        self.numberOfItems = numberOfItems
        self.falsePositiveTolerance = falsePositiveTolerance
        self.murmurSeed = murmurSeed

        let byteCount = (numberOfBits + 7) / 8
        self.bitArray = Data(count: byteCount)
    }

    // MARK: - Public Methods

    public func add(_ item: String) {
        let indices = getHashIndices(for: item)
        for index in indices {
            setBit(at: index)
        }
    }

    public func contains(_ item: String) -> Bool {
        let indices = getHashIndices(for: item)
        for index in indices where !isBitSet(at: index) {
            return false
        }
        return true
    }

    public func getData() -> Data {
        bitArray
    }

    public func getNumberOfBits() -> Int {
        numberOfBits
    }

    public func getNumberOfHashes() -> Int {
        numberOfHashes
    }

    public func getNumberOfItems() -> Int {
        numberOfItems
    }

    public func getFalsePositiveTolerance() -> Double {
        falsePositiveTolerance
    }

    public func getMurmurSeed() -> UInt32 {
        murmurSeed
    }

    public var description: String {
        var result = "BloomFilter {\n"

        result += "  numberOfBits: \(numberOfBits)\n"
        result += "  numberOfHashes: \(numberOfHashes)\n"
        result += "  falsePositiveTolerance: \(falsePositiveTolerance)\n"
        result += "  numberOfItems: \(numberOfItems)\n"
        result += "  murmurSeed: 0x\(String(murmurSeed, radix: 16, uppercase: true))\n"
        result += "  bitArray.count: \(bitArray.count) bytes\n"

        result += "  bitArray data:\n"
        result += "    Bloom Filter Bits (Total: \(bitArray.count * 8) bits)\n"
        result += "    " + String(repeating: "=", count: 50) + "\n"

        var bitIndex = 0
        for (byteOffset, byte) in bitArray.enumerated() {
            if bitIndex % 64 == 0 {
                result +=
                    "\n    Byte \(bitIndex / 8)-\(min((bitIndex / 8) + 7, bitArray.count - 1)):\n    "
            }

            let binaryString =
                String(repeating: "0", count: max(0, 8 - String(byte, radix: 2).count))
                + String(byte, radix: 2)

            let spacedBits = binaryString.enumerated()
                .map { index, bit in
                    index == 4 ? " \(bit)" : String(bit)
                }
                .joined()

            result += spacedBits

            if (bitIndex + 8) % 64 != 0 && byteOffset < bitArray.count - 1 {
                result += " "
            }

            bitIndex += 8

            if bitIndex % 64 == 0 {
                result += "\n"
            }
        }

        if bitIndex % 64 != 0 {
            result += "\n"
        }

        result += "\n    Summary:\n"
        let totalBits = bitArray.count * 8
        let setBits = bitArray.reduce(0) { count, byte in
            count + byte.nonzeroBitCount
        }
        let fillRatio = totalBits > 0 ? Double(setBits) / Double(totalBits) : 0.0

        result += "    Total bits: \(totalBits)\n"
        result += "    Set bits: \(setBits)\n"
        result += "    Fill ratio: \(String(format: "%.2f", fillRatio * 100))%\n"

        result += "  \n"
        result += "  Statistics:\n"
        result +=
            "    Estimated false positive rate: \(String(format: "%.6f", pow(fillRatio, Double(numberOfHashes))))\n"
        result += "}"

        return result
    }
}
