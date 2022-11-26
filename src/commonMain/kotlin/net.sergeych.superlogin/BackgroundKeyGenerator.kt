package net.sergeych.superlogin

import kotlinx.coroutines.Deferred
import kotlinx.datetime.Clock
import net.sergeych.mp_tools.globalDefer
import net.sergeych.unikrypto.*
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds


object BackgroundKeyGenerator {

    const val DefaultStrength = 4096

    class EntropyLowException(current: Int,requested: Int) : Exception("entropy level is below requested ($current/$requested)")

    private var keyStrength = DefaultStrength
    private var nextKey: Deferred<PrivateKey>? = null

    var entropy = 0
        private set
    private val hashAlgorithm = HashAlgorithm.SHA3_256
    private var entropyHash: ByteArray? = null


    fun startPrivateKeyGeneration(strength: Int = DefaultStrength) {
        if (keyStrength != strength) {
            nextKey?.cancel()
            nextKey = null
            keyStrength = strength
        }
        nextKey = globalDefer { AsymmetricKeys.generate(keyStrength) }
    }

    fun getKeyAsync(strength: Int = DefaultStrength, startNext: Boolean = true): Deferred<PrivateKey> {
        if (keyStrength != strength || nextKey == null)
            startPrivateKeyGeneration(strength)
        return nextKey!!.also {
            nextKey = null
            if (startNext) startPrivateKeyGeneration(strength)
        }
    }

    suspend fun getPrivateKey(strength: Int = DefaultStrength): PrivateKey = getKeyAsync(strength).await()

    fun addEntropyString(s: String, count: Int = 10) {
        entropy += count
        entropyHash = entropyHash?.let { hashAlgorithm.digest(s.encodeToByteArray(), it) } ?: hashAlgorithm.digest(s)
    }

    fun addEntropyPointerMove(x: Int, y: Int) {
        addEntropyString("x:$x,y:$y")
    }

    private var lastTime = Clock.System.now()

    fun addEntropyKey(key: String?) {
        val t = Clock.System.now()
        val e = (if (t - lastTime < 1.seconds) 3 else 10) + (key?.length ?: 0) * 4
        addEntropyString("${Clock.System.now().nanosecondsOfSecond}$key", e)
        lastTime = t
    }

    fun addEntropyTimestamp() {
        addEntropyKey(null)
    }

    fun randomSymmetricKey(minEntropy: Int = 0): SymmetricKey {
        return SymmetricKeys.create(randomBytes(32, minEntropy), BytesId.random()).also {
            entropy = 0
            addEntropyTimestamp()
        }
    }

    fun randomBytes(length: Int,minEntropy: Int): ByteArray {
        addEntropyTimestamp()
        entropyHash?.let {
            if (minEntropy <= entropy) {
                entropy -= minEntropy
                return randomBytes(length, it)
            }
        }
        if( minEntropy == 0 ) {
            return randomBytes(length, null)
        }
        throw EntropyLowException(minEntropy, entropy)
    }

    fun randomBytes(length: Int, IV: ByteArray? = null): ByteArray {
        var result = byteArrayOf()
        var iv2 = IV ?: Random.nextBytes(32)
        entropyHash?.let { iv2 += it }
        var seed = HashAlgorithm.SHA3_384.digest(Random.nextBytes(48), iv2)
        while (result.size < length) {
            if (result.size + seed.size <= length)
                result += seed
            else
                result += seed.sliceArray(0 until (length - result.size))
            seed = HashAlgorithm.SHA3_384.digest(Random.nextBytes(48), seed)
        }
        return result
    }

}