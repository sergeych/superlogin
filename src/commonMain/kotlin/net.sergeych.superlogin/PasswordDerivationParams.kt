package net.sergeych.superlogin

import kotlinx.serialization.Serializable
import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.Passwords
import net.sergeych.unikrypto.SymmetricKey
import kotlin.random.Random

/**
 * Common structure to keep PBKDF2 params to safely generate keys
 * and a method to derive password accordingly.
 */
@Serializable
data class PasswordDerivationParams(
    val rounds: Int = 15000,
    val algorithm: HashAlgorithm = HashAlgorithm.SHA3_256,
    val salt: ByteArray = Random.nextBytes(32),
    ) {

    /**
     * Derive one or more keys in cryptographically-independent manner
     * @param password password to derive keys from
     * @param amount deisred number of keys (all of them will be mathematically and cryptographically independent)
     * @return list of generated symmetric keys (with a proper ids that allow independent derivation later)
     */
    suspend fun derive(password: String,amount: Int = 1): List<SymmetricKey> {
        return Passwords.deriveKeys(password, amount, rounds, algorithm, salt, Passwords.KeyIdAlgorithm.Independent)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PasswordDerivationParams

        if (rounds != other.rounds) return false
        if (algorithm != other.algorithm) return false
        if (!salt.contentEquals(other.salt)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rounds
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + salt.contentHashCode()
        return result
    }
}