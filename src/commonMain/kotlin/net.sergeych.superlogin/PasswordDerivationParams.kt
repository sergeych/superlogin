package net.sergeych.superlogin

import kotlinx.serialization.Serializable
import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.Passwords
import net.sergeych.unikrypto.SymmetricKey
import kotlin.random.Random

@Serializable
class PasswordDerivationParams(
    val rounds: Int = 15000,
    val algorithm: HashAlgorithm = HashAlgorithm.SHA3_256,
    val salt: ByteArray = Random.nextBytes(32),
    ) {

    suspend fun derive(password: String,amount: Int = 1): List<SymmetricKey> {
        return Passwords.deriveKeys(password, amount, rounds, algorithm, salt, Passwords.KeyIdAlgorithm.Independent)
    }

}