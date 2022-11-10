package net.sergeych.superlogin

import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.unikrypto.*

/**
 * RestoreKey is a specially constructed highly random string that produces cryptographically
 * independent ID and symmetric key tohether with some tolerance to human typing errors and minimal
 * integrity check to simplify its entry.
 *
 * The restore key is too long to remember, it should better be copied to some safe place.It is intended
 * as a last resort to restore access to something impprtant using [AccessControlObject] object.
 *
 * Construct new instance with [generate], check with [checkSecretIntegrity] and derive key and id
 * with [parse]
 */
class RestoreKey private constructor(
    val restoreId: ByteArray,
    val key: SymmetricKey,
    val secret: String,
) {

    class InvalidSecretException: Exception("secret is not valid")

    companion object {

        /**
         * Remove auxiliary characters from secret
         */
        private fun p(secret: String): String = secret.trim().replace("-", "")

        /**
         * Perform internal integrity check against occasional mistypes. This check does
         * not mean it the key are ok to decrypt anything, just that the secret was not mistyped.
         *
         * This method does not alter key strength which is 136 random bits.
         */
        fun checkSecretIntegrity(secret: String): Boolean {
            return kotlin.runCatching { Safe58.decodeWithCrc(p(secret)) }.isSuccess
        }

        /**
         * Parse the secret (secret key combination) and provide corresponding id and key to
         * find and decrupt [AccessControlObject] object.
         * @return restoreId to restoreKey pair
         * @throws Safe58.InvalidCrcException if the secret is not valid, see [checkSecretIntegrity].
         */
        suspend fun parse(secret: String): Pair<ByteArray, SymmetricKey> {
            // Just ensure secret is valid
            val s = p(secret)
            if( !checkSecretIntegrity(s) ) throw InvalidSecretException()
            return Passwords.deriveKeys(
                s,
                2,
                salt = HashAlgorithm.SHA3_256.digest(s + "RestoreKeySecret"),
                rounds = 1000
            ).let { (a, b) -> a.keyBytes to b }
        }

        /**
         * Generate brand new random secret and return it and parsed id and key.
         */
        suspend fun generate(): RestoreKey {
            val secret = Safe58.encodeWithCrc(BackgroundKeyGenerator.randomBytes(17))
            val (id, key) = parse(secret)
            return RestoreKey(id, key, secret.chunked(5).joinToString("-"))
        }
    }
}