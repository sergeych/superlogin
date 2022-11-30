package net.sergeych.superlogin

import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.digest

/**
 * Primitive to simplify create and compare salted byte arrays
 */
data class Salted(val salt: ByteArray,val data: ByteArray) {

    val salted = HashAlgorithm.SHA3_256.digest(salt, data)

    fun matches(other: ByteArray): Boolean {
        return Salted(salt, other) == this
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Salted

        if (!salt.contentEquals(other.salt)) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = salt.contentHashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}