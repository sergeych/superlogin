package net.sergeych.superlogin.server

import kotlinx.serialization.Serializable
import net.sergeych.unikrypto.PrivateKey
import net.sergeych.unikrypto.SymmetricKey

/**
 * The base payload class for superlogin dance, it contains basic information
 * needed for an average superlogin system:
 *
 * - login (whatever string, say, email)
 * - login private key (used only to sign in to a service)
 * - storage key (used to safely keep stored data)
 */
@Serializable
data class SuperloginRestoreAccessPayload(
    val login: String,
    val loginPrivateKey: PrivateKey,
    val dataStorageKey: SymmetricKey
) {
}