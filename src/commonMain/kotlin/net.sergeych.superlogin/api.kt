package net.sergeych.superlogin

import kotlinx.serialization.Serializable
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.WithAdapter
import net.sergeych.unikrypto.PublicKey


@Serializable
data class RegistrationArgs(
    val loginName: String,
    val loginId: ByteArray,
    val loginPublicKey: PublicKey,
    val derivationParams: PasswordDerivationParams,
    val restoreId: ByteArray,
    val restoreData: ByteArray
)

@Serializable
sealed class AuthenticationResult {
    @Serializable
    data class Success(
        val loginToken: ByteArray,
    ): AuthenticationResult()

    @Serializable
    object LoginUnavailable: AuthenticationResult()

    @Serializable
    object RestoreIdUnavailable: AuthenticationResult()
}

@Serializable
data class LoginArgs(
    val loginId: ByteArray,
    val packedSignedRecord: ByteArray
)

@Serializable
data class LoginData(
    val encryptedPrivateKey: ByteArray,
    val loginNonce: ByteArray
)

class SuperloginServerApi<T: WithAdapter> : CommandHost<T>() {

    val registerUser by command<RegistrationArgs,AuthenticationResult>()
    val loginUserByToken by command<ByteArray,AuthenticationResult>()

    val requestUserLoginParams by command<String,PasswordDerivationParams>()


     /**
     * Get resstoreData by restoreId: password reset procedure start.
     */
    val requestUserLogin by command<ByteArray,ByteArray>()
//    val performLogin by command<LoginArgs
}