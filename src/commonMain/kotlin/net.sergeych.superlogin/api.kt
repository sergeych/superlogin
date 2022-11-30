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
    val restoreData: ByteArray,
    val extraData: ByteArray? = null
)

@Serializable
sealed class AuthenticationResult {
    @Serializable
    data class Success(
        val loginName: String,
        val loginToken: ByteArray,
        val applicationData: ByteArray?
    ): AuthenticationResult()

    @Serializable
    object LoginUnavailable: AuthenticationResult()

    @Serializable
    object LoginIdUnavailable: AuthenticationResult()

    @Serializable
    object RestoreIdUnavailable: AuthenticationResult()
}

@Serializable
data class RequestLoginDataArgs(
    val loginName: String,
    val loginId: ByteArray,
)

@Serializable
data class RequestLoginDataResult(
    val packedACO: ByteArray,
    val nonce: ByteArray
)

@Serializable
data class LoginByPasswordPayload(
    val loginName: String
)

class SuperloginServerApi<T: WithAdapter> : CommandHost<T>() {

    val slGetNonce by command<Unit,ByteArray>()
    val slRegister by command<ByteArray,AuthenticationResult>()
    val slLogout by command<Unit,Unit>()
    val slLoginByToken by command<ByteArray,AuthenticationResult>()

    val slRequestDerivationParams by command<String,PasswordDerivationParams>()
    val slRequestLoginData by command<RequestLoginDataArgs,RequestLoginDataResult>()
    val slLoginByKey by command<ByteArray,AuthenticationResult>()


     /**
     * Get resstoreData by restoreId: password reset procedure start.
     */
//    val requestUserLogin by command<ByteArray,ByteArray>()
//    val performLogin by command<LoginArgs
}