package net.sergeych.superlogin

import kotlinx.serialization.SerialName
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
    val packedACO: ByteArray,
    val extraData: ByteArray? = null
)

@Serializable
sealed class AuthenticationResult {
    @Serializable
    @SerialName("Success")
    data class Success(
        val loginName: String,
        val loginToken: ByteArray,
        val applicationData: ByteArray?
    ): AuthenticationResult()

    @Serializable
    @SerialName("LoginUnavailable")
    object LoginUnavailable: AuthenticationResult()

    @Serializable
    @SerialName("LoginIdUnavailable")
    object LoginIdUnavailable: AuthenticationResult()

    @Serializable
    @SerialName("RestoreIdUnavailable")
    object RestoreIdUnavailable: AuthenticationResult()
}

@Serializable
class RequestACOByLoginNameArgs(
    val loginName: String,
    val loginId: ByteArray,
)

@Serializable
class RequestACOResult(
    val packedACO: ByteArray,
    val nonce: ByteArray
)

@Serializable
class LoginByPasswordPayload(
    val loginName: String
)

@Serializable
class ChangePasswordArgs(
    val loginName: String,
    val packedSignedRecord: ByteArray
)

@Serializable
class ChangePasswordPayload(
    val packedACO: ByteArray,
    val passwordDerivationParams: PasswordDerivationParams,
    val newLoginKey: PublicKey
)


class SuperloginServerApi<T: WithAdapter> : CommandHost<T>() {

    val slGetNonce by command<Unit,ByteArray>()
    val slRegister by command<ByteArray,AuthenticationResult>()
    val slLogout by command<Unit,Unit>()
    val slLoginByToken by command<ByteArray,AuthenticationResult>()

    val slRequestDerivationParams by command<String,PasswordDerivationParams>()
    val slRequestACOByLoginName by command<RequestACOByLoginNameArgs,RequestACOResult>()
    val slLoginByKey by command<ByteArray,AuthenticationResult>()

    val slRequestACOBySecretId by command<ByteArray,ByteArray>()
    val slChangePasswordAndLogin by command <ChangePasswordArgs,AuthenticationResult>()

    val slSendTestException by command<Unit,Unit>()
}