package net.sergeych.superlogin.server

import net.sergeych.parsec3.AdapterBuilder
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.*
import net.sergeych.unikrypto.SignedRecord
import kotlin.random.Random

fun randomACOLike(): ByteArray {
    return Random.nextBytes(117)
}
inline fun <reified D, T : SLServerSession<D>, H : CommandHost<T>> AdapterBuilder<T, H>.superloginServer(
    crossinline sessionBuilder: suspend ()->T
) {
    newSession { sessionBuilder() }
    addErrors(SuperloginExceptionsRegistry)
    val a2 = SuperloginServerApi<WithAdapter>()
    on(a2.slGetNonce) { nonce }
    on(a2.slRegister) { packed ->
        requireLoggedOut()
        val ra = SignedRecord.unpack(packed) { sr ->
            if (!(sr.nonce contentEquals nonce))
                throw IllegalArgumentException("wrong signed record nonce")
        }.decode<RegistrationArgs>()

        register(ra).also { rr ->
            if (rr is AuthenticationResult.Success) {
                setSlData(rr)
            }
        }
    }
    on(a2.slLogout) {
        superloginData = null
        logout()
    }
    on(a2.slLoginByToken) { token ->
        requireLoggedOut()
        loginByToken(token).also {
            if (it is AuthenticationResult.Success)
                setSlData(it)
        }
    }
    on(a2.slRequestDerivationParams) { name ->
        // If we don't know this login, we still provide derivatino params to
        // slow down login scanning
        requestDerivationParams(name) ?: PasswordDerivationParams()
    }
    on(a2.slRequestACOByLoginName) { args ->
        requestACOByLoginName(args.loginName, args.loginId)?.let {
            RequestACOResult(it, nonce)
        } ?: RequestACOResult(randomACOLike(), nonce)
    }
    on(a2.slLoginByKey) { packedSR ->
        try {
            // Check key
            val sr = SignedRecord.unpack(packedSR) {
                if (!(it.nonce contentEquals nonce)) throw IllegalArgumentException()
            }
            val loginName: String = sr.decode<LoginByPasswordPayload>().loginName
            loginByKey(loginName, sr.publicKey).also {
                if (it is AuthenticationResult.Success)
                    setSlData(it)
            }
        } catch (x: Exception) {
            // most likely, wrong nonce, less probable bad signature
            AuthenticationResult.LoginUnavailable
        }
    }
    on(a2.slChangePasswordAndLogin) { args ->
        val currentSlData = superloginData
        try {
            val sr = SignedRecord.unpack(args.packedSignedRecord) {
                if (!(it.nonce contentEquals nonce)) throw IllegalArgumentException()
            }
            val payload = sr.decode<ChangePasswordPayload>()
            val loginResult = loginByKey(args.loginName, sr.publicKey)
            if (loginResult is AuthenticationResult.Success) {
                setSlData(loginResult)
                updateAccessControlData(
                    args.loginName,
                    payload.packedACO,
                    payload.passwordDerivationParams,
                    payload.newLoginKey
                )
                println(">> ${loginResult.loginToken} -- !")
            }
            loginResult
        } catch (_: IllegalArgumentException) {
            superloginData = currentSlData
            AuthenticationResult.LoginUnavailable
        } catch (x: Throwable) {
            x.printStackTrace()
            superloginData = currentSlData
            AuthenticationResult.LoginUnavailable
        }
    }
    on(a2.slRequestACOBySecretId) {
        requestACOByRestoreId(it) ?: randomACOLike()
    }
    on(a2.slSendTestException) {
        throw SLInternalException("test")
    }
}

