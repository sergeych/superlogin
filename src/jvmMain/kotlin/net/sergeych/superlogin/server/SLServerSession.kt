package net.sergeych.superlogin.server

import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.AuthenticationResult
import net.sergeych.superlogin.BackgroundKeyGenerator
import net.sergeych.superlogin.PasswordDerivationParams
import net.sergeych.superlogin.RegistrationArgs
import net.sergeych.superlogin.client.SuperloginData
import net.sergeych.unikrypto.PublicKey

/**
 * The superlogin server session. Please use only [currentLoginName] and [currentLoginToken], the rest could be
 * a subject to change.
 */
abstract class SLServerSession<T> : WithAdapter() {

    val nonce = BackgroundKeyGenerator.randomBytes(32)

    var superloginData: SuperloginData<T>? = null

    val userData: T? get() = superloginData?.data

    val currentLoginToken get() = superloginData?.loginToken

    val currentLoginName: String? get() = superloginData?.loginName

    fun requireLoggedIn() {
        if (currentLoginName == null) throw IllegalStateException("must be logged in")
    }

    fun requireLoggedOut() {
        if (currentLoginName != null) throw IllegalStateException("must be logged out")
    }

    /**
     * Register specified user. The server should check that:
     *
     * - [RegistrationArgs.loginName] is not used, otherwise return [AuthenticationResult.LoginUnavailable]
     * - [RegistrationArgs.loginId] is not used, otherwise return [AuthenticationResult.LoginIdUnavailable]
     * - [RegistrationArgs.restoreId] is not used or return [AuthenticationResult.RestoreIdUnavailable]
     *
     * Then it should save permanently data from `registrationArgs` in a way tha allow fast search (indexed,
     * usually) by `loginName`, `loginId` and `restoreId`, and return [AuthenticationResult.Success] with
     * newly generated random bytes string `loginToken` that would optionally simplify logging in.
     *
     * If the implementation does not provide login token, it should still provide random bytes string
     * to maintain hight security level of the serivce.
     */
    abstract suspend fun register(registrationArgs: RegistrationArgs): AuthenticationResult

    /**
     * Logging out procedure does not need any extra logic unless reuired by application
     * server software. Default implementation does nothing.
     */
    open suspend fun logout() {}

    /**
     * Try to log in using an authentication token, which normally is returned in
     * [AuthenticationResult.Success.loginToken]. If the server implementation
     * does not support login token, don't implement it, use the default implementation.
     *
     * Otherwise, implement login by token and return either [AuthenticationResult.Success]
     * or [AuthenticationResult.LoginUnavailable]. So not return anything else.
     */
    open suspend fun loginByToken(token: ByteArray): AuthenticationResult = AuthenticationResult.LoginUnavailable

    /**
     * Retreive exact password derivation params as were stored by registration.
     * @return derivation params for the login name or null if the name is not known
     */
    abstract suspend fun requestDerivationParams(loginName: String): PasswordDerivationParams?

    /**
     * Override this method, check loginId to match loginName, and of ot os ok, return packed ACO
     * @return packed ACO or null if loginName is wrong, or loginId does not match it.
     */
    abstract suspend fun requestACOByLoginName(loginName: String, loginId: ByteArray): ByteArray?

    /**
     * Implement retrieving ACO object by restoreId. Return found object ot null.
     */
    abstract suspend fun requestACOByRestoreId(restoreId: ByteArray): ByteArray?

    /**
     * Implementation must: find the actual user by loginName and check the publicKey is valid (for example
     * matches stored key id in the database, and return
     * @return [AuthenticationResult.Success]
     */
    abstract suspend fun loginByKey(loginName: String, publicKey: PublicKey): AuthenticationResult

    /**
     * Update access control object (resotre data) to the specified.
     */
    abstract suspend fun updateAccessControlData(
        loginName: String,
        packedACO: ByteArray,
        passwordDerivationParams: PasswordDerivationParams,
        newLoginKey: PublicKey,
        newLoginId: ByteArray
    )
}

inline fun <reified D, T : SLServerSession<D>> T.setSlData(it: AuthenticationResult.Success) {
    superloginData = SuperloginData(it.loginName, it.loginToken, it.applicationData?.decodeBoss<D>())
}
