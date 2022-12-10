package net.sergeych.superlogin.client

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.Loggable
import net.sergeych.mp_logger.exception
import net.sergeych.mp_logger.warning
import net.sergeych.mp_tools.globalLaunch
import net.sergeych.parsec3.*
import net.sergeych.superlogin.*
import net.sergeych.superlogin.server.SuperloginRestoreAccessPayload
import net.sergeych.unikrypto.SignedRecord
import kotlin.reflect.KType
import kotlin.reflect.typeOf

/**
 * Application might want to serialize and store updated instances of it in some
 * permanent storage to restore login data also in offline more, and re-login
 * automatically where possible withot asking the password again.
 *
 * Superlogin client _does not store the data itself_ but only notifies client software
 * that it is changed and ought to be updated.
 */
@Serializable
data class SuperloginData<T>(
    val loginName: String,
    val loginToken: ByteArray? = null,
    val data: T? = null,
)


class SuperloginClient<D, S : WithAdapter>(
    private val transport: Parsec3Transport<S>,
    savedData: SuperloginData<D>? = null,
    private val dataType: KType,
    override val exceptionsRegistry: ExceptionsRegistry = ExceptionsRegistry(),
) : Parsec3Transport<S>, Loggable by LogTag("SLCLI") {

    private val _state = MutableStateFlow<LoginState>(
        if (savedData == null) LoginState.LoggedOut
        else LoginState.LoggedIn(savedData)
    )
    val state: StateFlow<LoginState> = _state

    private val _cflow = MutableStateFlow<Boolean>(false)
    override val connectedFlow: StateFlow<Boolean> = _cflow

    private var slData: SuperloginData<D>? = savedData
        set(value) {
            if (field != value) {
                field = value
                if (value == null) {
                    // do actual disconnect work
                    _cflow.value = false
                    _state.value = LoginState.LoggedOut
                } else {
                    val v = _state.value
                    if (v !is LoginState.LoggedIn<*> || v.loginData != value) {
                        _state.value = LoginState.LoggedIn(value)
                        if (!adapterReady.isCompleted) adapterReady.complete(Unit)
                    }
                }
            }
        }

    val applicationData: D?
        get() = (state.value as? LoginState.LoggedIn<D>)?.loginData?.data

    private var adapterReady = CompletableDeferred<Unit>()

    override suspend fun adapter(): Adapter<S> = transport.adapter()
//        do {
//            try {
//                adapterReady.await()
//                return transport.adapter()
//            } catch (x: Throwable) {
//                exception { "failed to get adapter" to x }
//            }
//        } while (true)
//    }

    suspend fun <A, R> call(ca: CommandDescriptor<A, R>, args: A): R = adapter().invokeCommand(ca, args)
    suspend fun <R> call(ca: CommandDescriptor<Unit, R>): R = adapter().invokeCommand(ca)

    private suspend fun <A, R> invoke(ca: CommandDescriptor<A, R>, args: A): R =
        transport.adapter().invokeCommand(ca, args)

    private suspend fun <R> invoke(ca: CommandDescriptor<Unit, R>): R = transport.adapter().invokeCommand(ca)

    private var jobs = listOf<Job>()

    private val serverApi = SuperloginServerApi<WithAdapter>()

    private suspend fun tryRestoreLogin() {
        slData?.loginToken?.let { token ->
            try {
                val ar = transport.adapter().invokeCommand(serverApi.slLoginByToken, token)
                slData = if (ar is AuthenticationResult.Success) {
                    val data: D? = ar.applicationData?.let { BossDecoder.decodeFrom(dataType, it) }
                    SuperloginData(ar.loginName, ar.loginToken, data)
                } else {
                    null
                }
            } catch (t: Throwable) {
                exception { "failed to restore login by token, will retry" to t }
                delay(1500)
                tryRestoreLogin()
            }
        } ?: warning { "tryRestoreLogin is ignored as slData is now null" }
    }

    init {
        transport.registerExceptinos(SuperloginExceptionsRegistry)
        jobs += globalLaunch {
            transport.connectedFlow.collect { on ->
                if (on) tryRestoreLogin()
                else {
                    _cflow.value = false
                }
            }
        }
    }


    override fun close() {
        transport.close()
    }

    override fun reconnect() {
        transport.reconnect()
        if (!adapterReady.isActive) {
            adapterReady.cancel()
            adapterReady = CompletableDeferred()
        }
    }

    private var registration: Registration? = null

    val isLoggedIn get() = state.value.isLoggedIn

    /**
     * Perform registration and login attempt and return the result. It automatically caches and reuses intermediate
     * long-calculated keys so it runs much fatser when called again with the same password.
     *
     * _Client should be in logged-out state!_ Use [logout] as needed
     *
     * If result is [Registration.Result.Success], user state is _logged in_.
     *
     * @throws IllegalStateException if logged in
     */
    suspend fun register(
        loginName: String, password: String, data: D? = null,
        loginKeyStrength: Int = 2048, pbkdfRounds: Int = 15000,
    ): Registration.Result {
        mustBeLoggedOut()
        val rn = registration ?: Registration(transport.adapter(), loginKeyStrength, pbkdfRounds)
            .also { registration = it }
        return rn.registerWithData(loginName, password, extraData = BossEncoder.encode(dataType, data))
            .also { rr ->
                if (rr is Registration.Result.Success) {
                    slData = SuperloginData(loginName, rr.loginToken, extractData(rr.encodedData))
                }
            }
    }

    private fun extractData(rr: ByteArray?): D? = rr?.let { BossDecoder.decodeFrom(dataType, it) }

    private fun mustBeLoggedOut() {
        if (isLoggedIn)
            throw IllegalStateException("please log out first")
    }

    private fun mustBeLoggedIn() {
        if (!isLoggedIn)
            throw IllegalStateException("please log in first")
    }

    suspend fun logout() {
        mustBeLoggedIn()
        invoke(serverApi.slLogout)
        slData = null
    }

    /**
     * Try to log in by specified token, returned by [Registration.Result.Success.loginToken] or
     * [SuperloginData.loginToken] respectively.
     *
     * @return updated login data (and new token value) or null if token is not (or not anymore)
     *         available for logging in.
     */
    suspend fun loginByToken(token: ByteArray): SuperloginData<D>? {
        mustBeLoggedOut()
        val r = invoke(serverApi.slLoginByToken, token)
        return when (r) {
            AuthenticationResult.LoginIdUnavailable -> TODO()
            AuthenticationResult.LoginUnavailable -> null
            AuthenticationResult.RestoreIdUnavailable -> TODO()
            is AuthenticationResult.Success -> SuperloginData(
                r.loginName,
                r.loginToken,
                extractData(r.applicationData)
            ).also {
                slData = it
            }
        }
    }

    suspend fun loginByPassword(loginName: String, password: String): SuperloginData<D>? {
        mustBeLoggedOut()
        // Request derivation params
        val params = invoke(serverApi.slRequestDerivationParams, loginName)
        val keys = DerivedKeys.derive(password, params)
        // Request login data by derived it
        return invoke(
            serverApi.slRequestACOByLoginName,
            RequestACOByLoginNameArgs(loginName, keys.loginId)
        ).let { loginRequest ->
            try {
                AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(
                    loginRequest.packedACO,
                    keys.loginAccessKey
                )?.let { aco ->
                    val result = invoke(
                        serverApi.slLoginByKey,
                        SignedRecord.pack(
                            aco.payload.loginPrivateKey,
                            LoginByPasswordPayload(loginName),
                            loginRequest.nonce
                        )
                    )
                    if (result is AuthenticationResult.Success) {
                        SuperloginData(loginName, result.loginToken, extractData(result.applicationData))
                            .also { slData = it }
                    } else null
                }
            } catch (t: Throwable) {
                t.printStackTrace()
                throw t
            }
        }
    }

    /**
     * Resets password and log in using a `secret` string (one that wwas reported on registration. __Never store
     * secrt string in your app__. Always ask user to enter it just before the operation and wipe it out
     * immediately after. It is a time-consuming procedure. Note that on success the client state changes
     * to [LoginState.LoggedIn].
     *
     * @param secret the secret string as was reported when registering
     * @param newPassword new password (apply strength checks, it is not checked here)
     * @param loginKeyStrength desired login key strength (it will be generated there)
     * @param params password derivation params: it is possible to change its strength here
     * @return login data instance on success or null
     */
    suspend fun resetPasswordAndLogin(
        secret: String, newPassword: String,
        params: PasswordDerivationParams = PasswordDerivationParams(),
        loginKeyStrength: Int = 2048
    ): SuperloginData<D>? {
        mustBeLoggedOut()
        return try {
            val (id, key) = RestoreKey.parse(secret)
            val packedACO = invoke(serverApi.slRequestACOBySecretId, id)
            AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(packedACO, key)?.let {
                changePasswordWithACO(it, newPassword)
                slData
            }
        } catch (x: RestoreKey.InvalidSecretException) {
            null
        } catch (x: Exception) {
            x.printStackTrace()
            null
        }
    }

    /**
     * Changes the password (which includes generating new login key). Does not require any particular
     * [state]. This is a long operation. On success, it changes (updates) [state] to [LoginState.LoggedIn]
     * with new data whatever it was before. Be aware of it.
     */
    protected suspend fun changePasswordWithACO(
        aco: AccessControlObject<SuperloginRestoreAccessPayload>,
        newPassword: String,
        params: PasswordDerivationParams = PasswordDerivationParams(),
        loginKeyStrength: Int = 2048,
    ): Boolean {
        return coroutineScope {
            // Get current nonce in parallel
            val deferredNonce = async { invoke(serverApi.slGetNonce) }
            // get login key in parallel
            val newLoginKey = BackgroundKeyGenerator.getKeyAsync(loginKeyStrength)
            // derive keys in main scope
            val keys = DerivedKeys.derive(newPassword, params)

            // new ACO payload: new login key, old data storage key and login
            val newSlp = SuperloginRestoreAccessPayload(
                aco.payload.login,
                newLoginKey.await(),
                aco.payload.dataStorageKey
            )
            // new ACO with a new password key and payload (but the same secret!)
            var newAco = aco.updatePasswordKey(keys.loginAccessKey).updatePayload(newSlp)
            // trying to update
            val result = invoke(
                serverApi.slChangePasswordAndLogin, ChangePasswordArgs(
                    aco.payload.login,
                    SignedRecord.pack(aco.payload.loginPrivateKey,
                        ChangePasswordPayload(newAco.packed,params,newLoginKey.await().publicKey,keys.loginId),
                        deferredNonce.await())
                )
            )
            when (result) {
                is AuthenticationResult.Success -> {
                    slData = SuperloginData(result.loginName, result.loginToken, extractData(result.applicationData))
                    true
                }

                else -> {
                    warning { "Change password result: $result" }
                    false
                }
            }
        }
    }

    /**
     * Change password for a logged-in user using its known password. It is a long operation
     * @param oldPassword existing password (re-request it from a user!)
     * @param newPassword new password. we do not chek it but it should be strong - check it on your end
     *                    for example with [net.sergeych.unikrypto.Passwords] tools
     * @param passwordDerivationParams at this point derivation parameters are alwaus updated so it is possible
     *                    to set it to desired
     * @param loginKeyStrength login key is regenerateed so its strength could be updated here
     * @return true if the password has been successfully changed
     */
    suspend fun changePassword(oldPassword: String, newPassword: String,
                               passwordDerivationParams: PasswordDerivationParams = PasswordDerivationParams(),
                               loginKeyStrength: Int = 2048
    ): Boolean {
        mustBeLoggedIn()
        val loginName = slData?.loginName ?: throw SLInternalException("loginName should be defined here")
        val dp = invoke(serverApi.slRequestDerivationParams,loginName)
        val keys = DerivedKeys.derive(oldPassword,dp)
        val data = invoke(serverApi.slRequestACOByLoginName,RequestACOByLoginNameArgs(loginName,keys.loginId))
        return AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(data.packedACO, keys.loginAccessKey)?.let {
            changePasswordWithACO(it, newPassword,passwordDerivationParams, loginKeyStrength)
        } ?: false
    }


    companion object {
        inline operator fun <reified D,S : WithAdapter> invoke(
            t: Parsec3Transport<S>,
            savedData: SuperloginData<D>? = null,
        ): SuperloginClient<D, S> {
            return SuperloginClient(t, savedData, typeOf<D>())
        }
    }

}