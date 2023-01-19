package net.sergeych.superlogin.client

import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.mp_logger.*
import net.sergeych.mp_tools.globalLaunch
import net.sergeych.parsec3.*
import net.sergeych.superlogin.*
import net.sergeych.superlogin.server.SuperloginRestoreAccessPayload
import net.sergeych.unikrypto.SignedRecord
import net.sergeych.unikrypto.SymmetricKey
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

@Serializable
class ClientState<T>(val slData: SuperloginData<T>, val dataKey: SymmetricKey) {
    val loginName by slData::loginName
    val loginToken by slData::loginToken
    val data by slData::data

    constructor(loginName: String,loginToken: ByteArray?,data: T?, dataKey: SymmetricKey)
    : this(SuperloginData(loginName, loginToken, data), dataKey)
}


class SuperloginClient<D, S : WithAdapter>(
    private val transport: Parsec3Transport<S>,
    savedData: ClientState<D>? = null,
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

    private var clientState: ClientState<D>? = savedData
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
                    }
                }
            }
        }

    val applicationData: D?
        get() = (state.value as? LoginState.LoggedIn<D>)?.loginData?.data

    private var adapterReady = MutableStateFlow<Boolean>(false)

    /**
     * The flow that tracks readiness state of the connetion adapter. In other works,
     * when its value is false, [adapter] deferred is not completed and [call] method
     * will wait until it is ready.
     *
     * The reason for it is as follows: when connetion drops,
     * superlogin client awaits its automatic restore (by parsec3) and then tries to re-login.
     * Until this login restore will finish either successful or not, calling parsec3 commands
     * may produce unpredictable results, so it is automatically postponed until login state
     * is restored. This is completely transparent to the caller, and this state flow allows
     * client to be notified on actual connection state.
     */
    val connectionReady = adapterReady.asStateFlow()

    override suspend fun adapter(): Adapter<S> {
        adapterReady.waitFor(true)
        return transport.adapter()
    }

    /**
     * Call client API commands with it (uses [adapter] under the hood)
     */
    suspend fun <A, R> call(ca: CommandDescriptor<A, R>, args: A): R = adapter().invokeCommand(ca, args)

    /**
     * Call client API commands with it (uses [adapter] under the hood)
     */
    suspend fun <R> call(ca: CommandDescriptor<Unit, R>): R = adapter().invokeCommand(ca)

    private suspend fun <A, R> invoke(ca: CommandDescriptor<A, R>, args: A): R =
        transport.adapter().invokeCommand(ca, args)

    private suspend fun <R> invoke(ca: CommandDescriptor<Unit, R>): R = transport.adapter().invokeCommand(ca)

    private var jobs = listOf<Job>()

    private val serverApi = SuperloginServerApi<WithAdapter>()

    private suspend fun tryRestoreLogin() {
        clientState?.let { clientState ->
            clientState.loginToken?.let { token ->
                debug { "trying to restore login with a token" }
                while (true) {
                    try {
                        val ar = transport.adapter().invokeCommand(serverApi.slLoginByToken, token)
                        this.clientState = if (ar is AuthenticationResult.Success) {
                            val data: D? = ar.applicationData?.let { BossDecoder.decodeFrom(dataType, it) }
                            debug { "login restored by the token: ${ar.loginName}" }
                            ClientState(ar.loginName, ar.loginToken, data, clientState.dataKey)
                        } else {
                            debug { "failed to restore login by the token: $ar" }
                            null
                        }
                        break
                    } catch (t: Throwable) {
                        exception { "failed to restore login by token, will retry" to t }
                        delay(1500)
                    }
                }
            }
        } ?: warning { "tryRestoreLogin is ignored as slData is now null" }
        adapterReady.value = true
    }

    init {
        transport.registerExceptinos(SuperloginExceptionsRegistry)
        jobs += globalLaunch {
            transport.connectedFlow.collect { on ->
                if (on) tryRestoreLogin()
                else {
                    adapterReady.value = false
                    _cflow.value = false
                }
            }
        }
    }


    override fun close() {
        transport.close()
    }

    /**
     * Force dropping and re-establish underlying parsec3 connection and restore
     * login state to the current.
     */
    override fun reconnect() {
        adapterReady.value = false
        transport.reconnect()
    }

    private var registration: Registration? = null

    /**
     * Whether the client is supposed to be logged in. Note that it is also true when
     * there is no ready connection (means also offline), if there is information about staved
     * loged in state. It can change at aby time as server may drop login state too. Use
     * [state] flow to track the state changes and [adapterReady] flow to track connection state
     * that are in fact independent to some degree.
     */
    val isLoggedIn get() = state.value.isLoggedIn

    /**
     * The data storage key, a random key created when registering. It is retrieved automatically
     * on login by password and on registration, _It does not restore when logged in by key
     * as it would require storing user's password which must not be done_.
     * Use [retrieveDataKey] to restore to with a password (when logged in)
     */
    val dataKey: SymmetricKey? get() = clientState?.dataKey

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
                    clientState = ClientState(loginName, rr.loginToken, extractData(rr.encodedData), rr.dataKey)
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
        clientState = null
    }

    /**
     * Try to log in by specified token, returned by [Registration.Result.Success.loginToken] or
     * [SuperloginData.loginToken] respectively.
     *
     * @return updated login data (and new token value) or null if token is not (or not anymore)
     *         available for logging in.
     */
    suspend fun loginByToken(token: ByteArray,newDataKey: SymmetricKey): ClientState<D>? {
        mustBeLoggedOut()
        val r = invoke(serverApi.slLoginByToken, token)
        return when (r) {
            is AuthenticationResult.Success -> ClientState(
                r.loginName,
                r.loginToken,
                extractData(r.applicationData),
                newDataKey
            ).also {
                clientState = it
            }
            else -> null
        }
    }

    suspend fun loginByPassword(loginName: String, password: String): ClientState<D>? {
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
                        ClientState(loginName, result.loginToken, extractData(result.applicationData),
                            aco.payload.dataStorageKey)
                            .also {
                                clientState = it
                            }
                    } else null
                }
            } catch (t: Throwable) {
                debug { "error while signign in: $t" }
                null
            }
        }
    }

//    /**
//     * Try to retrieve dataKey (usually after login by token), it is impossible
//     * to do without a valid password key. Should be logged in. If [dataKey] is not null
//     * what means is already known, returns it immediatel, otherwise uses password
//     * to access ACO on the server and extract data key.
//     * @return data key or null if it is impossible to do (no connection or wrong password)
//     */
//    suspend fun retrieveDataKey(password: String): SymmetricKey? {
//        mustBeLoggedIn()
//        dataKey?.let { return it }
//
//        val loginName = slData?.loginName ?: throw SLInternalException("slData: empty login name")
//        try {
//            val params = invoke(
//                serverApi.slRequestDerivationParams,
//                loginName
//            )
//            val keys = DerivedKeys.derive(password, params)
//            // Request login data by derived it
//            return invoke(
//                serverApi.slRequestACOByLoginName,
//                RequestACOByLoginNameArgs(loginName, keys.loginId)
//            ).let { loginRequest ->
//                AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(
//                    loginRequest.packedACO,
//                    keys.loginAccessKey
//                )?.let { aco ->
//                    aco.data.payload.dataStorageKey.also { dataKey = it }
//                }
//            }
//        } catch (t: Throwable) {
//            t.printStackTrace()
//            return null
//        }
//    }

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
    suspend fun resetPasswordAndSignIn(
        secret: String, newPassword: String,
        params: PasswordDerivationParams = PasswordDerivationParams(),
        loginKeyStrength: Int = 2048,
    ): ClientState<D>? {
        mustBeLoggedOut()
        return try {
            val (id, key) = RestoreKey.parse(secret)
            val packedACO = invoke(serverApi.slRequestACOBySecretId, id)
            AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(packedACO, key)?.let {
                changePasswordWithACO(it, newPassword)
                clientState
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
                    SignedRecord.pack(
                        aco.payload.loginPrivateKey,
                        ChangePasswordPayload(newAco.packed, params, newLoginKey.await().publicKey, keys.loginId),
                        deferredNonce.await()
                    )
                )
            )
            when (result) {
                is AuthenticationResult.Success -> {
                    clientState = ClientState(result.loginName, result.loginToken, extractData(result.applicationData),
                        aco.payload.dataStorageKey)
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
    suspend fun changePassword(
        oldPassword: String, newPassword: String,
        passwordDerivationParams: PasswordDerivationParams = PasswordDerivationParams(),
        loginKeyStrength: Int = 2048,
    ): Boolean {
        mustBeLoggedIn()
        val loginName = clientState?.loginName ?: throw SLInternalException("loginName should be defined here")
        val dp = invoke(serverApi.slRequestDerivationParams, loginName)
        val keys = DerivedKeys.derive(oldPassword, dp)
        val data = invoke(serverApi.slRequestACOByLoginName, RequestACOByLoginNameArgs(loginName, keys.loginId))
        return AccessControlObject.unpackWithKey<SuperloginRestoreAccessPayload>(data.packedACO, keys.loginAccessKey)
            ?.let {
                changePasswordWithACO(it, newPassword, passwordDerivationParams, loginKeyStrength)
            } ?: false
    }


    companion object {
        inline operator fun <reified D, S : WithAdapter> invoke(
            t: Parsec3Transport<S>,
            savedData: ClientState<D>? = null,
        ): SuperloginClient<D, S> {
            return SuperloginClient(t, savedData, typeOf<D>())
        }
    }

}