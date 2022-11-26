package net.sergeych.superlogin.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
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
import net.sergeych.parsec3.Adapter
import net.sergeych.parsec3.CommandDescriptor
import net.sergeych.parsec3.Parsec3Transport
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.AuthenticationResult
import net.sergeych.superlogin.SuperloginServerApi
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
    val loginToken: ByteArray? = null,
    val data: T? = null,
)


class SuperloginClient<D, S : WithAdapter>(
    private val transport: Parsec3Transport<S>,
    savedData: SuperloginData<D>? = null,
    private val dataType: KType,
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
                    if (!adapterReady.isActive) {
                        adapterReady.cancel()
                        adapterReady = CompletableDeferred()
                    }
                    globalLaunch {
                        transport.adapter().invokeCommand(api.slLogout)
                        adapterReady.complete(Unit)
                    }
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

    override suspend fun adapter(): Adapter<S> {
        do {
            try {
                adapterReady.await()
                return transport.adapter()
            } catch (x: Throwable) {
                exception { "failed to get adapter" to x }
            }
        } while (true)
    }

    suspend fun <A, R> call(ca: CommandDescriptor<A, R>, args: A ): R = adapter().invokeCommand(ca, args)
    suspend fun <R> call(ca: CommandDescriptor<Unit, R>): R = adapter().invokeCommand(ca)

    private suspend fun <A, R> invoke(ca: CommandDescriptor<A, R>, args: A ): R = transport.adapter().invokeCommand(ca, args)
    private suspend fun <R> invoke(ca: CommandDescriptor<Unit, R>): R = transport.adapter().invokeCommand(ca)

    private var jobs = listOf<Job>()

    private val api = SuperloginServerApi<WithAdapter>()

    private suspend fun tryRestoreLogin() {
        slData?.loginToken?.let { token ->
            try {
                val ar = transport.adapter().invokeCommand(api.slLoginByToken, token)
                slData = if (ar is AuthenticationResult.Success) {
                    val data: D? = ar.applicationData?.let { BossDecoder.decodeFrom(dataType, it) }
                    SuperloginData(ar.loginToken, data)
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
                    slData = SuperloginData(rr.loginToken, rr.encodedData?.let { BossDecoder.decodeFrom(dataType, it) })
                }
            }
    }

    private fun mustBeLoggedOut() {
        if (isLoggedIn)
            throw IllegalStateException("please log out first")
    }

    private fun mustBeLoggedIn() {
        if (!isLoggedIn)
            throw IllegalStateException("please log in first")
    }

    fun logout() {
        mustBeLoggedIn()
        slData = null
    }

    suspend fun LoginByToken(token: ByteArray): SuperloginData<D> {
        mustBeLoggedOut()
        val r = invoke(api.slLoginByToken,token)
        when(r) {
            AuthenticationResult.LoginIdUnavailable -> TODO()
            AuthenticationResult.LoginUnavailable -> TODO()
            AuthenticationResult.RestoreIdUnavailable -> TODO()
            is AuthenticationResult.Success -> TODO()
        }
    }

    companion object {
        inline operator fun <reified D, S : WithAdapter> invoke(
            t: Parsec3Transport<S>,
            savedData: SuperloginData<D>? = null,
        ): SuperloginClient<D, S> {
            return SuperloginClient(t, savedData, typeOf<D>())
        }
    }

}