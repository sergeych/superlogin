package net.sergeych.superlogin.server

import io.ktor.server.application.*
import net.sergeych.parsec3.AdapterBuilder
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.WithAdapter
import net.sergeych.parsec3.parsec3TransportServer
import net.sergeych.superlogin.*
import net.sergeych.unikrypto.SignedRecord
import kotlin.random.Random

fun randomACOLike(): ByteArray {
    return Random.nextBytes(117)
}

/**
 * Create superlogin server using default parsec 3 server transport providing session creation
 * lambda and a block to set up server-specific api. The session must inherit [SLServerSession]
 * with application-specific data, and implement all of its abstract methods at list (also it
 * might need t override some default methods, see docs. For example:
 * ~~~
 *
 * // Application-specific API declaration
 * class TestApiServer<T : WithAdapter> : CommandHost<T>() {
 *     val foobar by command<Unit, String?>()
 * }
 *
 * // application data to be included in the "user" data transfered to and from the client:
 * data class TestData(clientData: String)
 *
 * // session state, is kept until the user connection (e.g. session) is closed, in the RAM:
 * class TestSession(var sessionData: String) : SLServerSession<TestData>()
 *
 * // Create a server in a ktor context:
 * fun Application.serverModule() {
 *   SuperloginServer(TestApiServer<TestSession>(), { TestSession("foobar") }) {
 *       // application API implementation
 *       on(api.foobar) {
 *           "Session data: ${sessionData}, loginName: $currentLoginName user data: $superloginData"
 *       }
 *   }
 * }
 * ~~~
 *
 * @param api service specific API declaration (usually in the shared code)
 * @param sessionBuilder function that creates new session. Session is created on every incoming
 *          connection so try not to do any time and resource consuming operations there
 * @param adapterBuilder block that should implement service-specific api.
 * @param D application specific data (included in the session and transferred with registration
 *          and login)
 * @param T service-specific session, class implementing any session-based code specific to the
 *          application but also implement necessary `superlogin` methods (implementing abstract
 *          ones) that implement user login data persistence and search.
 */
inline fun <reified D, T : SLServerSession<D>,> Application.SuperloginServer(
    api: CommandHost<T>,
    crossinline sessionBuilder: suspend AdapterBuilder<T, CommandHost<T>>.()->T,
    crossinline adapterBuilder: AdapterBuilder<T, CommandHost<T>>.()->Unit
) {
    parsec3TransportServer(api) {
        setupSuperloginServer { sessionBuilder() }
        adapterBuilder()
    }
}


/**
 * Set up a superlogin server manually, on a current adapter builder, using some session builder lambda.
 * Note that session must inherit [SLServerSession] and implement necessary abstract methods
 * that do store and retrieve user data. Usually you can do it easier with [SuperloginServer] call.
 * If you want to do it manually (fr example using a custom transport), do it like this:
 * ```
 *     parsec3TransportServer(TestApiServer<TestSession>()) {
 *         // the session extends SLServerSession and contain app-specific data and
 *         // storage/retrieve methods:
 *         superloginServer { TestSession() }
 *
 *         // Sample service-specifiv api (above login api):
 *         on(api.loginName) {
 *             println("login name called. now we have $currentLoginName : $superloginData")
 *             currentLoginName
 *         }
 *     }
 * ```
 *
 * @param sessionBuilder code that builds a new session over the adapter.
 */
inline fun <reified D, T : SLServerSession<D>, H : CommandHost<T>> AdapterBuilder<T, H>.setupSuperloginServer(
    crossinline sessionBuilder: suspend AdapterBuilder<T, H>.() -> T,
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
                    payload.newLoginKey,
                    payload.newLoginId
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

