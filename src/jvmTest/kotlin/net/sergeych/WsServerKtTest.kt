package net.sergeych

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import net.sergeych.parsec3.*
import net.sergeych.superlogin.*
import net.sergeych.superlogin.client.LoginState
import net.sergeych.superlogin.client.Registration
import net.sergeych.superlogin.client.SuperloginClient
import net.sergeych.superlogin.server.SLServerSession
import net.sergeych.superlogin.server.setupSuperloginServer
import net.sergeych.unikrypto.PublicKey
import superlogin.assertThrowsAsync
import kotlin.random.Random
import kotlin.test.*

data class TestSession(var buzz: String = "BuZZ") : SLServerSession<TestData>() {
    val byLogin = mutableMapOf<String, RegistrationArgs>()
    val byLoginId = mutableMapOf<List<Byte>, RegistrationArgs>()
    val byRestoreId = mutableMapOf<List<Byte>, RegistrationArgs>()
    val byToken = mutableMapOf<List<Byte>, RegistrationArgs>()
    val tokens = mutableMapOf<String, ByteArray>()

    override suspend fun register(ra: RegistrationArgs): AuthenticationResult {
        println("ra: ${ra.loginName} : $currentLoginName : $superloginData")
        return when {
            ra.loginName in byLogin -> {
                AuthenticationResult.LoginUnavailable
            }

            ra.loginId.toList() in byLoginId -> AuthenticationResult.LoginIdUnavailable
            ra.restoreId.toList() in byRestoreId -> AuthenticationResult.RestoreIdUnavailable
            else -> {
                byLogin[ra.loginName] = ra
                byRestoreId[ra.restoreId.toList()] = ra
                byLoginId[ra.loginId.toList()] = ra
                val token = Random.Default.nextBytes(32)
                byToken[token.toList()] = ra
                tokens[ra.loginName] = token
                AuthenticationResult.Success(ra.loginName, token, ra.extraData)
            }
        }
    }

    override suspend fun loginByToken(token: ByteArray): AuthenticationResult {
        return byToken[token.toList()]?.let {
            AuthenticationResult.Success(it.loginName, token, it.extraData)
        }
            ?: AuthenticationResult.LoginUnavailable
    }

    override suspend fun requestDerivationParams(loginName: String): PasswordDerivationParams? =
        byLogin[loginName]?.derivationParams

    override suspend fun requestACOByLoginName(loginName: String, loginId: ByteArray): ByteArray? {
        return byLogin[loginName]?.packedACO
    }

    override suspend fun requestACOByRestoreId(restoreId: ByteArray): ByteArray? {
        return byRestoreId[restoreId.toList()]?.packedACO
    }

    override suspend fun loginByKey(loginName: String, publicKey: PublicKey): AuthenticationResult {
        val ra = byLogin[loginName]
        return if (ra != null && ra.loginPublicKey.id == publicKey.id)
            AuthenticationResult.Success(ra.loginName, tokens[loginName]!!, ra.extraData)
        else AuthenticationResult.LoginUnavailable
    }

    override suspend fun updateAccessControlData(
        loginName: String,
        packedData: ByteArray,
        passwordDerivationParams: PasswordDerivationParams,
        newLoginKey: PublicKey,
    ) {
        val r = byLogin[loginName]?.copy(
            packedACO = packedData,
            derivationParams = passwordDerivationParams,
            loginPublicKey = newLoginKey
        )
            ?: throw RuntimeException("login not found")
        byLogin[loginName] = r
        byLoginId[r.loginId.toList()] = r
        byToken[currentLoginToken!!.toList()] = r
        byRestoreId[r.restoreId.toList()] = r
    }

}


class TestApiServer<T : WithAdapter> : CommandHost<T>() {
    val loginName by command<Unit, String?>()
}


@Serializable
data class TestData(
    val foo: String,
)

internal class WsServerKtTest {


    @Test
    fun testWsServer() {

        embeddedServer(Netty, port = 8080, module = Application::testServerModule).start(wait = false)

        val client = Parsec3WSClient("ws://localhost:8080/api/p3")

        runBlocking {
            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, WithAdapter>(client)
            assertEquals(LoginState.LoggedOut, slc.state.value)
            var rt = slc.register("foo", "passwd", TestData("bar!"))
            assertIs<Registration.Result.Success>(rt)
            val secret = rt.secret
            var token = rt.loginToken
            println(rt.secret)
            assertEquals("bar!", rt.data<TestData>()?.foo)

            assertEquals("foo", slc.call(api.loginName))

            val s = slc.state.value
            assertIs<LoginState.LoggedIn<TestData>>(s)
            assertEquals("bar!", s.loginData.data!!.foo)

            assertThrowsAsync<IllegalStateException> {
                slc.register("foo", "passwd", TestData("nobar"))
            }
            slc.logout()
            assertIs<LoginState.LoggedOut>(slc.state.value)
            assertEquals(null, slc.call(api.loginName))

            rt = slc.register("foo", "passwd", TestData("nobar"))
            assertIs<Registration.Result.InvalidLogin>(rt)
            assertIs<LoginState.LoggedOut>(slc.state.value)
            assertEquals(null, slc.call(api.loginName))

            var ar = slc.loginByToken(token)
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))
//
            assertThrowsAsync<IllegalStateException> { slc.loginByToken(token) }
        }

    }

    class S1: WithAdapter()

    @Test
    fun changePasswordTest() {
        embeddedServer(Netty, port = 8081, module = Application::testServerModule).start(wait = false)

        runBlocking {
            val client = Parsec3WSClient.withSession<S1>("ws://localhost:8081/api/p3")

            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, S1>(client)
            assertEquals(LoginState.LoggedOut, slc.state.value)
            var rt = slc.register("foo", "passwd", TestData("bar!"))
            assertIs<Registration.Result.Success>(rt)
            val secret = rt.secret
            var token = rt.loginToken

            assertFalse(slc.changePassword("wrong", "new"))
            assertTrue(slc.changePassword("passwd", "newpass1"))
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))

            slc.logout()
            assertNull(slc.loginByPassword("foo", "passwd"))
            var ar = slc.loginByPassword("foo", "newpass1")
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))

            slc.logout()
            assertNull(slc.resetPasswordAndLogin("bad_secret", "newpass2"))
            assertNull(slc.resetPasswordAndLogin("3PBpp-Aris5-ogdV7-Abz36-ggGH5", "newpass2"))
            ar = slc.resetPasswordAndLogin(secret,"newpass2")
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))


        }
    }

    @Test
    fun testExceptions() {
        embeddedServer(Netty, port = 8082, module = Application::testServerModule).start(wait = false)
        val client = Parsec3WSClient("ws://localhost:8082/api/p3")
        runBlocking {
            val slc = SuperloginClient<TestData, WithAdapter>(client)
            val serverApi = SuperloginServerApi<WithAdapter>()
            assertThrowsAsync<SLInternalException> {
                slc.call(serverApi.slSendTestException,Unit)
            }
        }

    }

}

inline fun <reified D, T : SLServerSession<D>, H : CommandHost<T>> Application.SuperloginServer(
    api: H,
    crossinline sessionBuilder: suspend AdapterBuilder<T, H>.()->T,
    crossinline adapterBuilder: AdapterBuilder<T, H>.()->Unit
) {
    parsec3TransportServer(api) {
        setupSuperloginServer { sessionBuilder() }
        adapterBuilder()
    }
}

fun Application.testServerModule() {
    SuperloginServer(TestApiServer<TestSession>(), { TestSession() }) {
        on(api.loginName) {
            println("login name called. now we have $currentLoginName : $superloginData")
            currentLoginName
        }
    }
}