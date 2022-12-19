package net.sergeych

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import net.sergeych.mp_logger.Log
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.info
import net.sergeych.mp_tools.encodeToBase64Compact
import net.sergeych.parsec3.Adapter
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.Parsec3WSClient
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.*
import net.sergeych.superlogin.client.LoginState
import net.sergeych.superlogin.client.Registration
import net.sergeych.superlogin.client.SuperloginClient
import net.sergeych.superlogin.server.SLServerSession
import net.sergeych.superlogin.server.superloginServer
import net.sergeych.unikrypto.PublicKey
import superlogin.assertThrowsAsync
import kotlin.random.Random
import kotlin.test.*

class TestStorage(
    val byLogin: MutableMap<String, RegistrationArgs> = mutableMapOf<String, RegistrationArgs>(),
    val byLoginId: MutableMap<List<Byte>, RegistrationArgs> = mutableMapOf<List<Byte>, RegistrationArgs>(),
    val byRestoreId: MutableMap<List<Byte>, RegistrationArgs> = mutableMapOf<List<Byte>, RegistrationArgs>(),
    val byToken: MutableMap<List<Byte>, RegistrationArgs> = mutableMapOf<List<Byte>, RegistrationArgs>(),
    val tokens: MutableMap<String, ByteArray> = mutableMapOf<String, ByteArray>(),
)
data class TestSession(val s: TestStorage) : SLServerSession<TestData>() {

    var buzz: String = "BuZZ"

    override suspend fun register(ra: RegistrationArgs): AuthenticationResult {
        println("ra: ${ra.loginName} : $currentLoginName : $superloginData")
        return when {
            ra.loginName in s.byLogin -> {
                AuthenticationResult.LoginUnavailable
            }

            ra.loginId.toList() in s.byLoginId -> AuthenticationResult.LoginIdUnavailable
            ra.restoreId.toList() in s.byRestoreId -> AuthenticationResult.RestoreIdUnavailable
            else -> {
                s.byLogin[ra.loginName] = ra
                s.byRestoreId[ra.restoreId.toList()] = ra
                s.byLoginId[ra.loginId.toList()] = ra
                val token = Random.Default.nextBytes(32)
                s.byToken[token.toList()] = ra
                s.tokens[ra.loginName] = token
                println("registered with token ${token.encodeToBase64Compact()}")
                println("                      ${s.byToken[token.toList()]}")
                AuthenticationResult.Success(ra.loginName, token, ra.extraData)
            }
        }
    }

    override suspend fun loginByToken(token: ByteArray): AuthenticationResult {
        println("requested login by tokeb ${token.encodeToBase64Compact()}")
        println("                         ${s.byToken[token.toList()]}")
        println("                         ${s.byToken.size} / ${s.byLoginId.size}")

        return s.byToken[token.toList()]?.let {
            AuthenticationResult.Success(it.loginName, token, it.extraData)
        }
            ?: AuthenticationResult.LoginUnavailable
    }

    override suspend fun requestDerivationParams(loginName: String): PasswordDerivationParams? =
        s.byLogin[loginName]?.derivationParams

    override suspend fun requestACOByLoginName(loginName: String, loginId: ByteArray): ByteArray? {
        return s.byLogin[loginName]?.packedACO
    }

    override suspend fun requestACOByRestoreId(restoreId: ByteArray): ByteArray? {
        return s.byRestoreId[restoreId.toList()]?.packedACO
    }

    override suspend fun loginByKey(loginName: String, publicKey: PublicKey): AuthenticationResult {
        val ra = s.byLogin[loginName]
        return if (ra != null && ra.loginPublicKey.id == publicKey.id)
            AuthenticationResult.Success(ra.loginName, s.tokens[loginName]!!, ra.extraData)
        else AuthenticationResult.LoginUnavailable
    }

    override suspend fun updateAccessControlData(
        loginName: String,
        packedACO: ByteArray,
        passwordDerivationParams: PasswordDerivationParams,
        newLoginKey: PublicKey,
        newLoginId: ByteArray
    ) {
        val r = s.byLogin[loginName]?.also {
           s.byLoginId.remove(it.loginId.toList())
        }?.copy(
            packedACO = packedACO,
            derivationParams = passwordDerivationParams,
            loginPublicKey = newLoginKey,
            loginId = newLoginId
        )
            ?: throw RuntimeException("login not found")
        s.byLogin[loginName] = r
        s.byLoginId[newLoginId.toList()] = r
        s.byToken[currentLoginToken!!.toList()] = r
        s.byRestoreId[r.restoreId.toList()] = r
    }

}


class TestApiServer<T : WithAdapter> : CommandHost<T>() {
    val loginName by command<Unit, String?>()
    val dropConnection by command<Unit,Unit>()
}


@Serializable
data class TestData(
    val foo: String,
)

internal class WsServerKtTest {


    @Test
    fun testWsServer() {

        embeddedServer(Netty, port = 8085, module = Application::testServerModule).start(wait = false)

        val client = Parsec3WSClient("ws://localhost:8085/api/p3")

        runBlocking {
            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, WithAdapter>(client)
            assertNull(slc.dataKey)
            assertEquals(LoginState.LoggedOut, slc.state.value)
            var rt = slc.register("foo", "passwd", TestData("bar!"))
            val dk1 = slc.dataKey
            assertIs<Registration.Result.Success>(rt)
            assertEquals(dk1, rt.dataKey)
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
            assertNull(slc.dataKey)
            assertIs<LoginState.LoggedOut>(slc.state.value)
            assertEquals(null, slc.call(api.loginName))

            rt = slc.register("foo", "passwd", TestData("nobar"))
            assertIs<Registration.Result.InvalidLogin>(rt)
            assertIs<LoginState.LoggedOut>(slc.state.value)
            assertEquals(null, slc.call(api.loginName))

            var ar = slc.loginByToken(token, dk1!!)
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))

//            assertNull(slc.retrieveDataKey("badpasswd"))
//            assertEquals(dk1?.id, slc.retrieveDataKey("passwd")?.id)
//            assertEquals(dk1?.id, slc.dataKey?.id)
//
            assertThrowsAsync<IllegalStateException> { slc.loginByToken(token, dk1) }
        }

    }

    class S1: WithAdapter()

    @Test
    fun loginByPasswordTest() {
        embeddedServer(Netty, port = 8081, module = Application::testServerModule).start(wait = false)

        runBlocking {
            val client = Parsec3WSClient.withSession<S1>("ws://localhost:8081/api/p3")

            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, S1>(client)
            assertEquals(LoginState.LoggedOut, slc.state.value)
            var rt = slc.register("foo", "passwd", TestData("bar!"))
            assertIs<Registration.Result.Success>(rt)
            val dk1 = slc.dataKey!!
            slc.logout()
            assertNull(slc.loginByPassword("foo", "passwd2"))
            var ar = slc.loginByPassword("foo", "passwd")
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))
            assertEquals(dk1.id, slc.dataKey!!.id)
        }
    }

    @Test
    fun changePasswordTest() {
        embeddedServer(Netty, port = 8083, module = Application::testServerModule).start(wait = false)

        runBlocking {
            val client = Parsec3WSClient.withSession<S1>("ws://localhost:8083/api/p3")

            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, S1>(client)
            assertEquals(LoginState.LoggedOut, slc.state.value)
            var rt = slc.register("foo", "passwd", TestData("bar!"))
            val dk1 = slc.dataKey!!
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
            assertNull(slc.resetPasswordAndSignIn("bad_secret", "newpass2"))
            assertNull(slc.resetPasswordAndSignIn("3PBpp-Aris5-ogdV7-Abz36-ggGH5", "newpass2"))
            ar = slc.resetPasswordAndSignIn(secret,"newpass2")
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))
            assertEquals(dk1.id, slc.dataKey!!.id)
        }
    }
    @Test
    fun testExceptions() {
        embeddedServer(Netty, port = 8082, module = Application::testServerModule).start(wait = false)
        val client = Parsec3WSClient("ws://localhost:8082/api/p3")
        runBlocking {
            Log.connectConsole(Log.Level.DEBUG)
            val slc = SuperloginClient<TestData, WithAdapter>(client)
            val serverApi = SuperloginServerApi<WithAdapter>()
            assertThrowsAsync<SLInternalException> {
                slc.call(serverApi.slSendTestException,Unit)
            }
        }

    }

    @Test
    fun testDroppedConnection() {
        embeddedServer(Netty, port = 8089, module = Application::testServerModule).start(wait = false)
        val client = Parsec3WSClient("ws://localhost:8089/api/p3")
        runBlocking {
            Log.connectConsole(Log.Level.DEBUG)
            val l = LogTag("Test")
            val api = TestApiServer<WithAdapter>()
            val slc = SuperloginClient<TestData, WithAdapter>(client)
            val serverApi = SuperloginServerApi<WithAdapter>()

            var rt = slc.register("foo", "passwd", TestData("bar!"))
            assertIs<Registration.Result.Success>(rt)

            assertEquals("foo", slc.call(api.loginName))

            l.info { "---- breaking the connection ----------" }
            assertThrowsAsync<Adapter.CloseError> { slc.call(api.dropConnection) }

            assertTrue { slc.isLoggedIn }
            assertEquals("foo", slc.call(api.loginName))
        }

    }


}

fun Application.testServerModule() {
    val s = TestStorage()
    superloginServer(TestApiServer<TestSession>(), { TestSession(s) }) {
        on(api.loginName) {
            currentLoginName
        }
        on(api.dropConnection) {
            adapter.cancel()
        }
    }
}