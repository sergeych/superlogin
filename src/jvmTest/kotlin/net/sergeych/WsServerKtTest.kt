package net.sergeych

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.Parsec3WSClient
import net.sergeych.parsec3.WithAdapter
import net.sergeych.parsec3.parsec3TransportServer
import net.sergeych.superlogin.AuthenticationResult
import net.sergeych.superlogin.RegistrationArgs
import net.sergeych.superlogin.client.LoginState
import net.sergeych.superlogin.client.Registration
import net.sergeych.superlogin.client.SuperloginClient
import net.sergeych.superlogin.server.SLServerSession
import net.sergeych.superlogin.server.SLServerTraits
import net.sergeych.superlogin.server.superloginServer
import superlogin.assertThrowsAsync
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

data class TestSession(var buzz: String = "BuZZ") : SLServerSession<TestData>()


class TestApiServer<T : WithAdapter> : CommandHost<T>() {
    val loginName by command<Unit, String?>()
}


object TestServerTraits : SLServerTraits {
    val byLogin = mutableMapOf<String, RegistrationArgs>()
    val byLoginId = mutableMapOf<List<Byte>, RegistrationArgs>()
    val byRestoreId = mutableMapOf<List<Byte>, RegistrationArgs>()
    val byToken = mutableMapOf<List<Byte>, RegistrationArgs>()

    override suspend fun register(ra: RegistrationArgs): AuthenticationResult {
        println("ra: ${ra.loginName}")
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
                AuthenticationResult.Success(token, ra.extraData)
            }
        }
    }

    override suspend fun loginByToken(token: ByteArray): AuthenticationResult {
        return byToken[token.toList()]?.let {
            AuthenticationResult.Success(token, it.extraData)
        } ?: AuthenticationResult.LoginUnavailable
    }

}

@Serializable
data class TestData(
    val foo: String,
)

//fun <S: SLServerSession<*>,A: CommandHost<S>> Application.superloginServer(
//    traits: SLServerTraits,
//    api: A,
//    f: AdapterBuilder<S,A>.()->Unit) {
//    parsec3TransportServer(api) {
//        superloginServer(traits)
//        f()
//    }
//}


internal class WsServerKtTest {


    @Test
    fun testWsServer() {

        embeddedServer(Netty, port = 8080) {
            parsec3TransportServer(TestApiServer<SLServerSession<TestData>>()) {
//            superloginServer(TestServerTraits,TestApiServer<SLServerSession<TestData>>()) {
                newSession { TestSession() }
                superloginServer(TestServerTraits)
                on(api.loginName) {
                    loginName
                }
            }
        }.start(wait = false)

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

            var ar = slc.loginByToken(token)
            assertNotNull(ar)
            assertEquals("bar!", ar.data?.foo)
            assertEquals("foo", slc.call(api.loginName))
        }

    }


}