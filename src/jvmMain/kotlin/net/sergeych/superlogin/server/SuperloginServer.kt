package net.sergeych.superlogin.server

import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.parsec3.AdapterBuilder
import net.sergeych.parsec3.CommandHost
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.AuthenticationResult
import net.sergeych.superlogin.SuperloginServerApi
import net.sergeych.superlogin.client.SuperloginData

inline fun <reified D, T : SLServerSession<D>, H : CommandHost<T>> AdapterBuilder<T, H>.superloginServer(
    traits: SLServerTraits,
) {
    val a2 = SuperloginServerApi<WithAdapter>()
    on(a2.slRegister) { ra ->
        traits.register(ra).also { rr ->
            if( rr is AuthenticationResult.Success)
                slData = SuperloginData<D>(rr.loginToken, rr.applicationData?.let { it.decodeBoss<D>()})
                loginName = ra.loginName
        }
    }
    on(a2.slLogout) {
        println("--- logged out ---")
        slData = null
        loginName = null
        traits.logout()
    }
}