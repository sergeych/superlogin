package net.sergeych.superlogin.server

import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.client.SuperloginData

/**
 * The superlogin server session. Please use only [loginName] and [loginToken], the rest could be
 * a subject to change.
 */
open class SLServerSession<T>: WithAdapter() {
    var slData: SuperloginData<T>? = null

    val userData: T? get() = slData?.let { it.data }

    val loginToken get() = slData?.loginToken

    var loginName: String? = null
}