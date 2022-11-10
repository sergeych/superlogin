package net.sergeych.superlogin

import net.sergeych.parsec3.Adapter
import net.sergeych.parsec3.WithAdapter

/**
 * Registration instances are used to perform registration
 * in steps to not no regemerate all keys on every attempt to
 * say change login.
 */
class Registration<T: WithAdapter>(adapter: Adapter<T>) {

    sealed class Result {
        /**
         * Login is already in use or is somehow else invalid
         */
        object InvalidLogin: Result()

        /**
         * Operation failed for nknown reason, usually it means
         * network or server downtime
         */
        object NetworkFailure: Result()

//        class Success(val l)
    }

//    fun register(
//        login: String,
//        password: String,
//    )

}