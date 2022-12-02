package net.sergeych.superlogin

import net.sergeych.parsec3.ExceptionsRegistry

class SLInternalException(reason: String?="superlogin internal exception (a bug)",cause: Throwable?=null):
        Exception(reason, cause)

fun addSuperloginExceptions(er: ExceptionsRegistry) {
    er.register { SLInternalException(it) }
}

val SuperloginExceptionsRegistry = ExceptionsRegistry().also { addSuperloginExceptions(it) }