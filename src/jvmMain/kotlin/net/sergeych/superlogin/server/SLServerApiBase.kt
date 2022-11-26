package net.sergeych.superlogin.server

import net.sergeych.parsec3.CommandHost

/**
 * Server-side API convenience base.
 */
open class SLServerApiBase<D>: CommandHost<SLServerSession<D>>()