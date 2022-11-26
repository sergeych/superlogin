package net.sergeych.superlogin.server

import net.sergeych.superlogin.AuthenticationResult
import net.sergeych.superlogin.RegistrationArgs

/**
 * Set of procedures the server implementing superlogin protocol should provide
 */
interface SLServerTraits {
    /**
     * Register specified user. The server should check that:
     *
     * - [RegistrationArgs.loginName] is not used, otherwise return [AuthenticationResult.LoginUnavailable]
     * - [RegistrationArgs.loginId] is not used, otherwise return [AuthenticationResult.LoginIdUnavailable]
     * - [RegistrationArgs.restoreId] is not used or return [AuthenticationResult.RestoreIdUnavailable]
     *
     * Then it should save permanently data from `registrationArgs` in a way tha allow fast search (indexed,
     * usually) by `loginName`, `loginId` and `restoreId`, and return [AuthenticationResult.Success] with
     * newly generated random bytes string `loginToken` that would optionally simplify logging in.
     *
     * If the implementation does not provide login token, it should still provide random bytes string
     * to maintain hight security level of the serivce.
     */
    suspend fun register(registrationArgs: RegistrationArgs): AuthenticationResult

    suspend fun logout() {}
}