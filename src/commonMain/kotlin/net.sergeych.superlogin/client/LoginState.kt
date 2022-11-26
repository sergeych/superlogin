package net.sergeych.superlogin.client

sealed class LoginState(val isLoggedIn: Boolean) {
    /**
     * User is logged in (either connected or yet not). Client application should save
     * updated [loginData] at this point
     */
    class LoggedIn<D>(val loginData: SuperloginData<D>) : LoginState(true)

    /**
     * Login state whatever it was now is logged out, and client application should delete
     * any saved [SuperloginData] instance it has.
     */
    object LoggedOut : LoginState(false)
}