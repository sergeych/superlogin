package net.sergeych.superlogin.client

/**
 * Login client has a _login state_ which represents known state of the log-in protocol.
 * It can properly process offline state and reconnection and report state bu mean
 * of the state flow pf instanses of this class. See [SuperloginClient.state].
 */
sealed class LoginState(val isLoggedIn: Boolean) {
    /**
     * User is logged in (either connected or yet not). Client application should save
     * updated [loginData] at this point
     */
    class LoggedIn<D>(val loginData: ClientState<D>) : LoginState(true)

    /**
     * Login state whatever it was now is logged out, and client application should delete
     * any saved [SuperloginData] instance it has.
     */
    object LoggedOut : LoginState(false)
}