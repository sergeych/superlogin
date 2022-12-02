package superlogin

import kotlin.test.fail

suspend inline fun <reified T: Throwable> assertThrowsAsync(f: suspend () -> Unit) {
    try {
        f()
        fail("Nothing was thrown while ${T::class.simpleName} is expected")
    }
    catch(x: Throwable) {
        if( x !is T )
            fail("${x::class.simpleName} was thrown instead of ${T::class.simpleName}: $x")
    }
}
