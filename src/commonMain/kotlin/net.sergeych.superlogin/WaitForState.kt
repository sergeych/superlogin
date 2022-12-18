package net.sergeych.superlogin

import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch


/**
 * Wait for stateflow value to be accepted by the predicate that should
 * return true. Does not wait if the predicate returns true for the
 * current state value.
 */
suspend fun <T> StateFlow<T>.waitUntil(predicate: (T) -> Boolean) {
    // Speed optimization:
    if( predicate(value)) return
    // we have to wait here
    coroutineScope {
        // first we watch the state change to avoid RCs:
        val job = launch {
            collect {
                if (predicate(value)) cancel()
            }
        }
        // now the value can be changed while we were starting up the
        // job so another check is necessary before waiting for a job
        if (!predicate(value)) job.join()
        // created job should be cancelled anyway
        if (job.isActive) job.cancel()
    }
}

/**
 * Wait for state flow to be equal to the expected value. Does not wait if it
 * already so.
 */
suspend fun <T> StateFlow<T>.waitFor(state: T) {
    waitUntil { it == state }
}
