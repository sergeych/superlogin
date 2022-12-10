package net.sergeych.superlogin

import kotlinx.coroutines.await
import net.sergeych.unikrypto.Unicrypto

actual suspend fun InitSuperlogin() {
    // library uses sync operations from unicrypto so:
    Unicrypto.unicryptoReady.await()
}