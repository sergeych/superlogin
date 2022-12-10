package superlogin

import kotlinx.coroutines.test.runTest
import net.sergeych.superlogin.InitSuperlogin
import net.sergeych.superlogin.RestoreKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

internal class RestoreKeyTest {

    @Test
    fun checkRestoreKey() = runTest {
        InitSuperlogin()
        val rk = RestoreKey.generate()

        val (id, k) = RestoreKey.parse(rk.secret)
        assertContentEquals(rk.restoreId, id)
        assertEquals(rk.key.id, k.id)
        assertContentEquals(rk.key.keyBytes, k.keyBytes)

        val x = StringBuilder(rk.secret)
        x[0] = (x[0].code xor 0x75).toChar()
        assertFails {
            RestoreKey.parse(x.toString())
        }

    }
}