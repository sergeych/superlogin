package superlogin

import kotlinx.coroutines.test.runTest
import net.sergeych.superlogin.AccessControlObject
import net.sergeych.superlogin.RestoreKey
import net.sergeych.unikrypto.SymmetricKeys
import kotlin.test.*

internal class AccessControlObjectTest {

    @Test
    fun createRestoreTest() = runTest {
        val pk1 = SymmetricKeys.random()
        val pk2 = SymmetricKeys.random()
        val (rk, packed1) = AccessControlObject.pack(pk1, 117)
        println(rk.secret)
        val ac1 = AccessControlObject.unpackWithPasswordKey<Int>(packed1,pk1)
        assertNotNull(ac1)
        assertEquals(117, ac1.payload)
        val ac2 = AccessControlObject.unpackWithSecret<Int>(packed1,rk.secret)
        assertNotNull(ac2)
        assertEquals(117, ac2.payload)
        assertNull(AccessControlObject.unpackWithPasswordKey<Int>(packed1,pk2))
        assertNull(AccessControlObject.unpackWithSecret<Int>(packed1,"the_-wrong-secret-yess"))

        val (rk2, packed2) = AccessControlObject.pack(pk2, 107)
        assertNull(AccessControlObject.unpackWithSecret<Int>(packed1,rk2.secret))
        var ac21 = AccessControlObject.unpackWithPasswordKey<Int>(packed2,pk2)
        assertNotNull(ac21)
        assertEquals(107, ac21.payload)

        var packed3 = ac1.updatePayload(121).packed
        ac21 = AccessControlObject.unpackWithPasswordKey(packed3,pk1)
        assertNotNull(ac21)
        assertEquals(121, ac21.payload)

        packed3 = ac1.updatePasswordKey(pk2).packed
        println("-------")
        ac21 = AccessControlObject.unpackWithPasswordKey(packed3,pk2)
        assertNotNull(ac21)
        assertEquals(117, ac21.payload)

        ac21 = AccessControlObject.unpackWithSecret(packed3,rk.secret)
        assertNotNull(ac21)
        assertEquals(117, ac21.payload)

    }
}