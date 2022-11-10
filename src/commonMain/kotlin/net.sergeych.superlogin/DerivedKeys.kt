package net.sergeych.superlogin

import net.sergeych.unikrypto.SymmetricKey

/**
 * Super creds are derived from a password and given derivatino parameters.
 * They should not being sent over the netowkr as is or stored so it is not serializable.
 */
class DerivedKeys(
    val loginId: ByteArray,
    val loginAccessKey: SymmetricKey,
    val systemAccessKey: SymmetricKey
) {

   companion object {
       suspend fun derive(password: String, params: PasswordDerivationParams = PasswordDerivationParams()): DerivedKeys {
           val kk = params.derive(password, 3)
           return DerivedKeys(kk[0].keyBytes, kk[1], kk[2])
       }
   }
}