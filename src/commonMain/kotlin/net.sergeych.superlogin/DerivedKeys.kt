package net.sergeych.superlogin

import net.sergeych.unikrypto.SymmetricKey

/**
 * Super creds are derived from a password and given derivation parameters.
 * They should not be being sent over the network or stored (re-derivation is
 * usually required), so it is not serializable.
 * @param loginId cryptographically independent and strong id that depends on the password
 *                but does not disclose [loginAccessKey], Superlogin uses it to allow
 *                API access to ACO with login private key (it can be safely stored in the
 *                database)
 * @param loginAccessKey first symmetric key, used to decrypt ACO
 * @param extraKey just for future extensions. not used as for now.
 */
class DerivedKeys(
    val loginId: ByteArray,
    val loginAccessKey: SymmetricKey,
    @Suppress("unused") val extraKey: SymmetricKey
) {

   companion object {
       suspend fun derive(password: String, params: PasswordDerivationParams = PasswordDerivationParams()): DerivedKeys {
           val kk = params.derive(password, 3)
           return DerivedKeys(kk[0].keyBytes, kk[1], kk[2])
       }
   }
}