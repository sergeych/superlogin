package net.sergeych.superlogin

import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.unikrypto.Container
import net.sergeych.unikrypto.SymmetricKey
import kotlin.reflect.KType
import kotlin.reflect.typeOf

/**
 * Access Control Object (ACO) allows to decrypt vital application data using either some `passwordKey`, usually
 * obtained from user password using [DerivedKeys], or a special randomly created `secret` string, which is
 * hard to remember but cryptographically string and contains some protection against typing errors,
 * see [RestoreKey] for details. Once the access control object is generated, it can be decrypted using:
 *
 * - regenerated password key, usually [DerivedKeys.loginAccessKey]
 * - `restoreSecret`, that should only be known to a user
 *
 * It is possible to change data and/or `passwordKey` of a decrypted object. Use [packed] property on new instance
 * to save encrypted updated data.
 *
 * AceesControlObject holds also application-specific `data`.
 *
 * _Important note. While the primary constructor is public, we strongly recommend never using it directly.
 * To construct it please use one of:_
 *
 * - [AccessControlObject.pack] to generate new
 * - [AccessControlObject.unpackWithKey] to decrypt it with a password key
 * - [AccessControlObject.unpackWithSecret] to decrypt it with a `secret`
 *
 * @param payloadType  used to properly serialize application=specific data for [payload]
 * @param packed encrypted and packed representation of the object, could be stored in public.
 * @param passwordKey the password-derived key that could be used to unpack the [packed] data
 * @param data contains necessary data to keep and operate the ACO
 */
@Suppress("OPT_IN_USAGE")
class AccessControlObject<T>(
    val payloadType: KType,
    val packed: ByteArray,
    val passwordKey: SymmetricKey,
    val data: Data<T>,
) {

    /**
     * The application-specific data stored in the ACO. Should be @Serializable or a simple type
     */
    val payload: T by data::payload

    /**
     * The ID that can be used to index/find the stored ACO, restoreId is derived from the secret
     * with [RestoreKey] and could be obtanied by application software independently. The recommended
     * use is to identify stored login record that should include a copy of most recent
     * packed AccessControlObject.
     */
    val restoreId: ByteArray by data::restoreId

    /**
     * Internal use only. The data ACO needs to operate, including the application's [payload]. This is
     * the content of encrypted packed ACO.
     */
    @Serializable
    class Data<T>(
        val restoreId: ByteArray,
        val derivedRestoreKey: SymmetricKey,
        val payload: T,
    )

    /**
     * Update payload and return new instance of te ACO. The `secret` and `passwordKey` are not changed.
     * Use [packed] property on the result to save updated copy.
     */
    inline fun <reified R>updatePayload(newPayload: R): AccessControlObject<R> {
        val data = Data(restoreId, data.derivedRestoreKey, newPayload)
        return AccessControlObject<R>(
            typeOf<Data<R>>(),
            Container.encrypt(
                data,
                passwordKey, data.derivedRestoreKey
            ),
            passwordKey, data
        )
    }

    /**
     * Update the password key and return new instance. It could be decrypted with the same `secret` and
     * [newPasswordKey] only. The [payload] is not changed.
     */
    fun updatePasswordKey(newPasswordKey: SymmetricKey): AccessControlObject<T> {
        val data = Data(restoreId, data.derivedRestoreKey, payload)
        return AccessControlObject(
            payloadType,
            Container.encryptData(
                BossEncoder.encode(payloadType,data),
                newPasswordKey, data.derivedRestoreKey
            ),
            newPasswordKey, data
        )

    }

    class WrongKeyException : Exception("can't decrypt AccessControlObject")

    companion object {

        /**
         * Create and pack brand-new access control object with new random `secret`. It returns [RestoreKey]
         * instance which contains not only `secret` but also `restoreId` which are often needed to save (and identify)
         * encrypted object in the cloud, and also the key used to encrypt it. _Never save the key to disk or
         * transmit it over the network_. If need, derive it from s `secret` again, see [RestoreKey.parse].
         * @param passwordKey the second key that is normally used to decrypt ACO
         * @param payload application-specific data to keep inside the ACO
         * @return pair where first is a [RestoreKey] instance containing new `secret` and so on, and packed encrypted
         *          ACO that could be restored using `secret` or a [passwordKey]
         */
        inline suspend fun <reified T> pack(
            passwordKey: SymmetricKey,
            payload: T,
        ): Pair<RestoreKey, ByteArray> {
            val restoreKey = RestoreKey.generate()
            return restoreKey to Container.encrypt(
                Data(restoreKey.restoreId, restoreKey.key, payload),
                passwordKey, restoreKey.key
            )
        }

        /**
         * Unpack and decrypt ACO with a password key or secret-based key (this once can be obtained from `secret`
         * with [RestoreKey.parse].
         * @return decrypted ACO or null if the key is wrong.
         */
        inline fun <reified T> unpackWithKey(packed: ByteArray, key: SymmetricKey): AccessControlObject<T>? =
            Container.decrypt<Data<T>>(packed, key)?.let {
                AccessControlObject(typeOf<Data<T>>(), packed, key, it)
            }

        fun <T>unpackWithKey(packed: ByteArray, passwordKey: SymmetricKey, payloadType: KType): AccessControlObject<T>? =
            Container.decryptAsBytes(packed, passwordKey)?.let {
                AccessControlObject(payloadType, packed, passwordKey, BossDecoder.decodeFrom(payloadType,it))
            }

        /**
         * Unpack and decrypt ACO with a [secret]. If you want to check [secret] integrity, use
         * [RestoreKey.checkSecretIntegrity].
         * @return deccrypted ACO or null if the secret is wrong
         */
        suspend inline fun <reified T> unpackWithSecret(packed: ByteArray, secret: String): AccessControlObject<T>? {
            try {
                val (_, key) = RestoreKey.parse(secret)
                return unpackWithKey(packed, key)
            }
            catch(_: RestoreKey.InvalidSecretException) {
                return null
            }
        }
    }
}