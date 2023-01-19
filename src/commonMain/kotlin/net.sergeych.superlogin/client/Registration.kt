package net.sergeych.superlogin.client

import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.debug
import net.sergeych.mp_logger.error
import net.sergeych.mp_logger.exception
import net.sergeych.parsec3.Adapter
import net.sergeych.parsec3.WithAdapter
import net.sergeych.superlogin.*
import net.sergeych.superlogin.server.SuperloginRestoreAccessPayload
import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.SignedRecord
import net.sergeych.unikrypto.SymmetricKey
import net.sergeych.unikrypto.digest
import kotlin.random.Random

/**
 * Registration instances are used to perform superlogin-compatible registration in a smart way
 * avoiding unnecessary time-consuming password derivation and key generation repetitions.
 * once calculated these values are kept in the instance unless new password or different
 * password derivation parameters are supplied. This is useful in the case the login in user error
 * result - user can provide new login and re-register times faster than otherwise re-deriving
 * and creating new keys.
 *
 * It is important to use _different_ instances for different registrations, and the same instance
 * for consecutive attempts to register the same user varying login only.
 *
 * See [register] for more.
 */
class Registration(
    val adapter: Adapter<*>, loginKeyStrength: Int = 4096,
    val pbkdfRounds: Int = 15000,
) : LogTag("SLREG") {

    sealed class Result {
        /**
         * Login is already in use or is somehow else invalid
         */
        object InvalidLogin : Result()

        /**
         * Operation failed for nknown reason, usually it means
         * network or server downtime
         */
        class NetworkFailure(val exception: Throwable? = null) : Result()

        class Success(
            val secret: String,
            val dataKey: SymmetricKey,
            val loginToken: ByteArray,
            val encodedData: ByteArray?) : Result() {
                inline fun <reified D>data() = encodedData?.let { BossDecoder.decodeFrom<D>(it)}
            }
    }

    private var lastPasswordHash: ByteArray? = null
    private var lastDerivationParams: PasswordDerivationParams? = null
    private var passwordKeys: DerivedKeys? = null
    val api = SuperloginServerApi<WithAdapter>()
    private val deferredLoginKey = BackgroundKeyGenerator.getKeyAsync(loginKeyStrength)
    private val dataKey = BackgroundKeyGenerator.randomSymmetricKey()

    inline suspend fun <reified T> register(
        login: String,
        password: String,
        extraData: T? = null,
    ): Result = registerWithData(login, password, extraData?.let { BossEncoder.encode(it) })


    /**
     * Smart attempt to register. It is ok to repeatedly call it if the result is not [Result.Success]: it will
     * cache internal data and reuse time-consuming precalculated values for caches and derived keys if the
     * password and derivarion parameters are not changed between calls.
     */
    suspend fun registerWithData(
        login: String,
        password: String,
        extraData: ByteArray? = null,
    ): Result {
        val newPasswordHash = HashAlgorithm.SHA3_256.digest(password)
        if (lastPasswordHash?.contentEquals(newPasswordHash) != true ||
            passwordKeys == null
        ) {
            lastDerivationParams = PasswordDerivationParams(pbkdfRounds)
            passwordKeys = DerivedKeys.derive(password, lastDerivationParams!! )
            lastPasswordHash = newPasswordHash
        }
        val nonce = adapter.invokeCommand(api.slGetNonce)
        val loginPrivateKey = deferredLoginKey.await()
        val spl = SuperloginRestoreAccessPayload(login, loginPrivateKey, dataKey)
        repeat(10) {
            val (restoreKey, restoreData) = AccessControlObject.pack(passwordKeys!!.loginAccessKey, spl)
            try {
                val packedArgs = SignedRecord.pack(
                    loginPrivateKey,
                    RegistrationArgs(
                        login,
                        passwordKeys!!.loginId,
                        deferredLoginKey.await().publicKey,
                        lastDerivationParams!!,
                        restoreKey.restoreId, restoreData,
                        extraData
                    ),
                    nonce
                )
                val result = adapter.invokeCommand(api.slRegister, packedArgs)
                when (result) {
                    AuthenticationResult.RestoreIdUnavailable -> {
                        // rare situation but still possible: just repack the ACO
                        debug { "retrying registration on restoreId clash" }
                    }

                    AuthenticationResult.LoginIdUnavailable -> {
                        // rare situation: loginId is already in use. We have to re-derive password keys
                        // using new random salt:
                        debug { "retrying registration on loginId clash"}
                        lastDerivationParams = lastDerivationParams!!.copy(salt = Random.nextBytes(32))
                        passwordKeys = DerivedKeys.derive(password, lastDerivationParams!!)
                    }

                    AuthenticationResult.LoginUnavailable -> return Result.InvalidLogin

                    is AuthenticationResult.Success -> {
                        return Result.Success(
                            restoreKey.secret,
                            dataKey,
                            result.loginToken,
                            result.applicationData
                        )
                    }
                }
            } catch (x: Throwable) {
                exception { "Failed to register" to x }
            }
        }
        // If we still get there, its a strange error - 10 times we cant get suitable restoreId...
        error { "Failed to register after 10 repetitions with no apparent reason" }
        return Result.NetworkFailure(null)
    }

}