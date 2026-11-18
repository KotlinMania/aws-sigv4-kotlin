/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source sign/v4.rs
package io.github.kotlinmania.awssigv4.sign.v4

import io.github.kotlinmania.awscredentialtypes.Credentials
import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.formatDate
import io.github.kotlinmania.hmac.Hmac
import io.github.kotlinmania.hmac.registerHasher
import io.github.kotlinmania.sha2.Sha256
import kotlin.time.Instant

private val LOWER_HEX_CHARS = "0123456789abcdef".toCharArray()
private const val HMAC_256: String = "AWS4-HMAC-SHA256"

private val sha256Registration: Unit by lazy {
    val probe = Sha256.new()
    registerHasher(
        type = Sha256::class,
        blockSize = probe.blockSize,
        outputSize = probe.outputSize,
        algName = "Sha256",
        create = { Sha256.new() },
        update = { hasher, bytes -> hasher.update(bytes) },
        finalize = { hasher -> hasher.finalize() },
        reset = { hasher -> hasher.reset() },
        digest = { bytes -> Sha256.digest(bytes) },
    )
}

private fun newHmacSha256(key: ByteArray): Hmac<Sha256> {
    sha256Registration
    return Hmac.newFromSlice(Sha256::class, key).getOrThrow()
}

internal fun lowerHexEncode(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val unsigned = b.toInt() and 0xFF
        sb.append(LOWER_HEX_CHARS[unsigned ushr 4])
        sb.append(LOWER_HEX_CHARS[unsigned and 0x0F])
    }
    return sb.toString()
}

/** HashedPayload = Lowercase(HexEncode(Hash(requestPayload))). */
internal fun sha256HexString(bytes: ByteArray): String {
    val hasher = Sha256.new()
    hasher.update(bytes)
    return lowerHexEncode(hasher.finalize())
}

/** Calculates a SigV4 signature as a lowercase hex string. */
fun calculateSignature(
    signingKey: ByteArray,
    stringToSign: ByteArray,
): String {
    val mac = newHmacSha256(signingKey)
    mac.update(stringToSign)
    return lowerHexEncode(mac.finalizeFixed())
}

/** Calculates a SigV4 signature over a UTF-8 encoded string-to-sign. */
fun calculateSignatureUtf8(
    signingKey: ByteArray,
    stringToSign: String,
): String = calculateSignature(signingKey, stringToSign.encodeToByteArray())

/** Generates a 32-byte signing key for SigV4. */
fun generateSigningKey(
    secret: String,
    time: Instant,
    region: String,
    service: String,
): ByteArray {
    // kSecret = your secret access key
    // kDate = HMAC("AWS4" + kSecret, Date)
    // kRegion = HMAC(kDate, Region)
    // kService = HMAC(kRegion, Service)
    // kSigning = HMAC(kService, request termination marker)
    val prefixedSecret = "AWS4$secret".encodeToByteArray()
    val dateMac = newHmacSha256(prefixedSecret)
    dateMac.update(formatDate(time).encodeToByteArray())
    val dateKey = dateMac.finalizeFixed()

    // sign region
    val regionMac = newHmacSha256(dateKey)
    regionMac.update(region.encodeToByteArray())
    val regionKey = regionMac.finalizeFixed()

    // sign service
    val serviceMac = newHmacSha256(regionKey)
    serviceMac.update(service.encodeToByteArray())
    val serviceKey = serviceMac.finalizeFixed()

    // sign request
    val signingMac = newHmacSha256(serviceKey)
    signingMac.update("aws4_request".encodeToByteArray())
    return signingMac.finalizeFixed()
}

/** Generates a 32-byte signing key for SigV4 from epoch seconds. */
fun generateSigningKeyAtEpochSeconds(
    secret: String,
    epochSeconds: Long,
    region: String,
    service: String,
): ByteArray = generateSigningKey(secret, Instant.fromEpochSeconds(epochSeconds), region, service)

/** Parameters to use when signing with SigV4. */
class SigningParams<S>(
    internal val identity: SigningIdentity,
    internal val region: String,
    internal val name: String,
    internal val time: Instant,
    internal val settings: S,
) {
    /** Returns the identity used to sign requests. */
    fun identity(): SigningIdentity = identity

    /** Returns the region that will be used to sign SigV4 requests. */
    fun region(): String = region

    /** Returns the signing name that will be used to sign requests. */
    fun name(): String = name

    /** Returns the timestamp used in the signature. */
    fun time(): Instant = time

    /** Returns the additional signing settings. */
    fun settings(): S = settings

    /** Returns the name of the algorithm used to sign requests. */
    fun algorithm(): String = HMAC_256

    override fun toString(): String =
        "SigningParams(identity=$identity, region=$region, name=$name, time=$time, settings=$settings)"

    companion object {
        /** Returns a builder that can create new [SigningParams]. */
        fun <S> builder(): Builder<S> = Builder()
    }
}

/** Error returned when a required field on [Builder] was omitted. */
class BuildError internal constructor(
    val reason: String,
) {
    override fun toString(): String = reason

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BuildError) return false
        return reason == other.reason
    }

    override fun hashCode(): Int = reason.hashCode()
}

/** Flat result container for [Builder.build]. */
class BuildResult<S> internal constructor(
    val value: SigningParams<S>?,
    val error: BuildError?,
) {
    fun isSuccess(): Boolean = error == null

    fun isFailure(): Boolean = error != null

    fun getOrNull(): SigningParams<S>? = value

    fun getOrThrow(): SigningParams<S> {
        val err = error
        check(err == null) { err?.reason ?: "build failed" }
        return checkNotNull(value)
    }

    companion object {
        internal fun <S> ok(value: SigningParams<S>): BuildResult<S> = BuildResult(value, null)

        internal fun <S> err(error: BuildError): BuildResult<S> = BuildResult(null, error)
    }
}

/** Builder that can create new [SigningParams]. */
class Builder<S> {
    private var identityValue: SigningIdentity? = null
    private var regionValue: String? = null
    private var nameValue: String? = null
    private var timeValue: Instant? = null
    private var settingsValue: S? = null

    /** Sets the identity (required). */
    fun setIdentity(identity: SigningIdentity?) {
        identityValue = identity
    }

    /** Sets the identity (required). */
    fun identity(identity: SigningIdentity): Builder<S> {
        identityValue = identity
        return this
    }

    /** Sets the identity from AWS [Credentials]. */
    fun credentials(credentials: Credentials): Builder<S> {
        identityValue = SigningIdentity.fromCredentials(credentials)
        return this
    }

    /** Sets the region (required). */
    fun setRegion(region: String?) {
        regionValue = region
    }

    /** Sets the region (required). */
    fun region(region: String): Builder<S> {
        regionValue = region
        return this
    }

    /** Sets the name (required). */
    fun setName(name: String?) {
        nameValue = name
    }

    /** Sets the name (required). */
    fun name(name: String): Builder<S> {
        nameValue = name
        return this
    }

    /** Sets the time to be used in the signature (required). */
    fun setTime(time: Instant?) {
        timeValue = time
    }

    /** Sets the time to be used in the signature (required). */
    fun time(time: Instant): Builder<S> {
        timeValue = time
        return this
    }

    /** Sets the time to be used in the signature from epoch seconds. */
    fun timeEpochSeconds(
        epochSeconds: Long,
        nanosecondsOfSecond: Int = 0,
    ): Builder<S> {
        timeValue = Instant.fromEpochSeconds(epochSeconds, nanosecondsOfSecond)
        return this
    }

    /** Sets additional signing settings (required). */
    fun setSettings(settings: S?) {
        settingsValue = settings
    }

    /** Sets additional signing settings (required). */
    fun settings(settings: S): Builder<S> {
        settingsValue = settings
        return this
    }

    /**
     * Builds an instance of [SigningParams], yielding a [BuildError] in [BuildResult]
     * if any required argument was not provided.
     */
    fun build(): BuildResult<S> {
        val resolvedIdentity = identityValue ?: return BuildResult.err(BuildError("identity is required"))
        val resolvedRegion = regionValue ?: return BuildResult.err(BuildError("region is required"))
        val resolvedName = nameValue ?: return BuildResult.err(BuildError("name is required"))
        val resolvedTime = timeValue ?: return BuildResult.err(BuildError("time is required"))
        val resolvedSettings = settingsValue ?: return BuildResult.err(BuildError("settings are required"))
        return BuildResult.ok(
            SigningParams(
                identity = resolvedIdentity,
                region = resolvedRegion,
                name = resolvedName,
                time = resolvedTime,
                settings = resolvedSettings,
            ),
        )
    }
}
