/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awscredentialtypes.Credentials
import io.github.kotlinmania.awssigv4.SignatureVersion
import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.sign.v4.BuildError
import io.github.kotlinmania.awssigv4.sign.v4.Builder
import kotlin.time.Instant
import io.github.kotlinmania.awssigv4.sign.v4.SigningParams as V4SigningParams

internal class CredentialsLookupResult(
    val credentials: Credentials?,
    val error: SigningError?,
)

/**
 * Parameters for signing an HTTP request.
 */
class SigningParams private constructor(
    internal val v4Params: V4SigningParams<SigningSettings>,
) {
    /** Returns the credentials within the signing params, or an unsupported-identity error. */
    internal fun credentials(): CredentialsLookupResult {
        val creds = v4Params.identity.credentials()
        return if (creds != null) {
            CredentialsLookupResult(creds, null)
        } else {
            CredentialsLookupResult(null, SigningError.unsupportedIdentityType())
        }
    }

    /** If the signing params are for SigV4, returns the region. */
    fun region(): String? = v4Params.region

    /** Returns a reference to the settings held by the signing params. */
    fun settings(): SigningSettings = v4Params.settings

    /** Returns a mutable reference to the settings held by the signing params. */
    fun settingsMut(): SigningSettings = v4Params.settings

    /** Sets the [PayloadChecksumKind] for the signing params. */
    internal fun setPayloadChecksumKind(kind: PayloadChecksumKind) {
        settingsMut().payloadChecksumKind = kind
    }

    /** Sets the [SessionTokenMode] for the signing params. */
    internal fun setSessionTokenMode(mode: SessionTokenMode) {
        settingsMut().sessionTokenMode = mode
    }

    /** Returns the signing timestamp. */
    fun time(): Instant = v4Params.time

    /** Returns the signing timestamp epoch seconds. */
    fun timeEpochSeconds(): Long = v4Params.time.epochSeconds

    /** Returns the service signing name. */
    fun name(): String = v4Params.name

    /** Returns the name of the configured signing algorithm. */
    fun algorithm(): String = v4Params.algorithm()

    /** Returns the signature scheme version. */
    fun signatureVersion(): SignatureVersion = SignatureVersion.V4

    override fun toString(): String = "SigningParams.V4($v4Params)"

    companion object {
        /** Wraps SigV4 signing parameters into HTTP [SigningParams]. */
        fun v4(params: V4SigningParams<SigningSettings>): SigningParams = SigningParams(params)

        /** Creates a concrete HTTP SigV4 builder suitable for both Kotlin and Swift callers. */
        fun v4Builder(): HttpSigningParamsBuilder = HttpSigningParamsBuilder()
    }
}

/** Flat build result for [HttpSigningParamsBuilder]. */
class HttpSigningParamsBuildResult internal constructor(
    val value: SigningParams?,
    val error: BuildError?,
) {
    fun isSuccess(): Boolean = error == null

    fun isFailure(): Boolean = error != null

    fun getOrNull(): SigningParams? = value

    fun getOrThrow(): SigningParams {
        val err = error
        if (err != null) {
            error("Failed to build SigningParams: ${err.reason}")
        }
        return checkNotNull(value)
    }
}

/** Concrete non-generic SigV4 HTTP [SigningParams] builder. */
class HttpSigningParamsBuilder {
    private val delegate = Builder<SigningSettings>()

    fun identity(identity: SigningIdentity): HttpSigningParamsBuilder {
        delegate.identity(identity)
        return this
    }

    fun credentials(credentials: Credentials): HttpSigningParamsBuilder {
        delegate.credentials(credentials)
        return this
    }

    fun region(region: String): HttpSigningParamsBuilder {
        delegate.region(region)
        return this
    }

    fun name(name: String): HttpSigningParamsBuilder {
        delegate.name(name)
        return this
    }

    fun time(time: Instant): HttpSigningParamsBuilder {
        delegate.time(time)
        return this
    }

    fun timeEpochSeconds(
        epochSeconds: Long,
        nanosecondsOfSecond: Int = 0,
    ): HttpSigningParamsBuilder {
        delegate.timeEpochSeconds(epochSeconds, nanosecondsOfSecond)
        return this
    }

    fun settings(settings: SigningSettings): HttpSigningParamsBuilder {
        delegate.settings(settings)
        return this
    }

    fun build(): HttpSigningParamsBuildResult {
        val built = delegate.build()
        val v4Value = built.value
        return if (v4Value != null) {
            HttpSigningParamsBuildResult(SigningParams.v4(v4Value), null)
        } else {
            HttpSigningParamsBuildResult(null, built.error)
        }
    }
}

/** Converts SigV4 HTTP [V4SigningParams] into [SigningParams]. */
fun V4SigningParams<SigningSettings>.toHttpSigningParams(): SigningParams = SigningParams.v4(this)
