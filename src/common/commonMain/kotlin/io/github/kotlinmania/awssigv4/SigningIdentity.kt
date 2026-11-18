/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package io.github.kotlinmania.awssigv4

import io.github.kotlinmania.awscredentialtypes.Credentials
import kotlin.time.Instant

/**
 * Identity container used for request and event-stream signing.
 *
 * Mirrors the runtime identity envelope wrapping [Credentials] (or another
 * identity payload when testing unsupported identity rejection) along with an
 * optional expiration timestamp.
 */
class SigningIdentity internal constructor(
    internal val payload: Any,
    private val expirationValue: Instant?,
) {
    /** Returns the embedded [Credentials] if this identity holds AWS credentials. */
    fun credentials(): Credentials? = payload as? Credentials

    /** Returns the optional expiration instant of this identity. */
    fun expiration(): Instant? = expirationValue

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SigningIdentity) return false
        return payload == other.payload && expirationValue == other.expirationValue
    }

    override fun hashCode(): Int {
        var result = payload.hashCode()
        result = 31 * result + (expirationValue?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String = "SigningIdentity(hasCredentials=${payload is Credentials}, expiration=$expirationValue)"

    companion object {
        /** Creates a [SigningIdentity] backed by AWS [Credentials]. */
        fun fromCredentials(
            credentials: Credentials,
            expiration: Instant? = credentials.expiry(),
        ): SigningIdentity = SigningIdentity(credentials, expiration)

        /** Creates a [SigningIdentity] directly from AWS access key material. */
        fun fromKeys(
            accessKeyId: String,
            secretAccessKey: String,
            sessionToken: String? = null,
            expiration: Instant? = null,
        ): SigningIdentity =
            SigningIdentity(
                Credentials.fromKeys(accessKeyId, secretAccessKey, sessionToken),
                expiration,
            )

        /** Creates a [SigningIdentity] with deterministic test credentials. */
        fun forTests(): SigningIdentity = fromCredentials(Credentials.forTests())

        /** Creates a [SigningIdentity] with deterministic test credentials including a session token. */
        fun forTestsWithSessionToken(): SigningIdentity = fromCredentials(Credentials.forTestsWithSessionToken())

        /** Creates a [SigningIdentity] carrying a non-credentials payload (for unsupported-identity error paths). */
        fun unsupported(
            payload: Any,
            expiration: Instant? = null,
        ): SigningIdentity = SigningIdentity(payload, expiration)
    }
}

/** Converts these AWS [Credentials] into a [SigningIdentity]. */
fun Credentials.toSigningIdentity(expiration: Instant? = expiry()): SigningIdentity =
    SigningIdentity.fromCredentials(this, expiration)
