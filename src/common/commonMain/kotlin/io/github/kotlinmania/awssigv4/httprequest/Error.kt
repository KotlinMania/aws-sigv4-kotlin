/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/error.rs
package io.github.kotlinmania.awssigv4.httprequest

internal sealed class SigningErrorKind {
    data class FailedToCreateCanonicalRequest(
        val source: CanonicalRequestError,
    ) : SigningErrorKind()

    data object UnsupportedIdentityType : SigningErrorKind()
}

/** Error signing request. */
class SigningError internal constructor(
    internal val kind: SigningErrorKind,
) {
    /** Human-readable description of the signing failure. */
    val message: String =
        when (kind) {
            is SigningErrorKind.FailedToCreateCanonicalRequest -> "failed to create canonical request"
            SigningErrorKind.UnsupportedIdentityType -> "only 'AWS credentials' are supported for signing"
        }

    internal val cause: CanonicalRequestError?
        get() =
            when (kind) {
                is SigningErrorKind.FailedToCreateCanonicalRequest -> kind.source
                SigningErrorKind.UnsupportedIdentityType -> null
            }

    /** Returns true when this error wraps an underlying canonical-request failure. */
    fun hasSource(): Boolean = cause != null

    /** Returns the underlying canonical-request error message if present. */
    fun sourceMessage(): String? = cause?.message

    override fun toString(): String = message

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SigningError) return false
        return kind == other.kind
    }

    override fun hashCode(): Int = kind.hashCode()

    companion object {
        internal fun unsupportedIdentityType(): SigningError =
            SigningError(SigningErrorKind.UnsupportedIdentityType)

        internal fun from(source: CanonicalRequestError): SigningError =
            SigningError(SigningErrorKind.FailedToCreateCanonicalRequest(source))
    }
}

internal sealed class CanonicalRequestErrorKind {
    data class InvalidHeaderName(
        val source: Any? = null,
    ) : CanonicalRequestErrorKind()

    data class InvalidHeaderValue(
        val source: Any? = null,
    ) : CanonicalRequestErrorKind()

    data class InvalidUri(
        val source: Any? = null,
    ) : CanonicalRequestErrorKind()

    data object UnsupportedIdentityType : CanonicalRequestErrorKind()
}

internal class CanonicalRequestError internal constructor(
    internal val kind: CanonicalRequestErrorKind,
) {
    val message: String =
        when (kind) {
            is CanonicalRequestErrorKind.InvalidHeaderName -> "invalid header name"
            is CanonicalRequestErrorKind.InvalidHeaderValue -> "invalid header value"
            is CanonicalRequestErrorKind.InvalidUri -> "the uri was invalid"
            CanonicalRequestErrorKind.UnsupportedIdentityType -> "only AWS credentials are supported for signing"
        }

    val cause: Any?
        get() =
            when (kind) {
                is CanonicalRequestErrorKind.InvalidHeaderName -> kind.source
                is CanonicalRequestErrorKind.InvalidHeaderValue -> kind.source
                is CanonicalRequestErrorKind.InvalidUri -> kind.source
                CanonicalRequestErrorKind.UnsupportedIdentityType -> null
            }

    override fun toString(): String = message

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanonicalRequestError) return false
        return kind == other.kind
    }

    override fun hashCode(): Int = kind.hashCode()

    companion object {
        internal fun unsupportedIdentityType(): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.UnsupportedIdentityType)

        internal fun invalidHeaderName(source: Any? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidHeaderName(source))

        internal fun invalidHeaderValue(source: Any? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidHeaderValue(source))

        internal fun invalidUri(source: Any? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidUri(source))
    }
}
