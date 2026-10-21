/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/error.rs
package io.github.kotlinmania.awssigv4.httprequest

sealed class SigningErrorKind {
    data class FailedToCreateCanonicalRequest(
        val source: CanonicalRequestError,
    ) : SigningErrorKind()

    data object UnsupportedIdentityType : SigningErrorKind()
}

/** Error signing request. */
class SigningError internal constructor(
    internal val kind: SigningErrorKind,
) : Exception(
        when (kind) {
            is SigningErrorKind.FailedToCreateCanonicalRequest -> "failed to create canonical request"
            SigningErrorKind.UnsupportedIdentityType -> "only 'AWS credentials' are supported for signing"
        },
        when (kind) {
            is SigningErrorKind.FailedToCreateCanonicalRequest -> kind.source
            SigningErrorKind.UnsupportedIdentityType -> null
        },
    ) {
    override fun toString(): String = message ?: "SigningError"

    companion object {
        internal fun unsupportedIdentityType(): SigningError =
            SigningError(SigningErrorKind.UnsupportedIdentityType)

        internal fun from(source: CanonicalRequestError): SigningError =
            SigningError(SigningErrorKind.FailedToCreateCanonicalRequest(source))
    }
}

sealed class CanonicalRequestErrorKind {
    data class InvalidHeaderName(
        val source: Throwable? = null,
    ) : CanonicalRequestErrorKind()

    data class InvalidHeaderValue(
        val source: Throwable? = null,
    ) : CanonicalRequestErrorKind()

    data class InvalidUri(
        val source: Throwable? = null,
    ) : CanonicalRequestErrorKind()

    data object UnsupportedIdentityType : CanonicalRequestErrorKind()
}

class CanonicalRequestError internal constructor(
    internal val kind: CanonicalRequestErrorKind,
) : Exception(
        when (kind) {
            is CanonicalRequestErrorKind.InvalidHeaderName -> "invalid header name"
            is CanonicalRequestErrorKind.InvalidHeaderValue -> "invalid header value"
            is CanonicalRequestErrorKind.InvalidUri -> "the uri was invalid"
            CanonicalRequestErrorKind.UnsupportedIdentityType -> "only AWS credentials are supported for signing"
        },
        when (kind) {
            is CanonicalRequestErrorKind.InvalidHeaderName -> kind.source
            is CanonicalRequestErrorKind.InvalidHeaderValue -> kind.source
            is CanonicalRequestErrorKind.InvalidUri -> kind.source
            CanonicalRequestErrorKind.UnsupportedIdentityType -> null
        },
    ) {
    override fun toString(): String = message ?: "CanonicalRequestError"

    companion object {
        internal fun unsupportedIdentityType(): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.UnsupportedIdentityType)

        internal fun invalidHeaderName(source: Throwable? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidHeaderName(source))

        internal fun invalidHeaderValue(source: Throwable? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidHeaderValue(source))

        internal fun invalidUri(source: Throwable? = null): CanonicalRequestError =
            CanonicalRequestError(CanonicalRequestErrorKind.InvalidUri(source))
    }
}
