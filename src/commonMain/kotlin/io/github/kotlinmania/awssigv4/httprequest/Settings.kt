/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/settings.rs
package io.github.kotlinmania.awssigv4.httprequest

import kotlin.time.Duration

private const val HEADER_NAME_X_RAY_TRACE_ID: String = "x-amzn-trace-id"

// HTTP-specific signing settings
data class SigningSettings(
    // Specifies how to encode the request URL when signing. Some services do not decode
    // the path prior to checking the signature, requiring clients to actually _double-encode_
    // the URI in creating the canonical request in order to pass a signature check.
    var percentEncodingMode: PercentEncodingMode = PercentEncodingMode.Double,

    // Add an additional checksum header
    var payloadChecksumKind: PayloadChecksumKind = PayloadChecksumKind.NoHeader,

    // Where to put the signature
    var signatureLocation: SignatureLocation = SignatureLocation.Headers,

    // For presigned requests, how long the presigned request is valid for
    var expiresIn: Duration? = null,

    // Headers that should be excluded from the signing process
    var excludedHeaders: List<String>? = defaultExcludedHeaders(),

    // Specifies whether the absolute path component of the URI should be normalized during signing.
    var uriPathNormalizationMode: UriPathNormalizationMode = UriPathNormalizationMode.Enabled,

    // Some services require X-Amz-Security-Token to be included in the
    // canonical request. Other services require only it to be added after
    // calculating the signature.
    var sessionTokenMode: SessionTokenMode = SessionTokenMode.Include,

    // Some services require an alternative session token header or query param instead of
    // `x-amz-security-token` or `X-Amz-Security-Token`.
    var sessionTokenNameOverride: String? = null,
)

// Headers that are potentially altered by proxies or as a part of standard service operations.
// Reference:
// Go SDK: https://github.com/aws/aws-sdk-go/blob/v1.44.289/aws/signer/v4/v4.go#L92
// Java SDK: https://github.com/aws/aws-sdk-java-v2/blob/master/core/auth/src/main/java/software/amazon/awssdk/auth/signer/internal/AbstractAws4Signer.java#L70
// JS SDK: https://github.com/aws/aws-sdk-js/blob/master/lib/signers/v4.js#L191
// There is no single source of truth for these available, so this uses the minimum common set of the excluded options.
// Build the list every time, because SigningSettings holds a mutable list (which cannot be a top-level constant).
private fun defaultExcludedHeaders(): List<String> = listOf(
    // This header is calculated as part of the signing process, so if it's present, discard it
    "authorization",
    // Changes when sent by proxy
    "user-agent",
    // Changes based on the request from the client
    HEADER_NAME_X_RAY_TRACE_ID,
    // Hop by hop header, can be erased by Cloudfront
    "transfer-encoding",
)

// HTTP payload checksum type
enum class PayloadChecksumKind {
    // Add x-amz-checksum-sha256 to the canonical request
    //
    // This setting is required for S3
    XAmzSha256,

    // Do not add an additional header when creating the canonical request
    //
    // This is "normal mode" and will work for services other than S3
    NoHeader,
}

// Config value to specify how to encode the request URL when signing.
//
// We assume the URI will be encoded _once_ prior to transmission. Some services
// do not decode the path prior to checking the signature, requiring clients to actually
// _double-encode_ the URI in creating the canonical request in order to pass a signature check.
enum class PercentEncodingMode {
    // Re-encode the resulting URL (e.g. %30 becomes `%2530)
    Double,

    // Take the resulting URL as-is
    Single,
}

// Config value to specify whether the canonical request's URI path should be normalized.
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
//
// URI path normalization is performed based on https://www.rfc-editor.org/rfc/rfc3986.
enum class UriPathNormalizationMode {
    // Normalize the URI path according to RFC3986
    Enabled,

    // Don't normalize the URI path (S3, for example, rejects normalized paths in some instances)
    Disabled;

    companion object {
        fun fromBoolean(value: Boolean): UriPathNormalizationMode =
            if (value) Enabled else Disabled
    }
}

// Config value to specify whether X-Amz-Security-Token should be part of the canonical request.
// http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html#temporary-security-credentials
enum class SessionTokenMode {
    // Include in the canonical request before calculating the signature.
    Include,

    // Exclude in the canonical request.
    Exclude,
}

// Where to place signing values in the HTTP request
enum class SignatureLocation {
    // Place the signature in the request headers
    Headers,

    // Place the signature in the request query parameters
    QueryParams,
}
