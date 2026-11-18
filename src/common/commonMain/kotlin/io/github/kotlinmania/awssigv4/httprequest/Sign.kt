/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/sign.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awssigv4.SignatureVersion
import io.github.kotlinmania.awssigv4.SigningOutput
import io.github.kotlinmania.awssigv4.sign.v4.calculateSignature
import io.github.kotlinmania.awssigv4.sign.v4.generateSigningKey
import io.github.kotlinmania.awssigv4.sign.v4.sha256HexString
import io.github.kotlinmania.http.uri.Uri

/** Named HTTP header pair used to construct a [SignableRequest]. */
data class SignableHeader(
    val name: String,
    val value: String,
)

/** Flat result container for [SignableRequest.new]. */
class SignableRequestResult internal constructor(
    val value: SignableRequest?,
    val error: SigningError?,
) {
    fun isSuccess(): Boolean = error == null

    fun isFailure(): Boolean = error != null

    fun getOrNull(): SignableRequest? = value

    fun getOrThrow(): SignableRequest {
        val err = error
        check(err == null) { err?.message ?: "signing failed" }
        return checkNotNull(value)
    }

    companion object {
        internal fun ok(value: SignableRequest): SignableRequestResult = SignableRequestResult(value, null)

        internal fun err(error: SigningError): SignableRequestResult = SignableRequestResult(null, error)
    }
}

/** Represents all of the information necessary to sign an HTTP request. */
class SignableRequest private constructor(
    private val methodValue: String,
    private val uriValue: Uri,
    private val headersList: List<SignableHeader>,
    private val bodyValue: SignableBody,
) {
    /** Returns the signable URI. */
    internal fun uri(): Uri = uriValue

    /** Returns the signable HTTP method. */
    internal fun method(): String = methodValue

    /** Returns the request headers. */
    internal fun headers(): List<SignableHeader> = headersList

    /** Returns the signable body. */
    fun body(): SignableBody = bodyValue

    override fun toString(): String =
        "SignableRequest(method=$methodValue, uri=$uriValue, headers=$headersList, body=$bodyValue)"

    companion object {
        /**
         * Creates a new [SignableRequest].
         *
         * Note: The [uri] is expected to already be in encoded form.
         */
        fun new(
            method: String,
            uri: String,
            headers: List<SignableHeader>,
            body: SignableBody,
        ): SignableRequestResult {
            val parsedUriResult = Uri.tryFrom(uri)
            val parsedUri = parsedUriResult.getOrNull()
            if (parsedUri == null) {
                val cause = parsedUriResult.exceptionOrNull()
                return SignableRequestResult.err(
                    SigningError.from(CanonicalRequestError.invalidUri(cause)),
                )
            }
            return SignableRequestResult.ok(
                SignableRequest(
                    methodValue = method,
                    uriValue = parsedUri,
                    headersList = headers.toList(),
                    bodyValue = body,
                ),
            )
        }
    }
}

/** Discriminator for [SignableBody] variants. */
enum class SignableBodyKind {
    Bytes,
    UnsignedPayload,
    Precomputed,
    StreamingUnsignedPayloadTrailer,
}

/** A signable HTTP request body. */
class SignableBody private constructor(
    private val bodyKind: SignableBodyKind,
    private val bytesData: ByteArray?,
    private val precomputedDigest: String?,
) {
    /** Returns the variant kind of this body. */
    fun kind(): SignableBodyKind = bodyKind

    /** Returns a copy of the byte payload when [kind] is [SignableBodyKind.Bytes]. */
    fun bytesOrNull(): ByteArray? = bytesData?.copyOf()

    /** Returns the precomputed SHA-256 hex digest when [kind] is [SignableBodyKind.Precomputed]. */
    fun precomputedDigestOrNull(): String? = precomputedDigest

    /**
     * Formats the body in debug representation.
     * Pass [logSignableBody] = true to format raw byte values instead of redacting.
     */
    fun debugString(logSignableBody: Boolean = false): String =
        when (bodyKind) {
            SignableBodyKind.Bytes -> {
                val raw = checkNotNull(bytesData)
                if (logSignableBody) {
                    val joined = raw.joinToString(", ") { (it.toInt() and 0xFF).toString() }
                    "Bytes([$joined])"
                } else {
                    "Bytes(\"** REDACTED **. To print ${raw.size} bytes of raw data, set environment variable `LOG_SIGNABLE_BODY=true`\")"
                }
            }

            SignableBodyKind.UnsignedPayload -> {
                "UnsignedPayload"
            }

            SignableBodyKind.Precomputed -> {
                "Precomputed(\"${checkNotNull(precomputedDigest)}\")"
            }

            SignableBodyKind.StreamingUnsignedPayloadTrailer -> {
                "StreamingUnsignedPayloadTrailer"
            }
        }

    override fun toString(): String = debugString(false)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignableBody) return false
        if (bodyKind != other.bodyKind) return false
        if (precomputedDigest != other.precomputedDigest) return false
        val a = bytesData
        val b = other.bytesData
        if (a != null && b != null) return a.contentEquals(b)
        return a == null && b == null
    }

    override fun hashCode(): Int {
        var result = bodyKind.hashCode()
        result = 31 * result + (bytesData?.contentHashCode() ?: 0)
        result = 31 * result + (precomputedDigest?.hashCode() ?: 0)
        return result
    }

    companion object {
        /** A body composed of a slice of bytes. */
        fun bytes(data: ByteArray): SignableBody =
            SignableBody(SignableBodyKind.Bytes, data.copyOf(), null)

        /** A body composed of UTF-8 encoded text bytes. */
        fun fromUtf8(text: String): SignableBody =
            SignableBody(SignableBodyKind.Bytes, text.encodeToByteArray(), null)

        /** Creates a new empty signable body. */
        fun empty(): SignableBody = SignableBody(SignableBodyKind.Bytes, ByteArray(0), null)

        /** An unsigned payload for streaming requests whose body cannot be known prior to signing. */
        fun unsignedPayload(): SignableBody =
            SignableBody(SignableBodyKind.UnsignedPayload, null, null)

        /** A precomputed lowercase hex-encoded SHA-256 body checksum. */
        fun precomputed(digest: String): SignableBody =
            SignableBody(SignableBodyKind.Precomputed, null, digest)

        /** Set when a streaming body has checksum trailers. */
        fun streamingUnsignedPayloadTrailer(): SignableBody =
            SignableBody(SignableBodyKind.StreamingUnsignedPayloadTrailer, null, null)
    }
}

/** Header representation for use in [SigningInstructions]. */
class Header internal constructor(
    private val key: String,
    private val headerValue: String,
    private val isSensitive: Boolean,
) {
    /** The name of this header. */
    fun name(): String = key

    /** The value of this header. */
    fun value(): String = headerValue

    /** Whether this header has a sensitive value. */
    fun sensitive(): Boolean = isSensitive

    override fun toString(): String {
        val displayVal = if (isSensitive) "** REDACTED **" else headerValue
        return "Header { key: \"$key\", value: \"$displayVal\" }"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Header) return false
        return key == other.key && headerValue == other.headerValue && isSensitive == other.isSensitive
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + headerValue.hashCode()
        result = 31 * result + isSensitive.hashCode()
        return result
    }
}

/** Query parameter representation for use in [SigningInstructions]. */
data class QueryParam(
    val name: String,
    val value: String,
)

/** Decomposed headers and query parameters of [SigningInstructions]. */
data class SigningInstructionsParts(
    val headers: List<Header>,
    val params: List<QueryParam>,
)

/** Instructions for applying a signature to an HTTP request. */
class SigningInstructions internal constructor(
    private val headersList: List<Header>,
    private val paramsList: List<QueryParam>,
) {
    /** Returns the headers and query params that should be applied to this request. */
    fun intoParts(): SigningInstructionsParts = SigningInstructionsParts(headersList, paramsList)

    /** Returns the headers that should be added to the request. */
    fun headers(): List<Header> = headersList

    /** Returns the query parameters that should be added to the request. */
    fun params(): List<QueryParam> = paramsList

    /** Applies the query parameters in these instructions to [uri] and returns the updated [Uri]. */
    internal fun applyToUri(uri: Uri): Uri {
        if (paramsList.isEmpty()) {
            return uri
        }
        val query = QueryWriter(uri)
        for (param in paramsList) {
            query.insert(param.name, param.value)
        }
        return query.buildUri()
    }

    /** Applies the query parameters in these instructions to a URI string and returns the updated URI string. */
    fun applyToUriString(uriString: String): String {
        if (paramsList.isEmpty()) {
            return uriString
        }
        val query = QueryWriter.newFromString(uriString)
        for (param in paramsList) {
            query.insert(param.name, param.value)
        }
        return query.buildUri().toString()
    }

    override fun toString(): String = "SigningInstructions(headers=$headersList, params=$paramsList)"
}

/** Flat result container for [sign]. */
class SignResult internal constructor(
    val value: SigningOutput<SigningInstructions>?,
    val error: SigningError?,
) {
    fun isSuccess(): Boolean = error == null

    fun isFailure(): Boolean = error != null

    fun getOrNull(): SigningOutput<SigningInstructions>? = value

    /** Concrete helper returning the signed [SigningInstructions] when [isSuccess] is true. */
    fun instructions(): SigningInstructions? = value?.output()

    /** Concrete helper returning the lowercase hex signature when [isSuccess] is true. */
    fun signature(): String? = value?.signature()

    fun getOrThrow(): SigningOutput<SigningInstructions> {
        val err = error
        check(err == null) { err?.message ?: "signing failed" }
        return checkNotNull(value)
    }

    companion object {
        internal fun ok(output: SigningOutput<SigningInstructions>): SignResult = SignResult(output, null)

        internal fun err(error: SigningError): SignResult = SignResult(null, error)
    }
}

/**
 * Produces a signature for the given [request] and returns instructions
 * that can be used to apply that signature to an HTTP request.
 */
fun sign(
    request: SignableRequest,
    params: SigningParams,
): SignResult =
    when (params.settings().signatureLocation) {
        SignatureLocation.Headers -> {
            val headerOut = calculateSigningHeaders(request, params)
            if (headerOut.error != null) {
                SignResult.err(headerOut.error)
            } else {
                val (signingHeaders, signature) = checkNotNull(headerOut.value).intoParts()
                SignResult.ok(
                    SigningOutput.new(
                        SigningInstructions(signingHeaders, emptyList()),
                        signature,
                    ),
                )
            }
        }

        SignatureLocation.QueryParams -> {
            val paramOut = calculateSigningParams(request, params)
            if (paramOut.error != null) {
                SignResult.err(paramOut.error)
            } else {
                SignResult.ok(
                    SigningOutput.new(
                        SigningInstructions(emptyList(), checkNotNull(paramOut.params)),
                        checkNotNull(paramOut.signature),
                    ),
                )
            }
        }
    }

private class CalculatedQueryResult(
    val params: List<QueryParam>?,
    val signature: String?,
    val error: SigningError?,
)

private class CalculatedHeadersResult(
    val value: SigningOutput<List<Header>>?,
    val error: SigningError?,
)

private fun calculateSigningParams(
    request: SignableRequest,
    params: SigningParams,
): CalculatedQueryResult {
    val credsLookup = params.credentials()
    val creds = credsLookup.credentials ?: return CalculatedQueryResult(null, null, credsLookup.error)

    val creqResult = CanonicalRequest.from(request, params)
    if (creqResult.error != null) {
        return CalculatedQueryResult(null, null, SigningError.from(creqResult.error))
    }
    val creq = checkNotNull(creqResult.value)
    val encodedCreq = sha256HexString(creq.toString().encodeToByteArray())

    val v4 = params.v4Params
    val stringToSign = StringToSign.newV4(v4.time, v4.region, v4.name, encodedCreq).toString()
    val signingKey = generateSigningKey(creds.secretAccessKey(), v4.time, v4.region, v4.name)
    val signature = calculateSignature(signingKey, stringToSign.encodeToByteArray())

    val values = checkNotNull(creq.values.intoQueryParams()) { "signing with query" }
    val signingParams = ArrayList<QueryParam>(7)
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_ALGORITHM, values.algorithm))
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_CREDENTIAL, values.credential))
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_DATE, values.dateTime))
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_EXPIRES, values.expires))
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_SIGNED_HEADERS, values.signedHeaders.asStr()))
    signingParams.add(QueryParam(CanonicalParamConstants.X_AMZ_SIGNATURE, signature))

    val securityToken = creds.sessionToken()
    if (securityToken != null) {
        val tokenOverride = params.settings().sessionTokenNameOverride
        signingParams.add(
            QueryParam(
                tokenOverride ?: CanonicalParamConstants.X_AMZ_SECURITY_TOKEN,
                securityToken,
            ),
        )
    }

    return CalculatedQueryResult(signingParams, signature, null)
}

/**
 * Calculates the signature headers that need to be added to the given [request].
 */
private fun calculateSigningHeaders(
    request: SignableRequest,
    params: SigningParams,
): CalculatedHeadersResult {
    val credsLookup = params.credentials()
    val creds = credsLookup.credentials ?: return CalculatedHeadersResult(null, credsLookup.error)

    // Step 1: Create canonical request.
    val creqResult = CanonicalRequest.from(request, params)
    if (creqResult.error != null) {
        return CalculatedHeadersResult(null, SigningError.from(creqResult.error))
    }
    val creq = checkNotNull(creqResult.value)
    // Step 2: Create string to sign.
    val encodedCreq = sha256HexString(creq.toString().encodeToByteArray())
    val headers = ArrayList<Header>(4)

    val v4 = params.v4Params
    val sts = StringToSign.newV4(v4.time, v4.region, v4.name, encodedCreq)

    // Step 3: Calculate signature.
    val signingKey = generateSigningKey(creds.secretAccessKey(), v4.time, v4.region, v4.name)
    val signature = calculateSignature(signingKey, sts.toString().encodeToByteArray())

    // Step 4: Add signature to request.
    val values = checkNotNull(creq.values.asHeaders()) { "signing with headers" }
    addHeader(headers, CanonicalHeaderConstants.X_AMZ_DATE, values.dateTime, false)
    headers.add(
        Header(
            key = "authorization",
            headerValue =
                buildAuthorizationHeader(
                    accessKey = creds.accessKeyId(),
                    creq = creq,
                    sts = sts,
                    signature = signature,
                    signatureVersion = SignatureVersion.V4,
                ),
            isSensitive = false,
        ),
    )
    if (v4.settings.payloadChecksumKind == PayloadChecksumKind.XAmzSha256) {
        addHeader(headers, CanonicalHeaderConstants.X_AMZ_CONTENT_SHA_256, values.contentSha256, false)
    }

    val securityToken = creds.sessionToken()
    if (securityToken != null) {
        val tokenOverride = v4.settings.sessionTokenNameOverride
        addHeader(
            headers,
            tokenOverride ?: CanonicalHeaderConstants.X_AMZ_SECURITY_TOKEN,
            securityToken,
            true,
        )
    }

    return CalculatedHeadersResult(SigningOutput.new(headers, signature), null)
}

internal fun addHeader(
    map: MutableList<Header>,
    key: String,
    value: String,
    sensitive: Boolean,
) {
    map.add(Header(key = key, headerValue = value, isSensitive = sensitive))
}

private fun buildAuthorizationHeader(
    accessKey: String,
    creq: CanonicalRequest,
    sts: StringToSign,
    signature: String,
    signatureVersion: SignatureVersion,
): String {
    val scope =
        when (signatureVersion) {
            SignatureVersion.V4 -> sts.scope.toString()
            SignatureVersion.V4a -> sts.scope.v4aDisplay()
        }
    return "${sts.algorithm} Credential=$accessKey/$scope, SignedHeaders=${creq.values.signedHeaders().asStr()}, Signature=$signature"
}
