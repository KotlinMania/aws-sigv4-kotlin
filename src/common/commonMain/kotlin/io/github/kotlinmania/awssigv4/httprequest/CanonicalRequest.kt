/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/canonical_request.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awssigv4.SignatureVersion
import io.github.kotlinmania.awssigv4.formatDate
import io.github.kotlinmania.awssigv4.formatDateTime
import io.github.kotlinmania.awssigv4.sign.v4.sha256HexString
import io.github.kotlinmania.http.header.HOST
import io.github.kotlinmania.http.header.HeaderName
import io.github.kotlinmania.http.uri.Port
import io.github.kotlinmania.http.uri.Scheme
import io.github.kotlinmania.http.uri.Uri
import kotlin.time.Instant

internal object CanonicalHeaderConstants {
    const val X_AMZ_CONTENT_SHA_256: String = "x-amz-content-sha256"
    const val X_AMZ_DATE: String = "x-amz-date"
    const val X_AMZ_SECURITY_TOKEN: String = "x-amz-security-token"
    const val X_AMZ_USER_AGENT: String = "x-amz-user-agent"
    const val X_AMZ_CHECKSUM_MODE: String = "x-amz-checksum-mode"
}

internal object CanonicalParamConstants {
    const val X_AMZ_ALGORITHM: String = "X-Amz-Algorithm"
    const val X_AMZ_CREDENTIAL: String = "X-Amz-Credential"
    const val X_AMZ_DATE: String = "X-Amz-Date"
    const val X_AMZ_EXPIRES: String = "X-Amz-Expires"
    const val X_AMZ_SECURITY_TOKEN: String = "X-Amz-Security-Token"
    const val X_AMZ_SIGNED_HEADERS: String = "X-Amz-SignedHeaders"
    const val X_AMZ_SIGNATURE: String = "X-Amz-Signature"
}

internal const val HMAC_256: String = "AWS4-HMAC-SHA256"

private const val UNSIGNED_PAYLOAD: String = "UNSIGNED-PAYLOAD"
private const val STREAMING_UNSIGNED_PAYLOAD_TRAILER: String = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

/**
 * Validated HTTP header value matching RFC 7230 / `http` crate byte rules:
 * horizontal tab (`0x09`) or any byte in `0x20..0xFF` excluding `0x7F` (DEL).
 */
internal class ValidatedHeaderValue private constructor(
    val value: String,
    var sensitive: Boolean = false,
) {
    fun asStr(): String = value

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ValidatedHeaderValue) return false
        return value == other.value
    }

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = if (sensitive) "Sensitive" else value

    companion object {
        fun fromStr(raw: String): CanonicalHeaderValueResult {
            val bytes = raw.encodeToByteArray()
            for (b in bytes) {
                val u = b.toInt() and 0xFF
                val valid = u == 0x09 || (u >= 32 && u != 127)
                if (!valid) {
                    return CanonicalHeaderValueResult(
                        null,
                        CanonicalRequestError.invalidHeaderValue("invalid header value byte: $u"),
                    )
                }
            }
            return CanonicalHeaderValueResult(ValidatedHeaderValue(raw), null)
        }
    }
}

internal class CanonicalHeaderValueResult(
    val value: ValidatedHeaderValue?,
    val error: CanonicalRequestError?,
) {
    fun isOk(): Boolean = error == null
}

/**
 * Multi-map of validated HTTP headers keyed by canonical lowercase [HeaderName].
 */
internal class CanonicalHeaderMap {
    private val map = LinkedHashMap<HeaderName, MutableList<ValidatedHeaderValue>>()

    fun append(
        name: HeaderName,
        value: ValidatedHeaderValue,
    ) {
        val list = map.getOrPut(name) { ArrayList() }
        list.add(value)
    }

    fun insert(
        name: HeaderName,
        value: ValidatedHeaderValue,
    ) {
        val list = ArrayList<ValidatedHeaderValue>(1)
        list.add(value)
        map[name] = list
    }

    fun insertStatic(
        nameStr: String,
        value: ValidatedHeaderValue,
    ): CanonicalRequestError? {
        val parsed = HeaderName.fromStr(nameStr.lowercase())
        if (parsed.isFailure()) {
            return CanonicalRequestError.invalidHeaderName(parsed.error)
        }
        insert(checkNotNull(parsed.value), value)
        return null
    }

    fun get(name: HeaderName): ValidatedHeaderValue? = map[name]?.firstOrNull()

    fun getByName(nameStr: String): String? {
        val parsed = HeaderName.fromStr(nameStr.lowercase())
        val key = parsed.value ?: return null
        return map[key]?.firstOrNull()?.asStr()
    }

    fun getAll(name: HeaderName): List<ValidatedHeaderValue> = map[name].orEmpty()

    fun keys(): Set<HeaderName> = map.keys

    fun size(): Int = map.size

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanonicalHeaderMap) return false
        return map == other.map
    }

    override fun hashCode(): Int = map.hashCode()
}

internal data class HeaderValues(
    val contentSha256: String,
    val dateTime: String,
    val securityToken: String?,
    val signedHeaders: SignedHeaders,
)

internal data class QueryParamValues(
    val algorithm: String,
    val contentSha256: String,
    val credential: String,
    val dateTime: String,
    val expires: String,
    val securityToken: String?,
    val signedHeaders: SignedHeaders,
)

internal sealed class SignatureValues {
    data class Headers(
        val values: HeaderValues,
    ) : SignatureValues()

    data class QueryParams(
        val values: QueryParamValues,
    ) : SignatureValues()

    fun signedHeaders(): SignedHeaders =
        when (this) {
            is Headers -> values.signedHeaders
            is QueryParams -> values.signedHeaders
        }

    fun contentSha256(): String =
        when (this) {
            is Headers -> values.contentSha256
            is QueryParams -> values.contentSha256
        }

    fun asHeaders(): HeaderValues? =
        when (this) {
            is Headers -> values
            is QueryParams -> null
        }

    fun intoQueryParams(): QueryParamValues? =
        when (this) {
            is QueryParams -> values
            is Headers -> null
        }
}

internal class CanonicalRequestResult(
    val value: CanonicalRequest?,
    val error: CanonicalRequestError?,
) {
    fun getOrThrow(): CanonicalRequest {
        val err = error
        if (err != null) {
            error("CanonicalRequest failed: ${err.message}")
        }
        return checkNotNull(value)
    }
}

private class HeadersComputationResult(
    val signedHeaders: List<CanonicalHeaderName>?,
    val canonicalHeaders: CanonicalHeaderMap?,
    val error: CanonicalRequestError?,
)

internal class CanonicalRequest(
    val method: String,
    val path: String,
    val params: String?,
    val headers: CanonicalHeaderMap,
    val values: SignatureValues,
) {
    fun headerValuesFor(key: HeaderName): String =
        headers.getAll(key).joinToString(",") { it.asStr() }

    fun headerValuesFor(keyStr: String): String {
        val parsed = HeaderName.fromStr(keyStr.lowercase())
        val key = parsed.getOrThrow()
        return headerValuesFor(key)
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append(method).append('\n')
        sb.append(path).append('\n')
        sb.append(params.orEmpty()).append('\n')
        for (header in values.signedHeaders().headers) {
            sb.append(header.name.asStr()).append(':')
            sb.append(headerValuesFor(header.name)).append('\n')
        }
        sb.append('\n')
        sb.append(values.signedHeaders().asStr()).append('\n')
        sb.append(values.contentSha256())
        return sb.toString()
    }

    companion object {
        /**
         * Constructs a [CanonicalRequest] from a [SignableRequest] and [SigningParams].
         */
        fun from(
            req: SignableRequest,
            params: SigningParams,
        ): CanonicalRequestResult {
            val credsLookup = params.credentials()
            val creds =
                credsLookup.credentials
                    ?: return CanonicalRequestResult(null, CanonicalRequestError.unsupportedIdentityType())

            val settings = params.settings()
            val rawPath = req.uri().path()
            val normalizedPath =
                when (settings.uriPathNormalizationMode) {
                    UriPathNormalizationMode.Enabled -> normalizeUriPath(rawPath)
                    UriPathNormalizationMode.Disabled -> rawPath
                }
            val encodedPath =
                when (settings.percentEncodingMode) {
                    PercentEncodingMode.Double -> percentEncodePath(normalizedPath)
                    PercentEncodingMode.Single -> normalizedPath
                }
            val payloadHash = payloadHash(req.body())
            val dateTime = formatDateTime(params.time())

            val headersComputed = computeHeaders(req, params, payloadHash, dateTime)
            if (headersComputed.error != null) {
                return CanonicalRequestResult(null, headersComputed.error)
            }
            val signedHeaders = SignedHeaders.new(checkNotNull(headersComputed.signedHeaders))
            val canonicalHeaders = checkNotNull(headersComputed.canonicalHeaders)

            val securityToken =
                when (settings.sessionTokenMode) {
                    SessionTokenMode.Include -> creds.sessionToken()
                    SessionTokenMode.Exclude -> null
                }

            val signatureValues =
                when (settings.signatureLocation) {
                    SignatureLocation.Headers -> {
                        SignatureValues.Headers(
                            HeaderValues(
                                contentSha256 = payloadHash,
                                dateTime = dateTime,
                                securityToken = securityToken,
                                signedHeaders = signedHeaders,
                            ),
                        )
                    }

                    SignatureLocation.QueryParams -> {
                        val v4 = params.v4Params
                        val credential =
                            "${creds.accessKeyId()}/${formatDate(v4.time)}/${v4.region}/${v4.name}/aws4_request"
                        val expiresDuration =
                            checkNotNull(settings.expiresIn) {
                                "presigning requires expiresIn"
                            }
                        SignatureValues.QueryParams(
                            QueryParamValues(
                                algorithm = params.algorithm(),
                                contentSha256 = payloadHash,
                                credential = credential,
                                dateTime = dateTime,
                                expires = expiresDuration.inWholeSeconds.toString(),
                                securityToken = securityToken,
                                signedHeaders = signedHeaders,
                            ),
                        )
                    }
                }

            val creq =
                CanonicalRequest(
                    method = req.method(),
                    path = encodedPath,
                    params = computeParams(req.uri(), signatureValues, settings),
                    headers = canonicalHeaders,
                    values = signatureValues,
                )
            return CanonicalRequestResult(creq, null)
        }

        private fun computeHeaders(
            req: SignableRequest,
            params: SigningParams,
            payloadHash: String,
            dateTime: String,
        ): HeadersComputationResult {
            val canonicalHeaders = CanonicalHeaderMap()
            for (header in req.headers()) {
                val parsedName = HeaderName.fromStr(header.name.lowercase())
                if (parsedName.isFailure()) {
                    return HeadersComputationResult(
                        null,
                        null,
                        CanonicalRequestError.invalidHeaderName(parsedName.error),
                    )
                }
                val normalizedVal = normalizeHeaderValue(header.value)
                if (normalizedVal.error != null) {
                    return HeadersComputationResult(null, null, normalizedVal.error)
                }
                canonicalHeaders.append(
                    checkNotNull(parsedName.value),
                    checkNotNull(normalizedVal.value),
                )
            }

            insertHostHeader(canonicalHeaders, req.uri())

            val settings = params.settings()
            val tokenOverride = settings.sessionTokenNameOverride
            val tokenHeaderName = tokenOverride ?: CanonicalHeaderConstants.X_AMZ_SECURITY_TOKEN

            if (settings.signatureLocation == SignatureLocation.Headers) {
                val credsLookup = params.credentials()
                val creds =
                    credsLookup.credentials
                        ?: return HeadersComputationResult(
                            null,
                            null,
                            CanonicalRequestError.unsupportedIdentityType(),
                        )
                insertDateHeader(canonicalHeaders, dateTime)

                val securityToken = creds.sessionToken()
                if (securityToken != null) {
                    val secVal = ValidatedHeaderValue.fromStr(securityToken)
                    if (secVal.error != null) {
                        return HeadersComputationResult(null, null, secVal.error)
                    }
                    val validatedSec = checkNotNull(secVal.value)
                    validatedSec.sensitive = true
                    val nameErr = canonicalHeaders.insertStatic(tokenHeaderName, validatedSec)
                    if (nameErr != null) {
                        return HeadersComputationResult(null, null, nameErr)
                    }
                }

                if (settings.payloadChecksumKind == PayloadChecksumKind.XAmzSha256) {
                    val hashVal = ValidatedHeaderValue.fromStr(payloadHash)
                    if (hashVal.error != null) {
                        return HeadersComputationResult(null, null, hashVal.error)
                    }
                    canonicalHeaders.insert(
                        HeaderName.fromStatic(CanonicalHeaderConstants.X_AMZ_CONTENT_SHA_256),
                        checkNotNull(hashVal.value),
                    )
                }
            }

            val tokenHeaderParsed = HeaderName.fromStr(tokenHeaderName.lowercase()).value
            val excludedHeaders = settings.excludedHeaders
            val signedHeaders = ArrayList<CanonicalHeaderName>(canonicalHeaders.size())
            for (name in canonicalHeaders.keys()) {
                if (excludedHeaders != null && excludedHeaders.any { name.asStr() == it }) {
                    continue
                }
                if (settings.sessionTokenMode == SessionTokenMode.Exclude && tokenHeaderParsed != null && name == tokenHeaderParsed) {
                    continue
                }
                if (settings.signatureLocation == SignatureLocation.QueryParams) {
                    if (name == HeaderName.fromStatic(CanonicalHeaderConstants.X_AMZ_USER_AGENT) ||
                        name == HeaderName.fromStatic(CanonicalHeaderConstants.X_AMZ_CHECKSUM_MODE)
                    ) {
                        continue
                    }
                }
                signedHeaders.add(CanonicalHeaderName(name))
            }

            return HeadersComputationResult(signedHeaders, canonicalHeaders, null)
        }

        private fun payloadHash(body: SignableBody): String =
            when (body.kind()) {
                SignableBodyKind.Bytes -> sha256HexString(checkNotNull(body.bytesOrNull()))
                SignableBodyKind.Precomputed -> checkNotNull(body.precomputedDigestOrNull())
                SignableBodyKind.UnsignedPayload -> UNSIGNED_PAYLOAD
                SignableBodyKind.StreamingUnsignedPayloadTrailer -> STREAMING_UNSIGNED_PAYLOAD_TRAILER
            }

        private fun computeParams(
            uri: Uri,
            values: SignatureValues,
            settings: SigningSettings,
        ): String? {
            val params = ArrayList<DecodedQueryPair>()
            params.addAll(parseFormUrlEncoded(uri.query().orEmpty()))

            if (values is SignatureValues.QueryParams) {
                val qv = values.values
                params.add(DecodedQueryPair(CanonicalParamConstants.X_AMZ_DATE, qv.dateTime))
                params.add(DecodedQueryPair(CanonicalParamConstants.X_AMZ_EXPIRES, qv.expires))
                params.add(DecodedQueryPair(CanonicalParamConstants.X_AMZ_ALGORITHM, qv.algorithm))
                params.add(DecodedQueryPair(CanonicalParamConstants.X_AMZ_CREDENTIAL, qv.credential))
                params.add(DecodedQueryPair(CanonicalParamConstants.X_AMZ_SIGNED_HEADERS, qv.signedHeaders.asStr()))

                val securityToken = qv.securityToken
                if (securityToken != null) {
                    val tokenOverride = settings.sessionTokenNameOverride
                    params.add(
                        DecodedQueryPair(
                            tokenOverride ?: CanonicalParamConstants.X_AMZ_SECURITY_TOKEN,
                            securityToken,
                        ),
                    )
                }
            }

            // Sort on the encoded key/value pairs.
            val encodedParams =
                params
                    .map { pair ->
                        DecodedQueryPair(
                            percentEncodeQueryComponent(pair.key),
                            percentEncodeQueryComponent(pair.value),
                        )
                    }.sortedWith(compareBy<DecodedQueryPair> { it.key }.thenBy { it.value })

            val queryWriter = QueryWriter(uri)
            queryWriter.clearParams()
            for (encoded in encodedParams) {
                queryWriter.insertEncoded(encoded.key, encoded.value)
            }

            val query = queryWriter.buildQuery()
            return if (query.isEmpty()) null else query
        }

        private fun insertHostHeader(
            canonicalHeaders: CanonicalHeaderMap,
            uri: Uri,
        ): ValidatedHeaderValue {
            val existing = canonicalHeaders.get(HOST)
            if (existing != null) {
                return existing
            }
            val port = uri.port()
            val scheme = uri.scheme()
            val authority =
                checkNotNull(uri.authority()) {
                    "request uri authority must be set for signing"
                }.asStr()
            val host =
                checkNotNull(uri.host()) {
                    "request uri host must be set for signing"
                }

            val headerValueStr =
                if (isPortSchemeDefault(scheme, port)) {
                    host
                } else {
                    authority
                }
            val headerVal =
                checkNotNull(ValidatedHeaderValue.fromStr(headerValueStr).value) {
                    "endpoint must contain valid header characters"
                }
            canonicalHeaders.insert(HOST, headerVal)
            return headerVal
        }

        private fun insertDateHeader(
            canonicalHeaders: CanonicalHeaderMap,
            dateTime: String,
        ): ValidatedHeaderValue {
            val xAmzDate = HeaderName.fromStatic(CanonicalHeaderConstants.X_AMZ_DATE)
            val dateHeader =
                checkNotNull(ValidatedHeaderValue.fromStr(dateTime).value) {
                    "date is valid header value"
                }
            canonicalHeaders.insert(xAmzDate, dateHeader)
            return dateHeader
        }
    }
}

/**
 * Removes excess spaces before and after a given string, and converts multiple sequential
 * spaces (`' '`) to a single space. Non-ASCII whitespace (such as non-breaking space `\u00A0`
 * or tabs/newlines) is preserved unchanged.
 */
internal fun trimAll(text: String): String {
    val trimmed = text.trim { it == ' ' }
    var hasConsecutiveSpaces = false
    for (i in 0 until trimmed.length - 1) {
        if (trimmed[i] == ' ' && trimmed[i + 1] == ' ') {
            hasConsecutiveSpaces = true
            break
        }
    }
    if (!hasConsecutiveSpaces) {
        return trimmed
    }
    val sb = StringBuilder(trimmed.length)
    var prevWasSpace = false
    for (ch in trimmed) {
        if (ch == ' ') {
            if (!prevWasSpace) {
                sb.append(ch)
                prevWasSpace = true
            }
        } else {
            sb.append(ch)
            prevWasSpace = false
        }
    }
    return sb.toString()
}

internal fun normalizeHeaderValue(headerValue: String): CanonicalHeaderValueResult {
    val trimmedValue = trimAll(headerValue)
    return ValidatedHeaderValue.fromStr(trimmedValue)
}

internal fun isPortSchemeDefault(
    scheme: Scheme?,
    port: Port?,
): Boolean {
    if (scheme != null && port != null) {
        val s = scheme.asStr()
        val p = port.asStr()
        return (s == "http" && p == "80") || (s == "https" && p == "443")
    }
    return false
}

internal data class SignedHeaders(
    val headers: List<CanonicalHeaderName> = emptyList(),
    private val formatted: String = "",
) {
    fun asStr(): String = formatted

    override fun toString(): String = formatted

    companion object {
        fun new(headers: List<CanonicalHeaderName>): SignedHeaders {
            val sorted = headers.sorted()
            val formatted = sorted.joinToString(";") { it.name.asStr() }
            return SignedHeaders(sorted, formatted)
        }
    }
}

internal class CanonicalHeaderName(
    val name: HeaderName,
) : Comparable<CanonicalHeaderName> {
    override fun compareTo(other: CanonicalHeaderName): Int = name.asStr().compareTo(other.name.asStr())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanonicalHeaderName) return false
        return name == other.name
    }

    override fun hashCode(): Int = name.hashCode()

    override fun toString(): String = name.asStr()
}

internal data class SigningScope(
    val time: Instant,
    val region: String,
    val service: String,
) {
    fun v4aDisplay(): String = "${formatDate(time)}/$service/aws4_request"

    override fun toString(): String = "${formatDate(time)}/$region/$service/aws4_request"
}

internal data class StringToSign(
    val algorithm: String,
    val scope: SigningScope,
    val time: Instant,
    val region: String,
    val service: String,
    val hashedCreq: String,
    private val signatureVersion: SignatureVersion,
) {
    override fun toString(): String {
        val scopeStr =
            when (signatureVersion) {
                SignatureVersion.V4 -> scope.toString()
                SignatureVersion.V4a -> scope.v4aDisplay()
            }
        return "$algorithm\n${formatDateTime(time)}\n$scopeStr\n$hashedCreq"
    }

    companion object {
        fun newV4(
            time: Instant,
            region: String,
            service: String,
            hashedCreq: String,
        ): StringToSign {
            val scope = SigningScope(time = time, region = region, service = service)
            return StringToSign(
                algorithm = HMAC_256,
                scope = scope,
                time = time,
                region = region,
                service = service,
                hashedCreq = hashedCreq,
                signatureVersion = SignatureVersion.V4,
            )
        }
    }
}
