/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/url_escape.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.http.uri.Uri

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

internal fun percentEncodePath(value: String): String {
    val bytes = value.encodeToByteArray()
    val sb = StringBuilder(bytes.size)
    for (b in bytes) {
        val c = b.toInt().toChar()
        if (isUnreservedByte(c) || c == '/') {
            sb.append(c)
        } else {
            appendPercentEncodedByte(sb, b)
        }
    }
    return sb.toString()
}

internal fun percentEncodeQueryComponent(value: String): String {
    val bytes = value.encodeToByteArray()
    val sb = StringBuilder(bytes.size)
    for (b in bytes) {
        val c = b.toInt().toChar()
        if (isUnreservedByte(c)) {
            sb.append(c)
        } else {
            appendPercentEncodedByte(sb, b)
        }
    }
    return sb.toString()
}

private fun isUnreservedByte(c: Char): Boolean =
    c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~'

private fun appendPercentEncodedByte(
    sb: StringBuilder,
    byte: Byte,
) {
    val unsigned = byte.toInt() and 0xFF
    sb.append('%')
    sb.append(HEX_CHARS[unsigned ushr 4])
    sb.append(HEX_CHARS[unsigned and 0x0F])
}

internal data class DecodedQueryPair(
    val key: String,
    val value: String,
)

/**
 * Parses an `application/x-www-form-urlencoded` query string in WHATWG form-urlencoded order.
 */
internal fun parseFormUrlEncoded(query: String): List<DecodedQueryPair> {
    if (query.isEmpty()) {
        return emptyList()
    }
    val pairs = ArrayList<DecodedQueryPair>()
    var start = 0
    while (start <= query.length) {
        val ampIdx = query.indexOf('&', start)
        val end = if (ampIdx == -1) query.length else ampIdx
        if (end > start) {
            val segment = query.substring(start, end)
            val eqIdx = segment.indexOf('=')
            if (eqIdx == -1) {
                pairs.add(DecodedQueryPair(formUrlDecode(segment), ""))
            } else {
                val rawKey = segment.substring(0, eqIdx)
                val rawValue = segment.substring(eqIdx + 1)
                pairs.add(DecodedQueryPair(formUrlDecode(rawKey), formUrlDecode(rawValue)))
            }
        }
        if (ampIdx == -1) {
            break
        }
        start = ampIdx + 1
    }
    return pairs
}

private fun formUrlDecode(input: String): String {
    val rawBytes = input.encodeToByteArray()
    val out = ByteArray(rawBytes.size)
    var outLen = 0
    var i = 0
    while (i < rawBytes.size) {
        val b = rawBytes[i].toInt() and 0xFF
        if (b == '+'.code) {
            out[outLen++] = ' '.code.toByte()
            i += 1
        } else if (b == '%'.code && i + 2 < rawBytes.size) {
            val hi = hexDigitValue(rawBytes[i + 1].toInt() and 0xFF)
            val lo = hexDigitValue(rawBytes[i + 2].toInt() and 0xFF)
            if (hi >= 0 && lo >= 0) {
                out[outLen++] = ((hi shl 4) or lo).toByte()
                i += 3
            } else {
                out[outLen++] = rawBytes[i]
                i += 1
            }
        } else {
            out[outLen++] = rawBytes[i]
            i += 1
        }
    }
    return out.decodeToString(0, outLen)
}

private fun hexDigitValue(byte: Int): Int =
    when (byte) {
        in '0'.code..'9'.code -> byte - '0'.code
        in 'a'.code..'f'.code -> byte - 'a'.code + 10
        in 'A'.code..'F'.code -> byte - 'A'.code + 10
        else -> -1
    }

/**
 * Query string builder mirroring Smithy HTTP query writer behavior.
 */
internal class QueryWriter(
    private val baseUri: Uri,
) {
    private val encodedSegments = ArrayList<String>()

    init {
        val existing = baseUri.query()
        if (!existing.isNullOrEmpty()) {
            for (part in existing.split('&')) {
                if (part.isNotEmpty()) {
                    encodedSegments.add(part)
                }
            }
        }
    }

    fun clearParams() {
        encodedSegments.clear()
    }

    fun insert(
        key: String,
        value: String,
    ) {
        insertEncoded(percentEncodeQueryComponent(key), percentEncodeQueryComponent(value))
    }

    fun insertEncoded(
        encodedKey: String,
        encodedValue: String,
    ) {
        encodedSegments.add("$encodedKey=$encodedValue")
    }

    fun buildQuery(): String = encodedSegments.joinToString("&")

    fun buildUri(): Uri {
        val queryStr = buildQuery()
        val path = baseUri.path()
        val newPathAndQuery =
            if (queryStr.isEmpty()) {
                path
            } else {
                "$path?$queryStr"
            }
        val builder = Uri.builder()
        val scheme = baseUri.scheme()
        if (scheme != null) {
            builder.scheme(scheme)
        }
        val authority = baseUri.authority()
        if (authority != null) {
            builder.authority(authority)
        }
        builder.pathAndQuery(newPathAndQuery)
        return builder.build().getOrThrow()
    }

    companion object {
        fun newFromString(uriString: String): QueryWriter = QueryWriter(Uri.tryFrom(uriString).getOrThrow())
    }
}
