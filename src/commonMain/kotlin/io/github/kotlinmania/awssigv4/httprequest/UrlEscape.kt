/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/url_escape.rs
package io.github.kotlinmania.awssigv4.httprequest

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

internal fun percentEncodePath(value: String): String {
    val bytes = value.encodeToByteArray()
    val sb = StringBuilder(bytes.size)
    for (b in bytes) {
        val c = b.toInt().toChar()
        if (c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            sb.append(c)
        } else {
            val unsigned = b.toInt() and 0xFF
            sb.append('%')
            sb.append(HEX_CHARS[unsigned ushr 4])
            sb.append(HEX_CHARS[unsigned and 0x0F])
        }
    }
    return sb.toString()
}
