/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/uri_path_normalization.rs
package io.github.kotlinmania.awssigv4.httprequest

// Normalize `uriPath` according to
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
internal fun normalizeUriPath(uriPath: String): String {
    // If the absolute path is empty, use a forward slash (/).
    if (uriPath.isEmpty()) {
        return "/"
    }

    // The canonical URI is the URI-encoded version of the _absolute_ path component of the URI.
    val result = if (uriPath.startsWith('/')) uriPath else "/$uriPath"

    if (!result.contains('.') && !result.contains("//")) {
        return result
    }

    return normalizePathSegment(result)
}

// Implement 5.2.4. Remove Dot Segments in https://www.rfc-editor.org/rfc/rfc3986
//
// The function assumes that `uriPath` is an absolute path,
// starting with a forward slash.
private fun normalizePathSegment(uriPath: String): String {
    val numberOfSlashes = uriPath.count { it == '/' }
    val normalized = ArrayList<String>(numberOfSlashes + 1)

    for (segment in uriPath.split('/')) {
        when (segment) {
            // Segments that are empty or contain only a single period should not be preserved.
            "", "." -> {}
            ".." -> if (normalized.isNotEmpty()) normalized.removeAt(normalized.lastIndex)
            else -> normalized.add(segment)
        }
    }

    var result = normalized.joinToString("/")

    // Even though `uriPath` starts with a `/`, that may not be the case for `result`.
    // An example of this is `uriPath` being "/../foo" where the corresponding `result`
    // will be "foo".
    if (!result.startsWith('/')) {
        result = "/$result"
    }

    // If `uriPath` is "/foo/bar/.", normalizing it should be "/foo/bar/". However,
    // the logic so far only makes `result` "/foo/bar", without the trailing slash.
    // The condition below ensures that the trailing slash is appended to `result`
    // if `uriPath` ends with a slash, per the RFC, but `result` does not.
    if (endsWithSlash(uriPath) && !result.endsWith('/')) {
        result += '/'
    }

    return result
}

private fun endsWithSlash(uriPath: String): Boolean =
    listOf("/", "/.", "/./", "/..", "/../").any { uriPath.endsWith(it) }
