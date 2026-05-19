/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/uri_path_normalization.rs
package io.github.kotlinmania.awssigv4.httprequest

import kotlin.test.Test
import kotlin.test.assertEquals

class UriPathNormalizationTest {
    @Test
    fun normalizeUriPathShouldNotModifyInputContainingJustAForwardSlash() {
        assertEquals("/", normalizeUriPath("/"))
    }

    @Test
    fun normalizeUriPathShouldAddAForwardSlashWhenInputIsEmpty() {
        assertEquals("/", normalizeUriPath(""))
    }

    @Test
    fun normalizeUriPathShouldNotModifySingleNonDotSegmentStartingWithASingleForwardSlash() {
        assertEquals("/foo", normalizeUriPath("/foo"))
    }

    @Test
    fun normalizeUriPathShouldPrependForwardSlashWhenInputIsRelative() {
        assertEquals("/foo", normalizeUriPath("foo"))
    }

    @Test
    fun normalizeUriPathShouldNotModifyMultipleNonDotSegmentsStartingWithASingleForwardSlash() {
        assertEquals("/foo/bar", normalizeUriPath("/foo/bar"))
    }

    @Test
    fun normalizeUriPathShouldNotModifyMultipleNonDotSegmentsWithATrailingForwardSlash() {
        assertEquals("/foo/bar/", normalizeUriPath("/foo/bar/"))
    }

    // 2.A in https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    @Test
    fun normalizeUriPathShouldRemoveALeadingDotFromInput() {
        // The expected value is "/" rather than "" because if the absolute path is empty,
        // we use a forward slash.
        assertEquals("/", normalizeUriPath("./"))

        assertEquals("/foo", normalizeUriPath("./foo"))
    }

    // 2.A in https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    @Test
    fun normalizeUriPathShouldRemoveLeadingDoubleDotsFromInput() {
        // The expected value is "/" rather than "" because if the absolute path is empty,
        // we use a forward slash.
        assertEquals("/", normalizeUriPath("../"))

        assertEquals("/foo", normalizeUriPath("../foo"))
    }

    // 2.B in https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    @Test
    fun normalizeUriPathShouldRemoveASingelDotFromInput() {
        assertEquals("/", normalizeUriPath("/."))
        assertEquals("/", normalizeUriPath("/./"))
        assertEquals("/foo", normalizeUriPath("/./foo"))
        assertEquals("/foo/bar/", normalizeUriPath("/foo/bar/."))
        assertEquals("/foo/bar/", normalizeUriPath("/foo/bar/./"))
        assertEquals("/foo/bar/", normalizeUriPath("/foo/./bar/./"))
    }

    // 2.C in https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    @Test
    fun normalizeUriPathShouldRemoveDoubleDotsFromInput() {
        assertEquals("/", normalizeUriPath("/.."))
        assertEquals("/", normalizeUriPath("/../"))
        assertEquals("/foo", normalizeUriPath("/../foo"))
        assertEquals("/foo/", normalizeUriPath("/foo/bar/.."))
        assertEquals("/foo/", normalizeUriPath("/foo/bar/../"))
        assertEquals("/", normalizeUriPath("/foo/../bar/../"))
    }

    // 2.D in https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    @Test
    fun normalizeUriPathShouldReplaceADotSegmentWithAForwardSlash() {
        assertEquals("/", normalizeUriPath("."))
        assertEquals("/", normalizeUriPath(".."))
    }

    // Page 34 in https://www.rfc-editor.org/rfc/rfc3986
    @Test
    fun normalizeUriPathShouldBehaveAsExpectedAgainstExamplesInRfc() {
        assertEquals("/a/g", normalizeUriPath("/a/b/c/./../../g"))
        // The expected value will be absolutized.
        assertEquals("/mid/6", normalizeUriPath("mid/content=5/../6"))
    }

    // The CRT does this so I figured we should too. - Zelda
    @Test
    fun normalizeUriPathShouldMergeMultipleSubsequentSlashesIntoOne() {
        assertEquals("/foo/", normalizeUriPath("//foo//"))
    }

    @Test
    fun normalizeUriPathShouldNotRemoveDotWhenSurroundedByPercentEncodedForwardSlashes() {
        assertEquals("/foo%2F.%2Fbar", normalizeUriPath("/foo%2F.%2Fbar"))
    }
}
