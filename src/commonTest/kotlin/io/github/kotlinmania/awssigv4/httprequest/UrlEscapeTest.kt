/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests http_request/url_escape.rs
package io.github.kotlinmania.awssigv4.httprequest

import kotlin.test.Test
import kotlin.test.assertEquals

class UrlEscapeTest {
    @Test
    fun preservesUnreservedAndSlash() {
        val input = "abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/0123456789/-_.~"
        assertEquals(input, percentEncodePath(input))
    }

    @Test
    fun encodesSpacesAndSpecialCharacters() {
        assertEquals("foo%20bar", percentEncodePath("foo bar"))
        assertEquals("foo%25bar", percentEncodePath("foo%bar"))
        assertEquals("foo%40bar%3Abaz", percentEncodePath("foo@bar:baz"))
        assertEquals("%2B%3D%26%3F%23", percentEncodePath("+=&?#"))
    }

    @Test
    fun preservesEmptyAndForwardSlashes() {
        assertEquals("", percentEncodePath(""))
        assertEquals("/", percentEncodePath("/"))
        assertEquals("///", percentEncodePath("///"))
        assertEquals("/a/b/c/", percentEncodePath("/a/b/c/"))
    }
}
