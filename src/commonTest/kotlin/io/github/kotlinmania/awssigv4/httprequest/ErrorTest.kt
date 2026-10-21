/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests http_request/error.rs
package io.github.kotlinmania.awssigv4.httprequest

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

class ErrorTest {
    @Test
    fun signingErrorUnsupportedIdentityType() {
        val err = SigningError.unsupportedIdentityType()
        assertEquals("only 'AWS credentials' are supported for signing", err.message)
        assertEquals("only 'AWS credentials' are supported for signing", err.toString())
        assertNull(err.cause)
    }

    @Test
    fun signingErrorFromCanonicalRequestError() {
        val canonicalErr = CanonicalRequestError.unsupportedIdentityType()
        val signingErr = SigningError.from(canonicalErr)
        assertEquals("failed to create canonical request", signingErr.message)
        assertEquals("failed to create canonical request", signingErr.toString())
        assertSame(canonicalErr, signingErr.cause)
    }

    @Test
    fun canonicalRequestErrorVariants() {
        val unsupported = CanonicalRequestError.unsupportedIdentityType()
        assertEquals("only AWS credentials are supported for signing", unsupported.message)
        assertNull(unsupported.cause)

        val dummyCause = IllegalArgumentException("boom")

        val invalidHeaderName = CanonicalRequestError.invalidHeaderName(dummyCause)
        assertEquals("invalid header name", invalidHeaderName.message)
        assertSame(dummyCause, invalidHeaderName.cause)

        val invalidHeaderValue = CanonicalRequestError.invalidHeaderValue(dummyCause)
        assertEquals("invalid header value", invalidHeaderValue.message)
        assertSame(dummyCause, invalidHeaderValue.cause)

        val invalidUri = CanonicalRequestError.invalidUri(dummyCause)
        assertEquals("the uri was invalid", invalidUri.message)
        assertSame(dummyCause, invalidUri.cause)
    }
}
