/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package io.github.kotlinmania.awssigv4

import kotlin.test.Test
import kotlin.test.assertEquals

class SignatureVersionAndOutputTest {
    @Test
    fun signatureVersionDisplay() {
        assertEquals("SigV4", SignatureVersion.V4.toString())
        assertEquals("SigV4a", SignatureVersion.V4a.toString())
    }

    @Test
    fun signingOutputPropertiesAndParts() {
        val output = SigningOutput.new("payload", "0123456789abcdef")
        assertEquals("payload", output.output())
        assertEquals("0123456789abcdef", output.signature())

        val (payload, sig) = output.intoParts()
        assertEquals("payload", payload)
        assertEquals("0123456789abcdef", sig)
    }
}
