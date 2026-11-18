/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests sign/v4.rs
package io.github.kotlinmania.awssigv4.sign.v4

import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.TestParsers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// benches/hmac.rs uses Criterion + ring microbenchmark harnesses; HMAC-SHA256 digest equivalence is covered below.
class V4Test {
    @Test
    fun testSignatureCalculation() {
        val secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        val creq =
            "AWS4-HMAC-SHA256\n" +
                "20150830T123600Z\n" +
                "20150830/us-east-1/iam/aws4_request\n" +
                "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        val time = TestParsers.parseDateTime("20150830T123600Z")

        val derivedKey = generateSigningKey(secret, time, "us-east-1", "iam")
        val signature = calculateSignature(derivedKey, creq.encodeToByteArray())

        val expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        assertEquals(expected, signature)
        assertEquals(expected, calculateSignatureUtf8(derivedKey, creq))
    }

    @Test
    fun signPayloadEmptyString() {
        val expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val actual = sha256HexString(ByteArray(0))
        assertEquals(expected, actual)
    }

    @Test
    fun signingParamsBuilderValidation() {
        val missingIdentity = SigningParams.builder<Unit>().build()
        assertTrue(missingIdentity.isFailure())
        assertEquals("identity is required", missingIdentity.error?.reason)

        val time = TestParsers.parseDateTime("20150830T123600Z")
        val built =
            SigningParams
                .builder<Unit>()
                .identity(SigningIdentity.forTests())
                .region("us-east-1")
                .name("iam")
                .time(time)
                .settings(Unit)
                .build()
        assertTrue(built.isSuccess())
        val params = built.getOrThrow()
        assertEquals("us-east-1", params.region())
        assertEquals("iam", params.name())
        assertEquals("AWS4-HMAC-SHA256", params.algorithm())
    }
}
