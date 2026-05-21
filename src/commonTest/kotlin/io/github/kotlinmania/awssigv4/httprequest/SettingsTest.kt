/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: ignore
// Sanity tests for the Kotlin port of http_request/settings.rs. The upstream
// settings.rs has no #[test] blocks; these tests pin the documented default
// shape of SigningSettings so unintended drift is caught.
package io.github.kotlinmania.awssigv4.httprequest

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SettingsTest {
    @Test
    fun signingSettingsDefaults() {
        val settings = SigningSettings()
        assertEquals(PercentEncodingMode.Double, settings.percentEncodingMode)
        assertEquals(PayloadChecksumKind.NoHeader, settings.payloadChecksumKind)
        assertEquals(SignatureLocation.Headers, settings.signatureLocation)
        assertNull(settings.expiresIn)
        assertEquals(UriPathNormalizationMode.Enabled, settings.uriPathNormalizationMode)
        assertEquals(SessionTokenMode.Include, settings.sessionTokenMode)
        assertNull(settings.sessionTokenNameOverride)

        val excluded = settings.excludedHeaders
        assertTrue(excluded != null && excluded.containsAll(
            listOf("authorization", "user-agent", "x-amzn-trace-id", "transfer-encoding")
        ))
    }

    @Test
    fun uriPathNormalizationModeFromBoolean() {
        assertEquals(UriPathNormalizationMode.Enabled, UriPathNormalizationMode.fromBoolean(true))
        assertEquals(UriPathNormalizationMode.Disabled, UriPathNormalizationMode.fromBoolean(false))
    }

    @Test
    fun signingSettingsIsMutable() {
        val settings = SigningSettings()
        settings.percentEncodingMode = PercentEncodingMode.Single
        settings.payloadChecksumKind = PayloadChecksumKind.XAmzSha256
        settings.signatureLocation = SignatureLocation.QueryParams
        settings.sessionTokenMode = SessionTokenMode.Exclude
        settings.uriPathNormalizationMode = UriPathNormalizationMode.Disabled
        settings.sessionTokenNameOverride = "X-My-Token"

        assertEquals(PercentEncodingMode.Single, settings.percentEncodingMode)
        assertEquals(PayloadChecksumKind.XAmzSha256, settings.payloadChecksumKind)
        assertEquals(SignatureLocation.QueryParams, settings.signatureLocation)
        assertEquals(SessionTokenMode.Exclude, settings.sessionTokenMode)
        assertEquals(UriPathNormalizationMode.Disabled, settings.uriPathNormalizationMode)
        assertEquals("X-My-Token", settings.sessionTokenNameOverride)
    }
}
