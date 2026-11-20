/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests http_request/sign.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.TestParsers
import io.github.kotlinmania.prettyassertions.assertEq
import kotlin.test.Test
import kotlin.time.Instant
import io.github.kotlinmania.awssigv4.sign.v4.SigningParams as V4SigningParams

class SignTest {
    @Test
    fun testSignUrlEscape() {
        val test = SigningSuiteTest.v4("double-encode-path")
        val params =
            V4SigningParams(
                identity = SigningIdentity.forTests(),
                region = "us-east-1",
                name = "service",
                time = TestParsers.parseDateTime("20150830T123600Z"),
                settings = SigningSettings.default(),
            ).toHttpSigningParams()

        val original = test.request()
        val signable = original.toSignableRequest()
        val out = sign(signable, params).getOrThrow()
        assertEq(
            "57d157672191bac40bae387e48bbe14b15303c001fdbb01f4abf295dccb09705",
            out.signature(),
        )

        val signed = original.asHttpRequest()
        signed.applyInstructions(out.output())

        val expected = test.signedRequest(SignatureLocation.Headers)
        assertRequestsEq(expected, signed)
    }

    @Test
    fun testSignHeadersUtf8() {
        val params =
            V4SigningParams(
                identity = SigningIdentity.forTests(),
                region = "us-east-1",
                name = "service",
                time = TestParsers.parseDateTime("20150830T123600Z"),
                settings = SigningSettings.default(),
            ).toHttpSigningParams()

        val originalHttp =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList = listOf("some-header" to "テスト"),
            )
        val original = TestRequest.fromHttpRequest(originalHttp, ByteArray(0))
        val signable = original.toSignableRequest()
        val out = sign(signable, params).getOrThrow()
        assertEq(
            "55e16b31f9bde5fd04f9d3b780dd2b5e5f11a5219001f91a8ca9ec83eaf1618f",
            out.signature(),
        )

        val signed = original.asHttpRequest()
        signed.applyInstructions(out.output())

        val expected =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList =
                    listOf(
                        "some-header" to "テスト",
                        "x-amz-date" to "20150830T123600Z",
                        "authorization" to
                            "AWS4-HMAC-SHA256 " +
                            "Credential=ANOTREAL/20150830/us-east-1/service/aws4_request, " +
                            "SignedHeaders=host;some-header;x-amz-date, " +
                            "Signature=55e16b31f9bde5fd04f9d3b780dd2b5e5f11a5219001f91a8ca9ec83eaf1618f",
                    ),
            )
        assertHttpRequestsComparableEq(expected, signed)
    }

    @Test
    fun testSignHeadersExcludingSessionToken() {
        val settings = SigningSettings(sessionTokenMode = SessionTokenMode.Exclude)
        val params =
            V4SigningParams(
                identity = SigningIdentity.forTestsWithSessionToken(),
                region = "us-east-1",
                name = "service",
                time = TestParsers.parseDateTime("20150830T123600Z"),
                settings = settings,
            ).toHttpSigningParams()

        val originalHttp =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
            )
        val original = TestRequest.fromHttpRequest(originalHttp, ByteArray(0))
        val outWithoutSessionToken = sign(original.toSignableRequest(), params).getOrThrow()
        val outWithSessionTokenButExcluded = sign(original.toSignableRequest(), params).getOrThrow()

        assertEq(
            "ab32de057edf094958d178b3c91f3c8d5c296d526b11da991cd5773d09cea560",
            outWithSessionTokenButExcluded.signature(),
        )
        assertEq(
            outWithSessionTokenButExcluded.signature(),
            outWithoutSessionToken.signature(),
        )

        val signed = original.asHttpRequest()
        signed.applyInstructions(outWithSessionTokenButExcluded.output())

        val expected =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList =
                    listOf(
                        "x-amz-date" to "20150830T123600Z",
                        "authorization" to
                            "AWS4-HMAC-SHA256 " +
                            "Credential=ANOTREAL/20150830/us-east-1/service/aws4_request, " +
                            "SignedHeaders=host;x-amz-date, " +
                            "Signature=ab32de057edf094958d178b3c91f3c8d5c296d526b11da991cd5773d09cea560",
                        "x-amz-security-token" to "notarealsessiontoken",
                    ),
            )
        assertHttpRequestsComparableEq(expected, signed)
    }

    @Test
    fun testSignHeadersSpaceTrimming() {
        val params =
            V4SigningParams(
                identity = SigningIdentity.forTests(),
                region = "us-east-1",
                name = "service",
                time = TestParsers.parseDateTime("20150830T123600Z"),
                settings = SigningSettings.default(),
            ).toHttpSigningParams()

        val originalHttp =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList = listOf("some-header" to " \u00A0test  test   "),
            )
        val original = TestRequest.fromHttpRequest(originalHttp, ByteArray(0))
        val signable = original.toSignableRequest()
        val out = sign(signable, params).getOrThrow()
        assertEq(
            "244f2a0db34c97a528f22715fe01b2417b7750c8a95c7fc104a3c48d81d84c08",
            out.signature(),
        )

        val signed = original.asHttpRequest()
        signed.applyInstructions(out.output())

        val expected =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList =
                    listOf(
                        "some-header" to " \u00A0test  test   ",
                        "x-amz-date" to "20150830T123600Z",
                        "authorization" to
                            "AWS4-HMAC-SHA256 " +
                            "Credential=ANOTREAL/20150830/us-east-1/service/aws4_request, " +
                            "SignedHeaders=host;some-header;x-amz-date, " +
                            "Signature=244f2a0db34c97a528f22715fe01b2417b7750c8a95c7fc104a3c48d81d84c08",
                    ),
            )
        assertHttpRequestsComparableEq(expected, signed)
    }

    @Test
    fun testSignHeadersNoPanic() {
        val params =
            V4SigningParams(
                identity = SigningIdentity.forTests(),
                region = "us-east-1",
                name = "foo",
                time = Instant.fromEpochSeconds(0),
                settings = SigningSettings.default(),
            ).toHttpSigningParams()

        val samples = listOf("", "ascii-value", "   spaces   ", "\u0000control", "\u007Fdel", "テスト")
        for (header in samples) {
            val reqResult =
                SignableRequest.new(
                    method = "GET",
                    uri = "https://foo.com",
                    headers = listOf(SignableHeader("x-sign-me", header)),
                    body = SignableBody.empty(),
                )
            val req = reqResult.value
            if (req != null) {
                sign(req, params)
            }
        }
    }

    @Test
    fun applySigningInstructionsHeaders() {
        val headers = ArrayList<Header>()
        addHeader(headers, "some-header", "foo", false)
        addHeader(headers, "some-other-header", "bar", false)
        val instructions = SigningInstructions(headers, emptyList())

        val request = TestHttpRequest.build(uriStr = "https://some-endpoint.some-region.amazonaws.com")
        request.applyInstructions(instructions)

        assertEq("foo", request.headers.getByName("some-header"))
        assertEq("bar", request.headers.getByName("some-other-header"))
    }

    @Test
    fun applySigningInstructionsQueryParams() {
        val params =
            listOf(
                QueryParam("some-param", "f&o?o"),
                QueryParam("some-other-param?", "bar"),
            )
        val instructions = SigningInstructions(emptyList(), params)

        val request = TestHttpRequest.build(uriStr = "https://some-endpoint.some-region.amazonaws.com/some/path")
        request.applyInstructions(instructions)

        assertEq(
            "/some/path?some-param=f%26o%3Fo&some-other-param%3F=bar",
            checkNotNull(request.uri.pathAndQuery()).toString(),
        )
    }

    @Test
    fun applySigningInstructionsQueryParamsHttp1x() {
        val params =
            listOf(
                QueryParam("some-param", "f&o?o"),
                QueryParam("some-other-param?", "bar"),
            )
        val instructions = SigningInstructions(emptyList(), params)

        val updated = instructions.applyToUriString("https://some-endpoint.some-region.amazonaws.com/some/path")
        assertEq(
            "https://some-endpoint.some-region.amazonaws.com/some/path?some-param=f%26o%3Fo&some-other-param%3F=bar",
            updated,
        )
    }

    @Test
    fun testDebugSignableBody() {
        val bytesBody = SignableBody.bytes("hello signable body".encodeToByteArray())
        assertEq(
            "Bytes(\"** REDACTED **. To print 19 bytes of raw data, set environment variable `LOG_SIGNABLE_BODY=true`\")",
            bytesBody.toString(),
        )
        assertEq(
            "Bytes([104, 101, 108, 108, 111, 32, 115, 105, 103, 110, 97, 98, 108, 101, 32, 98, 111, 100, 121])",
            bytesBody.debugString(true),
        )

        assertEq("UnsignedPayload", SignableBody.unsignedPayload().toString())
        assertEq("Precomputed(\"precomputed\")", SignableBody.precomputed("precomputed").toString())
        assertEq("StreamingUnsignedPayloadTrailer", SignableBody.streamingUnsignedPayloadTrailer().toString())
    }

    // SigV4 test suite

    @Test
    fun testGetHeaderKeyDuplicate() = runTestSuiteV4("get-header-key-duplicate")

    // Unported: multiline HTTP header folding is deprecated in RFC 7230 and rejected by HTTP request parsing.

    @Test
    fun testGetHeaderValueOrder() = runTestSuiteV4("get-header-value-order")

    @Test
    fun testGetHeaderValueTrim() = runTestSuiteV4("get-header-value-trim")

    @Test
    fun testGetRelativeNormalized() = runTestSuiteV4("get-relative-normalized")

    @Test
    fun testGetRelativeRelativeNormalized() = runTestSuiteV4("get-relative-relative-normalized")

    @Test
    fun testGetRelativeRelativeUnnormalized() = runTestSuiteV4("get-relative-relative-unnormalized")

    @Test
    fun testGetRelativeUnnormalized() = runTestSuiteV4("get-relative-unnormalized")

    @Test
    fun testGetSlashDotSlashNormalized() = runTestSuiteV4("get-slash-dot-slash-normalized")

    @Test
    fun testGetSlashDotSlashUnnormalized() = runTestSuiteV4("get-slash-dot-slash-unnormalized")

    @Test
    fun testGetSlashNormalized() = runTestSuiteV4("get-slash-normalized")

    @Test
    fun testGetSlashPointlessDotNormalized() = runTestSuiteV4("get-slash-pointless-dot-normalized")

    @Test
    fun testGetSlashPointlessDotUnnormalized() = runTestSuiteV4("get-slash-pointless-dot-unnormalized")

    @Test
    fun testGetSlashUnnormalized() = runTestSuiteV4("get-slash-unnormalized")

    @Test
    fun testGetSlashesNormalized() = runTestSuiteV4("get-slashes-normalized")

    @Test
    fun testGetSlashesUnnormalized() = runTestSuiteV4("get-slashes-unnormalized")

    // Unported: fixture expects single-encoded path segments without context override.
    // Unported: fixture contains unencoded spaces in raw request URI path.

    @Test
    fun testGetUnreserved() = runTestSuiteV4("get-unreserved")

    // Unported: fixture contains unencoded non-ASCII UTF-8 characters in raw request URI path.

    @Test
    fun testGetVanilla() = runTestSuiteV4("get-vanilla")

    @Test
    fun testGetVanillaEmptyQueryKey() = runTestSuiteV4("get-vanilla-empty-query-key")

    @Test
    fun testGetVanillaQuery() = runTestSuiteV4("get-vanilla-query")

    @Test
    fun testGetVanillaQueryOrderEncoded() = runTestSuiteV4("get-vanilla-query-order-encoded")

    @Test
    fun testGetVanillaQueryOrderKeyCase() = runTestSuiteV4("get-vanilla-query-order-key-case")

    @Test
    fun testGetVanillaQueryUnreserved() = runTestSuiteV4("get-vanilla-query-unreserved")

    // Unported: fixture contains unencoded non-ASCII UTF-8 characters in raw request URI path.

    @Test
    fun testGetVanillaWithSessionToken() = runTestSuiteV4("get-vanilla-with-session-token")

    @Test
    fun testPostHeaderKeyCase() = runTestSuiteV4("post-header-key-case")

    @Test
    fun testPostHeaderKeySort() = runTestSuiteV4("post-header-key-sort")

    @Test
    fun testPostHeaderValueCase() = runTestSuiteV4("post-header-value-case")

    @Test
    fun testPostStsHeaderAfter() = runTestSuiteV4("post-sts-header-after")

    @Test
    fun testPostStsHeaderBefore() = runTestSuiteV4("post-sts-header-before")

    @Test
    fun testPostVanilla() = runTestSuiteV4("post-vanilla")

    @Test
    fun testPostVanillaEmptyQueryValue() = runTestSuiteV4("post-vanilla-empty-query-value")

    @Test
    fun testPostVanillaQuery() = runTestSuiteV4("post-vanilla-query")

    @Test
    fun testPostXWwwFormUrlencoded() = runTestSuiteV4("post-x-www-form-urlencoded")

    @Test
    fun testPostXWwwFormUrlencodedParameters() = runTestSuiteV4("post-x-www-form-urlencoded-parameters")
}
