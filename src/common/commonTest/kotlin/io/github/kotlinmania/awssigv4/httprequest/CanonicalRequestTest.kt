/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests http_request/canonical_request.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.TestParsers
import io.github.kotlinmania.awssigv4.httprequest.canonicalrequest.Header
import io.github.kotlinmania.awssigv4.httprequest.canonicalrequest.Param
import io.github.kotlinmania.awssigv4.sign.v4.Builder
import io.github.kotlinmania.awssigv4.sign.v4.sha256HexString
import io.github.kotlinmania.http.uri.Uri
import io.github.kotlinmania.prettyassertions.assertEq
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class CanonicalRequestTest {
    private fun signingParams(
        identity: SigningIdentity,
        settings: SigningSettings,
    ): SigningParams =
        Builder<SigningSettings>()
            .identity(identity)
            .region("test-region")
            .name("testservicename")
            .time(TestParsers.parseDateTime("20210511T154045Z"))
            .settings(settings)
            .build()
            .getOrThrow()
            .toHttpSigningParams()

    @Test
    fun testRepeatedHeader() {
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val req = test.request()
        req.headers.add("x-amz-object-attributes" to "Checksum")
        req.headers.add("x-amz-object-attributes" to "ObjectSize")
        val signable = req.toSignableRequest()
        val settings =
            SigningSettings(
                payloadChecksumKind = PayloadChecksumKind.XAmzSha256,
                sessionTokenMode = SessionTokenMode.Exclude,
            )
        val params = signingParams(SigningIdentity.forTests(), settings)
        val creq = CanonicalRequest.from(signable, params).getOrThrow()

        assertEq(
            "host;x-amz-content-sha256;x-amz-date;x-amz-object-attributes",
            creq.values.signedHeaders().toString(),
        )
        assertEq(
            "Checksum,ObjectSize",
            creq.headerValuesFor("x-amz-object-attributes"),
        )
    }

    @Test
    fun testHostHeaderProperlyHandlesPorts() {
        fun hostHeaderTestSetup(endpoint: String): String {
            val test = SigningSuiteTest.v4("get-vanilla")
            val req = test.request()
            req.uri = endpoint
            val signable = req.toSignableRequest()
            val settings =
                SigningSettings(
                    payloadChecksumKind = PayloadChecksumKind.XAmzSha256,
                    sessionTokenMode = SessionTokenMode.Exclude,
                )
            val params = signingParams(SigningIdentity.forTests(), settings)
            val creq = CanonicalRequest.from(signable, params).getOrThrow()
            return creq.headerValuesFor("host")
        }

        assertEq("localhost", hostHeaderTestSetup("http://localhost:80"))
        assertEq("localhost:1234", hostHeaderTestSetup("http://localhost:1234"))
        assertEq("localhost", hostHeaderTestSetup("https://localhost:443"))
        assertEq("localhost:1234", hostHeaderTestSetup("https://localhost:1234"))
    }

    @Test
    fun testSetXamzSha256() {
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val signable = test.request().toSignableRequest()
        val settings =
            SigningSettings(
                payloadChecksumKind = PayloadChecksumKind.XAmzSha256,
                sessionTokenMode = SessionTokenMode.Exclude,
            )
        val params = signingParams(SigningIdentity.forTests(), settings)
        val creq = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            creq.values.contentSha256(),
        )
        assertEq(
            "host;x-amz-content-sha256;x-amz-date",
            creq.values.signedHeaders().asStr(),
        )

        params.setPayloadChecksumKind(PayloadChecksumKind.NoHeader)
        val creqNoHeader = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq("host;x-amz-date", creqNoHeader.values.signedHeaders().asStr())
    }

    @Test
    fun testUnsignedPayload() {
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val req = test.request()
        req.setBody(SignableBody.unsignedPayload())
        val signable = req.toSignableRequest()

        val settings = SigningSettings(payloadChecksumKind = PayloadChecksumKind.XAmzSha256)
        val params = signingParams(SigningIdentity.forTests(), settings)
        val creq = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq("UNSIGNED-PAYLOAD", creq.values.contentSha256())
        assertTrue(creq.toString().endsWith("UNSIGNED-PAYLOAD"))
    }

    @Test
    fun testPrecomputedPayload() {
        val payloadHash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val req = test.request()
        req.setBody(SignableBody.precomputed(payloadHash))
        val signable = req.toSignableRequest()

        val settings = SigningSettings(payloadChecksumKind = PayloadChecksumKind.XAmzSha256)
        val params = signingParams(SigningIdentity.forTests(), settings)
        val creq = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq(payloadHash, creq.values.contentSha256())
        assertTrue(creq.toString().endsWith(payloadHash))
    }

    @Test
    fun testGenerateScope() {
        val expected = "20150830/us-east-1/iam/aws4_request\n"
        val scope =
            SigningScope(
                time = TestParsers.parseDateTime("20150830T123600Z"),
                region = "us-east-1",
                service = "iam",
            )
        assertEq(expected, "$scope\n")
    }

    @Test
    fun testStringToSign() {
        val time = TestParsers.parseDateTime("20150830T123600Z")
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val creq = test.canonicalRequest(SignatureLocation.Headers)
        val expectedSts = test.stringToSign(SignatureLocation.Headers)
        val encoded = sha256HexString(creq.encodeToByteArray())

        val actual = StringToSign.newV4(time, "us-east-1", "service", encoded)
        assertEq(expectedSts, actual.toString())
    }

    @Test
    fun testDigestOfCanonicalRequest() {
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val creq = test.canonicalRequest(SignatureLocation.Headers)
        val expected = "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"
        val actual = sha256HexString(creq.encodeToByteArray())
        assertEq(expected, actual)
    }

    @Test
    fun testDoubleUrlEncodePath() {
        val test = SigningSuiteTest.v4("double-encode-path")
        val signable = test.request().toSignableRequest()
        val params = signingParams(SigningIdentity.forTests(), SigningSettings.default())
        val creq = CanonicalRequest.from(signable, params).getOrThrow()

        val expected = test.canonicalRequest(SignatureLocation.Headers)
        assertEq(expected, creq.toString())
    }

    @Test
    fun testDoubleUrlEncode() {
        val test = SigningSuiteTest.v4("double-url-encode")
        val signable = test.request().toSignableRequest()
        val params = signingParams(SigningIdentity.forTests(), SigningSettings.default())
        val creq = CanonicalRequest.from(signable, params).getOrThrow()

        val expected = test.canonicalRequest(SignatureLocation.Headers)
        assertEq(expected, creq.toString())
    }

    @Test
    fun testTildeInUri() {
        val rawUri =
            "https://s3.us-east-1.amazonaws.com/my-bucket?list-type=2&prefix=~objprefix&single&k=&unreserved=-_.~"
        val httpReq = TestHttpRequest.build(uriStr = rawUri)
        val signable = TestRequest.fromHttpRequest(httpReq, ByteArray(0)).toSignableRequest()
        val params = signingParams(SigningIdentity.forTests(), SigningSettings.default())
        val creq = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq(
            "k=&list-type=2&prefix=~objprefix&single=&unreserved=-_.~",
            creq.params,
        )
    }

    @Test
    fun testSigningUrlsWithPercentEncodedQueryStrings() {
        val allPrintableAsciiChars = (32..126).map { it.toChar() }.joinToString("")
        val uri = Uri.fromStatic("https://s3.us-east-1.amazonaws.com/my-bucket")

        val queryWriter = QueryWriter(uri)
        queryWriter.insert("list-type", "2")
        queryWriter.insert("prefix", allPrintableAsciiChars)

        val httpReq = TestHttpRequest.build(uriStr = queryWriter.buildUri().toString())
        val signable = TestRequest.fromHttpRequest(httpReq, ByteArray(0)).toSignableRequest()
        val params = signingParams(SigningIdentity.forTests(), SigningSettings.default())
        val creq = CanonicalRequest.from(signable, params).getOrThrow()

        val expected =
            "list-type=2&prefix=%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40" +
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~"
        assertEq(expected, creq.params)
    }

    @Test
    fun testOmitSessionToken() {
        val test = SigningSuiteTest.v4("get-vanilla-query-order-key-case")
        val signable = test.request().toSignableRequest()
        val settings = SigningSettings(sessionTokenMode = SessionTokenMode.Include)
        val params = signingParams(SigningIdentity.forTestsWithSessionToken(), settings)

        val creq = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq(
            "host;x-amz-date;x-amz-security-token",
            creq.values.signedHeaders().asStr(),
        )
        assertEq(
            "notarealsessiontoken",
            creq.headers.getByName("x-amz-security-token"),
        )

        params.setSessionTokenMode(SessionTokenMode.Exclude)
        val creqExcluded = CanonicalRequest.from(signable, params).getOrThrow()
        assertEq(
            "notarealsessiontoken",
            creqExcluded.headers.getByName("x-amz-security-token"),
        )
        assertEq("host;x-amz-date", creqExcluded.values.signedHeaders().asStr())
    }

    @Test
    fun nonPresigningHeaderExclusion() {
        val httpReq =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList =
                    listOf(
                        "authorization" to "test-authorization",
                        "content-type" to "application/xml",
                        "content-length" to "0",
                        "user-agent" to "test-user-agent",
                        "x-amzn-trace-id" to "test-trace-id",
                        "x-amz-user-agent" to "test-user-agent",
                        "transfer-encoding" to "chunked",
                    ),
            )
        val signable = TestRequest.fromHttpRequest(httpReq, ByteArray(0)).toSignableRequest()
        val settings = SigningSettings(signatureLocation = SignatureLocation.Headers)
        val params = signingParams(SigningIdentity.forTests(), settings)
        val canonical = CanonicalRequest.from(signable, params).getOrThrow()

        val values = checkNotNull(canonical.values.asHeaders())
        assertEq(
            "content-length;content-type;host;x-amz-date;x-amz-user-agent",
            values.signedHeaders.asStr(),
        )
    }

    @Test
    fun presigningHeaderExclusion() {
        val httpReq =
            TestHttpRequest.build(
                uriStr = "https://some-endpoint.some-region.amazonaws.com",
                headersList =
                    listOf(
                        "authorization" to "test-authorization",
                        "content-type" to "application/xml",
                        "content-length" to "0",
                        "user-agent" to "test-user-agent",
                        "x-amzn-trace-id" to "test-trace-id",
                        "x-amz-user-agent" to "test-user-agent",
                        "transfer-encoding" to "chunked",
                    ),
            )
        val signable = TestRequest.fromHttpRequest(httpReq, ByteArray(0)).toSignableRequest()
        val settings =
            SigningSettings(
                signatureLocation = SignatureLocation.QueryParams,
                expiresIn = 30.seconds,
            )
        val params = signingParams(SigningIdentity.forTests(), settings)
        val canonical = CanonicalRequest.from(signable, params).getOrThrow()

        val values = checkNotNull(canonical.values.intoQueryParams())
        assertEq(
            "content-length;content-type;host",
            values.signedHeaders.asStr(),
        )
    }

    @Test
    fun presigningHeaderExclusionWithExplicitExclusionListSpecified() {
        val exclusionSamples =
            listOf(
                listOf("alpha"),
                listOf("customheader", "anotherheader", "trace"),
                listOf("z", "xcustom", "foo", "bar"),
            )
        for (excludedHeaders in exclusionSamples) {
            val headers = ArrayList<Pair<String, String>>()
            headers.add("content-type" to "application/xml")
            headers.add("content-length" to "0")
            for (key in excludedHeaders) {
                headers.add(key to "value")
            }
            val httpReq =
                TestHttpRequest.build(
                    uriStr = "https://some-endpoint.some-region.amazonaws.com",
                    headersList = headers,
                )
            val signable = TestRequest.fromHttpRequest(httpReq, ByteArray(0)).toSignableRequest()
            val settings =
                SigningSettings(
                    signatureLocation = SignatureLocation.QueryParams,
                    expiresIn = 30.seconds,
                    excludedHeaders = excludedHeaders,
                )
            val params = signingParams(SigningIdentity.forTests(), settings)
            val canonical = CanonicalRequest.from(signable, params).getOrThrow()
            val values = checkNotNull(canonical.values.intoQueryParams())
            assertEq("content-length;content-type;host", values.signedHeaders.asStr())
        }
    }

    @Test
    fun testTrimAllHandlesSpacesCorrectly() {
        assertEq("don't touch me", trimAll("don't touch me"))
        assertEq("trim left", trimAll("   trim left"))
        assertEq("trim right", trimAll("trim right "))
        assertEq("trim both", trimAll("   trim both  "))
        assertEq("", trimAll(" "))
        assertEq("", trimAll("  "))
        assertEq("a b", trimAll(" a   b "))
        assertEq("Some example text", trimAll("  Some  example   text  "))
    }

    @Test
    fun testTrimAllIgnoresOtherFormsOfWhitespace() {
        assertEq(
            "\t\u00A0Some\u00A0 example \u00A0text\u00A0\n",
            trimAll("\t\u00A0Some\u00A0     example   \u00A0text\u00A0\n"),
        )
    }

    @Test
    fun trimSpacesWorksOnSingleCharacters() {
        assertEq("2", trimAll("2"))
    }

    @Test
    fun testTrimAllDoesntElongateStrings() {
        val inputs = listOf("", " ", "   ", "abc", "  a  b   c  ", "\t\n  x  y ")
        for (s in inputs) {
            assertTrue(trimAll(s).length <= s.length)
        }
    }

    @Test
    fun testNormalizeHeaderValueWorksOnValidHeaderValue() {
        val inputs = listOf("", "simple", "  padded  value ", "\twith-tab", "bad\u007Fdel", "bad\nnewline", "テスト")
        for (v in inputs) {
            assertEq(ValidatedHeaderValue.fromStr(v).isOk(), normalizeHeaderValue(v).isOk())
        }
    }

    @Test
    fun testTrimAllDoesNothingWhenThereAreNoSpaces() {
        val inputs = listOf("", "abc", "123-456_789", "\t\u00A0nospace\n", "テスト")
        for (s in inputs) {
            assertEq(s, trimAll(s))
        }
    }

    @Test
    fun testSigV4aConstantsAndStringToSign() {
        assertEq("x-amz-region-set", Header.X_AMZ_REGION_SET)
        assertEq("X-Amz-Region-Set", Param.X_AMZ_REGION_SET)

        val time = TestParsers.parseDateTime("20150830T123600Z")
        val encoded = "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"
        val actual = StringToSign.newV4a(time, "us-east-1,us-west-2", "service", encoded)
        assertEq(
            "AWS4-ECDSA-P256-SHA256\n" +
                "20150830T123600Z\n" +
                "20150830/service/aws4_request\n" +
                encoded,
            actual.toString(),
        )
    }
}
