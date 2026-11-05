/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests http_request/test.rs
package io.github.kotlinmania.awssigv4.httprequest

import io.github.kotlinmania.awscredentialtypes.Credentials
import io.github.kotlinmania.awssigv4.SigningIdentity
import io.github.kotlinmania.awssigv4.sign.v4.sha256HexString
import io.github.kotlinmania.http.Method
import io.github.kotlinmania.http.header.HeaderName
import io.github.kotlinmania.http.uri.Uri
import io.github.kotlinmania.time.OffsetDateTime
import io.github.kotlinmania.time.formatdescription.wellknown.Rfc3339
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.github.kotlinmania.awssigv4.sign.v4.SigningParams as V4SigningParams

internal sealed class TestSignedBody {
    data class Signable(
        val body: SignableBody,
    ) : TestSignedBody()

    class Bytes(
        val data: ByteArray,
    ) : TestSignedBody()

    fun asSignableBody(): SignableBody =
        when (this) {
            is Signable -> body
            is Bytes -> SignableBody.bytes(data)
        }
}

internal class TestHttpRequest(
    var method: Method,
    var uri: Uri,
    val headers: CanonicalHeaderMap,
    val body: String,
) {
    fun applyInstructions(instructions: SigningInstructions) {
        val (newHeaders, newQuery) = instructions.intoParts()
        for (header in newHeaders) {
            val validated = ValidatedHeaderValue.fromStr(header.value()).value
            checkNotNull(validated)
            validated.sensitive = header.sensitive()
            val err = headers.insertStatic(header.name(), validated)
            check(err == null) { "invalid header name: ${header.name()}" }
        }
        if (newQuery.isNotEmpty()) {
            val query = QueryWriter(uri)
            for (param in newQuery) {
                query.insert(param.name, param.value)
            }
            uri = query.buildUri()
        }
    }

    companion object {
        fun build(
            uriStr: String,
            methodStr: String = "GET",
            headersList: List<Pair<String, String>> = emptyList(),
            bodyText: String = "",
        ): TestHttpRequest {
            val parsedUri = Uri.tryFrom(uriStr).getOrThrow()
            val parsedMethod = Method.fromBytes(methodStr.encodeToByteArray()).getOrThrow()
            val map = CanonicalHeaderMap()
            for ((k, v) in headersList) {
                val hn = HeaderName.fromStr(k.lowercase()).getOrThrow()
                val hv = checkNotNull(ValidatedHeaderValue.fromStr(v).value) { "invalid header value: $v" }
                map.append(hn, hv)
            }
            return TestHttpRequest(parsedMethod, parsedUri, map, bodyText)
        }
    }
}

internal class TestRequest(
    var uri: String,
    var method: String,
    val headers: MutableList<Pair<String, String>>,
    var body: TestSignedBody,
) {
    fun setBody(newBody: SignableBody) {
        body = TestSignedBody.Signable(newBody)
    }

    fun toSignableRequest(): SignableRequest =
        SignableRequest
            .new(
                method = method,
                uri = uri,
                headers = headers.map { (k, v) -> SignableHeader(k, v) },
                body = body.asSignableBody(),
            ).getOrThrow()

    fun asHttpRequest(): TestHttpRequest =
        TestHttpRequest.build(
            uriStr = uri,
            methodStr = method,
            headersList = headers,
            bodyText = "body",
        )

    companion object {
        fun fromHttpRequest(
            req: TestHttpRequest,
            rawBodyBytes: ByteArray = req.body.encodeToByteArray(),
        ): TestRequest {
            val pairs = ArrayList<Pair<String, String>>()
            for (name in req.headers.keys()) {
                for (v in req.headers.getAll(name)) {
                    pairs.add(name.asStr() to v.asStr())
                }
            }
            return TestRequest(
                uri = req.uri.toString(),
                method = req.method.asStr(),
                headers = pairs,
                body = TestSignedBody.Bytes(rawBodyBytes),
            )
        }
    }
}

internal data class TestContext(
    val identity: SigningIdentity,
    val expirationInSeconds: Long,
    val normalize: Boolean,
    val region: String,
    val service: String,
    val timestamp: String,
    val omitSessionToken: Boolean,
    val signBody: Boolean,
) {
    fun toV4SigningParams(signatureLocation: SignatureLocation): SigningParams {
        val parsedTime = OffsetDateTime.parse(timestamp, Rfc3339).getOrThrow().toSystemTime()
        val settings =
            SigningSettings(
                expiresIn = expirationInSeconds.seconds,
                uriPathNormalizationMode = UriPathNormalizationMode.fromBoolean(normalize),
                sessionTokenMode = if (omitSessionToken) SessionTokenMode.Exclude else SessionTokenMode.Include,
                payloadChecksumKind =
                    if (signBody) {
                        PayloadChecksumKind.XAmzSha256
                    } else {
                        PayloadChecksumKind.NoHeader
                    },
                signatureLocation = signatureLocation,
            )
        val v4 =
            V4SigningParams(
                identity = identity,
                region = region,
                name = service,
                time = parsedTime,
                settings = settings,
            )
        return SigningParams.v4(v4)
    }
}

internal class SigningSuiteTest private constructor(
    private val case: V4FixtureCase,
) {
    fun request(): TestRequest = parseRawHttpRequest(case.requestTxt)

    fun signedRequest(signatureLocation: SignatureLocation): TestRequest =
        when (signatureLocation) {
            SignatureLocation.QueryParams -> parseRawHttpRequest(case.querySignedRequest)
            SignatureLocation.Headers -> parseRawHttpRequest(case.headerSignedRequest)
        }

    fun canonicalRequest(signatureLocation: SignatureLocation): String =
        when (signatureLocation) {
            SignatureLocation.QueryParams -> case.queryCanonicalRequest
            SignatureLocation.Headers -> case.headerCanonicalRequest
        }

    fun stringToSign(signatureLocation: SignatureLocation): String =
        when (signatureLocation) {
            SignatureLocation.QueryParams -> case.queryStringToSign
            SignatureLocation.Headers -> case.headerStringToSign
        }

    fun signature(signatureLocation: SignatureLocation): String =
        when (signatureLocation) {
            SignatureLocation.QueryParams -> case.querySignature
            SignatureLocation.Headers -> case.headerSignature
        }

    fun context(): TestContext {
        val creds = Credentials.fromKeys(case.accessKeyId, case.secretAccessKey, case.token)
        val identity = SigningIdentity.fromCredentials(creds)
        return TestContext(
            identity = identity,
            expirationInSeconds = case.expirationInSeconds,
            normalize = case.normalize,
            region = case.region,
            service = case.service,
            timestamp = case.timestamp,
            omitSessionToken = case.omitSessionToken,
            signBody = case.signBody,
        )
    }

    companion object {
        fun v4(testName: String): SigningSuiteTest {
            val found =
                checkNotNull(SigningSuiteFixtures.v4Cases[testName]) {
                    "Unknown v4 signing suite case: $testName"
                }
            return SigningSuiteTest(found)
        }
    }
}

internal fun parseRawHttpRequest(rawText: String): TestRequest {
    val normalized = rawText.replace("\r\n", "\n")
    val headerBodySplit = normalized.indexOf("\n\n")
    val headerSection = if (headerBodySplit >= 0) normalized.substring(0, headerBodySplit) else normalized
    val bodyBytes =
        if (headerBodySplit >= 0) {
            normalized.substring(headerBodySplit + 2).encodeToByteArray()
        } else {
            ByteArray(0)
        }

    val lines = headerSection.split('\n')
    check(lines.isNotEmpty()) { "empty raw HTTP request" }
    val requestLine = lines[0]
    val firstSpace = requestLine.indexOf(' ')
    check(firstSpace > 0) { "invalid HTTP request line: $requestLine" }
    val method = requestLine.substring(0, firstSpace)
    val restAfterMethod = requestLine.substring(firstSpace + 1)
    val versionSpace = restAfterMethod.lastIndexOf(" HTTP/")
    val rawPath =
        if (versionSpace >= 0) {
            restAfterMethod.substring(0, versionSpace)
        } else {
            restAfterMethod
        }

    val uriBuilder = Uri.builder().scheme("https").pathAndQuery(rawPath)
    val headers = ArrayList<Pair<String, String>>()
    for (i in 1 until lines.size) {
        val line = lines[i]
        if (line.isEmpty()) {
            continue
        }
        val colonIdx = line.indexOf(':')
        check(colonIdx > 0) { "invalid header line: $line" }
        val rawName = line.substring(0, colonIdx)
        val rawVal = line.substring(colonIdx + 1).trim { it == ' ' || it == '\t' }
        if (rawName.lowercase() == "host") {
            uriBuilder.authority(rawVal)
        } else if (rawName.isNotEmpty()) {
            headers.add(rawName to rawVal)
        }
    }

    val builtUri = uriBuilder.build().getOrThrow().toString()
    return TestRequest(
        uri = builtUri,
        method = method,
        headers = headers,
        body = TestSignedBody.Bytes(bodyBytes),
    )
}

internal fun assertUriEq(
    expected: Uri,
    actual: Uri,
) {
    assertEquals(expected.scheme(), actual.scheme())
    assertEquals(expected.authority(), actual.authority())
    assertEquals(expected.path(), actual.path())

    val expectedParams =
        parseFormUrlEncoded(expected.query().orEmpty())
            .sortedWith(compareBy<DecodedQueryPair> { it.key }.thenBy { it.value })
    val actualParams =
        parseFormUrlEncoded(actual.query().orEmpty())
            .sortedWith(compareBy<DecodedQueryPair> { it.key }.thenBy { it.value })
    assertEquals(expectedParams, actualParams)
}

internal fun assertRequestsEq(
    expectedReq: TestRequest,
    actual: TestHttpRequest,
) {
    val expected = expectedReq.asHttpRequest()
    assertEquals(expected.method, actual.method)
    assertEquals(expected.headers.size(), actual.headers.size(), "extra or missing headers")
    assertEquals(expected.headers, actual.headers, "headers mismatch")
    assertUriEq(expected.uri, actual.uri)
    assertEquals(expected.body, actual.body, "body mismatch")
}

internal fun assertHttpRequestsComparableEq(
    expected: TestHttpRequest,
    actual: TestHttpRequest,
) {
    assertEquals(expected.method, actual.method)
    assertEquals(expected.headers.size(), actual.headers.size(), "extra or missing headers")
    assertEquals(expected.headers, actual.headers, "headers mismatch")
    assertUriEq(expected.uri, actual.uri)
}

internal fun runV4Test(
    testName: String,
    signatureLocation: SignatureLocation,
) {
    val test = SigningSuiteTest.v4(testName)
    val tc = test.context()
    val params = tc.toV4SigningParams(signatureLocation)

    val req = test.request()
    val expectedCreq = test.canonicalRequest(signatureLocation)
    val signableReq = req.toSignableRequest()
    val actualCreq = CanonicalRequest.from(signableReq, params).getOrThrow()

    assertEquals(
        expectedCreq,
        actualCreq.toString(),
        "canonical request didn't match (signature location: $signatureLocation)",
    )

    val expectedStringToSign = test.stringToSign(signatureLocation)
    val hashedCreq = sha256HexString(actualCreq.toString().encodeToByteArray())
    val actualStringToSign =
        StringToSign
            .newV4(
                params.time(),
                checkNotNull(params.region()),
                params.name(),
                hashedCreq,
            ).toString()

    assertEquals(
        expectedStringToSign,
        actualStringToSign,
        "'string to sign' didn't match (signature location: $signatureLocation)",
    )

    val out = sign(signableReq, params).getOrThrow()
    val signed = req.asHttpRequest()
    signed.applyInstructions(out.output())

    assertEquals(
        test.signature(signatureLocation),
        out.signature(),
        "signature didn't match (signature location: $signatureLocation)",
    )

    val expected = test.signedRequest(signatureLocation)
    assertRequestsEq(expected, signed)
}

internal fun runTestSuiteV4(testName: String) {
    runV4Test(testName, SignatureLocation.Headers)
    runV4Test(testName, SignatureLocation.QueryParams)
}

class TestSupportTest {
    @Test
    fun testParse() {
        val req = SigningSuiteTest.v4("post-header-key-case").request()
        assertEquals("POST", req.method)
        assertEquals("https://example.amazonaws.com/", req.uri)
        assertTrue(req.headers.isEmpty())
    }

    @Test
    fun testReadQueryParams() {
        val req = SigningSuiteTest.v4("get-header-value-trim").request()
        assertEquals("GET", req.method)
        assertEquals("https://example.amazonaws.com/", req.uri)
        assertTrue(req.headers.isNotEmpty())
    }

    @Test
    fun testParseHeaders() {
        val raw = "GET / HTTP/1.1\nHost:example.amazonaws.com\nX-Amz-Date:20150830T123600Z\n\nblah blah"
        val parsed = parseRawHttpRequest(raw)
        assertEquals("https://example.amazonaws.com/", parsed.uri)
        assertEquals(listOf("X-Amz-Date" to "20150830T123600Z"), parsed.headers)
        assertEquals("blah blah", checkNotNull(parsed.body.asSignableBody().bytesOrNull()).decodeToString())
    }
}
