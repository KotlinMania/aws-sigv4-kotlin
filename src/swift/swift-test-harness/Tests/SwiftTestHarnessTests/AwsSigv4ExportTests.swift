import Testing
import AwsSigv4

private typealias v4 = ExportedKotlinPackages.io.github.kotlinmania.awssigv4.sign.v4

@Suite("AwsSigv4 Swift Export Tests")
struct AwsSigv4ExportTests {
    @Test("Exports SignatureVersion and SigningIdentity metadata cleanly")
    func signatureVersionAndIdentityMetadata() {
        #expect(SignatureVersion.V4.toString() == "SigV4")
        #expect(SignatureVersion.V4a.toString() == "SigV4a")

        let identity = SigningIdentity.Companion.shared.fromKeys(
            accessKeyId: "AKIDEXAMPLE",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            sessionToken: "SESSION_TOKEN",
            expiration: nil
        )
        #expect(identity.credentials() != nil)
        #expect(identity.expiration() == nil)
    }

    @Test("Derives SigV4 signing key and calculates HMAC-SHA256 signature")
    func v4KeyDerivationAndSignature() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        let epoch: Int64 = 1_440_938_160
        let creq = """
        AWS4-HMAC-SHA256
        20150830T123600Z
        20150830/us-east-1/iam/aws4_request
        f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59
        """
        let derivedKey = v4.generateSigningKeyAtEpochSeconds(
            secret: secret,
            epochSeconds: epoch,
            region: "us-east-1",
            service: "iam"
        )
        let signature = v4.calculateSignatureUtf8(
            signingKey: derivedKey,
            stringToSign: creq
        )
        #expect(signature == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
    }

    @Test("Signs HTTP requests with headers and presigned query parameters")
    func httpRequestHeaderAndQuerySigning() {
        let identity = SigningIdentity.Companion.shared.fromKeys(
            accessKeyId: "AKIDEXAMPLE",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            sessionToken: nil,
            expiration: nil
        )
        let epoch: Int64 = 1_440_938_160

        let headerSettings = httprequest.SigningSettings.Companion.shared.default()
        let builtHeaderParams = httprequest.SigningParams.Companion.shared.v4Builder()
            .identity(identity: identity)
            .region(region: "us-east-1")
            .name(name: "service")
            .timeEpochSeconds(epochSeconds: epoch, nanosecondsOfSecond: 0)
            .settings(settings: headerSettings)
            .build()
        #expect(builtHeaderParams.isSuccess())
        let headerParams = builtHeaderParams.getOrThrow()

        let reqResult = httprequest.SignableRequest.Companion.shared.new(
            method: "GET",
            uri: "https://example.amazonaws.com/",
            headers: [],
            body: httprequest.SignableBody.Companion.shared.empty()
        )
        #expect(reqResult.isSuccess())
        let req = reqResult.getOrThrow()

        let signedHeaderOut = httprequest.sign(request: req, params: headerParams)
        #expect(signedHeaderOut.isSuccess())
        #expect(signedHeaderOut.signature() == "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
        let instructions = signedHeaderOut.instructions()!
        #expect(instructions.headers().count == 2)

        let querySettings = httprequest.SigningSettings.Companion.shared.default()
        querySettings.signatureLocation = .QueryParams
        querySettings.setExpiresInSeconds(secondsValue: 3600)
        let queryParams = httprequest.SigningParams.Companion.shared.v4Builder()
            .identity(identity: identity)
            .region(region: "us-east-1")
            .name(name: "service")
            .timeEpochSeconds(epochSeconds: epoch, nanosecondsOfSecond: 0)
            .settings(settings: querySettings)
            .build()
            .getOrThrow()

        let signedQueryOut = httprequest.sign(request: req, params: queryParams)
        #expect(signedQueryOut.isSuccess())
        let presignedUri = signedQueryOut.instructions()!.applyToUriString(uriString: "https://example.amazonaws.com/")
        #expect(presignedUri.contains("X-Amz-Signature="))
    }

    @Test("Rejects unsupported identity without throwing across FFI")
    func unsupportedIdentityReturnsErrorResult() {
        let unsupported = SigningIdentity.Companion.shared.unsupported(
            payload: SignatureVersion.V4,
            expiration: nil
        )
        let params = httprequest.SigningParams.Companion.shared.v4Builder()
            .identity(identity: unsupported)
            .region(region: "us-east-1")
            .name(name: "service")
            .timeEpochSeconds(epochSeconds: 1_440_938_160, nanosecondsOfSecond: 0)
            .settings(settings: httprequest.SigningSettings.Companion.shared.default())
            .build()
            .getOrThrow()

        let req = httprequest.SignableRequest.Companion.shared.new(
            method: "GET",
            uri: "https://example.amazonaws.com/",
            headers: [],
            body: httprequest.SignableBody.Companion.shared.empty()
        ).getOrThrow()

        let result = httprequest.sign(request: req, params: params)
        #expect(result.isFailure())
        #expect(result.error?.message == "only 'AWS credentials' are supported for signing")
    }
}
