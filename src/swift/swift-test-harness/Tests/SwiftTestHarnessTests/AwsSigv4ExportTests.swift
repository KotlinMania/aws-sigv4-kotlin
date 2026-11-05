#if canImport(Testing)
import Testing
import AwsSigv4

@Suite("AwsSigv4 Swift Export Tests")
struct AwsSigv4ExportTests {
    @Test("AwsSigv4 swift module imported cleanly")
    func testSwiftModuleLoads() throws {
        #expect(Bool(true), "AwsSigv4 swift module imported cleanly")
    }
}
#elseif canImport(XCTest)
import XCTest
import AwsSigv4

final class AwsSigv4ExportTests: XCTestCase {
    func testSwiftModuleLoads() throws {
        XCTAssertTrue(true, "AwsSigv4 swift module imported cleanly")
    }
}
#endif
