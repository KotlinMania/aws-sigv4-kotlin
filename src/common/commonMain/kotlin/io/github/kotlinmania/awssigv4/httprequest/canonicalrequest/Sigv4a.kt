/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source http_request/canonical_request/sigv4a.rs
package io.github.kotlinmania.awssigv4.httprequest.canonicalrequest

internal object Header {
    internal const val X_AMZ_REGION_SET: String = "x-amz-region-set"
}

internal object Param {
    internal const val X_AMZ_REGION_SET: String = "X-Amz-Region-Set"
}
