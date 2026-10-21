/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package io.github.kotlinmania.awssigv4

/** The version of the signing algorithm to use. */
enum class SignatureVersion {
    /** The SigV4 signing algorithm. */
    V4,

    /** The SigV4a signing algorithm. */
    V4a,
    ;

    override fun toString(): String =
        when (this) {
            V4 -> "SigV4"
            V4a -> "SigV4a"
        }
}
