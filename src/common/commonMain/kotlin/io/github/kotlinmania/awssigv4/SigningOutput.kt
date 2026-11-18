/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package io.github.kotlinmania.awssigv4

/**
 * Decomposed components of a [SigningOutput].
 */
data class SigningOutputParts<T>(
    val output: T,
    val signature: String,
)

/**
 * Container for the signed output and the signature.
 *
 * This is returned by signing functions, and the signed output will be
 * different based on what is being signed (for example, an event stream
 * message, or an HTTP request).
 */
data class SigningOutput<T>(
    private val output: T,
    private val signature: String,
) {
    /** Returns the signed output. */
    fun output(): T = output

    /** Returns the signature as a lowercase hex string. */
    fun signature(): String = signature

    /** Decomposes the [SigningOutput] into its signed output and signature parts. */
    fun intoParts(): SigningOutputParts<T> = SigningOutputParts(output, signature)

    companion object {
        /** Creates a new [SigningOutput]. */
        fun <T> new(
            output: T,
            signature: String,
        ): SigningOutput<T> = SigningOutput(output, signature)
    }
}
