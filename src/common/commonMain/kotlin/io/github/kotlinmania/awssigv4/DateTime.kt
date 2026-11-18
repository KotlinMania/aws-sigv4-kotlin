/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: source date_time.rs
package io.github.kotlinmania.awssigv4

import io.github.kotlinmania.time.OffsetDateTime
import io.github.kotlinmania.time.Time
import kotlin.time.Instant

/** Truncates the subseconds from the given [Instant] to zero. */
internal fun truncateSubsecs(time: Instant): Instant {
    val dateTime = OffsetDateTime.from(time)
    val t = dateTime.time()
    val newTime = Time.fromHms(t.hour(), t.minute(), t.second()).getOrThrow()
    return dateTime.replaceTime(newTime).toSystemTime()
}

/** Formats an [Instant] in `YYYYMMDD` format. */
internal fun formatDate(time: Instant): String {
    val t = OffsetDateTime.from(time)
    val year = t.year().toString().padStart(4, '0')
    val month =
        t
            .month()
            .number
            .toString()
            .padStart(2, '0')
    val day = t.day().toString().padStart(2, '0')
    return "$year$month$day"
}

/** Formats an [Instant] in `YYYYMMDD'T'HHMMSS'Z'` format. */
internal fun formatDateTime(time: Instant): String {
    val t = OffsetDateTime.from(time)
    val year = t.year().toString().padStart(4, '0')
    val month =
        t
            .month()
            .number
            .toString()
            .padStart(2, '0')
    val day = t.day().toString().padStart(2, '0')
    val hour = t.hour().toString().padStart(2, '0')
    val minute = t.minute().toString().padStart(2, '0')
    val second = t.second().toString().padStart(2, '0')
    return "${year}${month}${day}T${hour}${minute}${second}Z"
}
