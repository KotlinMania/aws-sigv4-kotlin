/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// port-lint: tests date_time.rs
package io.github.kotlinmania.awssigv4

import io.github.kotlinmania.time.Date
import io.github.kotlinmania.time.Month
import io.github.kotlinmania.time.OffsetDateTime
import io.github.kotlinmania.time.PrimitiveDateTime
import io.github.kotlinmania.time.Time
import io.github.kotlinmania.time.formatdescription.wellknown.Rfc3339
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Instant

class ParseError(
    message: String,
) : Exception("failed to parse time: $message")

internal object TestParsers {
    /** Parses `YYYYMMDD'T'HHMMSS'Z'` formatted dates into an [Instant]. */
    fun parseDateTime(dateTimeStr: String): Instant {
        try {
            val year = dateTimeStr.substring(0, 4).toInt()
            val month = Month.tryFrom(dateTimeStr.substring(4, 6).toInt()).getOrThrow()
            val day = dateTimeStr.substring(6, 8).toInt()
            val hour = dateTimeStr.substring(9, 11).toInt()
            val minute = dateTimeStr.substring(11, 13).toInt()
            val second = dateTimeStr.substring(13, 15).toInt()
            val date = Date.fromCalendarDate(year, month, day).getOrThrow()
            val time = Time.fromHms(hour, minute, second).getOrThrow()
            return PrimitiveDateTime.new(date, time).assumeUtc().toSystemTime()
        } catch (e: Exception) {
            throw ParseError(e.message ?: "unknown")
        }
    }

    /** Parses `YYYYMMDD` formatted dates into an [Instant]. */
    fun parseDate(dateStr: String): Instant {
        try {
            val year = dateStr.substring(0, 4).toInt()
            val month = Month.tryFrom(dateStr.substring(4, 6).toInt()).getOrThrow()
            val day = dateStr.substring(6, 8).toInt()
            val date = Date.fromCalendarDate(year, month, day).getOrThrow()
            val time = Time.fromHms(0, 0, 0).getOrThrow()
            return PrimitiveDateTime.new(date, time).assumeUtc().toSystemTime()
        } catch (e: Exception) {
            throw ParseError(e.message ?: "unknown")
        }
    }
}

class DateTimeTest {
    @Test
    fun dateFormat() {
        val time: Instant = OffsetDateTime.parse("2039-02-04T23:01:09.104Z", Rfc3339).getOrThrow().toSystemTime()
        assertEquals("20390204", formatDate(time))
        val time2: Instant = OffsetDateTime.parse("0100-01-02T00:00:00.000Z", Rfc3339).getOrThrow().toSystemTime()
        assertEquals("01000102", formatDate(time2))
    }

    @Test
    fun dateTimeFormat() {
        val time: Instant = OffsetDateTime.parse("2039-02-04T23:01:09.104Z", Rfc3339).getOrThrow().toSystemTime()
        assertEquals("20390204T230109Z", formatDateTime(time))
        val time2: Instant = OffsetDateTime.parse("0100-01-02T00:00:00.000Z", Rfc3339).getOrThrow().toSystemTime()
        assertEquals("01000102T000000Z", formatDateTime(time2))
    }

    @Test
    fun dateTimeRoundtrip() {
        val time = TestParsers.parseDateTime("20150830T123600Z")
        assertEquals("20150830T123600Z", formatDateTime(time))
    }

    @Test
    fun dateRoundtrip() {
        val time = TestParsers.parseDate("20150830")
        assertEquals("20150830", formatDate(time))
    }

    @Test
    fun testTruncateSubsecs() {
        val time: Instant = OffsetDateTime.parse("2039-02-04T23:01:09.104Z", Rfc3339).getOrThrow().toSystemTime()
        val expected: Instant = OffsetDateTime.parse("2039-02-04T23:01:09.000Z", Rfc3339).getOrThrow().toSystemTime()
        assertEquals(expected, truncateSubsecs(time))
    }
}
