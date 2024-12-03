#ifndef TIME_H
#define TIME_H

#include <stddef.h>
#include <stdint.h>

/**
 * Custom implementation of the tm struct since we don't have access to time.h
 */
typedef struct {
    int tm_sec;  /* seconds,  range 0 to 59          */
    int tm_min;  /* minutes, range 0 to 59           */
    int tm_hour; /* hours, range 0 to 23             */
    int tm_mday; /* day of the month, range 1 to 31  */
    int tm_mon;  /* month, range 0 to 11             */
    int tm_year; /* The number of years since 1900   */
    int tm_wday; /* day of the week, range 0 to 6    */
    int tm_yday; /* day in the year, range 0 to 365  */
} tm;

/**
 * Converts seconds since Unix epoch to a tm struct containing date/time components.
 * @param seconds Number of seconds since Unix epoch (January 1, 1970)
 * @param tm Pointer to tm struct to store the converted time
 * @return 0 on success, -1 if the year would overflow an int, -2 if year > 9999
 */
int secondsToTm(long long seconds, tm *tm);

/**
 * Formats a tm struct into a human readable date/time string.
 * @param time The tm struct containing the time to format
 * @param dst The destination buffer to write the formatted string to
 * @param dstLength The length of the destination buffer
 * @return The number of bytes written to dst
 * @throws ERROR_BUFFER_OVERFLOW if dstLength is too small
 */
int timeToDisplayText(tm time, uint8_t *dst, size_t dstLength);

/**
 * Returns the number of digits in the given number.
 * @param number The number to count digits for
 * @return The length of the number when written as text
 */
size_t lengthOfNumber(uint64_t number);

/**
 * Converts a number to its text representation.
 * @param dst The destination buffer to write to
 * @param dstLength The length of the destination buffer
 * @param number The number to convert
 * @return The number of bytes written
 */
size_t numberToText(uint8_t *dst, size_t dstLength, uint64_t number);

/**
 * Helper function that prepends a zero to single digit numbers.
 * @param dst The destination buffer to write to
 * @param value The number to potentially prefix
 * @return 1 if a zero was prefixed, 0 otherwise
 */
int prefixWithZero(uint8_t *dst, int value);

/**
 * Formats a release time into a human readable date/time string.
 */
int formatReleaseTime(uint64_t release_time, uint8_t *dst, size_t dstLength);

#endif /* TIME_H */
