#ifndef RIST_TIME_H
#define RIST_TIME_H

#include "common/attributes.h"
#include "proto/rtp.h"

#include <stdint.h>
/* Time conversion */
// this value is UINT32_MAX 4294967.296
#define RIST_CLOCK (4294967LL)
#define ONE_SECOND (1000 * RIST_CLOCK)
#define RIST_LOG_QUIESCE_TIMER  ONE_SECOND
#define SEVENTY_YEARS_OFFSET (2208988800ULL)

RIST_PRIV uint64_t timestampNTP_u64(void);
RIST_PRIV uint64_t timestampNTP_RTC_u64(void);
RIST_PRIV uint64_t convertRTPtoNTP(uint8_t ptype, uint32_t time_extension, uint32_t i_rtp);
RIST_PRIV uint64_t calculate_rtt_delay(uint64_t request, uint64_t response, uint32_t delay);

/* Convert a 64-bit NTP timestamp (1 s = 2^32) to a 32-bit RTP timestamp.
 * advanced picks the clock: the Advanced Profile 1 MHz clock (TR-06-3
 * Section 5.2.1; RIST_ADV_CLOCK_HZ) or the MPEG-TS 90 kHz clock. Scaling by
 * the clock rate and shifting down 32 bits gives the tick count; the uint32
 * cast wraps as RTP timestamps do. Header-inline so it can be unit-tested
 * without dragging in the clock_gettime plumbing of this module. */
static inline uint32_t timestampRTP_u32(int advanced, uint64_t i_ntp)
{
  uint64_t hz = advanced ? 1000000ULL : (uint64_t)RTP_PTYPE_MPEGTS_CLOCKHZ;
  return (uint32_t)((i_ntp * hz) >> 32);
}

/* Convert the 64-bit NTP form (1 s = 2^32) to nanoseconds or microseconds. The
 * halves are converted separately because the 1900 epoch offset in the upper 32
 * bits makes (i_ntp * 1000000000) >> 32 overflow a uint64. */
static inline uint64_t timestampNTP_to_ns(uint64_t i_ntp)
{
  return (i_ntp >> 32) * 1000000000ULL +
         (((i_ntp & 0xFFFFFFFFULL) * 1000000000ULL) >> 32);
}

static inline uint64_t timestampNTP_to_us(uint64_t i_ntp)
{
  return (i_ntp >> 32) * 1000000ULL +
         (((i_ntp & 0xFFFFFFFFULL) * 1000000ULL) >> 32);
}

#endif /* RIST_TIME_H */
