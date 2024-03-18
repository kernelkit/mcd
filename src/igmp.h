/* SPDX-License-Identifier: ISC */

#ifndef MCD_IGMP_H_
#define MCD_IGMP_H_

/*
 * Constants for IGMP Version 2.  Several of these, especially the
 * robustness variable, should be variables and not constants.
 *
 * The IGMP_LAST_MEMBER_INTERVAL_DEFAULT defines the default interval in
 * seconds for group-specific queries, sent when the last member of a
 * group sends leave.
 */
#define	IGMP_ROBUSTNESS_DEFAULT			2
#define	IGMP_QUERY_INTERVAL_DEFAULT		125
#define	IGMP_QUERY_RESPONSE_INTERVAL		10
#define	IGMP_GROUP_MEMBERSHIP_INTERVAL		(igmp_robustness * \
					igmp_query_interval + \
					igmp_response_interval)
#define	IGMP_OTHER_QUERIER_PRESENT_INTERVAL	(igmp_robustness * \
					igmp_query_interval + \
					igmp_response_interval / 2)
						/* Round to the nearest TIMER_INTERVAL */
#define	IGMP_STARTUP_QUERY_INTERVAL		(((igmp_query_interval / 4) \
							/ TIMER_INTERVAL) * TIMER_INTERVAL)
#define	IGMP_STARTUP_QUERY_COUNT		igmp_robustness
#define	IGMP_LAST_MEMBER_INTERVAL_DEFAULT	1
#define	IGMP_LAST_MEMBER_QUERY_COUNT		igmp_robustness

/*
 * OLD_AGE_THRESHOLD is the number of IGMP_QUERY_INTERVAL's to remember the
 * presence of an IGMPv1 group member.  According to the IGMPv2 specification,
 * routers remember this presence for [Robustness Variable] * [Query Interval] +
 * [Query Response Interval].  However, OLD_AGE_THRESHOLD is in units of
 * [Query Interval], so doesn't have sufficient resolution to represent
 * [Query Response Interval].  When the timer mechanism gets an efficient
 * method of refreshing timers, this should get fixed.
 */
#define OLD_AGE_THRESHOLD		igmp_robustness

/*
 * The original multicast releases defined
 * IGMP_HOST_{MEMBERSHIP_QUERY,MEMBERSHIP_REPORT,NEW_MEMBERSHIP_REPORT
 *   ,LEAVE_MESSAGE}.  Later releases removed the HOST and inserted
 * the IGMP version number.  NetBSD inserted the version number in
 * a different way.  mcd use the new names, so we #define them
 * to the old ones if needed.
 */
#if !defined(IGMP_MEMBERSHIP_QUERY) && defined(IGMP_HOST_MEMBERSHIP_QUERY)
#define	IGMP_MEMBERSHIP_QUERY		IGMP_HOST_MEMBERSHIP_QUERY
#define	IGMP_V2_LEAVE_GROUP		IGMP_HOST_LEAVE_MESSAGE
#endif
#ifndef	IGMP_V1_MEMBERSHIP_REPORT
#ifdef	IGMP_HOST_MEMBERSHIP_REPORT
#define	IGMP_V1_MEMBERSHIP_REPORT	IGMP_HOST_MEMBERSHIP_REPORT
#define	IGMP_V2_MEMBERSHIP_REPORT	IGMP_HOST_NEW_MEMBERSHIP_REPORT
#endif
#ifdef	IGMP_v1_HOST_MEMBERSHIP_REPORT
#define	IGMP_V1_MEMBERSHIP_REPORT	IGMP_v1_HOST_MEMBERSHIP_REPORT
#define	IGMP_V2_MEMBERSHIP_REPORT	IGMP_v2_HOST_MEMBERSHIP_REPORT
#endif
#endif
#define IGMP_V3_MEMBERSHIP_REPORT	0x22	/* Ver. 3 membership report */

/*
 * IGMPv3 report modes.
 */
#ifndef IGMP_MODE_IS_INCLUDE
#define IGMP_DO_NOTHING			0	/* don't send a record */
#define IGMP_MODE_IS_INCLUDE		1	/* MODE_IN */
#define IGMP_MODE_IS_EXCLUDE		2	/* MODE_EX */
#define IGMP_CHANGE_TO_INCLUDE_MODE	3	/* TO_IN */
#define IGMP_CHANGE_TO_EXCLUDE_MODE	4	/* TO_EX */
#define IGMP_ALLOW_NEW_SOURCES		5	/* ALLOW_NEW */
#define IGMP_BLOCK_OLD_SOURCES		6	/* BLOCK_OLD */
#endif

struct igmpv3_query {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    uint32_t group;
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t  qrv:3,
             suppress:1,
             resv:4;
#else
    uint8_t  resv:4,
	     suppress:1,
	     qrv:3;
#endif
    uint8_t  qqic;
    uint16_t nsrcs;
    uint32_t srcs[0];
};

struct igmpv3_grec {
    uint8_t  grec_type;
    uint8_t  grec_auxwords;
    uint16_t grec_nsrcs;
    uint32_t grec_mca;
    uint32_t grec_src[0];
};

#define IGMP_GRPREC_HDRLEN		8
#define IGMP_V3_GROUP_RECORD_MIN_SIZE	8

struct igmpv3_report {
    uint8_t  type;
    uint8_t  resv1;
    uint16_t csum;
    uint16_t resv2;
    uint16_t ngrec;
    struct igmpv3_grec grec[0];
};

#ifndef IGMP_V3_REPORT_MINLEN
#define IGMP_V3_REPORT_MINLEN		8
#define IGMP_V3_REPORT_MAXRECS		65535
#endif


/*
 * RFC-3376 states that Max Resp Code (MRC) and Querier's Query Interval Code
 * (QQIC) should be presented in floating point value if their value exceeds
 * 128. The following formula is used by IGMPv3 clients to calculate the
 * actual value of the floating point:
 *
 *       0 1 2 3 4 5 6 7
 *      +-+-+-+-+-+-+-+-+
 *      |1| exp | mant  |
 *      +-+-+-+-+-+-+-+-+
 *
 *   QQI / MRT = (mant | 0x10) << (exp + 3)
 *
 * This requires us to find the largest set (fls) bit in the 15-bit number
 * and set the exponent based on its index in the bits 15-8. ie.
 *
 *   exponent 0: igmp_fls(0000 0000 1000 0010)
 *   exponent 5: igmp_fls(0001 0000 0000 0000)
 *   exponent 7: igmp_fls(0111 0101 0000 0000)
 *
 * and set that as the exponent. The mantissa is set to the last 4 bits
 * remaining after the (3 + exponent) shifts to the right.
 *
 * Note!
 * The numbers 31744-32767 are the maximum we can present with floating
 * point that has an exponent of 3 and a mantissa of 4. After this the
 * implementation just wraps around back to zero.
 */
static inline uint8_t igmp_floating_point(unsigned int mantissa)
{
    unsigned int exponent;

    /* Wrap around numbers larger than 2^15, since those can not be
     * presented with 7-bit floating point. */
    mantissa &= 0x00007FFF;

    /* If top 8 bits are zero. */
    if (!(mantissa & 0x00007F80))
        return mantissa;

    /* Shift the mantissa and mark this code floating point. */
    mantissa >>= 3;
    /* At this point the actual exponent (bits 7-5) are still 0, but the
     * exponent might be incremented below. */
    exponent   = 0x00000080;

    /* If bits 7-4 are not zero. */
    if (mantissa & 0x00000F00) {
        mantissa >>= 4;
        /* The index of largest set bit is at least 4. */
        exponent  |= 0x00000040;
    }

    /* If bits 7-6 OR bits 3-2 are not zero. */
    if (mantissa & 0x000000C0) {
        mantissa >>= 2;
        /* The index of largest set bit is atleast 6 if we shifted the
         * mantissa earlier or atleast 2 if we did not shift it. */
        exponent  |= 0x00000020;
    }

    /* If bit 7 OR bit 3 OR bit 1 is not zero. */
    if (mantissa & 0x00000020) {
        mantissa >>= 1;
        /* The index of largest set bit is atleast 7 if we shifted the
         * mantissa two times earlier or atleast 3 if we shifted the
         * mantissa last time or atleast 1 if we did not shift it. */
        exponent  |= 0x00000010;
    }

    return exponent | (mantissa & 0x0000000F);
}

/*
 * Convert from IGMP floating point back to seconds
 */
static inline uint16_t igmp_code_time(uint8_t code)
{
    uint16_t exp = (code >> 4) & 0x7;
    uint16_t mant = code & 0xf;
    uint16_t time;

    if (code < 128)
	time = code;
    else
	time = (mant | 0x10) << (exp + 3);

    return time / IGMP_TIMER_SCALE;
}

#endif /* MCD_IGMP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
