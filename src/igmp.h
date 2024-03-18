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

#endif /* MCD_IGMP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
