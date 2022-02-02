/*
 * Parts of this program has been derived from mrouted.  It is covered
 * by the license in the accompanying file named "LICENSE".
 */

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
