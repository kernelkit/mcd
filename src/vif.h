/*
 * Parts of this program has been derived from mrouted.  It is covered
 * by the license in the accompanying file named "LICENSE".
 */
#ifndef QUERIERD_VIF_H_
#define QUERIERD_VIF_H_

#include <stdint.h>
#include "queue.h"

/*
 * Bitmap handling functions.
 * These should be fast but generic.  bytes can be slow to zero and compare,
 * words are hard to make generic.  Thus two sets of macros (yuk).
 */

/*
 * The VIFM_ functions should migrate out of <netinet/ip_mroute.h>, since
 * the kernel no longer uses vifbitmaps.
 */
#ifndef VIFM_SET
typedef	uint32_t vifbitmap_t;

#define	VIFM_SET(n, m)			((m) |=  (1 << (n)))
#define	VIFM_CLR(n, m)			((m) &= ~(1 << (n)))
#define	VIFM_ISSET(n, m)		((m) &   (1 << (n)))
#define VIFM_CLRALL(m)			((m) = 0x00000000)
#define VIFM_COPY(mfrom, mto)		((mto) = (mfrom))
#define VIFM_SAME(m1, m2)		((m1) == (m2))
#endif
/*
 * And <netinet/ip_mroute.h> was missing some required functions anyway
 */
#if !defined(VIFM_SETALL)
#define	VIFM_SETALL(m)			((m) = ~0)
#endif
#define	VIFM_ISSET_ONLY(n, m)		((m) == (1 << (n)))
#define	VIFM_ISEMPTY(m)			((m) == 0)
#define	VIFM_CLR_MASK(m, mask)		((m) &= ~(mask))
#define	VIFM_SET_MASK(m, mask)		((m) |= (mask))

/*
 * Neighbor bitmaps are, for efficiency, implemented as a struct
 * containing two variables of a native machine type.  If you
 * have a native type that's bigger than a long, define it below.
 */
#define	NBRTYPE		uint32_t
#define NBRBITS		sizeof(NBRTYPE) * 8

typedef struct {
    NBRTYPE hi;
    NBRTYPE lo;
} nbrbitmap_t;
#define	MAXNBRS		2 * NBRBITS
#define	NO_NBR		MAXNBRS

#define	NBRM_SET(n, m)		(((n) < NBRBITS) ? ((m).lo |= (1 << (n))) :  \
				      ((m).hi |= (1 << (n - NBRBITS))))
#define	NBRM_CLR(n, m)		(((n) < NBRBITS) ? ((m).lo &= ~(1 << (n))) : \
				      ((m).hi &= ~(1 << (n - NBRBITS))))
#define	NBRM_ISSET(n, m)	(((n) < NBRBITS) ? ((m).lo & (1 << (n))) :   \
				      ((m).hi & (1 << ((n) - NBRBITS))))
#define	NBRM_CLRALL(m)		((m).lo = (m).hi = 0)
#define	NBRM_COPY(mfrom, mto)	((mto).lo = (mfrom).lo, (mto).hi = (mfrom).hi)
#define	NBRM_SAME(m1, m2)	(((m1).lo == (m2).lo) && ((m1).hi == (m2).hi))
#define	NBRM_ISEMPTY(m)		(((m).lo == 0) && ((m).hi == 0))
#define	NBRM_SETMASK(m, mask)	(((m).lo |= (mask).lo),((m).hi |= (mask).hi))
#define	NBRM_CLRMASK(m, mask)	(((m).lo &= ~(mask).lo),((m).hi &= ~(mask).hi))
#define	NBRM_MASK(m, mask)	(((m).lo &= (mask).lo),((m).hi &= (mask).hi))
#define	NBRM_ISSETMASK(m, mask)	(((m).lo & (mask).lo) || ((m).hi & (mask).hi))
#define	NBRM_ISSETALLMASK(m, mask)\
				((((m).lo & (mask).lo) == (mask).lo) && \
				 (((m).hi & (mask).hi) == (mask).hi))

/*
 * User level Virtual Interface structure
 *
 * A "virtual interface" is either a physical, multicast-capable interface
 * (called a "phyint") or a virtual point-to-point link (called a "tunnel").
 * (Note: all addresses, subnet numbers and masks are kept in NETWORK order.)
 */
struct uvif {
    TAILQ_ENTRY(uvif) uv_link;		/* link to next/prev vif            */
    uint32_t	     uv_flags;	        /* VIFF_ flags defined below         */
    uint32_t	     uv_lcl_addr;       /* local address of this vif         */
    uint32_t	     uv_subnet;         /* subnet number         (phyints)   */
    uint32_t	     uv_subnetmask;     /* subnet mask           (phyints)   */
    uint32_t	     uv_subnetbcast;    /* subnet broadcast addr (phyints)   */
    char	     uv_name[IFNAMSIZ]; /* interface name                    */
    TAILQ_HEAD(,listaddr) uv_static;    /* list of static groups (phyints)   */
    TAILQ_HEAD(,listaddr) uv_groups;    /* list of local groups  (phyints)   */
    struct listaddr *uv_querier;        /* IGMP querier on vif (one or none) */
    int		     uv_igmpv1_warn;    /* To rate-limit IGMPv1 warnings     */
    struct phaddr   *uv_addrs;	        /* Additional subnets on this vif    */
    int		     uv_ifindex;        /* Primarily for Linux systems       */
};

#define VIFF_KERNEL_FLAGS	(VIFF_TUNNEL|VIFF_SRCRT)
#define VIFF_DOWN		0x000100	/* kernel state of interface */
#define VIFF_DISABLED		0x000200	/* administratively disabled */
#define VIFF_QUERIER		0x000400	/* I am the subnet's querier */
#define VIFF_ONEWAY		0x000800	/* Maybe one way interface   */
#define VIFF_LEAF		0x001000	/* all neighbors are leaves  */
#define VIFF_IGMPV1		0x002000	/* Act as an IGMPv1 Router   */
#define VIFF_PASSIVE		0x008000	/* passive tunnel	     */
#define VIFF_NOFLOOD		0x020000	/* don't flood on this vif   */
#define	VIFF_NOTRANSIT		0x040000	/* don't transit these vifs  */
#define	VIFF_FORCE_LEAF		0x100000	/* ignore nbrs on this vif   */
#define	VIFF_OTUNNEL		0x200000	/* DVMRP msgs "beside" tunnel*/
#define	VIFF_IGMPV2		0x400000	/* Act as an IGMPv2 Router   */

struct phaddr {
    struct phaddr   *pa_next;
    uint32_t	     pa_subnet;		/* extra subnet			*/
    uint32_t	     pa_subnetmask;	/* netmask of extra subnet	*/
    uint32_t	     pa_subnetbcast;	/* broadcast of extra subnet	*/
};

/* The Access Control List (list with scoped addresses) member */
struct vif_acl {
    struct vif_acl  *acl_next;	    /* next acl member         */
    uint32_t	     acl_addr;	    /* Group address           */
    uint32_t	     acl_mask;	    /* Group addr. mask        */
};

struct vif_filter {
    int			vf_type;
#define	VFT_ACCEPT	1
#define	VFT_DENY	2
    int			vf_flags;
#define	VFF_BIDIR	1
    struct vf_element  *vf_filter;
};

struct vf_element {
    struct vf_element  *vfe_next;
    uint32_t		vfe_addr;
    uint32_t		vfe_mask;
    int			vfe_flags;
#define	VFEF_EXACT	0x0001
};

struct listaddr {
    TAILQ_ENTRY(listaddr) al_link;	/* link to next/prev addr           */
    uint32_t	     al_addr;		/* local group or neighbor address  */
    uint32_t	     al_mtime;		/* mtime from virtual_time, for IPC */
    time_t	     al_ctime;		/* entry creation time		    */
    union {
	struct {
    	    uint32_t alur_genid;	/* generation id for neighbor       */
	    uint32_t alur_nroutes;	/* # of routes w/ nbr as parent	    */
    	    uint8_t  alur_mv;		/* router mrouted version	    */
    	    uint8_t  alur_index;	/* neighbor index		    */
	} alu_router;
	struct {
    	    uint32_t alug_reporter;	/* a host which reported membership */
    	    int	     alug_timerid;	/* timer for group membership	    */
    	    int	     alug_query;	/* timer for repeated leave query   */
	} alu_group;
    } al_alu;
    uint8_t	     al_pv;		/* group/router protocol version    */
    int 	     al_pv_timerid;	/* timer for version switch         */
    uint16_t	     al_flags;		/* flags related to neighbor/group  */
};
#define	al_genid	al_alu.alu_router.alur_genid
#define	al_nroutes	al_alu.alu_router.alur_nroutes
#define al_mv		al_alu.alu_router.alur_mv
#define	al_index	al_alu.alu_router.alur_index
#define	al_reporter	al_alu.alu_group.alug_reporter
#define	al_timerid	al_alu.alu_group.alug_timerid
#define	al_query	al_alu.alu_group.alug_query

#define	NBRF_LEAF		0x0001	/* This neighbor is a leaf 	    */
#define	NBRF_GENID		0x0100	/* I know this neighbor's genid	    */
#define	NBRF_WAITING		0x0200	/* Waiting for peering to come up   */
#define	NBRF_ONEWAY		0x0400	/* One-way peering 		    */
#define	NBRF_TOOOLD		0x0800	/* Too old (policy decision) 	    */
#define	NBRF_TOOMANYROUTES	0x1000	/* Neighbor is spouting routes 	    */
#define	NBRF_STATIC_GROUP	0x4000	/* Static group entry		    */

/*
 * Don't peer with neighbors with any of these flags set
 */
#define	NBRF_DONTPEER		(NBRF_WAITING|NBRF_ONEWAY|NBRF_TOOOLD| \
				 NBRF_TOOMANYROUTES|NBRF_NOTPRUNING)

#define NO_VIF		((vifi_t)MAXVIFS)  /* An invalid vif index */

#endif /* QUERIERD_VIF_H_ */

/**
 * Local Variables:
 *  c-file-style: "cc-mode"
 * End:
 */
