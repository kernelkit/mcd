/* SPDX-License-Identifier: ISC */

#ifndef MCD_IFACE_H_
#define MCD_IFACE_H_

#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>

#include "inet.h"
#include "queue.h"

struct sock;

struct ifi {
    TAILQ_ENTRY(ifi) ifi_link;		 /* link to next/prev interface       */
    TAILQ_HEAD(,listaddr) ifi_static;    /* list of static groups (phyints)   */
    TAILQ_HEAD(,listaddr) ifi_groups;    /* list of local groups  (phyints)   */
    TAILQ_HEAD(,phaddr) ifi_addrs;	 /* Secondary addresses               */
    TAILQ_HEAD(,mrd_router) ifi_mrd_routers; /* MRD routers heard     */
    struct sock     *ifi_sock;		 /* Packet socket, shared per family  */
    uint32_t	     ifi_flags;	         /* IFIF_ flags defined below         */
    int		     ifi_vlan;	         /* Raw VLAN ID for send and accept   */
    char	     ifi_name[IFNAMSIZ]; /* interface name                    */
    int		     ifi_index;          /* Primarily for Linux systems       */
    int		     ifi_lower;          /* Bridge below a vlan interface     */
    int		     ifi_family;         /* AF_INET or AF_INET6, one querier each */
    int		     ifi_compat;         /* Protocol generation, GEN_V1 .. GEN_V3 */
    inet_addr_t      ifi_inaddr;         /* Current address of this interface */
    uint32_t	     ifi_query_interval; /* IGMP query interval               */
    struct listaddr *ifi_querier;        /* IGMP querier (one or none)        */
    int		     ifi_timerid;	 /* IGMP query timer           	      */
    int		     ifi_startup_timerid;/* startup query burst timer         */
    int		     ifi_topo_timerid;	 /* hold-off after a topology query   */
    int		     ifi_topo_pending;	 /* port change during the hold-off   */
    int		     ifi_mrd_timerid;	 /* next MRD advertisement            */
    int		     ifi_mrd_init;	 /* initial advertisements sent       */
    int		     ifi_mrd_pending;	 /* advertisement already on its way  */
    int		     ifi_igmpv1_warn;    /* To rate-limit IGMPv1 warnings     */
    uint8_t	     ifi_hwaddr[6];	 /* MAC address of this interface     */
};

#define IFIF_DOWN		0x000100 /* kernel state of interface */
#define IFIF_DISABLED		0x000200 /* administratively disabled */
#define IFIF_IGMP_QUERIER	0x000400 /* I am the subnet's querier */
#define IFIF_PROXY_QUERIER	0x002000 /* Act as proxy querier      */
#define IFIF_MRD		0x004000 /* Multicast Router Discovery */

/*
 * Protocol generations shared by IGMP and MLD, per interface compat
 * mode and per group: IGMPv1, IGMPv2 and MLDv1, IGMPv3 and MLDv2.
 */
#define GEN_V1			1
#define GEN_V2			2
#define GEN_V3			3

struct phaddr {
    TAILQ_ENTRY(phaddr) pa_link;
    inet_addr_t	     pa_addr;
};

struct listaddr {
    TAILQ_ENTRY(listaddr) al_link;	/* link to next/prev addr           */
    inet_addr_t      al_addr;		/* local group or neighbor address  */
    uint32_t	     al_mtime;		/* mtime from virtual_time, for IPC */
    time_t	     al_ctime;		/* entry creation time		    */
    inet_addr_t      al_reporter;	/* a host which reported membership */
    int		     al_timerid;	/* timer for group membership	    */
    int		     al_queryid;	/* timer for repeated leave query   */
    int		     al_interval;	/* querier's query interval         */
    uint8_t	     al_pv;		/* group/router protocol version    */
    int 	     al_pv_timerid;	/* timer for version switch         */
    uint16_t	     al_flags;		/* flags related to neighbor/group  */
};

#define	NBRF_STATIC_GROUP	0x4000	/* Static group entry		    */

/* A multicast router heard on the LAN, RFC 4286 */
struct mrd_router {
    TAILQ_ENTRY(mrd_router) link;
    inet_addr_t      addr;
    time_t	     expires;		/* NeighborDeadInterval from last   */
    int		     interval;		/* its advertisement interval, sec  */
    int		     qqi;		/* its query interval, sec          */
    int		     qrv;		/* its robustness variable          */
};

#endif /* MCD_IFACE_H_ */

/**
 * Local Variables:
 *  c-file-style: "cc-mode"
 * End:
 */
