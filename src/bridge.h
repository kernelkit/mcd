/* SPDX-License-Identifier: ISC */

#ifndef MCD_BRIDGE_H_
#define MCD_BRIDGE_H_

#include <stdio.h>

extern void bridge_prop         (FILE *fp, const char *brname, const char *prop);
extern void bridge_router_ports (FILE *fp, const char *brname);

extern int  show_bridge_compat  (FILE *fp);
extern int  show_bridge_groups  (FILE *fp);

#endif /* MCD_BRIDGE_H_ */
