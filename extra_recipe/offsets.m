//
//  offsets.m
//  extra_recipe
//
//  Created by Sem Voigtländer on 6/2/18.
//  Copyright © 2018 Ian Beer. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <Foundation/Foundation.h>
#include "offsets.h"

int* ian_offsets = NULL;

int kstruct_offsets_11_0[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x108, // KSTRUCT_OFFSET_PROC_P_FD
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x6c,  // KFREE_ADDR_OFFSET
};

int kstruct_offsets_11_3[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x108, // KSTRUCT_OFFSET_PROC_P_FD
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x7c,  // KFREE_ADDR_OFFSET
};

int koffset(enum kstruct_offset offset) {
    if (ian_offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        return 0;
    }
    return ian_offsets[offset];
}


int hasOffsets = 0;
ExploitOffsets offsets = {
};




ExploitOffsets init_offsets_iPhone81_11_3_1() {
    ExploitOffsets offsets = {};
    offsets.metaclass = 0xfffffff0074c5410;
    offsets.rootvnode = 0xfffffff0075d5088;
    offsets.copyin = 0xfffffff0071a7090;
    offsets.copyout = 0xfffffff0071a72b4;
    offsets.kernel_task = 0xfffffff0075d5048;
    offsets.kernel_map = 0xFFFFFFF0075D5030;
    offsets.allproc = 0xFFFFFFF00777FC68;
    offsets.kernproc = 0xfffffff0075d50a0;
    offsets.AGXCommandQueue_vtable = 0xfffffff006ffa3d0;
    offsets.osserializer_serialize = 0xFFFFFFF0074DC3C8;
    return offsets;
}


ExploitOffsets init_offsets_iPhone82_11_3_1() {
    ExploitOffsets offsets = {};

    return  offsets;
}

ExploitOffsets init_offsets_iPhone83_11_3_1() {
    ExploitOffsets offsets = {};
    return  offsets;
}

ExploitOffsets init_offsets_iPhone84_11_3_1() {
    ExploitOffsets offsets = {};
    offsets.metaclass = 0;
    offsets.rootvnode = 0xfffffff0075d5088;
    offsets.copyin = 0xfffffff0071a7090;
    offsets.copyout = 0xfffffff0071a72b4;
    offsets.kernel_task = 0xfffffff0075d5048;
    offsets.kernel_map = 0xfffffff0075d5050;
    offsets.realhost = 0xfffffff0075dab98;
    offsets.kernproc = 0;
    offsets.allproc = 0;
    return  offsets;
}

ExploitOffsets init_offsets_iPhone91_11_3_1() {
    ExploitOffsets offsets = {};
    return  offsets;
}

ExploitOffsets init_offsets_iPhone92_11_3_1() {
    ExploitOffsets offsets = {};
    return  offsets;
}

ExploitOffsets init_offsets_iPhone93_11_3_1() {
    ExploitOffsets offsets = {};
    return  offsets;
}
//iPhone9,4 GSM iPhone 7+ kernel offsets found by @LavarBridges
ExploitOffsets init_offsets_iPhone94_11_3_1() {
    ExploitOffsets offsets = {0};
    offsets.metaclass = 0xfffffff00750eb04;
    offsets.rootvnode = 0xfffffff007621088;
    offsets.copyin = 0xfffffff0071f0534;
    offsets.copyout = 0xfffffff0071f075c;
    offsets.kernel_task = 0xfffffff007621050;
    offsets.kernel_map = 0xfffffff007621050;
    offsets.allproc = 0xFFFFFFF00777FC68;
    offsets.kernproc = 0xfffffff0075d50a0;
    offsets.AGXCommandQueue_vtable = 0xfffffff006ea9800;
    offsets.osserializer_serialize = 0xfffffff007525abc;
    return offsets;
}
//iPhone X 15E302
ExploitOffsets init_offsets_iPhone103_11_3_1() {
    ExploitOffsets offsets = {};
    offsets.kernproc = 0xfffffff0076450a8;;
    offsets.AGXCommandQueue_vtable = 0xfffffff006fdd978;
    return offsets;
}

//iPad Air 2 (WiFi)
ExploitOffsets init_offsets_iPad53_11_3_1() {
    ExploitOffsets offsets = {};
    offsets.kernproc = 0xfffffff0075dd0a0;
    offsets.AGXCommandQueue_vtable = 0xfffffff006fd9dd0;
    return offsets;
}

void ian_offsets_init() {
    if (@available(iOS 11.4, *)) {
        printf("this bug is patched in iOS 11.4 and above\n");
        exit(EXIT_FAILURE);
    } else if (@available(iOS 11.3, *)) {
        printf("offsets selected for iOS 11.3 or above\n");
        ian_offsets = kstruct_offsets_11_3;
    } else if (@available(iOS 11.0, *)) {
        printf("offsets selected for iOS 11.0 to 11.2.6\n");
        ian_offsets = kstruct_offsets_11_0;
    } else {
        printf("iOS version too low, 11.0 required\n");
        exit(EXIT_FAILURE);
    }
}


void init_offsets() {
    
    ian_offsets_init();
    
    size_t size = 32;
    char build_id[size];
    memset(build_id, 0, size);
    int err = sysctlbyname("kern.osversion", build_id, &size, NULL, 0);
    if (err == -1) {
        printf("failed to detect version (sysctlbyname failed\n");
        return;
    }
    printf("build_id: %s\n", build_id);
    
    struct utsname u = {0};
    uname(&u);
    
    printf("sysname: %s\n", u.sysname);
    printf("nodename: %s\n", u.nodename);
    printf("release: %s\n", u.release);
    printf("version: %s\n", u.version);
    printf("machine: %s\n", u.machine);
    
    // set the offsets
    
    if (strcmp(build_id, "15E302") == 0) {
        
        /*
        //iPhone 6 Global
        if(strcmp(u.machine, "iPhone7,1") == 0) {
            
        }
        
        //iPhone 6 CDMA
        else if(strcmp(u.machine, "iPhone7,2") == 0) {
         
        } else
        */
        //iPhone 6S Global
        if(strcmp(u.machine, "iPhone8,1") == 0) {
             offsets = init_offsets_iPhone81_11_3_1();
        }
        
        else if(strcmp(u.machine, "iPhone8,4") == 0) {
            offsets = init_offsets_iPhone84_11_3_1();
        else if(strcmp(u.machine, "iPHone9,4") == 0) {
            offsets = init_offsets_iPhone94_11_3_1();
        } else {
            printf("Your device isn't supported yet, find your offsets and add them to offsets.m in the project.\n");
            return;
        }
    } else {
        printf("Currently this only supports iOS 11.3.1.\n");
        hasOffsets = 0;
        return;
    }
    
    printf("Your offsets are: \n\n");
    printf("- AGXCommandQueue vtable: %#llx\n", offsets.AGXCommandQueue_vtable);
    printf("- copyin: %#llx\n", offsets.copyin);
    printf("- copyout: %#llx\n", offsets.copyout);
    printf("- OSSerializer_Serialize: %#llx\n", offsets.osserializer_serialize);
    printf("- OSMetaClass: %#llx\n", offsets.metaclass);
    printf("- kernproc: %#llx\n", offsets.kernproc);
    printf("- kernel_map: %#llx\n", offsets.kernel_map);
    printf(" \n");
    if(offsets.AGXCommandQueue_vtable == 0) {
        printf("We wont be able to leak aslr because an invalid offset for AGXCommandQueue_vtable.\n");
    }
    if(offsets.copyin == 0) {
        printf("We wont be able to gain kernel r/w because an invalid offset for copyin.\n");
    }
    if(offsets.copyout == 0) {
        printf("We wont be able to gain kernel r/w because an invalid offset for copyout.\n");
    }
    if(offsets.osserializer_serialize == 0) {
        printf("We wont be able to gain kernel r/w because an invalid offset for OSSerializer::Serialize().\n");
    }
    if(offsets.metaclass == 0) {
        printf("We wont be able to gain kernel r/w because an invalid offset for OSMetaClass.\n");
    }
    if(offsets.kernproc == 0) {
        printf("We wont be able to do post-exploitation with QiLin because an invalid offset for kernproc.\n");
    }
}

















