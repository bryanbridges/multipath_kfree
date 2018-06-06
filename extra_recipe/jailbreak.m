//
//  jailbreak.c
//  multipath_kfree
//
//  Created by John Åkerblom on 6/1/18.
//  Copyright © 2018 kjljkla. All rights reserved.
//

#include "jailbreak.h"
#include "multipath_kfree.h"
#include "iansploit.h"
#include "offsets.h"
#include <unistd.h>

#define BEER 1
#define MULTIPATH 0

void jb_go(void)
{
    int poc = MULTIPATH; //change this to MULTIPATH if you want the other exploit
    
    printf("Stage 1: Exploiting the kernel.\n");
    init_offsets();
    
    if(poc == BEER) {
        
        brewbeer();
    
    } else {
    
        multipath_exploit();
    
    }

    for (;;)
        sleep(1);
}
