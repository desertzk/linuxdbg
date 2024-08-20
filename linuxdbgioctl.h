#ifndef _LINUXDBGIOCTL_H
#define _LINUXDBGIOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>  // For kernel-space types
#else
#include <sys/ioctl.h>
#include <sys/types.h>    // For user-space types like pid_t
#endif



struct pte_args {
    pid_t pid;
    unsigned long address;
};

// Define the IOCTL command, using int instead of pid_t for compatibility
#define IOCTL_GET_MM _IOR('E', 1, pid_t)
#define IOCTL_PTE _IOR('E', 1, struct pte_args)


#endif // IOCTL_COMMON_H

