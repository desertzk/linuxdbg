#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>



#define PAGE_SIZE 4096ULL
#define PAGEMAP_LENGTH 8

int g_testnum=19;
char str[50]="";




unsigned long long get_pagemap_entry(unsigned long long vaddr, int pid) {
    char pagemap_file[64];
    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%d/pagemap", pid);

    int fd = open(pagemap_file, O_RDONLY);
    if (fd < 0) {
        perror("Error opening pagemap");
        exit(1);
    }

    unsigned long long index = vaddr / PAGE_SIZE * PAGEMAP_LENGTH;
    unsigned long long entry;
    lseek(fd, index, SEEK_SET);

    if (read(fd, &entry, PAGEMAP_LENGTH) != PAGEMAP_LENGTH) {
        perror("Error reading pagemap");
        close(fd);
        exit(1);
    }

    close(fd);

    if (entry & (1ULL << 63)) { // Check if page is present
        unsigned long long pfn = entry & ((1ULL << 55) - 1);
        return (pfn * PAGE_SIZE) | (vaddr & (PAGE_SIZE - 1));
    } else {
        printf("Page not present\n");
        return -1;
    }
}





void read_physical(unsigned long long physical_addr)
{

    int fd = open("/dev/mem", O_RDONLY);
    if (fd == -1) {
        perror("Error opening /dev/mem");
        exit(1);
    }

    void *map_base = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, physical_addr & ~(4096-1));
    if (map_base == MAP_FAILED) {
        perror("Error with mmap");
        close(fd);
        exit(1);
    }

    char *content = ((char*)map_base + (physical_addr & (4096-1)));
    printf("Content at physical address 0x%lx: %s\n", physical_addr, content);

    munmap(map_base, 4096);
    close(fd);
}



void test()
{
	 pid_t pid = getpid();  // Get the current process ID
    unsigned long long paddr = get_pagemap_entry(&g_testnum, pid);
printf("virtual address %llx physical address %llx \n",&g_testnum,paddr);
    unsigned long long pcaddr = get_pagemap_entry(str, pid);
printf("str virtual address %llx physical address %llx \n",str,pcaddr);
//read_physical(pcaddr);




}




int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <pid> <virtual address in hex>\n", argv[0]);
        return 1;
    }
    strcpy(str,"zykzykzkyyzkyzykzkzkzkzkzkkkkkkk");
test();
    int pid = atoi(argv[1]);
    unsigned long long vaddr = strtoull(argv[2], NULL, 16);
    unsigned long long paddr = get_pagemap_entry(vaddr, pid);

    if (paddr != -1) {
        printf("Physical address: 0x%llx\n", paddr);
    }

    return 0;
}

