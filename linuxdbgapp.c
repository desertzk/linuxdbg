#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include<string.h>
#include <sys/ioctl.h>
#include <sys/types.h> 

#define DEVICE_PATH "/dev/linuxdbgdevice"
#define IOCTL_GET_MM _IOR('E', 1, pid_t)


int main(int argc, char *argv[])
{
    int fd;
    ssize_t bytes_written, bytes_read;
    char buffer[128];



    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address>\n", argv[0]);
        return 1;
    }

    // Get PID from the first argument
     pid_t pid = (pid_t)atoi(argv[1]);

    printf("pid %d  address %llx \n",pid,argv[2]);


    // Open the device for writing
    if ((fd = open(DEVICE_PATH, O_RDWR)) < 0) {
        perror("Failed to open the device");
        return 1;
    }

    // Call the IOCTL
    if (ioctl(fd, IOCTL_GET_MM, &pid) < 0) {
        perror("ioctl failed");
        close(fd);
        return 1;
    }


    // Write to the device
    printf("Writing to the device... %s  %d\n",argv[2],strlen(argv[2])+1);
    bytes_written = write(fd, argv[2], strlen(argv[2])+1);
    if (bytes_written != 14) {
        perror("Error writing to the device");
        close(fd);
        return 1;
    }

    // Read from the device
    printf("Reading from the device...\n");
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        perror("Error reading from the device");
        close(fd);
        return 1;
    }

    buffer[bytes_read] = '\0';  // Null terminate the string
    printf("Received: %s\n", buffer);

    // Close the device
    close(fd);

    return 0;
}