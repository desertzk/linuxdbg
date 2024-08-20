
#include <fcntl.h>
#include <unistd.h>
#include<string.h>
#include <sys/ioctl.h>
#include <sys/types.h> 
#include <iostream>
#include <string>
#include <unordered_map>
#include <functional>


#include"linuxdbgioctl.h"

#define DEVICE_PATH "/dev/linuxdbgdevice"



// Define functions for each command
void pte(int fd,char *argv[]) {
    std::cout << "Starting the process..." << std::endl;
    struct pte_args args;
    // Get PID from the first argument
    pid_t pid = (pid_t)atoi(argv[2]);

    

    unsigned long address;
    char *caddress;
    address = strtoul(argv[3], &caddress, 0);
    args.pid = pid;
    args.address = address;
    printf("pid %d  address %lx \n",pid,address);


    // Call the IOCTL
    if (ioctl(fd, IOCTL_PTE, &args) < 0) {
        perror("ioctl failed");
        close(fd);
        //return 1;
    }

    // Call the IOCTL
    // if (ioctl(fd, IOCTL_GET_MM, &pid) < 0) {
    //     perror("ioctl failed");
    //     close(fd);
    //     return 1;
    // }

    // // Write to the device
    // printf("Writing to the device... %s  %d\n",argv[2],strlen(argv[2])+1);
    // bytes_written = write(fd, argv[2], strlen(argv[2])+1);
    // if (bytes_written != 14) {
    //     perror("Error writing to the device");
    //     close(fd);
    //     return 1;
    // }
}

void print_vma(int fd,char *argv[]) {
    std::cout << "Stopping the process..." << std::endl;
}

void edit_data(int fd,char *argv[]) {
    std::cout << "Restarting the process..." << std::endl;
}

void display_data(int fd,char *argv[]) {
    std::cout << "Checking the status..." << std::endl;
}


int main(int argc, char *argv[])
{
    int fd;
    ssize_t bytes_written, bytes_read;
    char buffer[128];

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <command> <arg1> [arg2]" << std::endl;
        return 1;
    }


    std::string cmd = argv[1];


    // Open the device for writing
    if ((fd = open(DEVICE_PATH, O_RDWR)) < 0) {
        perror("Failed to open the device");
        return 1;
    }


        
    // Define a map of commands to actions
    std::unordered_map<std::string, std::function<void(int,char *argv[])>> command_map = {
        {"pte", pte},
        {"pvma", print_vma},
        {"ed", edit_data},
        {"dd", display_data}
    };



   // Find and execute the corresponding command
    auto it = command_map.find(cmd);
    if (it != command_map.end()) {
        it->second(fd,argv);  // Call the function associated with the command
    } else {
        std::cerr << "Unknown command: " << cmd << std::endl;
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