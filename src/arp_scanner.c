#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <vector>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h> // close()
#include <cstdint>
#include <string.h>

int get_ip_from_interface(struct if_nameindex *interface, struct in_addr * addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    int ret;

    strncpy(ifr.ifr_name , interface->if_name, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        *addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
        ret = 0;
	} else { 
        ret = -1; 
    }

    close(fd);
    return ret;
}

int get_netmask_from_interface(struct if_nameindex *interface, struct in_addr * addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    int ret;

    strncpy(ifr.ifr_name , interface->if_name, IFNAMSIZ-1);

    // netmask
	if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
		*addr = ((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr;
        ret = 0;
	} else { 
        ret = -1; 
    }

    close(fd);
    return ret;
}

struct my_if_data {
	std::string Name;
	std::string Ip;
	std::string SubnetMask;
};

int calculateSubnetRange(struct in_addr * subnet_mask, struct in_addr * ip_addr, struct in_addr * broadcast_address) {

	//printf("IpAddr: %s\n", inet_ntoa(*ip_addr));
	//printf("SubnetMask: %s\n", inet_ntoa(*subnet_mask));

    broadcast_address->s_addr = ip_addr->s_addr | ~subnet_mask->s_addr;

    return 0;
}

int calculate_min_address_in_range(struct in_addr * subnet_mask, struct in_addr * ip_addr, struct in_addr * min_address) {
    min_address->s_addr = ip_addr->s_addr & subnet_mask->s_addr;
    return 0;
}

void do_arp(struct in_addr * address) {
    return;
}

void iterate_addresses(struct in_addr * broadcast_addr, struct in_addr * min_addr) {

    while (min_addr < broadcast_addr) {
        min_addr->s_addr = htonl(htonl(min_addr->s_addr) + 1);
        printf("%s\n", inet_ntoa(*min_addr));
        do_arp(min_addr);
    }
}

int main(int argc, char *argv[]) {
    struct if_nameindex *if_ni, *i;

    if_ni = if_nameindex(); // READ THIS
	if (if_ni == NULL) {
	   perror("if_nameindex");
	   exit(EXIT_FAILURE);
	}

	std::vector<my_if_data*> networkInterfaces;

   	for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
        //my_if_data *CurrentInterface;

        // todo
        //printf("\n%u: %s\n", i->if_index, i->if_name);
        struct in_addr ip_address;
        if (get_ip_from_interface(i, &ip_address) != 0) {
            //printf("Error no address for this interface");
            continue;
        };

        struct in_addr subnet_mask;
        if (get_netmask_from_interface(i, &subnet_mask) != 0) {
            //printf("Error no address for this interface");
            continue;
        }

        printf("%u: %s %s\n", i->if_index, i->if_name, inet_ntoa(ip_address));
        printf("%s\n", inet_ntoa(subnet_mask));

        struct in_addr broadcast_addr;
        if (calculateSubnetRange(&subnet_mask, &ip_address, &broadcast_addr) != 0) {
            //printf("Error no address for this interface");
            continue;
        }

        printf("%s\n", inet_ntoa(broadcast_addr));

        struct in_addr min_addr;
        if (calculate_min_address_in_range(&subnet_mask, &ip_address, &min_addr) != 0) {
            //printf("Error no address for this interface");
            continue;
        }

        // printf("%s\n", inet_ntoa(min_addr));


        // iterate_addresses(&broadcast_addr, &min_addr);
    }

    return 0;
}