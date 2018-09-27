#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h> // close()
#include <string.h>
#include <ifaddrs.h>

#include <linux/if_arp.h>
#include <arpa/inet.h>  //htons etc

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define BUF_SIZE 60

/*
 * Debugging tools for readability
 * and debugging obviously.
 */
#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");

/*
 * Struct for arp header.
 */
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    // debug("Copy IP address to arp_req");
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    // debug("get_if_info for %s", ifname);
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    // debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) {
        // debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    // debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    // debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        // debug("Cleanup socket");
        close(*fd);
    }
    return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd)
{
    // int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    // debug("read_arp");
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    
    int index;
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet 1");
        goto out;
    }

    // debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

    printf("[%s] - ", inet_ntoa(sender_a));
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    ret = 0;

out:
    return ret;
}

/*
 * Sends an ARP who-has request on
 * interface <interface> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int arp_handler(struct if_nameindex * interface, struct in_addr * ip) {
    int ret = -1;
    uint32_t dst = ntohl(ip->s_addr);
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(interface->if_name, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", interface->if_name);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }

    if (send_arp(arp_fd, ifindex, mac, src, dst)) {
        err("Failed to send_arp");
        goto out;
    }
    
    
    for (int i = 0; i < 10; i++) {
        int r = read_arp(arp_fd);
        if (r == 0) {
            // info("Got reply, break out");
            break;
        }
    }

    // int r = read_arp(arp_fd);
    // if (r == 0) {
    //     // info("Got reply, break out");
    // }

    ret = 0;
    out:
        if (arp_fd) {
            close(arp_fd);
            arp_fd = 0;
        }
        return ret;
}

/*
 * Gets host ip address from interface.
 * Returns 0 on success.
 */
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

/*
 * Gets subnet mask from interface.
 * Returns 0 on success.
 */
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

/*
 * Calculates broadcast address in subnet.
 * Returns 0.
 */
int calculate_broadcast_address(struct in_addr * subnet_mask, struct in_addr * ip_addr, struct in_addr * broadcast_address) {
    broadcast_address->s_addr = ip_addr->s_addr | ~subnet_mask->s_addr;
    return 0;
}

/*
 * Calculates min address in subnet.
 * Returns 0.
 */
int calculate_min_address_in_range(struct in_addr * subnet_mask, struct in_addr * ip_addr, struct in_addr * min_address) {
    min_address->s_addr = ip_addr->s_addr & subnet_mask->s_addr;
    return 0;
}


void iterate_addresses(struct if_nameindex *interface, struct in_addr * broadcast_addr,
 struct in_addr * min_addr, struct in_addr * ip_addr) {
    min_addr->s_addr = htonl(htonl(min_addr->s_addr) + 1);
    while (min_addr->s_addr < broadcast_addr->s_addr) {
        min_addr->s_addr = htonl(htonl(min_addr->s_addr) + 1);

        /* Don't want to ping ourselves */
        if (ip_addr->s_addr == min_addr->s_addr)
            continue; 
        arp_handler(interface, min_addr);
    }
}

/*
 * Handles all of the logic in arp-map
 * Gets the data and calls functions for 
 * calculating range of ipv4 addresses
 * in subnet.
 */
void handle_arp_map(int index) {

    struct ifaddrs *ifaddr, *ifa;
    char * interface_name;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    int count = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        char protocol[IFNAMSIZ]  = {0};

        if (ifa->ifa_addr == NULL ||
            ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        // check if interface is loopback
        int iIsLoopBack = (0 != (ifa->ifa_flags & IFF_LOOPBACK));
        if (!iIsLoopBack) { 
            if (count == index)
                interface_name = ifa->ifa_name;
            count++;
        }
    }

    if (count < index) {
        printf("Invalid index.\n");
        return;
    }

    struct if_nameindex *if_ni, *i;

    if_ni = if_nameindex();
	if (if_ni == NULL) {
	   perror("if_nameindex");
	   exit(EXIT_FAILURE);
	}

    for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
        if (strcmp(interface_name, i->if_name) == 0) {
            struct in_addr ip_address;
            if (get_ip_from_interface(i, &ip_address) != 0) {
                //printf("Error no address for this interface");
                continue;
            }

            struct in_addr subnet_mask;
            if (get_netmask_from_interface(i, &subnet_mask) != 0) {
                //printf("Error no address for this interface");
                continue;
            }

            struct in_addr min_addr;
            if (calculate_min_address_in_range(&subnet_mask, &ip_address, &min_addr) != 0) {
                //printf("Error no address for this interface");
                continue;
            }

            struct in_addr broadcast_addr;
            if (calculate_broadcast_address(&subnet_mask, &ip_address, &broadcast_addr) != 0) {
                //printf("Error no address for this interface");
                continue;
            }

            iterate_addresses(i, &broadcast_addr, &min_addr, &ip_address);

            break;
        }
    }
}


void menu() {
    printf("\n--- ARP Map ---\n");
    printf("Welcome to ARP-Map, the ultimate tool for scanning your computer's interfaces.\n");
    printf("\nSelect a following Interface to run an ARP-map scan on:\n");
    printf("[0] to reprint the menu\n");
}

int main(int argc, char *argv[]) {

    int command = 0;
    int index = 0;

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    /* Prompt user with menu */
    while(1) {
        menu();
        
        /* Walk through linked list, maintaining head pointer so we
        can free list later */
        index = 0;
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            char protocol[IFNAMSIZ]  = {0};

            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_PACKET) continue;
            
            // check if interface is loopback
            int iIsLoopBack = (0 != (ifa->ifa_flags & IFF_LOOPBACK));
            if (!iIsLoopBack) { 
                printf("[%d] %s\n", index + 1, ifa->ifa_name);
                index++;
            }
        }

        printf("\n\nEnter a command (-1 to quit):\n");
        scanf("%d", &command);
        if (command == -1)
            break;
        switch (command) {
            case 0:
                menu();
                break;
            default:
                if (command <= index) {
                handle_arp_map(command - 1);
                } else {
                    printf("Incorrect index, 0-%d only!", index);
                }
        }
    }
    freeifaddrs(ifaddr);
    return 0;
}
