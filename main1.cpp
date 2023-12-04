/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: hasith
 *
 * Created on May 9, 2016, 10:17 AM
 */

#include <cstdlib>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include "pq_packet_reader.h"
#include "pq_packet_classify.h"
#include "pq_packet_support_functions.h"

#include <arpa/inet.h>

using namespace std;

void ethernetAddressToString(uint64_t ethAddress, char *ethString, size_t size) {
    // Extract bytes from the uint64_t
    unsigned char bytes[6];
    bytes[0] = (ethAddress >> 40) & 0xFF;
    bytes[1] = (ethAddress >> 32) & 0xFF;
    bytes[2] = (ethAddress >> 24) & 0xFF;
    bytes[3] = (ethAddress >> 16) & 0xFF;
    bytes[4] = (ethAddress >> 8) & 0xFF;
    bytes[5] = ethAddress & 0xFF;

    // Format the Ethernet address string
    snprintf(ethString, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             bytes[3], bytes[2], bytes[1],
             bytes[0], bytes[5], bytes[4]);
}

void packet_callback(pqpr_callback* cbk){
    printf("data: %d\n",cbk->header->len);
    
    uint32_t ip_offset = 0;

    //extracting the ethernet header
    pq_ethhdr* ehddr = (pq_ethhdr*) (cbk->pkt_data);
    uint16_t protocol = ntohs(ehddr->h_proto);
    uint32_t eth_src_0 = ehddr->h_source_0;
    uint16_t eth_src_1 = ehddr->h_source_1;

    uint32_t eth_dest_0 = ehddr->h_dest_0;
    uint16_t eth_dest_1 = ehddr->h_dest_1;

    //ethernet source and destination
    uint64_t eth_src = ((uint64_t)eth_src_0 << 16) | eth_src_1;
    uint64_t eth_dest = ((uint64_t)eth_dest_0 << 16) | eth_dest_1;

    char eth_src_string[18];  // 17 characters for the address + 1 for the null terminator
    ethernetAddressToString(eth_src, eth_src_string, sizeof(eth_src_string));
    char eth_dest_string[18];  // 17 characters for the address + 1 for the null terminator
    ethernetAddressToString(eth_dest, eth_dest_string, sizeof(eth_dest_string));


    if (protocol == ETH_P_IP) {
        ip_offset = 14;
    } else {
        //printf(KRED "unsupported ETH protocol" KRESET "\n");
    }

    iphdr* iph = (iphdr*) (cbk->pkt_data + ip_offset);
    uint16_t ipheader_len = iph->ihl * 4;
    
    if(iph->version == 4){  //IPV4
        
        //Extracting the IP header
        uint32_t src_ip = (iph->saddr);
        uint32_t dest_ip = (iph->daddr);
        uint32_t ip_protocol = iph->protocol;

        
        //Converting the uint32_t addresses to human readable IPv4 format
        //Source
        // Convert uint32_t to struct in_addr 
        struct in_addr src_ip_struct;
        src_ip_struct.s_addr = src_ip;

        char src_ip_string[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_ip_struct,  src_ip_string, sizeof( src_ip_string));

        //Dest
        // Convert uint32_t to struct in_addr 
        struct in_addr dest_ip_struct;
        dest_ip_struct.s_addr = dest_ip;

        // Convert struct in_addr to human-readable IPV4 format
        char dest_ip_string[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest_ip_struct,  dest_ip_string, sizeof( dest_ip_string));

        
        
        printf("IP Header Src Ip: %s   Dest IP:%s   Protocol:%u  \n",src_ip_string, dest_ip_string, ip_protocol);
        //printf("IP Header Src Ip: %u   Dest IP:%u   Protocol:%u  \n",src_ip, dest_ip, ip_protocol);

        printf("Ethernet Header Src: %s   Dest:%s    Protocol:%u  \n",eth_src_string, eth_dest_string, protocol);
        //printf("Ethernet Header Src: %lld   Dest:%lld    Protocol:%u  \n",eth_src, eth_dest, protocol);

        
        if(ip_protocol == IPPROTO_TCP)
        {
            tcphdr* tcph = (tcphdr*) (cbk->pkt_data + ip_offset + ipheader_len );
            uint16_t src_port = htons(tcph->source);
            uint16_t dest_port = htons(tcph->dest);
            printf("TCP Header Src: %u  Dest:%u    \n",src_port, dest_port);
            
        } else if(ip_protocol ==  IPPROTO_UDP)
        {
            udphdr *udph = (udphdr *) (cbk->pkt_data + ip_offset + ipheader_len);
            uint16_t src_port = udph->uh_sport;
            uint16_t dest_port = udph->uh_dport;
            printf("UDP Header Src: %u   Dest:%u    \n",src_port, dest_port);
        }
        
    }
    else                    //IPV6
    {
        printf("Skip IPV6 type packets!");
    }
    
}
/*
 * 
 */
int main(int argc, char** argv) {
    pq_packet_readfile((char*)"smallFlows.pcap",false,1,packet_callback);
    
    //pq_packet_liveread((char*)"eth0",packet_callback);
    return 0;
}

