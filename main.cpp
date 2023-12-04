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

using namespace std;


void packet_callback(pqpr_callback* cbk){
    printf("data: %d\n",cbk->header->len);
    
    uint32_t ip_offset = 0;
    pq_ethhdr* ehddr = (pq_ethhdr*) (cbk->pkt_data);
    uint16_t protocol = ntohs(ehddr->h_proto);
    if (protocol == ETH_P_IP) {
        ip_offset = 14;
    } else {
        //printf(KRED "unsupported ETH protocol" KRESET "\n");
    }

    iphdr* iph = (iphdr*) (cbk->pkt_data + ip_offset);
    uint16_t ipheader_len = iph->ihl * 4;
    
    if(iph->version == 4){  //IPV4
        
        uint32_t src_ip = iph->saddr;
        uint32_t dest_ip = iph->daddr;
        uint32_t ip_protocol = iph->protocol;
        
        printf("IP Header Src Ip: %u    Dest IP:%u    Protocol:%u  \n",src_ip, dest_ip, ip_protocol);
        
        if(ip_protocol == IPPROTO_TCP)
        {
            tcphdr* tcph = (tcphdr*) (cbk->pkt_data + ip_offset + ipheader_len );
            uint16_t src_port = tcph->source;
            uint16_t dest_port = tcph->dest;
            
        } else if(ip_protocol ==  IPPROTO_UDP)
        {
            udphdr *udph = (udphdr *) (cbk->pkt_data + ip_offset + ipheader_len);
            uint16_t src_port = udph->uh_sport;
            uint16_t dest_port = udph->uh_dport;
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

