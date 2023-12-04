/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_mreader.h
 * Author: hasith@paraqum.com
 * Description : PCAP Live Capture Multi Interface Support
 * Created on January 15, 2018, 3:02 PM
 */

#ifndef PQ_PACKET_MREADER_H
#define PQ_PACKET_MREADER_H

#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define PDEV_MAX_IFACE_COUNT 4

typedef struct {
    const struct pcap_pkthdr *header;
    const u_char *pkt_data;
} pqpr_callback;

pcap_t *pcap_mifc[PDEV_MAX_IFACE_COUNT];
void (*cap_remote_callback_mifc[PDEV_MAX_IFACE_COUNT])(pqpr_callback*);

#endif /* PQ_PACKET_MREADER_H */

