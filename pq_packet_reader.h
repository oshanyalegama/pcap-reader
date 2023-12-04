/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_reader.h
 * Author: hasith
 *
 * Created on May 9, 2016, 10:29 AM
 */

#ifndef PQ_PACKET_READER_H
#define PQ_PACKET_READER_H

#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif
#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
    const struct pcap_pkthdr *header;
    const u_char *pkt_data;
} pqpr_callback;

pcap_t *pcap;
pcap_dumper_t *dumpfile;
static bool capture_to_file = false;

void (*cap_remote_callback)(pqpr_callback*);

/**
 * External Function [ get the given capture interface IP Address]
 * @param capDev capture Interface
 * @return IP address 
 */
uint32_t
pq_get_interface_ip(const char* capDev) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t ifaceIP = 1;

    int status = pcap_findalldevs(&alldevs, errbuf);
    if (status != 0) {
        printf("%s\n", errbuf);
        return 1;
    }
    std::string cap(capDev);
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        //printf("IFCS: %s  %s\n", d->name, capDev);
        std::string com(d->name);
        if (cap == com) {
            ifaceIP = 100;
            for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
                if (a->addr->sa_family == AF_INET) {
                    ifaceIP = (((struct sockaddr_in*) a->addr)->sin_addr).s_addr;
                    //printf(" %s\n", inet_ntoa(((struct sockaddr_in*) a->addr)->sin_addr));
                }                
            }
            break;
        }
    }
    pcap_freealldevs(alldevs);
    return ifaceIP;
}

/**
 * Internal Function [read packets from file support]
 * @param _fileName File Path
 * @return zero
 */
int
read_packets_from_file(const char* _fileName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap = pcap_open_offline(_fileName, errbuf)) == NULL)
        printf("Unable to open standard input for packets:\n%s",
            errbuf);

    struct pcap_pkthdr *h;
    const u_char *data;
    int n;
    uint64_t pktcount = 0;
    while (1) {
        n = pcap_next_ex(pcap, &h, &data);
        if (n == -2) {
            break;
        }
        if (n == -1)
            printf("Unable to read one packet:\n%s", pcap_geterr(pcap));

        pqpr_callback pktData;
        pktData.header = h;
        pktData.pkt_data = data;
        cap_remote_callback(&pktData);
    }

    pcap_close(pcap);
    return 0;
}

/**
 * Internal Function [Live packet capture support]
 * @param useless empty
 * @param pkthdr packet header data
 * @param packet packet data
 */
void
cap_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char *
        packet) {

    pqpr_callback data;
    data.header = pkthdr;
    data.pkt_data = packet;
    cap_remote_callback(&data);
}

/**
 * Internal Function [Live packet capture support]
 * @param arg_1 empty string
 * @param _capDev capture interface
 * @return zero
 */
int
init_live_packat_cap(char* arg_1, const char *_capDev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr; /* pcap.h                    */
    struct ether_header *eptr; /* net/ethernet.h            */
    struct bpf_program fp; /* hold compiled program     */
    bpf_u_int32 maskp; /* subnet mask               */
    bpf_u_int32 netp; /* ip                        */

    uint32_t ip_ad = pq_get_interface_ip(_capDev);
    if (ip_ad == 1) {
        printf("%s Interface not found. Finding other Interface\n", _capDev);
        _capDev = pcap_lookupdev(errbuf);
    }
    if (_capDev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    printf("Device: %s\n", _capDev);
    pcap_t *handle;

    handle = pcap_open_live(_capDev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", _capDev, errbuf);
        return (2);
    }

    //If your program doesn't support the link-layer header type provided by the device, it has to give up; 
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", _capDev);
        return (2);
    }

    /* Lets try and compile the program.. non-optimized */
    if (pcap_compile(handle, &fp, arg_1, 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    /* set the compiled program as the filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    if (capture_to_file) {
        dumpfile = pcap_dump_open(handle, "pkt_dump.pcap");
    }
    /* ... and loop */
    pcap_loop(handle, -1, cap_callback, NULL);
}

/**
 * Live Capture Packets from Given Interface
 * @param iface Interface Name
 * @param callback Callback function
 */
void pq_packet_liveread(char* iface, void (*callback)(pqpr_callback*)) {
    cap_remote_callback = callback;
    char *str;
    init_live_packat_cap(str, iface);
}

/**
 * Read Packets from given pcap File
 * @param filename File Location
 * @param isloopread true for read file in loop
 * @param callback Callback function
 */
void pq_packet_readfile(char* filename, bool isloopread, int count_read, void (*callback)(pqpr_callback*)) {
    cap_remote_callback = callback;
    uint32_t count_temp = 0;
    while (isloopread) {
        read_packets_from_file(filename);
        count_temp++;
        if (count_read > 0) {
            if (count_temp > count_read) {
                break;
            }
        }
    }
    read_packets_from_file(filename);
}

#endif /* PQ_PACKET_READER_H */

