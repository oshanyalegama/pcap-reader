/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_support_functions.h
 * Author: chandula
 *
 * Created on December 21, 2022, 2:59 PM
 */

#ifndef PQ_PACKET_SUPPORT_FUNCTIONS_H
#define PQ_PACKET_SUPPORT_FUNCTIONS_H

struct pq_ethhdr {
    uint32_t h_dest_0; /// destination eth addr	
    uint16_t h_dest_1;
    uint32_t h_source_0; // source ether addr	
    uint16_t h_source_1;
    uint16_t h_proto; // packet type ID field	
} __attribute__ ((packed));




#endif /* PQ_PACKET_SUPPORT_FUNCTIONS_H */

