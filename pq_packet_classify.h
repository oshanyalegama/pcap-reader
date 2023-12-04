/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_classify.h
 * Author: hasith
 *
 * Created on May 9, 2016, 3:33 PM
 */

#ifndef PQ_PACKET_CLASSIFY_H
#define PQ_PACKET_CLASSIFY_H

#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

#include <vector>
#include <string.h>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

using namespace std;

typedef struct {
    uint8_t rule_id;
    std::string rule;
}
pq_rule;
std::vector<pq_rule> rule_set;

typedef struct __attribute__((packed)) dns_packet_header {
    u_int16_t transaction_id, flags, num_queries, answer_rrs, authority_rrs, additional_rrs;
}
dns_packet_header;

typedef struct {
    char client[INET6_ADDRSTRLEN];
    char server[INET6_ADDRSTRLEN];
    char ssl2; /* Inside a SSL2 packet */
    unsigned char vmajor; /* Major SSL version */
    unsigned char vminor; /* Minor SSL version */
    int sessionidlen;
    unsigned char sessionid[32]; /* Session ID */
    char *ciphers; /* List of cipher suites */
    char *compression; /* List of compression methods */
    std::string sservername; /* TLS extension: server name */
    char ticket; /* Ticket extension present */
    int ticketlen; /* Ticket length */
} https_hello;

typedef struct __attribute__((packed)) {
    uint16_t des_port;
    uint16_t src_port;
    uint16_t payload_length;
    uint8_t ip_protocol;
    char* payload;
    uint8_t ip_count;
    uint8_t rule_hit;
    uint32_t* ip_data;
}
pkt_attributes;

typedef struct {
    uint8_t id;
    std::string app_name;
    std::string signature;
    std::string type;
} pq_rule_element;

pq_rule_element pq_rules [] = {
    {1, "DropBox", ".dropbox.com", "ANY"},
    {2, "Facebook", ".facebook.com", "ANY"},
    {2, "Facebook", ".fbcdn.net", "ANY"},
    {2, "Facebook", "fbcdn-", "ANY"},
    {2, "Facebook", "fbstatic-", "ANY"},
    {2, "Facebook", "fbexternal-", "ANY"},
    {3, "Google", ".google.", "ANY"},
    {3, "Google", ".gstatic.com", "ANY"},
    {3, "Google", ".googlesyndication.com", "ANY"},
    {3, "Google", ".googletagservices.com", "ANY"},
    {3, "Google", ".2mdn.net", "ANY"},
    {3, "Google", ".doubleclick.net", "ANY"},
    {3, "Google", "googleads.", "ANY"},
    {3, "Google", "google-analytics.", "ANY"},
    {3, "Google", "googleusercontent.", "ANY"},
    {3, "Google", "googleadservices.", "ANY"},
    {3, "Google", "googleapis.com", "ANY"},
    {3, "Google", "ggpht.com", "ANY"},
    {3, "GoogleMaps", "maps.google.", "ANY"},
    {3, "GoogleMaps", "maps.gstatic.com", "ANY"},
    {4, "GMail", ".gmail.", "ANY"},
    {4, "GMail", "mail.google.", "ANY"},
    {5, "Skype", ".skype.", "ANY"},
    {5, "Skype", ".skypeassets.", "ANY"},
    {5, "Skype", ".skypedata.", "ANY"},
    {5, "Skype", ".skypeecs-", "ANY"},
    {6, "Twitter", ".twttr.com", "ANY"},
    {6, "Twitter", "twitter.", "ANY"},
    {6, "Twitter", "twimg.com", "ANY"},
    {7, "Viber", ".viber.com", "ANY"},
    {8, "WhatsApp", ".whatsapp.net", "ANY"},
    {9, "YouTube", "youtube.", "ANY"},
    {9, "YouTube", ".googlevideo.com", "ANY"},
    {9, "YouTube", ".ytimg.com", "ANY"},
    {9, "YouTube", "youtube-nocookie.", "ANY"},
    {10, "Instagram", "instagram.com", "ANY"},
    {10, "Instagram", "igcdn-photos-", "ANY"},
    {10, "Instagram", "instagramstatic-", "ANY"},
    {10, "Instagram", "instagramimages-", "ANY"},
    {10, "Instagram", ".cdninstagram.com", "ANY"}
};

struct tcphaddr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urg;
    /* Options */
} __attribute__((__packed__));

void add_rule(uint8_t id, char* rule) {
    pq_rule rul;
    rul.rule = rule;
    rul.rule_id = id;
    rule_set.push_back(rul);
}

bool dns_decode(pkt_attributes * attr) { //Process the Packet

#define DPI_MAX_DNS_REQUESTS   16
    static char host_server_name[2048];
    u_int16_t dport = 0, sport = 0;
    attr->ip_count = 0;
    sport = ntohs(attr->des_port), dport = ntohs(attr->src_port);

    if (((dport == 53) || (sport == 53) || (dport == 5355))
            && (attr->payload_length > sizeof (struct dns_packet_header))) {

        int i = (attr->ip_protocol == 1) ? 2 : 0;
        struct dns_packet_header header, *dns = (struct dns_packet_header*) &attr->payload[i];

        u_int8_t is_query, ret_code, is_dns = 0;
        u_int32_t a_record[DPI_MAX_DNS_REQUESTS] = {0}, query_offset, num_a_records = 0;

        header.flags = ntohs(dns->flags);
        header.transaction_id = ntohs(dns->transaction_id);
        header.num_queries = ntohs(dns->num_queries);
        header.answer_rrs = ntohs(dns->answer_rrs);
        header.authority_rrs = ntohs(dns->authority_rrs);
        header.additional_rrs = ntohs(dns->additional_rrs);
        is_query = (header.flags & 0x8000) ? 0 : 1;
        ret_code = is_query ? 0 : (header.flags & 0x0F);
        i += sizeof (struct dns_packet_header);
        query_offset = i;



        if (is_query) {

        } else {
            /* DNS Reply */
            if ((header.num_queries <= DPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
                    && (((header.answer_rrs > 0) && (header.answer_rrs <= DPI_MAX_DNS_REQUESTS))
                    || ((header.authority_rrs > 0) && (header.authority_rrs <= DPI_MAX_DNS_REQUESTS))
                    || ((header.additional_rrs > 0) && (header.additional_rrs <= DPI_MAX_DNS_REQUESTS)))
                    ) {

                //printf("Try Get DNS\n"); //(char*) _flow->payload);

                /* This is a good query */
                is_dns = 1;

                //i++;            

                int j = 0;

                //printf(_flow->payload[i] + "");

                u_int8_t _dns_go_ahad = (*((u_int8_t*) (attr->payload + i)));
                i++;
                uint16_t _dns_string_length = 0;
                while (_dns_go_ahad != 0) {
                    for (int dc = 0; dc < _dns_go_ahad; dc++) {
                        host_server_name[j] = (u_char) (attr->payload[i]);
                        j++;
                        i++;
                    }
                    _dns_go_ahad = (*((u_int8_t*) (attr->payload + i)));
                    if (_dns_go_ahad != 0) {
                        host_server_name[j] = '.';
                        j++;
                    }
                    i++;
                }
                _dns_string_length = j;
                // Now We Have The Host Name

                //Lets Look for the Type of The Dns Query
                u_int16_t q_type = ntohs(*((u_int16_t*) (attr->payload + i)));
                i += 2;

                if (q_type == 1) { //Type A Host
                    //
                } else if (q_type == 5) { //Type CNAME Alias

                } else {
                    //printf("..................CHECK DNS Qury Type........................\n"); //TO-DO Domain Name Pointer is Also there
                }

                i += 2; //Skip 2 bytes (Class Field)

                if (header.answer_rrs > 0) {
                    bool is_dns_hit = false;
                    int dns_hit_point = 0;
                    uint8_t ip_count = 0;
                    std::string _serverName((char*) host_server_name, _dns_string_length);
                    //printf("%s\n", _serverName.c_str());
                    for (int rule_count = 0; rule_count < rule_set.size(); rule_count++) {
                        char * pch;
                        pch = strstr((char*) _serverName.c_str(), rule_set[rule_count].rule.c_str());
                        if (pch != NULL) {
                            dns_hit_point = rule_set[rule_count].rule_id;
                            attr->rule_hit = dns_hit_point;
                            is_dns_hit = true;
                            printf("DNS: %u %s\n", attr->rule_hit, _serverName.c_str());
                            break;
                        }
                    }

                    u_int16_t rsp_type /*, rsp_class */;
                    u_int16_t num;
                    uint16_t _adress_length;

                    for (num = 0; num < header.answer_rrs; num++) {

                        i += 2; //Skip 2 bytes (Next Name)

                        rsp_type = ntohs(*((u_int16_t*) (attr->payload + i)));
                        i += 2;

                        i += 2; //Skip the Class IN

                        i += 4; //Skip the TTL


                        _adress_length = ntohs(*((u_int16_t*) (attr->payload + i)));
                        i += 2;

                        if (rsp_type == 1) { //Type A Host
                            u_int32_t Ip_adress = (*((u_int32_t*) (attr->payload + i)));
                            attr->ip_data[attr->ip_count] = Ip_adress;
                            attr->ip_count++;
                            i += _adress_length;
                        } else if (rsp_type == 5) {
                            i += _adress_length;
                        }
                    }
                    if (is_dns_hit && attr->ip_count > 0) {
                        return true;
                    } else {
                        if (is_dns_hit != 1) {
                            //printf("DNS Host Name Missed: %s\n", _flow->host_server_name);
                        } else {
                            // printf("test ..................................... %s  ....... %u\n",host_server_name,0);
                        }
                    }
                }
            }
        }

        if ((header.num_queries <= DPI_MAX_DNS_REQUESTS)
                && ((header.answer_rrs == 0)
                || (header.authority_rrs == 0)
                || (header.additional_rrs == 0))
                && (ret_code != 0 /* 0 == OK */)
                ) {
            /* This is a good reply */
            is_dns = 1;
        }
    }

    return false;

}

https_hello *ssl_decoder(https_hello* c_hello, const u_char *data, int len) { //Look for SSL Signatures
    if (len < 14) return NULL;
    int proto;
    memcpy(&proto, data + 12, 2);
    if (ntohs(proto) != 0x800) return NULL;
    data += 14;
    len -= 14;

    /* IP header. */
    u_int8_t version;
    if (len < 1) return NULL;
    version = (data[0] & 0xf0) >> 4;
    switch (version) {
        case 4:
            /* IPv4 */
            if (len < 20) return NULL;
            struct iphdr ip4;
            memcpy(&ip4, data, sizeof (ip4));
            if ((ntohs(ip4.frag_off) & 0xbf) != 0) return NULL; /* Don't handle fragments */
            if (ip4.protocol != 6) return NULL; /* TCP only */
            if (ntohs(ip4.tot_len) < len) return NULL; /* Packet too small */
            len = ntohs(ip4.tot_len); /* Keep only real data */
            if (!inet_ntop(AF_INET, &ip4.saddr,
                    c_hello->client, sizeof (c_hello->client))) return NULL;
            if (!inet_ntop(AF_INET, &ip4.daddr,
                    c_hello->server, sizeof (c_hello->server))) return NULL;
            data += (ip4.ihl) * 4;
            len -= (ip4.ihl) * 4;
            /* TCPv4 */
            if (len < 20) return NULL;
            tcphaddr tcp4;
            memcpy(&tcp4, data, sizeof (tcp4));
            if (ntohs(tcp4.flags) & 0x7) return NULL; /* SYN, FIN, RST */
            data += ((ntohs(tcp4.flags) & 0xf000) >> 12) * 4;
            len -= ((ntohs(tcp4.flags) & 0xf000) >> 12) * 4;
            break;
        case 6:
            /* IPv6 */
            return NULL; /* TODO */
            break;
        default: return NULL;
    }

    /* SSLv2 + SSLv3/TLS. See ssl/s23_srvr.c for detection logic */
    if (len < 11) return NULL;
    u_int16_t tlen;
    if ((data[0] & 0x80) && (data[2] == 1)) {
        /* Let's assume SSLv2. This is now prohibited, see RFC 6176, but
           we want to keep track of clients still using it. */
        c_hello->ssl2 = 1;
        memcpy(&tlen, data, 2);
        tlen = ntohs(tlen) & 0x2fff;
        c_hello->vmajor = data[3];
        c_hello->vminor = data[4];
        if (c_hello->vmajor != 2 && c_hello->vmajor != 3) return NULL;
        if (c_hello->vmajor == 2 && c_hello->vminor != 0) return NULL;
        if (c_hello->vmajor == 3 && c_hello->vminor > 3) return NULL;
        if (tlen != len - 2) return NULL;

        u_int16_t sidlen;
        u_int16_t ciphlen;
        memcpy(&sidlen, data + 7, 2);
        sidlen = ntohs(sidlen);
        memcpy(&ciphlen, data + 5, 2);
        ciphlen = ntohs(ciphlen);
        if (len < 11 + sidlen + ciphlen) return NULL;

        /* Session ID */
        if (sidlen != 16 && sidlen != 0) return NULL;
        memcpy(c_hello->sessionid, data + 11 + ciphlen, sidlen);
        c_hello->sessionidlen = sidlen;
    } else {
        /* SSLv3 or TLS */
        if (data[0] != 22) return NULL; /* Not TLS Handshake */
        if (data[1] != 3) return NULL; /* Not TLS 1.x */
        if (data[2] > 3) return NULL; /* TLS 1.3 or more */
        memcpy(&tlen, data + 3, 2);
        tlen = ntohs(tlen);
        data += 5;
        len -= 5;
        if (tlen != len) return NULL;
        if (len < 5) return NULL;
        if (data[0] != 1) return NULL; /* Client Hello */
        if (data[1] != 0) return NULL; /* We don't handle fragmentation */
        memcpy(&tlen, data + 2, 2);
        if (ntohs(tlen) != len - 4) return NULL;
        c_hello->vmajor = data[4];
        c_hello->vminor = data[5];
        if (c_hello->vmajor != 3) return NULL;
        if (c_hello->vminor > 3) return NULL;
        data += 38;
        len -= 38;

        /* Session ID */
        if (len < 1) return NULL;
        c_hello->sessionidlen = data[0];
        if (c_hello->sessionidlen != 0 &&
                c_hello->sessionidlen != 32) return NULL; /* Session ID should be 32 */
        memcpy(c_hello->sessionid, data + 1, c_hello->sessionidlen);
        data += 1 + c_hello->sessionidlen;
        len -= 1 + c_hello->sessionidlen;

        /* Ciphers */
        if (len < 2) return NULL;
        u_int16_t ciphlen;
        memcpy(&ciphlen, data, 2);
        ciphlen = ntohs(ciphlen);
        data += ciphlen + 2;
        len -= ciphlen + 2;

        /* Compression methods */
        if (len < 1) goto err;
        unsigned char complen = data[0];
        if (complen == 0) goto err;
        if (len < 1 + complen) goto err;
        len -= data[0] + 1;
        data += data[0] + 1;

        /* Extensions */
        if (len > 2) {
            u_int16_t extlen;
            memcpy(&extlen, data, 2);
            extlen = ntohs(extlen);
            if (len != extlen + 2) goto err;
            data += 2;
            len -= 2;
            while (len > 0) {
                u_int16_t exttype;
                char *sni; /* Current name */
                u_int16_t snilen; /* Length of current name */
                u_int16_t clen; /* Remaining length in extension */
                const unsigned char *p; /* Current position in data */
                if (len < 4) goto err;
                memcpy(&exttype, data, 2);
                exttype = ntohs(exttype);
                memcpy(&extlen, data + 2, 2);
                extlen = ntohs(extlen);
                if (len + 4 < extlen) goto err;
                switch (exttype) {
                    case 0: /* Server name */
                        if (extlen < 2) break;
                        memcpy(&clen, data + 4, 2);
                        clen = ntohs(clen);
                        if (clen + 2 != extlen) break;
                        p = data + 6;
                        while (clen >= 3) {
                            memcpy(&snilen, p + 1, 2);
                            snilen = ntohs(snilen);
                            if (clen < snilen + 3) break;
                            if (*p == 0) {
                                if ((sni = (char*) malloc(snilen + 1)) == NULL)
                                    printf("Not enough memory");
                                memcpy(sni, p + 3, snilen);
                                sni[snilen] = '\0';
                                c_hello->sservername = std::string(sni);
                                // https_helper_append(&c_hello->servername, sni);
                                free(sni);
                            }
                            p += 3 + snilen;
                            clen -= 3 + snilen;
                        }
                        break;
                    case 0x23:
                        c_hello->ticket = 1;
                        c_hello->ticketlen = extlen;
                        break;
                }
                data += extlen + 4;
                len -= extlen + 4;
            }
            if (len != 0) goto err;
        }
    }

    return c_hello;
err:
    return NULL;
}

uint8_t ssl_decode(const u_char* pkt, uint16_t length) {
    https_hello clnt_hello;
    if (ssl_decoder(&clnt_hello, pkt, length) != NULL) {
        printf("SSL: %s\n", clnt_hello.sservername.c_str());
        for (int rule_count = 0; rule_count < rule_set.size(); rule_count++) {
            char * pch;
            pch = strstr((char*) clnt_hello.sservername.c_str(), rule_set[rule_count].rule.c_str());
            if (pch != NULL) {
                return rule_set[rule_count].rule_id;
                break;
            }
        }
    }
    return 0;
}

#endif /* PQ_PACKET_CLASSIFY_H */

