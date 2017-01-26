#include "net_utils.h"

#include<sys/time.h>
#include<stdio.h>

#define MAX_CONNECTION_NUM 2000
#define MAX_ATTACKERS_NUM 100

#define MAX_ALLOWED_CONNECTIONS 5
#define MAX_ALLOWED_SYN_RST 5

#define MAX_ALLOWED_HALF_OPENED_LIFE 20
#define MAX_ALLOWED_HALF_OPENED 5


void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void* handle_packet(void*);

void Process_IP(uint8_t * packet, int length);
void Process_TCP(uint8_t * packet, int length);
void Process_UDP(uint8_t * packet, int length);
void Process_ICMP(uint8_t * packet, int length);
void* analyze_traffic(void*);
int find_attacker(struct in_addr attacker_ip);
void print_timestamp();


struct handle_packet_params
{
    char packet[1500]; // packet captured using pcap as a sequence of bytes
    int length; ///packet length
};




struct tcp_connection
{
    uint16_t src_port;  // source port 
    uint16_t dst_port;  // destination port
    /*state variables : TCP flags true-> TCP packet has been send with flag set  */
    bool syn;  
    bool ack;
    bool fin;
    bool rst;

    int number_of_syn; // no of syn packets sends -> no connection requests
    int time_stamp;  // time of connection establishment

    bool port_scan_detected; //state variable to show if port scan has been detected on dst_port
    bool half_opened_detected; // state variable t denote half open TCP connection
} __attribute__ ((packed)) ;

struct udp_connection
{
    uint16_t src_port;
    uint16_t dst_port;
} __attribute__ ((packed)) ;

struct attacker
{
    struct in_addr attacker_ip; //attacker ip address

    struct tcp_connection tcp_conns[MAX_CONNECTION_NUM]; // array maintaing log of each tcp connection from this ip
    int tcp_conns_number; // count of number of oconnections for this ip
    int tcp_conns_index; // current empty location in the circular array tcp_conns

    struct udp_connection udp_conns[MAX_CONNECTION_NUM];
    int udp_conns_number;
    int udp_conns_index;

    int tcp_syn_and_rst_num;

    bool all_port_scan_detected;
    bool tcp_syn_and_rst_num_detected;
} __attribute__ ((packed)) ;
