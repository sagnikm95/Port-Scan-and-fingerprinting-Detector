#include "detect.h"
#include "interface_ip.cpp"
#include <string.h>
#include <pcap.h>
#include <pthread.h>
pcap_t* descr;
struct in_addr local_ip;
pthread_t analyze_thread;
pthread_t handle_packet_thread;
struct attacker attackers[MAX_ATTACKERS_NUM];
int attackers_index;


int main(int argc, char* argv[])
{
     /*to take the ip address of current machine*/
    string ip=get_ip();
    int addr_len=ip.length();
    char* my_interface_ip=new char[addr_len+1];
    strcpy(my_interface_ip,ip.c_str());
    
    printf("%s\n",my_interface_ip);
    
    //inet_aton converts string format of ip to network address [ byte form ]
    inet_aton(my_interface_ip,&local_ip);
    memset(attackers, 0, sizeof(attacker) * MAX_ATTACKERS_NUM);
    attackers_index = 0;


    char* dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    //Selecting device to capture from 
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){ 
        printf("Could not find default device : %s\n", errbuf);
        return 1;
    }
    printf("Device: %s\n", dev);


    //Opening the selected device 
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return 1;
    }

    /* In the main thread we do the sniffing while in the checker thread we do the analysis and change states deoending upon connection parameters */
	pthread_create(&analyze_thread, NULL, analyze_traffic, NULL);
	//printf("ANALYZING 1 \n\n");
	pcap_loop(descr, 0, sniffer, NULL);
	return 0;
}

/* 	the sniffer function receieves the captured packet from pcap_loop as a chunk of bytes stored in 'packet' and 
	then checks what type of packet it is and what are its attributes'*/
	
void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){

    struct handle_packet_params* params= new handle_packet_params;
    memset(params->packet,0,1500);
    memcpy(params->packet,packet,pkthdr->len);
   
    pthread_create(&handle_packet_thread,NULL,handle_packet,params);
}



void* handle_packet(void* args){
	
	struct handle_packet_params* params= (handle_packet_params*) (args);
    //packet type must be 0x 08 00 for IPv4
	if(!((params->packet[12] == 8) && (params->packet[13] == 0)))	 // ip packet
    {   
        return NULL;
    }	
	
	/*cast to ip_header type
	  The ip header starts after the Ethernet headed hence we do packet + ETH_HEADER_SIZE */	
	struct ip_hdr* ipptr=(ip_hdr*)(params->packet + ETH_HEADER_SIZE);
    //  printf("checking %s\n",inet_ntoa(ipptr->ip_dst));
	
	// we are concerned only with packets coming to victim computer
	if(ipptr->ip_dst.s_addr!=local_ip.s_addr){  
		return NULL;}
		
	//printf("checked %s\n",inet_ntoa(local_ip)); 
    //Process_IP((uint8_t*)params->packet, params->length);
	
	/*check Protocol */
	int length_ip=ipptr->ip_hl*4;// length given in header as count of 4 byte words
	char* attacker_ip = inet_ntoa(ipptr->ip_src);
	
    /*cast to tcp_header type
	  The ip header starts after the Ethernet headed hence we do packet + Ethernet header size + ip header size */
	struct tcp_hdr* tcpptr = ((tcp_hdr*)((uint8_t*)params->packet + ETH_HEADER_SIZE + length_ip)); 
	int length_tcp=tcpptr->tcp_dt_ofst*4;// obtain the length of header in bytes to check for options
	int length_tcp_options = length_tcp - 20;
	printf("ALL PACKET CHECK attacker ip : %s\ntcp flag : %x\n",attacker_ip,tcpptr->tcp_flags);

	switch(ipptr->ip_p){
		case IP_PROTO_TCP: //TCP packet
            Process_TCP((uint8_t*)params->packet, params->length);
            break;
        
		/*UDP AND ICMP packets not analysed yet */
		case IP_PROTO_UDP:  //UDP packet
            Process_UDP((uint8_t*)params->packet, params->length);
            break;
	
        case IP_PROTO_ICMP: // ICMP packet
            Process_ICMP((uint8_t*)params->packet, params->length);
            break;

        default:
            break;
    }
}

/*	A record of each client is stored , where a state variable keeps info about the 
	client’s connections from different ports to different services.
	This function changes the state of the connections based on the parameters of the TCP packet captured  */
	 
void StatefullCheck(struct ip_hdr* ipptr , struct tcp_hdr* tcpptr,char* attacker_ip){
	/*	FIN 0x01
	SYN 0x02
	RST 0x04
	PUSH 0x08
	ACK 0x10
	URG 0x20
	ECE 0x40
	CWR 0x80 */
	
	
	/*Check existing entries for attacker IP */
	int attacker_index=find_attacker(ipptr->ip_src);
	if(attacker_index=-1){ //attacker not found then add it	
		attacker_index=attackers_index;
		attackers_index = (attackers_index + 1) % MAX_ATTACKERS_NUM; //increment the index pointing to last attacker  in the array [ circular queue ]	
		memset(&attackers[attacker_index], 0, sizeof(attacker));
		attackers[attacker_index].attacker_ip.s_addr = ipptr->ip_src.s_addr;
 	}

	//Finding the connection
	int tcp_conn_i=-1; //-1 = no matching connection found from this attacker
	for (int i = 0; i < attackers[attacker_index].tcp_conns_number; i++){
        /* To check if such a connection entry or state already exists check both destination and source port of attacker */
		if ((attackers[attacker_index].tcp_conns[i].src_port == tcpptr->tcp_src_prt) &
            (attackers[attacker_index].tcp_conns[i].dst_port == tcpptr->tcp_dst_prt))
        {
            tcp_conn_i = i;	//return the index of the connection
            break;
        }
    }

	if(tcp_conn_i== -1){ // First packet of connection
		if ((tcpptr->tcp_flags & 2) != 2)	//the packet is not SYN
        {   
            printf("-> ");
			printf("%x\n\n",tcpptr->tcp_flags);
            print_timestamp();
            printf(": [%s] sending TCP packets to port [%d] (flags = [%x]) with no established connection (suspecting OSF).\a\n",
                attacker_ip, htons(tcpptr->tcp_dst_prt), tcpptr->tcp_flags);
        } 

  
	    else if ((tcpptr->tcp_flags & 2) == 2) {   //the packet is a SYN trying to establish a connection
	    
		//add a connection definition to the array
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].src_port = tcpptr->tcp_src_prt;
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].dst_port = tcpptr->tcp_dst_prt;
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].syn = true;

            time_t time_stamp;
            time(&time_stamp);
        //keep track of time of connection to be able to track time out and half connections
            attackers[attacker_index].tcp_conns[ attackers[attacker_index].tcp_conns_index].time_stamp = ((int)(time_stamp));

//increment the number of SYN packets received on this connection
	    attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].number_of_syn++;

	    //increment the number of connections for this IP and add one to the index
            attackers[attacker_index].tcp_conns_number++;
            attackers[attacker_index].tcp_conns_index = (attackers[attacker_index].tcp_conns_index +1) % MAX_CONNECTION_NUM;  	     
		
	    
        }
    }

 	else {	//connection already exists
    
        if ((tcpptr->tcp_flags & 2) == 2) {	//the packet is SYN
    		
	    //increment the number of SYN packets received on this connection
	    attackers[attacker_index].tcp_conns[tcp_conn_i].number_of_syn++;   
		}
		
        else if ((tcpptr->tcp_flags & 16) == 16){	//the packet is ACK

            attackers[attacker_index].tcp_conns[tcp_conn_i].ack = true;
        }
        
        else if ((tcpptr->tcp_flags & 4) == 4){	//the packet is RST

            attackers[attacker_index].tcp_conns[tcp_conn_i].rst = true;

            if ((attackers[attacker_index].tcp_conns[tcp_conn_i].syn == true) &
                (attackers[attacker_index].tcp_conns[tcp_conn_i].ack == false))
            {  
             //keep count of pairs of SYN and RST TCP packets    
                attackers[attacker_index].tcp_syn_and_rst_num++;
            }
        }
        
        else if ((tcpptr->tcp_flags & 1) == 1){	//the packet is FIN

            attackers[attacker_index].tcp_conns[tcp_conn_i].fin = true;
        }
    }	
}


/*The function performs stateless checks on each TCP packet received for suspiscious behavious*/
int statelessChecks(struct ip_hdr* ipptr , struct tcp_hdr* tcpptr ,char* attacker_ip){
	
	/*	FIN 0x01
	SYN 0x02
	RST 0x04
	PUSH 0x08
	ACK 0x10
	URG 0x20
	ECE 0x40
	CWR 0x80 */
	
	if (tcpptr->tcp_flags == 8) {
        printf("-> ");
        print_timestamp();
       	printf(": [%s] sent a TCP packet containing only PSH flag (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

 	if ((tcpptr->tcp_flags & 33) == 33){  //SYN ACK WITH FIN URG
    
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with FIN and URG flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

	 if ((tcpptr->tcp_flags & 36) == 36){
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and URG flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

	if (tcpptr->tcp_flags == 0){
        printf("-> ");	
        print_timestamp();
        printf(": [%s] sent a TCP null [no flags set] (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

	if ((tcpptr->tcp_flags & 3) == 3) {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with SYN and FIN flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

	if ((tcpptr->tcp_flags & 5) == 5) {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and FIN flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;
    }

	if ((tcpptr->tcp_flags & 6) == 6){
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and SYN flags set (suspecting OSF).\a\n", attacker_ip);
   		return 0;
    }

	if ((tcpptr->tcp_flags & 16 == 16) & (ipptr->ip_off && 0x4000 == 0x4000) & (htons(tcpptr->tcp_window) == 1024)){
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP ACK packet with IP DF and a window size of 1024 (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }

 	if ((tcpptr->tcp_flags & 2 == 2) & (ipptr->ip_off && 0x4000 == 0x0000) & (htons(tcpptr->tcp_window) == 31337) &
        (htons(tcpptr->tcp_dst_prt) != 80)){		//80 is the only opened port 
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP SYN packet without IP DF and a window size of 31337 to a closed port (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }

    if ((tcpptr->tcp_flags & 2 == 2) & (ipptr->ip_off && 0x4000 == 0x4000) & (htons(tcpptr->tcp_window) == 32768) &
        (htons(tcpptr->tcp_dst_prt) != 80))	{	//80 is the only opened port

        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP SYN packet with IP DF and a window size of 32768 to a closed port (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }

	if ((tcpptr->tcp_flags & 41) == 41){
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the FIN, PSH, and URG flags set [Xmas tree scan] (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }

	if ((tcpptr->tcp_flags & 43) == 43){
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the SYN, FIN, PSH, and URG flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }

	if ((tcpptr->tcp_flags & 194) == 194) {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the SYN, ECN, and CWR flags set (suspecting OSF).\a\n", attacker_ip);
		return 0;    
    }
	
	return 1;
}


/* The Process_TCP function analyses the TCP packets */
void Process_TCP(uint8_t * packet, int length){
	/*cast to ip_header type
	The ip header starts after the Ethernet headed hence we do packet + ETH_HEADER_SIZE */
	struct ip_hdr* ipptr =(ip_hdr*) (packet+ETH_HEADER_SIZE);
	int length_ip=ipptr->ip_hl*4;// length given in header as count of 4 byte words
	char* attacker_ip = inet_ntoa(ipptr->ip_src);
	
	
	/*cast to tcp_header type
	The ip header starts after the Ethernet headed hence we do packet + Ethernet header size + ip header size */
    struct tcp_hdr* tcpptr = ((tcp_hdr*)(packet + ETH_HEADER_SIZE + length_ip)); 
	int length_tcp=tcpptr->tcp_dt_ofst*4;// obtain the length of header in bytes to check for options
	int length_tcp_options = length_tcp - 20;
	printf("attacker ip : %s\ntcp flag : %x\n",attacker_ip,tcpptr->tcp_flags);



	/* Connectionless or stateless Attacks */
	if(!statelessChecks(ipptr,tcpptr,attacker_ip)) return;
 

	//Stateful ATTACKS//
	StatefullCheck(ipptr,tcpptr,attacker_ip);

}




// The analyze_traffic function checks the current state of the TCP connection and checks for suspecting behaviour 
void* analyze_traffic(void*){	
    while(1){	//printf("ANALYZING\n\n");
        for (int i = 0; i < MAX_ATTACKERS_NUM; i++) {
            if (attackers[i].attacker_ip.s_addr == 0)
            	continue;
			int open_conx = 0;  // all open connections to the server
            time_t time_stamp;
            int current_time_stamp;
			
			//Check all port connection for the ith attacker ip
            for (int j = 0; j < MAX_CONNECTION_NUM; j++){
                open_conx += attackers[i].tcp_conns[j].number_of_syn;
				if(((attackers[i].tcp_conns[j].number_of_syn) >= MAX_ALLOWED_CONNECTIONS) && (attackers[i].tcp_conns[j].port_scan_detected == false)) {
                    // to show the message only once if detected the port scan
                    attackers[i].tcp_conns[j].port_scan_detected = true;

                    char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                    printf("-> ");
                    print_timestamp();
                    printf(": [%s] connected multiple times with the same {src_prt = %d} and {dst_prt = %d} (suspecting OSF).\a\n", attacker_ip,
                        htons(attackers[i].tcp_conns[j].src_port), htons(attackers[i].tcp_conns[j].dst_port));
                }

                int half_opened_num = 0;  // number of half-opened connections

                if (attackers[i].tcp_conns[j].half_opened_detected == false)
                {
                    time(&time_stamp);
                    current_time_stamp = ((int)(time_stamp));
					/* Half open connection check */
                    if ((attackers[i].tcp_conns[j].syn == true) & (attackers[i].tcp_conns[j].ack == false) &
                        (attackers[i].tcp_conns[j].rst == false) & (attackers[i].tcp_conns[j].fin == false) &
                        ((current_time_stamp - attackers[i].tcp_conns[j].time_stamp) >= MAX_ALLOWED_HALF_OPENED_LIFE)){
						
                  
                        half_opened_num++;
                    }

                    //checking for halp open conncetion with this port [ might be from some other source port of this particular attacker ip]
					for (int k = 0; k < MAX_CONNECTION_NUM; k++) {
                        if (k == j)
                        	continue;

                        if (attackers[i].tcp_conns[k].half_opened_detected == false) {
                            if (attackers[i].tcp_conns[k].dst_port == attackers[i].tcp_conns[j].dst_port){
                                time(&time_stamp);
                                current_time_stamp = ((int)(time_stamp));

                                if ((attackers[i].tcp_conns[k].syn == true) & (attackers[i].tcp_conns[k].ack == false) &
                                    (attackers[i].tcp_conns[k].rst == false) & (attackers[i].tcp_conns[k].fin == false) &
                                    ((current_time_stamp - attackers[i].tcp_conns[k].time_stamp) >= MAX_ALLOWED_HALF_OPENED_LIFE)) {
                                    half_opened_num++;
                                }
                            }
                        }
                    }

                    if (half_opened_num >= MAX_ALLOWED_HALF_OPENED) {
                        attackers[i].tcp_conns[j].half_opened_detected = true;

                        for (int k = 0; k < MAX_CONNECTION_NUM; k++) {
                            if (attackers[i].tcp_conns[k].dst_port == attackers[i].tcp_conns[j].dst_port) {
                                attackers[i].tcp_conns[k].half_opened_detected = true;
                            }
                        }

                        char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                        printf("-> ");
                        print_timestamp();
                        printf(": [%s] established multiple half-opened connections to port [%d] [each with life > %d secs] (suspecting OSF).\a\n",
                            attacker_ip, htons(attackers[i].tcp_conns[j].dst_port), MAX_ALLOWED_HALF_OPENED_LIFE);
                    }
                }
            }

		/*Checking count of TCP connections with all ports of victim */  	
            if(open_conx > (MAX_ALLOWED_CONNECTIONS * 3) && (attackers[i].all_port_scan_detected == false)) {
                attackers[i].all_port_scan_detected = true;

                char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                printf("-> ");
                print_timestamp();
                printf(": [%s] attempting a port scan (suspecting OSF).\a\n", attacker_ip);
                
            }


			/* Checking count of TCP RST pairs */
            if ((attackers[i].tcp_syn_and_rst_num >= MAX_ALLOWED_SYN_RST) & (attackers[i].tcp_syn_and_rst_num_detected == false)) {
                attackers[i].tcp_syn_and_rst_num_detected = true;

                char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                printf("-> ");
                print_timestamp();
                printf(": [%s] sending multiple SYN then RST TCP packet to multiple ports (suspecting OSF).\a\n", attacker_ip);
            }
        }

        //sleep(1);
    }
}

/* Helper function to get timestamp*/
void print_timestamp(){
    struct timeval tv;
    struct tm* ptm;
    char time_string[40];
    long microseconds;

    gettimeofday(&tv, NULL);
    ptm = localtime(&tv.tv_sec);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", ptm);
    microseconds = tv.tv_usec;
    
    printf("%s.%06ld", time_string, microseconds);
}  


void Process_UDP(uint8_t * packet, int length){}
void Process_ICMP(uint8_t * packet, int length){}


/* FUnction to get attacker index */	
int find_attacker(struct in_addr attacker_ip){
    for (int i = 0; i < MAX_ATTACKERS_NUM; i++) {
        if (attackers[i].attacker_ip.s_addr == attacker_ip.s_addr){
            return i;
        }
    }

    return -1; //attacker  not present in list
}

