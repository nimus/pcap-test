#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define ETHER_ADDR_LEN 6 

struct libnet_ethernet_hdr
{
     uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
     uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
     uint16_t ether_type;                 /* protocol */
};
  
struct libnet_ipv4_hdr
{
     uint8_t ip_tos;          /* type of service */
     uint16_t ip_len;         /* total length */
     uint16_t ip_id;          /* identification */
     uint16_t ip_off;
     uint8_t ip_ttl;          /* time to live */
     uint8_t ip_p;            /* protocol */
     uint16_t ip_sum;         /* checksum */
     struct in_addr ip_src;   /* soruce address*/
     struct in_addr ip_dst;   /* dest address */
};
  
struct libnet_tcp_hdr
{
     uint16_t th_sport;       /* source port */
     uint16_t th_dport;       /* destination port */
     uint32_t th_seq;         /* sequence number */
     uint32_t th_ack;         /* acknowledgement number */
     uint8_t  th_flags;       /* control flags */
     uint16_t th_win;         /* window */
     uint16_t th_sum;         /* checksum */
     uint16_t th_urp;         /* urgent pointer */
};  


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


void info_eth(const u_char* packet) {

	struct libnet_ethernet_hdr* p;
	p = (struct libnet_ethernet_hdr*)packet;

	printf("1. Ethernet Header\n");

	printf("src mac : ");

	for(int i = 0; i<6; i++){

		printf("%02x", (*p).ether_shost[i]);

		if(i<5) printf(":");
	}

	printf("\ndst mac : ");

	for(int i = 0; i<6; i++){

		printf("%02x", (*p).ether_dhost[i]);

		if(i<5) printf(":");

	}

	printf("\n\n");

}

void info_ip(const u_char* packet) {

	struct libnet_ipv4_hdr* p;
	p = (libnet_ipv4_hdr*)packet;

	printf("2. IP Header\n");
	printf("src ip : %s\n", inet_ntoa((*p).ip_src));
	printf("dst ip : %s\n", inet_ntoa((*p).ip_dst));

	printf("\n");

}

void info_tcp(const u_char* packet) {

	struct libnet_tcp_hdr* p;
	p = (libnet_tcp_hdr*)packet;

	printf("3. TCP Header\n");
	printf("src port : %d\n", ntohs((*p).th_sport));
	printf("dst port : %d\n", ntohs((*p).th_dport));

	printf("\n");
		
}

void info_data(const u_char* packet) {

	printf("4. Payload(Data)\n");


	printf("hexadecimal value : ");

	for(int i=0; i<16; i++){
		printf("%02x ", *(packet+i));
	}

	printf("\n\n");

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        //       printf("%u bytes captured\n", header->caplen);

	info_eth(packet);
	
	packet = packet + sizeof(struct libnet_ethernet_hdr);
	
	info_ip(packet);
	
	packet = packet + sizeof(struct libnet_ipv4_hdr);
	
	info_tcp(packet);
	
	packet = packet + sizeof(struct libnet_tcp_hdr);
	
	info_data(packet);

    }

    pcap_close(handle);
}



