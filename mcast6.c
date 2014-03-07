/****************


Based on http://www.tcpdump.org/pcap.html

evyncke@cisco.com, 17 January 2014

**********************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include "hash.h"

#define PACKETS_BETWEEN_DOTS 100

// Packet formats
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

htable * all_lla_m ; /* All IPv6 addresses seen as link-local multicast */
htable * all_sl_m ; /* All IPv6 addresses seen as site-local multicast */
htable * all_o_m ; /* All IPv6 addresses seen as organization-scope multicast */
htable * all_g_m ; /* All IPv6 addresses seen as global multicast */
htable * all_rip ; /* All IPv6 addresses of routers */
htable * all_rmac ; /* All MAC addresses of routers */
htable * all_smac ; /* All MAC addresses seen as source */
htable * all_dmac ; /* All MAC addresses seen as destination */
htable * all_mmac ; /* All MAC addresses seen as multicats destination */

unsigned long int wifi_control_frames = 0 ; /* Only relevant in radio monitor mode */
unsigned long int wifi_management_frames = 0 ; /* Only relevant in radio monitor mode */

unsigned long int ether_ucast_frames = 0 ;
unsigned long int ether_mcast_frames = 0 ;
unsigned long int ether_bcast_frames = 0 ;
unsigned long int ether_ucast_bytes = 0 ;
unsigned long int ether_mcast_bytes = 0 ;
unsigned long int ether_bcast_bytes = 0 ;

unsigned long int ipv6_ll_ucast_packets = 0 ;
unsigned long int ipv6_ll_mcast_packets = 0 ;
unsigned long int ipv6_sl_mcast_packets = 0 ;
unsigned long int ipv6_o_mcast_packets = 0 ;
unsigned long int ipv6_g_ucast_packets = 0 ;
unsigned long int ipv6_g_mcast_packets = 0 ;

unsigned long int ipv6_ll_ucast_bytes = 0 ;
unsigned long int ipv6_ll_mcast_bytes = 0 ;
unsigned long int ipv6_sl_mcast_bytes = 0 ;
unsigned long int ipv6_o_mcast_bytes = 0 ;
unsigned long int ipv6_g_ucast_bytes = 0 ;
unsigned long int ipv6_g_mcast_bytes = 0 ;

unsigned long int ipv6_packets = 0 ;
unsigned long int ipv6_bytes = 0 ;

unsigned long int ipv6_ucast_rs = 0 ;
unsigned long int ipv6_mcast_rs = 0 ;
unsigned long int ipv6_ucast_ra = 0 ;
unsigned long int ipv6_mcast_ra = 0 ;

unsigned long int ipv6_ucast_ns = 0 ;
unsigned long int ipv6_mcast_ns = 0 ;
unsigned long int ipv6_ucast_na = 0 ;
unsigned long int ipv6_mcast_na = 0 ;

/* Detailed information about mcast NS */
unsigned long int ipv6_mcast_ns_dad = 0 ; /* Source address is :: */
unsigned long int ipv6_mcast_ns_rh = 0 ; /* MAC addresses from router to non-router */
unsigned long int ipv6_mcast_ns_hh = 0 ; /* MAC addresses from non-router to non-router */
unsigned long int ipv6_mcast_ns_hr = 0 ; /* MAC addresses from non-router to router */
unsigned long int ipv6_mcast_ns_rr = 0 ; /* MAC addresses from router to router */

/* Detailed information about mcast NA */
unsigned long int ipv6_mcast_na_none = 0 ; /* No flags set */
unsigned long int ipv6_mcast_na_override = 0 ; /* Override bit is set */
unsigned long int ipv6_mcast_na_solicited = 0 ; /* Solicited bit is set */
unsigned long int ipv6_mcast_na_routeroverride = 0 ; /* R & O bits are set */
unsigned long int ipv6_mcast_na_other = 0 ; /* for the rest */

unsigned long int ipv6_ucast_mdns = 0 ;
unsigned long int ipv6_mcast_mdns = 0 ; 

unsigned long int ipv6_ucast_llmnr = 0 ;
unsigned long int ipv6_mcast_llmnr = 0 ;

unsigned long int ipv6_ucast_ssdp = 0 ;
unsigned long int ipv6_mcast_ssdp = 0 ;

unsigned long int ipv6_ucast_dhcp = 0 ;
unsigned long int ipv6_mcast_dhcp = 0 ;

unsigned long int ipv6_mcast_vrrp = 0 ;

time_t start_time ;
int ctrl_c_pressed ;
int verbose = 0 ;
int do_rfmon = 0 ;
int rfmon_mode = 0 ;
int dump_tables = 0 ;
char * sniffing_device = NULL ;

pcap_t *handle;			/* Session handle */
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */

#define ETHER_ADDR_LEN	6

struct ieee80211_radiotap_header {
	u_int8_t        it_version;     /* set to 0 */
	u_int8_t        it_pad;
	u_int16_t       it_len;         /* entire length */
	u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct ieee80211_header {

	u_int16_t	wi_fc ; /* Frame control field */
	u_int16_t	wi_duration ;
	u_char		wi_daddr[ETHER_ADDR_LEN] ;
	u_char		wi_saddr[ETHER_ADDR_LEN] ;
	u_char		wi_faddr[ETHER_ADDR_LEN] ;
	u_short		wi_sc ; /* Frame sequence control */
} ;

/* Ethernet header */
struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
} ;
void dump(u_char * p, int len) {
	int i ;

	while (len > 0) {
		for (i = 0; (i < 16) && (i < len); i++)
			printf("%2.2X ", p[i]) ;
		for (; i < 16; i++)
			printf("   ") ;
		printf("  ") ;
		for (i = 0; (i < 16) && (i < len); i++)
			if ((' ' <= p[i]) && (p[i] <= 127))
				printf("%c ", p[i]) ;
			else
				printf(". ") ;
		printf("\n") ;
		len -= 16 ;
		p += 16 ;
	}
	printf("\n") ;
}

void usage(char * pgm_name) {
	printf("Usage is: %s <options>\nWhere <options> is a combination of:\n\t-d: dump a lot of tables when exiting\n\t-h: display this message\n\t-m: put the device in radio monitoriing mode\n\t-i device: listen on promiscuous mode on this interface (eth0, en0, ...), else an interface is magically selected.\n\t-v: verbose mode, display one line per IPv6 packet\n",
		pgm_name) ;
	exit(0) ;
}

int parse_args(int argc, char * argv[]) {
	int c;
	
	opterr = 0 ;
	while ((c = getopt(argc, argv, "dhi:mv")) != -1) {
		switch(c) {
			case 'd': dump_tables ++ ; break ;
			case 'h': usage(argv[0]) ; break ;
			case 'i': sniffing_device = optarg; break ;
			case 'm': do_rfmon ++ ; break ;
			case 'v': verbose ++ ;
		}
	}
	if (optind != argc) 
		fprintf(stderr, "Unknown options have been ignored.\n") ;			
	if (sniffing_device == NULL) {
		/* Define the device */
		sniffing_device = pcap_lookupdev(errbuf);
		if (sniffing_device == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return 2;
		}
	}
	return 0 ;
}

pcap_t * init_pcap(char * dev) {
	pcap_t *handle;			/* Session handle */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp = "ip6";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Create an handle to the sniffing device */
	handle = pcap_create(dev, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s.\n", dev, errbuf) ;
		return NULL ; // or exit or return an error code or something
	}
	if (do_rfmon) {
		/* Try to set RF Monitor mode */
		if (pcap_can_set_rfmon(handle) == 1) {
			printf("Enabling RF monitor mode on Wi-Fi...") ;
			rfmon_mode = pcap_set_rfmon(handle, 1) == 0;
			if (rfmon_mode)
				printf(" [OK]\n") ;
			else
				printf(" *** FAILED ***, continuing\n") ;
		} else
			fprintf(stderr, "Cannot set %s in RFMON mode.\n", dev) ;
	}
	/* Specify the capture length */
	if (pcap_set_snaplen(handle, BUFSIZ)) {
		fprintf(stderr, "Couldn't specify the capture length of %d on device %s: %s\n", BUFSIZ, dev, errbuf);
		return NULL;
	}
	/* Specify promiscuous mode... perhaps to be disabled in rfmon mode ??? */
	if (pcap_set_promisc(handle, 1)) {
		fprintf(stderr, "Couldn't put device %s in promiscuous mode: %s\n", dev, errbuf);
		return NULL;
	}
	/* Specify time-out */
	if (pcap_set_timeout(handle, 1000)) {
		fprintf(stderr, "Couldn't set device %s read timeout: %s\n", dev, errbuf);
		return NULL;
	}
	/* Let's activate it now! */
	if (pcap_activate(handle)) {
		fprintf(stderr, "Couldn't activate device %s: %s\n", dev, errbuf);
		return NULL;
	}
	/* Check data-link headers */
	if (rfmon_mode) {
		if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
			fprintf(stderr, "Device %s doesn't provide WiFi radio tap headers - not supported\n", dev);
			return NULL;
		}
	} else {
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
			return NULL;
		}
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return NULL;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return NULL;
	}
	return handle ;
}

void display_stats() {
	time_t now ;

	time(&now) ;
	printf("\nEthernet IPv6: unicast: %ld (%ld bytes), multicast: %ld (%ld bytes), broadcast: %ld (%ld bytes) in %ld seconds\n",
		ether_ucast_frames, ether_ucast_bytes, ether_mcast_frames, ether_mcast_bytes, ether_bcast_frames, ether_bcast_bytes, now-start_time) ;
	printf("IPv6: total: %ld (%ld bytes)\n\tLink-local: unicast: %ld (%ld bytes), multicast: %ld (%ld bytes)\n",
		ipv6_packets, ipv6_bytes, ipv6_ll_ucast_packets, ipv6_ll_ucast_bytes, ipv6_ll_mcast_packets, ipv6_ll_mcast_bytes) ;
	printf("\tSite-local: multicast: %ld (%ld bytes)\n",
		ipv6_sl_mcast_packets, ipv6_sl_mcast_bytes) ;
	printf("\tOrganization-scope: multicast: %ld (%ld bytes)\n",
		ipv6_o_mcast_packets, ipv6_o_mcast_bytes) ;
	printf("\tGlobal: unicast: %ld (%ld bytes), multicast: %ld (%ld bytes)\n",
		ipv6_g_ucast_packets, ipv6_g_ucast_bytes, ipv6_g_mcast_packets, ipv6_g_mcast_bytes) ;
	printf("\tNDP: RS ucast=%ld mcast=%ld, RA ucast=%ld mcast=%ld, NS ucast=%ld mcast=%ld, NA ucast=%ld mcast=%ld\n",
		ipv6_ucast_rs, ipv6_mcast_rs, ipv6_ucast_ra, ipv6_mcast_ra, ipv6_ucast_ns, ipv6_mcast_ns, ipv6_ucast_na, ipv6_mcast_na) ;
	printf("\t\tDetails on mcast NS, sent by :: (i.e. DAD) %ld, host for router %ld, router for host %ld, host for host %ld, router for router %ld\n",
		ipv6_mcast_ns_dad, ipv6_mcast_ns_hr, ipv6_mcast_ns_rh, ipv6_mcast_ns_hh, ipv6_mcast_ns_rr) ;
	printf("\t\tDetails on mcast NA, no flags %ld, override %ld, solicited %ld, router+override  %ld, other %ld\n",
		ipv6_mcast_na_none, ipv6_mcast_na_override, ipv6_mcast_na_solicited, ipv6_mcast_na_routeroverride, ipv6_mcast_na_other) ;
	printf("\tmDNS ucast=%ld mcast=%ld, LLMNR ucast=%ld mcast=%ld, SSDP ucast=%ld mcast=%ld, DHCP ucast=%ld mcast=%ld, VRRP mcast=%ld\n",
		ipv6_ucast_mdns, ipv6_mcast_mdns, ipv6_ucast_llmnr, ipv6_mcast_llmnr, ipv6_ucast_ssdp, ipv6_mcast_ssdp, ipv6_ucast_dhcp, ipv6_mcast_dhcp, ipv6_mcast_vrrp) ;
}

void sigint(int ignore) {
	ctrl_c_pressed = -1 ;
	pcap_breakloop(handle) ;
	printf("\n\n*** TERMINATING ***\n\n") ;
}

void siginfo(int ignore) {
	display_stats() ;
}

/* If the sniffing device is in RFMON mode, then advance the pointer to the Ethernet header */

u_char* skip_rfmon_data(u_char *packet) {
	struct ieee80211_radiotap_header *rt ;
	struct ieee80211_header *wi_hdr ;

	if (rfmon_mode) {
		rt = (struct ieee80211_radiotap_header *) packet ;
		packet += rt->it_len ; /* Skip the radio tap header */
		wi_hdr = (struct ieee80211_header *) packet ;
		packet = (u_char *) (wi_hdr+1) ; /* Skip the 802.11 frame header */
		/* Now we are 00 00 AA AA 03 00 00 00 followed by EtherType, so, skip this */
		packet += 6 ;
		/* And overwrite the DA & SA, so we need 12 bytes and copy the addresses */
		packet -= 12 ;
		memcpy(packet, wi_hdr->wi_daddr, 6) ;
		memcpy(packet + 6, wi_hdr->wi_saddr, 6) ;
		return packet ;
		
	} else
		return packet ;
}

void pcap_receive(u_char *args, const struct pcap_pkthdr *header, const u_char *cpacket) {

	u_char * packet ;
	struct ether_header * ether_header ;
	struct ip6_hdr *ipv6_header ;
	struct icmp6_hdr * icmpv6_header;
	struct nd_neighbor_advert * na ;
	struct udphdr * udp_header ;
	char ipv6_ascii_address[INET6_ADDRSTRLEN] ;
	unsigned char * ipv6_address ;
	int is_ipv6_mcast, source_is_router, destination_is_router ;
	
//	dump((u_char *) cpacket, 128) ;
	packet = skip_rfmon_data((u_char *) cpacket) ;	
//	dump(packet, 128) ;
	ether_header = (struct ether_header *) packet ;
	if (ntohs(ether_header->ether_type) != 0x86dd) {
			fprintf(stderr, "This is not an IPv6 frame, pcap does not implement filtering... discarding\n") ;
			return ;
	}
	ipv6_packets ++ ;
	ipv6_bytes += header -> len ;
	if (verbose) {
		printf("Got %d bytes\t", header -> len) ;
		printf("DMAC: %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X", ether_header->ether_dhost[0], ether_header->ether_dhost[1],
			ether_header->ether_dhost[2], ether_header->ether_dhost[3],
			ether_header->ether_dhost[1], ether_header->ether_dhost[5]) ;
		if (ether_header->ether_dhost[0] & 0x02) printf("(locally administrated)") ;
	} else
		if ((ipv6_packets % PACKETS_BETWEEN_DOTS) == 0) {
				printf(".") ;
				fflush(stdout) ;
		} 
	htable_add(all_smac, ether_header->ether_shost) ;
	htable_add(all_dmac, ether_header->ether_dhost) ;
	
	/* Statistics at the Ethernet level */
	int i ;
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		if (ether_header->ether_dhost[i] != 0xFF) break ;
	if (i == ETHER_ADDR_LEN) {
		ether_bcast_frames ++ ;
		ether_bcast_bytes += header -> len ;
	} else if (ether_header->ether_dhost[0] & 0x01) {
		ether_mcast_frames ++ ;
		ether_mcast_bytes += header -> len ;
		htable_add(all_mmac, ether_header->ether_dhost) ;
	} else {
		ether_ucast_frames ++ ;
		ether_ucast_bytes += header -> len ;
	}
	
	/* Statistics at the IPv6 level */
	ipv6_header = (struct ip6_hdr *) (ether_header+1) ;
	if (verbose) {
			printf(" IPv6 %s->", inet_ntop(AF_INET6, (void *) &ipv6_header->ip6_src, ipv6_ascii_address, INET6_ADDRSTRLEN)) ;
			printf("%s", inet_ntop(AF_INET6, (void *) &ipv6_header->ip6_dst, ipv6_ascii_address, INET6_ADDRSTRLEN)) ;
			printf(", NH: %d", ipv6_header->ip6_nxt) ;
	}
	ipv6_address = (unsigned char *) &ipv6_header->ip6_dst ;
	if (ipv6_address[0] == 0xFF) {
		is_ipv6_mcast = -1 ;
		if (ipv6_address[1] == 0x02) {
			ipv6_ll_mcast_packets ++ ;
			ipv6_ll_mcast_bytes += header -> len ;
			htable_add(all_lla_m, ipv6_address) ;
		} else if (ipv6_address[1] == 0x05) {
			ipv6_sl_mcast_packets ++ ;
			ipv6_sl_mcast_bytes += header -> len ;
			htable_add(all_sl_m, ipv6_address) ;
		} else if (ipv6_address[1] == 0x08) {
			ipv6_o_mcast_packets ++ ;
			ipv6_o_mcast_bytes += header -> len ;
			htable_add(all_o_m, ipv6_address) ;
		} else {
			ipv6_g_mcast_packets ++ ;
			ipv6_g_mcast_bytes += header -> len ;
			htable_add(all_g_m, ipv6_address) ;
		}
	} else {
		is_ipv6_mcast = 0 ;
		if ((ipv6_address[0] == 0xFE) && (ipv6_address[1] == 0x80)) {
			ipv6_ll_ucast_packets ++ ;
			ipv6_ll_ucast_bytes += header -> len ;
		} else {
			ipv6_g_ucast_packets ++ ;
			ipv6_g_ucast_bytes += header -> len ;
		}
	}
	
	/* ICMP statistics */
	if (ipv6_header->ip6_nxt == IPPROTO_ICMPV6) {
		icmpv6_header = (struct icmp6_hdr *) (ipv6_header+1) ;
		switch (icmpv6_header->icmp6_type) {
			case ND_ROUTER_SOLICIT:
				if (verbose) printf(" RS") ; 
				if (is_ipv6_mcast)
					ipv6_mcast_rs++ ;
				else
					ipv6_ucast_rs++ ;
				break ;
			case ND_ROUTER_ADVERT:
				if (verbose) printf(" RA") ; 
				if (is_ipv6_mcast)
					ipv6_mcast_ra++ ;
				else
					ipv6_ucast_ra++ ;
				htable_add(all_rip, &ipv6_header->ip6_src) ;
				htable_add(all_rmac, ether_header->ether_shost) ;
				break ;
			case ND_NEIGHBOR_SOLICIT:
				if (verbose) printf(" NS") ; 
				if (is_ipv6_mcast) {
					ipv6_mcast_ns++ ;
					/* Check for source address being :: for DAD */
					ipv6_address = (unsigned char *) &ipv6_header->ip6_src ;
					if ((ipv6_address[0] == 0) && (ipv6_address[1] == 0) && (ipv6_address[2] == 0) && (ipv6_address[3] == 0) && (ipv6_address[4] == 0) && (ipv6_address[5] == 0))
						ipv6_mcast_ns_dad++ ;
					/* Check for source/destination being router */
					source_is_router = htable_exists(all_rmac, ether_header->ether_shost) ;
					/* destination_is_router = htable_exists(all_rmac, ether_header->ether_dhost) ; */
					ipv6_address = (unsigned char *) icmpv6_header ;
					ipv6_address += 8 ;
					destination_is_router = htable_exists(all_rip, ipv6_address) ;
					if (!source_is_router)
						if (!destination_is_router)
						ipv6_mcast_ns_hh ++ ;
					else
						ipv6_mcast_ns_hr ++ ;
					else
						if (!destination_is_router)
							ipv6_mcast_ns_rh ++ ;
						else
							ipv6_mcast_ns_rr ++ ;
				} else
					ipv6_ucast_ns++ ;
				break ;
			case ND_NEIGHBOR_ADVERT:
				na = (struct nd_neighbor_advert *) icmpv6_header ;
				if (verbose) printf(" NA") ; 
				if (is_ipv6_mcast) {
					ipv6_mcast_na++ ;
					na -> nd_na_flags_reserved &= ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED | ND_NA_FLAG_ROUTER ; /* Reset the reserved bits */
					switch (na -> nd_na_flags_reserved) {
						case 0: ipv6_mcast_na_none++ ; break ;
						case ND_NA_FLAG_OVERRIDE: ipv6_mcast_na_override ++ ; break ;
						case ND_NA_FLAG_SOLICITED: ipv6_mcast_na_solicited ++ ; break ;
						case ND_NA_FLAG_ROUTER+ND_NA_FLAG_OVERRIDE: ipv6_mcast_na_routeroverride ++ ; break ;
						default: ipv6_mcast_na_other ++ ;
					}
				} else
					ipv6_ucast_na++ ;
				/* Check whether it is a router */
				if (na -> nd_na_flags_reserved & ND_NA_FLAG_ROUTER) {
					htable_add(all_rip, &ipv6_header->ip6_src) ;
					htable_add(all_rmac, ether_header->ether_shost) ;
				}
				break ;
			case MLD_LISTENER_QUERY:
			case MLD_LISTENER_REPORT:
				if (verbose) printf(" MLD") ; 
				break ;
		}
	/* end of ICMP */	
	
	} else if (ipv6_header->ip6_nxt == IPPROTO_UDP) {
		udp_header = (struct udphdr *) (ipv6_header+1) ;

		if (verbose) printf(" %d/udp", ntohs(udp_header->uh_dport)) ;
		/* DHCP on UDP 546 and 547 */
		if ((ntohs(udp_header->uh_dport) == 546) && (ntohs(udp_header->uh_dport) == 547)) {
				if (is_ipv6_mcast)
					ipv6_mcast_dhcp++ ;
				else
					ipv6_ucast_dhcp++ ;
				if (verbose) printf(" DHCP") ;
		/* SSDP on UDP 1900 */
		} else if (ntohs(udp_header->uh_dport) == 1900) {
				if (is_ipv6_mcast)
					ipv6_mcast_ssdp++ ;
				else
					ipv6_ucast_ssdp++ ;
				if (verbose) printf(" SSDP") ;
		/* LLMNR on UDP 5355 */
		} else if (ntohs(udp_header->uh_dport) == 5355) {
				if (is_ipv6_mcast)
					ipv6_mcast_llmnr++ ;
				else
					ipv6_ucast_llmnr++ ;
				if (verbose) printf(" LLMNR") ;
		/* Bonjour on UDP 5353 */
		} else if (ntohs(udp_header->uh_dport) == 5353) {
				if (is_ipv6_mcast)
					ipv6_mcast_mdns++ ;
				else
					ipv6_ucast_mdns++ ;
				if (verbose) printf(" mDNS") ;
		} 
	/* end of UDP */
	} else if (ipv6_header->ip6_nxt == 112) {
		if (verbose) printf(" VRRP") ;
		if (is_ipv6_mcast)
			ipv6_mcast_vrrp++ ;
	}
	
	
	/* Clean up */
	if (verbose) {
		printf("\n") ;
		fflush(stdout) ;
	}
}
	    
int main(int argc, char *argv[]) {

	if (parse_args(argc, argv))
		return 1 ;
		
	handle = init_pcap(sniffing_device) ;
	if (handle == NULL) {
			fprintf(stderr, "Cannot initialize capture in promiscuous mode on device %s\n", sniffing_device) ;
			return 2 ;
	}
		
	all_lla_m = htable_init(16) ;
	all_sl_m = htable_init(16) ;
	all_o_m = htable_init(16) ;
	all_g_m = htable_init(16) ;
	all_rip = htable_init(16) ;
	all_rmac = htable_init(6) ;
	all_smac = htable_init(6) ;
	all_dmac = htable_init(6) ;
	all_mmac = htable_init(6) ;
	time(&start_time) ;
	ctrl_c_pressed = 0 ;
	if (signal(SIGINT, sigint) == SIG_ERR) fprintf(stderr, "Cannot intercept CTRL-C...\n") ;
	if (signal(SIGINFO, siginfo) == SIG_ERR) fprintf(stderr, "Cannot intercept CTRL-T...\n") ;
	printf("%s collecting IPv6 packets in promiscuous mode on %s\n", argv[0], sniffing_device) ;
	if (rfmon_mode) printf("\tRadio monitoring mode is enabled.\n") ;
	printf("\tPrinting a '.' every %d IPv6 packet.\n\tPress CTRL-T to display current statistics\n\tPress CTRL-C to exit\n\n",
		PACKETS_BETWEEN_DOTS) ;

	pcap_loop(handle, -1 /* For ever */, pcap_receive, NULL) ;

	display_stats() ;
	
	printf("\nList of all global multicast groups\n") ;
	htable_dump(all_g_m, htable_ipv6_printer) ;
	printf("\nList of all site-local multicast groups\n") ;
	htable_dump(all_sl_m, htable_ipv6_printer) ;
	printf("\nList of all organization multicast groups\n") ;
	htable_dump(all_o_m, htable_ipv6_printer) ;
	if (dump_tables) {
		printf("\nList of all link-local multicast groups\n") ;
		htable_dump(all_lla_m, htable_ipv6_printer) ;
		printf("\nList of all MAC multicast groups\n") ;
		htable_dump(all_mmac, NULL) ;
	}
	printf("\nList of all IP address of routers\n") ;
	htable_dump(all_rip, htable_ipv6_printer) ;
	printf("\nList of all MAC of routers\n") ;
	htable_dump(all_rmac, NULL) ;
	printf("\n%ld different source MAC addresses and %ld different destination MAC were analyzed; %ld different link-local mcast groups.\n", 
		htable_size(all_smac), htable_size(all_dmac), htable_size(all_lla_m)) ;

	/* And close the session */
	if (rfmon_mode) pcap_set_rfmon(handle, 0) ;
	pcap_close(handle);
	return 0;
}
