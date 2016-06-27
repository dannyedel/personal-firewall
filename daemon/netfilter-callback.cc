#include <cstdint>
#include <cstdio> // printf
#include <memory>
#include <vector>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <netdb.h> // protoinfo
#include <netinet/ip6.h>

#include "netfilter-callback.hh"

using namespace std;

int callback(
	nfq_q_handle* qh,
	nfgenmsg* /* unused nfmsg */,
	nfq_data* nfa,
	void* /* unused data */) {
	printf("callback\n");
	vector<char> buf(4096);
	int ret = nfq_snprintf_xml(buf.data(), 4096, nfa, NFQ_XML_ALL);
	if ( ret > 0 )
	{
		printf("Packet received: %s\n", buf.data());
		if ( ret > 4096 )
			printf( "Output truncated (was %d bytes)\n", ret);
	} else {
		perror("nfq_snprintf_xml");
	}
	int verdict = NF_ACCEPT;
	int id;
	nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		uint16_t hwproto = ntohs(ph->hw_protocol);
		printf("Hardware Proto: %x\n", hwproto);
		unsigned char* data;
		int length = nfq_get_payload(nfa, &data);
		printf("Payload length: %d\n",length);
		if ( hwproto == 0x0800 /* IPv4 */ ) {
			printf("This is IPv4\n");
			/* Transfer packet to userspace buffer */
			pkt_buff* pbuf= pktb_alloc( AF_INET, data, length, 1280);
			if ( ! pbuf ) {
				perror("pkt_buff");
			} else {
				iphdr* iph = nfq_ip_get_hdr( pbuf );
				if ( iph ) {
					printf("IPv4 source: %x destination: %x proto: %x\n",
						ntohl(iph->saddr), ntohl(iph->daddr), iph->protocol);
					char sbuf[ INET_ADDRSTRLEN ];
					char dbuf[ INET_ADDRSTRLEN ];
					printf("Source: %s Destination: %s\n",
						inet_ntop(AF_INET, &iph->saddr, sbuf, INET_ADDRSTRLEN),
						inet_ntop(AF_INET, &iph->daddr, dbuf, INET_ADDRSTRLEN));
					protoent* protoinfo = getprotobynumber(iph->protocol);
					if ( protoinfo ) {
						printf("Protocol name: %s number: %d (hex %x)\n",
							protoinfo->p_name, protoinfo->p_proto, protoinfo->p_proto);
					} else {
						perror("protoinfo");
					}
				} else {
					perror("nfq_ip_get_hdr");
				}
			}
			pktb_free(pbuf);
		} else if ( hwproto == 0x86dd /* IPv6 */ ) {
			printf("This is IPv6\n");
			pkt_buff* pbuf = pktb_alloc( AF_INET6, data, length, 1280);
			if ( !pbuf ) {
				perror("pkt_buff");
			} else {
				ip6_hdr* iph = nullptr;
				if ( ! pktb_network_header(pbuf) ) {
					printf("Warning: Cannot get the network header using the library, "
						"using workaround.\n");
					iph = reinterpret_cast<ip6_hdr*>( pktb_data( pbuf ) );
				} else {
					iph = nfq_ip6_get_hdr(pbuf);
				}
				if ( iph ) {
					char sbuf[INET6_ADDRSTRLEN];
					char dbuf[INET6_ADDRSTRLEN];
					printf("IPv6 source: %s destination %s\n",
						inet_ntop(AF_INET6, &iph->ip6_src, sbuf, INET6_ADDRSTRLEN),
						inet_ntop(AF_INET6, &iph->ip6_dst, dbuf, INET6_ADDRSTRLEN));
					protoent* protoinfo = getprotobynumber(iph->ip6_nxt);
					if ( protoinfo ) {
						printf("Protocol name: %s number: %d (hex %x)\n",
							protoinfo->p_name, protoinfo->p_proto, protoinfo->p_proto);
					} else {
						perror("protoinfo");
					}
				} else {
					perror("nfq_ip6_get_hdr");
				}
			}
		}
	}
	/*
	iphdr* iph = nfq_ip_get_hdr( nfa );
	if ( !iph )
		perror("Cant parse IP header");
		*/
	printf("Setting verdict ACCEPT for id %d\n",id);
	nfq_set_verdict(qh, id, verdict, 0, nullptr);
	return 0;
}
