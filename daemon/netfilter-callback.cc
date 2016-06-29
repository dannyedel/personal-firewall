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

#include "dissect-packet.hh"

#include <iostream>

using namespace std;
using namespace boost::property_tree;
using namespace PersonalFirewall;

int callback(
	nfq_q_handle* qh,
	nfgenmsg* /* unused nfmsg */,
	nfq_data* nfa,
	void* /* unused data */) {
	printf("callback() received a packet\n");

	/** FIXME: Dissect packet to property tree **/

	ptree pt = dissect_packet(nfa);

	clog << "Packet facts:" << endl << "=====" << endl;
	write_info(clog, pt);
	clog << "=====" << endl;

	/** FIXME DEBUG: Print property tree **/

	/** FIXME: Check rules for verdict **/

	/** FIXME: Print property tree to client **/

	/** FIXME: Set verdict **/

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
	} else {
		cerr << "FATAL: Cannot open packet header" << endl;
		exit(2);
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
