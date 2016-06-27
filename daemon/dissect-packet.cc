#include "dissect-packet.hh"
#include <stdexcept>
#include <string>
#include <arpa/inet.h>
#include <linux/ip.h> // ip_hdr
#include <netdb.h> //protoinfo
#include <iostream> // clog
#include <linux/tcp.h> // tcphdr

using namespace std;
using namespace boost::property_tree;

namespace{

struct LowlevelFailure: public runtime_error {
	LowlevelFailure(const std::string& functionName):
		runtime_error(functionName+" returned an error code")
	{
	}
};

struct PktbDeleter {
	void operator() (pkt_buff*b) {
		pktb_free(b);
	}
};

} // end anon namespace

ptree PersonalFirewall::dissect_packet(nfq_data* nfa) {
	ptree pt;

	nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
	if (! ph) {
		throw LowlevelFailure("nfq_get_msg_packet_hdr");
	}

	pt.put("packetid", ntohl(ph->packet_id));
	pt.put("hwproto", ntohs(ph->hw_protocol));

	/** Inspect the packet contents, a.k.a. payload */
	unsigned char* data;
	int length = nfq_get_payload(nfa, &data);
	if ( length < 1 ) {
		throw LowlevelFailure("nfq_get_payload");
	}

	if ( pt.get<int>("hwproto") == 0x0800 ) /* IPv4 */
	{
		unique_ptr<pkt_buff,PktbDeleter> pbuf {
			pktb_alloc(AF_INET, data, length, 1280) };
		if ( !pbuf ) {
			throw LowlevelFailure("pktb_alloc");
		}
		iphdr * iph = nfq_ip_get_hdr( pbuf.get() );
		if ( !iph ) {
			throw LowlevelFailure("nfq_ip_get_hdr");
		}
		dissect_ipv4_header(pt, pbuf.get(), iph );
	} else if ( pt.get<int>("hwproto") == 0x86dd ) {
		pt.put("FIXME", "Ipv6");
	}

	return pt;
}

void PersonalFirewall::dissect_ipv4_header(
	ptree& pt,
	pkt_buff* pktb,
	iphdr* iph)
{
	char sbuf[ INET_ADDRSTRLEN ];
	char dbuf[ INET_ADDRSTRLEN ];

	if ( ! inet_ntop(AF_INET, &iph->saddr, sbuf, INET_ADDRSTRLEN ) )
		throw LowlevelFailure("inet_ntop (source)");
	if ( ! inet_ntop(AF_INET, &iph->daddr, dbuf, INET_ADDRSTRLEN ) )
		throw LowlevelFailure("inet_ntop (dest)");

	pt.put("source", sbuf);
	pt.put("source4", sbuf);
	pt.put("destination", dbuf);
	pt.put("destination4", dbuf);

	pt.put("layer4protocolnumber", iph->protocol);

	protoent * protoinfo = getprotobynumber( iph->protocol );
	if ( protoinfo ) {
		pt.put("layer4protocol", protoinfo->p_name);
	} else {
		clog << "Unknown protocol number: " << iph->protocol << endl;
	}

	if ( pt.get<string>("layer4protocol") == "tcp" )
	{
		if ( 0 != nfq_ip_set_transport_header(pktb, iph) )
			throw LowlevelFailure("nfq_ip_set_transport_header");
		tcphdr * tcp = nfq_tcp_get_hdr(pktb);
		if ( ! tcp )
			throw LowlevelFailure("nfq_tcp_get_hdr");
		pt.put("sourceport", ntohs(tcp->source));
		pt.put("destinationport", ntohs(tcp->dest));
	}
}
