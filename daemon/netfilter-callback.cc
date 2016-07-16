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
	nfq_q_handle* /* unused queue handle */,
	nfgenmsg* /* unused nfmsg */,
	nfq_data* nfa,
	void* pq/* pointer to the packet queue */) {
	PacketQueue& packetqueue = *(reinterpret_cast<PacketQueue*>(pq));

	printf("Plain C callback() received a packet\n");

	Packet pt = dissect_packet(nfa);

	packetqueue.write(move(pt));

	printf("Plain C callback() done");

	return 0; // plain c: "Keep Going, send more packets"
}

#if 0
{

	clog << "Packet facts:" << endl << "=====" << endl;
	write_info(clog, pt.facts);
	clog << "=====" << endl;

	/** FIXME: Check rules for verdict **/

	/** FIXME: Print property tree to client **/

	/** FIXME: Set verdict **/

	int verdict = NF_ACCEPT;
	int id = pt.facts.get<int>("packetid");
	printf("Setting verdict ACCEPT for id %d\n",id);
	nfq_set_verdict(qh, id, verdict, 0, nullptr);
	return 0;
}

#endif
