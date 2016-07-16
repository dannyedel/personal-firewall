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

	Packet pt = dissect_packet(nfa);

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
