#include <cstdint>
#include <memory>
#include <vector>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <netdb.h> // protoinfo
#include <boost/log/trivial.hpp>

#include "netfilter-callback.hh"

#include "dissect-packet.hh"

using namespace std;
using namespace boost::property_tree;
using namespace PersonalFirewall;

int callback(
	nfq_q_handle* /* unused queue handle */,
	nfgenmsg* /* unused nfmsg */,
	nfq_data* nfa,
	void* pq/* pointer to the packet queue */) {
	PacketQueue& packetqueue = *(reinterpret_cast<PacketQueue*>(pq));

	BOOST_LOG_TRIVIAL(trace) << "Plain C callback() received a packet";

	Packet pt = dissect_packet(nfa);

	BOOST_LOG_TRIVIAL(trace) << "Plain C callback() writing packet " << pt.id() << " to queue";

	packetqueue.write(move(pt));

	BOOST_LOG_TRIVIAL(trace) << "Plain C callback() done";

	return 0; // plain c: "Keep Going, send more packets"
}
