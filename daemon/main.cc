#include "netfilter-queue-library.hh"
#include "netfilter-callback.hh"
#include "packetqueue.hh"
#include "rulerepository.hh"

#include <cstdlib> // exit

#include <boost/log/trivial.hpp>

#include <boost/property_tree/info_parser.hpp>

#include "dissect-packet.hh"

#include <thread> // thread

using namespace std;
using namespace PersonalFirewall;
using boost::property_tree::ptree;

namespace {
	PacketQueue packetqueue;

	nfq_q_handle* qh;

}

void PacketHandlingFunction() {

	RuleRepository rr(Verdict::reject, "rules/");

	{
		// Allow DNS resolves
		ptree pt;
		pt.put("direction", "output");
		pt.put("layer4protocol", "udp");
		pt.put("destinationport", "53");
		rr.append_rule( Rule(pt, Verdict::accept) );
	}

	{
		// Accept connections to our servers
		ptree pt;
		pt.put("hostnamematch", "*.server.simon-mueller.de");
		rr.append_rule( Rule(pt, Verdict::accept) );
	}

	BOOST_LOG_TRIVIAL(info) << "Packet handler thread started";
	for(;;) {
		try {
			BOOST_LOG_TRIVIAL(trace) << "PacketHandlingFunction(): blocking on the queue";
			Packet p = packetqueue.read();
			try {
				BOOST_LOG_TRIVIAL(trace) << "Packet recived:" << p;

				/** FIXME: Apply rules */

				/** Ask the rule repository for a verdict.
				 * This will throw if it needs a DNS resolve. */
				Verdict v = rr.processPacket(p);

				if ( v == Verdict::undecided ) {
					BOOST_LOG_TRIVIAL(warning) << "Packet did not match any rule, setting accept on " << p.id();
				}

				BOOST_LOG_TRIVIAL(debug) << "Setting verdict " << to_string(v) << " for packet " << p.id();

				nfq_set_verdict(
					qh,
					p.facts.get<int>("packetid"),
					to_netfilter_int( v ), // this throws if it needs a DNS lookup
					0,
					nullptr);
			}
			catch( NeedDnsResolve& e) {
				BOOST_LOG_TRIVIAL(debug) << "Packet " << p.id() << " needs DNS lookup before a decision";
				thread injectThread(lookup_and_reinject, move(p), ref(packetqueue) );
				injectThread.detach();
			}
		} catch( ShutdownException& e) {
			BOOST_LOG_TRIVIAL(debug) << e.what();
			return;
		}
	}
};

int main() {


	/** FIXME: Handle command-line-options **/

	/** FIXME: Add iptables rules **/

	nfq_handle* h=nfq_open();
	if (!h) {
		BOOST_LOG_TRIVIAL(fatal) << "nfq_open() returned null pointer";
		exit(1);
	}

	BOOST_LOG_TRIVIAL(trace) << "binding nfnetlink_queue as nf_queue handler for AF_INET";
	{ 
		int rc = nfq_bind_pf(h, AF_INET) < 0;
		if ( rc < 0 ) {
			BOOST_LOG_TRIVIAL(fatal) << "error " << rc << " during nfq_bind_pf()";
			exit(1);
		}
	}

	qh=nfq_create_queue(h, 0, callback, &packetqueue);
	if ( !qh ) {
		BOOST_LOG_TRIVIAL(fatal) << "Got a null queue_handle!  Please make sure that (a) you are root and (b) no other process is already using the queue.";
		exit(4);
	}

	{
		int rc = nfq_set_mode(qh, NFQNL_COPY_PACKET, 65531);
		if ( rc ) {
			BOOST_LOG_TRIVIAL(fatal) << "error " << rc << " during nfq_set_mode()";
			exit(2);
		}
	}
	{
		int rc = nfq_set_queue_maxlen(qh, /* 10M */ 10*1024*1024 );
		if ( rc ) {
			BOOST_LOG_TRIVIAL(fatal) << "error " << rc << " during nfq_set_queue_maxlen";
			exit(3);
		}
	}
	BOOST_LOG_TRIVIAL(debug) << "NFQUEUE queue_handle: " << qh;
	int fd= nfq_fd(h);
	BOOST_LOG_TRIVIAL(debug) << "NFQUEUE file descriptor: " << fd;

	thread handlerThread( PacketHandlingFunction);
	for(;;)
	{
		BOOST_LOG_TRIVIAL(trace) << "Blocking on recv() on queue fd " << fd;
		int rv;
		char buf[4096];
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			BOOST_LOG_TRIVIAL(trace) << "recv()'d something";
			nfq_handle_packet(h, buf, rv); /* send packet to callback */
		} else {
			BOOST_LOG_TRIVIAL(warning) << "recv() returned " << rv << ", ignoring";
		}
	}

	handlerThread.join();

	return 0;
}
