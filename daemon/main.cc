#include "netfilter-queue-library.hh"
#include "netfilter-callback.hh"
#include "packetqueue.hh"

#include <cstdio> // perror
#include <cstdlib> // exit

#include <boost/log/trivial.hpp>

#include <boost/property_tree/info_parser.hpp>

#include "dissect-packet.hh"

#include <thread> // thread

using namespace std;
using namespace PersonalFirewall;

namespace {
	PacketQueue packetqueue;

	const bool alwaysLookup=true;

	nfq_q_handle* qh;

}

void PacketHandlingFunction() {
	for(;;) {
		try {
			BOOST_LOG_TRIVIAL(trace) << "PacketHandlingFunction(): blocking on the queue";
			Packet p = packetqueue.read();
			BOOST_LOG_TRIVIAL(trace) << "PacketHandlingFunction() got a packet";
	
	/** FIXME: Apply rules */

	/** DNS Lookup
	 *
	 * Looks up if we still need a verdict or alwaysLookup is true
	 *
	 * Never lookup DNS packets themselves
	 */
	if ( ! p.metadata.get<bool>("hostnamelookupdone")
		&& ( p.verdict == Verdict::undecided || alwaysLookup )
	   ) {
		if ( is_dns_packet(p.facts) ) {
			BOOST_LOG_TRIVIAL(debug) << "Packet " << p.id() << " is a DNS packet, not looking it up";
		} else {
			BOOST_LOG_TRIVIAL(debug) << "Packet " << p.id() << " needs DNS lookup";
			thread injectThread(lookup_and_reinject, move(p), ref(packetqueue) );
			injectThread.detach();
			continue;
		}
	}

	BOOST_LOG_TRIVIAL(trace) << "Packet recived:" << p;

	if ( p.verdict == Verdict::undecided ) {
		BOOST_LOG_TRIVIAL(debug) << "Undecided, setting accept on " << p.id();
		nfq_set_verdict(qh,
			p.facts.get<int>("packetid"),
			to_netfilter_int(Verdict::accept),
			0,
			nullptr);
		continue;
	}

	int verdict = to_netfilter_int(p.verdict);
	int id = p.facts.get<int>("packetid");
	BOOST_LOG_TRIVIAL(debug) << "Setting verdict " << to_string(p.verdict) << " for packet " << p.id();
	nfq_set_verdict(qh, id, verdict, 0, nullptr);
		} catch( ShutdownException& e) {
			BOOST_LOG_TRIVIAL(debug) << e.what();
			return;
		}
	}
};

int main() {

	thread handlerThread( PacketHandlingFunction);

	/** FIXME: Handle command-line-options **/

	/** FIXME: Add iptables rules **/

	nfq_handle* h=nfq_open();
	if (!h) {
		perror("nfq_open");
		exit(1);
	}

	BOOST_LOG_TRIVIAL(debug) << "binding nfnetlink_queue as nf_queue handler for AF_INET";
	{ 
		int rc = nfq_bind_pf(h, AF_INET) < 0;
		if ( rc < 0 ) {
			BOOST_LOG_TRIVIAL(fatal) << "error " << rc << " during nfq_bind_pf()";
			exit(1);
		}
	}

	qh=nfq_create_queue(h, 0, callback, &packetqueue);
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
	if ( !qh ) {
		BOOST_LOG_TRIVIAL(fatal) << "Got a null queue_handle";
		exit(4);
	}
	BOOST_LOG_TRIVIAL(trace) << "queue handle: " << qh;
	int fd= nfq_fd(h);
	for(;;)
	{
		BOOST_LOG_TRIVIAL(trace) << "Blocking on recv() on queue fd";
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
