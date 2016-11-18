#include "netfilter-queue-library.hh"
#include "netfilter-callback.hh"
#include "packetqueue.hh"
#include "rulerepository.hh"

#include <cstdlib> // exit

#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>

#include <boost/property_tree/info_parser.hpp>
#include <boost/lexical_cast.hpp>

#include "dissect-packet.hh"

#include <thread> // thread

#include <signal.h> // signal(), SIGINT, etc.

using namespace std;
using namespace PersonalFirewall;
using boost::property_tree::ptree;
using boost::filesystem::path;
using boost::lexical_cast;

namespace {
	PacketQueue packetqueue;

	nfq_q_handle* qh;

	int fd;
	void PosixSignalHandler(int signalNumber) {
		if ( signalNumber == SIGINT || signalNumber == SIGTERM) {
			BOOST_LOG_TRIVIAL(info) << "Caught SIGINT or SIGTERM, initiating shutdown.";
			packetqueue.shutdown();
			{
				int rc = close(fd);
				BOOST_LOG_TRIVIAL(debug) << "close() returned " << rc;
			}
			{
				int rc = nfq_destroy_queue(qh);
				BOOST_LOG_TRIVIAL(debug) << "nfq_destroy_queue() returned " << rc;
			}
			BOOST_LOG_TRIVIAL(debug) << "Shutdown signal sent.";
		}
	}
}


void PacketHandlingFunction(const Verdict& v, const path& p) {

	try{
		RuleRepository rr(v, p);

		BOOST_LOG_TRIVIAL(info) << "Packet handler thread started";
		for(;;) {
			BOOST_LOG_TRIVIAL(trace) << "PacketHandlingFunction(): blocking on the queue";
			Packet p = packetqueue.read();
			try {
				BOOST_LOG_TRIVIAL(trace) << "Packet recived:" << p;

				/** Ask the rule repository for a verdict.
				 * This will throw if it needs a DNS resolve. */
				Verdict v = rr.processPacket(p);

				if ( v == Verdict::undecided ) {
					/** FIXME: Forward undecided packet to the client, and
					 * let user decide */
					BOOST_LOG_TRIVIAL(warning) << "Packet did not match any rule, the verdict is undecided for " << p.id();
				}

				BOOST_LOG_TRIVIAL(debug) << "Setting verdict " << to_string(v) << " for packet " << p.id();

				nfq_set_verdict(
					qh,
					p.facts.get<int>("packetid"),
					to_netfilter_int( v ),
					0,
					nullptr);
			}
			catch( NeedDnsResolve& e) {
				BOOST_LOG_TRIVIAL(debug) << "Packet " << p.id() << " needs DNS lookup before a decision";
				thread injectThread(lookup_and_reinject, move(p), ref(packetqueue) );
				injectThread.detach();
			}
		}
	} catch( ShutdownException& e) {
		// planned shutdown
		return;
	} catch( ::std::exception& e) {
		// unexpected exception!
		BOOST_LOG_TRIVIAL(error) << "Unexpected exception caught! what(): " << e.what();
		packetqueue.shutdown();
		close(fd);
		return;
	}

};

int main(int argc, char** argv) {
	// Do a clean shutdown on SIGINT
	signal(SIGINT, PosixSignalHandler);
	signal(SIGTERM, PosixSignalHandler);

	boost::log::core::get() -> set_filter(
		boost::log::trivial::severity >= boost::log::trivial::debug
	);
	/** FIXME: Handle command-line-options with boost **/

	if ( argc < 3 ) {
		BOOST_LOG_TRIVIAL(fatal) << "Usage: " << argv[0] << " <default-verdict> <path/to/rules>" << endl;
		return 1;
	}

	const Verdict verd = lexical_cast<Verdict>(argv[1]);
	const path rulepath{ argv[2] };

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
	fd = nfq_fd(h);
	BOOST_LOG_TRIVIAL(debug) << "NFQUEUE file descriptor: " << fd;

	thread handlerThread( PacketHandlingFunction, verd, rulepath);
	for(;;)
	{
		BOOST_LOG_TRIVIAL(trace) << "Blocking on recv() on queue fd " << fd;
		int rv;
		char buf[4096];
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			BOOST_LOG_TRIVIAL(trace) << "recv()'d something";
			nfq_handle_packet(h, buf, rv); /* send packet to callback */
		} else {
			if ( packetqueue.is_shutdown() ) {
				BOOST_LOG_TRIVIAL(info) << "Main loop exiting.";
				// this is expected.
				break;
			} else {
				BOOST_LOG_TRIVIAL(warning) << "recv() on the queue returned " << rv << ", shutting down";
				packetqueue.shutdown();
				break;
			}
		}
	}

	handlerThread.join();

	BOOST_LOG_TRIVIAL(info) << "Exiting normally.";

	return 0;
}
