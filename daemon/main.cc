#include "netfilter-queue-library.hh"
#include "netfilter-callback.hh"
#include "packetqueue.hh"

#include <cstdio> // perror
#include <cstdlib> // exit

#include <iostream> // clog

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
	clog << "PacketHandlingFunction(): blocking on the queue" << endl;
	Packet p = packetqueue.read();
	clog << "PacketHandlingFunction() got a packet" << endl;
	
	/** FIXME: Apply rules */

	/** DNS Lookup
	 *
	 * Looks up if we still need a verdict or alwaysLookup is true
	 */
	if ( ! p.metadata.get<bool>("hostnamelookupdone")
		&& ( p.verdict == Verdict::undecided || alwaysLookup )
		) {
		clog << "Packet needing DNS lookup received, re-injecting" << endl;
		thread injectThread(lookup_and_reinject, move(p), ref(packetqueue) );
		injectThread.detach();
		continue;
	}

	clog << "Packet recived. facts:" << endl;
	write_info(clog, p.facts);
	clog << endl;

	if ( p.verdict == Verdict::undecided ) {
		nfq_set_verdict(qh,
			p.facts.get<int>("packetid"),
			to_netfilter_int(Verdict::accept),
			0,
			nullptr);
		continue;
	}

	int verdict = to_netfilter_int(p.verdict);
	int id = p.facts.get<int>("packetid");
	clog << "Setting verdict " << to_string(p.verdict) << " for ID " << id << endl;
	nfq_set_verdict(qh, id, verdict, 0, nullptr);
		} catch( ShutdownException& e) {
			clog << e.what() << endl;
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

/*
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
*/

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	qh=nfq_create_queue(h, 0, callback, &packetqueue);
	{
		int rc = nfq_set_mode(qh, NFQNL_COPY_PACKET, 65531);
		if ( rc ) {
			perror("nfq_set_mode");
		}
	}
	{
		int rc = nfq_set_queue_maxlen(qh, /* 10M */ 10*1024*1024 );
		if ( rc ) {
			perror("nfq_set_queue_maxlen");
		}
	}
	if ( !qh ) {
		perror("nfq_q_handle");
	}
	printf("qh: %p\n",  qh );
	int fd= nfq_fd(h);
	for(;;)
	{
		printf("Waiting for packet\n");
		int rv;
		char buf[4096];
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("Got some\n");
			nfq_handle_packet(h, buf, rv); /* send packet to callback */
		} else {
			printf("recv() returned %d\n", rv);
		}
	}

	handlerThread.join();

	return 0;
}
