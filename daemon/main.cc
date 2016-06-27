#include "netfilter-queue-library.hh"
#include "netfilter-callback.hh"

#include <cstdio> // perror
#include <cstdlib> // exit

using namespace std;

int main() {
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

	nfq_q_handle* qh=nfq_create_queue(h, 0, callback, nullptr);
	nfq_set_mode(qh, NFQNL_COPY_PACKET, 65531);
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
			break;
		}
	}

	return 0;
}
