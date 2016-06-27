#include <cstdint>
#include <cstdio> // printf
#include <memory>
#include <vector>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <netdb.h> // protoinfo
extern "C" {
	#include <libnetfilter_queue/libnetfilter_queue.h>
	#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
	#include <libnetfilter_queue/pktbuff.h>
}

using namespace std;

static int callback(
	nfq_q_handle* qh,
	nfgenmsg* /* unused nfmsg */,
	nfq_data* nfa,
	void* /* unused data */) {
	printf("callback\n");
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
			printf("This is IPv4\n");
			/* Transfer packet to userspace buffer */
			pkt_buff* pbuf= pktb_alloc( AF_INET, data, length, 1280);
			if ( ! pbuf ) {
				perror("pkt_buff");
			} else {
				iphdr* iph = nfq_ip_get_hdr( pbuf );
				if ( iph ) {
					printf("IPv4 source: %x destination: %x proto: %x\n",
						ntohl(iph->saddr), ntohl(iph->daddr), iph->protocol);
					char sbuf[ INET_ADDRSTRLEN ];
					char dbuf[ INET_ADDRSTRLEN ];
					printf("Source: %s Destination: %s\n",
						inet_ntop(AF_INET, &iph->saddr, sbuf, INET_ADDRSTRLEN),
						inet_ntop(AF_INET, &iph->daddr, dbuf, INET_ADDRSTRLEN));
					protoent* protoinfo = getprotobynumber(iph->protocol);
					if ( protoinfo ) {
						printf("Protocol name: %s number: %d (hex %x)\n",
							protoinfo->p_name, protoinfo->p_proto, protoinfo->p_proto);
					} else {
						perror("protoinfo");
					}
				} else {
					perror("nfq_ip_get_hdr");
				}
			}
			pktb_free(pbuf);
		}
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


int main() {
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
