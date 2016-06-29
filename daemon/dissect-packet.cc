#include "dissect-packet.hh"
#include <stdexcept>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <linux/ip.h> // ip_hdr
#include <netdb.h> //protoinfo
#include <iostream> // clog
#include <linux/tcp.h> // tcphdr
#include <linux/udp.h> // udphdr
#include <sys/types.h> // getpwuid_r
#include <pwd.h> // struct passwd
#include <sys/stat.h>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>

using namespace std;
using namespace boost::property_tree;
using namespace boost::iostreams;

namespace{

struct LowlevelFailure: public runtime_error {
	LowlevelFailure(const std::string& functionName):
		runtime_error(functionName+" returned an error code")
	{
	}
};

struct InvalidDirection: public runtime_error {
	InvalidDirection(const std::string& direction):
		runtime_error("Invalid direction: "+direction)
	{
	}
};

struct PktbDeleter {
	void operator() (pkt_buff*b) {
		pktb_free(b);
	}
};

struct PopenDeleter {
	void operator() ( FILE* p) {
		int rc = pclose(p);
		if ( 0 != rc )
			clog << "pclose() returned "<< rc << endl;
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

	int ininterface = nfq_get_indev(nfa);
	int outinterface = nfq_get_outdev(nfa);

	if ( ininterface && outinterface ) {
		pt.put("direction", "forward");
	} else if ( ininterface ) {
		pt.put("direction", "input");
	} else if ( outinterface ) {
		pt.put("direction", "output");
	}

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
	else if ( pt.get<string>("layer4protocol") == "udp" )
	{
		if ( 0 != nfq_ip_set_transport_header(pktb, iph) )
			throw LowlevelFailure("nfq_ip_set_transport_header");
		udphdr * udp = nfq_udp_get_hdr(pktb);
		if ( ! udp )
			throw LowlevelFailure("nfq_udp_get_hdr");
		pt.put("sourceport", ntohs(udp->source));
		pt.put("destinationport", ntohs(udp->dest));
	}

	get_socket_owner_program(pt);
}

void PersonalFirewall::get_socket_owner_program(ptree& pt) {
	try {
	const string direction = pt.get<string>("direction");
	const string protocolname = pt.get<string>("layer4protocol");
	if ( protocolname.empty() ) {
		clog << "No protocol name, cannot get socket owner" << endl;
		return;
	}
	string portnumber;
	if ( direction == "forward" ) {
		clog << "Cannot get socket owner for forward packets" << endl;
		return;
	} else if ( direction == "input" ) {
		portnumber = pt.get<string>("destinationport");
	} else if ( direction == "output" ) {
		portnumber = pt.get<string>("sourceport");
	} else {
		throw InvalidDirection(direction );
	}

	const string commandline = "/bin/fuser "+portnumber+"/"+protocolname;

	/// FIXME use popen

	unique_ptr<FILE, PopenDeleter> p { popen(commandline.c_str(), "r") };
	if ( ! p ) {
		clog << "Cannot call " +commandline << endl;
		return;
	}

	stream<file_descriptor_source> fuser{ fileno(p.get()), never_close_handle };

	{
		string line;
		while(getline(fuser,line)) {
			istringstream is(line);
			string pid;
			is >> pid;
			pt.put("pid", pid);
			clog << "PID:" << pid << endl;
		}
	}

	const string procpath = "/proc/"+pt.get<string>("pid");

	{
		// get executable name
		vector<char> exename(4096);
		ssize_t size = readlink(
			(procpath+"/exe").c_str(),
			exename.data(),
			4096);
		if ( size < 0 ) {
			perror("readlink");
		} else if ( size < 4096 ) {
			exename.at(size)='\0';
			pt.put("binary", exename.data());
		}
		ifstream cmdline{ procpath+"/cmdline" };
		string buf;
		getline(cmdline, buf);
		pt.put("cmdline", buf);
	}

	{
		struct stat stats;
		int rc = stat( procpath.c_str(), &stats);
		if ( rc != 0 )
		{
			perror("stat binary");
		} else {
			pt.put("uid", stats.st_uid);
			pt.put("gid", stats.st_gid);
		}
	}

	{
		uid_t uid=pt.get<uid_t>("uid");
		struct passwd pwd_entry;
		struct passwd* pwd_result;
		vector<char> buf(4096);
		int rc = getpwuid_r(uid, &pwd_entry, buf.data(), buf.size(), &pwd_result);
		if ( rc != 0 )
		{
			perror("getpwuid_r");
		}
		else
		{
			pt.put("owner", pwd_result->pw_name);
		}
	}



	} catch( ptree_bad_path& e ) {
		clog << "Could not figure out socket owner: Bad path" << endl;
	}
}
