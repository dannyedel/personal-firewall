#include "dissect-packet.hh"
#include <stdexcept>
#include <string>
#include <utility> // pair
#include <vector>
#include <arpa/inet.h>
#include <linux/ip.h> // ip_hdr
#include <netinet/ip6.h> // ip6_hdr
#include <netdb.h> //protoinfo
#include <iostream> // clog
#include <linux/tcp.h> // tcphdr
#include <linux/udp.h> // udphdr
#include <sys/types.h> // getpwuid_r
#include <pwd.h> // struct passwd
#include <sys/stat.h>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <thread> // std::thread
#include <functional> // std::ref

using namespace std;
using namespace boost::property_tree;
using namespace boost::iostreams;
using namespace PersonalFirewall;

namespace{
	/** Look up the DNS Hostnames of packets regardless of
	 * whether a rule trying to match a hostname was encountered
	 *
	 * FIXME: Make this a command-line-switch */
	const bool alwaysDoDnsLookups=false;

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

struct ReverseLookupFailed: public runtime_error{
	ReverseLookupFailed(const std::string& ipaddress):
		runtime_error("Reverse lookup failed for "+ipaddress)
	{
	}
};

string const operator + ( const string& s , const vector<string>& vec) {
	string ret = s;
	for(auto& str: vec) {
		ret+=str+", ";
	}
	return ret;
}

struct ForwardLookupMismatch: public runtime_error{
	ForwardLookupMismatch(const std::string& ipaddress, const std::string& hostname, const vector<string> addresses):
		runtime_error("Reverse lookup for "+ipaddress+" resulted in "+hostname+" but this hostname resolves to "+addresses)
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

/** Determine whether the packet described by pt is a
 * dns packet, to break loops when resolving hostnames
 * */
bool is_dns_packet(const ptree& pt) {
	/* DNS happens via UDP */
	if ( pt.get<string>("layer4protocol") != "udp" )
		return false;

	/* Packet was neither generated nor targeted for
	 * the local machine */
	if ( pt.get<string>("direction") == "forward" )
		return false;

	/* Packet from a nameserver to us */
	if ( pt.get<string>("direction") == "input" &&
		pt.get<int>("sourceport") == 53 ) {
		return true;
	}

	/* Packet from us to a nameserver */
	if ( pt.get<string>("direction") == "output" &&
		pt.get<int>("destinationport") == 53 ) {
		return true;
	}

	/* Just a regular UDP packet. */
	return false;
}

} // end anon namespace

const Packet PersonalFirewall::dissect_packet(nfq_data* nfa) {
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
		unique_ptr<pkt_buff,PktbDeleter> pbuf{
			pktb_alloc(AF_INET6, data, length, 1280) };
		if ( !pbuf ) {
			throw LowlevelFailure("pktb_alloc (ipv6)");
		}
		ip6_hdr * iph = nullptr;
		if ( ! pktb_network_header(pbuf.get()) ) {
			printf("Warning: Cannot get the network header using the library, "
				"using workaround.\n");
			iph = reinterpret_cast<ip6_hdr*>( pktb_data( pbuf.get() ) );
		} else {
			iph = nfq_ip6_get_hdr(pbuf.get());
		}
		dissect_ipv6_header(pt, pbuf.get(), iph);
	}

	ptree metadata;
	metadata.put("hostnamelookupdone", false);

	return Packet{pt, metadata};
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

	if ( 0 != nfq_ip_set_transport_header(pktb, iph) )
		throw LowlevelFailure("nfq_ip_set_transport_header");
	if ( pt.get<string>("layer4protocol") == "tcp" )
	{
		dissect_tcp_header(pt, pktb);
	}
	else if ( pt.get<string>("layer4protocol") == "udp" )
	{
		dissect_udp_header(pt, pktb);
	}

	get_socket_owner_program(pt);

	/* Unless this is a DNS packet from or to this machine,
	 * resolve all addresses involved */
	if ( alwaysDoDnsLookups && ! is_dns_packet(pt)) {
		try {
			pt.put("sourcehostname", dns_reverse_lookup( pt.get<string>("source") ) );
		} catch( ReverseLookupFailed& e) {
			clog << e.what() << endl;
		} catch( ForwardLookupMismatch&e ) {
			clog << e.what() << endl;
		}
		try {
			pt.put("destinationhostname", dns_reverse_lookup( pt.get<string>("destination") ));
		} catch( ReverseLookupFailed&e ) {
			clog << e.what() << endl;
		} catch( ForwardLookupMismatch&e) {
			clog << e.what() << endl;
		}
	}
}

void PersonalFirewall::dissect_tcp_header(ptree& pt, pkt_buff* pktb) {
	tcphdr * tcp = nfq_tcp_get_hdr(pktb);
	if ( ! tcp )
		throw LowlevelFailure("nfq_tcp_get_hdr");
	pt.put("sourceport", ntohs(tcp->source));
	pt.put("destinationport", ntohs(tcp->dest));
}

void PersonalFirewall::dissect_udp_header(ptree& pt, pkt_buff* pktb) {
	udphdr * udp = nfq_udp_get_hdr(pktb);
	if ( ! udp )
		throw LowlevelFailure("nfq_udp_get_hdr");
	pt.put("sourceport", ntohs(udp->source));
	pt.put("destinationport", ntohs(udp->dest));
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

	// Socket owners are currently only supported for TCP and UDP
	if ( protocolname != "tcp" && protocolname != "udp" )
	{
		clog << "Cannot get owner, unsupported protocol: "+protocolname << endl;
		return;
	}

	if ( direction == "forward" ) {
		// Cannot get socket owner for forward packets
		return;
	} else if ( direction == "input" ) {
		portnumber = pt.get<string>("destinationport");
	} else if ( direction == "output" ) {
		portnumber = pt.get<string>("sourceport");
	} else {
		throw InvalidDirection(direction );
	}

	const string commandline = "/bin/fuser "+portnumber+"/"+protocolname+" 2>/dev/null";

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
		getline(cmdline, buf, '\0' );
		pt.put("cmdline", buf);
		while(getline(cmdline,buf,'\0')) {
			pt.add("cmdline.param", buf);
		}
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
		clog << "Could not figure out socket owner: Bad path: " << e.what() << endl;
	}
}

void PersonalFirewall::dissect_ipv6_header( ptree& pt, pkt_buff*pktb, ip6_hdr*iph) {
	char sbuf[INET6_ADDRSTRLEN];
	char dbuf[INET6_ADDRSTRLEN];

	const char * source = inet_ntop(AF_INET6, &iph->ip6_src, sbuf, INET6_ADDRSTRLEN);
	const char * dest = inet_ntop(AF_INET6, &iph->ip6_dst, dbuf, INET6_ADDRSTRLEN);
	pt.put("source", source);
	pt.put("source6", source);
	pt.put("destination", dest);
	pt.put("destination6", dest);
	protoent* protoinfo = getprotobynumber(iph->ip6_nxt);
	if ( protoinfo ) {
		pt.put("layer4protocol", protoinfo->p_name);
		pt.put("layer4protocolnumber", protoinfo->p_proto);
	} else {
		throw LowlevelFailure("getprotobynumber");
	}

	int rc= nfq_ip6_set_transport_header(pktb, iph, pt.get<uint8_t>("layer4protocolnumber"));
	if ( rc != 1) {
		throw LowlevelFailure("nfq_ip6_set_transport_header");
	}
	if ( pt.get<string>("layer4protocol") == "tcp" ) {
		dissect_tcp_header(pt, pktb);
	} else if ( pt.get<string>("layer4protocol") == "udp" ) {
		dissect_udp_header(pt, pktb);
	}
}

namespace {
	union sockaddr46 {
		sockaddr_in v4;
		sockaddr_in6 v6;
	};

	pair<sockaddr46,socklen_t> const to_sockaddr(const string& ipaddress) {
		pair<sockaddr46, socklen_t> ret;
		{
			struct sockaddr_in& sock = ret.first.v4;
			ret.second = sizeof( sockaddr_in );
			sock.sin_family= AF_INET;
			sock.sin_port = 0;
			/* Try as IPv4 */
			static_assert( sizeof(sockaddr_in) <= sizeof( sockaddr46), "sockaddr too small for ipv4" );
			ret.second = sizeof(sockaddr_in);
			int rc = inet_pton( AF_INET, ipaddress.c_str(), &sock.sin_addr );
			if ( rc == 1 ) {
				return ret;
			}
		}

		{
			/* Try as IPv6 */
			struct sockaddr_in6& sock = ret.first.v6;
			ret.second = sizeof( sockaddr_in6 );
			sock.sin6_family = AF_INET6;
			sock.sin6_port = 0;
			static_assert( sizeof(sockaddr_in6) <= sizeof(sockaddr46), "sockaddr too small for ipv6");
			ret.second=sizeof(sockaddr_in6);
			int rc = inet_pton( AF_INET6, ipaddress.c_str(), &sock.sin6_addr );
			if ( rc == 1 ) {
				return ret;
			}
		}

		/* Both failed */
		throw LowlevelFailure("inet_pton cannot parse: "+ipaddress);
	}
}

string PersonalFirewall::dns_reverse_lookup(const string& ipaddress) {
	auto p = to_sockaddr(ipaddress);

	vector<char> buf(1024);

	int rc = getnameinfo(reinterpret_cast<sockaddr*>( &( p.first )), p.second, buf.data(), buf.size(), nullptr, 0, NI_NAMEREQD);

	if ( rc != 0 )
	{
		clog << "getnameinfo returned error " << rc <<": " << gai_strerror(rc) <<
			" while trying to resolve " << ipaddress << endl;
		throw ReverseLookupFailed(ipaddress);
	}

	return string(buf.data());
}

void lookupAndWrite(Packet& packet, std::mutex& m, const std::string& from, const std::string& to) {
	// Copy source address
	unique_lock<mutex> lock(m);
	std::string addr = packet.facts.get<string>(from);

	// resolve without lock
	lock.unlock();

	clog << "Thread " << this_thread::get_id() << " resolving " << addr << " as " << to << endl;
	// this blocks
	try {
		std::string hostname = dns_reverse_lookup(addr);
		clog << "Thread " << this_thread::get_id() << " resolved " << addr << " as " << hostname << " and writing back to " << to << endl;
	
		lock.lock();
		packet.facts.put(to, hostname);
	} catch( ReverseLookupFailed& e) {
		clog << e.what() << endl;
		lock.lock();
		packet.metadata.add("hostnamelookup.failed", to);
	}
}

void PersonalFirewall::lookup_and_reinject(Packet&& oldPacket, PacketQueue& queue) {
	// Move packet to thread-local storage
	Packet p{oldPacket};
	// Create a mutex to protect access to the packet
	mutex m;

	clog << "Thread " << this_thread::get_id() << " starting resolves" << endl;

	// Lookup source hostname locally, lookup
	// destination hostname in thread
	thread dst(lookupAndWrite, ref(p), ref(m), "destination", "destinationhostname");
	lookupAndWrite( p, m, "source", "sourcehostname");
	// Lookups are now running in paralell
	dst.join();
	// Both lookups are complete now

	p.metadata.put("hostnamelookupdone", true);

	clog << "Thread " << this_thread::get_id() << " completed resolving of packet" << endl;

	queue.write(move(p));
}

