#include "dissect-packet.hh"
#include <stdexcept>
#include <string>
#include <utility> // pair
#include <vector>
#include <arpa/inet.h>
#include <netdb.h> //protoinfo
#include <boost/log/trivial.hpp>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h> // tcphdr
#include <linux/udp.h> // udphdr
#include <sys/types.h> // getpwuid_r
#include <pwd.h> // struct passwd
#include <sys/stat.h>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <thread> // std::thread
#include <functional> // std::ref
#include <chrono>


using namespace std;
using namespace boost::property_tree;
using namespace boost::iostreams;
using namespace PersonalFirewall;

namespace{

	void updateDnsTiming(double secondsReverse, double secondsForward) {
		static mutex m;
		unique_lock<mutex> lock(m);
		static unsigned numberRequests=0;
		static double totalTimeR;
		static double bestTimeR = secondsReverse;
		static double worstTimeR = secondsReverse;
		static double totalTimeF;
		static double bestTimeF = secondsForward;
		static double worstTimeF = secondsForward;
		numberRequests+=1;
		totalTimeR+=secondsReverse;
		totalTimeF+=secondsForward;
		if ( secondsReverse < bestTimeR ) {
			bestTimeR = secondsReverse;
		}
		if ( secondsForward < bestTimeF ) {
			bestTimeF = secondsForward;
		}
		if ( secondsReverse > worstTimeR ) {
			worstTimeR = secondsReverse;
		}
		if ( secondsForward > worstTimeF ) {
			worstTimeF = secondsForward;
		}
		BOOST_LOG_TRIVIAL(info) << "DNS lookup took " << secondsReverse << "s + " << secondsForward << "s";
		BOOST_LOG_TRIVIAL(info) <<
			"Reverse: total: " << totalTimeR <<
			" over " << numberRequests << " requests" <<
			", best: " << bestTimeR <<
			", worst: " << worstTimeR <<
			", avg: " << totalTimeR/numberRequests ;
		BOOST_LOG_TRIVIAL(info) <<
			"Forward: total: " << totalTimeF <<
			" over " << numberRequests << " requests" <<
			", best: " << bestTimeF <<
			", worst: " << worstTimeF <<
			", avg: " << totalTimeF/numberRequests ;
	}

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

struct ForwardLookupFailed: public runtime_error{
	ForwardLookupFailed(const std::string& ipaddress, const std::string& hostname):
		runtime_error("Reverse lookup for "+ipaddress+" resulted in "+hostname+", but this hostname does not resolve!")
	{
	}
};

struct ForwardLookupMismatch: public runtime_error{
	ForwardLookupMismatch(const std::string& ipaddress, const std::string& hostname, const vector<string> addresses):
		runtime_error("Reverse lookup for "+ipaddress+" resulted in "+hostname+", but this hostname resolves to "+addresses)
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
			BOOST_LOG_TRIVIAL(warning) << "pclose() returned "<< rc;
	}
};

struct ReadlinkFailed: public runtime_error {
	string filename;
	int errorcode;
	ReadlinkFailed(const string& f, int e):
		runtime_error(string("readlink(")+f+") failed: "+strerror(e)),
		filename(f),
		errorcode(e)
	{
	}
};

string readlink_str(const string& param) {
	const unsigned bufsize=4096;
	vector<char> link_target_buf(bufsize);
	ssize_t textsize = readlink(
		param.c_str(),
		link_target_buf.data(),
		bufsize);
	if ( textsize < 0 ) {
		throw ReadlinkFailed(param, errno);
	}
	link_target_buf.at(textsize)='\0';
	return string(link_target_buf.data());
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

	pt.put("sourceaddress", sbuf);
	pt.put("sourceaddress4", sbuf);
	pt.put("destinationaddress", dbuf);
	pt.put("destinationaddress4", dbuf);

	pt.put("layer4protocolnumber", iph->protocol);

	protoent * protoinfo = getprotobynumber( iph->protocol );
	if ( protoinfo ) {
		pt.put("layer4protocol", protoinfo->p_name);
	} else {
		BOOST_LOG_TRIVIAL(warning) << "Unknown IP protocol number: " << iph->protocol;
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
		BOOST_LOG_TRIVIAL(debug) << "No protocol name, cannot get socket owner";
		return;
	}
	string portnumber;

	// Socket owners are currently only supported for TCP and UDP
	if ( protocolname != "tcp" && protocolname != "udp" )
	{
		BOOST_LOG_TRIVIAL(debug) << "Cannot get owner, unsupported protocol: "+protocolname;
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

	unique_ptr<FILE, PopenDeleter> p { popen(commandline.c_str(), "r") };
	if ( ! p ) {
		BOOST_LOG_TRIVIAL(warning) << "Cannot call " << commandline << ", got null pointer from popen()";
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
		const string exepath = procpath+"/exe";
		pt.put("binary", readlink_str(exepath));
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
			BOOST_LOG_TRIVIAL(warning) << "stat() failed on " << procpath << ": " << strerror(errno);
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
			BOOST_LOG_TRIVIAL(warning) << "getpwuid_r() failed: " << strerror(errno);
		}
		else
		{
			pt.put("owner", pwd_result->pw_name);
		}
	}



	} catch( exception& e ) {
		BOOST_LOG_TRIVIAL(warning) << "Could not figure out socket owner: " << e.what() << endl;
	}
}

void PersonalFirewall::dissect_ipv6_header( ptree& pt, pkt_buff*pktb, ip6_hdr*iph) {
	char sbuf[INET6_ADDRSTRLEN];
	char dbuf[INET6_ADDRSTRLEN];

	const char * source = inet_ntop(AF_INET6, &iph->ip6_src, sbuf, INET6_ADDRSTRLEN);
	const char * dest = inet_ntop(AF_INET6, &iph->ip6_dst, dbuf, INET6_ADDRSTRLEN);
	pt.put("sourceaddress", source);
	pt.put("sourceaddress6", source);
	pt.put("destinationaddress", dest);
	pt.put("destinationaddress6", dest);
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

string to_string(addrinfo& ad) {
	if ( ad.ai_canonname ) {
		BOOST_LOG_TRIVIAL(trace) << "canon name: " << ad.ai_canonname;
	}
	vector<char> buffer(1024);
	/** Address of a sin_addr or sin6_addr field inside an ai_addr structure.
	 * No danger of getting any & * -> combination wrong here.
	 */
	void * whatcouldpossiblygowrong = nullptr;
	if ( ad.ai_family == AF_INET ) {
		whatcouldpossiblygowrong = & reinterpret_cast<sockaddr_in*>(ad.ai_addr)->sin_addr;
	} else if ( ad.ai_family == AF_INET6 ) {
		whatcouldpossiblygowrong = & reinterpret_cast<sockaddr_in6*>(ad.ai_addr)->sin6_addr;
	} else {
		BOOST_LOG_TRIVIAL(error) << "Unsupported address family: " << ad.ai_family;
		throw LowlevelFailure("Unsupported AF_SOMETHING");
	}

	if ( ! inet_ntop( ad.ai_family, whatcouldpossiblygowrong, buffer.data(), 1024) ) {
		BOOST_LOG_TRIVIAL(warning) << "inet_pton failed (AF_INET): " << strerror(errno);
		throw LowlevelFailure("inet_pton");
	}

	return string{buffer.data()};
}

vector<string> PersonalFirewall::dns_forward_lookup( const string& hostname) {
	vector<string> result;
	BOOST_LOG_TRIVIAL(debug) << "attempting forward lookup: " << hostname;
	struct addrinfo_result{
		addrinfo* p = nullptr;
		~addrinfo_result() {
			freeaddrinfo(p);
		}
	} gairesult;
	addrinfo hints;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = (AI_PASSIVE);
	int rc = getaddrinfo(
		hostname.c_str() /* node */,
		nullptr /* service */,
		&hints /* hints */,
		&gairesult.p /* address of pointer to result */);
	if ( rc != 0 ) {
		BOOST_LOG_TRIVIAL(warning) << "getaddrinfo returned error " << rc << ": "
			<< gai_strerror(rc) << " while resolving " << hostname;
		return result;
	}
	BOOST_LOG_TRIVIAL(trace) << "getaddrinfo() returned " << rc;
	for( addrinfo* ptr=gairesult.p ; ptr != nullptr ; ptr = ptr->ai_next ) {
		BOOST_LOG_TRIVIAL(debug) << "Forward lookup for " << hostname << ": " << to_string(*ptr);
		result.emplace_back( to_string( *ptr ) );
	}
	return result;
}

string PersonalFirewall::dns_reverse_lookup(const string& ipaddress) {
	auto p = to_sockaddr(ipaddress);

	vector<char> buf(1024);

	int rc = getnameinfo(reinterpret_cast<sockaddr*>( &( p.first )), p.second, buf.data(), buf.size(), nullptr, 0, NI_NAMEREQD);

	if ( rc != 0 )
	{
		BOOST_LOG_TRIVIAL(warning) << "getnameinfo returned error " << rc <<": " << gai_strerror(rc) <<
			" while trying to resolve " << ipaddress;
		throw ReverseLookupFailed(ipaddress);
	}

	const string reverseFqdn{ buf.data()};

	BOOST_LOG_TRIVIAL(trace) << "Got reverse lookup: " << ipaddress << " => " << reverseFqdn << ", checking forward";

	return reverseFqdn;
}

void lookupAndWrite(Packet& packet, std::mutex& m, const std::string& from, const std::string& to) {
	// Copy source address
	unique_lock<mutex> lock(m);
	std::string addr = packet.facts.get<string>(from);

	// resolve without lock
	lock.unlock();

	BOOST_LOG_TRIVIAL(debug) << "resolving " << addr << " as " << to << endl;
	// this blocks
	auto start = chrono::steady_clock::now();
	auto midpoint = start;
	try {
		std::string hostname = dns_reverse_lookup(addr);
		midpoint = chrono::steady_clock::now();
		vector<string> addresses = dns_forward_lookup( hostname );
		if ( addresses.empty() ) {
			throw ForwardLookupFailed(addr, hostname);
		}
		bool found=false;
		for( const auto& ad: addresses ) {
			// the address also resolves forward. success!
			if ( ad == addr ) {
				BOOST_LOG_TRIVIAL(debug) << "Check okay, forward lookup of " << hostname << " contains " << ad ;
				found=true;
				break;
			}
		}
		if ( !found ) {
			throw ForwardLookupMismatch(addr, hostname, addresses);
		}
		BOOST_LOG_TRIVIAL(debug) << "resolved " << addr << " as " << hostname << " and writing back to " << to;
	
		lock.lock();
		packet.facts.put(to, hostname);
	} catch( exception& e) {
		BOOST_LOG_TRIVIAL(warning) << e.what();
		lock.lock();
		packet.metadata.add("hostnamelookup.failed", to);
	}
	auto end = chrono::steady_clock::now();
	chrono::duration<double> timeR = midpoint-start;
	chrono::duration<double> timeF = end-midpoint;
	updateDnsTiming(timeR.count(), timeF.count());
}

void PersonalFirewall::lookup_and_reinject(Packet&& oldPacket, PacketQueue& queue) {
	// Move packet to thread-local storage
	Packet p{oldPacket};
	// Create a mutex to protect access to the packet
	mutex m;

	BOOST_LOG_TRIVIAL(debug) << "starting DNS resolves for packet " << p.id();

	// Lookup source hostname locally, lookup
	// destination hostname in thread
	thread dst(lookupAndWrite, ref(p), ref(m), "destinationaddress", "destinationhostname");
	lookupAndWrite( p, m, "sourceaddress", "sourcehostname");
	// Lookups are now running in paralell
	dst.join();
	// Both lookups are complete now

	p.metadata.put("hostnamelookupdone", true);

	BOOST_LOG_TRIVIAL(debug) << "completed DNS resolving of packet " << p.id();

	queue.write(move(p));
}

