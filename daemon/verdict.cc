#include "verdict.hh"

#include "netfilter-queue-library.hh"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/netfilter.h>

using namespace PersonalFirewall;
using namespace std;

int PersonalFirewall::to_netfilter_int(const Verdict& v) {
	if ( v == Verdict::accept ) {
		return NF_ACCEPT;
	}
	return NF_DROP;
}

std::string PersonalFirewall::to_string(const Verdict& v) {
	switch(v) {
		case Verdict::accept:
			return "accept";
		case Verdict::reject:
			return "reject";
		default:
			return "undecided";
	}
}

ostream& PersonalFirewall::operator << (ostream& where, const Verdict& v) {
	return where << to_string(v);
}
