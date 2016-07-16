#include "verdict.hh"

#include "netfilter-queue-library.hh"
#include <linux/netfilter.h>

using namespace PersonalFirewall;
using namespace std;

int to_netfilter_int(const Verdict& v) {
	if ( v == Verdict::accept ) {
		return NF_ACCEPT;
	}
	return NF_DROP;
}

std::string to_string(const Verdict& v) {
	switch(v) {
		case Verdict::accept:
			return "accept";
		case Verdict::reject:
			return "reject";
		default:
			return "undecided";
	}
}