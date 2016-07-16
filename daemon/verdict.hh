#pragma once

#include <string>
#include <stdexcept>

namespace PersonalFirewall {

enum class Verdict {
	/** Accept the packet */
	accept,

	/** Refuse the packet */
	reject,

	/** No decision has been reached */
	undecided
};

/** Need DNS Resolve to make a decision */
struct NeedDnsResolve: std::runtime_error {
	NeedDnsResolve(): runtime_error("Cannot make a decision without resolving DNS name") { }
};

int to_netfilter_int(const Verdict&);

std::string to_string(const Verdict&);

} // end namespace
