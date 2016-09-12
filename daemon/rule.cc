#include "rule.hh"

namespace PersonalFirewall {

	bool Rule::matches(const Packet&) const {
		return false;
	}

}
