#pragma once

#include "packet.hh"

namespace PersonalFirewall {

	struct Rule {
		/*** Set of restrictions that define whether this rule matches ***/
		boost::property_tree::ptree restrictions;

		/*** Verdict if it matches ***/
		Verdict verdict;

		/** Does this rule match against the packet?
		 *
		 * Throws NeedDnsResolve if this can only be answered
		 * with non-present DNS name data.
		 * */
		bool matches( const Packet& p) const;
	};

}
