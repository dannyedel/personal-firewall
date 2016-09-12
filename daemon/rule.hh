#pragma once

#include "packet.hh"

namespace PersonalFirewall {

	bool is_valid_match_key(const std::string&);
	void validate_match_keys(const boost::property_tree::ptree&);

	struct InvalidMatchKey: public InvalidKey {
		InvalidMatchKey(const std::string&);
	};

	class Rule {
	public:
		/*** Set of restrictions that define whether this rule matches ***/
		const boost::property_tree::ptree restrictions;

		/*** Verdict if this rule matches ***/
		const Verdict verdict;

		/** Does this rule match against the packet?
		 *
		 * Throws NeedDnsResolve if this can only be answered
		 * with non-present DNS name data.
		 * */
		bool matches( const Packet& p) const;

		Rule(const boost::property_tree::ptree&, const Verdict& verdict);

	private:
		void validate_keys();
	};

}
