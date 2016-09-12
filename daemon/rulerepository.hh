#pragma once

#include "verdict.hh"
#include "packet.hh"
#include "rule.hh"

#include <boost/filesystem.hpp>
#include <vector>

namespace PersonalFirewall {
/** Set of rules
 */
class RuleRepository {
public:

	/** Create empty rule set */
	RuleRepository(const Verdict& defaultVerdict );

	/** Load rule set from files inside this directory
	 * */
	RuleRepository(const Verdict& defaultVerdict, const boost::filesystem::path& directory );

	/** Try to decide packet.
	 *
	 * If a rule matches, it will return accept or reject.
	 *
	 * If the packet information does *not* contain "hostname"
	 * and does *not* contain the "hostnamelookupfailed" special
	 * field, this will throw NeedDnsResolve exception at the first
	 * rule that tries to match against a hostname.
	 *
	 * If a verdict could not be reached, but all rules
	 * have been checked, this will return "undecided".
	 */
	Verdict processPacket(const Packet&);

	/** Append this rule to the end of the set */
	void append_rule(Rule&&);

	/** Clear all rules */
	void clear_rules();

	/** Access the current rule set
	 *
	 * WARNING: Reference becomes invalid when this object is deleted */
	const std::vector<Rule>& rules() const;

private:
	std::vector<Rule> _rules;
	Verdict _defaultVerdict;
};

} // end namespace
