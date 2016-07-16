#pragma once

#include <boost/filesystem.hpp>

/** Set of rules
 */
class RuleRepository {
public:

	/** Create empty rule set */
	RuleRepository();

	/** Load rule set from files inside this directory
	 * */
	RuleRepository( const boost::filesystem::path& directory );

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
	const Verdict processPacket(const Packet&);

};
