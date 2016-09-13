#pragma once

#include "packet.hh"

#include <boost/filesystem/path.hpp>

namespace PersonalFirewall {

	struct InvalidRuleFile: public std::runtime_error {
		InvalidRuleFile(const boost::filesystem::path&, const std::string&);
	};

	struct InvalidRuleLine1: public InvalidRuleFile {
		/** Path of file, and contents of first line */
		InvalidRuleLine1(const boost::filesystem::path&, const std::string&);
	};

	struct InvalidRuleBody: public InvalidRuleFile {
		InvalidRuleBody(const boost::filesystem::path&, const std::string&);
	};

	bool is_valid_match_key(const std::string&);
	void validate_match_keys(const boost::property_tree::ptree&);

	struct InvalidMatchKey: public InvalidKey {
		InvalidMatchKey(const std::string&);
	};

	class Rule {
	public:
		/** Does this rule match against the packet?
		 *
		 * Throws NeedDnsResolve if this can only be answered
		 * with non-present DNS name data.
		 * */
		bool matches( const Packet& p) const;

		Rule(const boost::property_tree::ptree&, const Verdict& verdict);

		/** Construct a rule from a file */
		Rule(const boost::filesystem::path&);

		const Verdict& verdict() const;

		/** Warning, reference expires when this object is deleted*/
		const boost::property_tree::ptree& restrictions() const;

	private:
		void validate_keys();
		/*** Set of restrictions that define whether this rule matches ***/
		boost::property_tree::ptree _restrictions;
		/*** Verdict if this rule matches ***/
		Verdict _verdict;
	};

	bool operator == (const Rule&, const Rule&);

	std::ostream& operator << (std::ostream&, const Rule&);

}
