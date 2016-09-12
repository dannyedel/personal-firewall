#include "rule.hh"
#include <vector>

using namespace boost::property_tree;
using namespace PersonalFirewall;
using namespace std;

bool Rule::matches(const Packet&) const {
	return false;
}

/** Alphabetically sorted list of allowed rule matcher keys,
 * in addition to all allowed facts
 */
const vector<string> additionalKeys = {
	"address",
	"hostname",
	"hostnamematch",
	"port",
};

Rule::Rule( const ptree& r, const Verdict& v):
	restrictions(r),
	verdict(v)
{
	validate_keys();
}

void Rule::validate_keys() {
	validate_match_keys(restrictions);
}

bool PersonalFirewall::is_valid_match_key(const string& key) {
	if ( is_valid_fact_key(key) )
		return true;
	if ( binary_search(
		additionalKeys.cbegin(),
		additionalKeys.cend(),
		key) )
		return true;
	return false;
}

void PersonalFirewall::validate_match_keys(const ptree& tree) {
	for( const auto& p: tree ) {
		if ( ! is_valid_match_key(p.first) )
			throw InvalidMatchKey(p.first);
	}
}

InvalidMatchKey::InvalidMatchKey( const string& s):
	InvalidKey(s, "rule")
{
};
