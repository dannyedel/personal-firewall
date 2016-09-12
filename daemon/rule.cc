#include "rule.hh"
#include <vector>
#include <boost/log/trivial.hpp>
#include <fnmatch.h>

using namespace boost::property_tree;
using namespace PersonalFirewall;
using namespace std;

/** Keys that cannot be decided without DNS lookup */
const vector<string> dnsKeys = {
	"destinationhostname",
	"hostname",
	"hostnamematch",
	"sourcehostname",
};

/** Keys that can match either the source- or destination- field */
const vector<string> specialKeys = {
	"address",
	"hostname",
	"port",
};

inline bool contains(const vector<string>& vec, const string& s) {
	return binary_search(vec.cbegin(), vec.cend(), s);
}

bool Rule::matches(const Packet& p) const {
	// Test given keys one by one to see if they match
	for( const auto& pair: restrictions) {
		// First check the simple keys
		if ( ! contains(dnsKeys, pair.first)
			&& ! contains(specialKeys, pair.first) ) {
			try {
				// If a key is not equal, its a fail
				if ( pair.second.data() != p.facts.get<string>(pair.first) ) {
					BOOST_LOG_TRIVIAL(trace) << "Failed on simple compare";
					return false;
				}
			} catch( ptree_bad_path& e) {
				// If a key does not exist, its a fail
				BOOST_LOG_TRIVIAL(trace) << "Failed on nonexistent key " << pair.first;
				return false;
			}
		}
	}
	// Check special non-dns keys
	for( const auto& pair: restrictions ) {
		if ( contains(specialKeys, pair.first) && ! contains(dnsKeys, pair.first) ) {
			const string& data = pair.second.data();
			if ( data != p.facts.get_optional<string>("source"+pair.first)
				&& data != p.facts.get_optional<string>("destination"+pair.first) )
			{
				// The packet matches neither the source-
				// nor the destination- version of the special key
				BOOST_LOG_TRIVIAL(trace) << "Failed on special key " << pair.first;
				return false;
			}
		}
	}
	
	// Check DNS keys
	for( const auto& pair: restrictions) {
		const string& data= pair.second.data();
		if ( contains(dnsKeys, pair.first) ) {
			if ( p.metadata.get_optional<string>("hostnamelookupdone") != string("true") ) {
				BOOST_LOG_TRIVIAL(trace) << "Need DNS resolve to check " << pair.first;
				throw NeedDnsResolve();
			}
			if ( pair.first == "hostnamematch" ) {
				// Special hostname match system
				auto source = p.facts.get_optional<string>("sourcehostname");
				auto dest = p.facts.get_optional<string>("destinationhostname");

				// If neither of them matches the specified match key,
				// this match is a fail
				//
				// structure of this devil:
				// if not (source exists and matches) and not (dest exists and matches)
				// then return false
				bool matched = false;
				if ( source ) {
					// source exists
					if ( 0 == fnmatch(data.c_str(), source->c_str(), 0) )
						matched = true;
				}
				if ( dest ) {
					if ( 0 == fnmatch(data.c_str(), dest->c_str(), 0))
						matched=true;
				}
				if ( not matched ) {
					BOOST_LOG_TRIVIAL(trace) << "Failed on hostname match, pattern " << data
						<< " vs. '" << source << "' -> '" << dest << "'";
					return false;
				}

			}
			// Check if this is a special dns key
			else if ( contains(specialKeys, pair.first) ) {
				if ( data != p.facts.get_optional<string>("source"+pair.first)
					&& data != p.facts.get_optional<string>("destination"+pair.first) )
				{
					BOOST_LOG_TRIVIAL(trace) << "Failed on special DNS key " << pair.first;
					return false;
				}
			} else {
				// DNS key, but not special key
				if ( data != p.facts.get<string>( pair.first ) ) {
					BOOST_LOG_TRIVIAL(trace) << "Failed on normal DNS key " << pair.first;
					return false;
				}
			}
		}
	}

	// All restrictions, if there were any,
	// matched so far. The rule as a total matches.

	return true;
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
