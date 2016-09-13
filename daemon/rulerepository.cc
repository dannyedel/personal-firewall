#include "rulerepository.hh"
#include <boost/log/trivial.hpp>
#include <iostream>

using namespace std;
using namespace boost::filesystem;

// Helper function: Output vector of T
ostream& operator << (ostream& where, const vector<path>& vec) {
	for(auto it=vec.cbegin(); it != vec.cend(); ) {
		where << *it;
		if ( it++ != vec.cend() ) {
			where << ", ";
		}
	}
	return where;
}


namespace PersonalFirewall {

void RuleRepository::append_rule(Rule&& r) {
	_rules.emplace_back( move(r) );
}

void RuleRepository::clear_rules() {
	_rules.clear();
}

bool isNotHidden(const path& p) {
	path::string_type name = p.filename().native();
	if ( name.length() > 0 && name[0] == '.' ) {
		BOOST_LOG_TRIVIAL(trace) << "Ignoring dotfile " << p;
		return false;
	}
	return true;
}

RuleRepository::RuleRepository(const Verdict& v, const path& p)
	: _defaultVerdict(v)
{
	BOOST_LOG_TRIVIAL(trace) << "Loading ruleset from " << p;
	// Read entire directory into vector of filenames
	vector<path> rulefiles;
	copy_if(directory_iterator(p), directory_iterator(),
		back_inserter(rulefiles), isNotHidden);

	sort(rulefiles.begin(), rulefiles.end());

	for(const auto& p: rulefiles) {
		BOOST_LOG_TRIVIAL(trace) << "Constructing Rule from file " << p;
		_rules.emplace_back( p );
	}
}

Verdict RuleRepository::processPacket(const Packet& p) {
	BOOST_LOG_TRIVIAL(trace) << "Starting rule application for packet " << p.id();
	unsigned int rulenum=0;
	for( const auto& rule: _rules ) {
		BOOST_LOG_TRIVIAL(trace) << "Testing rule " << rulenum << ": " << rule << " on packet " << p.id();
		if ( rule.matches(p) ) {
			BOOST_LOG_TRIVIAL(trace) << "Rule " << rulenum <<
				" matched, setting verdict " << rule.verdict() <<
				" on packet " << p.id();
			return rule.verdict();
		}
		++rulenum;
	}
	BOOST_LOG_TRIVIAL(trace) << "No rule matched, setting default verdict " <<
		_defaultVerdict << " on packet " << p.id();
	// No rule matched
	return _defaultVerdict;
}

RuleRepository::RuleRepository(const Verdict& v):
	_defaultVerdict(v)
{
}

const vector<Rule>& RuleRepository::rules() const {
	return _rules;
}

} //end namespace
