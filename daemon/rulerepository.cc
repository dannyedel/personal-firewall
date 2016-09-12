#include "rulerepository.hh"
#include <boost/log/trivial.hpp>

using namespace std;
using boost::filesystem::path;

namespace PersonalFirewall {

void RuleRepository::append_rule(Rule&& r) {
	_rules.emplace_back( move(r) );
}

void RuleRepository::clear_rules() {
	_rules.clear();
}

RuleRepository::RuleRepository(const Verdict& v, const path&)
	: _defaultVerdict(v)
{
}

Verdict RuleRepository::processPacket(const Packet& p) {
	BOOST_LOG_TRIVIAL(trace) << "Starting rule application for packet " << p.id();
	unsigned int rulenum=0;
	for( const auto& rule: _rules ) {
		BOOST_LOG_TRIVIAL(trace) << "Testing rule " << rulenum << " on packet " << p.id();
		if ( rule.matches(p) ) {
			BOOST_LOG_TRIVIAL(trace) << "Rule " << rulenum <<
				" matched, setting verdict " << rule.verdict <<
				" on packet " << p.id();
			return rule.verdict;
		}
		++rulenum;
	}
	BOOST_LOG_TRIVIAL(trace) << "No rule matched, setting default verdict " <<
		_defaultVerdict << " on packet " << p.id();
	// No rule matched
	return _defaultVerdict;
}

} //end namespace
