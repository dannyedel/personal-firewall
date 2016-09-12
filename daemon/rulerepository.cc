#include "rulerepository.hh"

using namespace std;

namespace PersonalFirewall {

void RuleRepository::append_rule(Rule&& r) {
	_rules.emplace_back( move(r) );
}

void RuleRepository::clear_rules() {
	_rules.clear();
}

Verdict RuleRepository::processPacket(const Packet& p) {
	for( const auto& rule: _rules ) {
		if ( rule.matches(p) ) {
			return rule.verdict;
		}
	}
	// No rule matched
	return _defaultVerdict;
}

} //end namespace
