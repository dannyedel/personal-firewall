#include "rule.hh"

using namespace boost::property_tree;
using namespace PersonalFirewall;

bool Rule::matches(const Packet&) const {
	return false;
}

Rule::Rule( const ptree& r, const Verdict& v):
	restrictions(r),
	verdict(v)
{
}
