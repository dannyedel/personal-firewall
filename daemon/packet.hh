#pragma once

#include <boost/property_tree/ptree.hpp>
#include "verdict.hh"

namespace PersonalFirewall {

struct Packet{
	boost::property_tree::ptree facts;
	boost::property_tree::ptree metadata;
	Verdict verdict = Verdict::undecided;

	int id() const;
};

std::ostream& operator << (std::ostream&, const Packet&);

} // end namespace
