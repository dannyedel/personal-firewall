#pragma once

#include <boost/property_tree/ptree.hpp>
#include "verdict.hh"

namespace PersonalFirewall {

struct Packet{
	boost::property_tree::ptree facts;
	boost::property_tree::ptree metadata;
	Verdict verdict = Verdict::undecided;
};

} // end namespace
