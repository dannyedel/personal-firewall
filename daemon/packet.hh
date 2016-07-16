#pragma once

#include <boost/property_tree/ptree.hpp>
#include "verdict.hh"

struct Packet{
	boost::property_tree::ptree facts;
	Verdict verdict = Verdict::undecided;
};
