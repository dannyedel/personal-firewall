#pragma once

#include <boost/property_tree/ptree.hpp>
#include "verdict.hh"

namespace PersonalFirewall {

bool is_valid_fact_key(const std::string& );
bool is_valid_metadata_key(const std::string& );

struct InvalidKey: public std::runtime_error{
	InvalidKey(const std::string& keyName, const std::string& context);
};

struct InvalidFactsKey: public InvalidKey{
	InvalidFactsKey(const std::string&);
};

struct InvalidMetadataKey: public InvalidKey{
	InvalidMetadataKey(const std::string&);
};

void validate_facts_keys(const boost::property_tree::ptree&);
void validate_metadata_keys(const boost::property_tree::ptree&);

struct Packet{
	boost::property_tree::ptree facts;
	boost::property_tree::ptree metadata;
	Verdict verdict = Verdict::undecided;

	// constructs a Packet from facts (empty metadata)
	Packet( const boost::property_tree::ptree& );

	// constructs a Packet from facts and metadata
	Packet( const boost::property_tree::ptree&, const boost::property_tree::ptree&);

	int id() const;

private:
	void validate_keys();
};

std::ostream& operator << (std::ostream&, const Packet&);

} // end namespace
