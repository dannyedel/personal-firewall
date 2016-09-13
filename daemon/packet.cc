#include "packet.hh"
#include <vector>
#include <boost/property_tree/info_parser.hpp>

using namespace std;
using namespace PersonalFirewall;
using namespace boost::property_tree;

/** Alphabetically sorted list of valid fact strings */
const vector<string> validFactsKeys = {
	"binary",
	"cmdline",
	"destinationaddress",
	"destinationaddress4",
	"destinationaddress6",
	"destinationhostname",
	"destinationport",
	"direction",
	"gid",
	"hwproto",
	"layer4protocol",
	"layer4protocolnumber",
	"owner",
	"packetid",
	"pid",
	"sourceaddress",
	"sourceaddress4",
	"sourceaddress6",
	"sourcehostname",
	"sourceport",
	"uid",
	"user",
};

const vector<string> validMetadataKeys = {
	"hostnamelookupdone",
};

ostream& PersonalFirewall::operator<< (ostream& where, const Packet& what) {
	where << " *** facts ***\n";
	write_info(where, what.facts);
	where << " *** metadata ***\n";
	write_info(where, what.metadata);
	where << " *** verdict ***\n" << to_string(what.verdict);
	return where;
}

int Packet::id() const {
	return facts.get<int>("packetid");
}

Packet::Packet(const ptree& f, const ptree& m):
	facts(f),
	metadata(m) {
	validate_keys();
}

Packet::Packet(const ptree& facts): Packet(facts, ptree()) {
}

bool PersonalFirewall::is_valid_fact_key(const string& s) {
	return binary_search( validFactsKeys.cbegin(), validFactsKeys.cend(), s);
}

bool PersonalFirewall::is_valid_metadata_key(const string& s) {
	return binary_search( validMetadataKeys.cbegin(), validMetadataKeys.cend(), s);
}

InvalidKey::InvalidKey(const string& keyName, const string& context):
	runtime_error("The key name "+keyName+" is not valid in the context "+context)
{
}

InvalidFactsKey::InvalidFactsKey(const string& keyName):
	InvalidKey(keyName, "facts")
{
}

InvalidMetadataKey::InvalidMetadataKey(const string& keyName):
	InvalidKey(keyName, "metadata")
{
}

void Packet::validate_keys() {
	validate_facts_keys(facts);
	validate_metadata_keys(metadata);
}

void PersonalFirewall::validate_facts_keys(const ptree& facts){
	for(const auto& pair: facts) {
		if ( ! is_valid_fact_key(pair.first) ) {
			throw InvalidFactsKey(pair.first);
		}
	}
}

void PersonalFirewall::validate_metadata_keys(const ptree& metadata){
	for(const auto& pair: metadata) {
		if ( ! is_valid_metadata_key(pair.first) )
			throw InvalidMetadataKey(pair.first);
	}
}
