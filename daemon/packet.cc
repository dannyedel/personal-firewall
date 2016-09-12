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
	"destination",
	"destination4",
	"destination6",
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
	"source",
	"source4",
	"source6",
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

InvalidKey::InvalidKey(const string& keyName, const string& context):
	runtime_error("The key name "+keyName+" is not valid in the context "+context)
{
}
