#include "packet.hh"
#include <boost/property_tree/info_parser.hpp>

using namespace std;
using namespace PersonalFirewall;
using namespace boost::property_tree;

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

Packet::Packet(const ptree& facts, const ptree& metadata) {
	(void)facts;
	(void)metadata;
}

Packet::Packet(const ptree& facts): Packet(facts, ptree()) {
}
