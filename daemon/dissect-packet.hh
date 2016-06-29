#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <vector>
#include "netfilter-queue-library.hh"

namespace PersonalFirewall{

boost::property_tree::ptree dissect_packet(nfq_data*);

void dissect_ipv4_header(boost::property_tree::ptree&, pkt_buff*, iphdr*);
void dissect_ipv6_header(boost::property_tree::ptree&, pkt_buff*, ip6_hdr*);

void dissect_tcp_header(boost::property_tree::ptree&, pkt_buff*);
void dissect_udp_header(boost::property_tree::ptree&, pkt_buff*);

void get_socket_owner_program(boost::property_tree::ptree&);

/** Returns the canonical hostname of the machine, as defined by a PTR record.
 *
 * This will verify the record with a forward lookup; if it does not match
 * it will not be returned.
 */
std::string dns_reverse_lookup(const std::string& ipaddress);
std::vector<std::string> dns_forward_lookup(const std::string& hostname);

}
