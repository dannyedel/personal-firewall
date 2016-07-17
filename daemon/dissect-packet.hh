#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <vector>
#include "netfilter-queue-library.hh"
#include "packet.hh"
#include "packetqueue.hh"

namespace PersonalFirewall{

const Packet dissect_packet(nfq_data*);

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

/** Thread worker function that will run DNS lookups and
 * re-inject the packet into the queue whey they are finished
 * */
void lookup_and_reinject(Packet&&, PacketQueue&);

bool is_dns_packet(const boost::property_tree::ptree& facts);

}
