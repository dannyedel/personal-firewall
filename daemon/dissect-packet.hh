#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include "netfilter-queue-library.hh"

namespace PersonalFirewall{

boost::property_tree::ptree dissect_packet(nfq_data*);

void dissect_ipv4_header(boost::property_tree::ptree&, pkt_buff*, iphdr*);
void dissect_ipv6_header(boost::property_tree::ptree&, pkt_buff*, ip6_hdr*);

void dissect_tcp_header(boost::property_tree::ptree&, pkt_buff*);
void dissect_udp_header(boost::property_tree::ptree&, pkt_buff*);

void get_socket_owner_program(boost::property_tree::ptree&);

}
