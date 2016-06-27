#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include "netfilter-queue-library.hh"

namespace PersonalFirewall{

boost::property_tree::ptree dissect_packet(nfq_data*);

void dissect_ipv4_header(boost::property_tree::ptree&, pkt_buff*, iphdr*);

}
