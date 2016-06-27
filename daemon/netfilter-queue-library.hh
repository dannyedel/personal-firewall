#pragma once

// This must be included before libnetfilter_queue
#include <cstdint>

extern "C" {
	#include <libnetfilter_queue/libnetfilter_queue.h>
	#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
	#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
	#include <libnetfilter_queue/pktbuff.h>
	#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
	#include <libnetfilter_queue/libnetfilter_queue_udp.h>
}
