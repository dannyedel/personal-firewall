#pragma once

#include "netfilter-queue-library.hh"

int callback(nfq_q_handle*, nfgenmsg*, nfq_data*, void*);
