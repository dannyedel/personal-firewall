#pragma once

enum class Verdict {
	/** Accept the packet */
	accept,

	/** Refuse the packet */
	deny,

	/** No decision has been reached */
	undecided
};

/** Need DNS Resolve to make a decision */
struct NeedDnsResolve: std::runtime_error {
	NeedDnsResolve(): runtime_error("Cannot make a decision without resolving DNS name") { }
};

