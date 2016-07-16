Value Dictionary
================

***Unless otherwise noted, IP Address can mean either IPv4
or IPv6 address.***

For converting between string representation and internal binary
representation of IP addresses, please read `inet_ntop(3)` and
`inet_pton(3)`.

Numbers marked as `integer` will be rendered as **decimal**
string representations.  (Example: UDP is rendered as "17", not as "11")

If a packet is IPv4, all the `-v6` facts will not

facts
-----

List of all the possible names in a `facts` property tree (things you
can inspect about a packet).

direction
:	(string) Direction of the packet, either `input`, `output` or `forward`.
	This should™ be equivalent to the iptables chain

sourcehostname
:	(string) Result of a reverse lookup of the packet's source address.  If a
	forward-lookup of the given hostname does **not** include the
	ip address of the packet, the hostname field will not be present

destinationhostname
:	(string) Result of a reverse lookup of the packet's destination
	address.  If a forward-lookup of the resulting hostname does **not** include
	the packet's address, the hostname field will not be present.

source
:	(string) the source IP (v4 or v6)

destination
:	(string) the destination IP (v4 or v6)

source4
:	(string) IPv4 source address

source6
:	(string) IPv6 source address

destination4
:	(string) IPv4 destination address

destination6
:	(string) IPv6 destination address

layer4protocol
:	(string) official protocol name, see `getprotobynumber(3)`.
	If `getprotobynumber(3)` does not know about the protocol, this
	field will not be present.

layer4protocolnumber
:	(integer) protocol number from the IP packet.

sourceport
:	(integer) source port number (currently only for tcp and udp)

destinationport
:	(integer) destination port number (currently only for tcp and udp)

pid
:	(integer) Process-ID owning the local endpoint

binary
:	(string) path to the binary owning the local endpoint, if available

user
:	(string) name of the user owning the local endpoint, if available

userid
:	(integer) id of the user owning the local endpoint, if available


metadata
--------

hostnamelookupfailed
:	(string) "true" if a DNS Lookup has been attempted, but failed.

rules
-----

In a rule, you can use all of the above matchers.  All fields are
`AND`ed, meaning the more you specify, the less your rule will match.
This is basically the same the same way `iptables(8)` operates.

In addition, there are a few pseudo-fields that allow checking both the
source and the destination, similar to how tcpdump's "host" or "port"
specifier work.

hostname
:	Matches if at least one of `sourcehostname` or `destinationhostname`
	matches.

hostnamematch
:	Same as hostname, but allows wildcards. For example, `*.example.com`
	would match all subdomains of .example.com (but not example.com
	itself).  See `fnmatch(3)` for the syntax.

address
:	Matches if at least one of `sourceaddress` or `destinationaddress`
	match.

port
:	Matches if at least one of `sourceport` or `destinationport` match.
