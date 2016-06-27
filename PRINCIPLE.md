Target operating principle
==========================

This is basically the high-level specification of what
this program SHOULD do.  Inconsistencies with the actual
code are expected since it is a work-in-progress, but
they should™ get fixed soon™.


Startup phase
-------------

1. Unless otherwise configured, the daemon adds
   rules to the `INPUT`, `OUTPUT` and `FORWARD`
   chains of the `nat` tables of both `iptables`
   and `ip6tables`, to ensure all *connections*
   (not packets) have to pass the daemon.
   1. If these rules already exist, do nothing.
1. Unless otherwise configured, the daemon adds
   implicit and un-changeable rules at the beginning
   of the ruleset that allow
   1. DNS resolution
      1. Outgoing UDP 53 to all nameservers specified
         in /etc/resolv.conf are accepted
      1. Incoming UDP 53 from all nameservers specified
         in /etc/resolv.conf are accepted
   1. Loopback connections
      1. All packets outgoing via `lo` interface
         are accepted
      1. All packets incoming via `lo` interface
         are accepted
1. Daemon reads the startup firewall rule file
   (this could be empty)
1. Daemon creates a UNIX socket with mode 0770, and
   a group appropriate to manage the firewall
   (this group will be able to see the first packet
   of every connection in full text)
1. Daemon drops root privileges
1. Daemon starts processing firewall rules and accepts
   client connections at the unix socket


Main operation loop 1
---------------------

1. The daemon receives a packet from the kernel
1. It tries to discover as many facts about the
   packet as possible, and add them to the `facts`
   struct.
   1. Unless otherwise configured, this includes
      reverse DNS lookups on the involved IP addresses.
   1. If a reverse lookup succeeds, also forward-lookup
      the returned hostname.  If this gives the same IP
      back, fill the hostname field.  Otherwise do not
      include a hostname.
1. Try to match all rules, in order.
   1. If a rule matches, send this as a diagnostic to
      the connected client.
1. If no verdict can be reached, and a client is
   connected, send the facts to the client.
1. If no client is connected, do nothing.
   1. This will fill up the kernel buffer, resulting
      in packet drops if no client connects to decide
      what to do.


Teardown phase
--------------

1. Disconnect all clients
1. If configured to do so, drop the `iptables` rules.
   1. This is not the default behaviour.
   1. If this does *not* happen (the default), the
      system will stop communicating until the firewall
      process is restarted.


Client communication
--------------------

The client-communication is async event-based, meaning
a request ("Add rule this-and-that") will generate
an answer, but it is possible that between the
request and the answer a few "Don't know what to
do with packet xyz" events will interleave.

It is possible that in a future version a simple
synchronous interface will be added.
