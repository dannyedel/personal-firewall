Implements a personal firewall using the NFQUEUE mechanism.

This allows you to interactively choose which packets
you allow your machine to send and receive.

You must configure iptables to send the packets to NFQUEUE
in order to use this program.

Example using the OUTPUT chain:

```bash
### Clear all output rules
iptables -t nat -F OUTPUT
### Allow all packets to the local machine
iptables -t nat -A OUTPUT -o lo -j ACCEPT
### If you have a completely trusted network, add this
# iptables -t nat -A OUTPUT -o ethX -j ACCEPT
### Send the rest to the firewall application
iptables -t nat -A OUTPUT -j NFQUEUE

### Same for incoming packets
iptables -t nat -F INPUT
iptables -t nat -A INPUT -i lo -j ACCEPT
iptables -t nat -A INPUT -j NFQUEUE

### Same for IPv6, outgoing
ip6tables -t nat -F OUTPUT
ip6tables -t nat -A OUTPUT -o lo -j ACCEPT
ip6tables -t nat -A OUTPUT -j NFQUEUE

### Same for IPv6, incoming
ip6tables -t nat -F INPUT
ip6tables -t nat -A INPUT -i lo -j ACCEPT
ip6tables -t nat -A INPUT -j NFQUEUE
```

To speed things up, we use the `nat` table, which only queues
the first packet of each connection, instead of every single packet.
While this removes the ability to stop already-opened connections,
it massively reduces CPU load.

## DNS lookups

It is ***HIGHLY*** recommended to install `nscd` (the
name-service-cache-daemon) to avoid massive slowdowns due to DNS
resolving.

The software does not attempt to exclude DNS resolves from filtering.
Please write appropriate rules, i.e. write a rule allowing requests to
your DNS server **before** you write any rule matching hostnames.

### DNS reverse / forward lookup behaviour

When trying to determine the hostname belonging to an IP, the firewall
will always forward-resolve the given hostname to check if it includes
the given IP.  If this is not the case, a diagnostic will be printed and
the hostname lookup will be treated as failed.

This happens for example, if an IP address gets re-assigned to a
different customer, but the reverse lookup still points into the old
customer's domain.  Once the old customer updates their forward zone,
this firewall will no longer treat connections to the IP as belonging to
the old customer.

## Full IPv6 support

This firewall was written with full IPv6 support in mind.  No features
are exclusive to IPv4, and hostname matchers will lookup both v4 and v6
addresses using getaddrinfo().

## Writing rules

A ruleset is a directory containing text files.  The first line of each
rule file is the verdict, subsequent lines are the specification of the
rule.
Files whose name starts with a dot get ignored, this can be useful if
you want to keep your rules in version control.
Files are applied in alphabetical order.

Example file:

```
accept
direction output
destinationaddress 10.1.1.1
layer4protocol udp
destinationport 53 ; dns port!
```

Assuming your DNS resolver is 10.1.1.1, this may be a useful first rule.

Read the `DICTIONARY.md` file for valid keywords.
Valid actions (first lines) are `accept`,
`reject` and `undecided` (the latter will just pass through to the next rule).

The rule file uses boost::property\_tree's INFO format beginning with
the second line, allowing comments.  Just the first line is not allowed
to contain comments.

The `hostnamematch`, `sourcehostnamematch` and
`destinationhostnamematch` fields allow for a pattern defined according
to `fnmatch(3)`.  In its simplest form, you can write things like:

```
accept
hostnamematch *.my-domain.com
```

To allow all communication in which any host has a suffix of
`.my-domain.com`.  If you also want to allow `my-domain.com` itself, but
not `not-my-domain.com`, you can write `?(*.)my-domain.com`.

## Launching the program

The command-line to run the program is currently
./personal-firewall \<defaultVerdict\> \<Rules-Directory\>

Valid default verdicts are `accept` and `reject`.

All rules are loaded into program memory on startup.
The program does not (yet) react to changes of the folder.

## Known bugs and workarounds

If you have a buggy DNS server and run into constant 5-second resolve
times, try adding `options single-request` to `/etc/resolv.conf` (or
`/etc/resolvconf/resolv.conf.d/tail`).
