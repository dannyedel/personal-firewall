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
your DNS server before you write any rule matching hostnames.

## Writing rules

A ruleset is a directory containing text files.  The first line of each
rule file is the verdict, subsequent lines are the specification of the
rule.

Example file:

```
accept
direction output
destinationaddress 10.1.1.1
layer4protocol udp
destinationport 53
```

Assuming your DNS resolver is 10.1.1.1, this may be a useful first rule.
The rules are applied in alphabetical order, and files starting with a
dot are ignored.  Read the `DICTIONARY.md` file for valid words.
Valid actions are `accept`, `reject` and `undecided` (the latter will
just pass through to the next rule).

## Launching the program

The command-line to run the program is currently
./personal-firewall \<defaultAction\> \<Rules-Directory\>

Valid default actions are `accept` and `reject`.

## Known bugs and workarounds

If you have a buggy DNS server and run into constant 5-second resolve
times, try adding `options single-request` to `/etc/resolv.conf` (or
`/etc/resolvconf/resolv.conf.d/tail`).
