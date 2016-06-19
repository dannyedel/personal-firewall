Implements a personal firewall using the NFQUEUE mechanism.

This allows you to interactively choose which packets
you allow your machine to send and receive.

You must configure iptables to send the packets to NFQUEUE
in order to use this program.

Example using the OUTPUT chain:

```bash
### Clear all output rules
iptables -F OUTPUT
### Allow all packets to the local machine
iptables -A OUTPUT -o lo -j ACCEPT
### If you have a completely trusted network, add this
# iptables -A OUTPUT -o ethX -j ACCEPT
### Send the rest to the firewall application
iptables -A OUTPUT -j NFQUEUE
```

To speed things up, you could use the `nat` table, which will only queue
the first packet of each connection, instead of every single packet.
While this will remove the ability to stop already-opened connections,
it will massively reduce CPU load.
