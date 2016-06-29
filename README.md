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
