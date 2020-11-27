Claim IP
========

A Linux command line tool to claim an IP by responding to ARP requests for that IP on a specified network interface.

Usage
-----

The command should be invoked with 2 parameters:

```
claim-ip <iface> <ipv4-addr>
```

### Example invocation

In order to claim IP address `10.11.12.13` on interface `eth0`:

```
claim-ip eth0 10.11.12.13
```
