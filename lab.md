# Capturing Packets with Scapy

This is an introduction to the Scapy package in Python for network packet capturing and generation.
To do this lab you must be using Linux (anything mainstream should work out of the box) and Python 3.6 or newer.

To begin this part of the tutorial, grab a copy of the `lab.py` Python script:


```python
from argparse import ArgumentParser, ArgumentTypeError
from sys import stderr
from code import InteractiveConsole
from readline import set_completer, parse_and_bind
from rlcompleter import Completer

from scapy.all import *

def pkt_callback(pkt):
    pass

def main(args):

    if args.filter:
        pkt_filter = ' '.join(args.filter)
    else:
        pkt_filter = None

    pkts = sniff(iface=args.iface, filter=pkt_filter, count=args.count, prn=pkt_callback)

    if args.interact:
        vars = globals()
        vars.update(locals())

        set_completer(Completer(vars).complete)
        parse_and_bind("tab: complete")

        InteractiveConsole(vars).interact()

if __name__ == '__main__':

    def count_type(count):
        count = int(count)

        if count == 0:
            print(f'{__file__}: ignoring packet count argument', file=stderr)
        elif count < 0:
            raise ArgumentTypeError('COUNT must be a positive integer')

        return count

    parser = ArgumentParser()

    parser.add_argument('iface', help='name of network interface to capture packets from')
    parser.add_argument('-c', '--count', type=count_type, default=0)
    parser.add_argument('-f', '--filter', nargs='*')
    parser.add_argument('-i', '--interact', action='store_true')

    args = parser.parse_args()

    main(args)
```

The script must be run as the *root* user (ideally using `sudo`) to allow Scapy to capture packets from the system's network interfaces.
Additionally, if you try to run the script without any additional arguments, you will receive the following error:

```bash
usage: arp_scan.py [-h] [-c COUNT] [-f [FILTER [FILTER ...]]] [-i] iface
arp_scan.py: error: the following arguments are required: iface
```

## Network Interface Selection

As shown in the second line of the error message above, the script needs a positional argument called *iface* which is the name of the network interface that you want to capture packets from.
The flags enclosed in square-brackets shows that the script also accepts some optional arguments that will be covered in due course.

To obtain a list of installed network interfaces, execute the following command:

```bash
$ ip link show
```

Upon running the command, you should receive output similar to:

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether de:ad:be:ef:ca:fe brd ff:ff:ff:ff:ff:ff
```

Notice the line containing `link/ether` which means Ethernet (IEEE 802.3) framing is used as the encapsulation type in the link layer.

Importantly, this means that applications performing packet sniffing on this interface will be presented with Ethernet frames by the Linux kernel.

If you have a WiFi card connected to your system that has been placed into monitor mode, then you will see `link/ieee802.11/radiotap` instead where IEEE 802.11 frames will be presented instead.

If you are unsure about what interface to use, then pick the one connected to your default gateway.
You can find your default gateway using the following command:

```bash
ip route show default
```

## Packet callback function

Most of the Python script simply parses all of the user-provided arguments from the command line and configures Scapy accordingly.

The first function defined in the script called `pkt_callback()` is (as the name suggests) a callback function.

### Callback functions 101

Callback functions are, by themselves, not particularly special.
For example, consider the following:

```python
def add(a, b):
    return a + b
```

In this example, `add()` simply returns whatever the + operator does on *a* and *b* when it is called.

Callback functions become interesting when we consider an additional function like the following:

```python
def do_something(func, x, y):
    return func(x, y)
```

The first argument *func* of `do_something()` **calls** whatever the value of *func* is.
Therefore, in order to use `do_something()` we need to something **callable** in addition to the objects *x* and *y*.

For example, what happens if we pass `add()` as the *func* argument to `do_something()`?

```python
>>> do_something(add, 3, 4)
7
>>>
```

In this example, we passed `add()` as a callback function to `do_something()` (the caller function)!

Importantly, callback functions *must* be usable in the way that caller function uses it, for example if we define:

```python
def bad_func(a, b, c):
    return a + b + c
```

And use it as the callback function for `do_something()` then Python raises an exception:

```python
>>> do_something(bad_func, 3, 4)
TypeError: bad_func() missing 1 required positional argument: 'c'
>>>
```

### The `pkt_callback()` function

The `pkt_callback()` function is the most important part of the script in this exercise; this function is called by the `sniff()` function whenever it captures a packet.
As you can see, the function simply contains the `pass` keyword which results in the function doing nothing.

Change the `pkt_callback()` function to the following:

```python
def pkt_callback(pkt):
    print('Captured a packet!')
```

Save your changes.
We will test the script by sending some ICMP *echo request* or ping messages to Google; to ensure that the `sniff()` function only processes IPv4 ICMP datagrams, we will use a filter.
The `-f FILTER` argument is used to pass tcpdump-like filters to Scapy; to filter out everything except IPv4 ICMP datagrams the filter `ip and icmp` should be used:

```bash
sudo python3 lab.py iface -f ip and icmp
```

While the script is running, open another terminal session and use the ping command to send the *echo request* datagrams:

```bash
ping -4 google.com
```

Upon running this command, the terminal within which the script is executing should begin printing messages:

```
Captured a packet!
Captured a packet!
Captured a packet!
Captured a packet!
Captured a packet!
Captured a packet!
Captured a packet!
Captured a packet!
```

We have successfully captured our first packets with Scapy!
Use CTRL+C to stop the ping command and script from executing.

```
PING google.com (216.58.212.238) 56(84) bytes of data.
64 bytes from ams16s22-in-f14.1e100.net (216.58.212.238): icmp_seq=1 ttl=118 time=25.8 ms
64 bytes from ams16s22-in-f14.1e100.net (216.58.212.238): icmp_seq=2 ttl=118 time=28.1 ms
64 bytes from ams16s22-in-f14.1e100.net (216.58.212.238): icmp_seq=3 ttl=118 time=28.2 ms
64 bytes from ams16s22-in-f14.1e100.net (216.58.212.238): icmp_seq=4 ttl=118 time=30.6 ms
^C
--- google.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 25.823/28.180/30.570/1.679 ms
```

Notice that the message has been twice for each *echo request* to account for the corresponding *echo reply* that Google send in response.

What if we only want to capture the first 4 packets which match our filter?
To do this we can pass the `-c COUNT` argument, where COUNT is the number of packets that should be captured.
Repeat the previous exercise using `-c 4` to try it out.

```bash
sudo python3 lab.py iface -f ip and icmp -c 4
```

Printing the same message for each packet gets old quickly, let's change the script so it gives us more information about each packet.
Begin by undoing your changes to the script and saving it (replace the print statement in the `pkt_callback()` function with the `pass` keyword).

### Layers in Scapy

<!--- SCAPY LAYERS EXPLANATION --->

Additionally, use the `-i` flag to enter *interactive mode* which will allow us to dissect the packet interactively:

```bash
sudo python3 lab.py iface -f ip and icmp -c 1 -i
```

Upon capturing the packet, your terminal should look something like this:

```
Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>>
```

Notice in our script that we assign the output produced by the `sniff()` function to an object called `pkts`.

```python
pkts = sniff(iface=args.iface, filter=pkt_filter, count=args.count, prn=pkt_callback)
```

We can access this object within the interactive console; do this by typing `pkts` and hitting return.

```python
>>> pkts
<Sniffed: TCP:0 UDP:0 ICMP:1 Other:0>
>>>
```

Using the `type()` built-in, we can see that `pkts` is an object of type `scapy.plist.PacketList` which is essentially a Python `list()` object with some extras bolted on by Scapy.
For exampe, we can determine the *length* of the `pkts` object, using the `len()` built-in, which will give us the number of packets that were captured by `sniff()`:

```python
>>> len(pkts)
1
>>>
```

Recall that we limited the capture to just a single packet so a length of 1 is expected.
As mentioned previously, this object behaves similarly to a normal `list()` in Python so we can use slicer notation to access it's member objects:

```python
>>> pkts[0]
<Ether  dst=de:ad:be:ef:ca:fe src=de:ad:be:ef:ca:fe type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=84 id=54026 flags=DF frag=0 ttl=64 proto=icmp chksum=0xf1aa src=192.168.16.34 dst=216.58.204.238 |<ICMP  type=echo-request code=0 chksum=0xc7f1 id=0x6 seq=0x1 |<Raw  load='~\x97*`\x00\x00\x00\x00\xba<\x0e\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567' |>>>>
>>>
```

This output is Scapy's compressed human-readable view of the entire packet/frame beginning at layer 2.
Repeat the same line as before, except save the output to a variable called `my_pkt`.

```python
>>> my_pkt = pkts[0]
```
