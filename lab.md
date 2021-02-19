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

        if not count:
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

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether de:ad:be:ef:ca:fe brd ff:ff:ff:ff:ff:ff
```

Notice the line containing `link/ether` for the *enp0s3* interface which means Ethernet (IEEE 802.3) framing is used as the encapsulation type in the link layer for the interface.
Importantly, this means that applications performing packet sniffing on this interface will be presented with Ethernet frames by the Linux kernel.
If you have a WiFi card that has been placed into monitor mode on your system, then you will see `link/ieee802.11/radiotap` instead as IEEE 802.11 frames will be presented to any sniffing applications.

If you are unsure about what interface to use, then pick the one connected to your default gateway.
You can find your default gateway by executing the following command:

```bash
ip route show default
```

## Packet callback function

Most of the script simply parses all of the user-provided arguments from the command line and configures Scapy accordingly.
The top `pkt_callback()` function is (as the name suggests) a callback function.

### Callback functions 101

Callback functions are, by themselves, not particularly special.
For example, consider the following:

```python
def add(a, b):
    return a + b
```

The function `add()` simply returns whatever the + operator does on *a* and *b* whenever it is called.
We can use `add()` as a **callback function** if we consider an addition function like the following:

```python
def do_something(func, x, y):
    return func(x, y)
```

The first argument of `do_something()` **calls** whatever the value of *func* is.
Therefore, in order to use `do_something()` we need to pass something **callable** in addition to the objects *x* and *y*.

For example, what would happen if we pass `add()` as the *func* argument to `do_something()`?

```python
>>> do_something(add, 3, 4)
7
>>>
```

In this example, we passed `add()` as a **callback function** to `do_something()` (the **caller function**)!
Notice the lack of parentheses around the `add()` function when it is passed to `do_something()` otherwise we would be passing whatever `add()` returns instead of the function itself.

Importantly, callback functions **must** be usable in the way that caller function uses it, for example if we define:

```python
def bad_func(a, b, c):
    return a + b + c
```

And use it as the callback function for `do_something()` then Python will raise an exception:

```python
>>> do_something(bad_func, 3, 4)
TypeError: bad_func() missing 1 required positional argument: 'c'
>>>
```

### The `pkt_callback()` function

The `pkt_callback()` function is the most important part of the script in this exercise; the function is called by Scapy's `sniff()` function.
The *pkt* argument for the function is Scapy's representation of the packet that the `sniff()` function passes whenever it calls `pkt_callback()`.
As you can see in the script, the function simply contains the `pass` keyword which results in the function doing nothing with the packet.

Begin by changing the `pkt_callback()` function of the script to the following:

```python
def pkt_callback(pkt):
    print('Captured a packet!')
```

Save your changes.
We will test the script by sending some ICMP *echo request* (ping) datagrams to Google.

To ensure that `pkt_callback()` is only called for our desired type of packet, we will make use of the script's `-f FILTER` argument where `FILTER` is any valid [Berkely Packet Filter](https://biot.com/capstats/bpf.html) string.
To limit our sniffing to IPv4 ICMP packets, we will use `ip and icmp` as our BPF:

```bash
sudo python3 lab.py iface -f ip and icmp
```

While the script is running, open another terminal session and use the `ping` command:

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
Use **CTRL+C** to stop the `ping` command and script from executing.

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

Notice that the message has been twice for each *echo request* sent to account for the corresponding *echo reply* that Google sent back in response.

What if we only want to capture the first 4 packets which match our filter?
To do this we can pass the `-c COUNT` argument, where `COUNT` is the number of packets that should be captured.
Repeat the previous exercise using `-c 4` to try it out.

```bash
sudo python3 lab.py iface -f ip and icmp -c 4
```

Printing the same message for each packet gets old quickly, let's change the script so it gives us more information about each packet.
Begin by undoing your changes to the script and saving it:

```python
def pkt_callback(pkt):
    pass
```

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

```
>>> pkts[0]
<Ether  dst=de:ad:be:ef:ca:fe src=de:ad:be:ef:ca:fe type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=84 id=54026 flags=DF frag=0 ttl=64 proto=icmp chksum=0xf1aa src=192.168.16.34 dst=216.58.204.238 |<ICMP  type=echo-request code=0 chksum=0xc7f1 id=0x6 seq=0x1 |<Raw  load='~\x97*`\x00\x00\x00\x00\xba<\x0e\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567' |>>>>
>>>
```

This output is Scapy's compressed human-readable view of the entire packet/frame beginning at layer 2.
Repeat the same line as before, except save the output to a variable called `my_pkt`.

```python
>>> my_pkt = pkts[0]
```

We can call the `summary()` method on `my_pkt` to get a more concise overview of the packet.

```python
>>> my_pkt.summary()
'Ether / IP / ICMP 192.168.16.34 > 142.250.178.14 echo-request 0 / Raw'
>>>
```

As we should already know, encapsulation is widely used within computer networks whereby lower layer protocols encapsulate higher layer protocols and payloads.

Scapy lets us access different layers of a packet using slicer notation.
We can determine the number of accessible layers within a packet by calling the `layers()` method on `my_pkt` along with `len()`.

```python
>>> len(my_pkt.layers())
4
>>>
```

Next we'll print out the name of each layer using a for loop and the `name()` method.

```python
>>> for index in range(4):
...     print(my_pkt[index].name)
... 
Ethernet
IP
ICMP
Raw
>>>
```

Recall that if our network interface says `link/ether` then the Linux kernel will present our application with network traffic in the form of Ethernet frames.
We can also see the higher layer IP and ICMP protocols that comprise the payload of the frame.
The Raw layer isn't an actual layer but is instead used as a catchall for anything that Scapy couldn't parse, for exaaple, fragments of data in a larger stream.

By taking a closer look at the `layers()` method we can see that it actually returns a list of Scapy classes.

```
>>> my_pkt.layers()
[<class 'scapy.layers.l2.Ether'>, <class 'scapy.layers.inet.IP'>, <class 'scapy.layers.inet.ICMP'>, <class 'scapy.packet.Raw'>]
>>>
```

Because the script contains the line:

```python
>>> from scapy.all import *
```

we can access these classes directly without specifying their namespaces.
Furthermore, Scapy lets us use them as a more convenient way of accessing and slicing the different layers of a packet.
For example, we can access the ICMP layer of the packet by typing:

```
>>> my_pkt[ICMP]
<ICMP  type=echo-request code=0 chksum=0x31e7 id=0x2 seq=0x1 |<Raw  load='#\xa6/`\x00\x00\x00\x00\xac<\x08\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567' |>>
>>>
```

If we look at the header structure of an ICMP *echo-request*, we can see that it contains several fields.

![ICMP header](https://www.frozentux.net/iptables-tutorial/chunkyhtml/images/icmp-echo-headers.jpg)

We can use the `show()` method to see each the values of each field.

```
>>> my_pkt[ICMP].show()
###[ ICMP ]### 
  type      = echo-request
  code      = 0
  chksum    = 0x31e7
  id        = 0x2
  seq       = 0x1
###[ Raw ]### 
     load      = '#\xa6/`\x00\x00\x00\x00\xac<\x08\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
>>>
```

Furthermore, Scapy exposes the values of fields as properties of the object.
For example, we can access the Sequence Number in the ICMP layer of `my_pkt` using:

```python
>>> my_pkt[ICMP].seq
1
>>>
```

We can also see every field that is accessible using the `fields` property:

```python
>>> my_pkt[ICMP].fields
{'type': 8, 'code': 0, 'chksum': 12775, 'id': 2, 'seq': 1, 'ts_ori': None, 'ts_rx': None, 'ts_tx': None, 'gw': None, 'ptr': None, 'reserved': None, 'length': None, 'addr_mask': None, 'nexthopmtu': None, 'unused': None}
>>>
```

## Challenge

Using what you have covered, modify the script so that for each IPv4 TCP packet received the following is printed:

1. Source and Destination IP addresses
2. Packet TTL
3. Source and Destination TCP port numbers
4. TCP flags

A line similar to the following should be printed for each packet:

```
192.168.16.34:43948 -> 192.168.16.100:8006 TTL: 64, Flags: S
```
