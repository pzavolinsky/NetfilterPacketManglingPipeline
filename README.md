Netfilter-queue packet mangling pipeline
========================================

This prototype was inspired by my friend Pablo Deymonnaz's degree [thesis](http://materias.fi.uba.ar/7500/TesisDeymonnaz.pdf) on steganographic vulnerabilities of the IP protocol.

Essentially, this prototype is a libnetfilter_queue object wrapper that abstracts packet-mangling operations (such as embedding steganographic messages in IP headers) from the boilerplate code required to setup, manage and destroy a Netfilter queues.

Build
-----

Make sure you have both [libnfnetlink](http://www.netfilter.org/projects/libnfnetlink/downloads.html) and [libnetfilter_queue](http://www.netfilter.org/projects/libnetfilter_queue/downloads.html).

For Debian and friends, this might do the trick for you:
```shell
sudo apt-get install libnetfilter-queue-dev
```

Otherwise, building from source is always an option (first `libnfnetlink`, then `libnetfilter_queue`).

When both dependencies are installed, you can build the prototype with:
```shell
make
```

The output should be:
```shell
$ make
g++ -g -Wall -Wno-long-long -c src/main.cpp -o src/main.o
g++ -g -Wall -Wno-long-long -c src/NetFilterQueue.cpp -o src/NetFilterQueue.o
g++ -g -Wall -Wno-long-long -c src/PacketHandlers.cpp -o src/PacketHandlers.o
mkdir -p bin
g++ -g -Wall -pedantic src/main.o src/NetFilterQueue.o src/PacketHandlers.o -o bin/main -lnetfilter_queue

[DONE] sudo bin/main
```

Running the prototype
---------------------

To see this in action you will need two terminal windows.

In the first terminal run:
```shell
sudo bin/main
```
This will add an iptables rule for ICMP packets and wait for packets to process:
```shell
[NF LIB]   created
[NF QUEUE] created
[IPTABLES] iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
    === Hit CTRL+C or kill -INT to stop ===
```

In the second terminal run:
```shell
ping google.com
```
This will generate ICMP packets that will be processed by the first terminal:
```shell
[NF LIB]   created
[NF QUEUE] created
[IPTABLES] iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
    === Hit CTRL+C or kill -INT to stop ===
[BEFORE] hw_protocol=0x0800 hook=3 id=1 outdev=2 payload_len=84 
[BEFORE]     ip { version=4, ihl=5, tos=0, len=84, id=8249, flags=2 frag_off=0, ttl=64, protocol=1, check=50368 } 
[AFTER]  hw_protocol=0x0800 hook=3 id=1 outdev=2 payload_len=84 
[AFTER]      ip { version=4, ihl=5, tos=0, len=84, id=8249, flags=2 frag_off=0, ttl=42, protocol=1, check=56000 } 
...
^C[IPTABLES] iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0
[NF QUEUE] destroyed
[NF LIB]   destroyed
```

When you are done with the prototype hit `CTRL+C` of `kill -INT <pid>` to stop.
