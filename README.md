
# libratp-barebox

libratp-barebox is a small
**[C library](https://aleksander0m.github.io/libratp-barebox/)**
that allows controlling a barebox running instance through a
[RATP](https://tools.ietf.org/pdf/rfc916) link,
in the same way as the barebox 'bbremote' tool does it.

# ratp-barebox-cli

ratp-barebox-cli is a simple command line tool that implements support for the
operations defined by libratp-barebox. E.g.:

```
$ ratp-barebox-cli -t /dev/ttyUSB3 --ping
Sending PING...
PONG received...

$ ratp-barebox-cli -t /dev/ttyUSB3 --getenv global.boot.default
Sending getenv request: global.boot.default
global.boot.default: net

$ ratp-barebox-cli -t /dev/ttyUSB3 --command "ls /dev"
Sending command: ls /dev
Received response (errno Success):
cs0              eeprom0          eeprom1          full
imx-ocotp        mem              netconsole-1     null
prng             ram0             ratpconsole-1    serial0-1
serial1-1        serial2-1        zero


```

## Building

### options and dependencies

The basic dependencies to build the libratp project are **libevent 2**,
**[libratp](https://github.com/aleksander0m/libratp/)** and
**gtk-doc** (only if building from a git checkout).

On a Debian based system, the additional dependencies may be installed as
follows:
```
$ sudo apt-get install libevent-dev gtk-doc-tools
```

### configure, compile and install

```
$ NOCONFIGURE=1 ./autogen.sh     # only needed if building from git
$ ./configure --prefix=/usr
$ make
$ sudo make install
```

## License

This libratp-barebox library is licensed under the LGPLv2.1+ license, and the
ratp-barebox-cli program under the GPLv2+ license.

* Copyright © 2017 Zodiac Inflight Innovations
* Copyright © 2017 Aleksander Morgado <aleksander@aleksander.es>
