Debian install of Protoshares Pool Miner (PTS Miner)
====================================================

Debian Wheezy
-------------
Install the dependencies:

apt-get install build-essential zlib1g-dev libboost-dev

Compile the miner

cd ptsminer/src
make -f makefile.unix

Debian Squeeze
--------------
Install the dependencies:

apt-get install build-essential libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev zlib1g-dev

Compile the miner

cd ptsminer/src
make -f makefile.unix.no-chrono

