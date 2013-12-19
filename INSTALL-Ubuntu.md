Ubuntu  install of Protoshares Pool Miner (PTS Miner)
====================================================

Ubuntu 12.04.3 LTS
--------------
Install the dependencies:

sudo apt-get install build-essential libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev zlib1g-dev yasm

Compile the miner

cd ptsminer/src
make -f makefile.unix.no-chrono

