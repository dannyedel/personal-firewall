Compiling personal firewall
===========================

This uses the standard CMake build system.

When in the root directory of the project (the one containing this
file), run the following commands in order:

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
```

You can then run the daemon with

```bash
sudo daemon/personal-firewalld
```


Dependencies
------------

This software directly uses the `libnetfilter-queue` library and `boost`.

Also, you'll need `cmake`, `pkg-config` and (of course) standard build
tools, such as a C++ compiler and a make program.

On a Debian or Debian-derived (i.e. Ubuntu) system, you should™ be able
to install all of these with the following command line:

```bash
apt-get -y install build-essential libboost-all-dev cmake pkg-config \
    libnetfilter-queue-dev
```
