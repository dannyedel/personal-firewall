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
