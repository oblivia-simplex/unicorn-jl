# Julia Bindings for the Unicorn Emulation Library

This package contains bindings for the [Unicorn Emulation Library](https://unicorn-engine.org). 

## Building

To build, first recursively clone this repository with 

```
$ git clone --recursive https://github.com/oblivia-simplex/unicorn-dl
```

Then compile the Unicorn library, which is provided as a submodule:
```
$ cd unicorn-dl/unicorn
$ make
```

After `unicorn/libunicorn.so` is built, the Unicorn-jl bindings can be used.

This is a work in progress, and still a bit rough around the edges.

