# Fluent Bit Plugin secured counter

The following repository shows the plugin for enumeration audit/log records in a more secure way.

>  Fluent Bit API development/usage is out of the scope of this article.

## Requirements

- [Fluent Bit](https://fluentbit.io) Source code, version >= 1.2
- C compiler: GCC or Clang
- CMake3

## Introduction
This plugin is intended for use of enumerating the records in such a way that if some records are lost, i.e. the
enumeration is not in sequence it should be more easy to discover.
This can be useful when records are of a more important item and reflects usage of something that are audited.

In the following steps we will build the plugin provided called __filter_securedcnt__. As a first step get into the _build/_ directory:

## Getting Started

In the following steps we will build the plugin provided called __filter_securedcnt__. As a first step get into the _build/_ directory:

```bash
$ cd build/
```

Now we will provide CMake (our build system) two important variables:

- FLB\_SOURCE: absolute path to source code of Fluent Bit.
- PLUGIN\_NAME: _directory_ name of the project that we aim to build. Note that any plugin name must have it proper prefix as the example mentioned above.

Assuming that Fluent Bit source code is located at /tmp/fluent-bit and we will build _filter\_securedcnt_, we will run CMake with the following options:

```bash
$ cmake -DFLB_SOURCE=/tmp/fluent-bit -DPLUGIN_NAME=filter_securedcnt ../
```

then type 'make' to build the plugin:

```
$ make
Scanning dependencies of target flb-filter_securedcnt
[ 50%] Building C object filter_securedcnt/CMakeFiles/flb-filter_securedcnt.dir/filter_securedcnt.c.o
[100%] Linking C shared library ../flb-filter_securedcnt.so
[100%] Built target flb-filter_securedcnt

```

If you query the content of the current directory you will find the new shared library created:

```
$ ls -l *.so
-rwxr-xr-x 1 root root 28928 Aug 12 20:12 flb-filter_securedcnt.so
```

that __.so__ file is our dynamic plugin that now can be loaded from Fluent Bit through the [plugins configuration](https://github.com/fluent/fluent-bit/blob/master/conf/plugins.conf) file.


## Usage
This program is designed to enumerate audit/log records in such a way that if a "gap" in the ordering is noticed 
it should be discovered. In order to enumerate the records, the config file for the plugin __securedcnt__ contains these values:
```
[FILTER]
    Name                securedcnt
    Match               *
#   securedcnt_file is used to store the secured counter value
    securedcnt_file            securedcnt_file.ccc
#   this file contains the key used to protect the securedcnt_file
#   it should be removed after startup.
    securedcnt_key_file        securedcnt_key_file.bin
#   this file contains a seed value when generating the new encryption key.
    securedcnt_seed            myseedvalue
#   this is the field that should be added as a secured counter value in the records
    securedcnt_field           securedcnt_field
```
When the program runs it adds a field name by the __securedcnt_field__ to the records.
A sample of this could be this configuration used:
```
[SERVICE]
    Flush           1
    Daemon          off
    Log_Level       debug

[INPUT]
    Name         cpu
    alias        cpu_data
    Interval_Sec 1
    Interval_NSec 10

[FILTER]
    Name                securedcnt
    Match               *
#   securedcnt_file is used to store the coc value
    securedcnt_file            securedcnt_file.ccc
#   this file contains the key used to protect the securedcnt_file
#   it should be removed after startup.
    securedcnt_key_file        securedcnt_key_file.bin
#   this file contains a seed value when generating the new encryption key.
    securedcnt_seed            myseedvalue
#   this is the field that should be added as a secured counter value in the records
    securedcnt_field           securedcnt_field

[OUTPUT]
    Name stdout
    Match *
```
A sample test of the plugin would look like this :
```
[0] cpu.0: [1565642298.000177130, {"cpu_p"=>39.000000, "user_p"=>6.000000, "system_p"=>33.000000, "cpu0.p_cpu"=>39.000000, "cpu0.p_user"=>6.000000, "cpu0.p_system"=>33.000000, "securedcnt_field"=>0}]
[0] cpu.0: [1565642299.000713632, {"cpu_p"=>71.999999, "user_p"=>13.000000, "system_p"=>58.999999, "cpu0.p_cpu"=>71.999999, "cpu0.p_user"=>13.000000, "cpu0.p_system"=>58.999999, "securedcnt_field"=>1}]
```
For security reasons, the securedcnt_key_file should be removed, when fluent-bit is started. For a restart of fluent-bit,
the file should be replaced again.
If the file containing the key value or the securedcnt_file is removed, the enumeration will start at 0 again, indicating something happened.

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).
