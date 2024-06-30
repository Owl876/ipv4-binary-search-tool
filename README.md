# IP Address Binary Search Tool

This project provides a tool for searching files containing a specified IPv4 address in both standard and binary formats. The tool leverages dynamic libraries (plugins) to extend its functionality and is designed for flexibility and ease of use.

## Features

- IPv4 Address Search: Search for files containing a specified IPv4 address in both standard and binary formats.
- Plugin Support: Extend functionality with custom plugins.
- Command-line Interface: Easy to use with various command-line options.

## Installation

To build the project, simply use the provided Makefile. Run the following command in the project directory:

```
make
```

This will compile the source code and create the necessary executable and shared library.

To clean the build files, run:

```
make clean
```

## Usage

The tool is run from the command line and supports various options:

```
./lab12dadN3251 --ipv4-addr-bin <IPv4_ADDRESS> <DIRECTORY>
```
## Options

- --ipv4-addr-bin <IPv4_ADDRESS>: Specifies the IPv4 address to search for in binary form.
- DIRECTORY: The directory to search within.

## Example

To search for files containing the IPv4 address 192.168.8.1 in the /home/user/downloads directory:

```
./lab12dadN3251 --ipv4-addr-bin 192.168.8.1 /home/user/downloads
```

## Plugin Development

To create a new plugin, implement the required functions defined in plugin_api.h:

- plugin_get_info(struct plugin_info *ppi): Provides information about the plugin.
- plugin_process_file(const char *fname, struct option in_opts[], size_t in_opts_len): Processes a file according to the plugin's functionality.
