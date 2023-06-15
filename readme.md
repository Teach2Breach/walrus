# Walrus IP Whois Lookup Tool

## Description

Walrus is a command line tool written in Rust for performing bulk IP whois lookups. The tool takes a file containing IP addresses or CIDR ranges as input and writes the lookup results to a CSV file. The tool also supports a "quick" mode where it only looks up the first IP in a CIDR range.

Walrus is fast and efficient, thanks to the async nature of the Rust programming language. It can be easily installed and used on a variety of operating systems, including Windows, Linux, and MacOS.

## Features

- Support for bulk IP lookups from a file
- Support for CIDR ranges
- Quick mode for faster lookups on CIDR ranges
- Progress bar for real-time update on lookups
- Writes output to CSV file

## Usage

You can run Walrus from the command line using the following options:

```bashag-0-1h2vq4a6cag-1-1h2vq4a6c
walrus -f [file] -q [quick lookup] -h [help] -o [output file]
```

- `-f`, `--file`: The input file containing a list of IP addresses or CIDR ranges.
- `-q`, `--quick`: Perform a 'quick' whois lookup for CIDR ranges. Only the first IP in the range will be looked up.
- `-h`, `--help`: Display help information.
- `-o`, `--output`: The name of the output CSV file. The default is `whois_results.csv`.

## Installation

Ensure that you have Rust and Cargo installed on your system. If you don't, you can install it from the [official Rust website](https://www.rust-lang.org/tools/install).

To build the project, navigate to the project directory and run:

`cargo build --release`

The compiled binary can be found in the `target/release` directory.

## Example Usage

![image](https://github.com/Teach2Breach/walrus/assets/105792760/87e6bdb8-a7c5-4daa-9d8b-5f6ee28110f3)



