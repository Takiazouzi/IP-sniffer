# IP Sniffer

A simple Java-based network packet analyzer built with Pcap4J for learning Object-Oriented Programming (OOP) concepts and basic packet analysis.

## Features

- Analyze PCAP files
- Display source/destination IPs and ports
- Detect TCP and UDP packets
- Show TCP flags and packet size
- Basic protocol detection (HTTP, HTTPS, DNS, SSH, etc.)
- Traffic statistics
- Packet filtering (TCP / UDP / All)

## Technologies

- Java 17
- Maven
- Pcap4J

## Project Structure

```text
src/main/java/sniffer/
├── Main.java
├── engine/
├── model/
├── parser/
├── analyzer/
├── filter/
├── stats/
└── utils/
```

## Build

```bash
mvn clean package
```

## Run

From project root:

```bash
java -cp target/classes sniffer.Main
```

Or with Maven:

```bash
mvn exec:java -Dexec.mainClass="sniffer.Main"
```

## Example Output

```text
[Packet #1] TCP | SRC: 192.168.1.100:52344 DST: 142.250.185.14:443 FLAGS: SYN APP: HTTPS SIZE: 74 bytes

[Packet #2] UDP | SRC: 192.168.1.100:54321 DST: 8.8.8.8:53 APP: DNS SIZE: 78 bytes
```

## OOP Concepts

- Interfaces
- Inheritance
- Polymorphism
- Encapsulation

## Dependencies

- Pcap4J
- SLF4J
