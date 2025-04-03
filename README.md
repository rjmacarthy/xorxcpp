# Kademlia DHT with Hole Punching

This project implements a Kademlia Distributed Hash Table (DHT) with NAT traversal capabilities using hole punching techniques. It allows nodes behind NATs to establish direct connections with each other.

## Features

- **Kademlia DHT**: Implementation of the Kademlia distributed hash table algorithm
- **NAT Traversal**: Hole punching techniques for NAT traversal
- **Key-Value Storage**: Distributed storage of key-value pairs
- **Node Discovery**: Automatic discovery of nodes in the network
- **Routing**: Efficient routing based on XOR metric

## Requirements

- C++17 compatible compiler
- CMake 3.10 or higher
- OpenSSL library
- POSIX-compatible system (Linux, macOS)

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

### Running as a Bootstrap Node

```bash
./kademlia_dht --port 4000
```

### Running as a Regular Node

```bash
./kademlia_dht --port 4001 --bootstrap 127.0.0.1:4000
```

### Commands

Once the node is running, you can use the following commands:

- `store <key> <value>`: Store a key-value pair in the DHT
- `get <key>`: Retrieve a value by key from the DHT
- `find <nodeID>`: Find the closest nodes to a given node ID
- `ping <nodeID>`: Ping a node
- `connect <nodeID>`: Connect to a node using hole punching
- `info`: Display information about the local node
- `quit`: Exit the application

## Architecture

### Components

- **Node**: Represents a node in the Kademlia network
- **RoutingTable**: Manages the k-buckets and node routing
- **HolePuncher**: Implements NAT traversal techniques
- **Kademlia**: Main DHT implementation

### NAT Traversal

The implementation supports different types of NATs:

- Open (No NAT)
- Full Cone NAT
- Restricted NAT
- Port Restricted NAT
- Symmetric NAT

It uses a combination of techniques to establish connections:

1. Direct connection attempt
2. STUN-assisted connection
3. TCP hole punching

## Implementation Details

### Kademlia DHT

- 160-bit node IDs
- XOR metric for distance calculation
- k-buckets for routing table
- Parallel lookups with alpha = 3
- Key republishing and expiration

### Hole Punching

- NAT type detection
- Public endpoint discovery
- UDP hole punching
- TCP hole punching
- STUN server integration

## Limitations

- Simplified implementation for educational purposes
- Limited support for symmetric NATs
- No encryption or authentication
- No persistence of stored data

## Future Improvements

- Add encryption and authentication
- Implement persistent storage
- Improve NAT traversal for symmetric NATs
- Add support for IPv6
- Implement DHT security features

## License

This project is licensed under the MIT License - see the LICENSE file for details.