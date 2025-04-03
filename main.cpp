#include "include/kademlia.h"
#include "include/node.h"
#include "include/routing_table.h"
#include "include/holepunch.h"
#include "include/utils.h"
#include "include/dht_key.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <signal.h>

// Global flag for handling Ctrl+C
volatile sig_atomic_t running = 1;

// Signal handler for Ctrl+C
void handleSignal(int signal) {
    if (signal == SIGINT) {
        std::cout << "\nReceived Ctrl+C, shutting down..." << std::endl;
        running = 0;
    }
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, handleSignal);
    
    std::cout << "Kademlia DHT with Hole Punching" << std::endl;
    std::cout << "===============================" << std::endl;
    
    // Parse command line arguments
    uint16_t port = 4000; // Default port
    std::string bootstrapIP = ""; // Default: no bootstrap
    uint16_t bootstrapPort = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
            i++;
        } else if (strcmp(argv[i], "--bootstrap") == 0 && i + 1 < argc) {
            std::string bootstrapArg = argv[i + 1];
            std::string::size_type pos = bootstrapArg.find(':');
            
            if (pos != std::string::npos) {
                bootstrapIP = bootstrapArg.substr(0, pos);
                bootstrapPort = static_cast<uint16_t>(std::stoi(bootstrapArg.substr(pos + 1)));
            }
            
            i++;
        }
    }
    
    // Create a Kademlia node
    kademlia::Kademlia dht(port, bootstrapIP, bootstrapPort);
    
    // Start the node
    if (!dht.start()) {
        std::cerr << "Failed to start the Kademlia node" << std::endl;
        return 1;
    }
    
    // Get the local node
    kademlia::NodePtr localNode = dht.getLocalNode();
    
    std::cout << "Node started with ID: " << localNode->getID().toString() << std::endl;
    std::cout << "Listening on " << localNode->getIP() << ":" << localNode->getPort() << std::endl;
    
    if (!bootstrapIP.empty()) {
        std::cout << "Bootstrapping from " << bootstrapIP << ":" << bootstrapPort << std::endl;
    } else {
        std::cout << "Running as a bootstrap node" << std::endl;
    }
    
    // Detect NAT type
    kademlia::NATType natType = dht.getHolePuncher()->detectNATType();
    std::cout << "Detected NAT type: ";
    
    switch (natType) {
        case kademlia::NATType::OPEN:
            std::cout << "Open (No NAT)";
            break;
        case kademlia::NATType::FULL_CONE:
            std::cout << "Full Cone NAT";
            break;
        case kademlia::NATType::RESTRICTED:
            std::cout << "Restricted NAT";
            break;
        case kademlia::NATType::PORT_RESTRICTED:
            std::cout << "Port Restricted NAT";
            break;
        case kademlia::NATType::SYMMETRIC:
            std::cout << "Symmetric NAT";
            break;
        default:
            std::cout << "Unknown";
            break;
    }
    
    std::cout << std::endl;
    
    // Get public endpoint
    std::string publicIP;
    uint16_t publicPort;
    
    if (dht.getHolePuncher()->getPublicEndpoint(publicIP, publicPort)) {
        std::cout << "Public endpoint: " << publicIP << ":" << publicPort << std::endl;
    } else {
        std::cout << "Failed to get public endpoint" << std::endl;
    }
    
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  store <key> <value>  - Store a key-value pair" << std::endl;
    std::cout << "  get <key>            - Get a value by key" << std::endl;
    std::cout << "  find <nodeID>        - Find the closest nodes to a node ID" << std::endl;
    std::cout << "  ping <nodeID>        - Ping a node" << std::endl;
    std::cout << "  connect <nodeID>     - Connect to a node using hole punching" << std::endl;
    std::cout << "  info                 - Show node information" << std::endl;
    std::cout << "  quit                 - Quit the application" << std::endl;
    
    // Main loop
    std::string line;
    while (running) {
        std::cout << "> ";
        std::getline(std::cin, line);
        
        if (line.empty()) {
            continue;
        }
        
        std::istringstream iss(line);
        std::string command;
        iss >> command;
        
        if (command == "store") {
            std::string key, value;
            iss >> key >> value;
            
            if (key.empty() || value.empty()) {
                std::cout << "Usage: store <key> <value>" << std::endl;
                continue;
            }
            
            // Convert key and value to bytes
            std::vector<uint8_t> keyBytes(key.begin(), key.end());
            std::vector<uint8_t> valueBytes(value.begin(), value.end());
            
            // Create a DHTKey from the key bytes
            kademlia::DHTKey dhtKey(keyBytes);
            
            // Store the key-value pair
            dht.store(dhtKey, valueBytes, [](bool success, const std::vector<uint8_t>& value) {
                if (success) {
                    std::string valueStr(value.begin(), value.end());
                    std::cout << "Stored successfully: " << valueStr << std::endl;
                } else {
                    std::cout << "Failed to store" << std::endl;
                }
            });
        } else if (command == "get") {
            std::string key;
            iss >> key;
            
            if (key.empty()) {
                std::cout << "Usage: get <key>" << std::endl;
                continue;
            }
            
            // Convert key to bytes
            std::vector<uint8_t> keyBytes(key.begin(), key.end());
            
            // Create a DHTKey from the key bytes
            kademlia::DHTKey dhtKey(keyBytes);
            
            // Find the value
            dht.findValue(dhtKey, [](bool success, const std::vector<uint8_t>& value) {
                if (success) {
                    std::string valueStr(value.begin(), value.end());
                    std::cout << "Found value: " << valueStr << std::endl;
                } else {
                    std::cout << "Value not found" << std::endl;
                }
            });
        } else if (command == "find") {
            std::string nodeIDStr;
            iss >> nodeIDStr;
            
            if (nodeIDStr.empty()) {
                std::cout << "Usage: find <nodeID>" << std::endl;
                continue;
            }
            
            // Convert node ID to NodeID
            kademlia::NodeID nodeID(nodeIDStr);
            
            // Find the closest nodes
            dht.findNode(nodeID, [](bool success, const std::vector<kademlia::NodePtr>& nodes) {
                if (success) {
                    std::cout << "Found " << nodes.size() << " nodes:" << std::endl;
                    for (const auto& node : nodes) {
                        std::cout << "  " << node->toString() << std::endl;
                    }
                } else {
                    std::cout << "Failed to find nodes" << std::endl;
                }
            });
        } else if (command == "ping") {
            std::string nodeIDStr;
            iss >> nodeIDStr;
            
            if (nodeIDStr.empty()) {
                std::cout << "Usage: ping <nodeID>" << std::endl;
                continue;
            }
            
            // Convert node ID to NodeID
            kademlia::NodeID nodeID(nodeIDStr);
            
            // Get the node from the routing table
            kademlia::NodePtr node = dht.getRoutingTable()->getNode(nodeID);
            
            if (!node) {
                std::cout << "Node not found in routing table" << std::endl;
                continue;
            }
            
            // Ping the node
            bool success = dht.ping(node);
            
            if (success) {
                std::cout << "Ping successful" << std::endl;
            } else {
                std::cout << "Ping failed" << std::endl;
            }
        } else if (command == "connect") {
            std::string nodeIDStr;
            iss >> nodeIDStr;
            
            if (nodeIDStr.empty()) {
                std::cout << "Usage: connect <nodeID>" << std::endl;
                continue;
            }
            
            // Convert node ID to NodeID
            kademlia::NodeID nodeID(nodeIDStr);
            
            // Get the node from the routing table
            kademlia::NodePtr node = dht.getRoutingTable()->getNode(nodeID);
            
            if (!node) {
                std::cout << "Node not found in routing table" << std::endl;
                continue;
            }
            
            // Initiate hole punching
            dht.getHolePuncher()->initiateHolePunch(node, [](bool success, const std::string& ip, uint16_t port) {
                if (success) {
                    std::cout << "Connection established with " << ip << ":" << port << std::endl;
                } else {
                    std::cout << "Failed to establish connection" << std::endl;
                }
            });
        } else if (command == "info") {
            // Show node information
            std::cout << "Node ID: " << localNode->getID().toString() << std::endl;
            std::cout << "Local endpoint: " << localNode->getIP() << ":" << localNode->getPort() << std::endl;
            
            // Get public endpoint
            std::string publicIP;
            uint16_t publicPort;
            
            if (dht.getHolePuncher()->getPublicEndpoint(publicIP, publicPort)) {
                std::cout << "Public endpoint: " << publicIP << ":" << publicPort << std::endl;
            } else {
                std::cout << "Public endpoint: Unknown" << std::endl;
            }
            
            // Show NAT type
            kademlia::NATType natType = dht.getHolePuncher()->detectNATType();
            std::cout << "NAT type: ";
            
            switch (natType) {
                case kademlia::NATType::OPEN:
                    std::cout << "Open (No NAT)";
                    break;
                case kademlia::NATType::FULL_CONE:
                    std::cout << "Full Cone NAT";
                    break;
                case kademlia::NATType::RESTRICTED:
                    std::cout << "Restricted NAT";
                    break;
                case kademlia::NATType::PORT_RESTRICTED:
                    std::cout << "Port Restricted NAT";
                    break;
                case kademlia::NATType::SYMMETRIC:
                    std::cout << "Symmetric NAT";
                    break;
                default:
                    std::cout << "Unknown";
                    break;
            }
            
            std::cout << std::endl;
            
            // Show routing table information
            std::vector<kademlia::NodePtr> allNodes = dht.getRoutingTable()->getAllNodes();
            std::cout << "Routing table: " << allNodes.size() << " nodes" << std::endl;
            
            for (const auto& node : allNodes) {
                std::cout << "  " << node->toString() << std::endl;
            }
        } else if (command == "quit") {
            running = 0;
        } else {
            std::cout << "Unknown command: " << command << std::endl;
        }
    }
    
    // Stop the node
    dht.stop();
    
    std::cout << "Node stopped" << std::endl;
    
    return 0;
}
