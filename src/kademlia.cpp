#include "../include/kademlia.h"
#include "../include/utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <algorithm>
#include <random>

namespace kademlia {

Kademlia::Kademlia(uint16_t port, const std::string& bootstrapIP, uint16_t bootstrapPort)
    : running_(false) {
    
    // Create a random node ID for the local node
    NodeID localID = NodeID::random();
    
    // Get the local IP address (simplified)
    std::string localIP = "127.0.0.1"; // In a real implementation, we would get the actual local IP
    
    // Create the local node
    localNode_ = std::make_shared<Node>(localID, localIP, port);
    
    // Create the routing table
    routingTable_ = std::make_shared<RoutingTable>(localID);
    
    // Create the hole puncher
    holePuncher_ = std::make_shared<HolePuncher>();
}

Kademlia::~Kademlia() {
    stop();
}

bool Kademlia::start() {
    if (running_) {
        return false;
    }
    
    running_ = true;
    
    // Start the message processing thread
    messageThread_ = std::thread(&Kademlia::processMessages, this);
    
    // Start the maintenance thread
    maintenanceThread_ = std::thread([this]() {
        while (running_) {
            // Refresh buckets
            refreshBuckets();
            
            // Republish keys
            republishKeys();
            
            // Expire old keys
            expireKeys();
            
            // Sleep for a while
            std::this_thread::sleep_for(std::chrono::minutes(10));
        }
    });
    
    // Bootstrap the node if bootstrap IP and port are provided
    if (!localNode_->getIP().empty() && localNode_->getPort() != 0) {
        bootstrap(localNode_->getIP(), localNode_->getPort());
    }
    
    return true;
}

void Kademlia::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Wait for threads to finish
    if (messageThread_.joinable()) {
        messageThread_.join();
    }
    
    if (maintenanceThread_.joinable()) {
        maintenanceThread_.join();
    }
}

void Kademlia::store(const DHTKey& key, const std::vector<uint8_t>& value, DHTCallback callback) {
    // Hash the key to get a NodeID
    NodeID targetID = utils::hashKey(key.getData());
    
    // Find the k closest nodes to the key
    nodeLookup(targetID, [this, key, value, callback](bool success, const std::vector<NodePtr>& nodes) {
        if (!success || nodes.empty()) {
            if (callback) {
                callback(false, std::vector<uint8_t>());
            }
            return;
        }
        
        // Store the key-value pair locally
        {
            std::lock_guard<std::mutex> lock(storageMutex_);
            storage_[key.toString()] = value;
            storageTimestamps_[key.toString()] = utils::getCurrentTimeMillis();
        }
        
        // Store the key-value pair on the k closest nodes
        bool allSuccess = true;
        
        for (const auto& node : nodes) {
            // Create a STORE RPC message
            RPCMessage message;
            message.type = RPCType::STORE;
            message.sender = localNode_->getID();
            message.receiver = node->getID();
            message.senderIP = localNode_->getIP();
            message.senderPort = localNode_->getPort();
            
            // Add the key and value to the payload
            const auto& keyData = key.getData();
            message.payload.insert(message.payload.end(), keyData.begin(), keyData.end());
            message.payload.insert(message.payload.end(), value.begin(), value.end());
            
            // Send the message
            if (!sendRPC(message)) {
                allSuccess = false;
            }
        }
        
        if (callback) {
            callback(allSuccess, value);
        }
    });
}
void Kademlia::findValue(const DHTKey& key, DHTCallback callback) {
    // Check if we have the value locally
    {
        std::string keyStr = key.toString();
        std::lock_guard<std::mutex> lock(storageMutex_);
        auto it = storage_.find(keyStr);
        if (it != storage_.end()) {
            if (callback) {
                callback(true, it->second);
            }
            return;
        }
    }
    
    // If not, perform a value lookup
    valueLookup(key, callback);
}

void Kademlia::findNode(const NodeID& id, NodeLookupCallback callback) {
    nodeLookup(id, callback);
}

bool Kademlia::ping(const NodePtr& node) {
    // Create a PING RPC message
    RPCMessage message;
    message.type = RPCType::PING;
    message.sender = localNode_->getID();
    message.receiver = node->getID();
    message.senderIP = localNode_->getIP();
    message.senderPort = localNode_->getPort();
    
    // Send the message
    return sendRPC(message);
}

NodePtr Kademlia::getLocalNode() const {
    return localNode_;
}

std::shared_ptr<RoutingTable> Kademlia::getRoutingTable() const {
    return routingTable_;
}

std::shared_ptr<HolePuncher> Kademlia::getHolePuncher() const {
    return holePuncher_;
}

void Kademlia::handleRPC(const RPCMessage& message) {
    // Update the sender in the routing table
    NodePtr sender = std::make_shared<Node>(message.sender, message.senderIP, message.senderPort);
    routingTable_->addNode(sender);
    
    // Handle the message based on its type
    switch (message.type) {
        case RPCType::PING: {
            // Respond with a PING message
            RPCMessage response;
            response.type = RPCType::PING;
            response.sender = localNode_->getID();
            response.receiver = message.sender;
            response.senderIP = localNode_->getIP();
            response.senderPort = localNode_->getPort();
            
            sendRPC(response);
            break;
        }
        
        case RPCType::STORE: {
            // Extract the key and value from the payload
            // In a real implementation, we would need to know the key and value sizes
            // For simplicity, we'll assume the key is the first half and the value is the second half
            size_t halfSize = message.payload.size() / 2;
            std::vector<uint8_t> keyData(message.payload.begin(), message.payload.begin() + halfSize);
            std::vector<uint8_t> value(message.payload.begin() + halfSize, message.payload.end());
            
            // Create a DHTKey from the key data
            DHTKey key(keyData);
            
            // Store the key-value pair
            std::lock_guard<std::mutex> lock(storageMutex_);
            storage_[key.toString()] = value;
            storageTimestamps_[key.toString()] = utils::getCurrentTimeMillis();
            break;
        }
        
        case RPCType::FIND_NODE: {
            // Extract the target ID from the payload
            NodeID targetID(std::string(message.payload.begin(), message.payload.end()));
            
            // Find the k closest nodes to the target ID
            std::vector<NodePtr> closestNodes = routingTable_->findClosestNodes(targetID);
            
            // Create a response message
            RPCMessage response;
            response.type = RPCType::FIND_NODE;
            response.sender = localNode_->getID();
            response.receiver = message.sender;
            response.senderIP = localNode_->getIP();
            response.senderPort = localNode_->getPort();
            
            // Add the closest nodes to the payload
            for (const auto& node : closestNodes) {
                // Add the node ID, IP, and port to the payload
                std::string nodeStr = node->getID().toString() + ":" + node->getIP() + ":" + std::to_string(node->getPort());
                response.payload.insert(response.payload.end(), nodeStr.begin(), nodeStr.end());
                response.payload.push_back('\n'); // Use a newline as a separator
            }
            
            sendRPC(response);
            break;
        }
        
        case RPCType::FIND_VALUE: {
            // Extract the key from the payload
            std::vector<uint8_t> keyData(message.payload.begin(), message.payload.end());
            DHTKey key(keyData);
            
            // Check if we have the value
            std::lock_guard<std::mutex> lock(storageMutex_);
            auto it = storage_.find(key.toString());
            
            if (it != storage_.end()) {
                // We have the value, create a response with the value
                RPCMessage response;
                response.type = RPCType::FIND_VALUE;
                response.sender = localNode_->getID();
                response.receiver = message.sender;
                response.senderIP = localNode_->getIP();
                response.senderPort = localNode_->getPort();
                
                // Add the value to the payload
                response.payload = it->second;
                
                sendRPC(response);
            } else {
                // We don't have the value, respond with the k closest nodes
                NodeID targetID = utils::hashKey(key.getData());
                std::vector<NodePtr> closestNodes = routingTable_->findClosestNodes(targetID);
                
                // Create a response message
                RPCMessage response;
                response.type = RPCType::FIND_NODE; // Use FIND_NODE type to indicate we're returning nodes
                response.sender = localNode_->getID();
                response.receiver = message.sender;
                response.senderIP = localNode_->getIP();
                response.senderPort = localNode_->getPort();
                
                // Add the closest nodes to the payload
                for (const auto& node : closestNodes) {
                    // Add the node ID, IP, and port to the payload
                    std::string nodeStr = node->getID().toString() + ":" + node->getIP() + ":" + std::to_string(node->getPort());
                    response.payload.insert(response.payload.end(), nodeStr.begin(), nodeStr.end());
                    response.payload.push_back('\n'); // Use a newline as a separator
                }
                
                sendRPC(response);
            }
            break;
        }
        
        case RPCType::HOLE_PUNCH_REQUEST: {
            // Extract the requester's information
            std::string requesterIP = message.senderIP;
            uint16_t requesterPort = message.senderPort;
            
            // Create a node for the requester
            NodePtr requester = std::make_shared<Node>(message.sender, requesterIP, requesterPort);
            
            // Handle the hole punch request
            holePuncher_->handleHolePunchRequest(requester);
            
            // Respond with a HOLE_PUNCH_RESPONSE
            RPCMessage response;
            response.type = RPCType::HOLE_PUNCH_RESPONSE;
            response.sender = localNode_->getID();
            response.receiver = message.sender;
            response.senderIP = localNode_->getIP();
            response.senderPort = localNode_->getPort();
            
            sendRPC(response);
            break;
        }
        
        case RPCType::HOLE_PUNCH_RESPONSE: {
            // The hole punch was successful, no need to do anything
            break;
        }
    }
}

void Kademlia::bootstrap(const std::string& bootstrapIP, uint16_t bootstrapPort) {
    // Create a node for the bootstrap node
    NodeID bootstrapID = NodeID::random(); // In a real implementation, we would get the actual ID
    NodePtr bootstrapNode = std::make_shared<Node>(bootstrapID, bootstrapIP, bootstrapPort);
    
    // Add the bootstrap node to the routing table
    routingTable_->addNode(bootstrapNode);
    
    // Perform a node lookup for our own ID to populate the routing table
    nodeLookup(localNode_->getID(), nullptr);
}

void Kademlia::refreshBuckets() {
    // Refresh each bucket by performing a node lookup for a random ID in the bucket's range
    for (size_t i = 0; i < KEY_BITS; ++i) {
        // Generate a random ID that differs from the local ID at bit i
        std::array<uint8_t, KEY_BYTES> id = localNode_->getID().getRaw();
        size_t bytePos = i / 8;
        size_t bitPos = 7 - (i % 8);
        id[bytePos] ^= (1 << bitPos);
        
        NodeID targetID(id);
        
        // Perform a node lookup for the target ID
        nodeLookup(targetID, nullptr);
    }
}

void Kademlia::republishKeys() {
    std::lock_guard<std::mutex> lock(storageMutex_);
    
    // Republish each key-value pair
    for (const auto& entry : storage_) {
        const auto& keyStr = entry.first;
        const auto& value = entry.second;
        
        // Create a DHTKey from the key string
        DHTKey key(keyStr);
        
        // Store the key-value pair again
        store(key, value, nullptr);
    }
}

void Kademlia::expireKeys() {
    std::lock_guard<std::mutex> lock(storageMutex_);
    
    // Get the current time
    uint64_t now = utils::getCurrentTimeMillis();
    
    // Expire keys that are older than 24 hours
    const uint64_t EXPIRE_THRESHOLD = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
    
    std::vector<std::string> keysToRemove;
    
    for (const auto& entry : storageTimestamps_) {
        const auto& key = entry.first;
        const auto& timestamp = entry.second;
        
        if (now - timestamp > EXPIRE_THRESHOLD) {
            keysToRemove.push_back(key);
        }
    }
    
    // Remove expired keys
    for (const auto& key : keysToRemove) {
        storage_.erase(key);
        storageTimestamps_.erase(key);
    }
}

bool Kademlia::sendRPC(const RPCMessage& message) {
    // In a real implementation, this would send the message over the network
    // For simplicity, we'll use a placeholder implementation
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Set up the destination address
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    
    // Get the IP and port of the receiver
    NodePtr receiver = routingTable_->getNode(message.receiver);
    if (!receiver) {
        close(sockfd);
        return false;
    }
    
    destAddr.sin_addr.s_addr = inet_addr(receiver->getIP().c_str());
    destAddr.sin_port = htons(receiver->getPort());
    
    // Serialize the message
    // In a real implementation, we would use a proper serialization format
    std::string serializedMsg;
    serializedMsg += std::to_string(static_cast<int>(message.type)) + ":";
    serializedMsg += message.sender.toString() + ":";
    serializedMsg += message.receiver.toString() + ":";
    serializedMsg += message.senderIP + ":";
    serializedMsg += std::to_string(message.senderPort) + ":";
    
    // Add the payload
    for (const auto& byte : message.payload) {
        serializedMsg += static_cast<char>(byte);
    }
    
    // Send the message
    ssize_t bytesSent = sendto(sockfd, serializedMsg.c_str(), serializedMsg.length(), 0,
                              (struct sockaddr*)&destAddr, sizeof(destAddr));
    
    close(sockfd);
    
    return bytesSent > 0;
}

void Kademlia::processMessages() {
    // In a real implementation, this would listen for incoming messages
    // For simplicity, we'll use a placeholder implementation
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Bind to the local port
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(localNode_->getPort());
    
    if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        close(sockfd);
        return;
    }
    
    // Process messages while running
    while (running_) {
        // Wait for a message
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        
        if (poll(&pfd, 1, 100) > 0) { // 100ms timeout
            char buffer[4096];
            struct sockaddr_in fromAddr;
            socklen_t fromLen = sizeof(fromAddr);
            
            ssize_t bytesRead = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                        (struct sockaddr*)&fromAddr, &fromLen);
            
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                
                // Deserialize the message
                // In a real implementation, we would use a proper deserialization format
                std::string msg(buffer);
                std::vector<std::string> parts;
                
                size_t pos = 0;
                size_t found;
                while ((found = msg.find(':', pos)) != std::string::npos) {
                    parts.push_back(msg.substr(pos, found - pos));
                    pos = found + 1;
                }
                parts.push_back(msg.substr(pos));
                
                if (parts.size() >= 6) {
                    RPCMessage message;
                    message.type = static_cast<RPCType>(std::stoi(parts[0]));
                    message.sender = NodeID(parts[1]);
                    message.receiver = NodeID(parts[2]);
                    message.senderIP = parts[3];
                    message.senderPort = static_cast<uint16_t>(std::stoi(parts[4]));
                    
                    // Extract the payload
                    std::string payloadStr = parts[5];
                    message.payload.assign(payloadStr.begin(), payloadStr.end());
                    
                    // Handle the message
                    handleRPC(message);
                }
            }
        }
    }
    
    close(sockfd);
}

void Kademlia::nodeLookup(const NodeID& target, NodeLookupCallback callback) {
    // Get the alpha closest nodes to the target from the local routing table
    const size_t ALPHA = 3; // Parallelism parameter
    std::vector<NodePtr> closestNodes = routingTable_->findClosestNodes(target, ALPHA);
    
    if (closestNodes.empty()) {
        if (callback) {
            callback(false, std::vector<NodePtr>());
        }
        return;
    }
    
    // Keep track of nodes we've already queried
    std::vector<NodePtr> queriedNodes;
    
    // Keep track of the k closest nodes we've found
    std::vector<NodePtr> kClosestNodes = closestNodes;
    
    // Query the alpha closest nodes
    for (const auto& node : closestNodes) {
        // Create a FIND_NODE RPC message
        RPCMessage message;
        message.type = RPCType::FIND_NODE;
        message.sender = localNode_->getID();
        message.receiver = node->getID();
        message.senderIP = localNode_->getIP();
        message.senderPort = localNode_->getPort();
        
        // Add the target ID to the payload
        std::string targetStr = target.toString();
        message.payload.assign(targetStr.begin(), targetStr.end());
        
        // Send the message
        if (sendRPC(message)) {
            queriedNodes.push_back(node);
        }
    }
    
    // In a real implementation, we would wait for responses and continue the lookup
    // For simplicity, we'll just return the closest nodes we found
    
    if (callback) {
        callback(true, kClosestNodes);
    }
}

void Kademlia::valueLookup(const DHTKey& key, DHTCallback callback) {
    // Hash the key to get a NodeID
    NodeID targetID = utils::hashKey(key.getData());
    
    // Get the alpha closest nodes to the target from the local routing table
    const size_t ALPHA = 3; // Parallelism parameter
    std::vector<NodePtr> closestNodes = routingTable_->findClosestNodes(targetID, ALPHA);
    
    if (closestNodes.empty()) {
        if (callback) {
            callback(false, std::vector<uint8_t>());
        }
        return;
    }
    
    // Keep track of nodes we've already queried
    std::vector<NodePtr> queriedNodes;
    
    // Query the alpha closest nodes
    for (const auto& node : closestNodes) {
        // Create a FIND_VALUE RPC message
        RPCMessage message;
        message.type = RPCType::FIND_VALUE;
        message.sender = localNode_->getID();
        message.receiver = node->getID();
        message.senderIP = localNode_->getIP();
        message.senderPort = localNode_->getPort();
        
        // Add the key to the payload
        message.payload.assign(key.getData().begin(), key.getData().end());
        
        // Send the message
        if (sendRPC(message)) {
            queriedNodes.push_back(node);
        }
    }
    
    // In a real implementation, we would wait for responses and continue the lookup
    // For simplicity, we'll just return failure
    
    if (callback) {
        callback(false, std::vector<uint8_t>());
    }
}

} // namespace kademlia