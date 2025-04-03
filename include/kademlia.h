#pragma once

#include "node.h"
#include "routing_table.h"
#include "dht_key.h"
#include "holepunch.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>

namespace kademlia {

// Callback for DHT operations
using DHTCallback = std::function<void(bool success, const std::vector<uint8_t>& value)>;

// Callback for node lookup
using NodeLookupCallback = std::function<void(bool success, const std::vector<NodePtr>& nodes)>;

/**
 * @brief Enum representing the type of RPC message
 */
enum class RPCType {
    PING,
    STORE,
    FIND_NODE,
    FIND_VALUE,
    HOLE_PUNCH_REQUEST,
    HOLE_PUNCH_RESPONSE
};

/**
 * @brief Struct representing an RPC message
 */
struct RPCMessage {
    RPCType type;
    NodeID sender;
    NodeID receiver;
    std::string senderIP;
    uint16_t senderPort;
    std::vector<uint8_t> payload;
};

/**
 * @brief Kademlia class implementing the Kademlia DHT
 */
class Kademlia {
public:
    Kademlia(uint16_t port, const std::string& bootstrapIP = "", uint16_t bootstrapPort = 0);
    ~Kademlia();
    
    // Start the Kademlia node
    bool start();
    
    // Stop the Kademlia node
    void stop();
    
    // Store a key-value pair in the DHT
    void store(const DHTKey& key, const std::vector<uint8_t>& value, DHTCallback callback = nullptr);
    
    // Find a value by key
    void findValue(const DHTKey& key, DHTCallback callback);
    
    // Find the k closest nodes to the given key
    void findNode(const NodeID& id, NodeLookupCallback callback);
    
    // Ping a node
    bool ping(const NodePtr& node);
    
    // Get the local node
    NodePtr getLocalNode() const;
    
    // Get the routing table
    std::shared_ptr<RoutingTable> getRoutingTable() const;
    
    // Get the hole puncher
    std::shared_ptr<HolePuncher> getHolePuncher() const;
    
    // Handle an incoming RPC message
    void handleRPC(const RPCMessage& message);

private:
    // Bootstrap the node into the network
    void bootstrap(const std::string& bootstrapIP, uint16_t bootstrapPort);
    
    // Refresh buckets
    void refreshBuckets();
    
    // Republish keys
    void republishKeys();
    
    // Expire old keys
    void expireKeys();
    
    // Send an RPC message
    bool sendRPC(const RPCMessage& message);
    
    // Process incoming messages
    void processMessages();
    
    // Node lookup procedure
    void nodeLookup(const NodeID& target, NodeLookupCallback callback);
    
    // Value lookup procedure
    void valueLookup(const DHTKey& key, DHTCallback callback);
    
    NodePtr localNode_;
    std::shared_ptr<RoutingTable> routingTable_;
    std::shared_ptr<HolePuncher> holePuncher_;
    std::unordered_map<std::string, std::vector<uint8_t>> storage_;
    std::unordered_map<std::string, uint64_t> storageTimestamps_;
    
    std::atomic<bool> running_;
    std::thread messageThread_;
    std::thread maintenanceThread_;
    
    mutable std::mutex storageMutex_;
};

} // namespace kademlia