#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace kademlia {

// Number of bits in the key
constexpr size_t KEY_BITS = 160;
// Number of bytes in the key (160 bits = 20 bytes)
constexpr size_t KEY_BYTES = KEY_BITS / 8;

/**
 * @brief NodeID class representing a 160-bit identifier
 */
class NodeID {
public:
    NodeID();
    explicit NodeID(const std::array<uint8_t, KEY_BYTES>& id);
    explicit NodeID(const std::string& hex);
    
    // Generate a random NodeID
    static NodeID random();
    
    // Calculate the distance between two NodeIDs (XOR metric)
    NodeID distance(const NodeID& other) const;
    
    // Get the bit at the specified position
    bool getBit(size_t position) const;
    
    // Get the byte at the specified position
    uint8_t getByte(size_t position) const;
    
    // Convert to string representation
    std::string toString() const;
    
    // Comparison operators
    bool operator==(const NodeID& other) const;
    bool operator!=(const NodeID& other) const;
    bool operator<(const NodeID& other) const;
    
    // Get the raw ID
    const std::array<uint8_t, KEY_BYTES>& getRaw() const;

private:
    std::array<uint8_t, KEY_BYTES> id_;
};

/**
 * @brief Node class representing a node in the Kademlia network
 */
class Node {
public:
    Node(const NodeID& id, const std::string& ip, uint16_t port);
    
    // Getters
    const NodeID& getID() const;
    const std::string& getIP() const;
    uint16_t getPort() const;
    
    // Update last seen timestamp
    void updateLastSeen();
    
    // Check if the node is active
    bool isActive() const;
    
    // Get string representation
    std::string toString() const;
    
    // Comparison operators
    bool operator==(const Node& other) const;
    bool operator!=(const Node& other) const;

private:
    NodeID id_;
    std::string ip_;
    uint16_t port_;
    uint64_t lastSeen_;
};

using NodePtr = std::shared_ptr<Node>;

} // namespace kademlia

// Hash function for NodeID to use in unordered_map
namespace std {
    template<>
    struct hash<kademlia::NodeID> {
        size_t operator()(const kademlia::NodeID& id) const {
            const auto& raw = id.getRaw();
            // Use the first 8 bytes as a hash
            size_t result = 0;
            for (size_t i = 0; i < 8 && i < raw.size(); ++i) {
                result = (result << 8) | raw[i];
            }
            return result;
        }
    };
}