#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <functional>

namespace kademlia {

/**
 * @brief DHTKey class representing a key in the DHT
 */
class DHTKey {
public:
    DHTKey();
    explicit DHTKey(const std::vector<uint8_t>& data);
    explicit DHTKey(const std::string& str);
    
    // Get the raw data
    const std::vector<uint8_t>& getData() const;
    
    // Convert to string
    std::string toString() const;
    
    // Comparison operators
    bool operator==(const DHTKey& other) const;
    bool operator!=(const DHTKey& other) const;

private:
    std::vector<uint8_t> data_;
};

} // namespace kademlia

// Hash function for DHTKey
namespace std {
    template<>
    struct hash<kademlia::DHTKey> {
        size_t operator()(const kademlia::DHTKey& key) const {
            const auto& data = key.getData();
            size_t hash = 0;
            
            // Simple hash function
            for (const auto& byte : data) {
                hash = hash * 31 + byte;
            }
            
            return hash;
        }
    };
}