#include "../include/utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <openssl/sha.h>
#include <regex>
#include <arpa/inet.h>

namespace kademlia {
namespace utils {

NodeID generateRandomID() {
    return NodeID::random();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (auto byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

uint64_t getCurrentTimeMillis() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

NodeID calculateDistance(const NodeID& a, const NodeID& b) {
    return a.distance(b);
}

size_t getCommonPrefixLength(const NodeID& a, const NodeID& b) {
    size_t commonPrefixLength = 0;
    
    for (size_t i = 0; i < KEY_BITS; ++i) {
        if (a.getBit(i) != b.getBit(i)) {
            break;
        }
        commonPrefixLength++;
    }
    
    return commonPrefixLength;
}

std::vector<NodePtr> sortNodesByDistance(const std::vector<NodePtr>& nodes, const NodeID& targetID) {
    std::vector<NodePtr> sortedNodes = nodes;
    
    std::sort(sortedNodes.begin(), sortedNodes.end(), 
        [&targetID](const NodePtr& a, const NodePtr& b) {
            NodeID distA = a->getID().distance(targetID);
            NodeID distB = b->getID().distance(targetID);
            return distA < distB;
        });
    
    return sortedNodes;
}

bool isNodeInList(const NodePtr& node, const std::vector<NodePtr>& nodes) {
    return std::find_if(nodes.begin(), nodes.end(), 
        [&node](const NodePtr& n) {
            return n->getID() == node->getID();
        }) != nodes.end();
}

NodeID hashKey(const std::vector<uint8_t>& key) {
    std::array<uint8_t, KEY_BYTES> hash;
    
    // Use SHA-1 to hash the key
    SHA1(key.data(), key.size(), hash.data());
    
    return NodeID(hash);
}

bool parseAddress(const std::string& address, std::string& ip, uint16_t& port) {
    std::regex addressRegex("([^:]+):(\\d+)");
    std::smatch match;
    
    if (std::regex_match(address, match, addressRegex)) {
        ip = match[1].str();
        port = static_cast<uint16_t>(std::stoi(match[2].str()));
        return true;
    }
    
    return false;
}

bool isValidIP(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

bool isValidPort(uint16_t port) {
    // Ports 0 and 1-1023 are reserved
    return port > 1023;
}

} // namespace utils
} // namespace kademlia