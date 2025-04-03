#include "../include/node.h"
#include "../include/utils.h"
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace kademlia {

// NodeID implementation
NodeID::NodeID() {
    std::fill(id_.begin(), id_.end(), 0);
}

NodeID::NodeID(const std::array<uint8_t, KEY_BYTES>& id) : id_(id) {}

NodeID::NodeID(const std::string& hex) {
    if (hex.length() != KEY_BYTES * 2) {
        throw std::invalid_argument("Invalid hex string length for NodeID");
    }
    
    for (size_t i = 0; i < KEY_BYTES; ++i) {
        std::string byteStr = hex.substr(i * 2, 2);
        id_[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }
}

NodeID NodeID::random() {
    std::array<uint8_t, KEY_BYTES> id;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < KEY_BYTES; ++i) {
        id[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return NodeID(id);
}

NodeID NodeID::distance(const NodeID& other) const {
    std::array<uint8_t, KEY_BYTES> result;
    
    for (size_t i = 0; i < KEY_BYTES; ++i) {
        result[i] = id_[i] ^ other.id_[i];
    }
    
    return NodeID(result);
}

bool NodeID::getBit(size_t position) const {
    if (position >= KEY_BITS) {
        throw std::out_of_range("Bit position out of range");
    }
    
    size_t bytePos = position / 8;
    size_t bitPos = 7 - (position % 8);
    
    return (id_[bytePos] & (1 << bitPos)) != 0;
}

uint8_t NodeID::getByte(size_t position) const {
    if (position >= KEY_BYTES) {
        throw std::out_of_range("Byte position out of range");
    }
    
    return id_[position];
}

std::string NodeID::toString() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (auto byte : id_) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

bool NodeID::operator==(const NodeID& other) const {
    return id_ == other.id_;
}

bool NodeID::operator!=(const NodeID& other) const {
    return !(*this == other);
}

bool NodeID::operator<(const NodeID& other) const {
    return id_ < other.id_;
}

const std::array<uint8_t, KEY_BYTES>& NodeID::getRaw() const {
    return id_;
}

// Node implementation
Node::Node(const NodeID& id, const std::string& ip, uint16_t port)
    : id_(id), ip_(ip), port_(port), lastSeen_(utils::getCurrentTimeMillis()) {}

const NodeID& Node::getID() const {
    return id_;
}

const std::string& Node::getIP() const {
    return ip_;
}

uint16_t Node::getPort() const {
    return port_;
}

void Node::updateLastSeen() {
    lastSeen_ = utils::getCurrentTimeMillis();
}

bool Node::isActive() const {
    // Consider a node inactive if it hasn't been seen in the last 15 minutes
    const uint64_t INACTIVE_THRESHOLD = 15 * 60 * 1000; // 15 minutes in milliseconds
    return (utils::getCurrentTimeMillis() - lastSeen_) < INACTIVE_THRESHOLD;
}

std::string Node::toString() const {
    std::stringstream ss;
    ss << id_.toString() << "@" << ip_ << ":" << port_;
    return ss.str();
}

bool Node::operator==(const Node& other) const {
    return id_ == other.id_;
}

bool Node::operator!=(const Node& other) const {
    return !(*this == other);
}

} // namespace kademlia