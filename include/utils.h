#pragma once

#include "node.h"
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>

namespace kademlia {
namespace utils {

/**
 * @brief Generate a random NodeID
 * @return A random NodeID
 */
NodeID generateRandomID();

/**
 * @brief Convert a hex string to bytes
 * @param hex The hex string
 * @return The bytes
 */
std::vector<uint8_t> hexToBytes(const std::string& hex);

/**
 * @brief Convert bytes to a hex string
 * @param bytes The bytes
 * @return The hex string
 */
std::string bytesToHex(const std::vector<uint8_t>& bytes);

/**
 * @brief Convert an array to a hex string
 * @param array The array
 * @return The hex string
 */
template<size_t N>
std::string arrayToHex(const std::array<uint8_t, N>& array) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : array) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

/**
 * @brief Get the current timestamp in milliseconds
 * @return The current timestamp
 */
uint64_t getCurrentTimeMillis();

/**
 * @brief Calculate the XOR distance between two NodeIDs
 * @param a The first NodeID
 * @param b The second NodeID
 * @return The XOR distance
 */
NodeID calculateDistance(const NodeID& a, const NodeID& b);

/**
 * @brief Get the common prefix length of two NodeIDs
 * @param a The first NodeID
 * @param b The second NodeID
 * @return The common prefix length in bits
 */
size_t getCommonPrefixLength(const NodeID& a, const NodeID& b);

/**
 * @brief Sort nodes by their distance to a target NodeID
 * @param nodes The nodes to sort
 * @param targetID The target NodeID
 * @return The sorted nodes
 */
std::vector<NodePtr> sortNodesByDistance(const std::vector<NodePtr>& nodes, const NodeID& targetID);

/**
 * @brief Check if a node is in a list of nodes
 * @param node The node to check
 * @param nodes The list of nodes
 * @return True if the node is in the list, false otherwise
 */
bool isNodeInList(const NodePtr& node, const std::vector<NodePtr>& nodes);

/**
 * @brief Generate a random number in the given range
 * @param min The minimum value
 * @param max The maximum value
 * @return A random number in the range [min, max]
 */
template<typename T>
T getRandomInRange(T min, T max) {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<T> dist(min, max);
    return dist(rng);
}

/**
 * @brief Hash a key using SHA-1
 * @param key The key to hash
 * @return The hash as a NodeID
 */
NodeID hashKey(const std::vector<uint8_t>& key);

/**
 * @brief Parse an IP address and port from a string
 * @param address The address string (format: "ip:port")
 * @param ip The output IP address
 * @param port The output port
 * @return True if parsing was successful, false otherwise
 */
bool parseAddress(const std::string& address, std::string& ip, uint16_t& port);

/**
 * @brief Check if an IP address is valid
 * @param ip The IP address to check
 * @return True if the IP address is valid, false otherwise
 */
bool isValidIP(const std::string& ip);

/**
 * @brief Check if a port is valid
 * @param port The port to check
 * @return True if the port is valid, false otherwise
 */
bool isValidPort(uint16_t port);

} // namespace utils
} // namespace kademlia