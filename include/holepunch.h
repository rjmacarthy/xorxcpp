#pragma once

#include "node.h"
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace kademlia {

/**
 * @brief Enum representing the NAT type
 */
enum class NATType {
    UNKNOWN,
    OPEN,
    FULL_CONE,
    RESTRICTED,
    PORT_RESTRICTED,
    SYMMETRIC
};

/**
 * @brief Struct representing connection information
 */
struct ConnectionInfo {
    std::string publicIP;
    uint16_t publicPort;
    std::string localIP;
    uint16_t localPort;
    NATType natType;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @brief Callback for hole-punching result
 */
using HolePunchCallback = std::function<void(bool success, const std::string& ip, uint16_t port)>;

/**
 * @brief HolePuncher class implementing NAT traversal techniques
 */
class HolePuncher {
public:
    HolePuncher();
    
    // Detect the NAT type
    NATType detectNATType();
    
    // Get the public IP and port
    bool getPublicEndpoint(std::string& ip, uint16_t& port);
    
    // Register with a STUN/rendezvous server
    bool registerWithServer(const std::string& serverIP, uint16_t serverPort);
    
    // Initiate hole-punching with a remote node
    void initiateHolePunch(const NodePtr& target, HolePunchCallback callback);
    
    // Handle an incoming hole-punch request
    void handleHolePunchRequest(const NodePtr& requester);
    
    // Update connection information
    void updateConnectionInfo(const ConnectionInfo& info);
    
    // Get the current connection information
    ConnectionInfo getConnectionInfo() const;

private:
    // Send UDP packets to create a hole in the NAT
    void sendHolePunchingPackets(const std::string& ip, uint16_t port, int count);
    
    // Perform direct connection attempt
    bool attemptDirectConnection(const std::string& ip, uint16_t port);
    
    // Perform connection attempt via STUN server
    bool attemptSTUNConnection(const NodePtr& target);
    
    // Perform connection attempt via TCP hole punching
    bool attemptTCPHolePunch(const NodePtr& target);
    
    // Perform connection attempt for localhost
    bool attemptLocalConnection(const std::string& ip, uint16_t port);
    
    // Check if the connection is local (localhost or same machine)
    bool isLocalConnection(const std::string& ip);
    
    // Helper method to detect local IP address
    void detectLocalIP();
    
    // Helper method to get public endpoint from a specific STUN server
    bool getPublicEndpointFromServer(const std::string& stunServer, uint16_t stunPort,
                                    std::string& ip, uint16_t& port);
    
    ConnectionInfo connectionInfo_;
    std::unordered_map<NodeID, HolePunchCallback> pendingHolePunches_;
    mutable std::mutex mutex_;
};

} // namespace kademlia