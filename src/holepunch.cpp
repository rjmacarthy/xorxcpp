#include "../include/holepunch.h"
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

namespace kademlia {

HolePuncher::HolePuncher() {
    // Initialize connection info
    connectionInfo_.natType = NATType::UNKNOWN;
    connectionInfo_.publicIP = "";
    connectionInfo_.publicPort = 0;
    connectionInfo_.localIP = "";
    connectionInfo_.localPort = 0;
    connectionInfo_.timestamp = std::chrono::system_clock::now();
}

NATType HolePuncher::detectNATType() {
    // This is a simplified implementation
    // In a real-world scenario, this would involve multiple STUN server requests
    
    // Try to get the public endpoint
    std::string publicIP;
    uint16_t publicPort;
    
    if (!getPublicEndpoint(publicIP, publicPort)) {
        return NATType::UNKNOWN;
    }
    
    // Create a socket for testing
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NATType::UNKNOWN;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Bind to a local port
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0); // Let the OS choose a port
    
    if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        close(sockfd);
        return NATType::UNKNOWN;
    }
    
    // Get the local port
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        close(sockfd);
        return NATType::UNKNOWN;
    }
    
    uint16_t localPort = ntohs(localAddr.sin_port);
    
    // Test for NAT type
    // This is a simplified test and would need to be expanded in a real implementation
    
    // Send a packet to the STUN server
    struct sockaddr_in stunAddr;
    memset(&stunAddr, 0, sizeof(stunAddr));
    stunAddr.sin_family = AF_INET;
    stunAddr.sin_addr.s_addr = inet_addr("stun.example.com"); // Replace with a real STUN server
    stunAddr.sin_port = htons(3478); // Standard STUN port
    
    const char* testMsg = "NAT test";
    sendto(sockfd, testMsg, strlen(testMsg), 0, (struct sockaddr*)&stunAddr, sizeof(stunAddr));
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    NATType natType = NATType::UNKNOWN;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        char buffer[1024];
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen) > 0) {
            // Check if the response is from the STUN server
            if (fromAddr.sin_addr.s_addr == stunAddr.sin_addr.s_addr &&
                fromAddr.sin_port == stunAddr.sin_port) {
                
                // Parse the response to determine NAT type
                // This is a simplified implementation
                
                // If we can receive a response, we're at least not behind a symmetric NAT
                natType = NATType::FULL_CONE;
                
                // Additional tests would be needed to differentiate between
                // Full Cone, Restricted, and Port Restricted NATs
            }
        }
    }
    
    close(sockfd);
    
    // Update connection info
    std::lock_guard<std::mutex> lock(mutex_);
    connectionInfo_.natType = natType;
    connectionInfo_.timestamp = std::chrono::system_clock::now();
    
    return natType;
}

bool HolePuncher::getPublicEndpoint(std::string& ip, uint16_t& port) {
    // This would normally involve a STUN server request
    // For simplicity, we'll use a placeholder implementation
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect to a STUN server
    struct sockaddr_in stunAddr;
    memset(&stunAddr, 0, sizeof(stunAddr));
    stunAddr.sin_family = AF_INET;
    stunAddr.sin_addr.s_addr = inet_addr("stun.example.com"); // Replace with a real STUN server
    stunAddr.sin_port = htons(3478); // Standard STUN port
    
    if (connect(sockfd, (struct sockaddr*)&stunAddr, sizeof(stunAddr)) < 0) {
        close(sockfd);
        return false;
    }
    
    // Send a STUN binding request
    // This is a simplified implementation
    const char* stunRequest = "STUN binding request";
    send(sockfd, stunRequest, strlen(stunRequest), 0);
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        char buffer[1024];
        int bytesRead = recv(sockfd, buffer, sizeof(buffer), 0);
        
        if (bytesRead > 0) {
            // Parse the STUN response to get the public IP and port
            // This is a simplified implementation
            
            // In a real implementation, we would parse the XOR-MAPPED-ADDRESS attribute
            // from the STUN response to get the public IP and port
            
            // For now, we'll use placeholder values
            ip = "203.0.113.1"; // Example public IP
            port = 12345; // Example public port
            
            // Update connection info
            std::lock_guard<std::mutex> lock(mutex_);
            connectionInfo_.publicIP = ip;
            connectionInfo_.publicPort = port;
            connectionInfo_.timestamp = std::chrono::system_clock::now();
            
            success = true;
        }
    }
    
    close(sockfd);
    return success;
}

bool HolePuncher::registerWithServer(const std::string& serverIP, uint16_t serverPort) {
    // Get the public endpoint
    std::string publicIP;
    uint16_t publicPort;
    
    if (!getPublicEndpoint(publicIP, publicPort)) {
        return false;
    }
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect to the rendezvous server
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    serverAddr.sin_port = htons(serverPort);
    
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sockfd);
        return false;
    }
    
    // Send registration message with public endpoint
    std::string regMsg = "REGISTER " + publicIP + ":" + std::to_string(publicPort);
    send(sockfd, regMsg.c_str(), regMsg.length(), 0);
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        char buffer[1024];
        int bytesRead = recv(sockfd, buffer, sizeof(buffer), 0);
        
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            
            // Check if registration was successful
            if (strstr(buffer, "OK") != nullptr) {
                success = true;
            }
        }
    }
    
    close(sockfd);
    return success;
}

void HolePuncher::initiateHolePunch(const NodePtr& target, HolePunchCallback callback) {
    // Store the callback
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pendingHolePunches_[target->getID()] = callback;
    }
    
    // Try direct connection first
    if (attemptDirectConnection(target->getIP(), target->getPort())) {
        // Direct connection successful
        callback(true, target->getIP(), target->getPort());
        return;
    }
    
    // Try STUN-assisted connection
    if (attemptSTUNConnection(target)) {
        // STUN connection successful
        callback(true, target->getIP(), target->getPort());
        return;
    }
    
    // Try TCP hole punching
    if (attemptTCPHolePunch(target)) {
        // TCP hole punching successful
        callback(true, target->getIP(), target->getPort());
        return;
    }
    
    // All methods failed
    callback(false, "", 0);
}

void HolePuncher::handleHolePunchRequest(const NodePtr& requester) {
    // Send UDP packets to create a hole in the NAT
    sendHolePunchingPackets(requester->getIP(), requester->getPort(), 5);
}

void HolePuncher::updateConnectionInfo(const ConnectionInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    connectionInfo_ = info;
}

ConnectionInfo HolePuncher::getConnectionInfo() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connectionInfo_;
}

void HolePuncher::sendHolePunchingPackets(const std::string& ip, uint16_t port, int count) {
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Set up the destination address
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(ip.c_str());
    destAddr.sin_port = htons(port);
    
    // Send multiple packets to create a hole in the NAT
    const char* holePunchMsg = "HOLE_PUNCH";
    for (int i = 0; i < count; ++i) {
        sendto(sockfd, holePunchMsg, strlen(holePunchMsg), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);
}

bool HolePuncher::attemptDirectConnection(const std::string& ip, uint16_t port) {
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
    destAddr.sin_addr.s_addr = inet_addr(ip.c_str());
    destAddr.sin_port = htons(port);
    
    // Send a test message
    const char* testMsg = "DIRECT_CONNECT";
    sendto(sockfd, testMsg, strlen(testMsg), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    if (poll(&pfd, 1, 2000) > 0) { // 2 second timeout
        char buffer[1024];
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen) > 0) {
            // Check if the response is from the expected peer
            if (fromAddr.sin_addr.s_addr == destAddr.sin_addr.s_addr &&
                fromAddr.sin_port == destAddr.sin_port) {
                success = true;
            }
        }
    }
    
    close(sockfd);
    return success;
}

bool HolePuncher::attemptSTUNConnection(const NodePtr& target) {
    // This would involve a STUN server to facilitate the connection
    // For simplicity, we'll use a placeholder implementation
    
    // In a real implementation, both peers would register with a STUN server
    // and the server would help them establish a connection
    
    // Send hole punching packets
    sendHolePunchingPackets(target->getIP(), target->getPort(), 10);
    
    // Try to establish a connection
    return attemptDirectConnection(target->getIP(), target->getPort());
}

bool HolePuncher::attemptTCPHolePunch(const NodePtr& target) {
    // TCP hole punching is more complex than UDP
    // For simplicity, we'll use a placeholder implementation
    
    // In a real implementation, this would involve simultaneous TCP connection attempts
    // from both peers to create holes in their respective NATs
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
    destAddr.sin_addr.s_addr = inet_addr(target->getIP().c_str());
    destAddr.sin_port = htons(target->getPort());
    
    // Try to connect
    connect(sockfd, (struct sockaddr*)&destAddr, sizeof(destAddr));
    
    // Wait for connection to complete or fail
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLOUT;
    
    bool success = false;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        int error = 0;
        socklen_t len = sizeof(error);
        
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
            // Connection successful
            success = true;
        }
    }
    
    close(sockfd);
    return success;
}

} // namespace kademlia