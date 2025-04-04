#include "../include/holepunch.h"
#include "../include/utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>

namespace kademlia {

// STUN message types
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;
constexpr uint16_t STUN_BINDING_ERROR_RESPONSE = 0x0111;

// STUN attribute types
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t STUN_ATTR_ERROR_CODE = 0x0009;
constexpr uint16_t STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
constexpr uint16_t STUN_ATTR_SOFTWARE = 0x8022;
constexpr uint16_t STUN_ATTR_CHANGE_REQUEST = 0x0003;
constexpr uint16_t STUN_ATTR_RESPONSE_ORIGIN = 0x802b;
constexpr uint16_t STUN_ATTR_OTHER_ADDRESS = 0x802c;

constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// List of public STUN servers
const std::vector<std::pair<std::string, uint16_t>> STUN_SERVERS = {
    {"stun.l.google.com", 19302},
    {"stun1.l.google.com", 19302},
    {"stun2.l.google.com", 19302},
    {"stun.ekiga.net", 3478},
    {"stun.ideasip.com", 3478},
    {"stun.schlund.de", 3478}
};

// STUN message header structure
struct StunMessageHeader {
    uint16_t messageType;
    uint16_t messageLength;
    uint32_t magicCookie;
    uint8_t transactionId[12];
};

// Generate a random transaction ID for STUN messages
void generateTransactionId(uint8_t* transactionId) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (int i = 0; i < 12; ++i) {
        transactionId[i] = static_cast<uint8_t>(dis(gen));
    }
}

// Create a STUN binding request message
std::vector<uint8_t> createStunBindingRequest(uint8_t* transactionId) {
    // STUN magic cookie
    

    std::vector<uint8_t> request(20); // Header size
    
    // Set message type (binding request)
    request[0] = 0x00;
    request[1] = 0x01;
    
    // Set message length (0 for now, no attributes)
    request[2] = 0x00;
    request[3] = 0x00;
    
    // Set magic cookie - multiply the left digit by 16 and add the right digit
    //          0xFF = 11111111
    //          F = 15 in hex
    //          F × 16 + F  
    //          = 15 × 16 + 15  
    //          = 240 + 15 = 255
    

    request[4] = (STUN_MAGIC_COOKIE >> 24) & 0xFF; 
    //          2 × 16 = 32 + 1 = 33
    //          00100001, 00010010, 10100100, 01000010 stun magic cookie
    // >> 24    00000000, 00000000, 00000000, 00100001
    //                                        0010 0001
    //                                        2    1     0x21                                             
    //          & OPERATION
    //          00000000, 00000000, 00000000, 11111111 // 0xFF
    //          00000000, 00000000, 00000000, 00100001 // mask last 8 bits
    
    request[5] = (STUN_MAGIC_COOKIE >> 16) & 0xFF;
    //          1 × 16 = 16 + 2 = 18
    //          00100001, 00010010, 10100100, 01000010 stun magic cookie
    // >> 16    00000000, 00000000, 00100001, 00010010
    //          & OPERATION
    //          00000000, 00000000, 00000000, 11111111 // 0xFF
    //          00000000, 00000000, 00000000, 00100001 // mask last 8 bits
    //                                        0001 0010
    //                                          1   2   0x12

    request[6] = (STUN_MAGIC_COOKIE >> 8) & 0xFF;
    //          1 × 16 = 16 + 2 = 18
    //          00100001, 00010010, 10100100, 01000010 stun magic cookie
    // >> 16    00000000, 00100001, 00010010, 10100100
    //          & OPERATION
    //          00000000, 00000000, 00000000, 11111111 // 0xFF
    //          00000000, 00000000, 00000000, 10100100 // mask last 8 bits
    //                                        1010 0100
    //                                          A   4   0xA4

    request[7] = STUN_MAGIC_COOKIE & 0xFF;
    //          1 × 16 = 16 + 2 = 18
    //          00100001, 00010010, 10100100, 01000010 stun magic cookie
    // >> 0     00100001, 00010010, 10100100, 01000010
    //          & OPERATION
    //          00000000, 00000000, 00000000, 11111111 // 0xFF
    //          00000000, 00000000, 00000000, 01000010 // mask last 8 bits
    //                                        0100 0010
    //                                          4   2   0x42
    
    // Set transaction ID
    for (int i = 0; i < 12; ++i) {
        request[8 + i] = transactionId[i];
    }
    
    return request;
}

// Parse a STUN response message to extract mapped address
bool parseStunResponse(const std::vector<uint8_t>& response, std::string& mappedIP, uint16_t& mappedPort) {
    if (response.size() < 20) {
        return false; // Too small to be a valid STUN message
    }
    
    // Check if it's a binding response
    uint16_t messageType = (response[0] << 8) | response[1];
    if (messageType != STUN_BINDING_RESPONSE) {
        return false;
    }
    
    // Check magic cookie
    uint32_t magicCookie = (response[4] << 24) | (response[5] << 16) | (response[6] << 8) | response[7];
    if (magicCookie != STUN_MAGIC_COOKIE) {
        return false;
    }
    
    // Get message length
    uint16_t messageLength = (response[2] << 8) | response[3];
    
    // Parse attributes
    size_t pos = 20; // Start after header
    while (pos + 4 <= response.size() && pos - 20 < messageLength) {
        uint16_t attrType = (response[pos] << 8) | response[pos + 1];
        uint16_t attrLength = (response[pos + 2] << 8) | response[pos + 3];
        pos += 4;
        
        if (pos + attrLength > response.size()) {
            break;
        }
        
        if (attrType == STUN_ATTR_XOR_MAPPED_ADDRESS) {
            if (attrLength < 8) {
                pos += attrLength;
                continue;
            }
            
            // Skip first byte (reserved) and get family
            uint8_t family = response[pos + 1];
            if (family != 0x01) { // IPv4
                pos += attrLength;
                continue;
            }
            
            // Get XOR-mapped port
            uint16_t xorPort = ((response[pos + 2] << 8) | response[pos + 3]) ^ (STUN_MAGIC_COOKIE >> 16);
            
            // Get XOR-mapped address
            uint32_t xorAddr = ((response[pos + 4] << 24) | (response[pos + 5] << 16) |
                               (response[pos + 6] << 8) | response[pos + 7]) ^ STUN_MAGIC_COOKIE;
            
            // Convert to string
            char ipBuffer[INET_ADDRSTRLEN];
            struct in_addr addr;
            addr.s_addr = htonl(xorAddr);
            if (inet_ntop(AF_INET, &addr, ipBuffer, sizeof(ipBuffer)) != nullptr) {
                mappedIP = ipBuffer;
                mappedPort = xorPort;
                return true;
            }
        } else if (attrType == STUN_ATTR_MAPPED_ADDRESS) {
            if (attrLength < 8) {
                pos += attrLength;
                continue;
            }
            
            // Skip first byte (reserved) and get family
            uint8_t family = response[pos + 1];
            if (family != 0x01) { // IPv4
                pos += attrLength;
                continue;
            }
            
            // Get port
            uint16_t port = (response[pos + 2] << 8) | response[pos + 3];
            
            // Get address
            uint32_t addr = (response[pos + 4] << 24) | (response[pos + 5] << 16) |
                           (response[pos + 6] << 8) | response[pos + 7];
            
            // Convert to string
            char ipBuffer[INET_ADDRSTRLEN];
            struct in_addr inAddr;
            inAddr.s_addr = htonl(addr);
            if (inet_ntop(AF_INET, &inAddr, ipBuffer, sizeof(ipBuffer)) != nullptr) {
                mappedIP = ipBuffer;
                mappedPort = port;
                return true;
            }
        }
        
        pos += attrLength;
        // Align to 4-byte boundary
        if (attrLength % 4 != 0) {
            pos += 4 - (attrLength % 4);
        }
    }
    
    return false;
}

HolePuncher::HolePuncher() {
    // Initialize connection info
    connectionInfo_.natType = NATType::UNKNOWN;
    connectionInfo_.publicIP = "";
    connectionInfo_.publicPort = 0;
    connectionInfo_.localIP = "";
    connectionInfo_.localPort = 0;
    connectionInfo_.timestamp = std::chrono::system_clock::now();
    
    // Try to detect local IP
    detectLocalIP();
}

// Helper method to detect local IP address
void HolePuncher::detectLocalIP() {
    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return;
    }
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
    // Connect to a public address (doesn't actually send anything)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google's DNS
    addr.sin_port = htons(53); // DNS port
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return;
    }
    
    // Get the local address
    struct sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        close(sockfd);
        return;
    }
    
    // Convert to string
    char ipBuffer[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &localAddr.sin_addr, ipBuffer, sizeof(ipBuffer)) != nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        connectionInfo_.localIP = ipBuffer;
    }
    
    close(sockfd);
}

NATType HolePuncher::detectNATType() {
    // This implementation follows a simplified version of the algorithm described in RFC 3489
    // It tests for different NAT behaviors by sending STUN requests to different servers
    
    // Try to get the public endpoint from the primary server
    std::string publicIP1;
    uint16_t publicPort1;
    
    if (!getPublicEndpoint(publicIP1, publicPort1)) {
        return NATType::UNKNOWN;
    }
    
    // Create a socket for testing
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NATType::UNKNOWN;
    }
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
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
    
    // Store local IP and port in connection info
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connectionInfo_.localIP.empty()) {
            // Try to get local IP from socket
            char ipBuffer[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &localAddr.sin_addr, ipBuffer, sizeof(ipBuffer)) != nullptr) {
                connectionInfo_.localIP = ipBuffer;
            }
        }
        connectionInfo_.localPort = localPort;
    }
    
    // Try a second STUN server to test for symmetric NAT
    // Use a different server from the list
    std::string secondServerIP;
    uint16_t secondServerPort;
    
    if (STUN_SERVERS.size() > 1) {
        secondServerIP = STUN_SERVERS[1].first;
        secondServerPort = STUN_SERVERS[1].second;
    } else {
        secondServerIP = STUN_SERVERS[0].first;
        secondServerPort = STUN_SERVERS[0].second;
    }
    
    // Resolve the second server
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    if (getaddrinfo(secondServerIP.c_str(), std::to_string(secondServerPort).c_str(), &hints, &servinfo) != 0) {
        close(sockfd);
        return NATType::UNKNOWN;
    }
    
    // Send a STUN binding request to the second server
    uint8_t transactionId[12];
    generateTransactionId(transactionId);
    std::vector<uint8_t> request = createStunBindingRequest(transactionId);
    
    if (sendto(sockfd, request.data(), request.size(), 0, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
        freeaddrinfo(servinfo);
        close(sockfd);
        return NATType::UNKNOWN;
    }
    
    freeaddrinfo(servinfo);
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    std::string publicIP2;
    uint16_t publicPort2;
    bool gotSecondResponse = false;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        std::vector<uint8_t> buffer(1024);
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        int bytesRead = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&fromAddr, &fromLen);
        if (bytesRead > 0) {
            buffer.resize(bytesRead);
            if (parseStunResponse(buffer, publicIP2, publicPort2)) {
                gotSecondResponse = true;
            }
        }
    }
    
    close(sockfd);
    
    // Determine NAT type based on test results
    NATType natType = NATType::UNKNOWN;
    
    if (publicIP1 == connectionInfo_.localIP) {
        // No NAT, public IP matches local IP
        natType = NATType::OPEN;
    } else if (gotSecondResponse) {
        if (publicIP1 == publicIP2 && publicPort1 == publicPort2) {
            // Same mapping for different servers, likely a full cone NAT
            natType = NATType::FULL_CONE;
            
            // Additional test for restricted vs. full cone would require a second socket
            // and testing if we can receive from a different IP without sending first
            // For simplicity, we'll assume full cone for now
        } else {
            // Different mapping for different servers, symmetric NAT
            natType = NATType::SYMMETRIC;
        }
    } else {
        // Could not determine precisely, assume port restricted
        natType = NATType::PORT_RESTRICTED;
    }
    
    // Update connection info
    std::lock_guard<std::mutex> lock(mutex_);
    connectionInfo_.natType = natType;
    connectionInfo_.publicIP = publicIP1;
    connectionInfo_.publicPort = publicPort1;
    connectionInfo_.timestamp = std::chrono::system_clock::now();
    
    return natType;
}

bool HolePuncher::getPublicEndpoint(std::string& ip, uint16_t& port) {
    // Try each STUN server until we get a response
    for (const auto& server : STUN_SERVERS) {
        if (getPublicEndpointFromServer(server.first, server.second, ip, port)) {
            return true;
        }
    }
    
    return false;
}

bool HolePuncher::getPublicEndpointFromServer(const std::string& stunServer, uint16_t stunPort,
                                             std::string& ip, uint16_t& port) {
    // Resolve the STUN server hostname
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    if (getaddrinfo(stunServer.c_str(), std::to_string(stunPort).c_str(), &hints, &servinfo) != 0) {
        return false;
    }
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        freeaddrinfo(servinfo);
        return false;
    }
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Create and send a STUN binding request

    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0 0|     STUN Message Type     |         Message Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                     Magic Cookie 0x2112A442                   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                     Transaction ID (96 bits)                  |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    uint8_t transactionId[12];
    generateTransactionId(transactionId);
    std::vector<uint8_t> request = createStunBindingRequest(transactionId);
    
    if (sendto(sockfd, request.data(), request.size(), 0, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
        freeaddrinfo(servinfo);
        close(sockfd);
        return false;
    }
    
    freeaddrinfo(servinfo);
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    if (poll(&pfd, 1, 5000) > 0) { // 5 second timeout
        std::vector<uint8_t> buffer(1024);
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        int bytesRead = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&fromAddr, &fromLen);
        if (bytesRead > 0) {
            buffer.resize(bytesRead);
            
            // Parse the STUN response
            if (parseStunResponse(buffer, ip, port)) {
                // Update connection info
                std::lock_guard<std::mutex> lock(mutex_);
                connectionInfo_.publicIP = ip;
                connectionInfo_.publicPort = port;
                connectionInfo_.timestamp = std::chrono::system_clock::now();
                
                success = true;
            }
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
    // Check if this is a local connection
    if (isLocalConnection(target->getIP())) {
        std::cout << "Detected localhost connection, using local connection method" << std::endl;
        
        // For localhost, just try a direct connection without NAT traversal
        if (attemptLocalConnection(target->getIP(), target->getPort())) {
            callback(true, target->getIP(), target->getPort());
        } else {
            callback(false, "", 0);
        }
        return;
    }
    
    // Store the callback for non-local connections
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
    // Check if this is a local connection
    if (isLocalConnection(requester->getIP())) {
        std::cout << "Handling localhost hole punch request" << std::endl;
        
        // For localhost, just respond directly
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            return;
        }
        
        // Set socket options to allow address reuse
        int optval = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        
        // Try to set SO_REUSEPORT if available
        #ifdef SO_REUSEPORT
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
        #endif
        
        // Set up the destination address
        struct sockaddr_in destAddr;
        memset(&destAddr, 0, sizeof(destAddr));
        destAddr.sin_family = AF_INET;
        destAddr.sin_addr.s_addr = inet_addr(requester->getIP().c_str());
        destAddr.sin_port = htons(requester->getPort());
        
        // Send response
        const char* response = "LOCAL_CONNECT_RESPONSE";
        for (int i = 0; i < 5; ++i) {
            sendto(sockfd, response, strlen(response), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        close(sockfd);
        return;
    }
    
    // For non-local connections, use the original NAT traversal logic
    // Get our public endpoint
    std::string ourPublicIP;
    uint16_t ourPublicPort;
    
    if (!getPublicEndpoint(ourPublicIP, ourPublicPort)) {
        return;
    }
    
    // Create a socket for communication
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
    // Bind to a specific port if we know our public port mapping
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    
    // Try to bind to our local port that maps to our public port
    if (connectionInfo_.localPort != 0) {
        localAddr.sin_port = htons(connectionInfo_.localPort);
        bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr));
    }
    
    // Set up the destination address
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(requester->getIP().c_str());
    destAddr.sin_port = htons(requester->getPort());
    
    // Send multiple packets with our public endpoint info
    // This helps create a hole in our NAT and provides the requester with our endpoint
    std::string msg = "HOLE_PUNCH_RESPONSE " + ourPublicIP + ":" + std::to_string(ourPublicPort);
    
    for (int i = 0; i < 10; ++i) {
        sendto(sockfd, msg.c_str(), msg.length(), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Wait for a short time to see if we get a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    if (poll(&pfd, 1, 2000) > 0) { // 2 second timeout
        char buffer[1024];
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        int bytesRead = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            
            // If we received a response, send a few more packets to confirm the connection
            if (fromAddr.sin_addr.s_addr == destAddr.sin_addr.s_addr) {
                std::string confirmMsg = "HOLE_PUNCH_CONFIRM";
                for (int i = 0; i < 3; ++i) {
                    sendto(sockfd, confirmMsg.c_str(), confirmMsg.length(), 0,
                           (struct sockaddr*)&fromAddr, fromLen);
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
        }
    }
    
    close(sockfd);
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
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
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
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
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
    // Get our public endpoint
    std::string ourPublicIP;
    uint16_t ourPublicPort;
    
    if (!getPublicEndpoint(ourPublicIP, ourPublicPort)) {
        return false;
    }
    
    // Create a socket for communication
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Bind to a specific port if we know our public port mapping
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    
    // Try to bind to our local port that maps to our public port
    // This might not work if the NAT doesn't have consistent port mapping
    if (connectionInfo_.localPort != 0) {
        localAddr.sin_port = htons(connectionInfo_.localPort);
        bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr));
    }
    
    // Send hole punching packets to the target's public endpoint
    sendHolePunchingPackets(target->getIP(), target->getPort(), 10);
    
    // Wait for a response or timeout
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    // Try for up to 10 seconds with multiple packets
    for (int attempt = 0; attempt < 5 && !success; ++attempt) {
        // Send another hole punching packet
        struct sockaddr_in destAddr;
        memset(&destAddr, 0, sizeof(destAddr));
        destAddr.sin_family = AF_INET;
        destAddr.sin_addr.s_addr = inet_addr(target->getIP().c_str());
        destAddr.sin_port = htons(target->getPort());
        
        std::string msg = "STUN_CONNECT " + ourPublicIP + ":" + std::to_string(ourPublicPort);
        sendto(sockfd, msg.c_str(), msg.length(), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
        
        // Wait for a response
        if (poll(&pfd, 1, 2000) > 0) { // 2 second timeout per attempt
            char buffer[1024];
            struct sockaddr_in fromAddr;
            socklen_t fromLen = sizeof(fromAddr);
            
            int bytesRead = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                
                // Verify the response is from the target
                char fromIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &fromAddr.sin_addr, fromIP, sizeof(fromIP));
                
                if (std::string(fromIP) == target->getIP() &&
                    ntohs(fromAddr.sin_port) == target->getPort()) {
                    success = true;
                    break;
                }
            }
        }
        
        // Short delay before next attempt
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    close(sockfd);
    return success;
}

bool HolePuncher::attemptTCPHolePunch(const NodePtr& target) {
    // TCP hole punching requires both peers to attempt connections simultaneously
    // This implementation uses a more sophisticated approach with both listening and connecting
    
    // Get our public endpoint
    std::string ourPublicIP;
    uint16_t ourPublicPort;
    
    if (!getPublicEndpoint(ourPublicIP, ourPublicPort)) {
        return false;
    }
    
    // Create a listening socket
    int listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        return false;
    }
    
    // Set socket options
    int optval = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Set socket to non-blocking
    int flags = fcntl(listenSock, F_GETFL, 0);
    fcntl(listenSock, F_SETFL, flags | O_NONBLOCK);
    
    // Bind to a local port
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0); // Let the OS choose a port
    
    if (bind(listenSock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        close(listenSock);
        return false;
    }
    
    // Start listening
    if (listen(listenSock, 5) < 0) {
        close(listenSock);
        return false;
    }
    
    // Get the local port we're listening on
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(listenSock, (struct sockaddr*)&localAddr, &addrLen) < 0) {
        close(listenSock);
        return false;
    }
    
    uint16_t localPort = ntohs(localAddr.sin_port);
    
    // Create a connecting socket
    int connectSock = socket(AF_INET, SOCK_STREAM, 0);
    if (connectSock < 0) {
        close(listenSock);
        return false;
    }
    
    // Set socket to non-blocking
    flags = fcntl(connectSock, F_GETFL, 0);
    fcntl(connectSock, F_SETFL, flags | O_NONBLOCK);
    
    // Set up the destination address
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(target->getIP().c_str());
    destAddr.sin_port = htons(target->getPort());
    
    // Try to connect (this will likely fail initially, but it creates a hole in our NAT)
    connect(connectSock, (struct sockaddr*)&destAddr, sizeof(destAddr));
    
    // Set up poll for both sockets
    struct pollfd pfds[2];
    pfds[0].fd = listenSock;
    pfds[0].events = POLLIN;
    pfds[1].fd = connectSock;
    pfds[1].events = POLLOUT;
    
    bool success = false;
    int connectedSock = -1;
    
    // Try for up to 10 seconds
    for (int attempt = 0; attempt < 5 && !success; ++attempt) {
        // Poll both sockets
        if (poll(pfds, 2, 2000) > 0) { // 2 second timeout per attempt
            // Check if we have an incoming connection
            if (pfds[0].revents & POLLIN) {
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(clientAddr);
                int newSock = accept(listenSock, (struct sockaddr*)&clientAddr, &clientLen);
                
                if (newSock >= 0) {
                    // Verify the connection is from the target
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
                    
                    if (std::string(clientIP) == target->getIP()) {
                        connectedSock = newSock;
                        success = true;
                        break;
                    } else {
                        close(newSock);
                    }
                }
            }
            
            // Check if our outgoing connection succeeded
            if (pfds[1].revents & POLLOUT) {
                int error = 0;
                socklen_t len = sizeof(error);
                
                if (getsockopt(connectSock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                    connectedSock = connectSock;
                    success = true;
                    break;
                }
            }
        }
        
        // If we haven't succeeded yet, try another connect attempt
        if (!success) {
            close(connectSock);
            connectSock = socket(AF_INET, SOCK_STREAM, 0);
            if (connectSock < 0) {
                break;
            }
            
            flags = fcntl(connectSock, F_GETFL, 0);
            fcntl(connectSock, F_SETFL, flags | O_NONBLOCK);
            
            connect(connectSock, (struct sockaddr*)&destAddr, sizeof(destAddr));
            pfds[1].fd = connectSock;
            
            // Short delay before next attempt
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    // Clean up
    if (listenSock >= 0) close(listenSock);
    if (connectSock >= 0 && connectSock != connectedSock) close(connectSock);
    if (connectedSock >= 0) close(connectedSock);
    
    return success;
}

bool HolePuncher::isLocalConnection(const std::string& ip) {
    // Check if the IP is localhost or matches our local IP
    return ip == "127.0.0.1" ||
           ip == "localhost" ||
           ip == connectionInfo_.localIP ||
           ip == "::1";
}

bool HolePuncher::attemptLocalConnection(const std::string& ip, uint16_t port) {
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket options to allow address reuse
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    // Try to set SO_REUSEPORT if available (not available on all systems)
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    
    // Bind to a specific port (use a different port than the target)
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0);  // Let OS choose a port
    
    if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        close(sockfd);
        return false;
    }
    
    // Set up the destination address
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(ip.c_str());
    destAddr.sin_port = htons(port);
    
    // Send a test message
    const char* testMsg = "LOCAL_CONNECT";
    sendto(sockfd, testMsg, strlen(testMsg), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    
    // Wait for a response
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    bool success = false;
    
    // Try multiple times with a short timeout
    for (int attempt = 0; attempt < 5 && !success; ++attempt) {
        sendto(sockfd, testMsg, strlen(testMsg), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
        
        if (poll(&pfd, 1, 500) > 0) {  // 500ms timeout
            char buffer[1024];
            struct sockaddr_in fromAddr;
            socklen_t fromLen = sizeof(fromAddr);
            
            if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen) > 0) {
                success = true;
                break;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);
    return success;
}

} // namespace kademlia