#pragma once

#include "node.h"
#include <list>
#include <vector>
#include <mutex>
#include <memory>

namespace kademlia {

// K value for k-buckets (maximum number of nodes per bucket)
constexpr size_t K_VALUE = 20;

/**
 * @brief KBucket class representing a k-bucket in the routing table
 */
class KBucket {
public:
    KBucket();
    
    // Copy constructor
    KBucket(const KBucket& other);
    
    // Move constructor
    KBucket(KBucket&& other) noexcept;
    
    // Copy assignment operator
    KBucket& operator=(const KBucket& other);
    
    // Move assignment operator
    KBucket& operator=(KBucket&& other) noexcept;
    
    // Add a node to the bucket
    bool addNode(const NodePtr& node);
    
    // Remove a node from the bucket
    bool removeNode(const NodeID& id);
    
    // Get a node by ID
    NodePtr getNode(const NodeID& id) const;
    
    // Get all nodes in the bucket
    std::vector<NodePtr> getNodes() const;
    
    // Check if the bucket is full
    bool isFull() const;
    
    // Get the number of nodes in the bucket
    size_t size() const;

private:
    std::list<NodePtr> nodes_;
    std::shared_ptr<std::mutex> mutex_;
};

/**
 * @brief RoutingTable class implementing the Kademlia routing table
 */
class RoutingTable {
public:
    explicit RoutingTable(const NodeID& localID);
    
    // Add a node to the routing table
    bool addNode(const NodePtr& node);
    
    // Remove a node from the routing table
    bool removeNode(const NodeID& id);
    
    // Find the k closest nodes to the given ID
    std::vector<NodePtr> findClosestNodes(const NodeID& id, size_t count = K_VALUE) const;
    
    // Get a node by ID
    NodePtr getNode(const NodeID& id) const;
    
    // Get all nodes in the routing table
    std::vector<NodePtr> getAllNodes() const;
    
    // Get the bucket index for a given node ID
    size_t getBucketIndex(const NodeID& id) const;
    
    // Get the local node ID
    const NodeID& getLocalID() const;

private:
    NodeID localID_;
    std::vector<KBucket> buckets_;
    mutable std::mutex mutex_;
};

} // namespace kademlia