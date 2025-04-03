#include "../include/routing_table.h"
#include "../include/utils.h"
#include <algorithm>

namespace kademlia {

// KBucket implementation
KBucket::KBucket() : mutex_(std::make_shared<std::mutex>()) {}

KBucket::KBucket(const KBucket& other) : nodes_(other.nodes_), mutex_(std::make_shared<std::mutex>()) {}

KBucket::KBucket(KBucket&& other) noexcept : nodes_(std::move(other.nodes_)), mutex_(std::move(other.mutex_)) {}

KBucket& KBucket::operator=(const KBucket& other) {
    if (this != &other) {
        nodes_ = other.nodes_;
        mutex_ = std::make_shared<std::mutex>();
    }
    return *this;
}

KBucket& KBucket::operator=(KBucket&& other) noexcept {
    if (this != &other) {
        nodes_ = std::move(other.nodes_);
        mutex_ = std::move(other.mutex_);
    }
    return *this;
}

bool KBucket::addNode(const NodePtr& node) {
    std::lock_guard<std::mutex> lock(*mutex_);
    
    // Check if the node is already in the bucket
    auto it = std::find_if(nodes_.begin(), nodes_.end(),
        [&node](const NodePtr& n) {
            return n->getID() == node->getID();
        });
    
    if (it != nodes_.end()) {
        // Node already exists, move it to the end (most recently seen)
        nodes_.erase(it);
        nodes_.push_back(node);
        return true;
    }
    
    // If the bucket is not full, add the node
    if (nodes_.size() < K_VALUE) {
        nodes_.push_back(node);
        return true;
    }
    
    // Bucket is full, check if the least recently seen node is still active
    NodePtr leastRecentNode = nodes_.front();
    if (!leastRecentNode->isActive()) {
        // Replace the inactive node
        nodes_.pop_front();
        nodes_.push_back(node);
        return true;
    }
    
    // Bucket is full and all nodes are active
    return false;
}

bool KBucket::removeNode(const NodeID& id) {
    std::lock_guard<std::mutex> lock(*mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(),
        [&id](const NodePtr& n) {
            return n->getID() == id;
        });
    
    if (it != nodes_.end()) {
        nodes_.erase(it);
        return true;
    }
    
    return false;
}

NodePtr KBucket::getNode(const NodeID& id) const {
    std::lock_guard<std::mutex> lock(*mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(),
        [&id](const NodePtr& n) {
            return n->getID() == id;
        });
    
    if (it != nodes_.end()) {
        return *it;
    }
    
    return nullptr;
}

std::vector<NodePtr> KBucket::getNodes() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return std::vector<NodePtr>(nodes_.begin(), nodes_.end());
}

bool KBucket::isFull() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return nodes_.size() >= K_VALUE;
}

size_t KBucket::size() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return nodes_.size();
}

// RoutingTable implementation
RoutingTable::RoutingTable(const NodeID& localID) : localID_(localID) {
    // Initialize buckets (one for each bit in the key)
    buckets_.resize(KEY_BITS);
}

bool RoutingTable::addNode(const NodePtr& node) {
    // Don't add the local node to the routing table
    if (node->getID() == localID_) {
        return false;
    }
    
    size_t bucketIndex = getBucketIndex(node->getID());
    return buckets_[bucketIndex].addNode(node);
}

bool RoutingTable::removeNode(const NodeID& id) {
    size_t bucketIndex = getBucketIndex(id);
    return buckets_[bucketIndex].removeNode(id);
}

std::vector<NodePtr> RoutingTable::findClosestNodes(const NodeID& id, size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodePtr> closestNodes;
    
    // Collect all nodes from all buckets
    for (const auto& bucket : buckets_) {
        auto nodes = bucket.getNodes();
        closestNodes.insert(closestNodes.end(), nodes.begin(), nodes.end());
    }
    
    // Sort nodes by distance to the target ID
    closestNodes = utils::sortNodesByDistance(closestNodes, id);
    
    // Limit the number of nodes
    if (closestNodes.size() > count) {
        closestNodes.resize(count);
    }
    
    return closestNodes;
}

NodePtr RoutingTable::getNode(const NodeID& id) const {
    size_t bucketIndex = getBucketIndex(id);
    return buckets_[bucketIndex].getNode(id);
}

std::vector<NodePtr> RoutingTable::getAllNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodePtr> allNodes;
    
    for (const auto& bucket : buckets_) {
        auto nodes = bucket.getNodes();
        allNodes.insert(allNodes.end(), nodes.begin(), nodes.end());
    }
    
    return allNodes;
}

size_t RoutingTable::getBucketIndex(const NodeID& id) const {
    // Calculate the XOR distance between the local ID and the given ID
    NodeID distance = localID_.distance(id);
    
    // Find the index of the first bit that is 1 (from left to right)
    for (size_t i = 0; i < KEY_BITS; ++i) {
        if (distance.getBit(i)) {
            return i;
        }
    }
    
    // If all bits are 0, use the last bucket
    return KEY_BITS - 1;
}

const NodeID& RoutingTable::getLocalID() const {
    return localID_;
}

} // namespace kademlia