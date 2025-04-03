#include "../include/dht_key.h"
#include "../include/utils.h"
#include <sstream>
#include <iomanip>

namespace kademlia {

DHTKey::DHTKey() {}

DHTKey::DHTKey(const std::vector<uint8_t>& data) : data_(data) {}

DHTKey::DHTKey(const std::string& str) {
    // Convert string to bytes
    for (char c : str) {
        data_.push_back(static_cast<uint8_t>(c));
    }
}

const std::vector<uint8_t>& DHTKey::getData() const {
    return data_;
}

std::string DHTKey::toString() const {
    std::stringstream ss;
    
    // If the data contains only printable ASCII characters, return as string
    bool allPrintable = true;
    for (auto byte : data_) {
        if (byte < 32 || byte > 126) {
            allPrintable = false;
            break;
        }
    }
    
    if (allPrintable && !data_.empty()) {
        for (auto byte : data_) {
            ss << static_cast<char>(byte);
        }
    } else {
        // Otherwise, return as hex
        ss << "0x";
        ss << std::hex << std::setfill('0');
        for (auto byte : data_) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
    }
    
    return ss.str();
}

bool DHTKey::operator==(const DHTKey& other) const {
    return data_ == other.data_;
}

bool DHTKey::operator!=(const DHTKey& other) const {
    return !(*this == other);
}

} // namespace kademlia