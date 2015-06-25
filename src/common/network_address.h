#pragma once

#include "common/platform.h"

#include <arpa/inet.h>
#include <functional>
#include <sstream>

#include "common/serialization.h"

struct NetworkAddress {
	struct in6_addr *ip;
	uint16_t port;

	NetworkAddress(struct in6_addr *ip, uint16_t port) : ip(ip), port(port) {
	}

	NetworkAddress() : ip(0), port(0) {
	}

	bool operator<(const NetworkAddress& rhs) const {
		return std::make_pair(ip, port) < std::make_pair(rhs.ip, rhs.port);
	}

	bool operator==(const NetworkAddress& rhs) const {
		return std::make_pair(ip, port) == std::make_pair(rhs.ip, rhs.port);
	}

	std::string toString() const {
		//std::stringstream ss;
		//for (int i = 24; i >= 0; i -= 8) {
		//	ss << ((ip >> i) & 0xff) << (i > 0 ? "." : "");
		//}
		//if (port > 0) {
		//	ss << ":" << port;
		//}
                const std::string foo = "toString() has not been implemented yet!";
		//return ss.str();
                return foo;
	}
};

inline uint32_t serializedSize(const NetworkAddress& server) {
	return serializedSize(server.ip, server.port);
}

inline void serialize(uint8_t** destination, const NetworkAddress& server) {
	return serialize(destination, server.ip, server.port);
}

inline void deserialize(const uint8_t** source, uint32_t& bytesLeftInBuffer,
		NetworkAddress& server) {
	deserialize(source, bytesLeftInBuffer, server.ip, server.port);
}

namespace std {
template <>
struct hash<NetworkAddress> {
	size_t operator()(const NetworkAddress& address) const {
		// MooseFS CSDB hash function
                //!!! Keep in mind!
                unsigned char ipv6_end[4];
                ipv6_end[0] = address.ip->s6_addr[12];
                ipv6_end[1] = address.ip->s6_addr[13];
                ipv6_end[2] = address.ip->s6_addr[14];
                ipv6_end[3] = address.ip->s6_addr[15];
                int hash_salt;
                hash_salt = ipv6_end[0] | (ipv6_end[1] << 8) | (ipv6_end[2] << 16) | (ipv6_end[3] << 24);
		return hash_salt * 0x7b348943 + address.port;
	}
};
}
