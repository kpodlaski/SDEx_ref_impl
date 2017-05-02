#include "stdafx.h"
#include "DMChainHash.h"
#include "Hash.h"

void DMChainHash::updateInitVector() {
	// IV -> IV XOR LAST_HASH
	for (int i = 0; i < hash->IV_SIZE; i++) {
		_next_init_vector[i] = _next_init_vector[i] ^ _last_hash[i];
	}

}


DMChainHash::DMChainHash(Hash * _hash) : ChainHash(_hash)
{
}


DMChainHash::~DMChainHash()
{
}
