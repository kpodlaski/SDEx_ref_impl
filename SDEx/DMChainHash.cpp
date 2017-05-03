#include "stdafx.h"
#include "DMChainHash.h"
#include "Hash.h"
#include <iostream>

void DMChainHash::updateInitVector() {
	// IV -> IV XOR LAST_HASH
	/*if (((int) _iteration_count) < 10) std::cout << "UPDATE" << _iteration_count << std::endl;
	  if (((int)_iteration_count) == 0) {
		std::cout << "POdmieniam iv:" << std::endl;
		_next_init_vector[0] = 0x67e6096a; 
		_next_init_vector[1] = 0x85ae67bb;
		_next_init_vector[2] = 0x72f36e3c;
		_next_init_vector[3] = 0x3af54fa5;
		_next_init_vector[4] = 0x7f520e51;
		_next_init_vector[5] = 0x8c68059b;
		_next_init_vector[6] = 0xabd9831f;
		_next_init_vector[7] = 0x19cde05b;

	}*/
	
	

	unsigned char * _niv = (unsigned char *)_next_init_vector;
	unsigned char * _lh = (unsigned char *)_last_hash;
	//std::cout << "Iteration : " << _iteration_count << std::endl;
	for (int i = 0; i < hash->IV_SIZE; i++) {
		_next_init_vector[i] = _next_init_vector[i] ^ _last_hash[i];
		//_niv[i] = _niv[i] ^ _lh[i];
	}

}


DMChainHash::DMChainHash(Hash * _hash) : ChainHash(_hash)
{
}


DMChainHash::~DMChainHash()
{
}
