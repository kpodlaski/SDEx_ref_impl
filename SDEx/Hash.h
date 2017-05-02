#ifndef HASH_H
#define HASH_H
#include <string>

class Hash
{
protected:
	typedef unsigned char uint8;
	typedef unsigned int uint32;
	typedef unsigned long long uint64;
	
	
public:
	virtual void init()=0;
	virtual void init(uint32 * iv, int iv_size)=0;
	virtual void update(const unsigned char *message, unsigned int len)=0;
	virtual void final(unsigned char *digest)=0;
	virtual ~Hash() {};
	Hash(unsigned int _digest_size);
	const unsigned int DIGEST_SIZE = (256 / 8);
	int IV_SIZE = 8; //for sha2
	std::string digest_to_string(unsigned char *digest);
	virtual uint32 * init_vector() = 0;

}; 

#endif
