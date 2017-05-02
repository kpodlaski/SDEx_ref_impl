#include "sha256.h"

class SDExSHA256 : SHA256
{
protected:
	uint32 last_h[8];
public:

	SDExSHA256();
	~SDExSHA256();
};

std::string SDExsha256(std::string input);
