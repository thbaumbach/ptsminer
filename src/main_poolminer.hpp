#if defined(__MINGW64__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <cstring>

#include "sha2.h"

typedef int sint32;

typedef struct {
  // comments: BYTES <index> + <length>
  sint32 nVersion;            // 0+4
  uint8 hashPrevBlock[32];       // 4+32
  uint8 hashMerkleRoot[32];      // 36+32
  uint32  nTime;               // 68+4
  uint32  nBits;               // 72+4
  uint32  nNonce;              // 76+4
  uint32  birthdayA;          // 80+32+4 (uint32_t)
  uint32  birthdayB;          // 84+32+4 (uint32_t)
  uint8   targetShare[32];
} blockHeader_t;              // = 80+32+8 bytes header (80 default + 8 birthdayA&B + 32 target)

class CBlockProvider {
public:
	CBlockProvider() { }
	~CBlockProvider() { }
	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time) = 0;
	virtual blockHeader_t* getOriginalBlock() = 0;
	virtual void submitBlock(blockHeader_t* block) = 0;
	virtual void forceReconnect() = 0;
	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) = 0;
};

volatile uint64 totalCollisionCount = 0;
volatile uint64 totalShareCount = 0;

#define MAX_MOMENTUM_NONCE (1<<26) // 67.108.864
#define SEARCH_SPACE_BITS  50
#define BIRTHDAYS_PER_HASH 8

void print256(const char* bfstr, uint32* v) {
	std::stringstream ss;
	for(ptrdiff_t i=7; i>=0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << v[i];
    ss.flush();
    std::cout << bfstr << " " << ss.str().c_str() << std::endl;
}

bool protoshares_revalidateCollision(blockHeader_t* block, uint8* midHash, uint32 indexA, uint32 indexB, CBlockProvider* bp)
{
        //if( indexA > MAX_MOMENTUM_NONCE )
        //        printf("indexA out of range\n");
        //if( indexB > MAX_MOMENTUM_NONCE )
        //        printf("indexB out of range\n");
        //if( indexA == indexB )
        //        printf("indexA == indexB");
        uint8 tempHash[32+4];
        uint64 resultHash[8];
        memcpy(tempHash+4, midHash, 32);
        // get birthday A
        *(uint32*)tempHash = indexA&~7;
        sha512_ctx c512;
        sha512_init(&c512);
        sha512_update(&c512, tempHash, 32+4);
        sha512_final(&c512, (unsigned char*)resultHash);
        uint64 birthdayA = resultHash[ptrdiff_t(indexA&7)] >> (64ULL-SEARCH_SPACE_BITS);
        // get birthday B
        *(uint32*)tempHash = indexB&~7;
        sha512_init(&c512);
        sha512_update(&c512, tempHash, 32+4);
        sha512_final(&c512, (unsigned char*)resultHash);
        uint64 birthdayB = resultHash[ptrdiff_t(indexB&7)] >> (64ULL-SEARCH_SPACE_BITS);
        if( birthdayA != birthdayB )
        {
                return false; // invalid collision
        }
        // birthday collision found
        totalCollisionCount += 2; // we can use every collision twice -> A B and B A (srsly?)
        //printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
        
		sha256_ctx c256;
		
		// get full block hash (for A B)
        block->birthdayA = indexA;
        block->birthdayB = indexB;
        uint8 proofOfWorkHash[32];        
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)block, 80+8);
        sha256_final(&c256, proofOfWorkHash);
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
        sha256_final(&c256, proofOfWorkHash);
        bool hashMeetsTarget = true;
        uint32* generatedHash32 = (uint32*)proofOfWorkHash;
        uint32* targetHash32 = (uint32*)block->targetShare;
        for(ptrdiff_t hc=7; hc>=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
        {
                totalShareCount++;
				bp->submitBlock(block);
        }
        // get full block hash (for B A)
        block->birthdayA = indexB;
        block->birthdayB = indexA;
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)block, 80+8);
        sha256_final(&c256, proofOfWorkHash);
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
        sha256_final(&c256, proofOfWorkHash);
        hashMeetsTarget = true;
        generatedHash32 = (uint32*)proofOfWorkHash;
        targetHash32 = (uint32*)block->targetShare;
        for(ptrdiff_t hc=7; hc>=0; hc--)
        {
                if( generatedHash32[hc] < targetHash32[hc] )
                {
                        hashMeetsTarget = true;
                        break;
                }
                else if( generatedHash32[hc] > targetHash32[hc] )
                {
                        hashMeetsTarget = false;
                        break;
                }
        }
        if( hashMeetsTarget )
        {
                totalShareCount++;
				bp->submitBlock(block);
        }
        return true;
}

#define CACHED_HASHES         (32)
#define COLLISION_TABLE_BITS  (27)
#define COLLISION_TABLE_SIZE  (1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH   (32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK	  (0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

void protoshares_process_512(blockHeader_t* block, uint32* collisionIndices, CBlockProvider* bp)
{
		//print256("share target", (uint32*)block->targetShare);
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8 midHash[32];
        sha256_ctx c256;
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)block, 80);
        sha256_final(&c256, midHash);
		//print256("midHash1", (uint32*)midHash);
        sha256_init(&c256);
        sha256_update(&c256, (unsigned char*)midHash, 32);
        sha256_final(&c256, midHash);
		//print256("midHash2", (uint32*)midHash);
        // init collision map
        //if( __collisionMap == NULL )
        //        __collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
        memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
        // start search
        // uint8 midHash[64];
        uint8 tempHash[32+4];
        sha512_ctx c512;
        uint64 resultHashStorage[8*CACHED_HASHES];
        memcpy(tempHash+4, midHash, 32);
		
        for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
        {
                // generate hash (birthdayA)
                //sha512_init(&c512);
                //sha512_update(&c512, tempHash, 32+4);
                //sha512_final(&c512, (unsigned char*)resultHash);
                //sha512(tempHash, 32+4, (unsigned char*)resultHash);
                for(uint32 m=0; m<CACHED_HASHES; m++)
                {
                        sha512_init(&c512);
                        *(uint32*)tempHash = n+m*8;
                        sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
						//sha512_update(&c512, tempHash, 32+4);
						//sha512_final((unsigned char*)(resultHashStorage+8*m), &c512);
                }
                for(uint32 m=0; m<CACHED_HASHES; m++)
                {
                        uint64* resultHash = resultHashStorage + 8*m;
                        uint32 i = n + m*8;
                        //uint64 resultHash2[8];
                        //sha512_init(&c512);
                        //sha512_update(&c512, tempHash, 32+4);
                        //sha512_final(&c512, (unsigned char*)resultHash);
                        //sha512(tempHash, 32+4, (unsigned char*)resultHash2);
                        //if( memcmp(resultHash, resultHash2, sizeof(resultHash2)) )
                        //        __debugbreak();
                        for(uint32 f=0; f<8; f++)
                        {
                                uint64 birthday = resultHash[ptrdiff_t(f)] >> (64ULL-SEARCH_SPACE_BITS);
                                uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
                                birthday %= COLLISION_TABLE_SIZE;
								if( collisionIndices[ptrdiff_t(birthday)] )
                                {
                                        if( ((collisionIndices[ptrdiff_t(birthday)]&COLLISION_KEY_MASK) != collisionKey) ||
										    protoshares_revalidateCollision(block, midHash, collisionIndices[ptrdiff_t(birthday)]&~COLLISION_KEY_MASK, i+f, bp) == false )
                                        {
                                                // invalid collision -> ignore
                                                // todo: Maybe mark this entry as invalid?
                                        }
                                }
                                collisionIndices[ptrdiff_t(birthday)] = i+f | collisionKey; // we have 6 bits available for validation
								if (ob != bp->getOriginalBlock()) return;
                        }
                }
        }
}
