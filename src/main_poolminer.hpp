#if defined(__MINGW64__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <cstring>

extern "C" {
#include "sph_sha2.h"
}
#ifdef	__x86_64__
#include "sha512.h"
#endif

enum SHAMODE { SPHLIB = 0, AVXSSE };

typedef struct {
  // comments: BYTES <index> + <length>
  int32_t nVersion;            // 0+4
  uint8_t hashPrevBlock[32];       // 4+32
  uint8_t hashMerkleRoot[32];      // 36+32
  uint32_t  nTime;               // 68+4
  uint32_t  nBits;               // 72+4
  uint32_t  nNonce;              // 76+4
  uint32_t  birthdayA;          // 80+32+4 (uint32_t)
  uint32_t  birthdayB;          // 84+32+4 (uint32_t)
  uint8_t   targetShare[32];
} blockHeader_t;              // = 80+32+8 bytes header (80 default + 8 birthdayA&B + 32 target)

class CBlockProvider {
public:
	CBlockProvider() { }
	~CBlockProvider() { }
	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) = 0;
	virtual blockHeader_t* getOriginalBlock() = 0;
	virtual void setBlockTo(blockHeader_t* newblock) = 0;
	virtual void submitBlock(blockHeader_t* block, unsigned int thread_id) = 0;
	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) = 0;
};

volatile uint64_t totalCollisionCount = 0;
volatile uint64_t totalShareCount = 0;

#define MAX_MOMENTUM_NONCE (1<<26) // 67.108.864
#define SEARCH_SPACE_BITS  50
#define BIRTHDAYS_PER_HASH 8

void print256(const char* bfstr, uint32_t* v) {
	std::stringstream ss;
	for(ptrdiff_t i=7; i>=0; --i)
		ss << std::setw(8) << std::setfill('0') << std::hex << v[i];
    ss.flush();
    std::cout << bfstr << ": " << ss.str().c_str() << std::endl;
}

template<SHAMODE shamode>
bool protoshares_revalidateCollision(blockHeader_t* block, uint8_t* midHash, uint32_t indexA, uint32_t indexB, CBlockProvider* bp, unsigned int thread_id)
{
        //if( indexA > MAX_MOMENTUM_NONCE )
        //        printf("indexA out of range\n");
        //if( indexB > MAX_MOMENTUM_NONCE )
        //        printf("indexB out of range\n");
        //if( indexA == indexB )
        //        printf("indexA == indexB");
        uint8_t tempHash[32+4];
        uint64_t resultHash[8];
        memcpy(tempHash+4, midHash, 32);
		uint64_t birthdayA, birthdayB;
#ifdef	__x86_64__
		if (shamode == AVXSSE) {
			// get birthday A
			*(uint32_t*)tempHash = indexA&~7;
			//AVX/SSE			
			SHA512_Context c512_avxsse;
			SHA512_Init(&c512_avxsse);
			SHA512_Update(&c512_avxsse, tempHash, 32+4);
			SHA512_Final(&c512_avxsse, (unsigned char*)resultHash);
			birthdayA = resultHash[ptrdiff_t(indexA&7)] >> (64ULL-SEARCH_SPACE_BITS);
			// get birthday B
			*(uint32_t*)tempHash = indexB&~7;
			SHA512_Init(&c512_avxsse);
			SHA512_Update(&c512_avxsse, tempHash, 32+4);
			SHA512_Final(&c512_avxsse, (unsigned char*)resultHash);
			birthdayB = resultHash[ptrdiff_t(indexB&7)] >> (64ULL-SEARCH_SPACE_BITS);
		} else {
#endif
			// get birthday A
			*(uint32_t*)tempHash = indexA&~7;
			//SPH
			sph_sha512_context c512_sph;
			sph_sha512_init(&c512_sph);
			sph_sha512(&c512_sph, tempHash, 32+4);
			sph_sha512_close(&c512_sph, (unsigned char*)resultHash);
			birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
			// get birthday B
			*(uint32_t*)tempHash = indexB&~7;
			sph_sha512_init(&c512_sph);
			sph_sha512(&c512_sph, tempHash, 32+4);
			sph_sha512_close(&c512_sph, (unsigned char*)resultHash);
			birthdayB = resultHash[ptrdiff_t(indexB&7)] >> (64ULL-SEARCH_SPACE_BITS);
#ifdef	__x86_64__
		}
#endif
        if( birthdayA != birthdayB )
        {
                return false; // invalid collision
        }
        // birthday collision found
        totalCollisionCount += 2; // we can use every collision twice -> A B and B A (srsly?)
        //printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
        
		sph_sha256_context c256; //SPH
		
		// get full block hash (for A B)
        block->birthdayA = indexA;
        block->birthdayB = indexB;
        uint8_t proofOfWorkHash[32];        
		//SPH
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        bool hashMeetsTarget = true;
        uint32_t* generatedHash32 = (uint32_t*)proofOfWorkHash;
        uint32_t* targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
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
			bp->submitBlock(block, thread_id);
		
        // get full block hash (for B A)
        block->birthdayA = indexB;
        block->birthdayB = indexA;
		//SPH
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)block, 80+8);
		sph_sha256_close(&c256, proofOfWorkHash);
		sph_sha256_init(&c256);
		sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
		sph_sha256_close(&c256, proofOfWorkHash);
        hashMeetsTarget = true;
        generatedHash32 = (uint32_t*)proofOfWorkHash;
        targetHash32 = (uint32_t*)block->targetShare;
        for(uint64_t hc=7; hc!=0; hc--)
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
			bp->submitBlock(block, thread_id);

		return true;
}

#define CACHED_HASHES         (32)

template<int COLLISION_TABLE_SIZE, int COLLISION_KEY_MASK, SHAMODE shamode>
void protoshares_process_512(blockHeader_t* block, uint32_t* collisionIndices, CBlockProvider* bp, unsigned int thread_id)
{
        // generate mid hash using sha256 (header hash)
		blockHeader_t* ob = bp->getOriginalBlock();
        uint8_t midHash[32];
		{
			//SPH
			sph_sha256_context c256;
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)block, 80);
			sph_sha256_close(&c256, midHash);
			sph_sha256_init(&c256);
			sph_sha256(&c256, (unsigned char*)midHash, 32);
			sph_sha256_close(&c256, midHash);
		}
        memset(collisionIndices, 0x00, sizeof(uint32_t)*COLLISION_TABLE_SIZE);
        // start search
        uint8_t tempHash[32+4];
#ifdef	__x86_64__
		SHA512_Context c512_avxsse; //AVX/SSE
#endif
		sph_sha512_context c512_sph; //SPH
        uint64_t resultHashStorage[8*CACHED_HASHES];
        memcpy(tempHash+4, midHash, 32);
		
        for(uint32_t n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
        {
                for(uint32_t m=0; m<CACHED_HASHES; m++)
                {
                        *(uint32_t*)tempHash = n+m*8;
						//AVX/SSE
#ifdef	__x86_64__
						if (shamode == AVXSSE) {
						SHA512_Init(&c512_avxsse);
						SHA512_Update(&c512_avxsse, tempHash, 32+4);
						SHA512_Final(&c512_avxsse, (unsigned char*)(resultHashStorage+8*m));
						} else {
#endif
						//SPH
						sph_sha512_init(&c512_sph);
						sph_sha512(&c512_sph, tempHash, 32+4);
						sph_sha512_close(&c512_sph, (unsigned char*)(resultHashStorage+8*m));
#ifdef	__x86_64__
						}
#endif
                }
                for(uint32_t m=0; m<CACHED_HASHES; m++)
                {
                        uint64_t* resultHash = resultHashStorage + 8*m;
                        uint32_t i = n + m*8;
                        for(uint32_t f=0; f<8; f++)
                        {
                                uint64_t birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
                                uint32_t collisionKey = (uint32_t)((birthday>>18) & COLLISION_KEY_MASK);
                                birthday %= COLLISION_TABLE_SIZE;
								if( collisionIndices[birthday] )
                                {
                                        if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) ||
										    protoshares_revalidateCollision<shamode>(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f, bp, thread_id) == false )
                                        {
                                                // invalid collision -> ignore or mark this entry as invalid?
                                        }
                                }
                                collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
								if (ob != bp->getOriginalBlock()) return;
                        }
                }
        }
}
