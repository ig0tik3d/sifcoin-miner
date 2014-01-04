#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"


/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context 	blake1;
	sph_bmw512_context		bmw1;
	sph_groestl512_context	groestl1;
	sph_skein512_context	skein1;
	sph_jh512_context		jh1;
	sph_keccak512_context	keccak1;
} sifhash_context_holder;

sifhash_context_holder base_contexts;

void init_sifhash_contexts()
{
    sph_blake512_init(&base_contexts.blake1);
    sph_bmw512_init(&base_contexts.bmw1);
    sph_groestl512_init(&base_contexts.groestl1);
    sph_skein512_init(&base_contexts.skein1);
   // sph_groestl512_init(&base_contexts.groestl2);
    sph_jh512_init(&base_contexts.jh1);	
   // sph_blake512_init(&base_contexts.blake2);	
   // sph_bmw512_init(&base_contexts.bmw2);	
    sph_keccak512_init(&base_contexts.keccak1);	
   // sph_skein512_init(&base_contexts.skein2);
   // sph_keccak512_init(&base_contexts.keccak2);
    //sph_jh512_init(&base_contexts.jh2);	
}

static void sifhash(void *state, const void *input)
{

	sifhash_context_holder ctx;

    uint32_t mask = 8;
    uint32_t zero = 0;

	
    uint32_t hashA[16], hashB[16];	
	

	
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	

    sph_blake512 (&ctx.blake1, input, 80);
    sph_blake512_close (&ctx.blake1, hashA);	 //0
	

    sph_bmw512 (&ctx.bmw1, hashA, 64);    //0
    sph_bmw512_close(&ctx.bmw1, hashB);   //1
	
  
     sph_groestl512 (&ctx.groestl1, hashB, 64); //1
     sph_groestl512_close(&ctx.groestl1, hashA); //2
   
    sph_jh512 (&ctx.jh1, hashA, 64); //3
    sph_jh512_close(&ctx.jh1, hashB); //4

  
    sph_keccak512 (&ctx.keccak1, hashB, 64); //5
    sph_keccak512_close(&ctx.keccak1, hashA); //6


    sph_skein512 (&ctx.skein1, hashA, 64); //6
    sph_skein512_close(&ctx.skein1, hashB); //7

	memcpy(state, hashB, 32);
	
}

int scanhash_sif(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{

     uint32_t n = pdata[19] - 1;
        const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];
        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];
        
         
        int kk=0;
        for (; kk < 32; kk++)
        {
                be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
        };

        
        
        do {
        
                pdata[19] = ++n;
                be32enc(&endiandata[19], n);
                sifhash(hash64, &endiandata);
        if (((hash64[7]&0xFFFFFF00)==0) &&
                                fulltest(hash64, ptarget)) {
            *hashes_done = n - first_nonce + 1;
                        return true;
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);
        
        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}




































