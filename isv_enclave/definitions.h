#ifndef DEFS
#define DEFS

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

/*
 * values to be defined as environment variables given to makefile:
 * BLOCK_DATA_SIZE
 * NUM_BLOCKS_POW power of two up to which the number of blocks will go
 * TEST_TYPE - 1 = linear, encrypted, 2 = linear, unencrypted, 3 = oram
 *
 * those will determine which experiment the code is compiled to run
 *
*/
//temporary for testing
//#define BLOCK_DATA_SIZE 1000 //as big as possible, I got it working up to 8000000; seems to exhaust heap memory faster than expected; try on supported ubuntu box
//#define NUM_BLOCKS_POW 3
//#define TEST_TYPE 1

//made up parameters to use
#define ORAM_CAPACITY 32 //must be power of two, real number of nodes in tree is twice this minus 1
#define MAX_BRANCH 10 //should be log in size of B+-tree, right?
#define BUCKET_SIZE 4
#define NUM_STRUCTURES 10 //number of structures supported
#define MAX_COLS 20
#define NUM_BLOCKS_LINEAR 16
#define NUM_BLOCKS_ORAM 64
#define EXTRA_STASH_SPACE 90
//NUM_BLOCKS_ORAM is larger than the logical size of the oram;
//within the oram, there will be a B+-tree in whose leaves we will store the actual data
//so to match a linear scan structure with 16 blocks, we need 16 blocks of leaves in the B+-tree, meaning 31 nodes in the B+-tree
//for 31 nodes in the B+-tree, we need

typedef enum _Obliv_Type{
	TYPE_LINEAR_SCAN,
	TYPE_TREE_ORAM,
	TYPE_ORAM,
	TYPE_LINEAR_UNENCRYPTED,
} Obliv_Type;

typedef enum _DB_TYPE{
	INTEGER, //4 bytes
	TINYTEXT, //255 bytes
	CHAR, //1 byte
	FLOAT, //4 bytes
} DB_Type;

typedef struct{
	uint8_t data[BLOCK_DATA_SIZE];
} Linear_Scan_Block;

typedef struct{
	int actualAddr;
	int leafNum;
	int numChildren;
	int children[MAX_BRANCH];
	uint8_t data[BLOCK_DATA_SIZE];
} Oram_Tree_Block;

typedef struct{
	int actualAddr;
	//int leafNum;
	uint8_t data[BLOCK_DATA_SIZE];
} Oram_Block;

typedef struct{
	Oram_Block blocks[BUCKET_SIZE];
} Oram_Bucket;

typedef struct{
	uint8_t ciphertext[sizeof(Oram_Bucket)]; //sizeof(Oram_Bucket)
	uint8_t macTag[16]; //16 bytes
	uint8_t iv[12]; //12 bytes
}Encrypted_Oram_Bucket;

typedef struct{
	uint8_t ciphertext[sizeof(Linear_Scan_Block)]; //sizeof(Oram_Tree_Block)
	uint8_t macTag[16]; //16 bytes
	uint8_t iv[12]; //12 bytes
} Encrypted_Linear_Scan_Block;

typedef struct{
	uint8_t ciphertext[sizeof(Oram_Tree_Block)]; //sizeof(Oram_Tree_Block)
	uint8_t macTag[16]; //16 bytes
	uint8_t iv[12]; //12 bytes
} Encrypted_Oram_Tree_Block;

typedef struct{
	uint8_t ciphertext[sizeof(Oram_Block)]; //sizeof(Oram_Tree_Block)
	uint8_t macTag[16]; //16 bytes
	uint8_t iv[12]; //12 bytes
} Encrypted_Oram_Block;

typedef struct{
	int numFields;
	int fieldOffsets[MAX_COLS];
	int fieldSizes[MAX_COLS];
	DB_Type fieldTypes[MAX_COLS];
	int index;//this is structNum
} Schema;



int getEncBlockSize(Obliv_Type type);
int getBlockSize(Obliv_Type type);
int getDBTypeSize(DB_Type type);
int getRowSize(Schema *schema);
#endif
