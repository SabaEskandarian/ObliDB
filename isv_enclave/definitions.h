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


#define BLOCK_DATA_SIZE 512 //as big as possible, I got it working up to 8000000; seems to exhaust heap memory faster than expected; try on supported ubuntu box
#define NUM_BLOCKS_POW 10
#define TEST_TYPE 1

//made up parameters to use
#define BUCKET_SIZE 4
#define NUM_STRUCTURES 10 //number of structures supported
#define MAX_COLS 20
#define EXTRA_STASH_SPACE 90
#define MAX_CONDITIONS 5
#define ROWS_IN_ENCLAVE 20
#define PERCENT_ALMOST_ALL 90
#define MAX_GROUPS 5
//NUM_BLOCKS_ORAM is larger than the logical size of the oram;
//within the oram, there will be a B+-tree in whose leaves we will store the actual data
//so to match a linear scan structure with 16 blocks, we need 16 blocks of leaves in the B+-tree, meaning 31 nodes in the B+-tree
//for 31 nodes in the B+-tree, we need

#define MAX_ORDER 20

typedef enum _Obliv_Type{
	TYPE_LINEAR_SCAN,
	TYPE_TREE_ORAM,
	TYPE_ORAM,
	TYPE_LINEAR_UNENCRYPTED,
} Obliv_Type;

typedef struct{
	uint8_t data[BLOCK_DATA_SIZE];
} Linear_Scan_Block;

typedef struct{
	int actualAddr;
	int leafNum;
	int numChildren;
	int children[MAX_ORDER];
	uint8_t data[BLOCK_DATA_SIZE];
} Oram_Tree_Block;

typedef struct{
	int actualAddr;
	//int leafNum;
	uint8_t data[BLOCK_DATA_SIZE];
} Oram_Block;

typedef struct{ //for compatibility with bplustree, same as Oram_Block
	int actualAddr;
	//int leafNum;
	uint8_t data[BLOCK_DATA_SIZE];
} record;

typedef struct node { //size 8*MAX_ORDER + 16 = currently 176, which wastes a lot of space, but oh well
	//void ** pointers;
	int actualAddr; //this is the oram address
	int is_leaf;
	int pointers[MAX_ORDER];//let NULL be -1
	int keys[MAX_ORDER];
	//struct node * parent;
	int parentAddr;
	int num_keys;
	uint8_t waste[BLOCK_DATA_SIZE - 8*MAX_ORDER - 12]; //to make all oram blocks the same size
	//struct node * next; // Used for queue.
} node;

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

typedef enum _DB_TYPE{
	INTEGER, //4 bytes
	TINYTEXT, //255 bytes
	CHAR, //1 byte
} DB_Type;

typedef struct{
	int numFields;
	int fieldOffsets[MAX_COLS];
	int fieldSizes[MAX_COLS];
	DB_Type fieldTypes[MAX_COLS];
	//int index;//this is structNum
} Schema;

//conditions will be in CNF form (product of sums)
typedef struct Condition Condition;
struct Condition{
	int numClauses;
	int fieldNums[MAX_CONDITIONS];
	int conditionType[MAX_CONDITIONS]; //0 equal, -1 less than, 1 greater than for integers, only support equality for other types
	uint8_t *values[MAX_CONDITIONS];
	Condition *nextCondition;
};


int getEncBlockSize(Obliv_Type type);
int getBlockSize(Obliv_Type type);
int getDBTypeSize(DB_Type type);
int getRowSize(Schema *schema);
int nextPowerOfTwo(unsigned int num);
#endif
