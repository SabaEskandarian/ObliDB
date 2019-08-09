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


#define BLOCK_DATA_SIZE 512
//#define BLOCK_DATA_SIZE 2048

//these two are no longer used
//#define NUM_BLOCKS_POW 10
//#define TEST_TYPE 1

//ORAM parameters
#define BUCKET_SIZE 4
#define EXTRA_STASH_SPACE 90 
//database parameters
#define NUM_STRUCTURES 10 //number of tables supported
#define MAX_COLS 15
#define MAX_CONDITIONS 3 //number of ORs allowed in one clause of a condition
#define ROWS_IN_ENCLAVE 7000
#define ROWS_IN_ENCLAVE_JOIN 7500
//#define ROWS_IN_ENCLAVE_JOIN 500
#define PERCENT_ALMOST_ALL 90 //when to switch to large strategy
#define PADDING 0 //0 - normal, >1: pad to that many rows always
//#define JOINMAX 350000 //how big are we expecting joins to get
#define MAX_GROUPS 350000
#define MIXED_USE_MODE 0 //linear scans of indexes

#define MAX_ORDER 62 //biggest value such that a 512-byte block is always big enough to hold a node

typedef enum _Obliv_Type{
	TYPE_LINEAR_SCAN,
	TYPE_TREE_ORAM,
	TYPE_ORAM,
	TYPE_LINEAR_UNENCRYPTED,
} Obliv_Type;

typedef struct{
	int actualAddr;
	uint8_t data[BLOCK_DATA_SIZE];
	int revNum;
} Real_Linear_Scan_Block;

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
	int revNum;
} Oram_Block;

typedef struct{ //for compatibility with bplustree, same as Oram_Block
	int actualAddr;
	//int leafNum;
	uint8_t data[BLOCK_DATA_SIZE];
	int revNum;
} record;

typedef struct node { //size 8*MAX_ORDER + 16 = currently 176, which wastes a lot of space, but oh well
	//void ** pointers;
	int actualAddr; //this is the oram address
	int is_leaf;
	int pointers[MAX_ORDER];//let NULL be -1
	int keys[MAX_ORDER];
	//struct node * parent;
	//int parentAddr; replaced by is_root
	int is_root;
	int num_keys;
	uint8_t waste[BLOCK_DATA_SIZE - 8*MAX_ORDER - 8]; //to make all oram blocks the same size
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
	uint8_t ciphertext[sizeof(Real_Linear_Scan_Block)];
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
