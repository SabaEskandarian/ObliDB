#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <list>
#include <cstring>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "stdio.h"

#include "definitions.h"

//key for reading/writing to oblivious data structures
extern sgx_aes_gcm_128bit_key_t *obliv_key;
//for keeping track of structures, should reflect the structures held by the untrusted app;
extern int oblivStructureSizes[NUM_STRUCTURES]; //actual size, not logical size for orams
extern Obliv_Type oblivStructureTypes[NUM_STRUCTURES];
//specific to database application, hidden from app
extern Schema schemas[NUM_STRUCTURES];
extern char* tableNames[NUM_STRUCTURES];
extern int rowsPerBlock[NUM_STRUCTURES];
extern int numRows[NUM_STRUCTURES];
//specific to oram structures
extern unsigned int* positionMaps[NUM_STRUCTURES];
extern uint8_t* usedBlocks[NUM_STRUCTURES];
extern int* revNum[NUM_STRUCTURES];
extern std::list<Oram_Block>* stashes[NUM_STRUCTURES];
extern int stashOccs[NUM_STRUCTURES];//stash occupancy, number of elements in stash
extern int logicalSizes[NUM_STRUCTURES];
extern node *bPlusRoots[NUM_STRUCTURES];
extern int lastInserted[NUM_STRUCTURES];

extern int maxPad;
extern int currentPad;


//isv_enclave.cpp
extern void printf(const char *fmt, ...);
sgx_status_t send_msg(
		uint8_t* message,
		size_t message_size,
		uint8_t* gcm_mac);

//enclave_data_structures.cpp
extern int opOneLinearScanBlock(int structureId, int index, Linear_Scan_Block* block, int write);
extern int opLinearScanBlock(int structureId, int index, Linear_Scan_Block* block, int write);
extern int opLinearScanUnencryptedBlock(int structureId, int index, Linear_Scan_Block* block, int write);
extern int opOramBlock(int structureId, int index, Oram_Block* retBlock, int write);
extern int posMapAccess(int structureId, int index, int* value, int write);
extern sgx_status_t oramDistribution(int structureId);
extern int opOramBlockSafe(int structureId, int index, Oram_Block* retBlock, int write);
extern int opOramTreeBlock(int structureId, int index, Oram_Tree_Block* block, int write);
extern int encryptBlock(void *ct, void *pt, sgx_aes_gcm_128bit_key_t *key, Obliv_Type type);
extern int decryptBlock(void *ct, void *pt, sgx_aes_gcm_128bit_key_t *key, Obliv_Type type);
extern int getNextId();
extern sgx_status_t total_init();
extern sgx_status_t init_structure(int size, Obliv_Type type, int* structureId);
extern sgx_status_t free_oram(int structureId);
extern sgx_status_t free_structure(int structureId);
extern int newBlock(int structureId);
extern int freeBlock(int structureId, int blockNum);

//enclave_db.cpp
extern int incrementNumRows(int structureId);
extern int getNumRows(int structureId);
extern int rowMatchesCondition(Condition c, uint8_t* row, Schema s);
extern int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId);
extern int growStructure(int structureId);
extern int getTableId(char *tableName);
extern int renameTable(char *oldTableName, char *newTableName);
extern int insertRow(char* tableName, uint8_t* row, int key);
extern int insertLinRowFast(char* tableName, uint8_t* row);
extern int insertIndexRowFast(char* tableName, uint8_t* row, int key);
extern int deleteRow(char* tableName, int key);
extern int deleteRows(char* tableName, Condition c, int startKey, int endKey);
extern int updateRows(char* tableName, Condition c, int colChoice, uint8_t* colVal, int startKey, int endKey);
extern int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
extern int highCardLinGroupBy(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
extern int printTable(char* tableName);
extern int printTableCheating(char* tableName);
extern int createTestTable(char* tableName, int numRows);
extern Schema getTableSchema(char *tableName);
extern int deleteTable(char *tableName);
extern int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey);
extern int indexSelect(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end, int intermediate);
extern int createTestTableIndex(char* tableName, int numberOfRows);
extern int saveIndexTable(char* tableName, int tableSize);
extern int loadIndexTable(int tableSize);

//enclave_tests.cpp
extern sgx_status_t run_tests();
extern sgx_status_t testMemory();
extern sgx_status_t setupPerformanceTest(int structNum, int size, Obliv_Type type);
extern sgx_status_t testLinScanBlockPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
extern sgx_status_t testLinScanBlockWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
extern sgx_status_t testLinScanBlockUnencryptedPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
extern sgx_status_t testLinScanBlockUnencryptedWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
extern sgx_status_t testOramPerformance(int structNum, int queryIndex, Oram_Block* b, int respLen);
extern sgx_status_t testOramSafePerformance(int structNum, int queryIndex, Oram_Block* b, int respLen);
extern sgx_status_t testOpOram();
extern sgx_status_t testOpLinScanBlock();

// FUNCTION PROTOTYPES. (from B+ tree)

int followNodePointer(int structureId, node* destinationNode, int pointerIndex);
int followRecordPointer(int structureId, record* destinationNode, int pointerIndex);

// Output and utility.
void print_leaves(int structureId,  node *root );
int find_range(int structureId, node *root, int key_start, int key_end, int destStructId);//going to insert range into a new temporary linear scan table
		//int returned_keys[], void * returned_pointers[]);
node * find_leaf(int structureId, node * root, int key);
record * find(int structureId, node * root, int key);
int cut(int length );

// Insertion.
record * make_record(int structureId, uint8_t* row);
node * make_node(int structureId, int isLeaf);
int get_left_index(int structureId, node * parent, node * left);
node * insert_into_leaf(int structureId,  node * leaf, int key, record * pointer );
node * insert_into_leaf_after_splitting(int structureId, node * root, node * leaf, int key,
                                        record * pointer);
node * insert_into_node(int structureId, node * root, node * parent,
		int left_index, int key, node * right);
node * insert_into_node_after_splitting(int structureId, node * root, node * parent,
                                        int left_index,
		int key, node * right);
node * insert_into_parent(int structureId, node * root, node * left, int key, node * right);
node * insert_into_new_root(int structureId, node * left, int key, node * right);
node * start_new_tree(int structureId, int key, record * pointer);
node * insert(int structureId,  node * root, int key, record *pointer );

// Deletion.
/* not referenced outside the cpp file and different in the two versions
int get_neighbor_index(int structureId,  node * n, node * nParent );
node * adjust_root(int structureId, node * root);
node * coalesce_nodes(int structureId, node * root, node * n, node * neighbor,
                      int neighbor_index, int k_prime, node * nParent);
node * redistribute_nodes(int structureId, node * root, node * n, node * neighbor,
                          int neighbor_index,
		int k_prime_index, int k_prime, node * nParent);
*/
node * delete_entry(int structureId,  node * root, node * n, int key, void * pointer );
node* deleteKey(int structureId,  node* root, int key );

