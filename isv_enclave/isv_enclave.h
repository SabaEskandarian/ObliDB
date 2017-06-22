#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <list>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

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
extern std::list<Oram_Block>* stashes[NUM_STRUCTURES];
extern int stashOccs[NUM_STRUCTURES];//stash occupancy, number of elements in stash
extern int logicalSizes[NUM_STRUCTURES];

//isv_enclave.cpp
extern void printf(const char *fmt, ...);
sgx_status_t send_msg(
		uint8_t* message,
		size_t message_size,
		uint8_t* gcm_mac);

//enclave_data_structures.cpp
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

//enclave_db.cpp
extern int rowMatchesCondition(Condition c, uint8_t* row, Schema s);
extern int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId);
extern int growStructure(int structureId);
extern int getTableId(char *tableName);
extern int insertRow(char* tableName, uint8_t* row);
extern int deleteRows(char* tableName, Condition c);
extern int updateRows(char* tableName, Condition c, int colChoice, uint8_t* colVal);
extern int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice);
extern int printTable(char* tableName);
extern int createTestTable(char* tableName, int numRows);
extern Schema getTableSchema(char *tableName);
extern int deleteTable(char *tableName);
//joins are still absent

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
