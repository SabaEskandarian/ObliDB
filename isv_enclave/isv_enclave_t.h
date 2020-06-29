#ifndef ISV_ENCLAVE_T_H__
#define ISV_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "definitions.h"
#include "stdio.h"
#include "string.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t send_msg(uint8_t* message, size_t message_size, uint8_t* gcm_mac);
sgx_status_t total_init(void);
sgx_status_t run_tests(void);
sgx_status_t setupPerformanceTest(int structNum, int size, Obliv_Type type);
sgx_status_t testLinScanBlockPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockUnencryptedPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockUnencryptedWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testOramPerformance(int structNum, int queryIndex, Oram_Block* b, int respLen);
sgx_status_t testOramSafePerformance(int structNum, int queryIndex, Oram_Block* b, int respLen);
sgx_status_t testOpOram(void);
sgx_status_t oramDistribution(int structureId);
sgx_status_t free_oram(int structureId);
sgx_status_t testMemory(void);
int rowMatchesCondition(Condition c, uint8_t* row, Schema s);
int createTable(Schema* schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId);
int growStructure(int structureId);
int getTableId(char* tableName);
int renameTable(char* oldTableName, char* newTableName);
int insertRow(char* tableName, uint8_t* row, int key);
int insertIndexRowFast(char* tableName, uint8_t* row, int key);
int insertLinRowFast(char* tableName, uint8_t* row);
int deleteRow(char* tableName, int key);
int deleteRows(char* tableName, Condition c, int startKey, int endKey);
int updateRows(char* tableName, Condition c, int colChoice, uint8_t* colVal, int startKey, int endKey);
int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
int highCardLinGroupBy(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
int printTable(char* tableName);
int printTableCheating(char* tableName);
int createTestTable(char* tableName, int numRows);
Schema getTableSchema(char* tableName);
int deleteTable(char* tableName);
int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey);
int createTestTableIndex(char* tableName, int numberOfRows);
int indexSelect(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end, int intermediate);
int saveIndexTable(char* tableName, int tableSize);
int loadIndexTable(int tableSize);
int opOneLinearScanBlock(int structureId, int index, Linear_Scan_Block* block, int write);
int incrementNumRows(int structureId);
int getNumRows(int structureId);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_respond(uint8_t* message, size_t message_size, uint8_t* gcm_mac);
sgx_status_t SGX_CDECL ocall_read_block(int structureId, int index, int blockSize, void* buffer);
sgx_status_t SGX_CDECL ocall_write_block(int structureId, int index, int blockSize, void* buffer);
sgx_status_t SGX_CDECL ocall_newStructure(int newId, Obliv_Type type, int size);
sgx_status_t SGX_CDECL ocall_deleteStructure(int structureId);
sgx_status_t SGX_CDECL ocall_write_file(const void* src, int dsize, int tableSize);
sgx_status_t SGX_CDECL ocall_open_read(int tableSize);
sgx_status_t SGX_CDECL ocall_read_file(void* dest, int dsize);
sgx_status_t SGX_CDECL ocall_make_name(void* name, int tableSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
