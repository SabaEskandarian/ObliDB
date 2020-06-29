#ifndef ISV_ENCLAVE_U_H__
#define ISV_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_RESPOND_DEFINED__
#define OCALL_RESPOND_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_respond, (uint8_t* message, size_t message_size, uint8_t* gcm_mac));
#endif
#ifndef OCALL_READ_BLOCK_DEFINED__
#define OCALL_READ_BLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_block, (int structureId, int index, int blockSize, void* buffer));
#endif
#ifndef OCALL_WRITE_BLOCK_DEFINED__
#define OCALL_WRITE_BLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_block, (int structureId, int index, int blockSize, void* buffer));
#endif
#ifndef OCALL_NEWSTRUCTURE_DEFINED__
#define OCALL_NEWSTRUCTURE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_newStructure, (int newId, Obliv_Type type, int size));
#endif
#ifndef OCALL_DELETESTRUCTURE_DEFINED__
#define OCALL_DELETESTRUCTURE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_deleteStructure, (int structureId));
#endif
#ifndef OCALL_WRITE_FILE_DEFINED__
#define OCALL_WRITE_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_file, (const void* src, int dsize, int tableSize));
#endif
#ifndef OCALL_OPEN_READ_DEFINED__
#define OCALL_OPEN_READ_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_read, (int tableSize));
#endif
#ifndef OCALL_READ_FILE_DEFINED__
#define OCALL_READ_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (void* dest, int dsize));
#endif
#ifndef OCALL_MAKE_NAME_DEFINED__
#define OCALL_MAKE_NAME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_make_name, (void* name, int tableSize));
#endif

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t send_msg(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* message, size_t message_size, uint8_t* gcm_mac);
sgx_status_t total_init(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t run_tests(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t setupPerformanceTest(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int size, Obliv_Type type);
sgx_status_t testLinScanBlockPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockUnencryptedPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockWritePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testLinScanBlockUnencryptedWritePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen);
sgx_status_t testOramPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Oram_Block* b, int respLen);
sgx_status_t testOramSafePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Oram_Block* b, int respLen);
sgx_status_t testOpOram(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t oramDistribution(sgx_enclave_id_t eid, sgx_status_t* retval, int structureId);
sgx_status_t free_oram(sgx_enclave_id_t eid, sgx_status_t* retval, int structureId);
sgx_status_t testMemory(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t rowMatchesCondition(sgx_enclave_id_t eid, int* retval, Condition c, uint8_t* row, Schema s);
sgx_status_t createTable(sgx_enclave_id_t eid, int* retval, Schema* schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId);
sgx_status_t growStructure(sgx_enclave_id_t eid, int* retval, int structureId);
sgx_status_t getTableId(sgx_enclave_id_t eid, int* retval, char* tableName);
sgx_status_t renameTable(sgx_enclave_id_t eid, int* retval, char* oldTableName, char* newTableName);
sgx_status_t insertRow(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row, int key);
sgx_status_t insertIndexRowFast(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row, int key);
sgx_status_t insertLinRowFast(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row);
sgx_status_t deleteRow(sgx_enclave_id_t eid, int* retval, char* tableName, int key);
sgx_status_t deleteRows(sgx_enclave_id_t eid, int* retval, char* tableName, Condition c, int startKey, int endKey);
sgx_status_t updateRows(sgx_enclave_id_t eid, int* retval, char* tableName, Condition c, int colChoice, uint8_t* colVal, int startKey, int endKey);
sgx_status_t selectRows(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
sgx_status_t highCardLinGroupBy(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate);
sgx_status_t printTable(sgx_enclave_id_t eid, int* retval, char* tableName);
sgx_status_t printTableCheating(sgx_enclave_id_t eid, int* retval, char* tableName);
sgx_status_t createTestTable(sgx_enclave_id_t eid, int* retval, char* tableName, int numRows);
sgx_status_t getTableSchema(sgx_enclave_id_t eid, Schema* retval, char* tableName);
sgx_status_t deleteTable(sgx_enclave_id_t eid, int* retval, char* tableName);
sgx_status_t joinTables(sgx_enclave_id_t eid, int* retval, char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey);
sgx_status_t createTestTableIndex(sgx_enclave_id_t eid, int* retval, char* tableName, int numberOfRows);
sgx_status_t indexSelect(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end, int intermediate);
sgx_status_t saveIndexTable(sgx_enclave_id_t eid, int* retval, char* tableName, int tableSize);
sgx_status_t loadIndexTable(sgx_enclave_id_t eid, int* retval, int tableSize);
sgx_status_t opOneLinearScanBlock(sgx_enclave_id_t eid, int* retval, int structureId, int index, Linear_Scan_Block* block, int write);
sgx_status_t incrementNumRows(sgx_enclave_id_t eid, int* retval, int structureId);
sgx_status_t getNumRows(sgx_enclave_id_t eid, int* retval, int structureId);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
