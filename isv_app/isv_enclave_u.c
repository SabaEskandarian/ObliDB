#include "isv_enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_put_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_put_secret_data_t;

typedef struct ms_send_msg_t {
	sgx_status_t ms_retval;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_gcm_mac;
} ms_send_msg_t;

typedef struct ms_total_init_t {
	sgx_status_t ms_retval;
} ms_total_init_t;

typedef struct ms_run_tests_t {
	sgx_status_t ms_retval;
} ms_run_tests_t;

typedef struct ms_setupPerformanceTest_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_size;
	Obliv_Type ms_type;
} ms_setupPerformanceTest_t;

typedef struct ms_testLinScanBlockPerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Linear_Scan_Block* ms_b;
	int ms_respLen;
} ms_testLinScanBlockPerformance_t;

typedef struct ms_testLinScanBlockUnencryptedPerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Linear_Scan_Block* ms_b;
	int ms_respLen;
} ms_testLinScanBlockUnencryptedPerformance_t;

typedef struct ms_testLinScanBlockWritePerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Linear_Scan_Block* ms_b;
	int ms_respLen;
} ms_testLinScanBlockWritePerformance_t;

typedef struct ms_testLinScanBlockUnencryptedWritePerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Linear_Scan_Block* ms_b;
	int ms_respLen;
} ms_testLinScanBlockUnencryptedWritePerformance_t;

typedef struct ms_testOramPerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Oram_Block* ms_b;
	int ms_respLen;
} ms_testOramPerformance_t;

typedef struct ms_testOramSafePerformance_t {
	sgx_status_t ms_retval;
	int ms_structNum;
	int ms_queryIndex;
	Oram_Block* ms_b;
	int ms_respLen;
} ms_testOramSafePerformance_t;

typedef struct ms_testOpOram_t {
	sgx_status_t ms_retval;
} ms_testOpOram_t;

typedef struct ms_oramDistribution_t {
	sgx_status_t ms_retval;
	int ms_structureId;
} ms_oramDistribution_t;

typedef struct ms_free_oram_t {
	sgx_status_t ms_retval;
	int ms_structureId;
} ms_free_oram_t;

typedef struct ms_testMemory_t {
	sgx_status_t ms_retval;
} ms_testMemory_t;

typedef struct ms_rowMatchesCondition_t {
	int ms_retval;
	Condition ms_c;
	uint8_t* ms_row;
	Schema ms_s;
} ms_rowMatchesCondition_t;

typedef struct ms_createTable_t {
	int ms_retval;
	Schema* ms_schema;
	char* ms_tableName;
	int ms_nameLen;
	Obliv_Type ms_type;
	int ms_numberOfRows;
	int* ms_structureId;
} ms_createTable_t;

typedef struct ms_growStructure_t {
	int ms_retval;
	int ms_structureId;
} ms_growStructure_t;

typedef struct ms_getTableId_t {
	int ms_retval;
	char* ms_tableName;
} ms_getTableId_t;

typedef struct ms_renameTable_t {
	int ms_retval;
	char* ms_oldTableName;
	char* ms_newTableName;
} ms_renameTable_t;

typedef struct ms_insertRow_t {
	int ms_retval;
	char* ms_tableName;
	uint8_t* ms_row;
	int ms_key;
} ms_insertRow_t;

typedef struct ms_insertIndexRowFast_t {
	int ms_retval;
	char* ms_tableName;
	uint8_t* ms_row;
	int ms_key;
} ms_insertIndexRowFast_t;

typedef struct ms_insertLinRowFast_t {
	int ms_retval;
	char* ms_tableName;
	uint8_t* ms_row;
} ms_insertLinRowFast_t;

typedef struct ms_deleteRow_t {
	int ms_retval;
	char* ms_tableName;
	int ms_key;
} ms_deleteRow_t;

typedef struct ms_deleteRows_t {
	int ms_retval;
	char* ms_tableName;
	Condition ms_c;
	int ms_startKey;
	int ms_endKey;
} ms_deleteRows_t;

typedef struct ms_updateRows_t {
	int ms_retval;
	char* ms_tableName;
	Condition ms_c;
	int ms_colChoice;
	uint8_t* ms_colVal;
	int ms_startKey;
	int ms_endKey;
} ms_updateRows_t;

typedef struct ms_selectRows_t {
	int ms_retval;
	char* ms_tableName;
	int ms_colChoice;
	Condition ms_c;
	int ms_aggregate;
	int ms_groupCol;
	int ms_algChoice;
	int ms_intermediate;
} ms_selectRows_t;

typedef struct ms_highCardLinGroupBy_t {
	int ms_retval;
	char* ms_tableName;
	int ms_colChoice;
	Condition ms_c;
	int ms_aggregate;
	int ms_groupCol;
	int ms_algChoice;
	int ms_intermediate;
} ms_highCardLinGroupBy_t;

typedef struct ms_printTable_t {
	int ms_retval;
	char* ms_tableName;
} ms_printTable_t;

typedef struct ms_printTableCheating_t {
	int ms_retval;
	char* ms_tableName;
} ms_printTableCheating_t;

typedef struct ms_createTestTable_t {
	int ms_retval;
	char* ms_tableName;
	int ms_numRows;
} ms_createTestTable_t;

typedef struct ms_getTableSchema_t {
	Schema ms_retval;
	char* ms_tableName;
} ms_getTableSchema_t;

typedef struct ms_deleteTable_t {
	int ms_retval;
	char* ms_tableName;
} ms_deleteTable_t;

typedef struct ms_joinTables_t {
	int ms_retval;
	char* ms_tableName1;
	char* ms_tableName2;
	int ms_joinCol1;
	int ms_joinCol2;
	int ms_startKey;
	int ms_endKey;
} ms_joinTables_t;

typedef struct ms_createTestTableIndex_t {
	int ms_retval;
	char* ms_tableName;
	int ms_numberOfRows;
} ms_createTestTableIndex_t;

typedef struct ms_indexSelect_t {
	int ms_retval;
	char* ms_tableName;
	int ms_colChoice;
	Condition ms_c;
	int ms_aggregate;
	int ms_groupCol;
	int ms_algChoice;
	int ms_key_start;
	int ms_key_end;
	int ms_intermediate;
} ms_indexSelect_t;

typedef struct ms_saveIndexTable_t {
	int ms_retval;
	char* ms_tableName;
	int ms_tableSize;
} ms_saveIndexTable_t;

typedef struct ms_loadIndexTable_t {
	int ms_retval;
	int ms_tableSize;
} ms_loadIndexTable_t;

typedef struct ms_opOneLinearScanBlock_t {
	int ms_retval;
	int ms_structureId;
	int ms_index;
	Linear_Scan_Block* ms_block;
	int ms_write;
} ms_opOneLinearScanBlock_t;

typedef struct ms_incrementNumRows_t {
	int ms_retval;
	int ms_structureId;
} ms_incrementNumRows_t;

typedef struct ms_getNumRows_t {
	int ms_retval;
	int ms_structureId;
} ms_getNumRows_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_respond_t {
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_gcm_mac;
} ms_ocall_respond_t;

typedef struct ms_ocall_read_block_t {
	int ms_structureId;
	int ms_index;
	int ms_blockSize;
	void* ms_buffer;
} ms_ocall_read_block_t;

typedef struct ms_ocall_write_block_t {
	int ms_structureId;
	int ms_index;
	int ms_blockSize;
	void* ms_buffer;
} ms_ocall_write_block_t;

typedef struct ms_ocall_newStructure_t {
	int ms_newId;
	Obliv_Type ms_type;
	int ms_size;
} ms_ocall_newStructure_t;

typedef struct ms_ocall_deleteStructure_t {
	int ms_structureId;
} ms_ocall_deleteStructure_t;

typedef struct ms_ocall_write_file_t {
	const void* ms_src;
	int ms_dsize;
	int ms_tableSize;
} ms_ocall_write_file_t;

typedef struct ms_ocall_open_read_t {
	int ms_tableSize;
} ms_ocall_open_read_t;

typedef struct ms_ocall_read_file_t {
	void* ms_dest;
	int ms_dsize;
} ms_ocall_read_file_t;

typedef struct ms_ocall_make_name_t {
	void* ms_name;
	int ms_tableSize;
} ms_ocall_make_name_t;

static sgx_status_t SGX_CDECL isv_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_respond(void* pms)
{
	ms_ocall_respond_t* ms = SGX_CAST(ms_ocall_respond_t*, pms);
	ocall_respond(ms->ms_message, ms->ms_message_size, ms->ms_gcm_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_read_block(void* pms)
{
	ms_ocall_read_block_t* ms = SGX_CAST(ms_ocall_read_block_t*, pms);
	ocall_read_block(ms->ms_structureId, ms->ms_index, ms->ms_blockSize, ms->ms_buffer);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_write_block(void* pms)
{
	ms_ocall_write_block_t* ms = SGX_CAST(ms_ocall_write_block_t*, pms);
	ocall_write_block(ms->ms_structureId, ms->ms_index, ms->ms_blockSize, ms->ms_buffer);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_newStructure(void* pms)
{
	ms_ocall_newStructure_t* ms = SGX_CAST(ms_ocall_newStructure_t*, pms);
	ocall_newStructure(ms->ms_newId, ms->ms_type, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_deleteStructure(void* pms)
{
	ms_ocall_deleteStructure_t* ms = SGX_CAST(ms_ocall_deleteStructure_t*, pms);
	ocall_deleteStructure(ms->ms_structureId);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_write_file(void* pms)
{
	ms_ocall_write_file_t* ms = SGX_CAST(ms_ocall_write_file_t*, pms);
	ocall_write_file(ms->ms_src, ms->ms_dsize, ms->ms_tableSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_open_read(void* pms)
{
	ms_ocall_open_read_t* ms = SGX_CAST(ms_ocall_open_read_t*, pms);
	ocall_open_read(ms->ms_tableSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_read_file(void* pms)
{
	ms_ocall_read_file_t* ms = SGX_CAST(ms_ocall_read_file_t*, pms);
	ocall_read_file(ms->ms_dest, ms->ms_dsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_make_name(void* pms)
{
	ms_ocall_make_name_t* ms = SGX_CAST(ms_ocall_make_name_t*, pms);
	ocall_make_name(ms->ms_name, ms->ms_tableSize);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_isv_enclave = {
	10,
	{
		(void*)isv_enclave_ocall_print,
		(void*)isv_enclave_ocall_respond,
		(void*)isv_enclave_ocall_read_block,
		(void*)isv_enclave_ocall_write_block,
		(void*)isv_enclave_ocall_newStructure,
		(void*)isv_enclave_ocall_deleteStructure,
		(void*)isv_enclave_ocall_write_file,
		(void*)isv_enclave_ocall_open_read,
		(void*)isv_enclave_ocall_read_file,
		(void*)isv_enclave_ocall_make_name,
	}
};
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 0, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 2, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_put_secret_data_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 3, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t send_msg(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* message, size_t message_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_send_msg_t ms;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 4, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t total_init(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_total_init_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t run_tests(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_run_tests_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t setupPerformanceTest(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int size, Obliv_Type type)
{
	sgx_status_t status;
	ms_setupPerformanceTest_t ms;
	ms.ms_structNum = structNum;
	ms.ms_size = size;
	ms.ms_type = type;
	status = sgx_ecall(eid, 7, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testLinScanBlockPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testLinScanBlockPerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 8, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testLinScanBlockUnencryptedPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testLinScanBlockUnencryptedPerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 9, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testLinScanBlockWritePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testLinScanBlockWritePerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 10, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testLinScanBlockUnencryptedWritePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Linear_Scan_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testLinScanBlockUnencryptedWritePerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 11, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testOramPerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Oram_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testOramPerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 12, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testOramSafePerformance(sgx_enclave_id_t eid, sgx_status_t* retval, int structNum, int queryIndex, Oram_Block* b, int respLen)
{
	sgx_status_t status;
	ms_testOramSafePerformance_t ms;
	ms.ms_structNum = structNum;
	ms.ms_queryIndex = queryIndex;
	ms.ms_b = b;
	ms.ms_respLen = respLen;
	status = sgx_ecall(eid, 13, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testOpOram(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_testOpOram_t ms;
	status = sgx_ecall(eid, 14, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t oramDistribution(sgx_enclave_id_t eid, sgx_status_t* retval, int structureId)
{
	sgx_status_t status;
	ms_oramDistribution_t ms;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 15, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t free_oram(sgx_enclave_id_t eid, sgx_status_t* retval, int structureId)
{
	sgx_status_t status;
	ms_free_oram_t ms;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 16, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testMemory(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_testMemory_t ms;
	status = sgx_ecall(eid, 17, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t rowMatchesCondition(sgx_enclave_id_t eid, int* retval, Condition c, uint8_t* row, Schema s)
{
	sgx_status_t status;
	ms_rowMatchesCondition_t ms;
	ms.ms_c = c;
	ms.ms_row = row;
	ms.ms_s = s;
	status = sgx_ecall(eid, 18, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createTable(sgx_enclave_id_t eid, int* retval, Schema* schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId)
{
	sgx_status_t status;
	ms_createTable_t ms;
	ms.ms_schema = schema;
	ms.ms_tableName = tableName;
	ms.ms_nameLen = nameLen;
	ms.ms_type = type;
	ms.ms_numberOfRows = numberOfRows;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 19, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t growStructure(sgx_enclave_id_t eid, int* retval, int structureId)
{
	sgx_status_t status;
	ms_growStructure_t ms;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 20, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t getTableId(sgx_enclave_id_t eid, int* retval, char* tableName)
{
	sgx_status_t status;
	ms_getTableId_t ms;
	ms.ms_tableName = tableName;
	status = sgx_ecall(eid, 21, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t renameTable(sgx_enclave_id_t eid, int* retval, char* oldTableName, char* newTableName)
{
	sgx_status_t status;
	ms_renameTable_t ms;
	ms.ms_oldTableName = oldTableName;
	ms.ms_newTableName = newTableName;
	status = sgx_ecall(eid, 22, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t insertRow(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row, int key)
{
	sgx_status_t status;
	ms_insertRow_t ms;
	ms.ms_tableName = tableName;
	ms.ms_row = row;
	ms.ms_key = key;
	status = sgx_ecall(eid, 23, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t insertIndexRowFast(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row, int key)
{
	sgx_status_t status;
	ms_insertIndexRowFast_t ms;
	ms.ms_tableName = tableName;
	ms.ms_row = row;
	ms.ms_key = key;
	status = sgx_ecall(eid, 24, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t insertLinRowFast(sgx_enclave_id_t eid, int* retval, char* tableName, uint8_t* row)
{
	sgx_status_t status;
	ms_insertLinRowFast_t ms;
	ms.ms_tableName = tableName;
	ms.ms_row = row;
	status = sgx_ecall(eid, 25, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t deleteRow(sgx_enclave_id_t eid, int* retval, char* tableName, int key)
{
	sgx_status_t status;
	ms_deleteRow_t ms;
	ms.ms_tableName = tableName;
	ms.ms_key = key;
	status = sgx_ecall(eid, 26, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t deleteRows(sgx_enclave_id_t eid, int* retval, char* tableName, Condition c, int startKey, int endKey)
{
	sgx_status_t status;
	ms_deleteRows_t ms;
	ms.ms_tableName = tableName;
	ms.ms_c = c;
	ms.ms_startKey = startKey;
	ms.ms_endKey = endKey;
	status = sgx_ecall(eid, 27, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t updateRows(sgx_enclave_id_t eid, int* retval, char* tableName, Condition c, int colChoice, uint8_t* colVal, int startKey, int endKey)
{
	sgx_status_t status;
	ms_updateRows_t ms;
	ms.ms_tableName = tableName;
	ms.ms_c = c;
	ms.ms_colChoice = colChoice;
	ms.ms_colVal = colVal;
	ms.ms_startKey = startKey;
	ms.ms_endKey = endKey;
	status = sgx_ecall(eid, 28, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t selectRows(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate)
{
	sgx_status_t status;
	ms_selectRows_t ms;
	ms.ms_tableName = tableName;
	ms.ms_colChoice = colChoice;
	ms.ms_c = c;
	ms.ms_aggregate = aggregate;
	ms.ms_groupCol = groupCol;
	ms.ms_algChoice = algChoice;
	ms.ms_intermediate = intermediate;
	status = sgx_ecall(eid, 29, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t highCardLinGroupBy(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate)
{
	sgx_status_t status;
	ms_highCardLinGroupBy_t ms;
	ms.ms_tableName = tableName;
	ms.ms_colChoice = colChoice;
	ms.ms_c = c;
	ms.ms_aggregate = aggregate;
	ms.ms_groupCol = groupCol;
	ms.ms_algChoice = algChoice;
	ms.ms_intermediate = intermediate;
	status = sgx_ecall(eid, 30, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t printTable(sgx_enclave_id_t eid, int* retval, char* tableName)
{
	sgx_status_t status;
	ms_printTable_t ms;
	ms.ms_tableName = tableName;
	status = sgx_ecall(eid, 31, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t printTableCheating(sgx_enclave_id_t eid, int* retval, char* tableName)
{
	sgx_status_t status;
	ms_printTableCheating_t ms;
	ms.ms_tableName = tableName;
	status = sgx_ecall(eid, 32, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createTestTable(sgx_enclave_id_t eid, int* retval, char* tableName, int numRows)
{
	sgx_status_t status;
	ms_createTestTable_t ms;
	ms.ms_tableName = tableName;
	ms.ms_numRows = numRows;
	status = sgx_ecall(eid, 33, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t getTableSchema(sgx_enclave_id_t eid, Schema* retval, char* tableName)
{
	sgx_status_t status;
	ms_getTableSchema_t ms;
	ms.ms_tableName = tableName;
	status = sgx_ecall(eid, 34, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t deleteTable(sgx_enclave_id_t eid, int* retval, char* tableName)
{
	sgx_status_t status;
	ms_deleteTable_t ms;
	ms.ms_tableName = tableName;
	status = sgx_ecall(eid, 35, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t joinTables(sgx_enclave_id_t eid, int* retval, char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey)
{
	sgx_status_t status;
	ms_joinTables_t ms;
	ms.ms_tableName1 = tableName1;
	ms.ms_tableName2 = tableName2;
	ms.ms_joinCol1 = joinCol1;
	ms.ms_joinCol2 = joinCol2;
	ms.ms_startKey = startKey;
	ms.ms_endKey = endKey;
	status = sgx_ecall(eid, 36, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createTestTableIndex(sgx_enclave_id_t eid, int* retval, char* tableName, int numberOfRows)
{
	sgx_status_t status;
	ms_createTestTableIndex_t ms;
	ms.ms_tableName = tableName;
	ms.ms_numberOfRows = numberOfRows;
	status = sgx_ecall(eid, 37, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t indexSelect(sgx_enclave_id_t eid, int* retval, char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end, int intermediate)
{
	sgx_status_t status;
	ms_indexSelect_t ms;
	ms.ms_tableName = tableName;
	ms.ms_colChoice = colChoice;
	ms.ms_c = c;
	ms.ms_aggregate = aggregate;
	ms.ms_groupCol = groupCol;
	ms.ms_algChoice = algChoice;
	ms.ms_key_start = key_start;
	ms.ms_key_end = key_end;
	ms.ms_intermediate = intermediate;
	status = sgx_ecall(eid, 38, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t saveIndexTable(sgx_enclave_id_t eid, int* retval, char* tableName, int tableSize)
{
	sgx_status_t status;
	ms_saveIndexTable_t ms;
	ms.ms_tableName = tableName;
	ms.ms_tableSize = tableSize;
	status = sgx_ecall(eid, 39, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t loadIndexTable(sgx_enclave_id_t eid, int* retval, int tableSize)
{
	sgx_status_t status;
	ms_loadIndexTable_t ms;
	ms.ms_tableSize = tableSize;
	status = sgx_ecall(eid, 40, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t opOneLinearScanBlock(sgx_enclave_id_t eid, int* retval, int structureId, int index, Linear_Scan_Block* block, int write)
{
	sgx_status_t status;
	ms_opOneLinearScanBlock_t ms;
	ms.ms_structureId = structureId;
	ms.ms_index = index;
	ms.ms_block = block;
	ms.ms_write = write;
	status = sgx_ecall(eid, 41, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t incrementNumRows(sgx_enclave_id_t eid, int* retval, int structureId)
{
	sgx_status_t status;
	ms_incrementNumRows_t ms;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 42, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t getNumRows(sgx_enclave_id_t eid, int* retval, int structureId)
{
	sgx_status_t status;
	ms_getNumRows_t ms;
	ms.ms_structureId = structureId;
	status = sgx_ecall(eid, 43, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 44, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 45, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 46, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

