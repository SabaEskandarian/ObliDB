#include "isv_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_context != NULL && _len_p_context != 0) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}

	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
	if (_in_p_context) {
		if (memcpy_s(_tmp_p_context, _len_p_context, _in_p_context, _len_p_context)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_context) free(_in_p_context);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enclave_ra_close(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_att_result_mac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_att_result_mac_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verify_att_result_mac_t* ms = SGX_CAST(ms_verify_att_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = verify_att_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);

err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_put_secret_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_put_secret_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_put_secret_data_t* ms = SGX_CAST(ms_put_secret_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret = ms->ms_p_secret;
	uint32_t _tmp_secret_size = ms->ms_secret_size;
	size_t _len_p_secret = _tmp_secret_size;
	uint8_t* _in_p_secret = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(uint8_t);
	uint8_t* _in_gcm_mac = NULL;

	if (sizeof(*_tmp_gcm_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_secret, _len_p_secret);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_secret != NULL && _len_p_secret != 0) {
		if ( _len_p_secret % sizeof(*_tmp_p_secret) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_secret = (uint8_t*)malloc(_len_p_secret);
		if (_in_p_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_secret, _len_p_secret, _tmp_p_secret, _len_p_secret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		if ( _len_gcm_mac % sizeof(*_tmp_gcm_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_gcm_mac, _len_gcm_mac, _tmp_gcm_mac, _len_gcm_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = put_secret_data(ms->ms_context, _in_p_secret, _tmp_secret_size, _in_gcm_mac);

err:
	if (_in_p_secret) free(_in_p_secret);
	if (_in_gcm_mac) free(_in_gcm_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_send_msg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_send_msg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_send_msg_t* ms = SGX_CAST(ms_send_msg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(uint8_t);
	uint8_t* _in_gcm_mac = NULL;

	if (sizeof(*_tmp_gcm_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		if ( _len_gcm_mac % sizeof(*_tmp_gcm_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_gcm_mac, _len_gcm_mac, _tmp_gcm_mac, _len_gcm_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = send_msg(_in_message, _tmp_message_size, _in_gcm_mac);

err:
	if (_in_message) free(_in_message);
	if (_in_gcm_mac) free(_in_gcm_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_total_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_total_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_total_init_t* ms = SGX_CAST(ms_total_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = total_init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_run_tests(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_run_tests_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_run_tests_t* ms = SGX_CAST(ms_run_tests_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = run_tests();


	return status;
}

static sgx_status_t SGX_CDECL sgx_setupPerformanceTest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setupPerformanceTest_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_setupPerformanceTest_t* ms = SGX_CAST(ms_setupPerformanceTest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = setupPerformanceTest(ms->ms_structNum, ms->ms_size, ms->ms_type);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testLinScanBlockPerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testLinScanBlockPerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testLinScanBlockPerformance_t* ms = SGX_CAST(ms_testLinScanBlockPerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Linear_Scan_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Linear_Scan_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Linear_Scan_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testLinScanBlockPerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testLinScanBlockUnencryptedPerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testLinScanBlockUnencryptedPerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testLinScanBlockUnencryptedPerformance_t* ms = SGX_CAST(ms_testLinScanBlockUnencryptedPerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Linear_Scan_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Linear_Scan_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Linear_Scan_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testLinScanBlockUnencryptedPerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testLinScanBlockWritePerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testLinScanBlockWritePerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testLinScanBlockWritePerformance_t* ms = SGX_CAST(ms_testLinScanBlockWritePerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Linear_Scan_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Linear_Scan_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Linear_Scan_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testLinScanBlockWritePerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testLinScanBlockUnencryptedWritePerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testLinScanBlockUnencryptedWritePerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testLinScanBlockUnencryptedWritePerformance_t* ms = SGX_CAST(ms_testLinScanBlockUnencryptedWritePerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Linear_Scan_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Linear_Scan_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Linear_Scan_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testLinScanBlockUnencryptedWritePerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testOramPerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOramPerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOramPerformance_t* ms = SGX_CAST(ms_testOramPerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Oram_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Oram_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Oram_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testOramPerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testOramSafePerformance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOramSafePerformance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOramSafePerformance_t* ms = SGX_CAST(ms_testOramSafePerformance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Oram_Block* _tmp_b = ms->ms_b;
	int _tmp_respLen = ms->ms_respLen;
	size_t _len_b = _tmp_respLen;
	Oram_Block* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ((_in_b = (Oram_Block*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testOramSafePerformance(ms->ms_structNum, ms->ms_queryIndex, _in_b, _tmp_respLen);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testOpOram(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOpOram_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOpOram_t* ms = SGX_CAST(ms_testOpOram_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = testOpOram();


	return status;
}

static sgx_status_t SGX_CDECL sgx_oramDistribution(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_oramDistribution_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_oramDistribution_t* ms = SGX_CAST(ms_oramDistribution_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = oramDistribution(ms->ms_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_free_oram(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_free_oram_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_free_oram_t* ms = SGX_CAST(ms_free_oram_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = free_oram(ms->ms_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testMemory(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testMemory_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testMemory_t* ms = SGX_CAST(ms_testMemory_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = testMemory();


	return status;
}

static sgx_status_t SGX_CDECL sgx_rowMatchesCondition(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rowMatchesCondition_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rowMatchesCondition_t* ms = SGX_CAST(ms_rowMatchesCondition_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_row = ms->ms_row;



	ms->ms_retval = rowMatchesCondition(ms->ms_c, _tmp_row, ms->ms_s);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createTable_t* ms = SGX_CAST(ms_createTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Schema* _tmp_schema = ms->ms_schema;
	char* _tmp_tableName = ms->ms_tableName;
	int* _tmp_structureId = ms->ms_structureId;



	ms->ms_retval = createTable(_tmp_schema, _tmp_tableName, ms->ms_nameLen, ms->ms_type, ms->ms_numberOfRows, _tmp_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_growStructure(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_growStructure_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_growStructure_t* ms = SGX_CAST(ms_growStructure_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = growStructure(ms->ms_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_getTableId(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getTableId_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getTableId_t* ms = SGX_CAST(ms_getTableId_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = getTableId(_tmp_tableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_renameTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_renameTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_renameTable_t* ms = SGX_CAST(ms_renameTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_oldTableName = ms->ms_oldTableName;
	char* _tmp_newTableName = ms->ms_newTableName;



	ms->ms_retval = renameTable(_tmp_oldTableName, _tmp_newTableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_insertRow(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_insertRow_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_insertRow_t* ms = SGX_CAST(ms_insertRow_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;
	uint8_t* _tmp_row = ms->ms_row;



	ms->ms_retval = insertRow(_tmp_tableName, _tmp_row, ms->ms_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_insertIndexRowFast(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_insertIndexRowFast_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_insertIndexRowFast_t* ms = SGX_CAST(ms_insertIndexRowFast_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;
	uint8_t* _tmp_row = ms->ms_row;



	ms->ms_retval = insertIndexRowFast(_tmp_tableName, _tmp_row, ms->ms_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_insertLinRowFast(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_insertLinRowFast_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_insertLinRowFast_t* ms = SGX_CAST(ms_insertLinRowFast_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;
	uint8_t* _tmp_row = ms->ms_row;



	ms->ms_retval = insertLinRowFast(_tmp_tableName, _tmp_row);


	return status;
}

static sgx_status_t SGX_CDECL sgx_deleteRow(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_deleteRow_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_deleteRow_t* ms = SGX_CAST(ms_deleteRow_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = deleteRow(_tmp_tableName, ms->ms_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_deleteRows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_deleteRows_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_deleteRows_t* ms = SGX_CAST(ms_deleteRows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = deleteRows(_tmp_tableName, ms->ms_c, ms->ms_startKey, ms->ms_endKey);


	return status;
}

static sgx_status_t SGX_CDECL sgx_updateRows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_updateRows_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_updateRows_t* ms = SGX_CAST(ms_updateRows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;
	uint8_t* _tmp_colVal = ms->ms_colVal;



	ms->ms_retval = updateRows(_tmp_tableName, ms->ms_c, ms->ms_colChoice, _tmp_colVal, ms->ms_startKey, ms->ms_endKey);


	return status;
}

static sgx_status_t SGX_CDECL sgx_selectRows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_selectRows_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_selectRows_t* ms = SGX_CAST(ms_selectRows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = selectRows(_tmp_tableName, ms->ms_colChoice, ms->ms_c, ms->ms_aggregate, ms->ms_groupCol, ms->ms_algChoice, ms->ms_intermediate);


	return status;
}

static sgx_status_t SGX_CDECL sgx_highCardLinGroupBy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_highCardLinGroupBy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_highCardLinGroupBy_t* ms = SGX_CAST(ms_highCardLinGroupBy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = highCardLinGroupBy(_tmp_tableName, ms->ms_colChoice, ms->ms_c, ms->ms_aggregate, ms->ms_groupCol, ms->ms_algChoice, ms->ms_intermediate);


	return status;
}

static sgx_status_t SGX_CDECL sgx_printTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_printTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_printTable_t* ms = SGX_CAST(ms_printTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = printTable(_tmp_tableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_printTableCheating(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_printTableCheating_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_printTableCheating_t* ms = SGX_CAST(ms_printTableCheating_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = printTableCheating(_tmp_tableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createTestTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createTestTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createTestTable_t* ms = SGX_CAST(ms_createTestTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = createTestTable(_tmp_tableName, ms->ms_numRows);


	return status;
}

static sgx_status_t SGX_CDECL sgx_getTableSchema(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getTableSchema_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getTableSchema_t* ms = SGX_CAST(ms_getTableSchema_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = getTableSchema(_tmp_tableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_deleteTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_deleteTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_deleteTable_t* ms = SGX_CAST(ms_deleteTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = deleteTable(_tmp_tableName);


	return status;
}

static sgx_status_t SGX_CDECL sgx_joinTables(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_joinTables_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_joinTables_t* ms = SGX_CAST(ms_joinTables_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName1 = ms->ms_tableName1;
	char* _tmp_tableName2 = ms->ms_tableName2;



	ms->ms_retval = joinTables(_tmp_tableName1, _tmp_tableName2, ms->ms_joinCol1, ms->ms_joinCol2, ms->ms_startKey, ms->ms_endKey);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createTestTableIndex(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createTestTableIndex_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createTestTableIndex_t* ms = SGX_CAST(ms_createTestTableIndex_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = createTestTableIndex(_tmp_tableName, ms->ms_numberOfRows);


	return status;
}

static sgx_status_t SGX_CDECL sgx_indexSelect(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_indexSelect_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_indexSelect_t* ms = SGX_CAST(ms_indexSelect_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = indexSelect(_tmp_tableName, ms->ms_colChoice, ms->ms_c, ms->ms_aggregate, ms->ms_groupCol, ms->ms_algChoice, ms->ms_key_start, ms->ms_key_end, ms->ms_intermediate);


	return status;
}

static sgx_status_t SGX_CDECL sgx_saveIndexTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_saveIndexTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_saveIndexTable_t* ms = SGX_CAST(ms_saveIndexTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tableName = ms->ms_tableName;



	ms->ms_retval = saveIndexTable(_tmp_tableName, ms->ms_tableSize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_loadIndexTable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_loadIndexTable_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_loadIndexTable_t* ms = SGX_CAST(ms_loadIndexTable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = loadIndexTable(ms->ms_tableSize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_opOneLinearScanBlock(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_opOneLinearScanBlock_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_opOneLinearScanBlock_t* ms = SGX_CAST(ms_opOneLinearScanBlock_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	Linear_Scan_Block* _tmp_block = ms->ms_block;



	ms->ms_retval = opOneLinearScanBlock(ms->ms_structureId, ms->ms_index, _tmp_block, ms->ms_write);


	return status;
}

static sgx_status_t SGX_CDECL sgx_incrementNumRows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_incrementNumRows_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_incrementNumRows_t* ms = SGX_CAST(ms_incrementNumRows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = incrementNumRows(ms->ms_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_getNumRows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getNumRows_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getNumRows_t* ms = SGX_CAST(ms_getNumRows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = getNumRows(ms->ms_structureId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[47];
} g_ecall_table = {
	47,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0, 0},
		{(void*)(uintptr_t)sgx_put_secret_data, 0, 0},
		{(void*)(uintptr_t)sgx_send_msg, 0, 0},
		{(void*)(uintptr_t)sgx_total_init, 0, 0},
		{(void*)(uintptr_t)sgx_run_tests, 0, 0},
		{(void*)(uintptr_t)sgx_setupPerformanceTest, 0, 0},
		{(void*)(uintptr_t)sgx_testLinScanBlockPerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testLinScanBlockUnencryptedPerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testLinScanBlockWritePerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testLinScanBlockUnencryptedWritePerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testOramPerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testOramSafePerformance, 0, 0},
		{(void*)(uintptr_t)sgx_testOpOram, 0, 0},
		{(void*)(uintptr_t)sgx_oramDistribution, 0, 0},
		{(void*)(uintptr_t)sgx_free_oram, 0, 0},
		{(void*)(uintptr_t)sgx_testMemory, 0, 0},
		{(void*)(uintptr_t)sgx_rowMatchesCondition, 0, 0},
		{(void*)(uintptr_t)sgx_createTable, 0, 0},
		{(void*)(uintptr_t)sgx_growStructure, 0, 0},
		{(void*)(uintptr_t)sgx_getTableId, 0, 0},
		{(void*)(uintptr_t)sgx_renameTable, 0, 0},
		{(void*)(uintptr_t)sgx_insertRow, 0, 0},
		{(void*)(uintptr_t)sgx_insertIndexRowFast, 0, 0},
		{(void*)(uintptr_t)sgx_insertLinRowFast, 0, 0},
		{(void*)(uintptr_t)sgx_deleteRow, 0, 0},
		{(void*)(uintptr_t)sgx_deleteRows, 0, 0},
		{(void*)(uintptr_t)sgx_updateRows, 0, 0},
		{(void*)(uintptr_t)sgx_selectRows, 0, 0},
		{(void*)(uintptr_t)sgx_highCardLinGroupBy, 0, 0},
		{(void*)(uintptr_t)sgx_printTable, 0, 0},
		{(void*)(uintptr_t)sgx_printTableCheating, 0, 0},
		{(void*)(uintptr_t)sgx_createTestTable, 0, 0},
		{(void*)(uintptr_t)sgx_getTableSchema, 0, 0},
		{(void*)(uintptr_t)sgx_deleteTable, 0, 0},
		{(void*)(uintptr_t)sgx_joinTables, 0, 0},
		{(void*)(uintptr_t)sgx_createTestTableIndex, 0, 0},
		{(void*)(uintptr_t)sgx_indexSelect, 0, 0},
		{(void*)(uintptr_t)sgx_saveIndexTable, 0, 0},
		{(void*)(uintptr_t)sgx_loadIndexTable, 0, 0},
		{(void*)(uintptr_t)sgx_opOneLinearScanBlock, 0, 0},
		{(void*)(uintptr_t)sgx_incrementNumRows, 0, 0},
		{(void*)(uintptr_t)sgx_getNumRows, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][47];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_respond(uint8_t* message, size_t message_size, uint8_t* gcm_mac)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = message_size;
	size_t _len_gcm_mac = 16;

	ms_ocall_respond_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_respond_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(message, _len_message);
	CHECK_ENCLAVE_POINTER(gcm_mac, _len_gcm_mac);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (message != NULL) ? _len_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (gcm_mac != NULL) ? _len_gcm_mac : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_respond_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_respond_t));
	ocalloc_size -= sizeof(ms_ocall_respond_t);

	if (message != NULL) {
		ms->ms_message = (uint8_t*)__tmp;
		if (_len_message % sizeof(*message) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, message, _len_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_message);
		ocalloc_size -= _len_message;
	} else {
		ms->ms_message = NULL;
	}
	
	ms->ms_message_size = message_size;
	if (gcm_mac != NULL) {
		ms->ms_gcm_mac = (uint8_t*)__tmp;
		if (_len_gcm_mac % sizeof(*gcm_mac) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, gcm_mac, _len_gcm_mac)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_gcm_mac);
		ocalloc_size -= _len_gcm_mac;
	} else {
		ms->ms_gcm_mac = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_block(int structureId, int index, int blockSize, void* buffer)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = blockSize;

	ms_ocall_read_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_block_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_block_t));
	ocalloc_size -= sizeof(ms_ocall_read_block_t);

	ms->ms_structureId = structureId;
	ms->ms_index = index;
	ms->ms_blockSize = blockSize;
	if (buffer != NULL) {
		ms->ms_buffer = (void*)__tmp;
		__tmp_buffer = __tmp;
		memset(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_block(int structureId, int index, int blockSize, void* buffer)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = blockSize;

	ms_ocall_write_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_block_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_block_t));
	ocalloc_size -= sizeof(ms_ocall_write_block_t);

	ms->ms_structureId = structureId;
	ms->ms_index = index;
	ms->ms_blockSize = blockSize;
	if (buffer != NULL) {
		ms->ms_buffer = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_newStructure(int newId, Obliv_Type type, int size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_newStructure_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_newStructure_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_newStructure_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_newStructure_t));
	ocalloc_size -= sizeof(ms_ocall_newStructure_t);

	ms->ms_newId = newId;
	ms->ms_type = type;
	ms->ms_size = size;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_deleteStructure(int structureId)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_deleteStructure_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_deleteStructure_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_deleteStructure_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_deleteStructure_t));
	ocalloc_size -= sizeof(ms_ocall_deleteStructure_t);

	ms->ms_structureId = structureId;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_file(const void* src, int dsize, int tableSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_src = dsize;

	ms_ocall_write_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(src, _len_src);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (src != NULL) ? _len_src : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_file_t));
	ocalloc_size -= sizeof(ms_ocall_write_file_t);

	if (src != NULL) {
		ms->ms_src = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, src, _len_src)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_src);
		ocalloc_size -= _len_src;
	} else {
		ms->ms_src = NULL;
	}
	
	ms->ms_dsize = dsize;
	ms->ms_tableSize = tableSize;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open_read(int tableSize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_open_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_read_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_read_t));
	ocalloc_size -= sizeof(ms_ocall_open_read_t);

	ms->ms_tableSize = tableSize;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_file(void* dest, int dsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = dsize;

	ms_ocall_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_file_t);
	void *__tmp = NULL;

	void *__tmp_dest = NULL;

	CHECK_ENCLAVE_POINTER(dest, _len_dest);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dest != NULL) ? _len_dest : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_file_t));
	ocalloc_size -= sizeof(ms_ocall_read_file_t);

	if (dest != NULL) {
		ms->ms_dest = (void*)__tmp;
		__tmp_dest = __tmp;
		memset(__tmp_dest, 0, _len_dest);
		__tmp = (void *)((size_t)__tmp + _len_dest);
		ocalloc_size -= _len_dest;
	} else {
		ms->ms_dest = NULL;
	}
	
	ms->ms_dsize = dsize;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (dest) {
			if (memcpy_s((void*)dest, _len_dest, __tmp_dest, _len_dest)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_make_name(void* name, int tableSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = 20;

	ms_ocall_make_name_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_make_name_t);
	void *__tmp = NULL;

	void *__tmp_name = NULL;

	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_make_name_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_make_name_t));
	ocalloc_size -= sizeof(ms_ocall_make_name_t);

	if (name != NULL) {
		ms->ms_name = (void*)__tmp;
		__tmp_name = __tmp;
		memset(__tmp_name, 0, _len_name);
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}
	
	ms->ms_tableSize = tableSize;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (name) {
			if (memcpy_s((void*)name, _len_name, __tmp_name, _len_name)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

