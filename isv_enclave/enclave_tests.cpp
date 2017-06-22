#include "definitions.h"
#include "isv_enclave.h"


sgx_status_t run_tests(){
	sgx_status_t ret = SGX_SUCCESS;

	return ret;
}

sgx_status_t testMemory(){
	for(int i = 0; i < 100; i++)
	{
		void* junk = malloc(1000000);
		free(junk);
		printf("round %d\n", i);
	}
	return SGX_SUCCESS;
}

sgx_status_t setupPerformanceTest(int structNum, int size, Obliv_Type type){
	sgx_status_t ret = SGX_SUCCESS;
	ret = init_structure(size, type, &structNum);
	return ret;
}

sgx_status_t testLinScanBlockPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen){//assume valid input
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opLinearScanBlock(structNum, queryIndex, b, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testLinScanBlockWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen){//assume valid input
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opLinearScanBlock(structNum, queryIndex, b, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testLinScanBlockUnencryptedPerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opLinearScanUnencryptedBlock(structNum, queryIndex, b, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testLinScanBlockUnencryptedWritePerformance(int structNum, int queryIndex, Linear_Scan_Block* b, int respLen){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opLinearScanUnencryptedBlock(structNum, queryIndex, b, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testOramPerformance(int structNum, int queryIndex, Oram_Block* b, int respLen){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opOramBlock(structNum, queryIndex, b, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testOramSafePerformance(int structNum, int queryIndex, Oram_Block* b, int respLen){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	retInt = opOramBlockSafe(structNum, queryIndex, b, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	return ret;
}

sgx_status_t testOpOram(){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	int oramBlockLen = sizeof(Oram_Block);

	//test of opLinearScanBlock
	int structNum = -1;
	ret = init_structure(7, TYPE_ORAM, &structNum);
	if(ret != SGX_SUCCESS) return ret;
	printf("passed oram init!\n");

	uint8_t arr0[BLOCK_DATA_SIZE] = {0};
	arr0[3]=0;arr0[8]=1;arr0[256]=3;
	Oram_Block *b0 = (Oram_Block*)malloc(oramBlockLen);
	b0->actualAddr = 0;
	memcpy(b0->data, arr0, oramBlockLen);
	retInt = opOramBlock(structNum, 0, b0, 1);
		if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opOram test part 1!\n");

	uint8_t arr1[BLOCK_DATA_SIZE] = {0};
	arr1[3]=1;arr1[8]=2;arr1[256]=4;
	Oram_Block *b1 = (Oram_Block*)malloc(oramBlockLen);
	b1->actualAddr = 1;
	memcpy(b1->data, arr1, oramBlockLen);
	retInt = opOramBlock(structNum, 1, b1, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opOram test part 2!\n");

	Oram_Block* bTest = (Oram_Block*)malloc(oramBlockLen);
	retInt = opOramBlock(structNum, 1, bTest, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	retInt = memcmp(bTest, b1, oramBlockLen);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opOram test part 3!\n");

	uint8_t arr2[BLOCK_DATA_SIZE] = {0};
	arr2[3]=0;arr2[8]=3;arr2[256]=5;
	Oram_Block *b2 = (Oram_Block*)malloc(oramBlockLen);
	b2->actualAddr = 0;
	memcpy(b2->data, arr2, oramBlockLen);
	retInt = opOramBlock(structNum, 0, b2, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opOram test part 4!\n");

	retInt = opOramBlock(structNum, 0, bTest, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	retInt = memcmp(bTest, b2, oramBlockLen);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opOram test part 5!\n");

	free(bTest);
	free(b0);
	free(b1);
	free(b2);
	return ret;
}

sgx_status_t testOpLinScanBlock(){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	int linScanBlockLen = sizeof(Linear_Scan_Block);

	//test of opLinearScanBlock
	int structNum = -1;
	ret = init_structure(7, TYPE_LINEAR_SCAN, &structNum);
	if(ret != SGX_SUCCESS) return ret;
	printf("passed opLinearScanBlock init!\n");

	uint8_t arr0[BLOCK_DATA_SIZE] = {0};
	printf("here\n");
	arr0[0]=1;arr0[256]=3;
	Linear_Scan_Block *b0 = (Linear_Scan_Block*)malloc(linScanBlockLen);
	memcpy(b0, arr0, linScanBlockLen);
	retInt = opLinearScanBlock(structNum, 0, b0, 1);
		if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opLinearScanBlock test part 1!\n");

	uint8_t arr1[BLOCK_DATA_SIZE] = {0};
	arr1[0]=2;arr1[256]=4;
	Linear_Scan_Block *b1 = (Linear_Scan_Block*)malloc(linScanBlockLen);
	memcpy(b1, arr1, linScanBlockLen);
	retInt = opLinearScanBlock(structNum, 1, b1, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opLinearScanBlock test part 2!\n");

	Linear_Scan_Block* bTest = (Linear_Scan_Block*)malloc(linScanBlockLen);
	retInt = opLinearScanBlock(structNum, 1, bTest, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	retInt = memcmp(bTest, b1, linScanBlockLen);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opLinearScanBlock test part 3!\n");

	uint8_t arr2[BLOCK_DATA_SIZE] = {0};
	arr2[0]=3;arr2[256]=5;
	Linear_Scan_Block *b2 = (Linear_Scan_Block*)malloc(linScanBlockLen);
	memcpy(b2, arr2, linScanBlockLen);
	retInt = opLinearScanBlock(structNum, 0, b2, 1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opLinearScanBlock test part 4!\n");

	retInt = opLinearScanBlock(structNum, 0, bTest, 0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	retInt = memcmp(bTest, b2, linScanBlockLen);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("Passed opLinearScanBlock test part 5!\n");

	free(bTest);
	free(b0);
	free(b1);
	free(b2);
	return ret;
}
