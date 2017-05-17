#include "definitions.h"
#include "isv_enclave.h"


sgx_status_t run_tests(){
	sgx_status_t ret = SGX_SUCCESS;

	ret = testOpLinScanBlock();
	if(ret != SGX_SUCCESS) return ret;
	ret = testLinScan(1);
	if(ret != SGX_SUCCESS) return ret;
	ret = testLinScanUnencrypted(2);
	if(ret != SGX_SUCCESS) return ret;

	printf("done running minimal tests!\n\n");

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

sgx_status_t testLinScan(int order){
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;

	//test of linear scan table creation, insertion, query
	//assuming it gets structureId 1
	const char *name = "testTable";
	char *tableName = (char*)malloc(strlen(name));
	strncpy(tableName, name, strlen(name));
	Schema *tableSchema = (Schema*)malloc(sizeof(Schema));
	Schema tempSchema = {3, {0, 4, 259}, {4, 255, 255}, {INTEGER, TINYTEXT, TINYTEXT}, -1};
	/*tempSchema.index=-1;
	tempSchema.numFields=3;
	tempSchema.fieldTypes={INTEGER, TINYTEXT, TINYTEXT};
	tempSchema.fieldSizes={4, 255, 255};
	tempSchema.fieldOffsets={0, 4, 259};*/
	memcpy(tableSchema, &tempSchema, sizeof(Schema));
	retInt = createTable(tableSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 5, &(tableSchema->index));
	if(retInt) {
		printf("table creation error %d\n schema numFields: %d", retInt, tableSchema->numFields);
		return SGX_ERROR_UNEXPECTED;
	}
	printf("passed linear scan createTable test!\n");

	int rowSize = getRowSize(tableSchema);
	uint8_t* row1 = (uint8_t*)malloc(rowSize);
	uint8_t* row2 = (uint8_t*)malloc(rowSize);
	uint8_t* row3 = (uint8_t*)malloc(rowSize);
	uint8_t* row4 = (uint8_t*)malloc(rowSize);
	uint8_t* row5 = (uint8_t*)malloc(rowSize);
	uint8_t content[rowSize] = {0};
	content[0] = (int)1;
	content[5] = 0xff;
	memcpy(row1, content, rowSize);
	printf("row 1: [0] = %x, [2]=%x\n", row1[0], row1[2]);
	retInt = insertRow(order, row1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 1\n");
	uint8_t content2[rowSize] = {0};
	content2[0] = (int)2;
	content2[5] = 0xff;
	memcpy(row2, content2, rowSize);
	retInt = insertRow(order, row2);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 2\n");
	uint8_t content3[rowSize] = {0};
	content3[0] = (int)3;
	content3[5] = 0xee;
	memcpy(row3, content3, rowSize);
	retInt = insertRow(order, row3);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 3\n");
	uint8_t content4[rowSize] = {0};
	content4[0] = (int)4;
	content4[5] = 0xff;
	memcpy(row4, content4, rowSize);
	retInt = insertRow(order, row4);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 4\n");
	uint8_t content5[rowSize] = {0};
	content5[0] = (int)5;
	content5[5] = 0xff;
	memcpy(row5, content5, rowSize);
	retInt = insertRow(order, row5);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 5\n");
	printf("passed linear scan insertRow test!\n");


	//int exactSearch(int structureId, int colNum, uint8_t* query, uint8_t* response, int* resRows){
	uint8_t q0 = 13;
	uint8_t q1 = 2;
	uint8_t q2[255] = {0}; q2[1]=0xee;
	uint8_t q3[255] = {0}; q3[1]=0xff;
	uint8_t q4[255] = {0};
	int *resRows0 = (int*)malloc(sizeof(int));
	int *resRows1 = (int*)malloc(sizeof(int));
	int *resRows2 = (int*)malloc(sizeof(int));
	int *resRows3 = (int*)malloc(sizeof(int));
	int *resRows4 = (int*)malloc(sizeof(int));
	uint8_t* res0 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res1 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res2 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res3 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res4 = (uint8_t*)malloc(rowSize*5);
	printf("beginning linear scan query test\n");
	retInt = exactSearch(order, 0, &q0, res0, resRows0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 0\n");
	retInt = exactSearch(order, 0, &q1, res1, resRows1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 1\n");
	retInt = exactSearch(order, 1, q2, res2, resRows2);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 2\n");
	retInt = exactSearch(order, 1, q3, res3, resRows3);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 3\n");
	retInt = exactSearch(order, 2, q4, res4, resRows4);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 4\n");
	if(*resRows0 != 0 || *resRows1 != 1 || *resRows2 != 1 || *resRows3 != 4 || *resRows4 != 5) {
		printf("failure: number of results per query: %d %d %d %d %d\n", *resRows0, *resRows1, *resRows2, *resRows3, *resRows4);
		return SGX_ERROR_UNEXPECTED;
	}
	if(memcmp(content2, res1, rowSize) != 0) {
		printf("failed to verify part 1 results\n");
		//printf("%d %x; %d %x\n", content[0], content[5], res1[0], res1[5]);
		return SGX_ERROR_UNEXPECTED;
	}
	if(memcmp(content3, res2, rowSize) != 0) {
		printf("failed to verify part 2 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	uint8_t* resComp = (uint8_t*)malloc(rowSize*5);
	memcpy(resComp, content, rowSize);
	memcpy(resComp+rowSize, content2, rowSize);
	memcpy(resComp+2*rowSize, content4, rowSize);
	memcpy(resComp+3*rowSize, content5, rowSize);
	if(memcmp(resComp, res3, 4*rowSize) != 0) {
		printf("failed to verify part 3 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	memcpy(resComp, content, rowSize);
	memcpy(resComp+rowSize, content2, rowSize);
	memcpy(resComp+2*rowSize, content3, rowSize);
	memcpy(resComp+3*rowSize, content4, rowSize);
	memcpy(resComp+4*rowSize, content5, rowSize);
	if(memcmp(resComp, res4, 5*rowSize) != 0) {
		printf("failed to verify part 4 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	printf("passed linear scan query test!\n");

	free(tableName);
	free(tableSchema);
	free(row1);
	free(row2);
	free(row3);
	free(row4);
	free(row5);
	free(resRows0);
	free(resRows1);
	free(resRows2);
	free(resRows3);
	free(resRows4);
	free(res0);
	free(res1);
	free(res2);
	free(res3);
	free(res4);
	free(resComp);
	return ret;
}

sgx_status_t testLinScanUnencrypted(int order){
	printf("linear scan unencrypted test\n");
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	//assuming necessary stored structures are created by the app

	//test of linear scan table creation, insertion, query
	//assuming it gets structureId 1
	const char *name = "testTable2";
	char *tableName = (char*)malloc(strlen(name));
	strncpy(tableName, name, strlen(name));
	Schema *tableSchema = (Schema*)malloc(sizeof(Schema));
	Schema tempSchema = {3, {0, 4, 259}, {4, 255, 255}, {INTEGER, TINYTEXT, TINYTEXT}, -1};
	memcpy(tableSchema, &tempSchema, sizeof(Schema));
	retInt = createTable(tableSchema, tableName, strlen(tableName), TYPE_LINEAR_UNENCRYPTED, 5, &(tableSchema->index));
	if(retInt) {
		printf("table creation error %d\n schema numFields: %d", retInt, tableSchema->numFields);
		return SGX_ERROR_UNEXPECTED;
	}
	printf("passed linear scan createTable test!\n");

	int rowSize = getRowSize(tableSchema);
	uint8_t* row1 = (uint8_t*)malloc(rowSize);
	uint8_t* row2 = (uint8_t*)malloc(rowSize);
	uint8_t* row3 = (uint8_t*)malloc(rowSize);
	uint8_t* row4 = (uint8_t*)malloc(rowSize);
	uint8_t* row5 = (uint8_t*)malloc(rowSize);
	uint8_t content[rowSize] = {0};
	content[0] = (int)1;
	content[5] = 0xff;
	memcpy(row1, content, rowSize);
	printf("row 1: [0] = %x, [2]=%x\n", row1[0], row1[2]);
	retInt = insertRow(order, row1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 1\n");
	uint8_t content2[rowSize] = {0};
	content2[0] = (int)2;
	content2[5] = 0xff;
	memcpy(row2, content2, rowSize);
	retInt = insertRow(order, row2);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 2\n");
	uint8_t content3[rowSize] = {0};
	content3[0] = (int)3;
	content3[5] = 0xee;
	memcpy(row3, content3, rowSize);
	retInt = insertRow(order, row3);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 3\n");
	uint8_t content4[rowSize] = {0};
	content4[0] = (int)4;
	content4[5] = 0xff;
	memcpy(row4, content4, rowSize);
	retInt = insertRow(order, row4);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 4\n");
	uint8_t content5[rowSize] = {0};
	content5[0] = (int)5;
	content5[5] = 0xff;
	memcpy(row5, content5, rowSize);
	retInt = insertRow(order, row5);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("insert: passed part 5\n");
	printf("passed linear scan unencrypted insertRow test!\n");


	//int exactSearch(int structureId, int colNum, uint8_t* query, uint8_t* response, int* resRows){
	uint8_t q0 = 13;
	uint8_t q1 = 2;
	uint8_t q2[255] = {0}; q2[1]=0xee;
	uint8_t q3[255] = {0}; q3[1]=0xff;
	uint8_t q4[255] = {0};
	int *resRows0 = (int*)malloc(sizeof(int));
	int *resRows1 = (int*)malloc(sizeof(int));
	int *resRows2 = (int*)malloc(sizeof(int));
	int *resRows3 = (int*)malloc(sizeof(int));
	int *resRows4 = (int*)malloc(sizeof(int));
	uint8_t* res0 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res1 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res2 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res3 = (uint8_t*)malloc(rowSize*5);
	uint8_t* res4 = (uint8_t*)malloc(rowSize*5);
	printf("beginning linear scan query test\n");
	retInt = exactSearch(order, 0, &q0, res0, resRows0);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 0\n");
	retInt = exactSearch(order, 0, &q1, res1, resRows1);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 1\n");
	retInt = exactSearch(order, 1, q2, res2, resRows2);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 2\n");
	retInt = exactSearch(order, 1, q3, res3, resRows3);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 3\n");
	retInt = exactSearch(order, 2, q4, res4, resRows4);
	if(retInt) return SGX_ERROR_UNEXPECTED;
	printf("ran part 4\n");
	if(*resRows0 != 0 || *resRows1 != 1 || *resRows2 != 1 || *resRows3 != 4 || *resRows4 != 5) {
		printf("failure: number of results per query: %d %d %d %d %d\n", *resRows0, *resRows1, *resRows2, *resRows3, *resRows4);
		return SGX_ERROR_UNEXPECTED;
	}
	if(memcmp(content2, res1, rowSize) != 0) {
		printf("failed to verify part 1 results\n");
		//printf("%d %x; %d %x\n", content[0], content[5], res1[0], res1[5]);
		return SGX_ERROR_UNEXPECTED;
	}
	if(memcmp(content3, res2, rowSize) != 0) {
		printf("failed to verify part 2 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	uint8_t* resComp = (uint8_t*)malloc(rowSize*5);
	memcpy(resComp, content, rowSize);
	memcpy(resComp+rowSize, content2, rowSize);
	memcpy(resComp+2*rowSize, content4, rowSize);
	memcpy(resComp+3*rowSize, content5, rowSize);
	if(memcmp(resComp, res3, 4*rowSize) != 0) {
		printf("failed to verify part 3 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	memcpy(resComp, content, rowSize);
	memcpy(resComp+rowSize, content2, rowSize);
	memcpy(resComp+2*rowSize, content3, rowSize);
	memcpy(resComp+3*rowSize, content4, rowSize);
	memcpy(resComp+4*rowSize, content5, rowSize);
	if(memcmp(resComp, res4, 5*rowSize) != 0) {
		printf("failed to verify part 4 results\n");
		return SGX_ERROR_UNEXPECTED;
	}
	printf("passed linear scan unencrypted query test!\n");

	free(tableName);
	free(tableSchema);
	free(row1);
	free(row2);
	free(row3);
	free(row4);
	free(row5);
	free(resRows0);
	free(resRows1);
	free(resRows2);
	free(resRows3);
	free(resRows4);
	free(res0);
	free(res1);
	free(res2);
	free(res3);
	free(res4);
	free(resComp);
	return ret;
}

sgx_status_t setup_timed_test_encrypted(int numberOfRows, Schema tempSchema) {
	//create a bunch of data and put it in database tables of different types
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;

	int order = tempSchema.index;

	//linear scan table creation, insertion, query
	const char *name = "linTestTable";
	char *tableName = (char*)malloc(strlen(name));
	strncpy(tableName, name, strlen(name));
	Schema *tableSchema = (Schema*)malloc(sizeof(Schema));
	memcpy(tableSchema, &tempSchema, sizeof(Schema));
	retInt = createTable(tableSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, numberOfRows, &(tableSchema->index));
	if(retInt) {
		printf("table creation error %d\n schema numFields: %d", retInt, tableSchema->numFields);
		return SGX_ERROR_UNEXPECTED;
	}
	printf("table created\n");

	int rowSize = getRowSize(tableSchema);//printf("row size: %d\n", rowSize);
	uint8_t* row = (uint8_t*)malloc(rowSize);
	for(int i = 0; i < 5; i++){
		if(i == 4) {
			memset(row, 0xff, rowSize);
		}
		else {
			if(sgx_read_rand(row, rowSize) != SGX_SUCCESS){
				printf("failed to generate random row\n");
			}
		}
		if(insertRow(order, row) != 0){
			printf("failed encrypted insert\n");
		}
		//if(i%500 == 0) printf("500 done");
	}
	numRows[order] = numberOfRows; //this is cheating to make the setup not take forever; actually only do 5 insertions
	printf("filled tables with data\n");
	return ret;
}

sgx_status_t setup_timed_test_unencrypted(int numberOfRows, Schema tempSchema) {
	//create a bunch of data and put it in database tables of different types
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;

	int order = tempSchema.index;

	//linear scan table creation, insertion, query
	Schema *tableSchema = (Schema*)malloc(sizeof(Schema));
	memcpy(tableSchema, &tempSchema, sizeof(Schema));
	const char *name2 = "linTestTableUnencrypted";
	char *tableName2 = (char*)malloc(strlen(name2));
	strncpy(tableName2, name2, strlen(name2));
	retInt = createTable(tableSchema, tableName2, strlen(tableName2), TYPE_LINEAR_UNENCRYPTED, numberOfRows, &(tableSchema->index));
	if(retInt) {
		printf("table creation error %d\n schema numFields: %d", retInt, tableSchema->numFields);
		return SGX_ERROR_UNEXPECTED;
	}
	printf("tables created\n");

	int rowSize = getRowSize(tableSchema);
	uint8_t* row = (uint8_t*)malloc(rowSize);
	for(int i = 0; i < 5; i++){
		if(i == 4) {
			memset(row, 0xff, rowSize);
		}
		else {
			if(sgx_read_rand(row, rowSize) != SGX_SUCCESS){
				printf("failed to generate random row\n");
			}
		}
		if(insertRow(order, row) != 0){
			printf("failed encrypted insert\n");
		}
		//if(i%500 == 0) printf("500 done");
	}
	numRows[order] = numberOfRows; //this is cheating to make the setup not take forever; actually only do 5 insertions
	printf("filled tables with data\n");

	return ret;
}

sgx_status_t linScanTimedTest(int numberOfRows, Schema tempSchema, uint8_t* query, uint8_t* response, int respLen) {
	sgx_status_t ret = SGX_SUCCESS;
	int retInt = 0;
	//respLen = (int*)malloc(sizeof(int));
	//response = (uint8_t*)malloc(sizeof(getRowSize(&tempSchema)*3));
	retInt = exactSearch(tempSchema.index, 0, query, response, &respLen);
	if(retInt) {
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}
