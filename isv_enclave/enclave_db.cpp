#include "definitions.h"
#include "isv_enclave.h"

//specific to database application, hidden from app
Schema schemas[NUM_STRUCTURES] = {0};
char* tableNames[NUM_STRUCTURES] = {0};
int rowsPerBlock[NUM_STRUCTURES] = {0};
int numRows[NUM_STRUCTURES] = {0};

int opLinearScanInsert(int structureId, int index, int offset, int length, uint8_t* data) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_SCAN) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int blockSize = sizeof(Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	//allocate dummy storage and real storage
	Linear_Scan_Block* dummy = (Linear_Scan_Block*)malloc(blockSize);
	Linear_Scan_Block* real = (Linear_Scan_Block*)malloc(blockSize);
	Encrypted_Linear_Scan_Block* dummyEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	Encrypted_Linear_Scan_Block* realEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//printf("before loop\n");
	for(int i = 0; i < size; i++){
		//printf("beginning of loop iteration %d\n", i);
		if(i == index){
			//printf("in target index\n");
			ocall_read_block(structureId, i, encBlockSize, realEnc);
			//printf("beginning of mac(op)? %d\n", realEnc->macTag[0]);
			if(decryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;
			memmove((real->data)+offset, data, length);
			if(encryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1; //replace encryption of real with encryption of block
			ocall_write_block(structureId, i, encBlockSize, realEnc);
		}
		else{
			//printf("not in target index\n");
			ocall_read_block(structureId, i, encBlockSize, dummyEnc);
			//printf("beginning of mac(op)? %d\n", dummyEnc->macTag[0]);
			if(decryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
			memmove(dummy->data+offset, (dummy->data+offset), length);//do a dummy memmove
			if(encryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
			ocall_write_block(structureId, i, encBlockSize, dummyEnc);
		}
		//printf("end of loop iteration %d\n", i);
	}
	//printf("after loop\n");
	//clean up
	free(dummy);
	free(real);
	free(dummyEnc);
	free(realEnc);
	//printf("end of insert function\n");
	return 0;
}

int opLinearScanUnencryptedInsert(int structureId, int index, int offset, int length, uint8_t* data) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_UNENCRYPTED) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int blockSize = sizeof(Linear_Scan_Block);
	//int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	//allocate dummy storage and real storage
	Linear_Scan_Block* dummy = (Linear_Scan_Block*)malloc(blockSize);
	Linear_Scan_Block* real = (Linear_Scan_Block*)malloc(blockSize);
	//Encrypted_Linear_Scan_Block* dummyEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//Encrypted_Linear_Scan_Block* realEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//printf("before loop\n");
	for(int i = 0; i < size; i++){
		//printf("beginning of loop iteration %d\n", i);
		if(i == index){
			//printf("in target index\n");
			ocall_read_block(structureId, i, blockSize, real);
			//printf("beginning of mac(op)? %d\n", realEnc->macTag[0]);
			//if(decryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;
			memmove((real->data)+offset, data, length);
			//if(encryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1; //replace encryption of real with encryption of block
			ocall_write_block(structureId, i, blockSize, real);
		}
		else{
			//printf("not in target index\n");
			ocall_read_block(structureId, i, blockSize, dummy);
			//printf("beginning of mac(op)? %d\n", dummyEnc->macTag[0]);
			memmove(dummy->data+offset, (dummy->data+offset), length);//do a dummy memmove
			ocall_write_block(structureId, i, blockSize, dummy);
		}
		//printf("end of loop iteration %d\n", i);
	}
	//printf("after loop\n");
	//clean up
	free(dummy);
	free(real);
	//printf("end of insert function\n");
	return 0;
}

int opLinearScanExactMatch(int structureId, int colNum, uint8_t* query, uint8_t* response, int* resRows) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_SCAN) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int colOffset = schemas[structureId].fieldOffsets[colNum];
	int blockSize = sizeof(Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	int rowSize = getRowSize(&schemas[structureId]);
	int fieldSize = schemas[structureId].fieldSizes[colNum];
	int resultRows = 0;
	int dummyRows = 0;
	//allocate dummy storage and real storage
	uint8_t* dummy = (uint8_t*)malloc(rowSize);
	Linear_Scan_Block* block = (Linear_Scan_Block*)malloc(blockSize);
	Encrypted_Linear_Scan_Block* blockEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//printf("before loops\n");
	for(int i = 0; i < size; i++){
		//printf("begin outer loop %d\n", i);
		ocall_read_block(structureId, i, encBlockSize, blockEnc);
		if(decryptBlock(blockEnc, block, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;
		for(int j = 0; j < rowsPerBlock[structureId]; j++){
			//printf("begin inner loop %d\n", j);
			//printf("comparing %d and %d (beginnings only) for %d bytes: %d", *query, *(block->data+(j*rowSize+colOffset)), fieldSize, memcmp(query, block->data+(j*rowSize+colOffset), fieldSize));
			//printf("%x %x; %x %x %x %x\n", query[0], query[1], *(block->data+(j*rowSize+colOffset)), *(block->data+(j*rowSize+colOffset+1)), *(block->data+(j*rowSize+colOffset+2)), *(block->data+(j*rowSize+colOffset+3)));
			if(consttime_memequal(query, block->data+(j*rowSize+colOffset), fieldSize) == 1){//this works the opposite of memcmp, 1=match
				if(i*rowsPerBlock[structureId]+j < numRows[structureId]){
					//printf("match! copying to response\n");
					memcpy(response+resultRows*rowSize, block->data+j*rowSize, rowSize);
					resultRows++;
				}
				else{
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
			}
			else{
				if(i*rowsPerBlock[structureId]+j < numRows[structureId]){
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
				else{
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
			}
		}
	}
	//printf("after loops\n");
	*resRows = resultRows;
	//printf("here\n");
	//clean up
	free(block);
	free(blockEnc);
	free(dummy);
	//printf("here\n");
	return 0;
}

int opLinearScanUnencryptedExactMatch(int structureId, int colNum, uint8_t* query, uint8_t* response, int* resRows) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_UNENCRYPTED) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int colOffset = schemas[structureId].fieldOffsets[colNum];
	int blockSize = sizeof(Linear_Scan_Block);
	//int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	int rowSize = getRowSize(&schemas[structureId]);
	int fieldSize = schemas[structureId].fieldSizes[colNum];
	int resultRows = 0;
	int dummyRows = 0;
	//allocate dummy storage and real storage
	uint8_t* dummy = (uint8_t*)malloc(rowSize);
	Linear_Scan_Block* block = (Linear_Scan_Block*)malloc(blockSize);
	//Encrypted_Linear_Scan_Block* blockEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//printf("before loops\n");
	for(int i = 0; i < size; i++){
		//printf("begin outer loop %d\n", i);
		ocall_read_block(structureId, i, blockSize, block);
		for(int j = 0; j < rowsPerBlock[structureId]; j++){
			//printf("begin inner loop %d\n", j);
			//printf("comparing %d and %d (beginnings only) for %d bytes: %d", *query, *(block->data+(j*rowSize+colOffset)), fieldSize, memcmp(query, block->data+(j*rowSize+colOffset), fieldSize));
			//printf("%x %x; %x %x %x %x\n", query[0], query[1], *(block->data+(j*rowSize+colOffset)), *(block->data+(j*rowSize+colOffset+1)), *(block->data+(j*rowSize+colOffset+2)), *(block->data+(j*rowSize+colOffset+3)));
			if(consttime_memequal(query, block->data+(j*rowSize+colOffset), fieldSize) == 1){//this works the opposite of memcmp, 1=match
				if(i*rowsPerBlock[structureId]+j < numRows[structureId]){
					//printf("match! copying to response\n");
					memcpy(response+resultRows*rowSize, block->data+j*rowSize, rowSize);
					resultRows++;
				}
				else{
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
			}
			else{
				if(i*rowsPerBlock[structureId]+j < numRows[structureId]){
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
				else{
					memcpy(dummy, block->data+j*rowSize, rowSize);
					dummyRows++;
				}
			}
		}
	}
	//printf("after loops\n");
	*resRows = resultRows;
	//printf("here\n");
	//clean up
	free(block);
	free(dummy);
	//printf("here\n");
	return 0;
}


int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId){
	sgx_status_t retVal = SGX_SUCCESS;

	//validate schema a little bit
	if(schema->numFields > MAX_COLS) return 1;
	int rowSize = getRowSize(schema);
	if(rowSize <= 0) return rowSize;
	if(BLOCK_DATA_SIZE/rowSize == 0) {//can't fit a row in a block of the data structure!
		return 4;
	}

	int initialSize = numberOfRows/(BLOCK_DATA_SIZE/rowSize)+1;
	//printf("%d %d blocks\n",numberOfRows*rowSize, initialSize);
	//if(type == TYPE_TREE_ORAM || type == TYPE_ORAM) initialSize = NUM_BLOCKS_ORAM; //since the logical size of the oram will consist of fewer blocks
	//handle increasing size for oram in the init_structure function
	retVal = init_structure(initialSize, type, structureId); //TODO: create a double-sized structure and copy all the data over when this one fills up
	if(retVal != SGX_SUCCESS) return 5;

	//size & type are set in init_structure, but we need to initiate the rest
	tableNames[*structureId] = (char*)malloc(nameLen);
	memcpy(tableNames[*structureId], tableName, nameLen);
	memcpy(&schemas[*structureId], schema, sizeof(Schema));

	rowsPerBlock[*structureId] = BLOCK_DATA_SIZE/rowSize;

	return 0;
}

int growStructure(int structureId){//TODO: make table double in size if the allocated space is full
	return 1;
}

//assuming table name has already been converted to structureId
//assuming data has already been processed so it is exactly the data that needs to be written to the data structure
//data should be of size rowSize[structureId]
int insertRow(int structureId, uint8_t* data){
	//find sequential block number in which to store the row
	int storageBlockNum = 0;
	int rowSize = getRowSize(&schemas[structureId]);
	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN: //printf("this branch %d %d\n", numRows[structureId], rowsPerBlock[structureId]);
		//printf("here %d %d\n", numRows[structureId], rowsPerBlock[structureId]);
		storageBlockNum = numRows[structureId]/rowsPerBlock[structureId];
		if(storageBlockNum >= oblivStructureSizes[structureId]) {
			//grow table if needed (or fail)
			if(growStructure(structureId)) {
				printf("fail 1 %d\n", storageBlockNum);
				return 1;
			}
		}
		if(opLinearScanInsert(structureId, storageBlockNum, (numRows[structureId]-rowsPerBlock[structureId]*storageBlockNum)*rowSize, rowSize, data)) {
			printf("fail 2\n");
			return 1;
		}
		break;
	case TYPE_LINEAR_UNENCRYPTED:
		storageBlockNum = numRows[structureId]/rowsPerBlock[structureId];
		if(storageBlockNum >= oblivStructureSizes[structureId]) {
			//grow table if needed (or fail)
			if(growStructure(structureId)) return 1;
		}
		if(opLinearScanUnencryptedInsert(structureId, storageBlockNum, (numRows[structureId]-rowsPerBlock[structureId]*storageBlockNum)*rowSize, rowSize, data)) return 1;
		break;
	case TYPE_TREE_ORAM:
		return 2;//TODO
		break;
	case TYPE_ORAM:
		return 3;
		break;
	default: return 1; break;
	}

	numRows[structureId]++;
	return 0;
}

//response should be big enough to hold all the returned data (e.g. the whole table)
int exactSearch(int structureId, int colNum, uint8_t* query, uint8_t* response, int* resRows){
	//find sequential block number in which to store the row
	int rowSize = getRowSize(&schemas[structureId]);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		if(opLinearScanExactMatch(structureId, colNum, query, response, resRows)) return 1;
		break;
	case TYPE_LINEAR_UNENCRYPTED:
		if(opLinearScanUnencryptedExactMatch(structureId, colNum, query, response, resRows)) return 1;
		break;
	case TYPE_TREE_ORAM:
		return 2;//TODO
		break;
	case TYPE_ORAM:
		return 3;
		break;
	default: return 1; break;
	}

	return 0;
}
