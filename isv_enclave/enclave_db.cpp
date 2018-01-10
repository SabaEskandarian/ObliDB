#include "definitions.h"
#include "isv_enclave.h"


//first field of every schema must be a char that is set to something other than '\0' (except for return tables)
//return tables must be handled and deleted before creation of next return table

//specific to database application, hidden from app
Schema schemas[NUM_STRUCTURES] = {0};
char* tableNames[NUM_STRUCTURES] = {0};
int rowsPerBlock[NUM_STRUCTURES] = {0}; //let's make this always 1; helpful for security and convenience; set block size appropriately for testing
int numRows[NUM_STRUCTURES] = {0};
int lastInserted[NUM_STRUCTURES] = {0};

int incrementNumRows(int structureId){
	numRows[structureId]++;
}

int rowMatchesCondition(Condition c, uint8_t* row, Schema s){

	/*for(int j = 0; j < schemas[0].numFields; j++){
		switch(schemas[0].fieldTypes[j]){
		case INTEGER:
			int temp;
			memcpy(&temp, &row[schemas[0].fieldOffsets[j]], 4);
			printf("%d", temp);
			break;
		case CHAR:
			printf("%c", row[schemas[0].fieldOffsets[j]]);
			break;
		case TINYTEXT:
			printf("%s", &row[schemas[0].fieldOffsets[j]]);
			break;
		}
		printf("  |  ");
	}
	printf("\n");*/
	//assume all inputs are good
	//printf("clauses: %d\n", c.numClauses);
	int sat = 0, flag = 0;
	do{
		if(flag){
			c = *c.nextCondition;
		}
		sat = 0;
		for(int i = 0; i < c.numClauses; i++){//printf("about to do a comparison\n");
			switch(s.fieldTypes[c.fieldNums[i]]){
			case INTEGER:
				int val, cond;
				memcpy(&val, &row[s.fieldOffsets[c.fieldNums[i]]], 4);
				memcpy(&cond, c.values[i], 4);
				if(c.conditionType[i] == 0){ //equality
					if(val == cond) {
						sat = 1;
					}
				}
				else if(c.conditionType[i] == 1) { //row val is greater than
					if(val > cond) {
						sat = 1;
					}
				}
				else { //row val is less than
					if(val < cond) {
						sat = 1;
					}
				}
				break;
			case TINYTEXT: //only check equality
				if(strncmp((char*)(&row[s.fieldOffsets[c.fieldNums[i]]]), (char*)c.values[i], 255) == 0) {
					sat = 1;
				}
				break;
			case CHAR: //only check equality
				//printf("comparing %c and %c", row[s.fieldOffsets[c.fieldNums[i]]], *(c.values[i]));
				if(row[s.fieldOffsets[c.fieldNums[i]]] == *(c.values[i])) {
					sat = 1;//printf("good");
				}
				break;
			}
		}
		//the order of these ifs is important
		if(c.numClauses == 0) sat = 1; //case there is no condition
		if(row[0] == '\0') sat = 0; //case row is deleted/dummy
		if(!sat) return 0;
		flag = 1;
	} while(c.nextCondition != NULL);
	//printf("satisfied!\n");
	return 1;
}


int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId){
	//structureId should be -1 unless we want to force a particular structure for testing
	sgx_status_t retVal = SGX_SUCCESS;

	//validate schema a little bit
	if(schema->numFields > MAX_COLS) return 1;
	int rowSize = getRowSize(schema);
	//printf("row size: %d\n", rowSize);
	if(rowSize <= 0) return rowSize;
	if(BLOCK_DATA_SIZE/rowSize == 0) {//can't fit a row in a block of the data structure!
		return 4;
	}
	if(PADDING > 0){
		numberOfRows = PADDING;
	}

	if(type == TYPE_TREE_ORAM){
		//this should be good assuming MAX_ORDER is big enough
		//if max order gets too small, replace 1.1 with something bigger
		numberOfRows = numberOfRows *1.1 -1; //need a larger memory, to store all the tree
	}
	if(type == TYPE_TREE_ORAM || type == TYPE_ORAM) numberOfRows = nextPowerOfTwo(numberOfRows+1) - 1; //get rid of the if statement to pad all tables to next power of 2 size
	numberOfRows += (numberOfRows == 0);
	int initialSize = numberOfRows;
	retVal = init_structure(initialSize, type, structureId);
	if(retVal != SGX_SUCCESS) return 5;

	//size & type are set in init_structure, but we need to initiate the rest
	tableNames[*structureId] = (char*)malloc(nameLen+1);
	strncpy(tableNames[*structureId], tableName, nameLen+1);
	memcpy(&schemas[*structureId], schema, sizeof(Schema));

	//rowsPerBlock[*structureId] = BLOCK_DATA_SIZE/rowSize;
	rowsPerBlock[*structureId] = 1; //fixed at 1 for now, see declaration
	numRows[*structureId] = 0;

	return 0;
}

int deleteTable(char *tableName) {
	int structureId = getTableId(tableName);
	free_structure(structureId);
	free(tableNames[structureId]);
	numRows[structureId] = 0;
	schemas[structureId] = {0};
}

int growStructure(int structureId){//TODO: make table double in size if the allocated space is full
	return 1; //likely to remain unimplemented
}

int getTableId(char *tableName) {
	for(int i = 0; i < NUM_STRUCTURES; i++){
		if(tableNames[i] != NULL && strcmp(tableName, tableNames[i]) == 0){
			return i;
		}
	}
	return -1;
}

int renameTable(char *oldTableName, char *newTableName){
	int nameLen = strlen(newTableName);
	for(int i = 0; i < NUM_STRUCTURES; i++){
		if(tableNames[i] != NULL && strcmp(oldTableName, tableNames[i]) == 0){
			free(tableNames[i]);
			tableNames[i] = (char*)malloc(nameLen+1);
			strncpy(tableNames[i], newTableName, nameLen+1);
			return i;
		}
	}
	return -1;
}

Schema getTableSchema(char *tableName) {
	int structureId = getTableId(tableName);
	return schemas[structureId];
}

int insertIndexRowFast(char* tableName, uint8_t* row, int key) {//trust that the row is good and insert it
	int structureId = getTableId(tableName);
	int done = 0;
	int dummyDone = 0;
	if(numRows[structureId] == oblivStructureSizes[structureId]){
		growStructure(structureId);//not implemented
	}
	uint8_t* tempRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	record *temp = make_record(structureId, row);
	//printf("before insert %d", key);
	bPlusRoots[structureId] = insert(structureId, bPlusRoots[structureId], key, temp);
	//printf("after insert\n");
	if(bPlusRoots[structureId] == NULL) printf("bad news...\n");
	free(temp);
	Oram_Block* oblock = (Oram_Block*)malloc(sizeof(Oram_Block));
	//printf("starting padding\n");
	free(oblock);

	numRows[structureId]++;
	free(tempRow);
}

int insertLinRowFast(char* tableName, uint8_t* row){
	int structureId = getTableId(tableName);
	int done = 0;
	int dummyDone = 0;
	if(numRows[structureId] == oblivStructureSizes[structureId]){
		growStructure(structureId);//not implemented
	}
	int insertId = lastInserted[structureId];	
	opOneLinearScanBlock(structureId, insertId, (Linear_Scan_Block*)row, 1);
	lastInserted[structureId]++;
}


int insertRow(char* tableName, uint8_t* row, int key) {//trust that the row is good and insert it
	int structureId = getTableId(tableName);
	int done = 0;
	int dummyDone = 0;
	if(numRows[structureId] == oblivStructureSizes[structureId]){
		growStructure(structureId);//not implemented
	}
	uint8_t* tempRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < oblivStructureSizes[structureId]; i++){
			opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
			if(tempRow[0] == '\0' && done == 0){
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 1);
				done++;
			}
			else{
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
				dummyDone++;
			}
		}
		break;
	case TYPE_TREE_ORAM:
		record *temp = make_record(structureId, row);
		//printf("before insert %d", key);
		currentPad = 0;
		bPlusRoots[structureId] = insert(structureId, bPlusRoots[structureId], key, temp);
		//printf("after insert\n");
		if(bPlusRoots[structureId] == NULL) printf("bad news...\n");
		free(temp);
		Oram_Block* oblock = (Oram_Block*)malloc(sizeof(Oram_Block));
		//printf("starting padding\n");
		while(currentPad < maxPad){
			currentPad++;//printf("padding... %d %d\n", currentPad,maxPad);
			opOramBlock(structureId, oblivStructureSizes[structureId]-1, oblock, 0);
		}
		free(oblock);
		break;
	}
	numRows[structureId]++;
	free(tempRow);
}

int deleteRow(char* tableName, int key) {
	int structureId = getTableId(tableName);
	node *root = bPlusRoots[structureId];
	Oram_Block* b = (Oram_Block*)malloc(sizeof(Oram_Block));
	int i;
	node * n = find_leaf(structureId, root, key);
	if (n == NULL) return 0;
	for (i = 0; i < n->num_keys && n->keys[i] < key; i++) ;
	if (i == n->num_keys) return 0;
	opOramBlock(structureId, n->pointers[i], b, 0);
	bPlusRoots[structureId] = delete_entry(structureId, root, n, n->keys[i], b);
	numRows[structureId]--;
	
	free(b);

	currentPad = 0;
	Oram_Block* oblock = (Oram_Block*)malloc(sizeof(Oram_Block));
	while(currentPad < maxPad){
		currentPad++;
		opOramBlock(structureId, oblivStructureSizes[structureId]-1, oblock, 0);
	}
	free(oblock);
}

int deleteRows(char* tableName, Condition c, int startKey, int endKey) {
	int structureId = getTableId(tableName);
	int dummyVar = 0;
	uint8_t* tempRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* dummyRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	memset(dummyRow, '\0', BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < oblivStructureSizes[structureId]; i++){
			opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
			//delete if it matches the condition, write back otherwise
			if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0'){
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)dummyRow, 1);
				numRows[structureId]--;
			}
			else{
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
				dummyVar--;
			}
		}
		free(tempRow);
		break;
	case TYPE_TREE_ORAM:
		free(tempRow);
		int imgivingupanddontcareflag = 0, markedFlag = -1;
		node *root = bPlusRoots[structureId];
		Oram_Block* b = (Oram_Block*)malloc(sizeof(Oram_Block));
		int i, num_found;
		num_found = 0;
		node * n = find_leaf(structureId, root, startKey);
		node *saveN = (node*)malloc(sizeof(record));
		node *saveB = (node*)malloc(sizeof(record));
		if (n == NULL) return 0;
		for (i = 0; i < n->num_keys && n->keys[i] < startKey; i++) ;
		if (i == n->num_keys) return 0;
		while (n != NULL) {//printf("outer loop\n");
			for ( ; n != NULL && i < n->num_keys && n->keys[i] <= endKey; i++) {//printf("inner loop %d", n->pointers[i]);
				opOramBlock(structureId, n->pointers[i], b, 0);
				tempRow = b->data;
				//printf("here %d\n", b->actualAddr);

				if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0' && !imgivingupanddontcareflag && markedFlag == -1){
					//printf("before...");
					//bPlusRoots[structureId] = delete_entry(structureId, root, n, n->keys[i], b);
					//imgivingupanddontcareflag = 1;
					//numRows[structureId]--;
					memcpy(saveN, n, sizeof(record));
					memcpy(saveB, b, sizeof(record));
					markedFlag = i;
					//printf("after\n");

					break;
				}
				else{//not sure what to put in dummy branch to match pattern of deletion. Maybe pick a random number and do that many ops?
					//opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
					dummyVar--;
				}
			}
			if(imgivingupanddontcareflag) break;
			//printf("after inner loop %d\n", n->pointers[MAX_ORDER - 1]);
			if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > endKey){i = 0; break;}
			followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
			//n = (node*)n->pointers[order - 1];
			i = 0;
		}

		currentPad = 0;
		if(markedFlag != -1){
			bPlusRoots[structureId] = delete_entry(structureId, root, saveN, saveN->keys[markedFlag], saveB);
			numRows[structureId]--;
		}

		free(b);
		//free(saveN); this sometimes caused segfaults... idk just going with it
		free(saveB);
		Oram_Block* oblock = (Oram_Block*)malloc(sizeof(Oram_Block));
		while(currentPad < maxPad){
			currentPad++;
			opOramBlock(structureId, oblivStructureSizes[structureId]-1, oblock, 0);
		}
		free(oblock);
		//if(n != NULL){
		//	free(n);
		//}
		break;
	}
	free(dummyRow);
}

int updateRows(char* tableName, Condition c, int colChoice, uint8_t* colVal, int startKey, int endKey){
	int structureId = getTableId(tableName);
	uint8_t* tempRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* dummyRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < oblivStructureSizes[structureId]; i++){//printf("in loop\n");
			opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);//printf("past\n");
			//update if it matches the condition, write back otherwise
			if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0'){
				//make changes
				memcpy(&tempRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
			}
			else{
				//make dummy changes
				memcpy(&dummyRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
			}
		}
		free(tempRow);
		break;
	case TYPE_TREE_ORAM:
		free(tempRow);
		node *root = bPlusRoots[structureId];
		Oram_Block* b = (Oram_Block*)malloc(sizeof(Oram_Block));
		int i, num_found;
		num_found = 0;
		node * n = find_leaf(structureId, root, startKey);
		if (n == NULL) return 0;
		for (i = 0; i < n->num_keys && n->keys[i] < startKey; i++) ;
		if (i == n->num_keys) return 0;

		while (n != NULL) {//printf("outer loop\n");
			for ( ; i < n->num_keys && n->keys[i] <= endKey; i++) {//printf("inner loop");
				opOramBlock(structureId, n->pointers[i], b, 0);
				tempRow = b->data;

				if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0'){
					memcpy(&tempRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
					opOramBlock(structureId, n->pointers[i], b, 1);
				}
				else{
					memcpy(&dummyRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
					opOramBlock(structureId, n->pointers[i], b, 1);
				}

			}

			if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > endKey){i = 0; break;}
			followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
			//n = (node*)n->pointers[order - 1];
			i = 0;
		}
		free(b);
		free(n);
		break;
	}
	free(dummyRow);
}

int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey) {//put the smaller table first for
	//create an oram, do block nested loop join in it, and manually convert it to a linear scan table
	int structureId1 = getTableId(tableName1);
	int structureId2 = getTableId(tableName2);//printf("table ids %d %d\n", structureId1, structureId2);
	Obliv_Type type1 = oblivStructureTypes[structureId1];
	Obliv_Type type2 = oblivStructureTypes[structureId2];
	uint8_t* row; //= (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* row1; //= (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* row2; //= (uint8_t*)malloc(BLOCK_DATA_SIZE);
	char* retTableName = "JoinTable";
	char* realRetTableName = "JoinReturn";
	int retStructId = -1;
	int realRetStructId = -1;
	int dummyVal = 0;

	int size = JOINMAX;

	//this may cause issues if the table returned is big. Table ordering matters on the input

	//figure out joined table schema
	Schema s2 = schemas[structureId2];//need the second schema sometimes

	Schema s;
	s.numFields = schemas[structureId1].numFields+schemas[structureId2].numFields - 2; //duplicate first field, duplicate join col
	int shift = 0;//printf("at the start\n");
	for(int i = 0; i < schemas[structureId1].numFields; i++){//printf("in loop %d %d\n", i, schemas[structureId1].numFields);
		s.fieldOffsets[i] = schemas[structureId1].fieldOffsets[i];
		s.fieldSizes[i] = schemas[structureId1].fieldSizes[i];
		s.fieldTypes[i] = schemas[structureId1].fieldTypes[i];
		shift++;
	}
	for(int i = 1; i < schemas[structureId2].numFields; i++){
		if(i == joinCol2) continue;
		//printf("shift: %d\n", shift);
		s.fieldOffsets[shift] = s.fieldOffsets[shift-1]+s.fieldSizes[shift-1];
		s.fieldSizes[shift] = schemas[structureId2].fieldSizes[i];
		s.fieldTypes[shift] = schemas[structureId2].fieldTypes[i];
		shift++;
	}

	if(type1 == TYPE_LINEAR_SCAN && type2 == TYPE_LINEAR_SCAN){
		//note: to match the functionality of the index join where we specify a range of keys,
		//we would have to do a select after this join
		printf("JOIN\n");
		row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
		row1 = (uint8_t*)malloc(BLOCK_DATA_SIZE);
		row2 = (uint8_t*)malloc(BLOCK_DATA_SIZE);
		uint8_t* block = (uint8_t*)malloc(BLOCK_DATA_SIZE);
		//allocate hash table
		uint8_t* hashTable = (uint8_t*)malloc(ROWS_IN_ENCLAVE*BLOCK_DATA_SIZE);
		uint8_t* hashIn = (uint8_t*)malloc(1+s.fieldSizes[joinCol1]);
		sgx_sha256_hash_t* hashOut = (sgx_sha256_hash_t*)malloc(256);
		unsigned int index = 0;

		createTable(&s, realRetTableName, strlen(realRetTableName), TYPE_LINEAR_SCAN, size, &realRetStructId);
		//createTable(&s, realRetTableName, strlen(realRetTableName), TYPE_LINEAR_SCAN, size, &realRetStructId);
		//printf("table creation returned %d %d %d\n", retStructId, size, strlen(retTableName));

		for(int i = 0; i < oblivStructureSizes[structureId1]; i+=(ROWS_IN_ENCLAVE/4)){
			//initialize hash table
			memset(hashTable, '\0', ROWS_IN_ENCLAVE*BLOCK_DATA_SIZE);

			for(int j = 0; j<(ROWS_IN_ENCLAVE/4) && i+j < oblivStructureSizes[structureId1]; j++){
				//get row
				opOneLinearScanBlock(structureId1, i+j, (Linear_Scan_Block*)row, 0);
				if(row[0] == '\0') continue;
				//insert into hash table
				int insertCounter = 0;//increment on failure to insert, set to -1 on successful insertion

				do{
					//compute hash
					memset(hashIn, 0, 1+s.fieldSizes[joinCol1]);
					hashIn[0] = insertCounter;
					if(s.fieldTypes[joinCol1] != TINYTEXT)
						memcpy(&hashIn[1], &row[s.fieldOffsets[joinCol1]], s.fieldSizes[joinCol1]);
					else
						strncpy((char*)&hashIn[1], (char*)&row[s.fieldOffsets[joinCol1]], s.fieldSizes[joinCol1]);
					sgx_sha256_msg(hashIn, 1+s.fieldSizes[joinCol1], hashOut);
					memcpy(&index, hashOut, 4);
					index %= ROWS_IN_ENCLAVE;
					//printf("hash input: %s\nhash output: %d\n", &hashIn[1], index);
					//try inserting or increment counter
					if(hashTable[BLOCK_DATA_SIZE*index] == '\0'){
						memcpy(&hashTable[BLOCK_DATA_SIZE*index], row, BLOCK_DATA_SIZE);
						insertCounter = -1;
					}
					else{
						//printf("%d next\n", index);
						insertCounter++;
					}
				}
				while(insertCounter != -1);
			}
			//printf("\n");
			for(int j = 0; j<oblivStructureSizes[structureId2]; j++){
				//get row
				opOneLinearScanBlock(structureId2, j, (Linear_Scan_Block*)row, 0);
				if(row[0] == '\0') continue;
				int checkCounter = 0, match = -1;
				do{
					//compute hash
					memset(hashIn, 0, 1+s2.fieldSizes[joinCol2]);
					hashIn[0] = checkCounter;
					if(s2.fieldTypes[joinCol2] != TINYTEXT){
						memcpy(&hashIn[1], &row[s2.fieldOffsets[joinCol2]], s2.fieldSizes[joinCol2]);
					}
					else{
						strncpy((char*)&hashIn[1], (char*)&row[s2.fieldOffsets[joinCol2]], s2.fieldSizes[joinCol2]);
					}
					sgx_sha256_msg(hashIn, 1+s2.fieldSizes[joinCol2], hashOut);
					memcpy(&index, hashOut, 4);
					index %= ROWS_IN_ENCLAVE;
					//printf("hash input: %s\nhash output: %d\n", &hashIn[1], index);
					//printf("%d %d %d %d\n", joinCol2, s2.fieldSizes[joinCol2], s2.fieldOffsets[joinCol2], s2.fieldTypes[joinCol2]);
					//compare hash against hash table
					if(hashTable[BLOCK_DATA_SIZE*index] == '\0' || row[0] == '\0'){
						checkCounter = -1;
						//printf("here??");
					}
					else if(memcmp(&row[schemas[structureId2].fieldOffsets[joinCol2]], &hashTable[index*BLOCK_DATA_SIZE+s.fieldOffsets[joinCol1]], s.fieldSizes[joinCol1]) == 0){
						//	|| schemas[structureId2].fieldTypes[joinCol2] == TINYTEXT &&
						//	strncmp((char*)&row[schemas[structureId2].fieldOffsets[joinCol2]], (char*)&hashTable[index*BLOCK_DATA_SIZE+s.fieldOffsets[joinCol1]], s.fieldSizes[joinCol1]) == 0){//match
						//printf("valid byte: %d %d\n", hashTable[BLOCK_DATA_SIZE*index], hashTable[BLOCK_DATA_SIZE*index+1]);

						//printf("matching vals: %d %d %d\n", row[schemas[structureId2].fieldOffsets[joinCol2]], hashTable[index*BLOCK_DATA_SIZE+s.fieldOffsets[joinCol1]], s.fieldSizes[joinCol1]);
						match = index;
						checkCounter = -1;
					}
					else{//false match
						//printf("here???");
						checkCounter++;
					}

				}while(checkCounter != -1);

				if(match != -1){//printf("match!\n");
					//assemble new row
					memcpy(&row1[0], &hashTable[match*BLOCK_DATA_SIZE], BLOCK_DATA_SIZE);
					shift = getRowSize(&schemas[structureId1]);
					for(int k = 1; k < schemas[structureId2].numFields; k++){
						if(k == joinCol2) continue;
						memcpy(&row1[shift], &row[schemas[structureId2].fieldOffsets[k]], schemas[structureId2].fieldSizes[k]);
						shift+= schemas[structureId2].fieldSizes[k];
					}
					match = 1;
				}
				else{//dummy op
					memcpy(&row1[0], &hashTable[0*BLOCK_DATA_SIZE], BLOCK_DATA_SIZE);
					row1[0] = '\0';
					shift = getRowSize(&schemas[structureId1]);
					for(int k = 1; k < schemas[structureId2].numFields; k++){
						if(k == joinCol2) continue;
						memcpy(&row1[shift], &row[schemas[structureId2].fieldOffsets[k]], schemas[structureId2].fieldSizes[k]);
						shift+= schemas[structureId2].fieldSizes[k];
					}
					match = 0;
				}

				//block->actualAddr = numRows[retStructId];
				memcpy(block, &row1[0], BLOCK_DATA_SIZE);

				opOneLinearScanBlock(realRetStructId, numRows[realRetStructId], (Linear_Scan_Block*)block, match);
				if(match) {
					//printf("here? %d\n", numRows[realRetStructId]);
					numRows[realRetStructId]++;
				}
				else {
					dummyVal++;
				}

			}
			//printf("here\n");
		}

		free(hashTable);
		free(hashIn);
		free(hashOut);

		free(row);
		free(row1);
		free(row2);
		free(block);
	}
	else if(type1 == TYPE_TREE_ORAM && type2 == TYPE_TREE_ORAM){
		printf("LEFT JOIN\n");
		//assuming that the join column is the same one as the index
		//assuming that each row in the first table only matches one row in the second table
		createTable(&s, retTableName, strlen(retTableName), TYPE_ORAM, size, &retStructId);
		createTable(&s, realRetTableName, strlen(realRetTableName), TYPE_LINEAR_SCAN, size, &realRetStructId);
		Oram_Block* b1 = (Oram_Block*)malloc(sizeof(Oram_Block));
		Oram_Block* b2 = (Oram_Block*)malloc(sizeof(Oram_Block));
		Oram_Block* block = (Oram_Block*)malloc(getBlockSize(TYPE_ORAM));
		row = (uint8_t*)malloc(BLOCK_DATA_SIZE);


		int i1, i2;
		node *root1 = (node*)malloc(sizeof(node));
		node *root2 = (node*)malloc(sizeof(node));
		if(bPlusRoots[structureId1] != NULL && bPlusRoots[structureId2] != NULL){
			memcpy(root1, bPlusRoots[structureId1], sizeof(node));
			memcpy(root2, bPlusRoots[structureId2], sizeof(node));
		}
		else{
			printf("no root!\n");
			return 1;
		}

		int n1Ended = 0, n2Ended = 0;
		int n1Advance = 0, n2Advance = 0;
		node * n1 = find_leaf(structureId1, root1, startKey);
		node * n2 = find_leaf(structureId2, root2, startKey);
		if(n1 == NULL) return 0;
		if(n2 == NULL) return 0;
		for (i1 = 0; i1 < n1->num_keys && n1->keys[i1] < startKey; i1++);// printf("i1 %d\n", i1);
		if (i1 == n1->num_keys) return 0;
		for (i2 = 0; i2 < n2->num_keys && n2->keys[i2] < startKey; i2++);// printf("i2 %d\n", i2);
		if (i2 == n2->num_keys) return 0;

		if(!(i1 < n1->num_keys && n1->keys[i1] <= endKey) || !(i2 < n2->num_keys && n2->keys[i2] <= endKey)){
			printf("fail\n");
			n1Ended = 1; n2Ended = 1;	//one of the tables has 0 applicable rows
		}
		int n1Lonely = 1;
		while (!n1Ended || !n2Ended) {//printf("in loop %d %d %d %d %d %d\n", i1, i2, n1->num_keys, n2->num_keys, n1Ended, n2Ended);
				if(n1Ended) i1 = n1->num_keys-1;
				if(n2Ended) i2 = n2->num_keys-1;
				opOramBlock(structureId1, n1->pointers[i1], b1, 0);
				row1 = b1->data;

				opOramBlock(structureId2, n2->pointers[i2], b2, 0);
				row2 = b2->data;
				int match = 0;
				//see if there is a match; if so, add to output and advance right pointer
				if(memcmp(&row1[schemas[structureId1].fieldOffsets[joinCol1]], &row2[schemas[structureId2].fieldOffsets[joinCol2]], s.fieldSizes[joinCol1]) == 0
						&& n1->keys[i1] <= endKey && n2->keys[i2] <= endKey && row1[0]!='\0' && row2[0]!='\0' && (!n1Ended && !n2Ended)){//match
					//printf("match!\n");
					//assemble new row
					memcpy(&row[0], &row1[0], BLOCK_DATA_SIZE);
					shift = getRowSize(&schemas[structureId1]);
					for(int k = 1; k < schemas[structureId2].numFields; k++){
						if(k == joinCol2) continue;
						memcpy(&row[shift], &row2[schemas[structureId2].fieldOffsets[k]], schemas[structureId2].fieldSizes[k]);
						shift+= schemas[structureId2].fieldSizes[k];
					}
					//n1Advance++;
					n2Advance++;
					match = 1;
					n1Lonely = 0;
					//put in some dummy stuff to match the other branch
					if(n1Ended) dummyVal++;
					else if(n2Ended) dummyVal--;
					else if(n1->keys[i1] < n2->keys[i2]) dummyVal++;
					else dummyVal--;
				}
				else{//else advance the lesser pointer
					//printf("no match\n");
					//put in dummy stuff to look like other branch
					memcpy(&row[0], &row1[0], BLOCK_DATA_SIZE);
					shift = getRowSize(&schemas[structureId1]);
					for(int k = 1; k < schemas[structureId2].numFields; k++){
						if(k == joinCol2) continue;
						memcpy(&row[shift], &row2[schemas[structureId2].fieldOffsets[k]], schemas[structureId2].fieldSizes[k]);
						shift+= schemas[structureId2].fieldSizes[k];
					}
					//dummyVal++;
					dummyVal++;
					match = 0;
					dummyVal = 0;
					//actual operation
					if(n1Ended) n2Advance++;
					else if(n2Ended) n1Advance++;
					else if(n1->keys[i1] < n2->keys[i2]) n1Advance++;
					else n2Advance++;
				}

				block->actualAddr = numRows[retStructId];
				memcpy(&block->data[0], &row[0], BLOCK_DATA_SIZE);
				//printf("match %d", match);
				//do oram op, write if there's a match
				//printf("here? %d %d", retStructId, numRows[retStructId]);
				if(match) {
					usedBlocks[retStructId][numRows[retStructId]]=1;
					numRows[retStructId]++;
					numRows[realRetStructId]++;
				}
				else {
					dummyVal++;
					dummyVal++;
				}

				if(match){
					opOramBlock(retStructId, numRows[retStructId]-1, block, 1);
				}
				else{
					opOramBlock(retStructId, numRows[retStructId], block, 0);
				}



			if(n1Advance){//printf("n1Advance");
				i1++;
				n1Advance = 0;
				if(n1Lonely){//put in row with NULLs
					//assemble new row
					memcpy(&row[0], &row1[0], BLOCK_DATA_SIZE);
					shift = getRowSize(&schemas[structureId1]);
					for(int k = 1; k < schemas[structureId2].numFields; k++){
						if(k == joinCol2) continue;
						//memcpy(&row[shift], &row2[schemas[structureId2].fieldOffsets[k]], schemas[structureId2].fieldSizes[k]);
						memset(&row[shift], 0, schemas[structureId2].fieldSizes[k]);
						shift+= schemas[structureId2].fieldSizes[k];
					}
					block->actualAddr = numRows[retStructId];
					memcpy(&block->data[0], &row[0], BLOCK_DATA_SIZE);

					opOramBlock(retStructId, numRows[retStructId], block, 1);
					numRows[retStructId]++;
					numRows[realRetStructId]++;
				}
				n1Lonely = 1;
			}
			if(n2Advance){//printf("n2Advance");
				i2++;
				n2Advance = 0;
			}
			if(!(i1 < n1->num_keys && n1->keys[i1] <= endKey)){
				if(n1->pointers[MAX_ORDER-1] == -1 || n1->keys[i1-1] > endKey)
				{
					n1Ended = 1;
				}
				else{
					followNodePointer(structureId1, n1, n1->pointers[MAX_ORDER - 1]);
					i1 = 0;
				}
			}
			if(!(i2 < n2->num_keys && n2->keys[i2] <= endKey)){
				if(n2->pointers[MAX_ORDER-1] == -1 || n2->keys[i2-1] > endKey)
				{
					n2Ended = 1;
				}
				else{
					followNodePointer(structureId2, n2, n2->pointers[MAX_ORDER - 1]);
					i2 = 0;
				}
			}
		}
		memset(row, '\0', BLOCK_DATA_SIZE);

		for(int i = 0; i < size; i++){
			//printf("size: %d\n", size);
			//opOramBlock(retStructId, i, block, 0);
			if(i < numRows[realRetStructId]){
				opOramBlock(retStructId, i, block, 0);
				opOneLinearScanBlock(realRetStructId, i, (Linear_Scan_Block*)&block->data[0], 1);
			}
			else{
				opOramBlock(retStructId, numRows[realRetStructId]-1, block, 0);
				opOneLinearScanBlock(realRetStructId, i, (Linear_Scan_Block*)&row[0], 1);
			}
		}

		deleteTable("JoinTable");

		free(b1);
		free(b2);
		free(row);
	}
	else{
		return 1; //TODO
	}
	return 0;
}

extern int indexSelect(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end, int intermediate){
	int structureId = getTableId(tableName);
	node *root = (node*)malloc(sizeof(node));
	if(bPlusRoots[structureId] != NULL){
		memcpy(root, bPlusRoots[structureId], sizeof(node));
	}
	else{
		printf("no root! %d\n", structureId);
		return 1;
	}
	//printf("here %d %d %d\n", root->num_keys, root->keys[0], root->actualAddr);

	Obliv_Type type = oblivStructureTypes[structureId];
	int colChoiceSize = BLOCK_DATA_SIZE;
	DB_Type colChoiceType = INTEGER;
	int colChoiceOffset = 0;
	uint8_t* dummy = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	dummy[0]='\0';
	if(colChoice != -1){
		colChoiceSize = schemas[structureId].fieldSizes[colChoice];
		colChoiceType = schemas[structureId].fieldTypes[colChoice];
		colChoiceOffset = schemas[structureId].fieldOffsets[colChoice];
		free(dummy);
		dummy = (uint8_t*)malloc(colChoiceSize+1);
		dummy[0]='\0';
	}
	int count = 0, rangeCount = 0, num_found = 0;
	int stat = 0;
	uint8_t* row; //= (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* row2; //= (uint8_t*)malloc(BLOCK_DATA_SIZE);
	char *retName = "ReturnTable";
	int retNameLen = strlen(retName);
	int retStructId = -1;
	Obliv_Type retType = TYPE_LINEAR_SCAN;
	Schema retSchema; //set later
	int retNumRows = 0; //set later

	Oram_Block* b = (Oram_Block*)malloc(sizeof(Oram_Block));
	Oram_Block* b2 = (Oram_Block*)malloc(sizeof(Oram_Block));

	Oram_Block* saveStart = (Oram_Block*)malloc(sizeof(Oram_Block));

	int i;
	node * n = find_leaf(structureId, root, key_start);

	//printf("something about n %d", n->is_leaf);
	if (n == NULL) {
		printf("returning here, n is NULL\n");
		return 0;
	}
	//printf("starting select for index\n");//return 1;

	for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++);// printf("n->keys[i] %d\n", n->keys[i]);
	if (i == n->num_keys) {
		printf("now returning zero %d %d\n", n->keys[i-1], key_start);
		return 0;
	}
	memcpy(&saveStart[0], &n[0], sizeof(Oram_Block));
	//find size of output and whether it is continuous
	if(groupCol == -1){
		if(aggregate == -1){ //actual select
			//printf("SELECT\n");
			int almostAll = 0;
			int continuous = 0;
			int small = 0;
			int contTemp = 0;
			int dummyVar = 0;
			int baseline = 0;
			while (n != NULL) {//printf("here %d %d\n", n->num_keys, n->keys[i]);//printf("outer loop %d %d %d\n", n->num_keys, n->keys[i], key_end);
				for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
					//printf("inner loop");
						opOramBlock(structureId, n->pointers[i], b, 0);
						row = b->data;
						/*
						//temp

						for(int j = 1; j < schemas[structureId].numFields; j++){
							switch(schemas[structureId].fieldTypes[j]){
							case INTEGER:
								int temp;
								memcpy(&temp, &row[schemas[structureId].fieldOffsets[j]], 4);
								printf("%d", temp);
								break;
							case CHAR:
								printf("%c", row[schemas[structureId].fieldOffsets[j]]);
								break;
							case TINYTEXT:
								printf("%s", &row[schemas[structureId].fieldOffsets[j]]);
								break;
							}
							printf("  |  ");
						}
						printf("\n");

						//end temp
						 */
						if(row[0] != '\0') rangeCount++;
						if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
							count++;
							if(!continuous && !contTemp){//first hit
								continuous = 1;
							}
							else if(continuous && contTemp){//a noncontinuous hit
								continuous = 0;
							}
						}
						else{
							dummyVar++;
							if(continuous && !contTemp){//end of continuous chunk
								contTemp = 1;
							}
						}
				}
				if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
				followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
				//n = (node*)n->pointers[order - 1];
				i = 0;
			}
			num_found = count;

			if(count > oblivStructureSizes[structureId]*.01*PERCENT_ALMOST_ALL && colChoice == -1){ //return almost all only if the whole row is selected (to make my life easier)
				almostAll = 1;
			}
			if(count < 5*ROWS_IN_ENCLAVE){
				small = 1;
				if(count < ROWS_IN_ENCLAVE && continuous == 1) continuous = 0;
			}

			switch(algChoice){
			case 1:
				continuous = 1;
				small = 0;
				break;
			case 2:
				continuous = 0;
				small = 1;
				break;
			case 3:
				continuous = 0;
				small = 0;
				break;
			case 5:
				baseline = 1;
				continuous = 0;
				small = 0;
				break;
			}

			//printf("%d %f\n",count,  oblivStructureSizes[structureId]*.01*PERCENT_ALMOST_ALL); //count and count needed for almost all

			//create table to return
			if(small || continuous){
				retNumRows = count; //printf("count %d %d\n", count, rangeCount);
			}
			else{//hash
				retNumRows = count*3/2;
			}
			if(colChoice != -1){ //include selected col only
				retSchema.numFields = 2;
				retSchema.fieldOffsets[0] = 0;
				retSchema.fieldOffsets[1] = 1;
				retSchema.fieldSizes[0] = 1;
				retSchema.fieldSizes[1] = colChoiceSize;
				retSchema.fieldTypes[0] = CHAR;
				retSchema.fieldTypes[1] = colChoiceType;
			}
			else{ //include whole selected row
				retSchema = schemas[structureId];
			}

			//printf("%d %d %d %d %s %d %d\n", retNameLen, retNumRows, retStructId, retType, retName, retSchema.numFields, retSchema.fieldSizes[1]);
			if(intermediate) retNumRows = oblivStructureSizes[structureId];
			if(PADDING) retNumRows = PADDING;
			int out = createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);
			//printf("%d |\n", out);
			if(count == 0) {
				free(b);
				free(b2);
				free(n);
				free(saveStart);
				free(root);
				return 0;
			}
			if(baseline){
				printf("BASELINE\n");
				Oram_Block* oBlock = (Oram_Block*)malloc(getBlockSize(TYPE_ORAM));
				int oramTableId = -1;
				char* oramName = "tempOram";
				createTable(&retSchema, oramName, strlen(oramName), TYPE_ORAM, retNumRows, &oramTableId);
				memset(oBlock, 0, sizeof(Oram_Block));
				opOramBlock(oramTableId, 0, oBlock, 1);

				int dummyVar = 0;//NOTE: rowi left in for historical reasons; it should be replaced by i
				int oramRows = 0;

				memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
				for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;//printf("i %d\n", i);
				if (i == n->num_keys) return 0;
				while (n != NULL) {//printf("outer loop\n");
					for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {//printf("inner loop %d %d", n->keys[i], key_end);
						opOramBlock(structureId, n->pointers[i], b, 0);
						row = b->data;
						//oBlock->data = ((Linear_Scan_Block*)(oBlock->data))->data;
						int match = rowMatchesCondition(c, oBlock->data, schemas[structureId]) && oBlock->data[0] != '\0';
						if(colChoice != -1){
							memset(&oBlock->data[0], 'a', 1);
							memmove(&oBlock->data[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
						}
						oBlock->actualAddr = oramRows;
						if(match){
							usedBlocks[oramTableId][oramRows]=1;
							opOramBlock(oramTableId, oramRows, oBlock, 1);
							oramRows++;
						}
						else{
							dummyVar=1;
							opOramBlock(oramTableId, 0, oBlock, 0);
							dummyVar++;
						}
					}
					if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
					followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
					//n = (node*)n->pointers[order - 1];
					i = 0;
				}

				//copy back to linear structure
				for(int i = 0; i < oramRows; i++){
					opOramBlock(oramTableId, i, oBlock, 0);
					opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)(oBlock->data), 1);
					numRows[retStructId]++;
				}
				free(oBlock);
			}
			else if(continuous){
				printf("CONTINUOUS\n");
				int rowi = -1, dummyVar = 0;//NOTE: rowi left in for historical reasons; it should be replaced by i

				memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
				for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;//printf("i %d\n", i);
				if (i == n->num_keys) return 0;
				while (n != NULL) {//printf("outer loop %d\n", n->num_keys);
					for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {//printf("inner loop %d %d", n->keys[i], key_end);
						opOramBlock(structureId, n->pointers[i], b, 0);
						row = b->data;
						rowi++;
						opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)b2, 0);
						row2 = b2->data;

						int match = rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0';
						if(colChoice != -1){
							memset(&row[0], 'a', 1);
							memmove(&row[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
						}
						if(match){
							opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row, 1);
							numRows[retStructId]++;//printf("HEER %d %d %d %d\n", retStructId, numRows[retStructId], i, rowi);
						}
						else{
							opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 1);
							dummyVar++;
						}
					}//printf("end inner loop\n");
					if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
					followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
					//n = (node*)n->pointers[order - 1];
					i = 0;
				}

			}
			else if(small){
				printf("SMALL\n");
				int storageCounter = 0;
				int dummyCounter = 0;
				int pauseCounter = 0;
				int isNotPaused = 1;
				int roundNum = 0;
				uint8_t* storage = (uint8_t*)malloc(ROWS_IN_ENCLAVE*colChoiceSize);
				do{
					int rowi = -1;


					memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
					for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
					if (i == n->num_keys) return 0;
					while (n != NULL) {
						for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
							opOramBlock(structureId, n->pointers[i], b, 0);
							row = b->data;

							if(row[0] != '\0') rowi++;
							else dummyCounter++;

							isNotPaused = storageCounter < ROWS_IN_ENCLAVE && rowi >= pauseCounter && row[0] != '\0';
							if(isNotPaused){
								pauseCounter++;
							}
							else{
								dummyCounter++;
							}
							if(rowMatchesCondition(c, row, schemas[structureId]) && isNotPaused ){
								//printf("row[0] %c\n", row[0]);
								memcpy(&storage[storageCounter*colChoiceSize], &row[colChoiceOffset], colChoiceSize);
								storageCounter++;
							}
							else{
								memcpy(dummy, dummy, colChoiceSize);
								dummyCounter++;
							}
						}
						if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
						followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
						//n = (node*)n->pointers[order - 1];
						i = 0;
					}

					//copy to response
					int twiddle = 0;
					if(colChoice != -1){
						memset(row, 'a', BLOCK_DATA_SIZE);//clear out row, set row[0] to not '\0'
						twiddle = 1;
					}
					for(int j = 0; j < ROWS_IN_ENCLAVE; j++){
						//printf("%d %d %d\n", i, storageCounter, storage[i*colChoiceSize]);
						if(j == storageCounter)break;
						memcpy(&row[twiddle], &storage[j*colChoiceSize], colChoiceSize);
						opOneLinearScanBlock(retStructId, roundNum*ROWS_IN_ENCLAVE+j, (Linear_Scan_Block*)row, 1);
						numRows[retStructId]++;
					}
					storageCounter = 0;
					roundNum++;
				}
				while(pauseCounter < rangeCount);
				free(storage);
			}
			else{//hash
				printf("HASH\n");
				//data structure is of size 5*output and use it as a hash table. each row is written to one of two hash values
				//hash should be first several bits of output of sha256. input will be the input row number concatenated with 0 and 1 for the two hashes
				int rowi = -1, dummyVar = 0;
				row2 = (uint8_t*)malloc(sizeof(Linear_Scan_Block));
				uint8_t* hashIn = (uint8_t*)malloc(5);
				sgx_sha256_hash_t* hashOut = (sgx_sha256_hash_t*)malloc(256);
				unsigned int index = 0;

				numRows[retStructId] = count;


				memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
				for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
				if (i == n->num_keys) return 0;
				while (n != NULL) {
					for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
						opOramBlock(structureId, n->pointers[i], b, 0);
						row = b->data;
						if(row[0] != '\0') rowi++;
						else dummyVar++;

						int match = rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0';
						if(colChoice != -1){
							memset(&row[0], 'a', 1);
							memmove(&row[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
						}
						
						int insertCounter = 0;
                        do{
                                //compute hash
                                memcpy(&hashIn[1], &rowi, 4);
                                hashIn[0] = insertCounter;
                                sgx_sha256_msg(hashIn, 5, hashOut);
                                memcpy(&index, hashOut, 4);
                                index %= count*3/2;
                                                
                                //try inserting or increment counter
                                opOneLinearScanBlock(retStructId, index, (Linear_Scan_Block*)row2, 0);
                                if(match && row2[0] == '\0'){
									opOneLinearScanBlock(retStructId, index, (Linear_Scan_Block*)row, 1);
                                    insertCounter = -1;
                                }
				else if(!match) insertCounter = -1;
                                else{
                                    insertCounter++;
                                }
                            }
                            while(insertCounter != -1);
                            
                    }
					if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
					followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
					//n = (node*)n->pointers[order - 1];
					i = 0;
				}
				free(row2);
			}

		}
		else{//aggregate without group
			//no need to pad here, see equivalent segment of selectRows
			printf("AGGREGATE\n");
			if(colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER){
				return 1;
			}
			//printf("here %d", structureId);

			retNumRows = 1;
			retSchema.numFields = 2;
			retSchema.fieldOffsets[0] = 0;
			retSchema.fieldOffsets[1] = 1;
			retSchema.fieldSizes[0] = 1;
			retSchema.fieldSizes[1] = 4;
			retSchema.fieldTypes[0] = CHAR;
			retSchema.fieldTypes[1] = INTEGER;
			createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);
			int first = 0, dummyCount = 0;


			memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
			for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
			if (i == n->num_keys) return 0;
		while (n != NULL) {//printf("hi %d %d %d %d\n", i, n->num_keys, n->keys[i], key_end);
			for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
				opOramBlock(structureId, n->pointers[i], b, 0);
				row = b->data;
				if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
					count++;
					int val = (int)row[schemas[structureId].fieldOffsets[colChoice]];
					switch(aggregate){
					case 1:
							stat+=val;
						break;
					case 2:
						if(val < stat || first == 0)
							stat = val;
						break;
					case 3:
						if(val > stat || first == 0)
							stat = val;
						break;
					case 4:
							stat+=val;
						break;
					}
					first = 1;
				}
				else{//dummy branch
					dummyCount++;
					int val = (int)row[schemas[structureId].fieldOffsets[colChoice]];
					switch(aggregate){
					case 1:
							dummyCount+=val;
						break;
					case 2:
						if(val < stat || first == 0)
							dummyCount = val;
						break;
					case 3:
						if(val > stat || first == 0)
							dummyCount = val;
						break;
					case 4:
						dummyCount+=val;
						break;
					}
					dummyCount = 1;
				}//end dummy branch
			}
			if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
			followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
			//n = (node*)n->pointers[order - 1];
			i = 0;
		}

			if(aggregate == 0) {
				stat = count;
			}
			else if(aggregate == 4){
				stat /= count;// to the nearest int
			}
			memset(row, 'a', BLOCK_DATA_SIZE);
			memcpy(&row[1], &stat, 4);
			//printf("stat is %d", stat);
			opOneLinearScanBlock(retStructId, 0, (Linear_Scan_Block*)row, 1);
			numRows[retStructId]++;
		}
	}
	else{//group by
		if(aggregate == -1 || colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER) {
			return 1;
		}
		printf("GROUP BY\n");
		//we will do this for small numbers of groups. the doc has an algorithm that can be used for larger numbers of groups
		//that uses the hyperloglog algorithm

		//first pass, count number of groups
		int numGroups = 0, dummyCounter = 0;
		uint8_t* groupVal = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
		int aggrVal = 0;
		uint8_t* groups[MAX_GROUPS];
		uint8_t* dummyData;
		int groupStat[MAX_GROUPS] = {0};
		int groupCount[MAX_GROUPS] = {0};


		memcpy(&n[0], &saveStart[0], sizeof(Oram_Block));
		for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
		if (i == n->num_keys) return 0;
		while (n != NULL) {
			for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
				opOramBlock(structureId, n->pointers[i], b, 0);
				row = b->data;
				memcpy(groupVal, &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);
				memcpy(&aggrVal, &row[schemas[structureId].fieldOffsets[colChoice]], 4);
				if(row[0] == '\0' || !rowMatchesCondition(c, row, schemas[structureId])) {//begin dummy branch
					//continue;
					int foundAGroup = 0;
					for(int j = 0; j < numGroups; j++){
						if(memcmp(groupVal, groups[j], schemas[structureId].fieldSizes[groupCol]) == 0){
							foundAGroup = 1;
							//groupCount[j]++;
							dummyCounter++;
							switch(aggregate){
							case 1:
									dummyCounter+=aggrVal;
								break;
							case 2:
								if(aggrVal < groupStat[j])
									dummyCounter = aggrVal;
								break;
							case 3:
								if(aggrVal > groupStat[j])
									dummyCounter = aggrVal;
								break;
							case 4:
									dummyCounter+=aggrVal;
								break;
							}
						}
					}
					if(!foundAGroup){
						//groupCount[numGroups]++;
						dummyCounter++;
						//groups[numGroups] = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);//TODO
						//memcpy(groups[numGroups], &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);//TODO
						dummyData = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
						memcpy(dummyData, &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);
						switch(aggregate){
						case 1:
								dummyCounter+=aggrVal;
							break;
						case 2:
							dummyCounter = aggrVal;
							break;
						case 3:
							dummyCounter = aggrVal;
							break;
						case 4:
							dummyCounter+=aggrVal;
							break;
						}
						dummyCounter++;
					}//end dummy branch
				}
				else{
					int foundAGroup = 0;
					for(int j = 0; j < numGroups; j++){
						if(memcmp(groupVal, groups[j], schemas[structureId].fieldSizes[groupCol]) == 0){
							foundAGroup = 1;
							groupCount[j]++;//printf("count %d", groupCount[j]);
							switch(aggregate){
							case 1:
									groupStat[j]+=aggrVal;
								break;
							case 2:
								if(aggrVal < groupStat[j])
									groupStat[j] = aggrVal;
								break;
							case 3:
								if(aggrVal > groupStat[j])
									groupStat[j] = aggrVal;
								break;
							case 4:
									groupStat[j]+=aggrVal;
								break;
							}
						}
					}
					if(!foundAGroup){
						groupCount[numGroups]++;
						groups[numGroups] = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
						memcpy(groups[numGroups], &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);
						switch(aggregate){
						case 1:
								groupStat[numGroups]+=aggrVal;
							break;
						case 2:
								groupStat[numGroups] = aggrVal;
							break;
						case 3:
								groupStat[numGroups] = aggrVal;
							break;
						case 4:
								groupStat[numGroups]+=aggrVal;
							break;
						}
						numGroups++;
					}
				}
			}
			if(n->pointers[MAX_ORDER-1] == -1 || n->keys[i-1] > key_end){i = 0; break;}
			followNodePointer(structureId, n, n->pointers[MAX_ORDER - 1]);
			//n = (node*)n->pointers[order - 1];
			i = 0;
		}

		for(int j = 0; j < numGroups; j++){
			if(aggregate == 0) groupStat[j] = groupCount[j];
			else if(aggregate == 4) groupStat[j] /= groupCount[j];
		}

		//create table and fill it with results
		retSchema.numFields = 3;
		retSchema.fieldOffsets[0] = 0;
		retSchema.fieldOffsets[1] = 1;
		retSchema.fieldOffsets[2] = 5;
		retSchema.fieldTypes[0] = CHAR;
		retSchema.fieldTypes[1] = INTEGER;
		retSchema.fieldTypes[2] = schemas[structureId].fieldTypes[groupCol];
		retSchema.fieldSizes[0] = 1;
		retSchema.fieldSizes[1] = 4;
		retSchema.fieldSizes[2] = schemas[structureId].fieldSizes[groupCol];
		int size = numGroups;
		if(intermediate) size = oblivStructureSizes[structureId];
		if(PADDING) size = MAX_GROUPS;
		createTable(&retSchema, retName, retNameLen, retType, size, &retStructId);
		for(int j = 0; j < size; j++){
			if(j < numGroups){
				row[0] = 'a';
				memcpy(&row[1], &groupStat[j], 4);
				memcpy(&row[5], groups[j], schemas[structureId].fieldSizes[groupCol]);
				opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
				numRows[retStructId]++;
				free(groups[j]);
			}
			else{
				row[0] = '\0';
				opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
			}
		}
	}
	
	free(b);
	free(b2);
	free(n);
	free(saveStart);
	free(root);
	//free(row);
	//free(row2);
	//printf("here");
	return num_found;
}

//groupCol = -1 means not to order or group by, aggregate = -1 means no aggregate, aggregate = 0 count, 1 sum, 2 min, 3 max, 4 mean
//including algChoice in case I need to use it later to choose among algorithms
//select column colNum; if colChoice = -1, select all columns
int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate) {
	int structureId = getTableId(tableName);
	Obliv_Type type = oblivStructureTypes[structureId];
	int colChoiceSize = BLOCK_DATA_SIZE;
	DB_Type colChoiceType = INTEGER;
	int colChoiceOffset = 0;
	uint8_t* dummy = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	dummy[0]='\0';
	if(colChoice != -1){
		colChoiceSize = schemas[structureId].fieldSizes[colChoice];
		colChoiceType = schemas[structureId].fieldTypes[colChoice];
		colChoiceOffset = schemas[structureId].fieldOffsets[colChoice];
		free(dummy);
		dummy = (uint8_t*)malloc(colChoiceSize+1);
		dummy[0]='\0';
	}
	int count = 0;
	int stat = 0;
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* row2 = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	char *retName = "ReturnTable";
	int retNameLen = strlen(retName);
	int retStructId = -1;
	Obliv_Type retType = TYPE_LINEAR_SCAN;
	Schema retSchema; //set later
	int retNumRows = 0; //set later
	switch(type){
	case TYPE_LINEAR_SCAN:
		if(groupCol == -1) {//printf("no groupby %d\n", aggregate);
			if(aggregate == -1) {//actually doing a select
				int almostAll = 0;
				int continuous = 0;
				int small = 0;
				int contTemp = 0;
				int dummyVar = 0;
				int baseline = 0;
				//first pass to determine 1) output size (count), 2) whether output is one continuous chunk (continuous)
				for(int i = 0; i < oblivStructureSizes[structureId]; i++){
					opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
					row = ((Linear_Scan_Block*)row)->data;
					//printf("ready for a comparison? %d\n", c.numClauses);
						if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
							count++;
							if(!continuous && !contTemp){//first hit
								continuous = 1;
							}
							else if(continuous && contTemp){//a noncontinuous hit
								continuous = 0;
							}
						}
						else{
							dummyVar++;
							if(continuous && !contTemp){//end of continuous chunk
								contTemp = 1;
							}
						}
				}

				if(count > oblivStructureSizes[structureId]*.01*PERCENT_ALMOST_ALL && colChoice == -1){ //return almost all only if the whole row is selected (to make my life easier)
					almostAll = 1;
				}
				if(count < 5*ROWS_IN_ENCLAVE){
					small = 1;
					if(count < ROWS_IN_ENCLAVE && continuous == 1) continuous = 0;
				}
				//printf("%d %f\n",count,  oblivStructureSizes[structureId]*.01*PERCENT_ALMOST_ALL); //count and count needed for almost all

				switch(algChoice){
				case 1:
					continuous = 1;
					small = 0;
					almostAll = 0;
					break;
				case 2:
					continuous = 0;
					small = 1;
					almostAll = 0;
					break;
				case 3:
					continuous = 0;
					small = 0;
					almostAll = 0;
					break;
				case 4:
					continuous = 0;
					small = 0;
					almostAll = 1;
					break;
				case 5:
					baseline = 1;
					continuous = 0;
					small = 0;
					almostAll = 0;
					break;
				}

				//create table to return
				if(almostAll){
					retNumRows = oblivStructureSizes[structureId];
				}
				else if(small || continuous || baseline){
					retNumRows = count;
				}
				else{//hash
					retNumRows = count*3/2;
				}
				if(colChoice != -1){ //include selected col only
					retSchema.numFields = 2;
					retSchema.fieldOffsets[0] = 0;
					retSchema.fieldOffsets[1] = 1;
					retSchema.fieldSizes[0] = 1;
					retSchema.fieldSizes[1] = colChoiceSize;
					retSchema.fieldTypes[0] = CHAR;
					retSchema.fieldTypes[1] = colChoiceType;
				}
				else{ //include whole selected row
					retSchema = schemas[structureId];
				}
				if(intermediate) retNumRows = oblivStructureSizes[structureId];
				if(PADDING) retNumRows = PADDING;
				//printf("%d %d %d %d %s %d %d\n", retNameLen, retNumRows, retStructId, retType, retName, retSchema.numFields, retSchema.fieldSizes[1]);
				int out = createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);
				//printf("%d |\n", retNumRows);
				//printf("%d %d %d %d %s %d %d\n", retNameLen, retNumRows, retStructId, retType, retName, retSchema.numFields, retSchema.fieldSizes[1]);
				//printf("%s\n", tableNames[retStructId]);
				//printTable("ReturnTable");
				if(count == 0) {
					free(dummy);
					free(row);
					free(row2);
					return 0;
				}
				//printf("Made it to algorithm slection\n");
				//pick algorithm
				if(baseline){
					printf("BASELINE\n");
					Oram_Block* oBlock = (Oram_Block*)malloc(getBlockSize(TYPE_ORAM));
					int oramTableId = -1;
					char* oramName = "tempOram";
					createTable(&retSchema, oramName, strlen(oramName), TYPE_ORAM, retNumRows, &oramTableId);
					memset(oBlock, 0, sizeof(Oram_Block));
					opOramBlock(oramTableId, 0, oBlock, 1);

					int oramRows = 0;
					for(int i = 0; i < oblivStructureSizes[structureId]; i++){
						opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)oBlock->data, 0);
						//oBlock->data = ((Linear_Scan_Block*)(oBlock->data))->data;
						int match = rowMatchesCondition(c, oBlock->data, schemas[structureId]) && oBlock->data[0] != '\0';
						if(colChoice != -1){
							memset(&oBlock->data[0], 'a', 1);
							memmove(&oBlock->data[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
						}
						oBlock->actualAddr = oramRows;
						if(match){
							usedBlocks[oramTableId][oramRows]=1;
							opOramBlock(oramTableId, oramRows, oBlock, 1);
							oramRows++;
						}
						else{
							dummyVar=1;
							opOramBlock(oramTableId, 0, oBlock, 0);
							dummyVar++;
						}
					}
					//copy back to linear structure
					for(int i = 0; i < oramRows; i++){
						opOramBlock(oramTableId, i, oBlock, 0);
						opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)(oBlock->data), 1);
						numRows[retStructId]++;
					}
					free(oBlock);
				}
				else if(continuous){//use continuous chunk algorithm
					printf("CONTINUOUS\n");
					int rowi = -1, dummyVar = 0;//NOTE: rowi left in for historical reasons; it should be replaced by i
					for(int i = 0; i < oblivStructureSizes[structureId]; i++){
						if(count == 0) break;
						opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);

						row = ((Linear_Scan_Block*)row)->data;
						rowi++;
						//printf("here2 %d %d\n", rowi, count);

						opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 0);
						//printf("here2\n");
						row2 = ((Linear_Scan_Block*)row2)->data;
						int match = rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0';
						if(colChoice != -1){
							memset(&row[0], 'a', 1);
							memmove(&row[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
						}
						if(match){
							opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row, 1);
							numRows[retStructId]++;//printf("HEER %d %d", retStructId, numRows[retStructId]);
						}
						else{
							opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 1);
							dummyVar++;
						}
					}
					//printTable("ReturnTable");
				}
				else{//pick one of other algorithms
					if(almostAll){
						printf("ALMOST ALL\n");
						//"almost all" solution, it's a field being returned that is not an integer so we can put in dummy entries
						//have new table that is copy of old table and delete any rows that are not supposed to be in the output
						memset(row2, '\0', BLOCK_DATA_SIZE);
						for(int i = 0; i < oblivStructureSizes[structureId]; i++){ //copy table
							opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
							opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 1);
						}
						numRows[retStructId] = numRows[structureId];
						int dummyVar = 0;
						for(int i = 0; i < oblivStructureSizes[structureId]; i++){ //delete bad rows
							opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 0);
							if(rowMatchesCondition(c, row, schemas[structureId]) || row[0] == '\0'){
								opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 1);
								dummyVar--;
							}
							else{
								opOneLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row2, 1);//write dummy row over unselected rows
								numRows[retStructId]--;
								//printf("LOOLZ %d\n", numRows[retStructId]);
							}

						}
					}
					else if(small){ //option 1 ("small")
						printf("SMALL\n");
						int storageCounter = 0;
						int dummyCounter = 0;
						int pauseCounter = 0;
						int isNotPaused = 1;
						int roundNum = 0;
						uint8_t* storage = (uint8_t*)malloc(ROWS_IN_ENCLAVE*colChoiceSize);
						do{
							if(count == 0) break;
							int rowi = -1;
							for(int i = 0; i < oblivStructureSizes[structureId]; i++){
								opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
								row = ((Linear_Scan_Block*)row)->data;

								if(row[0] != '\0') rowi++;
								else dummyCounter++;

								isNotPaused = storageCounter < ROWS_IN_ENCLAVE && rowi >= pauseCounter && row[0] != '\0';
								if(isNotPaused){
									pauseCounter++;
								}
								else{
									dummyCounter++;
								}
								if(rowMatchesCondition(c, row, schemas[structureId]) && isNotPaused ){
									//printf("row[0] %c\n", row[0]);
									memcpy(&storage[storageCounter*colChoiceSize], &row[colChoiceOffset], colChoiceSize);
									storageCounter++;
								}
								else{
									memcpy(dummy, dummy, colChoiceSize);
									dummyCounter++;
								}
							}
							//copy to response
							int twiddle = 0;
							if(colChoice != -1){
								memset(row, 'a', BLOCK_DATA_SIZE);//clear out row, set row[0] to not '\0'
								twiddle = 1;
							}
							for(int i = 0; i < ROWS_IN_ENCLAVE; i++){
								//printf("%d %d %d\n", i, storageCounter, storage[i*colChoiceSize]);
								if(i == storageCounter)break;
								memcpy(&row[twiddle], &storage[i*colChoiceSize], colChoiceSize);
								opOneLinearScanBlock(retStructId, roundNum*ROWS_IN_ENCLAVE+i, (Linear_Scan_Block*)row, 1);
								numRows[retStructId]++;
							}
							storageCounter = 0;
							roundNum++;
						}
						while(pauseCounter < numRows[structureId]);
						free(storage);
					}
					else{//hashing solution
						printf("HASH\n");
						int rowi = -1, dummyVar = 0;
						uint8_t* hashIn = (uint8_t*)malloc(5);
						sgx_sha256_hash_t* hashOut = (sgx_sha256_hash_t*)malloc(256);
						unsigned int index = 0;

						numRows[retStructId] = count;

						for(int i = 0; i < oblivStructureSizes[structureId]; i++){
							if(count == 0) break;
							opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
							row = ((Linear_Scan_Block*)row)->data;
							//if(row[0] == '\0') continue;
							//else rowi++;
							if(row[0] != '\0') rowi++;
							else dummyVar++;

							int match = rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0';
							if(colChoice != -1){
								memset(&row[0], 'a', 1);
								memmove(&row[1], &row[colChoiceOffset], colChoiceSize);//row[0] will already be not '\0'
							}
							
							int insertCounter = 0;
                            do{
                                //compute hash
                                memcpy(&hashIn[1], &rowi, 4);
                                hashIn[0] = insertCounter;
                                sgx_sha256_msg(hashIn, 5, hashOut);
                                memcpy(&index, hashOut, 4);
                                index %= count*3/2;
                                                
                                //try inserting or increment counter
                                opOneLinearScanBlock(retStructId, index, (Linear_Scan_Block*)row2, 0);
                                if(match && row2[0] == '\0'){
									opOneLinearScanBlock(retStructId, index, (Linear_Scan_Block*)row, 1);
                                    insertCounter = -1;
                                }
				else if(!match) insertCounter = -1;
                                else{
					//printf("try again %d %d\n", insertCounter, index);
                                    insertCounter++;
                                }
                            }
                            while(insertCounter != -1);
							

						}
					}
				}

			}
			else{//doing an aggregate with no group byprintf("here %d", structureId);
				//query plan gives away that there's only one row to return, so padding doesn't hide anything extra

				int baseline=0, baselineId=-1;
				char *tempName = "temp";
				Oram_Block* oBlock;
				if(intermediate == 2 || intermediate == 3){
					baseline =1;
					intermediate -=2;
					oBlock = (Oram_Block*)malloc(getBlockSize(TYPE_ORAM));
					memset(oBlock, 0, sizeof(Oram_Block));
					createTable(&retSchema, tempName, strlen(tempName), TYPE_ORAM, MAX_GROUPS, &baselineId);
					usedBlocks[baselineId][0] = 1;
					opOramBlock(baselineId, 0, oBlock, 1);
				}

				if(colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER){
					printf("aborting %d %d", colChoice == -1, schemas[structureId].fieldTypes[colChoice] != INTEGER);
					return 1;
				}
				//printf("here %d", structureId);
				int winRow = -1;
				retNumRows = 1;
				retSchema.numFields = 2;
				retSchema.fieldOffsets[0] = 0;
				retSchema.fieldOffsets[1] = 1;
				retSchema.fieldSizes[0] = 1;
				retSchema.fieldSizes[1] = 4;
				retSchema.fieldTypes[0] = CHAR;
				retSchema.fieldTypes[1] = INTEGER;
				if((aggregate == 2 || aggregate == 3) && algChoice == 0){
					createTable(&schemas[structureId], retName, retNameLen, retType, retNumRows, &retStructId);
				}
				else{
					createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);
				}
				int first = 0, dummyCount = 0;
				for(int i = 0; i < oblivStructureSizes[structureId]; i++){
					if(baseline){
						opOramBlock(baselineId, 0, oBlock, 0);
					}
					opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
					row = ((Linear_Scan_Block*)row)->data;
					if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
						count++;
						int val = (int)row[schemas[structureId].fieldOffsets[colChoice]];
						switch(aggregate){
						case 1:
								stat+=val;
							break;
						case 2:
							if(val < stat || first == 0){
								stat = val;
								winRow = i;
							}
							break;
						case 3:
							if(val > stat || first == 0){
								stat = val;
								winRow = i;
							}
							break;
						case 4:
								stat+=val;
							break;
						}
						first = 1;
					}
					else{//dummy branch
						dummyCount++;
						int val = (int)row[schemas[structureId].fieldOffsets[colChoice]];
						switch(aggregate){
						case 1:
								dummyCount+=val;
							break;
						case 2:
							if(val < stat || first == 0){
								dummyCount = val;
								dummyCount = i;
							}
							break;
						case 3:
							if(val > stat || first == 0){
								dummyCount = val;
								dummyCount = i;
							}
							break;
						case 4:
							dummyCount+=val;
							break;
						}
						dummyCount = 1;
					}//end dummy branch
				}
				if(aggregate == 0) {
					stat = count;
				}
				else if(aggregate == 4){
					stat /= count;// to the nearest int
				}

				memset(row, 'a', BLOCK_DATA_SIZE);
				//printf("%d %d\n", aggregate, algChoice);
				if((aggregate == 2 || aggregate == 3) && algChoice == 0){
					opLinearScanBlock(structureId, winRow, (Linear_Scan_Block*)row, 0);
				}
				else{
					memcpy(&row[1], &stat, 4);
				}
				//printf("stat is %d", stat);
				opOneLinearScanBlock(retStructId, 0, (Linear_Scan_Block*)row, 1);
				numRows[retStructId]++;

				if(baseline){
					free(oBlock);
					deleteTable(tempName);
				}

			}
		}
		else{ //group by

			//hack to simulate baseline where all these structures are in an oram.
			//Just do extra oram ops every time there would be an access
			//this will actually underestimate the number of oram calls needed
			//since some more calls would be needed to make this really oblivious
			//and I'm assuming all the structures are merged in the same block
			int baseline=0, baselineId=-1;
			char *tempName = "temp";
			Oram_Block* oBlock;
			if(intermediate == 2 || intermediate == 3){
				
				Schema slimSchema;
				slimSchema.numFields = 2;
				slimSchema.fieldOffsets[0] = 0;
				slimSchema.fieldOffsets[1] = 1;
				slimSchema.fieldSizes[0] = 1;
				slimSchema.fieldSizes[1] = 4;
				slimSchema.fieldTypes[0] = CHAR;
				slimSchema.fieldTypes[1] = INTEGER;

				baseline =1;
				intermediate -=2;
				oBlock = (Oram_Block*)malloc(getBlockSize(TYPE_ORAM));
				memset(oBlock, 0, sizeof(Oram_Block));
				printf("hi\n");
				createTable(&slimSchema, tempName, strlen(tempName), TYPE_ORAM, MAX_GROUPS, &baselineId);
				usedBlocks[baselineId][0] = 1;
				printf("hi\n");
				opOramBlock(baselineId, 0, oBlock, 1);
			}

			if(aggregate == -1 || colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER) {
				printf("aborting %d %d %d\n", aggregate == -1, colChoice == -1, schemas[structureId].fieldTypes[colChoice] != INTEGER);
				return 1;
			}
			printf("GROUP BY\n");
			//we will do this for small numbers of groups. the doc has an algorithm that can be used for larger numbers of groups
			//that uses the hyperloglog algorithm
			int colChoice2 = -1;
			int bdb2 = (algChoice == -2); //need little tweaks for things like substr to handle bdb queries
			if(!bdb2) colChoice2 = algChoice;
			int substrX = schemas[structureId].fieldSizes[groupCol];
			if(bdb2){
				substrX = 8;
			}
			//int bdb3 = (algChoice == 11); use algChoice for second aggregate col

			int numGroups = 0, dummyCounter = 0;
			uint8_t* groupVal = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
			int aggrVal = 0;
			int aggrVal2 = 0;
			uint8_t* groups[MAX_GROUPS];
			uint8_t* dummyData;
			int groupStat[MAX_GROUPS] = {0};
			int groupStat2[MAX_GROUPS] = {0};
			int groupCount[MAX_GROUPS] = {0};
			//printf("oblivStructureSizes %d %d\n", structureId, oblivStructureSizes[structureId]);
			for(int i = 0; i < oblivStructureSizes[structureId]; i++){
				//opOneLinearScanBlock(structureId, i+306000, (Linear_Scan_Block*)row, 0);
				//printf(" op done\n");
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
				memcpy(groupVal, &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);
				memcpy(&aggrVal, &row[schemas[structureId].fieldOffsets[colChoice]], 4);
				memcpy(&aggrVal2, &row[schemas[structureId].fieldOffsets[colChoice2]], 4);
				row = ((Linear_Scan_Block*)row)->data;

				//printf("numgroups: %d, groupval: %s %s %s\n", numGroups, groupVal, &row[schemas[structureId].fieldOffsets[2]], &row[schemas[structureId].fieldOffsets[11]]);

				if(row[0] == '\0' || !rowMatchesCondition(c, row, schemas[structureId])) {//begin dummy branch

					if(baseline){
						for(int j = 0; j < numGroups; j++)
							opOramBlock(baselineId, 0, oBlock, 0);
					}
					continue;
					int foundAGroup = 0;
					for(int j = 0; j < numGroups; j++){
						if(memcmp(groupVal, groups[j], substrX) == 0){
							foundAGroup = 1;
							//groupCount[j]++;
							dummyCounter++;
							switch(aggregate){
							case 1:
									dummyCounter+=aggrVal;
									dummyCounter+=aggrVal2;
								break;
							case 2:
								if(aggrVal < groupStat[j])
									dummyCounter = aggrVal;
								if(aggrVal < groupStat[j])
									dummyCounter = aggrVal;
								break;
							case 3:
								if(aggrVal > groupStat[j])
									dummyCounter = aggrVal;
								if(aggrVal > groupStat[j])
									dummyCounter = aggrVal;
								break;
							case 4:
									dummyCounter+=aggrVal;
									dummyCounter+=aggrVal2;
								break;
							}
						}
					}
					if(!foundAGroup){
						//groupCount[numGroups]++;
						dummyCounter++;
						//groups[numGroups] = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);//TODO
						//memcpy(groups[numGroups], &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);//TODO
						dummyData = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
						memcpy(dummyData, &row[schemas[structureId].fieldOffsets[groupCol]], substrX);
						switch(aggregate){
						case 1:
							dummyCounter+=aggrVal;
							dummyCounter+=aggrVal2;
							break;
						case 2:
							dummyCounter = aggrVal;
							dummyCounter+=aggrVal2;

							break;
						case 3:
							dummyCounter = aggrVal;
							dummyCounter=aggrVal2;

							break;
						case 4:
							dummyCounter+=aggrVal;
							dummyCounter+=aggrVal2;
							break;
						}
						dummyCounter++;
					}//end dummy branch
				}
				else{
					int foundAGroup = 0;
					for(int j = 0; j < numGroups; j++){//printf("here2\n");
						if(baseline){
							opOramBlock(baselineId, 0, oBlock, 0);
						}
						if(memcmp(groupVal, groups[j], substrX) == 0){
							foundAGroup = 1;
							groupCount[j]++;
							switch(aggregate){
							case 1:
									groupStat[j]+=aggrVal;
									groupStat2[j]+=aggrVal2;
								break;
							case 2:
								if(aggrVal < groupStat[j])
									groupStat[j] = aggrVal;
								if(aggrVal2 < groupStat2[j])
									groupStat2[j] = aggrVal2;
								break;
							case 3:
								if(aggrVal > groupStat[j])
									groupStat[j] = aggrVal;
								if(aggrVal2 > groupStat2[j])
									groupStat2[j] = aggrVal2;
								break;
							case 4:
									groupStat[j]+=aggrVal;
									groupStat2[j]+=aggrVal2;
								break;
							}
						}
					}
					if(!foundAGroup){
						groupCount[numGroups]++;
						groups[numGroups] = (uint8_t*)malloc(substrX);
						memcpy(groups[numGroups], &row[schemas[structureId].fieldOffsets[groupCol]], substrX);
						switch(aggregate){
						case 1:
								groupStat[numGroups]+=aggrVal;
								groupStat2[numGroups]+=aggrVal2;
							break;
						case 2:
								groupStat[numGroups] = aggrVal;
								groupStat2[numGroups]=aggrVal2;
							break;
						case 3:
								groupStat[numGroups] = aggrVal;
								groupStat2[numGroups]=aggrVal2;

							break;
						case 4:
								groupStat[numGroups]+=aggrVal;
								groupStat2[numGroups]+=aggrVal2;
							break;
						}
						numGroups++;
					}
				}
			}
			for(int j = 0; j < numGroups; j++){
				if(baseline){
					opOramBlock(baselineId, 0, oBlock, 0);
				}
				if(aggregate == 0) groupStat[j] = groupCount[j];
				else if(aggregate == 4) groupStat[j] /= groupCount[j];
			}

			int size = numGroups;
			if(intermediate) size = oblivStructureSizes[structureId];
			if(PADDING) size = MAX_GROUPS;

			if(!bdb2 && algChoice != -1){//bdb3
				//create table and fill it with results
				retSchema.numFields = 4;
				retSchema.fieldOffsets[0] = 0;
				retSchema.fieldOffsets[1] = 1;
				retSchema.fieldOffsets[2] = 5;
				retSchema.fieldOffsets[3] = 9;
				retSchema.fieldTypes[0] = CHAR;
				retSchema.fieldTypes[1] = INTEGER;
				retSchema.fieldTypes[2] = INTEGER;
				retSchema.fieldTypes[3] = schemas[structureId].fieldTypes[groupCol];
				retSchema.fieldSizes[0] = 1;
				retSchema.fieldSizes[1] = 4;
				retSchema.fieldSizes[2] = 4;
				retSchema.fieldSizes[3] = substrX;
				createTable(&retSchema, retName, retNameLen, retType, size, &retStructId);
				for(int j = 0; j < size; j++){
					if(baseline){
						opOramBlock(baselineId, 0, oBlock, 0);
					}
					if(j<numGroups){
						row[0] = 'a';
						memcpy(&row[1], &groupStat[j], 4);
						memcpy(&row[5], &groupStat2[j], 4);
						memcpy(&row[9], groups[j], substrX);
						opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
						numRows[retStructId]++;
						free(groups[j]);
					}
					else{
						row[0] = '\0';
						opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
					}
				}
			}
			else{
				//create table and fill it with results
				retSchema.numFields = 3;
				retSchema.fieldOffsets[0] = 0;
				retSchema.fieldOffsets[1] = 1;
				retSchema.fieldOffsets[2] = 5;
				retSchema.fieldTypes[0] = CHAR;
				retSchema.fieldTypes[1] = INTEGER;
				retSchema.fieldTypes[2] = schemas[structureId].fieldTypes[groupCol];
				retSchema.fieldSizes[0] = 1;
				retSchema.fieldSizes[1] = 4;
				retSchema.fieldSizes[2] = substrX;
				createTable(&retSchema, retName, retNameLen, retType, size, &retStructId);
				for(int j = 0; j < size; j++){
					if(baseline){
						opOramBlock(baselineId, 0, oBlock, 0);
					}
					if(j<numGroups){
						row[0] = 'a';
						memcpy(&row[1], &groupStat[j], 4);
						memcpy(&row[5], groups[j], substrX);
						opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
						numRows[retStructId]++;
						free(groups[j]);
					}
					else{
						row[0] = '\0';
						opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
					}
				}
			}

			if(baseline){
				free(oBlock);
				deleteTable(tempName);
			}
		}
		break;
	case TYPE_TREE_ORAM:
		//TODO
		break;
	}

	free(dummy);
	free(row);
	free(row2);
}

int highCardLinGroupBy(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int intermediate) {
	int structureId = getTableId(tableName);
	Obliv_Type type = oblivStructureTypes[structureId];
	int colChoiceSize = BLOCK_DATA_SIZE;
	DB_Type colChoiceType = INTEGER;
	int colChoiceOffset = 0;
	if(colChoice != -1){
		colChoiceSize = schemas[structureId].fieldSizes[colChoice];
		colChoiceType = schemas[structureId].fieldTypes[colChoice];
		colChoiceOffset = schemas[structureId].fieldOffsets[colChoice];
	}
	int count = 0;
	int stat = 0;
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	char *retName = "ReturnTable";
	int retNameLen = strlen(retName);
	int retStructId = -1;
	Obliv_Type retType = TYPE_LINEAR_SCAN;
	Schema retSchema; //set later
	int retNumRows = 0; //set later

	int groupValSize = schemas[structureId].fieldSizes[groupCol];
	if(algChoice == -2){
			groupValSize = 8;
	}

	//allocate hash table
	uint8_t* hashTable = (uint8_t*)malloc((groupValSize+4)*MAX_GROUPS*3/2);
	uint8_t* hashIn = (uint8_t*)malloc(groupValSize);//this could be made to fit different sizes if we wanted
	sgx_sha256_hash_t* hashOut = (sgx_sha256_hash_t*)malloc(256);
	unsigned int index = 0;
	//clear hash table
	memset(hashTable, 0xff, (groupValSize+4)*MAX_GROUPS*3/2);

	//group by
	if(aggregate == -1 || colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER) {
		printf("aborting %d %d %d\n", aggregate == -1, colChoice == -1, schemas[structureId].fieldTypes[colChoice] != INTEGER);
		return 1;
	}
	printf("GROUP BY\n");

	int colChoice2 = -1;
	int bdb2 = (algChoice == -2); //need little tweaks for things like substr to handle bdb queries
	if(!bdb2) colChoice2 = algChoice;
	int substrX = schemas[structureId].fieldSizes[groupCol];
	if(bdb2){
		substrX = 8;
	}
	int numGroups = 0, dummyCounter = 0;
	uint8_t* groupVal = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
	int aggrVal = 0;
	uint8_t* groups[MAX_GROUPS];
	uint8_t* dummyData;
	int groupStat[MAX_GROUPS] = {0};
	int groupCount[MAX_GROUPS] = {0};
	int groupNum = -1;
	//printf("oblivStructureSizes %d %d\n", structureId, oblivStructureSizes[structureId]);
	int forupto = oblivStructureSizes[structureId];
	if(MIXED_USE_MODE) forupto*=4;
	for(int i = 0; i < forupto; i++){
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
		memcpy(groupVal, &row[schemas[structureId].fieldOffsets[groupCol]], substrX);
		memcpy(&aggrVal, &row[schemas[structureId].fieldOffsets[colChoice]], 4);
		//printf("groupVal: %s", groupVal);
		row = ((Linear_Scan_Block*)row)->data;
		if(row[0] == '\0' || !rowMatchesCondition(c, row, schemas[structureId])) {//begin dummy branch
			continue; //dummy branch was here but we're not really worrying about this side channel too much
					  //and it won't matter for the evaluations we do on this piece of code
		}
		else{
			int foundAGroup = 0;

			int checkCounter = 0, match = -1;
			do{
				//compute hash
				memset(hashIn, 0, 1+groupValSize);
				hashIn[0] = checkCounter;
				if(schemas[structureId].fieldTypes[groupCol] != TINYTEXT || algChoice == -2)
					memcpy(&hashIn[1], groupVal, groupValSize);
				else
					strncpy((char*)&hashIn[1], (char*)groupVal, groupValSize);
				sgx_sha256_msg(hashIn, 1+groupValSize, hashOut);
				memcpy(&index, hashOut, 4);
				index %= MAX_GROUPS*3/2;
				//compare against table
				int compval = 0;
				memcpy(&compval, &hashTable[(4+groupValSize)*index], 4);
				if(compval == -1 || row[0] == '\0'){
					checkCounter = -1;
					//int i1 = compval == -1;
					//int i2 = row[0] == '\0';
					//printf("here?? %d %d\n", i1, i2);
				}
				else if(memcmp(groupVal, &hashTable[(4+groupValSize)*index+4], substrX) == 0){
					match = index;
					checkCounter = -1;
					memcpy(&groupNum, &hashTable[(4+groupValSize)*index], 4);
					//printf("here--------------------\n");
				}
				else{//false match
					//printf("here???\n");
					checkCounter++;
				}
			}while(checkCounter != -1);

			//printf("%s %s %d");
	  		if(match != -1){
	  			//printf("match!!\n");
				foundAGroup = 1;
				groupCount[groupNum]++;
				switch(aggregate){
					case 1:
					groupStat[groupNum]+=aggrVal;
					break;
					case 2:
					if(aggrVal < groupStat[groupNum])
						groupStat[groupNum] = aggrVal;
					break;
					case 3:
					if(aggrVal > groupStat[groupNum])
						groupStat[groupNum] = aggrVal;
					break;
					case 4:
					groupStat[groupNum]+=aggrVal;
					break;
				}
			}

			if(!foundAGroup){
				groupCount[numGroups]++;
				groups[numGroups] = (uint8_t*)malloc(substrX);
				memcpy(groups[numGroups], &row[schemas[structureId].fieldOffsets[groupCol]], substrX);
				switch(aggregate){
				case 1:
						groupStat[numGroups]+=aggrVal;
					break;
				case 2:
						groupStat[numGroups] = aggrVal;
					break;
				case 3:
						groupStat[numGroups] = aggrVal;

					break;
				case 4:
						groupStat[numGroups]+=aggrVal;
					break;
				}

				//insert into hash table
				int insertCounter = 0;//increment on failure to insert, set to -1 on successful insertion

				do{
					//compute hash
					memset(hashIn, 0, 1+groupValSize);
					hashIn[0] = insertCounter;
					if(schemas[structureId].fieldTypes[groupCol] != TINYTEXT || algChoice == -2)
						memcpy(&hashIn[1], groupVal, groupValSize);
					else
						strncpy((char*)&hashIn[1], (char*)groupVal, groupValSize);
					sgx_sha256_msg(hashIn, 1+groupValSize, hashOut);
					memcpy(&index, hashOut, 4);
					index %= MAX_GROUPS*3/2;
					//printf("hash input: %s\nhash output: %d\n", &hashIn[1], index);
					//try inserting or increment counter
					int compval = 0;
					memcpy(&compval, &hashTable[(4+groupValSize)*index], 4);
					if(compval == -1){
						memcpy(&hashTable[(groupValSize+4)*index], &numGroups, 4);
						memcpy(&hashTable[(groupValSize+4)*index+4], groupVal, groupValSize);
						//printf("putting in %d %d %s\n", index, numGroups, groupVal);
						insertCounter = -1;
					}
					else{
						//printf("%d next\n", index);
						insertCounter++;
					}
				}
				while(insertCounter != -1);
				numGroups++;
			}
		}
	}
	for(int j = 0; j < numGroups; j++){
		if(aggregate == 0) groupStat[j] = groupCount[j];
		else if(aggregate == 4) groupStat[j] /= groupCount[j];
	}

		//create table and fill it with results
		retSchema.numFields = 3;
		retSchema.fieldOffsets[0] = 0;
		retSchema.fieldOffsets[1] = 1;
		retSchema.fieldOffsets[2] = 5;
		retSchema.fieldTypes[0] = CHAR;
		retSchema.fieldTypes[1] = INTEGER;
		retSchema.fieldTypes[2] = schemas[structureId].fieldTypes[groupCol];
		retSchema.fieldSizes[0] = 1;
		retSchema.fieldSizes[1] = 4;
		retSchema.fieldSizes[2] = substrX;
		int size = numGroups;
		if(intermediate) size = oblivStructureSizes[structureId];
		if(PADDING) size = MAX_GROUPS;
		createTable(&retSchema, retName, retNameLen, retType, size, &retStructId);
		for(int j = 0; j < size; j++){
			if(j < numGroups){
				row[0] = 'a';
				memcpy(&row[1], &groupStat[j], 4);
				memcpy(&row[5], groups[j], substrX);
				opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
				numRows[retStructId]++;
				free(groups[j]);
			}
			else{
				row[0] = '\0';
				opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
			}
		}

	free(row);
}

int printTableCheating(char* tableName){//non-oblivious version that's good for debugging
	int structureId = getTableId(tableName);
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	printf("\nTable %s, %d rows, capacity for %d rows, stored in structure %d\n", tableNames[structureId], numRows[structureId], oblivStructureSizes[structureId], structureId);
	for(int i = 0; i < oblivStructureSizes[structureId]; i++){
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
		if(row[0] == '\0') {
			continue;
		}
		for(int j = 1; j < schemas[structureId].numFields; j++){
			switch(schemas[structureId].fieldTypes[j]){
			case INTEGER:
				int temp;
				memcpy(&temp, &row[schemas[structureId].fieldOffsets[j]], 4);
				printf("%d", temp);
				break;
			case CHAR:
				printf("%c", row[schemas[structureId].fieldOffsets[j]]);
				break;
			case TINYTEXT:
				printf("%s", &row[schemas[structureId].fieldOffsets[j]]);
				break;
			}
			printf("  |  ");
		}
		printf("\n");
	}
}

int printTable(char* tableName){//only for linear scan tables
	//looks like select small since all other selects have possibility of including empties in output and we can't do dummies here
	int structureId = getTableId(tableName);
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* dummy = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	printf("\nTable %s, %d rows, capacity for %d rows, stored in structure %d\n", tableNames[structureId], numRows[structureId], oblivStructureSizes[structureId], structureId);

	//unsigned int rand = 0;
	//sgx_read_rand((unsigned char*)&rand, 4);
	//rand %= oblivStructureSizes[structureId];

	int storageCounter = 0;
	int dummyCounter = 0;
	int pauseCounter = 0;
	int isNotPaused = 1;
	int roundNum = 0;
	uint8_t* storage = (uint8_t*)malloc(ROWS_IN_ENCLAVE*BLOCK_DATA_SIZE);
	do{
		int rowi = -1;
		//int flag = 0;
		for(int i = 0; i < oblivStructureSizes[structureId]; i++){//printf("%d %d %d \n", flag, i, rand);
		//for(int i = rand; !flag || i != rand; i++){//printf("%d %d %d \n", flag, i, rand);
			/*
			if(i == oblivStructureSizes[structureId]) {
				if(rand == 0) break;
				i = 0;
				flag = 1;
			}
			else {
				dummyCounter = 0;
				dummyCounter = 1;
			}
			*/
			opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
			row = ((Linear_Scan_Block*)row)->data;

			if(row[0] != '\0') rowi++;
			else dummyCounter++;

			isNotPaused = storageCounter < ROWS_IN_ENCLAVE && rowi >= pauseCounter && row[0] != '\0';
			if(isNotPaused){
				pauseCounter++;
			}
			else{
				dummyCounter++;
			}
			if(isNotPaused ){
				//printf("row[1] %d\n", row[1]);
				memcpy(&storage[storageCounter*BLOCK_DATA_SIZE], &row[0], BLOCK_DATA_SIZE);
				storageCounter++;
			}
			else{
				memcpy(dummy, dummy, BLOCK_DATA_SIZE);
				dummyCounter++;
			}
		}
		//printf("here! %d\n", pauseCounter);
		//copy to response
		for(int i = 0; i < ROWS_IN_ENCLAVE; i++){
			//printf("%d %d %d\n", i, storageCounter, storage[i*colChoiceSize]);
			if(i == storageCounter)break;
			memcpy(&row[0], &storage[i*BLOCK_DATA_SIZE], BLOCK_DATA_SIZE);
			//opOneLinearScanBlock(retStructId, roundNum*ROWS_IN_ENCLAVE+i, (Linear_Scan_Block*)row, 1);
			for(int j = 1; j < schemas[structureId].numFields; j++){
				switch(schemas[structureId].fieldTypes[j]){
				case INTEGER:
					int temp;
					memcpy(&temp, &row[schemas[structureId].fieldOffsets[j]], 4);
					printf("%d", temp);
					break;
				case CHAR:
					printf("%c", row[schemas[structureId].fieldOffsets[j]]);
					break;
				case TINYTEXT:
					printf("%s", &row[schemas[structureId].fieldOffsets[j]]);
					break;
				}
				printf("  |  ");
			}
			printf("\n");
		}
		storageCounter = 0;
		roundNum++;
		//printf("PauseCounter %d\n", pauseCounter);
	}
	while(pauseCounter < numRows[structureId]);
	free(storage);
	printf("\nTable %s, %d rows, capacity for %d rows, stored in structure %d\n", tableNames[structureId], numRows[structureId], oblivStructureSizes[structureId], structureId);
}

int getNumRows(int structureId){
	return numRows[structureId];
}

int createTestTable(char* tableName, int numberOfRows){
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	const char* text = "You would measure time the measureless and the immeasurable.";
	int structureId = -1;
	Schema testSchema;
	testSchema.numFields = 5;
	testSchema.fieldOffsets[0] = 0;
	testSchema.fieldOffsets[1] = 1;
	testSchema.fieldOffsets[2] = 5;
	testSchema.fieldOffsets[3] = 9;
	testSchema.fieldOffsets[4] = 10;
	testSchema.fieldSizes[0] = 1;
	testSchema.fieldSizes[1] = 4;
	testSchema.fieldSizes[2] = 4;
	testSchema.fieldSizes[3] = 1;
	testSchema.fieldSizes[4] = 255;
	testSchema.fieldTypes[0] = CHAR;
	testSchema.fieldTypes[1] = INTEGER;
	testSchema.fieldTypes[2] = INTEGER;
	testSchema.fieldTypes[3] = CHAR;
	testSchema.fieldTypes[4] = TINYTEXT;
	Schema testSchema2;
	testSchema2.numFields = 4;
	testSchema2.fieldOffsets[0] = 0;
	testSchema2.fieldOffsets[1] = 1;
	testSchema2.fieldOffsets[2] = 5;
	testSchema2.fieldOffsets[3] = 9;
	testSchema2.fieldSizes[0] = 1;
	testSchema2.fieldSizes[1] = 4;
	testSchema2.fieldSizes[2] = 4;
	testSchema2.fieldSizes[3] = 1;
	testSchema2.fieldTypes[0] = CHAR;
	testSchema2.fieldTypes[1] = INTEGER;
	testSchema2.fieldTypes[2] = INTEGER;
	testSchema2.fieldTypes[3] = CHAR;
	if(strcmp(tableName, "jTable") == 0 || strcmp(tableName, "jIndex") == 0) testSchema = testSchema2;
	//create the table
	createTable(&testSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, numberOfRows+100, &structureId);
	int rowi = 0;
	for(int i = 0; i < numberOfRows; i++){
		//put in a missed row to test handling of dummies
		if(i == 5) continue;
		numRows[structureId]++;
		row[0] = 'a';
		memcpy(&row[1], &rowi, 4);
		int temp = rowi/100;
		memcpy(&row[5], &temp, 4);
		if(rowi%2 == 0) row[9] = 'a';
		else if(rowi%3 == 0) row[9] = 'b';
		else row[9]= 'c';
		memcpy(&row[10], text, strlen(text)+1);

		//begin temp

		//opOneLinearScanBlock(retStructId, roundNum*ROWS_IN_ENCLAVE+i, (Linear_Scan_Block*)row, 1);


		//end temp

		//put this row into the table manually to get a big table fast
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 1);
		rowi++;
	}
	free(row);
	lastInserted[structureId] = numberOfRows;
}

int createTestTableIndex(char* tableName, int numberOfRows){
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	const char* text = "You would measure time the measureless and the immeasurable.";
	int structureId = -1;
	Schema testSchema;
	testSchema.numFields = 5;
	testSchema.fieldOffsets[0] = 0;
	testSchema.fieldOffsets[1] = 1;
	testSchema.fieldOffsets[2] = 5;
	testSchema.fieldOffsets[3] = 9;
	testSchema.fieldOffsets[4] = 10;
	testSchema.fieldSizes[0] = 1;
	testSchema.fieldSizes[1] = 4;
	testSchema.fieldSizes[2] = 4;
	testSchema.fieldSizes[3] = 1;
	testSchema.fieldSizes[4] = 255;
	testSchema.fieldTypes[0] = CHAR;
	testSchema.fieldTypes[1] = INTEGER;
	testSchema.fieldTypes[2] = INTEGER;
	testSchema.fieldTypes[3] = CHAR;
	testSchema.fieldTypes[4] = TINYTEXT;
	Schema testSchema2;
	testSchema2.numFields = 4;
	testSchema2.fieldOffsets[0] = 0;
	testSchema2.fieldOffsets[1] = 1;
	testSchema2.fieldOffsets[2] = 5;
	testSchema2.fieldOffsets[3] = 9;
	testSchema2.fieldSizes[0] = 1;
	testSchema2.fieldSizes[1] = 4;
	testSchema2.fieldSizes[2] = 4;
	testSchema2.fieldSizes[3] = 1;
	testSchema2.fieldTypes[0] = CHAR;
	testSchema2.fieldTypes[1] = INTEGER;
	testSchema2.fieldTypes[2] = INTEGER;
	testSchema2.fieldTypes[3] = CHAR;
	if(strcmp(tableName, "jTable") == 0 || strcmp(tableName, "jIndex") == 0) testSchema = testSchema2;

	//create the table
	createTable(&testSchema, tableName, strlen(tableName), TYPE_TREE_ORAM, numberOfRows+200, &structureId);
	int rowi = 0;
	for(int i = 0; i < numberOfRows; i++){//printf("in loop %d\n", i);
		if(i % 500 == 0){
			printf("500 checkpoint: i = %d\n", i);
		}
		//put in a missed row to test handling of dummies
		if(i == 5) continue;
		//numRows[structureId]++; insertRow takes care of this
		row[0] = 'a';
		memcpy(&row[1], &rowi, 4);
		int temp = rowi/100;
		memcpy(&row[5], &temp, 4);
		if(rowi%2 == 0) row[9] = 'a';
		else if(rowi%3 == 0) row[9] = 'b';
		else row[9]= 'c';
		memcpy(&row[10], text, strlen(text));
		//printf("heree");
		insertIndexRowFast(tableName, row, rowi);
		//printf("inserted!!\n");
		//debug
		//printf("root node actualAddr: %d\n", bPlusRoots[structureId]->actualAddr);
		//opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 1);
		rowi++;
	}
	free(row);
}

int saveIndexTable(char* tableName, int tableSize){
	int structureId = getTableId(tableName);
	Oram_Bucket* bucket = (Oram_Bucket*)malloc(sizeof(Oram_Bucket));
	Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(sizeof(Encrypted_Oram_Bucket));
	//char savedTableName[20];
	//sprintf(savedTableName, "testTable%d", numRows[structureId]);
//things I need to save
	ocall_write_file(&oblivStructureSizes[structureId], 4, tableSize); //printf("here %d\n", tableSize);
	ocall_write_file(&oblivStructureTypes[structureId], 4, tableSize);
	ocall_write_file(&schemas[structureId], sizeof(Schema), tableSize);
	ocall_write_file(&rowsPerBlock[structureId], 4, tableSize);
	ocall_write_file(&numRows[structureId], 4, tableSize);
	ocall_write_file(&stashOccs[structureId], 4, tableSize);
	ocall_write_file(&logicalSizes[structureId], 4, tableSize);
	ocall_write_file(bPlusRoots[structureId], sizeof(node), tableSize);
	ocall_write_file(usedBlocks[structureId], sizeof(uint8_t)*logicalSizes[structureId], tableSize);
	ocall_write_file(positionMaps[structureId], sizeof(unsigned int)*logicalSizes[structureId], tableSize);
	std::list<Oram_Block>::iterator stashScan = stashes[structureId]->begin();
	for(int i = 0; i < stashOccs[structureId]; i++){
		ocall_write_file(&(*stashScan), sizeof(Oram_Block), tableSize);
		stashScan++;
	}
	for(int i = 0; i < logicalSizes[structureId]; i++){
		ocall_read_block(structureId, i, sizeof(Encrypted_Oram_Bucket), encBucket);
		if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) return 1;
		ocall_write_file(&bucket[0], sizeof(Oram_Bucket), tableSize);
	}
	return 0;
}

int loadIndexTable(int tableSize){
	//printf("here. table name: %s\n", tableName);
	int structureId = getNextId();
	ocall_open_read(tableSize);
	Oram_Block* block = (Oram_Block*)malloc(sizeof(Oram_Block));
	Oram_Bucket* bucket = (Oram_Bucket*)malloc(sizeof(Oram_Bucket));
	Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(sizeof(Encrypted_Oram_Bucket));
	tableNames[structureId] = (char*)malloc(20);
	ocall_make_name(tableNames[structureId], tableSize);
	//printf("here %s\n", tableNames[structureId]);
	ocall_read_file(&oblivStructureSizes[structureId], 4);
	ocall_read_file(&oblivStructureTypes[structureId], 4);
	ocall_read_file(&schemas[structureId], sizeof(Schema));
	ocall_read_file(&rowsPerBlock[structureId], 4);
	ocall_read_file(&numRows[structureId], 4);
	ocall_read_file(&stashOccs[structureId], 4);
	ocall_read_file(&logicalSizes[structureId], 4); //printf("s %d, o %d, logical size: %d, size of node %d, uint8 %d", stashOccs[structureId], oblivStructureSizes[structureId], logicalSizes[structureId], sizeof(node), sizeof(uint8_t));
	bPlusRoots[structureId] = (node*)malloc(sizeof(node));//printf("here");
	usedBlocks[structureId] = (uint8_t*)malloc(sizeof(uint8_t)*logicalSizes[structureId]);
	positionMaps[structureId] = (unsigned int*)malloc(sizeof(unsigned int)*logicalSizes[structureId]);
	stashes[structureId] = new std::list<Oram_Block>();
	ocall_read_file(bPlusRoots[structureId], sizeof(node));
	ocall_read_file(usedBlocks[structureId], sizeof(uint8_t)*logicalSizes[structureId]);
	ocall_read_file(positionMaps[structureId], sizeof(unsigned int)*logicalSizes[structureId]);
	for(int i = 0; i < stashOccs[structureId]; i++){
		ocall_read_file(&block[0], sizeof(Oram_Block));
		stashes[structureId]->push_front(*block);
	}
	//ocall_read_file(&stashes[structureId][0], sizeof(Oram_Block)*stashOccs[structureId]);
	//printf("here %d %d %d %d %d\n", oblivStructureSizes[structureId], rowsPerBlock[structureId], logicalSizes[structureId], numRows[structureId], stashOccs[structureId]);
	ocall_newStructure(structureId, TYPE_TREE_ORAM, oblivStructureSizes[structureId]);
	for(int i = 0; i < logicalSizes[structureId]; i++){
		//printf("here1 %d %d %d", i, sizeof(Oram_Bucket), sizeof(Encrypted_Oram_Bucket));
		ocall_read_file(&bucket[0], sizeof(Oram_Bucket));
		//printf("here2 %d %d %d", i, bucket->blocks[0].actualAddr, bucket->blocks[0].data[0]);
		if(encryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) return 1;
		//printf("here3 %d", i);
		ocall_write_block(structureId, i, sizeof(Encrypted_Oram_Bucket), encBucket);
		//printf("here4 %d\n", i);
	}
	return 0;
}
