#include "definitions.h"
#include "isv_enclave.h"

//first field of every schema must be a char that is set to something other than '\0' (except for return tables)
//return tables must be handled and deleted before creation of next return table

//specific to database application, hidden from app
Schema schemas[NUM_STRUCTURES] = {0};
char* tableNames[NUM_STRUCTURES] = {0};
int rowsPerBlock[NUM_STRUCTURES] = {0}; //let's make this always 1; helpful for security and convenience; set block size appropriately for testing
int numRows[NUM_STRUCTURES] = {0};

int rowMatchesCondition(Condition c, uint8_t* row, Schema s){
	//assume all inputs are good
	int sat = 0, flag = 0;
	do{
		if(flag){
			c = *c.nextCondition;
		}
		sat = 0;
		for(int i = 0; i < c.numClauses; i++){
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
				if(row[s.fieldOffsets[c.fieldNums[i]]] == *(c.values[i])) {
					sat = 1;
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
	return 1;
}


int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId){
	//structureId should be -1 unless we want to force a particular structure for testing
	sgx_status_t retVal = SGX_SUCCESS;

	//validate schema a little bit
	if(schema->numFields > MAX_COLS) return 1;
	int rowSize = getRowSize(schema);
	if(rowSize <= 0) return rowSize;
	if(BLOCK_DATA_SIZE/rowSize == 0) {//can't fit a row in a block of the data structure!
		return 4;
	}

	int initialSize = numberOfRows;
	retVal = init_structure(initialSize, type, structureId);
	if(retVal != SGX_SUCCESS) return 5;

	//size & type are set in init_structure, but we need to initiate the rest
	tableNames[*structureId] = (char*)malloc(nameLen);
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

Schema getTableSchema(char *tableName) {
	int structureId = getTableId(tableName);
	return schemas[structureId];
}

int insertRow(char* tableName, uint8_t* row) {//trust that the row is good and insert it
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
		break;
	}
	numRows[structureId]++;
	free(tempRow);
}

int deleteRows(char* tableName, Condition c) {
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
		break;
	case TYPE_TREE_ORAM:
		break;
	}
	free(tempRow);
	free(dummyRow);
}

int updateRows(char* tableName, Condition c, int colChoice, uint8_t* colVal){
	int structureId = getTableId(tableName);
	uint8_t* tempRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	uint8_t* dummyRow = (uint8_t*)malloc(BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < oblivStructureSizes[structureId]; i++){
			opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
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
		break;
	case TYPE_TREE_ORAM:
		break;
	}
	free(tempRow);
	free(dummyRow);
}

int joinTables(char* tableName1, char* tableName2, int joinCol) {
	//create an oram, do block nested loop join in it, and manually convert it to a linear scan table
	//the conversion doesn't allow anything to be learned from the output of the
}

//groupCol = -1 means not to order or group by, aggregate = -1 means no aggregate, aggregate = 0 count, 1 sum, 2 min, 3 max, 4 mean
//including algChoice in case I need to use it later to choose among algorithms
//select column colNum; if colChoice = -1, select all columns
int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {
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
		if(groupCol == -1) {
			if(aggregate == -1) {//actually doing a select
				int almostAll = 0;
				int continuous = 0;
				int small = 0;
				int contTemp = 0;
				int dummyVar = 0;
				//first pass to determine 1) output size (count), 2) whether output is one continuous chunk (continuous)
				for(int i = 0; i < oblivStructureSizes[structureId]; i++){
					opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
					row = ((Linear_Scan_Block*)row)->data;
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
				if(count < 20*ROWS_IN_ENCLAVE){
					small = 1;
				}
				//printf("%d %f\n",count,  oblivStructureSizes[structureId]*.01*PERCENT_ALMOST_ALL); //count and count needed for almost all

				//create table to return
				if(almostAll){
					retNumRows = oblivStructureSizes[structureId];
				}
				else if(small || continuous){
					retNumRows = count;
				}
				else{//hash
					retNumRows = 5*count;
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
				createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);
				//printf("%d %d %d %d %s %d %d\n", retNameLen, retNumRows, retStructId, retType, retName, retSchema.numFields, retSchema.fieldSizes[1]);
				//printf("%s\n", tableNames[retStructId]);
				//printTable("ReturnTable");

				//printf("Made it to algorithm slection\n");
				//pick algorithm
				if(continuous){//use continuous chunk algorithm
					printf("CONTINUOUS\n");
					int rowi = -1, dummyVar = 0;//NOTE: rowi left in for historical reasons; it should be replaced by i
					for(int i = 0; i < oblivStructureSizes[structureId]; i++){
						opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
						row = ((Linear_Scan_Block*)row)->data;
						rowi++;
						opOneLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 0);
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
						//data structure is of size 5*output and use it as a hash table. each row is written to one of two hash values
						//hash should be first several bits of output of sha256. input will be the input row number concatenated with 0 and 1 for the two hashes
						int rowi = -1, dummyVar = 0;
						uint8_t* hashIn1 = (uint8_t*)malloc(5);
						uint8_t* hashIn2 = (uint8_t*)malloc(5);
						sgx_sha256_hash_t* hashOut1 = (sgx_sha256_hash_t*)malloc(256);
						sgx_sha256_hash_t* hashOut2 = (sgx_sha256_hash_t*)malloc(256);
						hashIn1[0] = '0';
						hashIn2[0] = '1';//doesn't really matter what these are as long as they're different
						unsigned int index1 = 0, index2 = 0;

						numRows[retStructId] = count;

						for(int i = 0; i < oblivStructureSizes[structureId]; i++){
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
							//take two hashes of rowi
							memcpy(&hashIn1[1], &rowi, 4);
							memcpy(&hashIn2[1], &rowi, 4);
							sgx_sha256_msg(hashIn1, 5, hashOut1);
							sgx_sha256_msg(hashIn2, 5, hashOut2);
							memcpy(&index1, hashOut1, 4);
							memcpy(&index2, hashOut2, 4);
							index1 %= count;
							index2 %= count;
							//printf("here %d %d %d %d\n", index1, index2, match, count);

							//walk through the 5 entries for each hash and write in the first place that has room, dummy write the rest
							int written = 0;
							if(match && row[0]!='\0') written = 0;
							else written = 1;
							for(int j = 0; j < 5; j++){
								opOneLinearScanBlock(retStructId, j*count+index1, (Linear_Scan_Block*)row2, 0);
								//printf("%d ", j*count+index1);
								if(match && !written && row2[0]=='\0'){//printf("write1\n");
									opOneLinearScanBlock(retStructId, j*count+index1, (Linear_Scan_Block*)row, 1);
									written++;								}
								else{
									opOneLinearScanBlock(retStructId, j*count+index1, (Linear_Scan_Block*)row2, 1);
									dummyVar++;
								}
								opOneLinearScanBlock(retStructId, j*count+index2, (Linear_Scan_Block*)row2, 0);
								if(match && !written && row2[0]=='\0'){//printf("write2\n");
									opOneLinearScanBlock(retStructId, j*count+index2, (Linear_Scan_Block*)row, 1);
									written++;
								}
								else{
									opOneLinearScanBlock(retStructId, j*count+index2, (Linear_Scan_Block*)row2, 1);
									dummyVar++;
								}
							}
							if(!written) {
								printf("ohhhh");
								return 1; //panic
							}

						}
					}
				}

			}
			else{//doing an aggregate with no group by
				if(colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER){
					return 1;
				}
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
				for(int i = 0; i < oblivStructureSizes[structureId]; i++){
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
		else{ //group by
			if(aggregate == -1 || colChoice == -1 || schemas[structureId].fieldTypes[colChoice] != INTEGER) {
				return 1;
			}
			printf("GROUP BY");
			//we will do this for small numbers of groups. the doc has an algorithm that can be used for larger numbers of groups
			//that uses the hyperloglog algorithm

			//first pass, count number of groups
			int numGroups = 0, dummyCounter = 0;
			uint8_t* groupVal = (uint8_t*)malloc(schemas[structureId].fieldSizes[groupCol]);
			int aggrVal = 0;
			uint8_t* groups[MAX_GROUPS];
			uint8_t* dummyData;
			int groupStat[MAX_GROUPS];
			int groupCount[MAX_GROUPS];
			for(int i = 0; i < oblivStructureSizes[structureId]; i++){
				opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
				memcpy(groupVal, &row[schemas[structureId].fieldOffsets[groupCol]], schemas[structureId].fieldSizes[groupCol]);
				memcpy(&aggrVal, &row[schemas[structureId].fieldOffsets[colChoice]], 4);
				row = ((Linear_Scan_Block*)row)->data;
				if(row[0] == '\0' || !rowMatchesCondition(c, row, schemas[structureId])) {//begin dummy brach
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
							groupCount[j]++;
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
			createTable(&retSchema, retName, retNameLen, retType, numGroups, &retStructId);
			for(int j = 0; j < numGroups; j++){
				row[0] = 'a';
				memcpy(&row[1], &groupStat[j], 4);
				memcpy(&row[5], groups[j], schemas[structureId].fieldSizes[groupCol]);
				opOneLinearScanBlock(retStructId, j, (Linear_Scan_Block*)row, 1);
				numRows[retStructId]++;
				free(groups[j]);
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

int printTable(char* tableName){
	//looks like select small since all other selects have possibility of including empties in output and we can't do dummies here
	//also, start from random position and wrap around so as not to give away what's at the beginning vs end of the data structure
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
				//printf("row[0] %c\n", row[0]);
				memcpy(&storage[storageCounter*BLOCK_DATA_SIZE], &row[0], BLOCK_DATA_SIZE);
				storageCounter++;
			}
			else{
				memcpy(dummy, dummy, BLOCK_DATA_SIZE);
				dummyCounter++;
			}
		}
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
	}
	while(pauseCounter < numRows[structureId]);
	free(storage);

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
	//create the table
	createTable(&testSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, numberOfRows+10, &structureId);
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
		memcpy(&row[10], text, strlen(text));
		//put this row into the table manually to get a big table fast
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 1);
		rowi++;
	}
	free(row);
}
