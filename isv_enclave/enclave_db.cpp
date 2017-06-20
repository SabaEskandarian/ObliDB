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
	int sat = 0;
	do{
		sat = 0;
		for(int i = 0; i < c.numClauses; i++){
			switch(s.fieldTypes[c.fieldNums[i]]){
			case INTEGER:
				if(c.conditionType[i] == 0){ //equality
					if((int)row[s.fieldOffsets[c.fieldNums[i]]] == (int)*(c.values[i])) {
						sat = 1;
					}
				}
				else if(c.conditionType[i] == 1) { //row val is greater than
					if((int)row[s.fieldOffsets[c.fieldNums[i]]] > (int)*(c.values[i])) {
						sat = 1;
					}
				}
				else { //row val is less than
					if((int)row[s.fieldOffsets[c.fieldNums[i]]] < (int)*(c.values[i])) {
						sat = 1;
					}
				}
				break;
			case TINYTEXT: //only check equality
				if(strncmp(&((char)row[s.fieldOffsets[c.fieldNums[i]]]), (char*)c.values[i], 255) == 0) {
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
	} while(c.nextCondition != NULL);
	return 1;
}


int createTable(Schema *schema, char* tableName, int nameLen, Obliv_Type type, int numberOfRows, int* structureId){
	//structureId should be -1 unless we want to force a particular structure for testing
	sgx_status_t retVal = SGX_SUCCESS;
	int rowsPerBlock = 1;

	//validate schema a little bit
	if(schema->numFields > MAX_COLS) return 1;
	int rowSize = getRowSize(schema);
	if(rowSize <= 0) return rowSize;
	if(BLOCK_DATA_SIZE/rowSize == 0) {//can't fit a row in a block of the data structure!
		return 4;
	}

	int initialSize = numberOfRows/rowsPerBlock;
	retVal = init_structure(initialSize, type, structureId);
	if(retVal != SGX_SUCCESS) return 5;

	//size & type are set in init_structure, but we need to initiate the rest
	tableNames[*structureId] = (char*)malloc(nameLen);
	memcpy(tableNames[*structureId], tableName, nameLen);
	memcpy(&schemas[*structureId], schema, sizeof(Schema));

	//rowsPerBlock[*structureId] = BLOCK_DATA_SIZE/rowSize;
	rowsPerBlock[*structureId] = 1; //fixed at 1 for now, see declaration
	numRows[*structureId] = 0;

	return 0;
}

int growStructure(int structureId){//TODO: make table double in size if the allocated space is full
	return 1; //likely to remain unimplemented
}

int getTableId(char *tableName) {
	for(int i = 0; i < NUM_STRUCTURES; i++){
		if(strcmp(tableName, tableNames[i]) == 0){
			return i;
		}
	}
	return -1;
}

int insertRow(char* tableName, uint8_t* row) {//trust that the row is good and insert it
	int structureId = getTableId(tableName);
	int done = 0;
	int dummyDone = 0;
	if(numRows[structureId] == logicalSizes[structureId]){
		growStructure(structureId);//not implemented
	}
	uint8_t* tempRow = malloc(BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < logicalSizes[structureId]; i++){
			opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
			if(tempRow[0] == '\0' && done == 0){
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 1);
				done++;
			}
			else{
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
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
	uint8_t* tempRow = malloc(BLOCK_DATA_SIZE);
	uint8_t* dummyRow = malloc(BLOCK_DATA_SIZE);
	memset(dummyRow, '\0', BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < logicalSizes[structureId]; i++){
			opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
			//delete if it matches the condition, write back otherwise
			if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0'){
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)dummyRow, 1);
				numRows[structureId]--;
			}
			else{
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
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
	uint8_t* tempRow = malloc(BLOCK_DATA_SIZE);
	uint8_t* dummyRow = malloc(BLOCK_DATA_SIZE);

	switch(oblivStructureTypes[structureId]){
	case TYPE_LINEAR_SCAN:
		for(int i = 0; i < logicalSizes[structureId]; i++){
			opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 0);
			//update if it matches the condition, write back otherwise
			if(rowMatchesCondition(c, tempRow, schemas[structureId]) && tempRow[0] != '\0'){
				//make changes
				memcpy(&tempRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
			}
			else{
				//make dummy changes
				memcpy(&dummyRow[schemas[structureId].fieldOffsets[colChoice]], colVal, schemas[structureId].fieldSizes[colChoice]);
				opLinearScanBlock(structureId, i, (Linear_Scan_Block*)tempRow, 1);
			}
		}
		break;
	case TYPE_TREE_ORAM:
		break;
	}
	free(tempRow);
	free(dummyRow);
}

//groupCol = -1 means not to order or group by, aggregate = -1 means no aggregate, aggregate = 0 count, 1 sum, 2 min, 3 max, 4 mean
//including algChoice in case I need to use it later to choose among algorithms
//select column colNum; if colChoice = -1, select all columns
int select(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {
	int structureId = getTableId(tableName);
	Obliv_Type type = oblivStructureTypes[structureId];
	int colChoiceSize = BLOCK_DATA_SIZE;
	DB_Type colChoiceType = INTEGER;
	int colChoiceOffset = 0;
	uint8_t* dummy;
	if(colChoice != -1){
		colChoiceSize = schemas[structureId].fieldSizes[colChoice];
		colChoiceType = schemas[structureId].fieldTypes[colChoice];
		colChoiceOffset = schemas[structureId].fieldOffsets[colChoice];
		dummy = malloc(colChoiceSize+1);
		dummy[0]='\0';
	}
	int count = 0;
	int stat = 0;
	uint8_t* row = malloc(BLOCK_DATA_SIZE);
	uint8_t* row2 = malloc(BLOCK_DATA_SIZE);

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
				int contTemp = 0;
				//first pass to determine 1) output size (count), 2) whether output is one continuous chunk (continuous)
				for(int i = 0; i < logicalSizes[structureId]; i++){
					opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
					row = ((Linear_Scan_Block*)row)->data;
					if(row[0] == '\0') continue;
					if(rowMatchesCondition(c, row, schemas[structureId])){
						count++;
						if(!continuous && !contTemp){//first hit
							continuous = 1;
						}
						else if(continuous && contTemp){//a noncontinuous hit
							continuous = 0;
						}
					}
					else{
						if(continuous && !contTemp){//end of continuous chunk
							contTemp = 1;
						}
					}
				}
				if(count > logicalSizes[structureId]*.01*PERCENT_ALMOST_ALL && colChoice == -1){ //return almost all only if the whole row is selected (to make my life easier)
					almostAll = 1;
				}

				//create table to return
				if(almostAll){
					retNumRows = logicalSizes[structureId];
				}
				else{
					retNumRows = count;
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
				createTable(&retSchema, retName, retNameLen, retType, retNumRows, &retStructId);


				//pick algorithm
				if(continuous){//use continuous chunk algorithm
					int rowi = -1;
					for(int i = 0; i < logicalSizes[structureId]; i++){
						opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
						row = ((Linear_Scan_Block*)row)->data;
						if(row[0] == '\0') continue;
						else rowi++;

						opLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 0);
						row2 = ((Linear_Scan_Block*)row2)->data;
						if(row[0] == '\0') continue;

						if(colChoice != -1){
							memset(row, 'a', BLOCK_DATA_SIZE);
							memmove(row+1, row+colChoiceOffset, colChoiceSize);//row[0] will already be not '\0'
						}
						if(rowMatchesCondition(c, row, schemas[structureId])){
							opLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row, 1);
						}
						else{
							opLinearScanBlock(retStructId, rowi%count, (Linear_Scan_Block*)row2, 1);
						}
					}
				}
				else{//pick one of other algorithms
					if(count < 20*ROWS_IN_ENCLAVE){ //option 1 ("small")
						int storageCounter = 0;
						int dummyCounter = 0;
						int pauseCounter = 0;
						int isNotPaused = 1;
						int roundNum = 1;
						uint8_t* storage = malloc(ROWS_IN_ENCLAVE*colChoiceSize);
						do{
							int rowi = -1;
							for(int i = 0; i < logicalSizes[structureId]; i++){
								opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
								row = ((Linear_Scan_Block*)row)->data;
								if(row[0] == '\0') continue;
								else rowi++;
								isNotPaused = storageCounter < ROWS_IN_ENCLAVE && rowi >= pauseCounter;
								if(isNotPaused){
									pauseCounter++;
								}
								else{
									dummyCounter++;
								}
								if(rowMatchesCondition(c, row, schemas[structureId]) && isNotPaused){
									storageCounter++;
									memcpy(storage+storageCounter*colChoiceSize, row+colChoiceOffset, colChoiceSize);
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
								memcpy(row+twiddle, storage+i*colChoiceSize, colChoiceSize);
								opLinearScanBlock(retStructId, roundNum*i, (Linear_Scan_Block*)row, 1);
							}
							storageCounter = 0;
							roundNum++;
						}
						while(pauseCounter < numRows[structureId]);
						free(storage);
					}
					else if(almostAll){
						//"almost all" solution, it's a field being returned that is not an integer so we can put in dummy entries
						//have new table that is copy of old table and delete any rows that are not supposed to be in the output
						memset(row2, '\0', BLOCK_DATA_SIZE);
						for(int i = 0; i < logicalSizes[structureId]; i++){ //copy table
							opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
							opLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 1);
						}
						for(int i = 0; i < logicalSizes[structureId]; i++){ //delete bad rows
							opLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 0);
							if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
								opLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row, 1);
							}
							else{
								opLinearScanBlock(retStructId, i, (Linear_Scan_Block*)row2, 1);//write dummy row over unselected rows
							}

						}
					}
					else{//hashing solution
						//TODO
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
				for(int i = 0; i < logicalSizes[structureId]; i++){
					opLinearScanBlock(structureId, i, (Linear_Scan_Block*)row, 0);
					row = ((Linear_Scan_Block*)row)->data;
					if(rowMatchesCondition(c, row, schemas[structureId]) && row[0] != '\0'){
						count++;
						int val = (int)row[schemas[structureId].fieldOffsets[colChoice]];
						switch(aggregate){
						case 1:
								stat+=val;
							break;
						case 2:
							if(val < stat)
								stat = val;
							break;
						case 3:
							if(val > stat)
								stat = val;
							break;
						case 4:
								stat+=val;
							break;
						}
					}
				}
				if(aggregate == 0) {
					stat = count;
				}
				else if(aggregate == 4){
					stat /= count;// to the nearest int
				}
				memset(row, 'a', BLOCK_DATA_SIZE);
				memcpy(row+1, &stat, 4);
				opLinearScanBlock(retStructId, 0, (Linear_Scan_Block*)row, 1);
			}
		}
		else{ //group by, aggregate must not be -1
			if(aggregate == -1) {
				return 1;
			}
			//TODO
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
