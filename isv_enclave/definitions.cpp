#include "definitions.h"

int getEncBlockSize(Obliv_Type type){
	int encBlockSize = 0;
	//note: maybe later I can have all encrypted blocks padded to be the same size and hide the type of structure
	switch(type){ //get the correct encrypted block size
	case TYPE_LINEAR_SCAN:
		encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
		break;
	case TYPE_TREE_ORAM:
		encBlockSize = sizeof(Encrypted_Oram_Block);
		break;
	case TYPE_ORAM:
		encBlockSize = sizeof(Encrypted_Oram_Block);
		break;
	case TYPE_LINEAR_UNENCRYPTED:
		encBlockSize = getBlockSize(TYPE_LINEAR_SCAN);
		break;
	}
	return encBlockSize;
}

int getBlockSize(Obliv_Type type){
	int encBlockSize = 0;
	//note: maybe later I can have all encrypted blocks padded to be the same size and hide the type of structure
	switch(type){ //get the correct encrypted block size
	case TYPE_LINEAR_SCAN:
		encBlockSize = sizeof(Real_Linear_Scan_Block);
		break;
	case TYPE_LINEAR_UNENCRYPTED:
		encBlockSize = sizeof(Linear_Scan_Block);
		break;
	case TYPE_TREE_ORAM:
		encBlockSize = sizeof(Oram_Block);
		break;
	case TYPE_ORAM:
		encBlockSize = sizeof(Oram_Block);
		break;
	}
	return encBlockSize;
}

int getDBTypeSize(DB_Type type){
	int ret = 0;
	switch(type){
	case INTEGER:
		ret = 4;
		break;
	case TINYTEXT:
		ret = 255;
		break;
	case CHAR:
		ret = 1;
		break;
	}
	return ret;
}

int getRowSize(Schema *schema){
	int rowSize = 0;
	for(int i = 0; i < schema->numFields; i++){
		if(schema->fieldOffsets[i] != rowSize) return -i;//offsets wrong
		if(i > 0 && schema->fieldOffsets[i] != schema->fieldOffsets[i-1]+getDBTypeSize(schema->fieldTypes[i-1])) return -2; //offsets wrong
		rowSize += schema->fieldSizes[i];
	}
	return rowSize;
}

int nextPowerOfTwo(unsigned int v){
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}
