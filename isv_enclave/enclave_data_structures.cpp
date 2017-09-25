#include "definitions.h"
#include "isv_enclave.h"

//key for reading/writing to oblivious data structures
sgx_aes_gcm_128bit_key_t *obliv_key;
//for keeping track of structures, should reflect the structures held by the untrusted app;
int oblivStructureSizes[NUM_STRUCTURES] = {0}; //actual size, not logical size for orams
Obliv_Type oblivStructureTypes[NUM_STRUCTURES];
//specific to oram structures
unsigned int* positionMaps[NUM_STRUCTURES] = {0};
uint8_t* usedBlocks[NUM_STRUCTURES] = {0};
int* revNum[NUM_STRUCTURES] = {0};
std::list<Oram_Block>* stashes[NUM_STRUCTURES];
int stashOccs[NUM_STRUCTURES] = {0};//stash occupancy, number of elements in stash
int logicalSizes[NUM_STRUCTURES] = {0};
node *bPlusRoots[NUM_STRUCTURES] = { NULL };
Oram_Bucket linOramCache = {0};

int newBlock(int structureId){
	int blockNum = -1;
	for(int i = 0; i < logicalSizes[structureId]; i++){
		if(usedBlocks[structureId][i] == 0){
			blockNum = i;
		}
	}
	usedBlocks[structureId][blockNum] = 1;
	//printf("allocating block #%d\n", blockNum);
	return blockNum;
}

int freeBlock(int structureId, int blockNum){
	uint8_t* dummyBlock = (uint8_t*)malloc(sizeof(Oram_Block));
	//printf("hey");
	memset(&dummyBlock[0], '\0', sizeof(Oram_Block));//printf("hey2");
	memset(&dummyBlock[0], 0xff, 4);
	opOramBlock(structureId, blockNum, (Oram_Block*)dummyBlock, 1);
	usedBlocks[structureId][blockNum] = 0;
	free(dummyBlock);
	return 0;
}


int opOneLinearScanBlock(int structureId, int index, Linear_Scan_Block* block, int write){

	if(MIXED_USE_MODE && !write){//need to do this fast without breaking other stuff or interfaces
		//praise be to God that the formats have the same size for one block
		//that will let me treat an oram block as a real linear scan block
		int size = oblivStructureSizes[structureId];
		int blockSize = sizeof(Real_Linear_Scan_Block);
		int encBlockSize = sizeof(Encrypted_Oram_Bucket);
		int i = index;
		Real_Linear_Scan_Block* real = (Real_Linear_Scan_Block*)malloc(blockSize);
		int realSize = size*4;
		if(i%4 == 0){//need to open a new block
			Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(encBlockSize);
			ocall_read_block(structureId, i/4, encBlockSize, encBucket);
			if(decryptBlock(encBucket, &linOramCache, obliv_key, TYPE_ORAM) != 0) return 1;//printf("here 2\n");
			free(encBucket);
		}
		i%=4;
		memcpy(real, &(linOramCache.blocks[i]), blockSize);
		//we don't care about the order when they're in an oram
		//if(real->actualAddr != index && real->actualAddr != -1){
		//	printf("AUTHENTICITY FAILURE: block address not as expected! Expected %d, got %d\n", index, real->actualAddr);
		//	return 1;
		//}
		if(real->revNum != revNum[structureId][real->actualAddr]){
			printf("AUTHENTICITY FAILURE: block version not as expected! Expected %d, got %d\n", revNum[structureId][index], real->revNum);
			return 1;
		}
		//linear ops in this mode will always be reads for now, but it could also be used
		memcpy(block, real->data, BLOCK_DATA_SIZE); //keep the value we extracted from real if we're reading

		free(real);
		return 0;
	}

	//if(oblivStructureTypes[structureId] != TYPE_LINEAR_SCAN) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int blockSize = sizeof(Real_Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	int i = index;
	//allocate dummy storage and real storage
	Real_Linear_Scan_Block* dummy = (Real_Linear_Scan_Block*)malloc(blockSize);
	Real_Linear_Scan_Block* real = (Real_Linear_Scan_Block*)malloc(blockSize);
	Encrypted_Linear_Scan_Block* dummyEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	Encrypted_Linear_Scan_Block* realEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	memcpy(real->data, block, BLOCK_DATA_SIZE);

	if(write){//we leak whether an op is a read or a write; we could hide it, but it may not be necessary?
		real->actualAddr = i;
		real->revNum = revNum[structureId][i]+1;
		revNum[structureId][i]++;
		if(encryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1; //replace encryption of real with encryption of block
		ocall_write_block(structureId, i, encBlockSize, realEnc);//printf("here 3\n");
	}else{//printf("here0");
		ocall_read_block(structureId, i, encBlockSize, realEnc);//printf("here\n");
		//printf("beginning of mac(op)? %d\n", realEnc->macTag[0]);
		if(decryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;//printf("here 2\n");
		if(!MIXED_USE_MODE && real->actualAddr != i && real->actualAddr != -1){
			printf("AUTHENTICITY FAILURE: block address not as expected! Expected %d, got %d\n", i, real->actualAddr);
			return 1;
		}
		if(!MIXED_USE_MODE && real->revNum != revNum[structureId][i]){
			printf("AUTHENTICITY FAILURE: block version not as expected! Expected %d, got %d\n", revNum[structureId][i], real->revNum);
			return 1;
		}
	}

	//clean up
	if(!write) memcpy(block, real->data, BLOCK_DATA_SIZE); //keep the value we extracted from real if we're reading

	free(real);
	free(dummy);
	free(dummyEnc);
	free(realEnc);

	return 0;
}

//generic features I may want at some point
int opLinearScanBlock(int structureId, int index, Linear_Scan_Block* block, int write) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_SCAN) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int blockSize = sizeof(Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);

	//allocate dummy storage and real storage
	Linear_Scan_Block* dummy = (Linear_Scan_Block*)malloc(blockSize);
	Linear_Scan_Block* real = (Linear_Scan_Block*)malloc(blockSize);
	Encrypted_Linear_Scan_Block* dummyEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	Encrypted_Linear_Scan_Block* realEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);

	for(int i = 0; i < size; i++){
		if(i == index){//printf("begin real\n");
			if(write){//we leak whether an op is a read or a write; we could hide it, but it may not be necessary?
				if(encryptBlock(realEnc, block, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1; //replace encryption of real with encryption of block
				ocall_write_block(structureId, i, encBlockSize, realEnc);
			}//printf("end real\n");
			else{
				ocall_read_block(structureId, i, encBlockSize, realEnc);//printf("here\n");
				//printf("beginning of mac(op)? %d\n", realEnc->macTag[0]);
				if(decryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;
			}

		}
		else{//printf("begin dummy\n");
			if(write){
				if(encryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
				ocall_write_block(structureId, i, encBlockSize, dummyEnc);
			}//printf("end dummy\n");
			else{
				ocall_read_block(structureId, i, encBlockSize, dummyEnc);
				//printf("beginning of mac(op)? %d\n", dummyEnc->macTag[0]);
				if(decryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
			}
		}
	}

	//clean up
	if(!write) memcpy(block, real, blockSize); //keep the value we extracted from real if we're reading

	free(real);
	free(dummy);
	free(dummyEnc);
	free(realEnc);

	return 0;
}

int opLinearScanUnencryptedBlock(int structureId, int index, Linear_Scan_Block* block, int write) {
	if(oblivStructureTypes[structureId] != TYPE_LINEAR_UNENCRYPTED) return 1; //if the designated data structure is not a linear scan structure
	int size = oblivStructureSizes[structureId];
	int blockSize = sizeof(Linear_Scan_Block);
	//int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	//allocate dummy storage and real storage
	Linear_Scan_Block* dummy = (Linear_Scan_Block*)malloc(blockSize);
	Linear_Scan_Block* real = (Linear_Scan_Block*)malloc(blockSize);
	//Encrypted_Linear_Scan_Block* dummyEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);
	//Encrypted_Linear_Scan_Block* realEnc = (Encrypted_Linear_Scan_Block*)malloc(encBlockSize);

	for(int i = 0; i < size; i++){
		if(i == index){
			ocall_read_block(structureId, i, blockSize, real);
			//printf("beginning of mac(op)? %d\n", realEnc->macTag[0]);
			//if(decryptBlock(realEnc, real, obliv_key, TYPE_LINEAR_SCAN) != 0) return 1;
			if(write){//we leak whether an op is a read or a write; we could hide it, but it may not be necessary?
				//if(encryptBlock(realEnc, block, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1; //replace encryption of real with encryption of block
				ocall_write_block(structureId, i, blockSize, real);
			}

		}
		else{
			ocall_read_block(structureId, i, blockSize, dummy);
			//printf("beginning of mac(op)? %d\n", dummyEnc->macTag[0]);
			//if(decryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
			if(write){
				//if(encryptBlock(dummyEnc, dummy, obliv_key, TYPE_LINEAR_SCAN)!=0) return 1;
				ocall_write_block(structureId, i, blockSize, dummy);
			}
		}
	}

	//clean up
	if(!write) memcpy(block, real, blockSize); //keep the value we extracted from real if we're reading

	free(real);
	free(dummy);
	//free(dummyEnc);
	//free(realEnc);

	return 0;
}

int opOramBlock(int structureId, int index, Oram_Block* retBlock, int write){
	//not making a real effort to protect against timing differences for this part
	//printf("check1 %d %d %d %d\n", structureId, stashOccs[structureId], stashes[structureId]->size(), stashes[structureId]->begin()->actualAddr);

	int blockSize = sizeof(Oram_Block);
	int bucketSize = sizeof(Oram_Bucket);
	int encBucketSize = sizeof(Encrypted_Oram_Bucket);
	Oram_Block* block = (Oram_Block*)malloc(sizeof(Oram_Block));
	Oram_Bucket* bucket = (Oram_Bucket*)malloc(sizeof(Oram_Bucket));
	Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(sizeof(Encrypted_Oram_Bucket));
	int oldLeaf = positionMaps[structureId][index];//printf("old leaf: %d", oldLeaf);
	int treeSize = logicalSizes[structureId];
	//pick a leaf between 0 and logicalSizes[structureId]/2
	if(sgx_read_rand((uint8_t*)&positionMaps[structureId][index], sizeof(unsigned int)) != SGX_SUCCESS) return 1;//Error comes from here
	positionMaps[structureId][index] = positionMaps[structureId][index] % (treeSize/2+1);
	int newLeaf = positionMaps[structureId][index];
	//if(newLeaf < 0) printf("bad!!!\n");

	//empty bucket to write to structure to erase stale data from tree
	uint8_t* junk = (uint8_t*)malloc(bucketSize);
	uint8_t* encJunk = (uint8_t*)malloc(encBucketSize);
	memset(junk, '\0', bucketSize);
	memset(&junk[0], 0xff, 4);//set actualAddr to -1
	memset(&junk[sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
	memset(&junk[2*sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
	memset(&junk[3*sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
	memset(encJunk, 0xff, encBucketSize);
	//printf("check1.5\n");
	if(encryptBlock(encJunk, junk, obliv_key, TYPE_ORAM)) return 1;


	//printf("old leaf: %d, new leaf: %d\n", oldLeaf, positionMaps[structureId][index]);

	//printf("begin stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());

	//printf("check2 %d %d\n", treeSize, oldLeaf);

	//read in a path
	int nodeNumber = treeSize/2+oldLeaf;
	for(int i = (int)log2(treeSize+1.1)-1; i>=0; i--){
		//read in bucket at depth i on path to oldLeaf
		//encrypt/decrypt buckets all at once instead of blocks
		//let index be the node number in a levelorder traversal and size the encBucketSize
		ocall_read_block(structureId, nodeNumber, encBucketSize, encBucket);//printf("here %d %d %d\n", nodeNumber, treeSize, oldLeaf);
		if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) return 1;
		//write back dummy blocks to replace blocks we just took out
		ocall_write_block(structureId, nodeNumber, encBucketSize, encJunk);
		for(int j = 0; j < BUCKET_SIZE;j++){
			//printf("saw block %d  ", bucket->blocks[j].actualAddr);
			if(bucket->blocks[j].actualAddr != -1){
				//printf("pushing actualAddr block %d\n", bucket->blocks[j].actualAddr);
				stashes[structureId]->push_front(bucket->blocks[j]);
				stashOccs[structureId]++;
			}
		}
		nodeNumber = (nodeNumber-1)/2;
	}

	//printf("check3\n");

	//debug: print blocks in stash
	//std::list<Oram_Block>::iterator stashScanDebug = stashes[structureId]->begin();
	//while(stashScanDebug != stashes[structureId]->end()){
			//printf("block %d is in stash\n", stashScanDebug->actualAddr);
	//	stashScanDebug++;
	//}
	//printf("\n");

	//read/write target block from stash
	int foundItFlag = 0;
	std::list<Oram_Block>::iterator stashScan = stashes[structureId]->begin();
	while(stashScan != stashes[structureId]->end()){
		//printf("looking at %d\n", stashScan->actualAddr);
		if(stashScan->actualAddr == index && foundItFlag == 0){//printf("hey! we're here!!\n");
			foundItFlag = 1;
			if(write){
				retBlock->actualAddr = index;
				revNum[structureId][retBlock->actualAddr]++;
				retBlock->revNum = revNum[structureId][retBlock->actualAddr];
				//memcpy(&stashes[structureId][i], retBlock, blockSize);
				memcpy(&(*stashScan), retBlock, blockSize);
			}
			else{
				//memcpy(retBlock, &stashes[structureId][i], blockSize);
				memcpy(retBlock, &(*stashScan), blockSize);
				if(retBlock->revNum != revNum[structureId][index]){
					printf("AUTHENTICITY FAILURE a: block version not as expected! Expected %d, got %d\n", revNum[structureId][index], retBlock->revNum);
					return 1;
				}
			}
		}
		stashScan++;
	}

	if(foundItFlag == 0){//the desired block has not been initialized
		//printf("creating block %d\n", index);
		//put the new block on the stash
		block->actualAddr = index;
		if(write){
			retBlock->actualAddr = index;
			revNum[structureId][retBlock->actualAddr]++;
			retBlock->revNum = revNum[structureId][retBlock->actualAddr];
			memcpy(block, retBlock, blockSize);
		}
		else{
			memset(block->data, 0, BLOCK_DATA_SIZE);
			memcpy(retBlock, block, blockSize);
			if(retBlock->revNum != revNum[structureId][index]){ // == 0
				printf("AUTHENTICITY FAILURE b: block version not as expected! Expected %d, got %d on block %d %d\n", revNum[structureId][index], retBlock->revNum, retBlock->actualAddr, index);
				return 1;
			}
		}
		//memcpy(&stashes[structureId][stashOccs[structureId]], &newBlock, blockSize);
		stashes[structureId]->push_back(*block);
		stashOccs[structureId]++;
	}

	//printf("check4\n");
	//printf("mid stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());

	nodeNumber = treeSize/2+oldLeaf;
	for(int i = (int)log2(treeSize+1.1)-1; i>=0; i--){
		int div = pow((double)2, ((int)log2(treeSize+1.1)-1)-i);
		//printf("nodeNumber: %d\n", nodeNumber);
		//read contents of bucket
		ocall_read_block(structureId, nodeNumber, encBucketSize, encBucket);
		if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) return 1;

		//for each dummy entry in bucket, fill with candidates from stash
		int stashCounter = stashOccs[structureId];
		std::list<Oram_Block>::iterator p = stashes[structureId]->begin();
		for(int j = 0; j < BUCKET_SIZE; j++){
			//printf("bucket entry %d, actualAddr %d %d\n", j, bucket->blocks[j].actualAddr, stashCounter);
			if(bucket->blocks[j].actualAddr == -1){//printf("herein %d\n", stashCounter);
				while(stashCounter > 0){//printf("hereinner %d\n", p->actualAddr);
					int destinationLeaf = positionMaps[structureId][p->actualAddr];
					int conditionMet = 0;
					//div is 2 raised to the number of levels from the leaf to the current depth
					conditionMet = ((treeSize/2)+oldLeaf-(div-1))/div == ((treeSize/2)+destinationLeaf-(div-1))/div;
					//printf("%d %d", ((treeSize/2)+oldLeaf-(div-1))/div, ((treeSize/2)+destinationLeaf-(div-1))/div);
					if(conditionMet){//we can put this block in this bucket
							//printf("condition met! leaves: %d %d, depth: %d, div: %d, block: %d\n", oldLeaf, destinationLeaf, i, div, p->actualAddr);
						//printf("removing an item form the stash\n");
						memcpy(&bucket->blocks[j], &(*p), blockSize);
						//remove from stash
						std::list<Oram_Block>::iterator prev = p++;
						stashes[structureId]->erase(prev);
						stashOccs[structureId]--;
						stashCounter--;
						break;
					}
					p++;
					stashCounter--;
				}//printf("here\n");
			}

		}
		//printf("another check\n");
		//write bucket back to tree
		//printf("blocks we are inserting at this level: %d %d %d %d\n", currentBucket.blocks[0].actualAddr, currentBucket.blocks[1].actualAddr, currentBucket.blocks[2].actualAddr,currentBucket.blocks[3].actualAddr);
		if(encryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) return 1;
		ocall_write_block(structureId, nodeNumber, encBucketSize, encBucket);
		nodeNumber = (nodeNumber-1)/2;
	}

	//printf("check5\n");
	//printf("end stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());
	if(stashOccs[structureId] > EXTRA_STASH_SPACE){
		printf("using too much stash! %d\n", stashOccs[structureId]);
		return 1;
	}

	//free resources used
	free(block);
	free(bucket);
	free(encBucket);
	free(junk);
	free(encJunk);

	return 0;
}

sgx_status_t oramDistribution(int structureId) {
	int blockSize = sizeof(Oram_Block);
	int bucketSize = sizeof(Oram_Bucket);
	int encBucketSize = sizeof(Encrypted_Oram_Bucket);
	Oram_Block* block = (Oram_Block*)malloc(sizeof(Oram_Block));
	Oram_Bucket* bucket = (Oram_Bucket*)malloc(sizeof(Oram_Bucket));
	Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(sizeof(Encrypted_Oram_Bucket));
	int treeSize = oblivStructureSizes[structureId];

	for(int i = (int)log2(treeSize+1.1)-1; i>=0; i--){
		int depthCount = 0;
		for (int k = 0; k < (int)pow((double)2, i)-.9; k++){
			//printf("reading block %d\n", (int)(pow((double)2, i)-.9)+k);
			ocall_read_block((double)structureId, (int)(pow((double)2, i)-.9)+k, encBucketSize, encBucket);//printf("here\n");
			if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) {
				printf("fail\n");
				return SGX_ERROR_UNEXPECTED;
			}

			for(int j = 0; j < BUCKET_SIZE;j++){
				//printf("saw block %d  ", bucket->blocks[j].actualAddr);
				if(bucket->blocks[j].actualAddr != -1){
					depthCount++;
					stashes[structureId]->push_front(bucket->blocks[j]);
					stashOccs[structureId]++;
				}
			}
		}
		printf("depth: %d, count: %d\n", i, depthCount);
	}

	return SGX_SUCCESS;
}

int posMapAccess(int structureId, int index, unsigned int* value, int write){
	int out = -1, dummyOut = -1;
	int dummyWriteVal = -1;
	for(int i = 0; i < logicalSizes[structureId]; i++){
		if(i == index) {
			if(write){
				positionMaps[structureId][index] = *value;
			}
			else{
				out = positionMaps[structureId][i];
			}
		}
		else {
			if(write){
				positionMaps[structureId][index] = positionMaps[structureId][index]-1+1;
			}
			else{
				dummyOut = positionMaps[structureId][i];
			}
		}
	}
	//printf("%d, %d\n", index,  out);
	if(!write){
		*value = out;
	}
	//if(write == 0 && out < 0) printf("WHOAOAOAOOAA\n");
	//if(write == 1 && *value < 0) printf("AOAOOAOAOAAOAWH\n");
	return 0;
}

int opOramBlockSafe(int structureId, int index, Oram_Block* retBlock, int write){
	//not making a real effort to protect against timing differences for this part
	//printf("check1 %d\n", structureId);

	int blockSize = sizeof(Oram_Block);
	int bucketSize = sizeof(Oram_Bucket);
	int encBucketSize = sizeof(Encrypted_Oram_Bucket);
	Oram_Block* block = (Oram_Block*)malloc(sizeof(Oram_Block));
	Oram_Bucket* bucket = (Oram_Bucket*)malloc(sizeof(Oram_Bucket));
	Encrypted_Oram_Bucket* encBucket = (Encrypted_Oram_Bucket*)malloc(sizeof(Encrypted_Oram_Bucket));
	unsigned int oldLeaf = -1;
	posMapAccess(structureId, index, &oldLeaf, 0);
	//printf("old leaf: %d\n", oldLeaf);
	int treeSize = logicalSizes[structureId];
	//pick a leaf between 0 and logicalSizes[structureId]/2
	unsigned int newLeaf = -1;
	if(sgx_read_rand((uint8_t*)&newLeaf, sizeof(unsigned int)) != SGX_SUCCESS) {
		printf("fail position 0\n");
		return 1;//Error comes from here
	}
	newLeaf = newLeaf % (treeSize/2+1);
	posMapAccess(structureId, index, &newLeaf, 1);
	//printf("new leaf: %d\n", newLeaf);


	//empty bucket to write to structure to erase stale data from tree
	uint8_t* junk = (uint8_t*)malloc(bucketSize);
	uint8_t* encJunk = (uint8_t*)malloc(encBucketSize);
	memset(junk, 0xff, bucketSize);
	memset(encJunk, 0xff, encBucketSize);
	if(encryptBlock(encJunk, junk, obliv_key, TYPE_ORAM)) {
		printf("fail position 1\n");
		return 1;
	}


	//printf("old leaf: %d, new leaf: %d\n", oldLeaf, positionMaps[structureId][index]);

	//printf("begin stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());

	//printf("check2\n");

	//read in a path
	int nodeNumber = treeSize/2+oldLeaf;
	for(int i = (int)log2(treeSize+1.1)-1; i>=0; i--){
		//read in bucket at depth i on path to oldLeaf
		//encrypt/decrypt buckets all at once instead of blocks
		//let index be the node number in a levelorder traversal and size the encBucketSize
		ocall_read_block(structureId, nodeNumber, encBucketSize, encBucket);//printf("here\n");
		if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) {
			printf("fail position 2\n");
			return 1;
		}
		//write back dummy blocks to replace blocks we just took out
		ocall_write_block(structureId, nodeNumber, encBucketSize, encJunk);
		for(int j = 0; j < BUCKET_SIZE;j++){
			//printf("saw block %d  ", bucket->blocks[j].actualAddr);
			if(bucket->blocks[j].actualAddr != -1){
				stashes[structureId]->push_front(bucket->blocks[j]);
				stashOccs[structureId]++;
			}
		}
		nodeNumber = (nodeNumber-1)/2;
	}

	//printf("check3\n");

	//debug: print blocks in stash
	std::list<Oram_Block>::iterator stashScanDebug = stashes[structureId]->begin();
	while(stashScanDebug != stashes[structureId]->end()){
			//printf("block %d is in stash\n", stashScanDebug->actualAddr);
		stashScanDebug++;
	}
	//printf("\n");

	//read/write target block from stash
	int foundItFlag = 0;
	std::list<Oram_Block>::iterator stashScan = stashes[structureId]->begin();
	while(stashScan != stashes[structureId]->end()){
		//printf("looking at %d\n", stashScan->actualAddr);
		if(stashScan->actualAddr == index){
			foundItFlag = 1;
			if(write){
				//memcpy(&stashes[structureId][i], retBlock, blockSize);
				memcpy(&(*stashScan), retBlock, blockSize);
			}
			else{
				//memcpy(retBlock, &stashes[structureId][i], blockSize);
				memcpy(retBlock, &(*stashScan), blockSize);

			}
		}
		stashScan++;
	}

	if(foundItFlag == 0){//the desired block has not been initialized
		//printf("creating block %d\n", index);
		//put the new block on the stash
		block->actualAddr = index;
		if(write){
			memcpy(block, retBlock, blockSize);
		}
		//memcpy(&stashes[structureId][stashOccs[structureId]], &newBlock, blockSize);
		stashes[structureId]->push_back(*block);
		stashOccs[structureId]++;
	}

	//printf("check4\n");
	//printf("mid stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());

	nodeNumber = treeSize/2+oldLeaf;
	for(int i = (int)log2(treeSize+1.1)-1; i>=0; i--){
		//printf("nodeNumber: %d\n", nodeNumber);
		int div = pow((double)2, ((int)log2(treeSize+1.1)-1)-i);
		//read contents of bucket
		ocall_read_block(structureId, nodeNumber, encBucketSize, encBucket);//printf("here\n");
		if(decryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) {
			printf("fail position 3\n");
			return 1;
		}

		//for each dummy entry in bucket, fill with candidates from stash
		int stashCounter = stashOccs[structureId];
		std::list<Oram_Block>::iterator p = stashes[structureId]->begin();
		for(int j = 0; j < BUCKET_SIZE; j++){
			//printf("bucket entry %d\n", j);
			if(bucket->blocks[j].actualAddr == -1){
				while(stashCounter > 0){
					unsigned int destinationLeaf = -1;
					posMapAccess(structureId, p->actualAddr, &destinationLeaf, 0);
					if(destinationLeaf < 0) printf("destLeaf %d\n", destinationLeaf);
					int conditionMet = 0;
					//div is 2 raised to the number of levels from the leaf to the current depth
					conditionMet = ((treeSize/2)+oldLeaf-(div-1))/div == ((treeSize/2)+destinationLeaf-(div-1))/div;
					if(conditionMet){//we can put this block in this bucket
							//printf("condition met! leaves: %d %d, depth: %d, div: %d, block: %d\n", oldLeaf, destinationLeaf, i, div, p->actualAddr);
						memcpy(&bucket->blocks[j], &(*p), blockSize);
						//remove from stash
						std::list<Oram_Block>::iterator prev = p++;
						stashes[structureId]->erase(prev);
						stashOccs[structureId]--;
						stashCounter--;
						break;
					}
					p++;
					stashCounter--;
				}
			}

		}
		//write bucket back to tree
		//printf("blocks we are inserting at this level: %d %d %d %d\n", currentBucket.blocks[0].actualAddr, currentBucket.blocks[1].actualAddr, currentBucket.blocks[2].actualAddr,currentBucket.blocks[3].actualAddr);
		if(encryptBlock(encBucket, bucket, obliv_key, TYPE_ORAM) != 0) {
			printf("fail position 4\n");
			return 1;
		}
		ocall_write_block(structureId, nodeNumber, encBucketSize, encBucket);
		nodeNumber = (nodeNumber-1)/2;
	}

	//printf("check5\n");
	//printf("end stash size: %d %d\n", stashOccs[structureId], stashes[structureId]->size());
	if(stashOccs[structureId] > EXTRA_STASH_SPACE){
		printf("using too much stash: %d\n", stashOccs[structureId]);
		return 1;
	}

	//free resources used
	free(block);
	free(bucket);
	free(encBucket);
	free(junk);
	free(encJunk);

	return 0;
}

int opOramTreeBlock(int structureId, int index, Oram_Tree_Block* block, int write) {
	return 1;
}





int encryptBlock(void *ct, void *pt, sgx_aes_gcm_128bit_key_t *key, Obliv_Type type){
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	int encBlockSize = getEncBlockSize(type);
	int blockSize = getBlockSize(type);
	if(type == TYPE_ORAM){
		blockSize = sizeof(Oram_Bucket);
		encBlockSize = sizeof(Encrypted_Oram_Bucket);
	}

	switch(type){
	case TYPE_LINEAR_SCAN://printf("here I am\n");
		//get random IV
		ret = sgx_read_rand(((Encrypted_Linear_Scan_Block*)ct)->iv, 12);
		if(ret != SGX_SUCCESS) retVal = 1;
		//encrypt
		ret = sgx_rijndael128GCM_encrypt(key, (unsigned char*)pt, blockSize, ((Encrypted_Linear_Scan_Block*)ct)->ciphertext,
				((Encrypted_Linear_Scan_Block*)ct)->iv, 12, NULL, 0, &((Encrypted_Linear_Scan_Block*)ct)->macTag);
		if(ret != SGX_SUCCESS) retVal = 1;
		break;
	case TYPE_TREE_ORAM:
		//get random IV
		ret = sgx_read_rand(((Encrypted_Oram_Tree_Block*)ct)->iv, 12);
		if(ret != SGX_SUCCESS) retVal = 1;
		//encrypt
		ret = sgx_rijndael128GCM_encrypt(key, (unsigned char*)pt, blockSize, ((Encrypted_Oram_Tree_Block*)ct)->ciphertext,
				((Encrypted_Oram_Tree_Block*)ct)->iv, 12, NULL, 0, &((Encrypted_Oram_Tree_Block*)ct)->macTag);
		if(ret != SGX_SUCCESS) retVal = 1;
		printf("I'M ACTUALLY HERE ENC, LOOK AT ME LOOK AT ME LOOK AT ME\n");

		break;
	case TYPE_ORAM:
		//get random IV
		ret = sgx_read_rand(((Encrypted_Oram_Bucket*)ct)->iv, 12);
		if(ret != SGX_SUCCESS) retVal = 1;
		//encrypt
		ret = sgx_rijndael128GCM_encrypt(key, (unsigned char*)pt, blockSize, ((Encrypted_Oram_Bucket*)ct)->ciphertext,
				((Encrypted_Oram_Bucket*)ct)->iv, 12, NULL, 0, &((Encrypted_Oram_Bucket*)ct)->macTag);
		//printf("hereenc: %d", ret);
		if(ret != SGX_SUCCESS) retVal = 1;
		break;
	default:
		printf("error: trying to encrypt invalid data structure type\n"); return 1;
		break;
	}

	//printf("completed an encryption with status %d and retVal %d\n", ret, retVal);
	return retVal;
}

int decryptBlock(void *ct, void *pt, sgx_aes_gcm_128bit_key_t *key, Obliv_Type type){
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	int encBlockSize = getEncBlockSize(type);
	int blockSize = getBlockSize(type);
	if(type == TYPE_ORAM){
		blockSize = sizeof(Oram_Bucket);
		encBlockSize = sizeof(Encrypted_Oram_Bucket);
	}

	switch(type){
	case TYPE_LINEAR_SCAN:
		//decrypt
		ret = sgx_rijndael128GCM_decrypt(key, ((Encrypted_Linear_Scan_Block*)ct)->ciphertext, blockSize, (unsigned char*)pt,
				((Encrypted_Linear_Scan_Block*)ct)->iv, 12, NULL, 0, &((Encrypted_Linear_Scan_Block*)ct)->macTag);
		//printf("beginning of mac(enclave)? %d\n", ((Encrypted_Linear_Scan_Block*)ct)->macTag[0]);//debug code
		if(ret != SGX_SUCCESS) retVal = 1;
		break;
	case TYPE_TREE_ORAM:
		//decrypt
		ret = sgx_rijndael128GCM_decrypt(key, ((Encrypted_Oram_Tree_Block*)ct)->ciphertext, blockSize, (unsigned char*)pt,
				((Encrypted_Oram_Tree_Block*)ct)->iv, 12, NULL, 0, &((Encrypted_Oram_Tree_Block*)ct)->macTag);
		if(ret != SGX_SUCCESS) retVal = 1;
		printf("I'M ACTUALLY HERE, LOOK AT ME LOOK AT ME LOOK AT ME\n");
		break;
	case TYPE_ORAM:
		//decrypt
		ret = sgx_rijndael128GCM_decrypt(key, ((Encrypted_Oram_Bucket*)ct)->ciphertext, blockSize, (unsigned char*)pt,
				((Encrypted_Oram_Bucket*)ct)->iv, 12, NULL, 0, &((Encrypted_Oram_Bucket*)ct)->macTag);
		//printf("here: %d", ret);
		if(ret != SGX_SUCCESS) retVal = 1;
		break;
	default:
		printf("error: trying to decrypt invalid data structure type\n"); return 1;
		break;
	}

	//printf("completed a decryption with status %d and retVal %d\n", ret, retVal);
	return retVal;
}

int getNextId(){
	int ret = -1;
	for(int i = 0; i < NUM_STRUCTURES; i++){
		if(oblivStructureSizes[i] == 0) {
			//printf("\ngetNextId() returning %d\n", i);
			return i;
		}
	}
	return ret;
}

sgx_status_t total_init(){ //get key
	obliv_key = (sgx_aes_gcm_128bit_key_t*)malloc(sizeof(sgx_aes_gcm_128bit_key_t));
	return sgx_read_rand((unsigned char*) obliv_key, sizeof(sgx_aes_gcm_128bit_key_t));
}

sgx_status_t init_structure(int size, Obliv_Type type, int* structureId){//size in blocks
	sgx_status_t ret = SGX_SUCCESS;
    int newId = getNextId();
    if(newId == -1) return SGX_ERROR_UNEXPECTED;
    if(*structureId != -1) newId = *structureId;
    int logicalSize = size;
    logicalSizes[newId] = logicalSize;
	int encBlockSize = getEncBlockSize(type);
	int blockSize = getBlockSize(type);
    //printf("initcheck1\n");
	revNum[newId] = (int*)malloc(logicalSize*sizeof(int));
	memset(&revNum[newId][0], 0, logicalSize*sizeof(int));

    if(type == TYPE_ORAM || type == TYPE_TREE_ORAM) {
    	blockSize = sizeof(Oram_Bucket);
    	encBlockSize = sizeof(Encrypted_Oram_Bucket);
    	//size = BUCKET_SIZE*size;
    	positionMaps[newId] = (unsigned int*)malloc(logicalSize*sizeof(unsigned int));
    	usedBlocks[newId] = (uint8_t*)malloc(logicalSize*sizeof(uint8_t));
    	memset(&usedBlocks[newId][0], 0, logicalSize*sizeof(uint8_t));
    	//stashes[*structureId] = (Oram_Block*)malloc(BLOCK_DATA_SIZE*(BUCKET_SIZE*((int)(log2(logicalSize+1.1))) + EXTRA_STASH_SPACE));//Zlog_2(N)B+90B
    	stashes[newId] = new std::list<Oram_Block>();
    	stashOccs[newId] = 0;
    	for(int i = 0; i < logicalSize; i++){
    		//pick a leaf between 0 and logicalSizes[structureId]/2
    		if(sgx_read_rand((uint8_t*)(&positionMaps[newId][i]), sizeof(unsigned int)) != SGX_SUCCESS) return SGX_ERROR_UNEXPECTED;
    		positionMaps[newId][i] = positionMaps[newId][i] % (logicalSize/2+1);
    		//printf("%d %d\n", newId, positionMaps[newId][i]);
    	}
    	//bPlusRoots[structureId] = NULL;
    }

    //printf("initcheck2\n");

	oblivStructureSizes[newId] = size;
	oblivStructureTypes[newId] = type;
	int ret2 = 0;
	ocall_newStructure(newId, type, size);

	//printf("initcheck3\n");

	uint8_t* junk = (uint8_t*)malloc(blockSize);
	uint8_t* encJunk = (uint8_t*)malloc(encBlockSize);
	memset(junk, '\0', blockSize);
	if(type == TYPE_LINEAR_SCAN){
		((Real_Linear_Scan_Block*)junk)->actualAddr = -1;
	}
	//memset(junk, 0xff, blockSize);
	memset(encJunk, 0xff, encBlockSize);
	if(type != TYPE_LINEAR_UNENCRYPTED){
		if(type == TYPE_TREE_ORAM) type = TYPE_ORAM;
		if(type == TYPE_ORAM){
			memset(&junk[0], 0xff, 4);//set actualAddr to -1
			memset(&junk[sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
			memset(&junk[2*sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
			memset(&junk[3*sizeof(Oram_Block)], 0xff, 4);//set actualAddr to -1
			//printf("%d thing %d %d %d %d %d \n", type, ((Oram_Bucket*)junk)->blocks[0].data[0], ((Oram_Bucket*)junk)->blocks[0].actualAddr, ((Oram_Bucket*)junk)->blocks[1].actualAddr, ((Oram_Bucket*)junk)->blocks[2].actualAddr, ((Oram_Bucket*)junk)->blocks[3].actualAddr);
		}
		ret2 = encryptBlock(encJunk, junk, obliv_key, type);
		//debug
		//ret2 = decryptBlock(encJunk, junk, obliv_key, type);
		//printf("%d thing %d %d %d %d \n", type, ((Oram_Bucket*)junk)->blocks[0].actualAddr, ((Oram_Bucket*)junk)->blocks[1].actualAddr, ((Oram_Bucket*)junk)->blocks[2].actualAddr, ((Oram_Bucket*)junk)->blocks[3].actualAddr);
		//end debug
		if(ret2) return SGX_ERROR_UNEXPECTED;
	}

	//printf("initcheck4\n");
	//printf("enclave: initializing %d blocks\n", size);
	//write junk to every block of data structure
	//printf("block size to write: %d\n", encBlockSize);
	for(int i = 0; i < size; i++)
	{
			//printf("about to write to encrypted block %d of size %d... ", i, encBlockSize);
			if(!encJunk) printf("buffer is null pointer!");
			ocall_write_block(newId, i, encBlockSize, encJunk);
			//printf("written\n");
	}
	//printf("enclave: done initializing structure\n");
	*structureId = newId;
	return ret;

	free(junk);
	free(encJunk);
}

sgx_status_t free_oram(int structureId){
	sgx_status_t ret = SGX_SUCCESS;
	free(positionMaps[structureId]);
	free(usedBlocks[structureId]);
	//free(stashes[structureId]);
	delete(stashes[structureId]);
	if(bPlusRoots[structureId] != NULL){
		free(bPlusRoots[structureId]);
		bPlusRoots[structureId] = NULL;
	}
	return ret;
}

//clean up a structure
sgx_status_t free_structure(int structureId) {
	sgx_status_t ret = SGX_SUCCESS;
	if(oblivStructureTypes[structureId] == TYPE_ORAM || oblivStructureTypes[structureId] == TYPE_TREE_ORAM) {
		free_oram(structureId);
	}
	free(revNum[structureId]);
	stashOccs[structureId] = 0;
	logicalSizes[structureId] = 0;
	oblivStructureSizes[structureId] = 0; //most important since this is what we use to check if a slot is open
	ocall_deleteStructure(structureId);
	return ret;
}
