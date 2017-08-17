/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server. 



#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"
#include "../isv_enclave/definitions.h"//structs, enums, fixed constants

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"


#define ENCLAVE_PATH "isv_enclave.signed.so"


//use these to keep track of all the structures and their types (added by me, not part of sample code)
int oblivStructureSizes[NUM_STRUCTURES] = {0};
int oblivStructureTypes[NUM_STRUCTURES] = {0};
uint8_t* oblivStructures[NUM_STRUCTURES] = {0}; //hold pointers to start of each oblivious data structure
FILE *readFile = NULL;

uint8_t* msg1_samples[] = { msg1_sample1, msg1_sample2 };
uint8_t* msg2_samples[] = { msg2_sample1, msg2_sample2 };
uint8_t* msg3_samples[MSG3_BODY_SIZE] = { msg3_sample1, msg3_sample2 };
uint8_t* attestation_msg_samples[] =
    { attestation_msg_sample1, attestation_msg_sample2};

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null %d %d)\n", mem, len);
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        /*
        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
        */
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        /*
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
        */
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

/*
 * Begin Saba's Code
 * OCALLS GO HERE
 *
 * */

void ocall_print(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
    fflush(stdout);
}

void ocall_read_block(int structureId, int index, int blockSize, void *buffer){ //read in to buffer
	if(blockSize == 0){
		printf("unkown oblivious data type\n");
		return;
	}//printf("heer\n");fflush(stdout);
	//printf("index: %d, blockSize: %d structureId: %d\n", index, blockSize, structureId);
	//printf("start %d, addr: %d, expGap: %d\n", oblivStructures[structureId], oblivStructures[structureId]+index*blockSize, index*blockSize);fflush(stdout);
	memcpy(buffer, oblivStructures[structureId]+((long)index*blockSize), blockSize);//printf("heer\n");fflush(stdout);
	//printf("beginning of mac(app)? %d\n", ((Encrypted_Linear_Scan_Block*)(oblivStructures[structureId]+(index*encBlockSize)))->macTag[0]);
	//printf("beginning of mac(buf)? %d\n", ((Encrypted_Linear_Scan_Block*)(buffer))->macTag[0]);

}
void ocall_write_block(int structureId, int index, int blockSize, void *buffer){ //write out from buffer
	if(blockSize == 0){
		printf("unkown oblivious data type\n");
		return;
	}
	//printf("data: %d %d %d %d\n", structureId, index, blockSize, ((int*)buffer)[0]);fflush(stdout);
	//printf("data: %d %d %d\n", structureId, index, blockSize);fflush(stdout);

	/*if(structureId == 3 && blockSize > 1) {
		blockSize = 8000000;//temp
		printf("in structure 3");fflush(stdout);
	}*/
	//printf("here! blocksize %d, index %d, structureId %d\n", blockSize, index, structureId);
	memcpy(oblivStructures[structureId]+((long)index*blockSize), buffer, blockSize);
	//printf("here2\n");
	//debug code
	//printf("pointer 1 %p, pointer 2 %p, difference %d\n", oblivStructures[structureId], oblivStructures[structureId]+(index*encBlockSize), (index*encBlockSize));
	//printf("beginning of mac? %d\n", ((Encrypted_Linear_Scan_Block*)(oblivStructures[structureId]+(index*encBlockSize)))->macTag[0]);
}

void ocall_respond( uint8_t* message, size_t message_size, uint8_t* gcm_mac){
	printf("ocall response\n");
}

void ocall_newStructure(int newId, Obliv_Type type, int size){ //this is actual size, the logical size will be smaller for orams
    //printf("app: initializing structure type %d of capacity %d blocks\n", type, size);
    int encBlockSize = getEncBlockSize(type);
    if(type == TYPE_ORAM || type == TYPE_TREE_ORAM) encBlockSize = sizeof(Encrypted_Oram_Bucket);
    //printf("Encrypted blocks of this type get %d bytes of storage\n", encBlockSize);
    oblivStructureSizes[newId] = size;
    oblivStructureTypes[newId] = type;
    long val = (long)encBlockSize*size;
    //printf("mallocing %ld bytes\n", val);
    oblivStructures[newId] = (uint8_t*)malloc(val);
    if(!oblivStructures[newId]) {
    	printf("failed to allocate space (%ld bytes) for structure\n", val);fflush(stdout);
    }
}

void ocall_deleteStructure(int structureId){

	oblivStructureSizes[structureId] = 0;
	oblivStructureTypes[structureId] = 0;
	free(oblivStructures[structureId]); //hold pointers to start of each oblivious data structure
}

void ocall_open_read(int tableSize){
	char tableName[20];
	sprintf(tableName, "testTable%d", tableSize);
	//printf("table's name is %s\n", tableName);fflush(stdout);
	readFile = fopen((char*)tableName, "r");
	//printf("here a function is called\n");fflush(stdout);
}

void ocall_make_name(void *name, int tableSize){
	sprintf((char*)name, "testTable%d", tableSize);
}

void ocall_write_file(const void *src, int dsize, int tableSize){
	char tableName[20];
	sprintf(tableName, "testTable%d", tableSize);
	//int t = 0;
	//memcpy(&t, src, 4);
	//printf("ocall writing %d to a file with %d bytes\n", t, dsize);fflush(stdout);
	FILE *outFile = fopen((char*)tableName, "a");
	fwrite(src, dsize, 1, outFile);
	fclose(outFile);
}

void ocall_read_file(void *dest, int dsize){
	if(readFile == NULL) printf("bad!!\n");
	//printf("b %d\n", dsize);
	int c = fread(dest, dsize, 1, readFile);
	//printf("c %d %d %d\n", c, ferror(readFile), feof(readFile));
	int t = 0;
	memcpy(&t, dest, 4);
	//printf("this funciton prints %d with %d bytes\n", t, dsize);

}

void BDB1(sgx_enclave_id_t enclave_id, int status){
	//block size needs to be 512

	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema rankingsSchema;
	rankingsSchema.numFields = 4;
	rankingsSchema.fieldOffsets[0] = 0;
	rankingsSchema.fieldSizes[0] = 1;
	rankingsSchema.fieldTypes[0] = CHAR;
	rankingsSchema.fieldOffsets[1] = 1;
	rankingsSchema.fieldSizes[1] = 255;
	rankingsSchema.fieldTypes[1] = TINYTEXT;
	rankingsSchema.fieldOffsets[2] = 256;
	rankingsSchema.fieldSizes[2] = 4;
	rankingsSchema.fieldTypes[2] = INTEGER;
	rankingsSchema.fieldOffsets[3] = 260;
	rankingsSchema.fieldSizes[3] = 4;
	rankingsSchema.fieldTypes[3] = INTEGER;

	Condition cond;
	int val = 1000;
	cond.numClauses = 1;
	cond.fieldNums[0] = 2;
	cond.conditionType[0] = 1;
	cond.values[0] = (uint8_t*)malloc(4);
	memcpy(cond.values[0], &val, 4);
	cond.nextCondition = NULL;

	char* tableName = "rankings";
	createTable(enclave_id, (int*)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_TREE_ORAM, 360010, &structureIdIndex);//TODO temp really 360010
	//printTable(enclave_id, (int*)&status, "rankings");

	std::ifstream file("rankings.csv");

	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 360000; i++){//TODO temp really 360000
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 3; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 1 || j == 2){//integer
				int d = 0;
				d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d\n", d);
				memcpy(&row[rankingsSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[rankingsSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//insert the row into the database - index by last sale price
		int indexval = 0;
		memcpy(&indexval, &row[rankingsSchema.fieldOffsets[2]], 4);
		insertRow(enclave_id, (int*)&status, "rankings", row, indexval);
		//if (indexval > 1000) printf("indexval %d \n", indexval);
		//printTable(enclave_id, (int*)&status, "rankings");
	}

	printf("created BDB1 table\n");
	time_t startTime, endTime;
	double elapsedTime;
	//printTable(enclave_id, (int*)&status, "rankings");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "rankings", -1, cond, -1, -1, 2, 1000, INT_MAX);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("BDB1 running time (small): %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "rankings", -1, cond, -1, -1, 3, 1000, INT_MAX);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("BDB1 running time (hash): %.5f\n", elapsedTime);
	printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "rankings");
}

void BDB2(sgx_enclave_id_t enclave_id, int status){
//block size 2048

	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema userdataSchema;
	userdataSchema.numFields = 10;
	userdataSchema.fieldOffsets[0] = 0;
	userdataSchema.fieldSizes[0] = 1;
	userdataSchema.fieldTypes[0] = CHAR;
	userdataSchema.fieldOffsets[1] = 1;
	userdataSchema.fieldSizes[1] = 255;
	userdataSchema.fieldTypes[1] = TINYTEXT;
	userdataSchema.fieldOffsets[2] = 256;
	userdataSchema.fieldSizes[2] = 255;
	userdataSchema.fieldTypes[2] = TINYTEXT;
	userdataSchema.fieldOffsets[3] = 511;
	userdataSchema.fieldSizes[3] = 4;
	userdataSchema.fieldTypes[3] = INTEGER;
	userdataSchema.fieldOffsets[4] = 515;
	userdataSchema.fieldSizes[4] = 4;
	userdataSchema.fieldTypes[4] = INTEGER;
	userdataSchema.fieldOffsets[5] = 519;
	userdataSchema.fieldSizes[5] = 255;
	userdataSchema.fieldTypes[5] = TINYTEXT;
	userdataSchema.fieldOffsets[6] = 774;
	userdataSchema.fieldSizes[6] = 255;
	userdataSchema.fieldTypes[6] = TINYTEXT;
	userdataSchema.fieldOffsets[7] = 1029;
	userdataSchema.fieldSizes[7] = 255;
	userdataSchema.fieldTypes[7] = TINYTEXT;
	userdataSchema.fieldOffsets[8] = 1284;
	userdataSchema.fieldSizes[8] = 255;
	userdataSchema.fieldTypes[8] = TINYTEXT;
	userdataSchema.fieldOffsets[9] = 1539;
	userdataSchema.fieldSizes[9] = 4;
	userdataSchema.fieldTypes[9] = INTEGER;

	Condition cond;
	cond.numClauses = 0;
	cond.nextCondition = NULL;

	char* tableName = "uservisits";
	createTable(enclave_id, (int*)&status, &userdataSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 3510, &structureIdLinear);//TODO temp really 350010


	std::ifstream file2("uservisits.csv");
	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 3500; i++){//TODO temp really 350000
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file2.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 9; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 2 || j == 3 || j == 8){//integer
				int d = 0;
				if(j==3) d = atof(data)*100;
				else d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d ", d);
				memcpy(&row[userdataSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[userdataSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//manually insert into the linear scan structure for speed purposes
		opOneLinearScanBlock(enclave_id, (int*)&status, structureIdLinear, i, (Linear_Scan_Block*)row, 1);
		incrementNumRows(enclave_id, (int*)&status, structureIdLinear);
	}

	printf("created BDB2 table\n");
	time_t startTime, endTime;
	double elapsedTime;
	printTable(enclave_id, (int*)&status, "uservisits");
	startTime = clock();
	selectRows(enclave_id, (int*)&status, "uservisits", 4, cond, 1, 1, -2);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("BDB2 running time: %.5f\n", elapsedTime);
	printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "uservisits");
}

void BDB3(sgx_enclave_id_t enclave_id, int status){

//block size 2048
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureId1 = -1;
	int structureIdIndex2 = -1;
	Schema rankingsSchema;
	rankingsSchema.numFields = 4;
	rankingsSchema.fieldOffsets[0] = 0;
	rankingsSchema.fieldSizes[0] = 1;
	rankingsSchema.fieldTypes[0] = CHAR;
	rankingsSchema.fieldOffsets[1] = 1;
	rankingsSchema.fieldSizes[1] = 255;
	rankingsSchema.fieldTypes[1] = TINYTEXT;
	rankingsSchema.fieldOffsets[2] = 256;
	rankingsSchema.fieldSizes[2] = 4;
	rankingsSchema.fieldTypes[2] = INTEGER;
	rankingsSchema.fieldOffsets[3] = 260;
	rankingsSchema.fieldSizes[3] = 4;
	rankingsSchema.fieldTypes[3] = INTEGER;

	char* tableName = "rankings";
	createTable(enclave_id, (int*)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 360010, &structureId1); //TODO temp really 360010

	std::ifstream file("rankings.csv");

	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 360000; i++){ //TODO temp really 360000
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 3; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 1 || j == 2){//integer
				int d = 0;
				d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d\n", d);
				memcpy(&row[rankingsSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[rankingsSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//manually insert into the linear scan structure for speed purposes
		opOneLinearScanBlock(enclave_id, (int*)&status, structureId1, i, (Linear_Scan_Block*)row, 1);
		incrementNumRows(enclave_id, (int*)&status, structureId1);
	}
	printf("created rankings table\n");

	Schema userdataSchema;
	userdataSchema.numFields = 10;
	userdataSchema.fieldOffsets[0] = 0;
	userdataSchema.fieldSizes[0] = 1;
	userdataSchema.fieldTypes[0] = CHAR;
	userdataSchema.fieldOffsets[1] = 1;
	userdataSchema.fieldSizes[1] = 255;
	userdataSchema.fieldTypes[1] = TINYTEXT;
	userdataSchema.fieldOffsets[2] = 256;
	userdataSchema.fieldSizes[2] = 255;
	userdataSchema.fieldTypes[2] = TINYTEXT;
	userdataSchema.fieldOffsets[3] = 511;
	userdataSchema.fieldSizes[3] = 4;
	userdataSchema.fieldTypes[3] = INTEGER;
	userdataSchema.fieldOffsets[4] = 515;
	userdataSchema.fieldSizes[4] = 4;
	userdataSchema.fieldTypes[4] = INTEGER;
	userdataSchema.fieldOffsets[5] = 519;
	userdataSchema.fieldSizes[5] = 255;
	userdataSchema.fieldTypes[5] = TINYTEXT;
	userdataSchema.fieldOffsets[6] = 774;
	userdataSchema.fieldSizes[6] = 255;
	userdataSchema.fieldTypes[6] = TINYTEXT;
	userdataSchema.fieldOffsets[7] = 1029;
	userdataSchema.fieldSizes[7] = 255;
	userdataSchema.fieldTypes[7] = TINYTEXT;
	userdataSchema.fieldOffsets[8] = 1284;
	userdataSchema.fieldSizes[8] = 255;
	userdataSchema.fieldTypes[8] = TINYTEXT;
	userdataSchema.fieldOffsets[9] = 1539;
	userdataSchema.fieldSizes[9] = 4;
	userdataSchema.fieldTypes[9] = INTEGER;

	char* tableName2 = "uservisits";
	createTable(enclave_id, (int*)&status, &userdataSchema, tableName2, strlen(tableName2), TYPE_TREE_ORAM, 15510, &structureIdIndex2); //TODO temp really 350010

	std::ifstream file2("uservisits.csv");

	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 15500; i++){//TODO temp really 350000
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file2.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 9; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 2 || j == 3 || j == 8){//integer
				int d = 0;
				if(j==3) d = atof(data)*100;
				else d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d ", d);
				memcpy(&row[userdataSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[userdataSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//insert the row into the database - index by visit date
		int indexval = 0;
		memcpy(&indexval, &row[userdataSchema.fieldOffsets[3]], 4);
		//printf("indexval: %d\n", indexval);
		insertRow(enclave_id, (int*)&status, "uservisits", row, indexval);
	}

	printf("created uservisits table\n");
	time_t startTime, endTime;
	double elapsedTime;

	Condition cond1, cond2;
	int l = 19800100, h = 19800402;
	cond1.numClauses = 1;
	cond1.fieldNums[0] = 3;
	cond1.conditionType[0] = 1;
	cond1.values[0] = (uint8_t*)malloc(4);
	memcpy(cond1.values[0], &l, 4);
	cond1.nextCondition = &cond2;
	cond2.numClauses = 1;
	cond2.fieldNums[0] = 3;
	cond2.conditionType[0] = 2;
	cond2.values[0] = (uint8_t*)malloc(4);
	memcpy(cond2.values[0], &h, 4);
	cond2.nextCondition = NULL;
	Condition noCond;
	noCond.numClauses = 0;
	noCond.nextCondition = NULL;

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "uservisits", -1, cond1, -1, -1, 2, l, h);
	renameTable(enclave_id, (int*)&status, "ReturnTable", "uvJ");
	//printTable(enclave_id, (int*)&status, "uvJ");
	joinTables(enclave_id, (int*)&status, "rankings", "uvJ", 1, 2, -1, -1);
	//int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey) {//put the smaller table first for
	renameTable(enclave_id, (int*)&status, "JoinReturn", "jr");
	selectRows(enclave_id, (int*)&status, "jr", 2, noCond, 4, 4, 6);
	renameTable(enclave_id, (int*)&status, "ReturnTable", "last");
	//printTable(enclave_id, (int*)&status, "last");
	selectRows(enclave_id, (int*)&status, "last", 2, noCond, 3, -1, 0);
	//select from index
	//join
	//fancy group by
	//select max
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("BDB3 running time: %.5f\n", elapsedTime);
	printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "uservisits");
    deleteTable(enclave_id, (int*)&status, "rankings");

}



void flightTables(sgx_enclave_id_t enclave_id, int status){
	//block data size can be shrunk as low as 32 for this test
//create a linear scan table and an index for the flight test data. Index the data by price
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema flightSchema;
	flightSchema.numFields = 8;
	flightSchema.fieldOffsets[0] = 0;
	flightSchema.fieldSizes[0] = 1;
	flightSchema.fieldTypes[0] = CHAR;
	flightSchema.fieldOffsets[1] = 1;
	flightSchema.fieldSizes[1] = 4;
	flightSchema.fieldTypes[1] = INTEGER;
	flightSchema.fieldOffsets[2] = 5;
	flightSchema.fieldSizes[2] = 4;
	flightSchema.fieldTypes[2] = INTEGER;
	flightSchema.fieldOffsets[3] = 9;
	flightSchema.fieldSizes[3] = 4;
	flightSchema.fieldTypes[3] = INTEGER;
	flightSchema.fieldOffsets[4] = 13;
	flightSchema.fieldSizes[4] = 4;
	flightSchema.fieldTypes[4] = INTEGER;
	flightSchema.fieldOffsets[5] = 17;
	flightSchema.fieldSizes[5] = 4;
	flightSchema.fieldTypes[5] = INTEGER;
	flightSchema.fieldOffsets[6] = 21;
	flightSchema.fieldSizes[6] = 4;
	flightSchema.fieldTypes[6] = INTEGER;
	flightSchema.fieldOffsets[7] = 25;
	flightSchema.fieldSizes[7] = 4;
	flightSchema.fieldTypes[7] = INTEGER;

	Condition cond0;
	int val = 12173;
	cond0.numClauses = 1;
	cond0.fieldNums[0] = 2;
	cond0.conditionType[0] = 0;
	cond0.values[0] = (uint8_t*)malloc(4);
	memcpy(cond0.values[0], &val, 4);
	cond0.nextCondition = NULL;

	char* tableNameIndex = "flightTableIndex";
	char* tableNameLinear = "flightTableLinear";

//	createTable(enclave_id, (int*)&status, &flightSchema, tableNameIndex, strlen(tableNameIndex), TYPE_TREE_ORAM, 1010, &structureIdIndex);
//	createTable(enclave_id, (int*)&status, &flightSchema, tableNameLinear, strlen(tableNameLinear), TYPE_LINEAR_SCAN, 1010, &structureIdLinear);
	createTable(enclave_id, (int*)&status, &flightSchema, tableNameIndex, strlen(tableNameIndex), TYPE_TREE_ORAM, 250010, &structureIdIndex);
	createTable(enclave_id, (int*)&status, &flightSchema, tableNameLinear, strlen(tableNameLinear), TYPE_LINEAR_SCAN, 250010, &structureIdLinear);

	std::ifstream file("flight_data_small.csv"); //eclipse doesn't like this line, but it compiles fine

	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 250000; i++){
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 7; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			int d = 0;
			d = atoi(data);
			//printf("data: %s\n", data);
			//printf("d %d\n", d);
			memcpy(&row[flightSchema.fieldOffsets[j+1]], &d, 4);
		}
		//insert the row into the database - index by last sale price
		int indexval = 0;
		memcpy(&indexval, &row[flightSchema.fieldOffsets[2]], 4);
		insertRow(enclave_id, (int*)&status, "flightTableIndex", row, indexval);
		//manually insert into the linear scan structure for speed purposes
		opOneLinearScanBlock(enclave_id, (int*)&status, structureIdLinear, i, (Linear_Scan_Block*)row, 1);
		incrementNumRows(enclave_id, (int*)&status, structureIdLinear);
	}

	//printTable(enclave_id, (int*)&status, "flightTableLinear");
	//now run the query and time it
	printf("created flight tables\n");
	time_t startTime, endTime;
	double elapsedTime;

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "flightTableLinear", 6, cond0, 4, 1, -1);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time small: %.5f\n", elapsedTime);
	printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "flightTableIndex", 6, cond0, 4, 1, -1, val-1, val);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 index running time hash: %.5f\n", elapsedTime);
	printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "flightTableLinear", 6, cond0, -1, -1, 2);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "flightTableLinear", 6, cond0, -1, -1, 3);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	selectRows(enclave_id, (int*)&status, "flightTableLinear", 6, cond0, -1, -1, 4);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time almost all: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "flightTableIndex", 6, cond0, -1, -1, 2, val-1, val);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 index running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
	getNumRows(enclave_id, (int*)&status, 2);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "flightTableIndex", 6, cond0, -1, -1, 3, val-1, val);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 index running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
	getNumRows(enclave_id, (int*)&status, 2);
	printf("number of rows selected: %d", (int)status);fflush(stdout);//this is a hack, ReturnTable should be in position 2
    deleteTable(enclave_id, (int*)&status, "ReturnTable");


    deleteTable(enclave_id, (int*)&status, "flightTableLinear");
    deleteTable(enclave_id, (int*)&status, "flightTableIndex");

}

void complaintTables(sgx_enclave_id_t enclave_id, int status){
	//will need to increase block size to 4096 to run this test
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema compSchema;
	compSchema.numFields = 14;
	compSchema.fieldOffsets[0] = 0;
	compSchema.fieldSizes[0] = 1;
	compSchema.fieldTypes[0] = CHAR;
	compSchema.fieldOffsets[1] = 1;
	compSchema.fieldSizes[1] = 4;
	compSchema.fieldTypes[1] = INTEGER;
	compSchema.fieldOffsets[2] = 5;
	compSchema.fieldSizes[2] = 255;
	compSchema.fieldTypes[2] = TINYTEXT;
	compSchema.fieldOffsets[3] = 260;
	compSchema.fieldSizes[3] = 255;
	compSchema.fieldTypes[3] = TINYTEXT;
	compSchema.fieldOffsets[4] = 515;
	compSchema.fieldSizes[4] = 255;
	compSchema.fieldTypes[4] = TINYTEXT;
	compSchema.fieldOffsets[5] = 770;
	compSchema.fieldSizes[5] = 4;
	compSchema.fieldTypes[5] = INTEGER;
	compSchema.fieldOffsets[6] = 774;
	compSchema.fieldSizes[6] = 255;
	compSchema.fieldTypes[6] = TINYTEXT;
	compSchema.fieldOffsets[7] = 1029;
	compSchema.fieldSizes[7] = 4;
	compSchema.fieldTypes[7] = INTEGER;
	compSchema.fieldOffsets[8] = 1033;
	compSchema.fieldSizes[8] = 4;
	compSchema.fieldTypes[8] = INTEGER;
	compSchema.fieldOffsets[9] = 1037;
	compSchema.fieldSizes[9] = 255;
	compSchema.fieldTypes[9] = TINYTEXT;
	compSchema.fieldOffsets[10] = 1292;
	compSchema.fieldSizes[10] = 255;
	compSchema.fieldTypes[10] = TINYTEXT;
	compSchema.fieldOffsets[11] = 1547;
	compSchema.fieldSizes[11] = 255;
	compSchema.fieldTypes[11] = TINYTEXT;
	compSchema.fieldOffsets[12] = 1802;
	compSchema.fieldSizes[12] = 255;
	compSchema.fieldTypes[12] = TINYTEXT;
	compSchema.fieldOffsets[13] = 2057;
	compSchema.fieldSizes[13] = 4;
	compSchema.fieldTypes[13] = INTEGER;


printf("here\n");fflush(stdout);
	Condition cond0, cond1, cond2, cond3, cond4, condNone;
	char* negative = "No";
	char* ccc = "Credit Card";
	char* mmm = "Mortgage";
	char* bank = "Bank of America";
	cond0.numClauses = 1;
	cond0.fieldNums[0] = 11;
	cond0.conditionType[0] = 0;
	cond0.values[0] = (uint8_t*)malloc(strlen(negative)+1);
	strcpy((char*)cond0.values[0], negative);
	cond0.nextCondition = &cond1;
	cond1.numClauses = 2;
	cond1.fieldNums[0] = 2;
	cond1.fieldNums[1] = 2;
	cond1.conditionType[0] = 0;
	cond1.conditionType[1] = 0;
	cond1.values[0] = (uint8_t*)malloc(strlen(ccc)+1);
	cond1.values[1] = (uint8_t*)malloc(strlen(mmm)+1);
	strcpy((char*)cond1.values[0], ccc);
	strcpy((char*)cond1.values[1], mmm);
	cond1.nextCondition = &cond4;
	cond2.numClauses = 1;
	cond2.fieldNums[0] = 7;
	cond2.conditionType[0] = 1;
	int l = 20130500, h = 20130532;
	cond2.values[0] = (uint8_t*)malloc(4);
	memcpy(cond2.values[0], &l, 4);
	cond2.nextCondition = &cond3;
	cond3.numClauses = 1;
	cond3.fieldNums[0] = 7;
	cond3.conditionType[0] = -1;
	cond3.values[0] = (uint8_t*)malloc(4);
	memcpy(cond3.values[0], &h, 4);
	cond3.nextCondition = NULL;
	cond4.numClauses = 1;
	cond4.fieldNums[0] = 9;
	cond4.conditionType[0] = 0;
	cond4.values[0] = (uint8_t*)malloc(strlen(bank)+1);
	strcpy((char*)cond4.values[0], bank);
	cond4.nextCondition = &cond2;

	char* tableNameIndex = "compTableIndex";
	char* tableNameLinear = "compTableLinear";

printf("here\n");fflush(stdout);
	createTable(enclave_id, (int*)&status, &compSchema, tableNameIndex, strlen(tableNameIndex), TYPE_TREE_ORAM, 107000, &structureIdIndex);
	createTable(enclave_id, (int*)&status, &compSchema, tableNameLinear, strlen(tableNameLinear), TYPE_LINEAR_SCAN, 107000, &structureIdLinear);
	//createTable(enclave_id, (int*)&status, &compSchema, tableNameIndex, strlen(tableNameIndex), TYPE_TREE_ORAM, 1010, &structureIdIndex);
printf("here\n");fflush(stdout);
	//createTable(enclave_id, (int*)&status, &compSchema, tableNameLinear, strlen(tableNameLinear), TYPE_LINEAR_SCAN, 1010, &structureIdLinear);

	std::ifstream file("cfpb_consumer_complaints.csv");

	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
printf("here\n");fflush(stdout);
	for(int i = 0; i < 106427; i++){
	//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 13; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 0 || j== 4 || j == 6 || j == 7 || j == 12){//integer
				int d = 0;
				d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d\n", d);
				memcpy(&row[compSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[compSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//insert the row into the database - index by last sale price
		int indexval = 0;
		memcpy(&indexval, &row[compSchema.fieldOffsets[7]], 4);
		insertRow(enclave_id, (int*)&status, "compTableIndex", row, indexval);
		//manually insert into the linear scan structure for speed purposes
		opOneLinearScanBlock(enclave_id, (int*)&status, structureIdLinear, i, (Linear_Scan_Block*)row, 1);
		incrementNumRows(enclave_id, (int*)&status, structureIdLinear);
	}

	//printTable(enclave_id, (int*)&status, "compTableLinear");
	//now run the query and time it
	printf("created complaint tables\n");
	time_t startTime, endTime;
	double elapsedTime;

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", 1, cond0, 0, -1, 2);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", 1, cond0, 0, -1, 3);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", 1, cond0, 0, -1, 4);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time almostAll: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "compTableIndex", 1, cond0, 0, -1, 2, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 index running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "compTableIndex", 1, cond0, 0, -1, 3, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 index running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    l = 20130505;
    h = 20130510;

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", -1, cond2, -1, -1, 2);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", -1, cond2, -1, -1, 3);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	selectRows(enclave_id, (int*)&status, "compTableLinear", -1, cond2, -1, -1, 4);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time almost all: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "compTableIndex", -1, cond2, -1, -1, 2, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 index running time small: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "compTableIndex", -1, cond2, -1, -1, 3, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 index running time hash: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
	getNumRows(enclave_id, (int*)&status, 2);
	printf("number of rows selected: %d", (int)status);//this is a hack, ReturnTable should be in position 2
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "compTableLinear");
    deleteTable(enclave_id, (int*)&status, "compTableIndex");

}

void nasdaqTables(sgx_enclave_id_t enclave_id, int status){
	//block data size must be at least 2048 here
//create a linear scan table and an index for the flight test data. Index the data by the destination city
	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema nasSchema;
	nasSchema.numFields = 11;
	nasSchema.fieldOffsets[0] = 0;
	nasSchema.fieldSizes[0] = 1;
	nasSchema.fieldTypes[0] = CHAR;
	nasSchema.fieldOffsets[1] = 1;
	nasSchema.fieldSizes[1] = 255;
	nasSchema.fieldTypes[1] = TINYTEXT;
	nasSchema.fieldOffsets[2] = 256;
	nasSchema.fieldSizes[2] = 255;
	nasSchema.fieldTypes[2] = TINYTEXT;
	nasSchema.fieldOffsets[3] = 511;
	nasSchema.fieldSizes[3] = 4;
	nasSchema.fieldTypes[3] = INTEGER;
	nasSchema.fieldOffsets[4] = 515;
	nasSchema.fieldSizes[4] = 4;
	nasSchema.fieldTypes[4] = INTEGER;
	nasSchema.fieldOffsets[5] = 519;
	nasSchema.fieldSizes[5] = 255;
	nasSchema.fieldTypes[5] = TINYTEXT;
	nasSchema.fieldOffsets[6] = 774;
	nasSchema.fieldSizes[6] = 255;
	nasSchema.fieldTypes[6] = TINYTEXT;
	nasSchema.fieldOffsets[7] = 1029;
	nasSchema.fieldSizes[7] = 255;
	nasSchema.fieldTypes[7] = TINYTEXT;
	nasSchema.fieldOffsets[8] = 1284;
	nasSchema.fieldSizes[8] = 255;
	nasSchema.fieldTypes[8] = TINYTEXT;
	nasSchema.fieldOffsets[9] = 1539;
	nasSchema.fieldSizes[9] = 255;
	nasSchema.fieldTypes[9] = TINYTEXT;
	nasSchema.fieldOffsets[10] = 1794;
	nasSchema.fieldSizes[10] = 4;
	nasSchema.fieldTypes[10] = INTEGER;

	Condition cond1, cond2, cond3, condNone;
	char* sector = "Technology";
	cond1.numClauses = 1;
	cond1.fieldNums[0] = 7;
	cond1.conditionType[0] = 0;
	cond1.values[0] = (uint8_t*)malloc(strlen(sector)+1);
	strcpy((char*)cond1.values[0], sector);
	cond1.nextCondition = &cond2;
	cond2.numClauses = 1;
	cond2.fieldNums[0] = 3;
	cond2.conditionType[0] = 1;
	int l = 100, h = 200;
	cond2.values[0] = (uint8_t*)malloc(4);
	memcpy(cond2.values[0], &l, 4);
	cond2.nextCondition = &cond3;
	cond3.numClauses = 1;
	cond3.fieldNums[0] = 3;
	cond3.conditionType[0] = -1;
	cond3.values[0] = (uint8_t*)malloc(4);
	memcpy(cond3.values[0], &h, 4);
	cond3.nextCondition = NULL;
	condNone.numClauses = 0;
	condNone.nextCondition = NULL;

	char* tableNameIndex = "nasTableIndex";
	char* tableNameLinear = "nasTableLinear";

	int s = createTable(enclave_id, (int*)&status, &nasSchema, tableNameIndex, strlen(tableNameIndex), TYPE_TREE_ORAM, 3300, &structureIdIndex);
	createTable(enclave_id, (int*)&status, &nasSchema, tableNameLinear, strlen(tableNameLinear), TYPE_LINEAR_SCAN, 3300, &structureIdLinear);

	printf("status %d\n", s);

	std::ifstream file("nasdaq_data.csv"); //eclipse doesn't like this line, but it compiles fine

	char line[BLOCK_DATA_SIZE];//make this big just in case
	char data[BLOCK_DATA_SIZE];
	file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for(int i = 0; i < 3209; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE);//get the field

		std::istringstream ss(line);
		for(int j = 0; j < 10; j++){
			if(!ss.getline(data, BLOCK_DATA_SIZE, ',')){
				break;
			}
			//printf("data: %s\n", data);
			if(j == 2 || j== 3 || j == 9){//integer
				int d = 0;
				d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d\n", d);
				memcpy(&row[nasSchema.fieldOffsets[j+1]], &d, 4);
			}
			else{//tinytext
				strncpy((char*)&row[nasSchema.fieldOffsets[j+1]], data, strlen(data)+1);
			}
		}
		//insert the row into the database - index by last sale price
		insertRow(enclave_id, (int*)&status, "nasTableIndex", row, row[nasSchema.fieldOffsets[3]]);
		//manually insert into the linear scan structure for speed purposes
		opOneLinearScanBlock(enclave_id, (int*)&status, structureIdLinear, i, (Linear_Scan_Block*)row, 1);
		incrementNumRows(enclave_id, (int*)&status, structureIdLinear);
	}

	//printTable(enclave_id, (int*)&status, "nasTableLinear");
	//now run the query and time it
	printf("created nasdaq tables\n");
	time_t startTime, endTime;
	double elapsedTime;

	//startTime = clock();
	//selectRows(enclave_id, (int*)&status, "nasTableLinear", 1, cond1, -1, -1, 1);
	//endTime = clock();
	//elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	//printf("query 1 linear running time cont: %.5f\n", elapsedTime);
    //deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "nasTableLinear", 1, cond1, -1, -1, 2);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time small: %.5f\n", elapsedTime);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "nasTableLinear", 1, cond1, -1, -1, 3);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time hash: %.5f\n", elapsedTime);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "nasTableLinear", 1, cond1, -1, -1, 4);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 linear running time almostAll: %.5f\n", elapsedTime);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");


	//startTime = clock();
	//indexSelect(enclave_id, (int*)&status, "nasTableIndex", 1, cond1, -1, -1, 1, l, h);
	//endTime = clock();
	//elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	//printf("query 1 index running time cont: %.5f\n", elapsedTime);
    //deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "nasTableIndex", 1, cond1, -1, -1, 2, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 index running time small: %.5f\n", elapsedTime);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "nasTableIndex", 1, cond1, -1, -1, 3, l, h);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 1 index running time hash: %.5f\n", elapsedTime);
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	selectRows(enclave_id, (int*)&status, "nasTableLinear", 3, condNone, 0, 7, -1);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 linear running time: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

	startTime = clock();
	indexSelect(enclave_id, (int*)&status, "nasTableIndex", 3, condNone, 0, 7, -1, -1, 100000);
	endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
	printf("query 2 index running time: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
    deleteTable(enclave_id, (int*)&status, "ReturnTable");

    deleteTable(enclave_id, (int*)&status, "nasTableLinear");
    deleteTable(enclave_id, (int*)&status, "nasTableIndex");
}

//helpers


/*
 * End Saba's code
 * */


// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x
int main(int argc, char* argv[])
{
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    sgx_enclave_id_t enclave_id = 0;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t* p_msg3_full = NULL;

    int32_t verify_index = -1;
    int32_t verification_samples = sizeof(msg1_samples)/sizeof(msg1_samples[0]);

    FILE* OUTPUT = stdout;

#define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && \
                                       verify_index <= verification_samples)
#define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

    if(argc > 1)
    {

        verify_index = atoi(argv[1]);

        if( VERIFICATION_INDEX_IS_VALID())
        {
            //fprintf(OUTPUT, "\nVerifying precomputed attestation messages "
            //                "using precomputed values# %d\n", verify_index);
        }
        else
        {
            fprintf(OUTPUT, "\nValid invocations are:\n");
            fprintf(OUTPUT, "\n\tisv_app\n");
            fprintf(OUTPUT, "\n\tisv_app <verification index>\n");
            fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
                    verification_samples);
            fprintf(OUTPUT, "\nUsing a verification index uses precomputed "
                    "messages to assist debugging the remote attestation "
                    "service provider.\n");
            return -1;
        }
    }

    // Preparation for remote attestation by configuring extended epid group id.
    {
        uint32_t extended_epid_group_id = 0;
        ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
                __FUNCTION__);
            return ret;
        }
        fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

        p_msg0_full = (ra_samp_request_header_t*)
            malloc(sizeof(ra_samp_request_header_t)
            +sizeof(uint32_t));
        if (NULL == p_msg0_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg0_full->type = TYPE_RA_MSG0;
        p_msg0_full->size = sizeof(uint32_t);

        *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
        {

            //fprintf(OUTPUT, "\nMSG0 body generated -\n");

            //PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

        }
        // The ISV application sends msg0 to the SP.
        // The ISV decides whether to support this extended epid group id.
        //fprintf(OUTPUT, "\nSending msg0 to remote attestation service provider.\n");

        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
            p_msg0_full,
            &p_msg0_resp_full);
        if (ret != 0)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
                "[%s].", __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");
    }
    // Remote attestation will be initiated the ISV server challenges the ISV
    // app or if the ISV app detects it doesn't have the credentials
    // (shared secret) from a previous attestation required for secure
    // communication with the server.
    {
        // ISV application creates the ISV enclave.
        int launch_token_update = 0;
        sgx_launch_token_t launch_token = {0};
        memset(&launch_token, 0, sizeof(sgx_launch_token_t));
        do
        {
            ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                     SGX_DEBUG_FLAG,
                                     &launch_token,
                                     &launch_token_update,
                                     &enclave_id, NULL);
            if(SGX_SUCCESS != ret)
            {
                ret = -1;
                fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                        __FUNCTION__);
                goto CLEANUP;
            }
            fprintf(OUTPUT, "\nCall sgx_create_enclave success.");

            ret = enclave_init_ra(enclave_id,
                                  &status,
                                  false,
                                  &context);
        //Ideally, this check would be around the full attestation flow.
        } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "\nCall enclave_init_ra success.");

        // isv application call uke sgx_ra_get_msg1
        p_msg1_full = (ra_samp_request_header_t*)
                      malloc(sizeof(ra_samp_request_header_t)
                             + sizeof(sgx_ra_msg1_t));
        if(NULL == p_msg1_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg1_full->type = TYPE_RA_MSG1;
        p_msg1_full->size = sizeof(sgx_ra_msg1_t);
        do
        {
            ret = sgx_ra_get_msg1(context, enclave_id, sgx_ra_get_ga,
                                  (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                                  + sizeof(ra_samp_request_header_t)));
            sleep(3); // Wait 3s between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
        if(SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            //fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

            //fprintf(OUTPUT, "\nMSG1 body generated -\n");

            //PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

        }

        if(VERIFICATION_INDEX_IS_VALID())
        {

            memcpy_s(p_msg1_full->body, p_msg1_full->size,
                     msg1_samples[GET_VERIFICATION_ARRAY_INDEX()],
                     p_msg1_full->size);

            fprintf(OUTPUT, "\nInstead of using the recently generated MSG1, "
                            "we will use the following precomputed MSG1 -\n");

            //PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
        }


        // The ISV application sends msg1 to the SP to get msg2,
        // msg2 needs to be freed when no longer needed.
        // The ISV decides whether to use linkable or unlinkable signatures.
        //fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider."
          //              "Expecting msg2 back.\n");


        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg1_full,
                                      &p_msg2_full);

        if(ret != 0 || !p_msg2_full)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
                            "[%s].", __FUNCTION__);
            if(VERIFICATION_INDEX_IS_VALID())
            {
                fprintf(OUTPUT, "\nBecause we are in verification mode we will "
                                "ignore this error.\n");
                fprintf(OUTPUT, "\nInstead, we will pretend we received the "
                                "following MSG2 - \n");

                SAFE_FREE(p_msg2_full);
                ra_samp_response_header_t* precomputed_msg2 =
                    (ra_samp_response_header_t*)msg2_samples[
                        GET_VERIFICATION_ARRAY_INDEX()];
                const size_t msg2_full_size = sizeof(ra_samp_response_header_t)
                                              +  precomputed_msg2->size;
                p_msg2_full =
                    (ra_samp_response_header_t*)malloc(msg2_full_size);
                if(NULL == p_msg2_full)
                {
                    ret = -1;
                    goto CLEANUP;
                }
                memcpy_s(p_msg2_full, msg2_full_size, precomputed_msg2,
                         msg2_full_size);

                //PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                //                 sizeof(ra_samp_response_header_t)
                //                 + p_msg2_full->size);
            }
            else
            {
                goto CLEANUP;
            }
        }
        else
        {
            // Successfully sent msg1 and received a msg2 back.
            // Time now to check msg2.
            if(TYPE_RA_MSG2 != p_msg2_full->type)
            {

                fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                                "[%s].", __FUNCTION__);

                if(VERIFICATION_INDEX_IS_VALID())
                {
                    fprintf(OUTPUT, "\nBecause we are in verification mode we "
                                    "will ignore this error.");
                }
                else
                {
                    goto CLEANUP;
                }
            }

            //fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
            //                "provider. Received the following MSG2:\n");
            //PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
             //                sizeof(ra_samp_response_header_t)
              //               + p_msg2_full->size);

            //fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
            //PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

            if( VERIFICATION_INDEX_IS_VALID() )
            {
                // The response should match the precomputed MSG2:
                ra_samp_response_header_t* precomputed_msg2 =
                    (ra_samp_response_header_t *)
                    msg2_samples[GET_VERIFICATION_ARRAY_INDEX()];
                if(memcmp( precomputed_msg2, p_msg2_full,
                   sizeof(ra_samp_response_header_t) + p_msg2_full->size))
                {/*
                    fprintf(OUTPUT, "\nVerification ERROR. Our precomputed "
                                    "value for MSG2 does NOT match.\n");
                    fprintf(OUTPUT, "\nPrecomputed value for MSG2:\n");
                    PRINT_BYTE_ARRAY(OUTPUT, precomputed_msg2,
                                     sizeof(ra_samp_response_header_t)
                                     + precomputed_msg2->size);
                    fprintf(OUTPUT, "\nA more descriptive representation "
                                    "of precomputed value for MSG2:\n");
                    PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT,
                                                       precomputed_msg2);*/
                }
                else
                {
                    fprintf(OUTPUT, "\nVerification COMPLETE. Remote "
                                    "attestation service provider generated a "
                                    "matching MSG2.\n");
                }
            }

        }

        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                      + sizeof(ra_samp_response_header_t));


        uint32_t msg3_size = 0;
        if( VERIFICATION_INDEX_IS_VALID())
        {
            // We cannot generate a valid MSG3 using the precomputed messages
            // we have been using. We will use the precomputed msg3 instead.
            msg3_size = MSG3_BODY_SIZE;
            p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
            if(NULL == p_msg3)
            {
                ret = -1;
                goto CLEANUP;
            }
            memcpy_s(p_msg3, msg3_size,
                     msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
            fprintf(OUTPUT, "\nBecause MSG1 was a precomputed value, the MSG3 "
                            "we use will also be. PRECOMPUTED MSG3 - \n");
        }
        else
        {
            busy_retry_time = 2;
            // The ISV app now calls uKE sgx_ra_proc_msg2,
            // The ISV app is responsible for freeing the returned p_msg3!!
            do
            {
                ret = sgx_ra_proc_msg2(context,
                                   enclave_id,
                                   sgx_ra_proc_msg2_trusted,
                                   sgx_ra_get_msg3_trusted,
                                   p_msg2_body,
                                   p_msg2_full->size,
                                   &p_msg3,
                                   &msg3_size);
            } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
            if(!p_msg3)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            if(SGX_SUCCESS != (sgx_status_t)ret)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "ret = 0x%08x [%s].", ret, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            else
            {
                fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
                fprintf(OUTPUT, "\nMSG3 - \n");
            }
        }

        //PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

        p_msg3_full = (ra_samp_request_header_t*)malloc(
                       sizeof(ra_samp_request_header_t) + msg3_size);
        if(NULL == p_msg3_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg3_full->type = TYPE_RA_MSG3;
        p_msg3_full->size = msg3_size;
        if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
        {
            fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
                    __FUNCTION__);
            ret = -1;
            goto CLEANUP;
        }

        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg3_full,
                                      &p_att_result_msg_full);
        if(ret || !p_att_result_msg_full)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
            goto CLEANUP;
        }


        sample_ra_att_result_msg_t * p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));
        if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].", p_att_result_msg_full->type,
                             __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation "
                            "result message back\n.");
            if( VERIFICATION_INDEX_IS_VALID() )
            {
                if(memcmp(p_att_result_msg_full->body,
                        attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
                        p_att_result_msg_full->size) )
                {
                    fprintf(OUTPUT, "\nSent MSG3 successfully. Received an "
                                    "attestation result message back that did "
                                    "NOT match the expected value.\n");
                    fprintf(OUTPUT, "\nEXPECTED ATTESTATION RESULT -");
                    PRINT_BYTE_ARRAY(OUTPUT,
                        attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()],
                        p_att_result_msg_full->size);
                }
            }
        }

        fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
        //PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
        //                 p_att_result_msg_full->size);


        if( VERIFICATION_INDEX_IS_VALID() )
        {
            fprintf(OUTPUT, "\nBecause we used precomputed values for the "
                            "messages, the attestation result message will "
                            "not pass further verification tests, so we will "
                            "skip them.\n");
            goto CLEANUP;
        }

        // Check the MAC using MK on the attestation result message.
        // The format of the attestation result message is ISV specific.
        // This is a simple form for demonstration. In a real product,
        // the ISV may want to communicate more information.
        ret = verify_att_result_mac(enclave_id,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                            "message MK based cmac failed in [%s].",
                            __FUNCTION__);
            goto CLEANUP;
        }

        bool attestation_passed = true;
        // Check the attestation result for pass or fail.
        // Whether attestation passes or fails is a decision made by the ISV Server.
        // When the ISV server decides to trust the enclave, then it will return success.
        // When the ISV server decided to not trust the enclave, then it will return failure.
        if(0 != p_att_result_msg_full->status[0]
           || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                            "failed in [%s].", __FUNCTION__);
            attestation_passed = false;
        }

        // The attestation result message should contain a field for the Platform
        // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
        // It is not returned in all cases, but when it is, the ISV app
        // should pass it to the blob analysis API called sgx_report_attestation_status()
        // along with the trust decision from the ISV server.
        // The ISV application will take action based on the update_info.
        // returned in update_info by the API.  
        // This call is stubbed out for the sample.
        // 
        // sgx_update_info_bit_t update_info;
        // ret = sgx_report_attestation_status(
        //     &p_att_result_msg_body->platform_info_blob,
        //     attestation_passed ? 0 : 1, &update_info);

        // Get the shared secret sent by the server using SK (if attestation
        // passed)
        if(attestation_passed)
        {
            ret = put_secret_data(enclave_id,
                                  &status,
                                  context,
                                  p_att_result_msg_body->secret.payload,
                                  p_att_result_msg_body->secret.payload_size,
                                  p_att_result_msg_body->secret.payload_tag);
            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
            {
                fprintf(OUTPUT, "\nError, attestation result message secret "
                                "using SK based AESGCM failed in [%s]. ret = "
                                "0x%0x. status = 0x%0x", __FUNCTION__, ret,
                                 status);
                goto CLEANUP;
            }
        }
        fprintf(OUTPUT, "\nSecret successfully received from server.");
        fprintf(OUTPUT, "\nRemote attestation success!");
    }

    //TODO: My untrusted application code goes here
    /*
     *
     *
     *Begin Saba's Code
     *
     *
	*/
    {
    	//free stuff used before
    	ra_free_network_response_buffer(p_msg0_resp_full);
    	ra_free_network_response_buffer(p_msg2_full);
    	ra_free_network_response_buffer(p_att_result_msg_full);

    	    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    	SAFE_FREE(p_msg3);
    	SAFE_FREE(p_msg3_full);
    	SAFE_FREE(p_msg1_full);
    	SAFE_FREE(p_msg0_full);


    	total_init(enclave_id, &status);
        if(status != SGX_SUCCESS){
        	printf("key initialization failed %d.\n", status);
        	goto CLEANUP;
        }

    	//trigger oram initialization
    	ra_samp_response_header_t *oramInitMsg_resp = NULL;
        ra_samp_request_header_t* p_oramInitMsg = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t));
        if (NULL == p_oramInitMsg)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_oramInitMsg->type = TYPE_TREE_ORAM_INIT;
        p_oramInitMsg->size = 0;
        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
            p_oramInitMsg,
            &oramInitMsg_resp);
        if (ret != 0)
        {
            //fprintf(OUTPUT, "\nError, ra_network_send_receive for oramInitMsg failed "
             //   "[%s].", __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "\nSent oram init to remote attestation service.\n");

        //now use the request in oramInitMsg to initialize oram

        unsigned int *oramCapacity = (unsigned int*)malloc(sizeof(int));
        memcpy(oramCapacity, oramInitMsg_resp->body, sizeof(int));


        //real world query tests

        //nasdaqTables(enclave_id, status); //2048
        //complaintTables(enclave_id, status); //4096
        //flightTables(enclave_id, status); //256
        //BDB1(enclave_id, status);//512
        BDB2(enclave_id, status);//2048
        //BDB3(enclave_id, status);//2048

        /*
        //rename test
        createTestTable(enclave_id, (int*)&status, "table1", 10);
        printTable(enclave_id, (int*)&status, "table1");
        char* newName = "t2";
        renameTable(enclave_id, (int*)&status, "table1", newName);
        printTable(enclave_id, (int*)&status, "t2");
*/

        //Tests for database functionalities here
/*
        Condition condition1, condition2, condition3, noCondition, gapCond1, gapCond2;
        char a = 'a', b = 'b', c='c';
        int low = 1, high = 900, lowPlusOne = 2;
        condition1.numClauses = 2;
        condition1.fieldNums[0] = 3;
        condition1.fieldNums[1] = 3;
        condition1.conditionType[0] = 0;
        condition1.conditionType[1] = 0;
        condition1.values[0] = (uint8_t*)&a;
        condition1.values[1] = (uint8_t*)&b;
        condition1.nextCondition = &condition2;
        condition2.numClauses = 1;
        condition2.fieldNums[0] = 1;
        condition2.conditionType[0] = 1;
        condition2.values[0] = (uint8_t*)&low;
        condition2.nextCondition = &condition3;
        condition3.numClauses = 1;
        condition3.fieldNums[0] = 1;
        condition3.conditionType[0] = -1;
        condition3.values[0] = (uint8_t*)&high;
        condition3.nextCondition = NULL;
        noCondition.numClauses = 0;
        noCondition.nextCondition = NULL;
        gapCond1.numClauses = 2;
        gapCond1.fieldNums[0] = 1;
        gapCond1.conditionType[0] = -1;
        gapCond1.values[0] = (uint8_t*)&low;
        gapCond1.fieldNums[1] = 1;
        gapCond1.conditionType[1] = 1;
        gapCond1.values[1] = (uint8_t*)&lowPlusOne;
        gapCond1.nextCondition = &condition2;

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
    	*/
/*
    	//time to test performance of everything

    	int testSizes[] = {100000};
    	int numTests = 1;
    	//int testSizes[] = {500};//for testing
    	//int numTests = 1;
        createTestTableIndex(enclave_id, (int*)&status, "jIndex", high);
        deleteRows(enclave_id, (int*)&status, "jIndex", condition1, low, high);
        createTestTable(enclave_id, (int*)&status, "jTable", high);
        deleteRows(enclave_id, (int*)&status, "jTable", condition1, -1, -1);
    	for(int i = 0; i < numTests; i++){
    		int testSize = testSizes[i];
    		printf("\n\n|Test Size %d:\n", testSize);

    		//first we'll do the read-only tests
    		int numInnerTests = 5;//how many points do we want along the line
    		for(int testRound = 0; testRound <= numInnerTests; testRound++){
    			//if(testRound > numInnerTests/6){
    			//	testRound = numInnerTests;
    			//}
			//if(i == 0){
			//	testRound = numInnerTests;
			//}
    			//testRound = numInnerTests; //temp for testing
    			printf("test round %d: ", testRound);

    			if(testRound < numInnerTests){
    				//printf("querying %d%% of table\n", (int)((double)1/numInnerTests*100*(testRound+1)));
    				//printf("%d rows", (testRound+1)*100);
    				printf("query %d rows of db\n", testSize - (testRound*5000));
    			}
    			else{
    				printf("doing insert, update, delete queries and miscellaneous stuff\n");
    			}
            	double insertTimes[6] = {0};//average will be stored in last entry
            	double updateTimes[6] = {0};
            	double deleteTimes[6] = {0};
            	double aggregateTimes[6] = {0};
            	double groupByTimes[6] = {0};
            	double selectTimes[6] = {0};
            	double contTimes[6] = {0};
            	double smallTimes[6] = {0};
            	double hashTimes[6] = {0};
            	double joinTimes[6] = {0};
            	double lininsertTimes[6] = {0};
            	double linupdateTimes[6] = {0};
            	double lindeleteTimes[6] = {0};
            	double linaggregateTimes[6] = {0};
            	double lingroupByTimes[6] = {0};
            	double linselectTimes[6] = {0};
            	double lincontTimes[6] = {0};
            	double linsmallTimes[6] = {0};
            	double linhashTimes[6] = {0};
            	double linalmostAllTimes[6] = {0};
            	double linjoinTimes[6] = {0};
            	time_t startTime, endTime;
            	uint8_t* row = (uint8_t*)malloc(BLOCK_DATA_SIZE);
            	const char* text = "You would measure time the measureless and the immeasurable.";
        		for(int j = 0; j < 1; j++){ //want to average 5 trials
        			char tableName[20];
        			sprintf(tableName, "testTable%d", testSize);
        	        createTestTable(enclave_id, (int*)&status, "testTable", testSize);
        	        loadIndexTable(enclave_id, (int*)&status, testSize);
        	        printf("created tables\n");
        			if(testRound < numInnerTests){
        				//high = testSize/20*(testRound+1);
					//high = (testRound+1)*100;
					high = testSize - (testRound)*5000;
        				
            			//do an aggregate
        				startTime = clock();
        				selectRows(enclave_id, (int*)&status, "testTable", 1, condition1, 3, -1, -1);
        				endTime = clock();
        				linaggregateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        //int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {

            			//do a group by aggregate
        				startTime = clock();
        				selectRows(enclave_id, (int*)&status, "testTable", 1, gapCond1, 3, 3, -1);
        				endTime = clock();
        				lingroupByTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        //printTable(enclave_id, (int*)&status, "ReturnTable");
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            			//select
        				startTime = clock();
        				selectRows(enclave_id, (int*)&status, "testTable", -1, gapCond1, -1, -1, -1);
        				endTime = clock();
        				linselectTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        //printTable(enclave_id, (int*)&status, "ReturnTable");
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");


        				startTime = clock();
        				selectRows(enclave_id, (int*)&status, "testTable", -1, condition2, -1, -1, 1);//continuous
        				endTime = clock();
        				lincontTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        	//			startTime = clock();
        	//			indexSelect(enclave_id, (int*)&status, tableName, -1, condition2, -1, -1, 1, low, high);
        	//			endTime = clock();
        	//			contTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        	//	        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        				startTime = clock();
        				selectRows(enclave_id, (int*)&status, "testTable", -1, gapCond1, -1, -1, 3);//hash
        				endTime = clock();
        				linhashTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        		//		startTime = clock();
        		//		indexSelect(enclave_id, (int*)&status, tableName, -1, gapCond1, -1, -1, 3, low, high);
        		//		endTime = clock();
        	//			hashTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        	//	        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        		        //if(testRound >= numInnerTests - 3){
            				startTime = clock();
            				selectRows(enclave_id, (int*)&status, "testTable", -1, gapCond1, -1, -1, 4);//almost all
            				endTime = clock();
            				linalmostAllTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        		        //}

        		        //if(testSize < 1500){
            				startTime = clock();
            				selectRows(enclave_id, (int*)&status, "testTable", -1, gapCond1, -1, -1, 2);//small
            				endTime = clock();
            				linsmallTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            				startTime = clock();
            				indexSelect(enclave_id, (int*)&status, tableName, -1, gapCond1, -1, -1, 2, low, high);
            				endTime = clock();
            				smallTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        	    			//join
        					startTime = clock();
        			        joinTables(enclave_id, (int*)&status, "jTable", "testTable", 1, 1, -1, -1);
        					endTime = clock();
        					linjoinTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        	    	        deleteTable(enclave_id, (int*)&status, "JoinReturn");
        		        //}

            			//do an aggregate
        				startTime = clock();
        				indexSelect(enclave_id, (int*)&status, tableName, 1, gapCond1, 3, -1, -1, low, high);
        				endTime = clock();
        				aggregateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        //int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {

            			//do a group by aggregate
        				startTime = clock();
        				indexSelect(enclave_id, (int*)&status, tableName, 1, gapCond1, 3, 3, -1, low, high);
        				endTime = clock();
        				groupByTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            			//select
        				startTime = clock();
        				indexSelect(enclave_id, (int*)&status, tableName, -1, gapCond1, -1, -1, -1, low, high);
        				endTime = clock();
        				selectTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
        		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            			//join
        				startTime = clock();
        		        joinTables(enclave_id, (int*)&status, "jIndex", tableName, 1, 1, low, high);
        				endTime = clock();
        				joinTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            	        deleteTable(enclave_id, (int*)&status, "JoinReturn");


        			}
        			else{
        				high = 900;
           		        //printTable(enclave_id, (int*)&status, "testTable");
                			//do an insertion
            				row[0] = 'a';
            				memcpy(&row[1], &testSize, 4);
            				int temp = testSize/100;
            				memcpy(&row[5], &temp, 4);
            				if((testSize)%2 == 0) row[9] = 'a';
            				else if((testSize)%3 == 0) row[9] = 'b';
            				else row[9]= 'c';
            				memcpy(&row[10], text, strlen(text)+1);

            		        //printTable(enclave_id, (int*)&status, "testTable");
            				//printf("here\n");
            				//do an update
            				int updateVal = 313;
            				
            				startTime = clock();
            		        updateRows(enclave_id, (int*)&status, "testTable", condition1, 2, (uint8_t*)&updateVal, -1, -1);
            				endTime = clock();
            				linupdateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        //printTable(enclave_id, (int*)&status, "testTable");

                			//do an aggregate
            				startTime = clock();
            				selectRows(enclave_id, (int*)&status, "testTable", 1, condition1, 3, -1, -1);
            				endTime = clock();
            				linaggregateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
            //int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {


                			//do a group by aggregate
            				startTime = clock();
            				selectRows(enclave_id, (int*)&status, "testTable", 1, condition1, 3, 3, -1);
            				endTime = clock();
            				lingroupByTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        //printTable(enclave_id, (int*)&status, "ReturnTable");
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

                			//select
            				startTime = clock();
            				selectRows(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, -1);
            				endTime = clock();
            				linselectTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        //printTable(enclave_id, (int*)&status, "ReturnTable");
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            		        if(testSize < 1500){
            	    			//join
            					startTime = clock();
            			        joinTables(enclave_id, (int*)&status, "jTable", "testTable", 1, 1, -1, -1);
            					endTime = clock();
            					linjoinTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            	    	        deleteTable(enclave_id, (int*)&status, "JoinReturn");
            		        }

            				startTime = clock();
            				insertRow(enclave_id, (int*)&status, "testTable", row, -1);
            				endTime = clock();
            				lininsertTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);

                	        //delete rows
                	        printf("DELETE\n");
            				startTime = clock();
            		        deleteRows(enclave_id, (int*)&status, "testTable", condition1, -1, -1);
            				endTime = clock();
            				lindeleteTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);

                			//do all the same stuff for an index
                	        //
                	        //
                	        //
                	        printf("switching to Index\n");
                			//create table of size testSize

                			//do an update
            				startTime = clock();
            		        updateRows(enclave_id, (int*)&status, tableName, condition1, 2, (uint8_t*)&updateVal, low, high);
            				endTime = clock();
            				updateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);

            		        small select
            				startTime = clock();
            				indexSelect(enclave_id, (int*)&status, tableName, -1, gapCond1, -1, -1, 2, low, high);
            				endTime = clock();
            				smallTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

            		        
                			//do an aggregate
            				startTime = clock();
            				indexSelect(enclave_id, (int*)&status, tableName, 1, condition1, 3, -1, -1, low, high);
            				endTime = clock();
            				aggregateTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");
            //int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice) {

                			//do a group by aggregate
            				startTime = clock();
            				indexSelect(enclave_id, (int*)&status, tableName, 1, condition1, 3, 3, -1, low, high);
            				endTime = clock();
            				groupByTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

                			//select
            				startTime = clock();
            				indexSelect(enclave_id, (int*)&status, tableName, -1, condition1, -1, -1, -1, low, high);
            				endTime = clock();
            				selectTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            		        deleteTable(enclave_id, (int*)&status, "ReturnTable");

                			//join
            				startTime = clock();
            		        joinTables(enclave_id, (int*)&status, "jIndex", tableName, 1, 1, low, high);
            				endTime = clock();
            				joinTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
                	        deleteTable(enclave_id, (int*)&status, "JoinReturn");
                	        

                	        printf("inserting\n");
                			//do an insertion
            				startTime = clock();
            				for(int q = 0; q < 10; q++){
                				insertRow(enclave_id, (int*)&status, tableName, row, testSize);
            				}
            				endTime = clock();
            				insertTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            				insertTimes[j]/=10;
                	        printf("deleting\n");
                	        //delete rows
            				startTime = clock();
            				for(int q = 0; q < 10; q++){//printf("del %d\n", q);
                		        deleteRows(enclave_id, (int*)&status, tableName, condition1, low, high);
            				}
            				endTime = clock();
            				deleteTimes[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
            				insertTimes[j]/=10;
            				printf("end\n");
        			}

        			deleteTable(enclave_id, (int*)&status, "testTable");
        			deleteTable(enclave_id, (int*)&status, tableName);


        		}
        		free(row);
        		for(int j = 0; j < 5; j++){
                	insertTimes[5] += insertTimes[j];
                	updateTimes[5] += updateTimes[j];
                	deleteTimes[5] += deleteTimes[j];
                	aggregateTimes[5] += aggregateTimes[j];
                	groupByTimes[5] += groupByTimes[j];
                	selectTimes[5] += selectTimes[j];
                	contTimes[5] += contTimes[j];
                	smallTimes[5] += smallTimes[j];
                	hashTimes[5] += hashTimes[j];
                	joinTimes[5] += joinTimes[j];
                	lininsertTimes[5] += lininsertTimes[j];
                	linupdateTimes[5] += linupdateTimes[j];
                	lindeleteTimes[5] += lindeleteTimes[j];
                	linaggregateTimes[5] += linaggregateTimes[j];
                	lingroupByTimes[5] += lingroupByTimes[j];
                	linselectTimes[5] += linselectTimes[j];
                	lincontTimes[5] += lincontTimes[j];
                	linsmallTimes[5] += linsmallTimes[j];
                	linhashTimes[5] += linhashTimes[j];
                	linalmostAllTimes[5] += linalmostAllTimes[j];
                	linjoinTimes[5] += linjoinTimes[j];
        		}
            	insertTimes[5] /= 5;
            	updateTimes[5] /= 5;
            	deleteTimes[5] /= 5;
            	aggregateTimes[5] /= 5;
            	groupByTimes[5] /= 5;
            	selectTimes[5] /= 5;
            	contTimes[5] /= 5;
            	smallTimes[5] /= 5;
            	hashTimes[5] /= 5;
            	joinTimes[5] /= 5;
            	lininsertTimes[5] /= 5;
            	linupdateTimes[5] /= 5;
            	lindeleteTimes[5] /= 5;
            	linaggregateTimes[5] /= 5;
            	lingroupByTimes[5] /= 5;
            	linselectTimes[5] /= 5;
            	lincontTimes[5] /= 5;
            	linsmallTimes[5] /= 5;
            	linhashTimes[5] /= 5;
            	linalmostAllTimes[5] /= 5;
            	linjoinTimes[5] /= 5;
        		printf("insertTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", insertTimes[0], insertTimes[1], insertTimes[2], insertTimes[3], insertTimes[4], insertTimes[5]);
        		printf("updateTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", updateTimes[0], updateTimes[1], updateTimes[2], updateTimes[3], updateTimes[4], updateTimes[5]);
        		printf("deleteTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", deleteTimes[0], deleteTimes[1], deleteTimes[2], deleteTimes[3], deleteTimes[4], deleteTimes[5]);
        		printf("aggregateTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", aggregateTimes[0], aggregateTimes[1], aggregateTimes[2], aggregateTimes[3], aggregateTimes[4], aggregateTimes[5]);
        		printf("groupByTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", groupByTimes[0], groupByTimes[1], groupByTimes[2], groupByTimes[3], groupByTimes[4], groupByTimes[5]);
        		printf("selectTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", selectTimes[0], selectTimes[1], selectTimes[2], selectTimes[3], selectTimes[4], selectTimes[5]);
        		printf("contTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", contTimes[0], contTimes[1], contTimes[2], contTimes[3], contTimes[4], contTimes[5]);
        		printf("smallTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", smallTimes[0], smallTimes[1], smallTimes[2], smallTimes[3], smallTimes[4], smallTimes[5]);
        		printf("hashTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", hashTimes[0], hashTimes[1], hashTimes[2], hashTimes[3], hashTimes[4], hashTimes[5]);
        		printf("joinTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", joinTimes[0], joinTimes[1], joinTimes[2], joinTimes[3], joinTimes[4], joinTimes[5]);
        		printf("lininsertTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", lininsertTimes[0], lininsertTimes[1], lininsertTimes[2], lininsertTimes[3], lininsertTimes[4], lininsertTimes[5]);
        		printf("linupdateTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linupdateTimes[0], linupdateTimes[1], linupdateTimes[2], linupdateTimes[3], linupdateTimes[4], linupdateTimes[5]);
        		printf("lindeleteTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", lindeleteTimes[0], lindeleteTimes[1], lindeleteTimes[2], lindeleteTimes[3], lindeleteTimes[4], lindeleteTimes[5]);
        		printf("linaggregateTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linaggregateTimes[0], linaggregateTimes[1], linaggregateTimes[2], linaggregateTimes[3], linaggregateTimes[4], linaggregateTimes[5]);
        		printf("lingroupByTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", lingroupByTimes[0], lingroupByTimes[1], lingroupByTimes[2], lingroupByTimes[3], lingroupByTimes[4], lingroupByTimes[5]);
        		printf("linselectTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linselectTimes[0], linselectTimes[1], linselectTimes[2], linselectTimes[3], linselectTimes[4], linselectTimes[5]);
        		printf("lincontTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", lincontTimes[0], lincontTimes[1], lincontTimes[2], lincontTimes[3], lincontTimes[4], lincontTimes[5]);
        		printf("linsmallTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linsmallTimes[0], linsmallTimes[1], linsmallTimes[2], linsmallTimes[3], linsmallTimes[4], linsmallTimes[5]);
        		printf("linhashTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linhashTimes[0], linhashTimes[1], linhashTimes[2], linhashTimes[3], linhashTimes[4], linhashTimes[5]);
        		printf("linalmostAllTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linalmostAllTimes[0], linalmostAllTimes[1], linalmostAllTimes[2], linalmostAllTimes[3], linalmostAllTimes[4], linalmostAllTimes[5]);
        		printf("linjoinTimes | %.5f %.5f %.5f %.5f %.5f : %.5f\n", linjoinTimes[0], linjoinTimes[1], linjoinTimes[2], linjoinTimes[3], linjoinTimes[4], linjoinTimes[5]);
    		}
    	}
        deleteTable(enclave_id, (int*)&status, "jIndex");
        deleteTable(enclave_id, (int*)&status, "jTable");
*/

/*
    	//printf("starting");fflush(stdout);
    	char delTestName[20];
		sprintf(delTestName, "testTable%d", 500);
        //loadIndexTable(enclave_id, (int*)&status, 500);
    	createTestTableIndex(enclave_id, (int*)&status, delTestName, 1000);printf("del0");fflush(stdout);
        //indexSelect(enclave_id, (int*)&status, delTestName, -1, noCondition, -1, -1, -1, low, high);
    	//printTable(enclave_id, (int*)&status, "ReturnTable");
    	//deleteTable(enclave_id, (int*)&status, "ReturnTable");

        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del1\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del2\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del3\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del4\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del5\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del6\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del1\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del2\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del3\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del4\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del5\n");fflush(stdout);
        deleteRows(enclave_id, (int*)&status, delTestName, condition1, low, high);printf("del6\n");fflush(stdout);
        indexSelect(enclave_id, (int*)&status, delTestName, -1, noCondition, -1, -1, -1, low, high);
    	//printf("selected! %d %d\n", low, high);
    	//printTable(enclave_id, (int*)&status, "ReturnTable");
*/

    	/*createTestTableIndex(enclave_id, (int*)&status, "testTable", 10);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 10);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 50);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 50);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 100);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 100);
    	deleteTable(enclave_id, (int*)&status, "testTable100");*/

    	/*createTestTableIndex(enclave_id, (int*)&status, "testTable", 50);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 50);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	loadIndexTable(enclave_id, (int*)&status, 50);
    	printf("loaded!\n");fflush(stdout);
        indexSelect(enclave_id, (int*)&status, "testTable50", -1, condition1, -1, -1, -1, low, high);
    	printf("selected!\n");
    	printTable(enclave_id, (int*)&status, "ReturnTable");*/
/*
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 500);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 500);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 1000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 1000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 5000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 5000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 10000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 10000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 50000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 50000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 100000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 100000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 500000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 500000);
    	deleteTable(enclave_id, (int*)&status, "testTable");
    	createTestTableIndex(enclave_id, (int*)&status, "testTable", 1000000);
    	saveIndexTable(enclave_id, (int*)&status, "testTable", 1000000);
    	deleteTable(enclave_id, (int*)&status, "testTable");*/
    	//loadIndexTable(enclave_id, (int*)&status, "testTable");
    	//printf("loaded!\n");fflush(stdout);
        //indexSelect(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, -1, low, high);
    	//printf("selected!\n");
    	//printTable(enclave_id, (int*)&status, "ReturnTable");
    	/*
        //test to create table and print it
        createTestTable(enclave_id, (int*)&status, "testTable", 100000);
        //printTable(enclave_id, (int*)&status, "myTestTable");
printf("created\n");
//selectRows(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, 1);
//printTable(enclave_id, (int*)&status, "ReturnTable");
//printf("deleting\n");

//deleteTable(enclave_id, (int*)&status, "ReturnTable");
//printf("deleted\n");

selectRows(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, 2);
printf("printing\n");

printTable(enclave_id, (int*)&status, "ReturnTable");
printf("deleting\n");

deleteTable(enclave_id, (int*)&status, "ReturnTable");
printf("deleted\n");


selectRows(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, 3);
printf("printing");
printTable(enclave_id, (int*)&status, "ReturnTable");
printf("deleting");
deleteTable(enclave_id, (int*)&status, "ReturnTable");
printf("deleted");

selectRows(enclave_id, (int*)&status, "testTable", -1, condition1, -1, -1, 4);
printTable(enclave_id, (int*)&status, "ReturnTable");
deleteTable(enclave_id, (int*)&status, "ReturnTable");

*/
        //test to satisfy conditions on rows
        /*Schema s;
        getTableSchema(enclave_id, &s, "myTestTable");
        uint8_t* row1 = (uint8_t*)malloc(BLOCK_DATA_SIZE);
        row1[0] = 'a';
        int val = 260;
        memcpy(&row1[1], &val, 4);
        //row1[1] = 260;
        int val2 = 313;
        memcpy(&row1[5], &val2, 4);
        row1[9] = 'b';
        int output = 0;
        rowMatchesCondition(enclave_id, &output, condition1, row1, s);
        printf("row1 matches condition: %d", output);*/

        //test to insert, update, delete
        /*
        insertRow(enclave_id, (int*)&status, "myTestTable", row1, -1);
        insertRow(enclave_id, (int*)&status, "myTestTable", row1, -1);
        printTable(enclave_id, (int*)&status, "myTestTable");
        updateRows(enclave_id, (int*)&status, "myTestTable", condition2, 2, &row1[5], -1, -1);
        printTable(enclave_id, (int*)&status, "myTestTable");
        deleteRows(enclave_id, (int*)&status, "myTestTable", condition2, -1, -1);
        printTable(enclave_id, (int*)&status, "myTestTable");
        */

        //test select aggregate without group
//int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice)
       /* selectRows(enclave_id, (int*)&status, "myTestTable", 1, condition2, 0, -1, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");*/


        //test select continuous:
        /*
        selectRows(enclave_id, (int*)&status, "myTestTable", -1, condition2, -1, -1, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        */

        /*
        //test select almost all: (depending on how much extra space is left in the table data structure)
        createTestTable(enclave_id, (int*)&status, "myTestTable2", 110);
        insertRow(enclave_id, (int*)&status, "myTestTable2", row1, -1);
        insertRow(enclave_id, (int*)&status, "myTestTable2", row1, -1);
        printTable(enclave_id, (int*)&status, "myTestTable2");
        selectRows(enclave_id, (int*)&status, "myTestTable2", -1, condition2, -1, -1, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        */

        //test select small:
        /*
        createTestTable(enclave_id, (int*)&status, "myTestTable2", 50);
        insertRow(enclave_id, (int*)&status, "myTestTable2", row1, -1);
        insertRow(enclave_id, (int*)&status, "myTestTable2", row1, -1);
        printTable(enclave_id, (int*)&status, "myTestTable2");
        selectRows(enclave_id, (int*)&status, "myTestTable2", -1, condition2, -1, -1, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
	*/

        //test group by
        //int selectRows(char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice)
        /*selectRows(enclave_id, (int*)&status, "myTestTable", 1, condition1, 0, 3, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");*/


        //test select hash
        /*
        createTestTable(enclave_id, (int*)&status, "myTestTable2", 50);
        insertRow(enclave_id, (int*)&status, "myTestTable2", row1, -1);
        selectRows(enclave_id, (int*)&status, "myTestTable2", -1, condition2, -1, -1, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
		*/

        //test join
/*
        createTestTable(enclave_id, (int*)&status, "join1", 50);
        createTestTable(enclave_id, (int*)&status, "join2", 50);
        deleteRows(enclave_id, (int*)&status, "join2", condition1, -1, -1);
        printTable(enclave_id, (int*)&status, "join2");
        joinTables(enclave_id, (int*)&status, "join1", "join2", 1, 1, -1, -1);
        printTable(enclave_id, (int*)&status, "JoinReturn");
        printTable(enclave_id, (int*)&status, "join2");
        selectRows(enclave_id, (int*)&status, "JoinReturn", 1, condition3, 0, 3, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "JoinReturn");
        deleteTable(enclave_id, (int*)&status, "join1");
        deleteTable(enclave_id, (int*)&status, "join2");
*/

        //Start Index tests
       // printf("start index tests\n");

        //createTestTableIndex(enclave_id, (int*)&status, "myTestIndex", 15);
        //printTable(enclave_id, (int*)&status, "myTestIndex");
        /*
        //indexSelect(enclave_id, (int*)&status, "myTestIndex", 1, condition1, 0, 3, -1, 2, 250);
        indexSelect(enclave_id, (int*)&status, "myTestIndex", -1, condition1, -1, -1, -1, 2, 250);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        //insertRow(enclave_id, (int*)&status, "myTestIndex", row1, 260);
        //insertRow(enclave_id, (int*)&status, "myTestIndex", row1, 260);
        //updateRows(enclave_id, (int*)&status, "myTestIndex", condition2, 2, &row1[5], 2, 7);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        deleteRows(enclave_id, (int*)&status, "myTestIndex", condition1, 2, 20);
        indexSelect(enclave_id, (int*)&status, "myTestIndex", -1, noCondition, -1, -1, -1, 2, 270);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        */
        //test join
/*
        createTestTableIndex(enclave_id, (int*)&status, "jointestTable", 50);
        createTestTableIndex(enclave_id, (int*)&status, "jIndex", 50);
        deleteRows(enclave_id, (int*)&status, "jIndex", condition1, 2, 37);
        deleteRows(enclave_id, (int*)&status, "jIndex", condition1, 2, 37);
        deleteRows(enclave_id, (int*)&status, "jIndex", condition1, 2, 37);
        deleteRows(enclave_id, (int*)&status, "jIndex", condition1, 2, 37);

        indexSelect(enclave_id, (int*)&status, "jointestTable", -1, noCondition, -1, -1, -1, 0, 100);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        indexSelect(enclave_id, (int*)&status, "jIndex", -1, noCondition, -1, -1, -1, -1, 100);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");

        joinTables(enclave_id, (int*)&status, "jointestTable", "jIndex", 1, 1, 2, 21);
        printTable(enclave_id, (int*)&status, "JoinReturn");
        selectRows(enclave_id, (int*)&status, "JoinReturn", 1, noCondition, 0, 3, -1);
        printTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "ReturnTable");
        deleteTable(enclave_id, (int*)&status, "JoinReturn");
*/
        //ret = newStructure(enclave_id, TYPE_TREE_ORAM, (*oramCapacity*2-1)*BUCKET_SIZE); //real size of oram is bigger than logical size
        //JK, ignore all this, I'm going to call the testing ecall. TODO: clean this and the service_provider up later
        //ret = newStructure(enclave_id, TYPE_LINEAR_SCAN, 7);//as per the requirements of the hard-coded test
        /*run_tests(enclave_id, &status);
        if(ret || status != SGX_SUCCESS){
        	printf("operation failed.\n");
        	goto CLEANUP;
        }*/


        //testMemory(enclave_id, &status);

        //begin performance tests for data structures

        //int numQueries = 50;
        //int numBlocks = pow(2, NUM_BLOCKS_POW)-1;
        //for(int n = 5; n < 6; n++){//make this something like 150 later and run for many different data block sizes
        	//numBlocks = pow(2, n)-1;
            //set up encrypted linear scan

        /*switch(TEST_TYPE){
        case 1:
        {
            printf("setting up encrypted linear scan\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_LINEAR_SCAN);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up encrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            Linear_Scan_Block* b1 = (Linear_Scan_Block*)malloc(sizeof(Linear_Scan_Block));
            //run encrypted linear scan
            //printf("running encrypted linear scan\n");
            time_t startEnc = clock();
            for(int i = 0; i < numQueries; i++) {//printf("here");fflush(stdout);
                testLinScanBlockPerformance(enclave_id, &status, 0, numBlocks/2, b1, sizeof(Linear_Scan_Block));
            }
            time_t endEnc = clock();
            double elapsedEnc = (double)(endEnc - startEnc)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("encrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            printf("Linear_Encrypted| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedEnc);
            //free the memory we used
            free(oblivStructures[0]);
            free(b1);
        }
        	break;
        case 2:
        {
            //set up unencrypted linear scan
            printf("setting up unencrypted linear scan\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_LINEAR_UNENCRYPTED);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up unencrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            Linear_Scan_Block* b2 = (Linear_Scan_Block*)malloc(sizeof(Linear_Scan_Block));
            //run unencrypted linear scan
            //printf("running unencrypted linear scan\n");
            time_t startUnEnc = clock();
            for(int i = 0; i < numQueries; i++) {
                testLinScanBlockUnencryptedPerformance(enclave_id, &status, 0, numBlocks/2, b2, sizeof(Linear_Scan_Block));
            }
            time_t endUnEnc = clock();
            double elapsedUnEnc = (double)(endUnEnc - startUnEnc)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("unencrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            printf("Linear_Unencrypted| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedUnEnc);
            //free the memory we used
            free(oblivStructures[0]);
            free(b2);
        }
        	break;
        case 3:
        {
            //set up oram
            //printf("setting up oram\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_ORAM);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up oram failed.\n");
            	goto CLEANUP;
            }
            Oram_Block* b3 = (Oram_Block*)malloc(sizeof(Oram_Block));
            //initialize all the blocks so we get a realistic test
            for(int i = 0; i < numBlocks; i++){
            	testOramPerformance(enclave_id, &status, 0, i, b3, sizeof(Oram_Block));
            }
            //run oram
            //printf("running oram\n");
            time_t startOram = clock();
            for(int i = 0; i < numQueries; i++) {
                testOramPerformance(enclave_id, &status, 0, numBlocks/2, b3, sizeof(Oram_Block));
            }
            time_t endOram = clock();
            double elapsedOram = (double)(endOram - startOram)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("oram failed.\n");
            	goto CLEANUP;
            }
            printf("ORAM| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedOram);
            //free the memory we used
            //function to free the memory used for the position map
            free_oram(enclave_id, &status, 0);
            free(oblivStructures[0]);
            free(b3);
        }
        	break;
        case 4:
        {
            //set up "safe" oram
            printf("setting up safe oram\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_ORAM);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up oram failed.\n");
            	goto CLEANUP;
            }
            Oram_Block* b3 = (Oram_Block*)malloc(sizeof(Oram_Block));
            //initialize all the blocks so we get a realistic test
            for(int i = 0; i < numBlocks; i++){
            	testOramPerformance(enclave_id, &status, 0, i, b3, sizeof(Oram_Block));
            }
            //run oram
            //printf("running oram\n");

            //temp for distribuction experiment
            oramDistribution(enclave_id, &status, 0);

            break;
            //end temp
            time_t startOram = clock();
            for(int i = 0; i < numQueries; i++) {
                testOramSafePerformance(enclave_id, &status, 0, numBlocks/2, b3, sizeof(Oram_Block));
            }
            time_t endOram = clock();
            double elapsedOram = (double)(endOram - startOram)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("oram failed.\n");
            	goto CLEANUP;
            }
            printf("ORAMSafe| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedOram);
            //free the memory we used
            //function to free the memory used for the position map
            free_oram(enclave_id, &status, 0);
            free(oblivStructures[0]);
            free(b3);
        }
        	break;
        case 5:
        {
            printf("setting up encrypted linear scan write\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_LINEAR_SCAN);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up encrypted linear scan write failed.\n");
            	goto CLEANUP;
            }
            Linear_Scan_Block* b1 = (Linear_Scan_Block*)malloc(sizeof(Linear_Scan_Block));
            //run encrypted linear scan
            //printf("running encrypted linear scan\n");
            time_t startEnc = clock();
            for(int i = 0; i < numQueries; i++) {//printf("here");fflush(stdout);
                testLinScanBlockWritePerformance(enclave_id, &status, 0, numBlocks/2, b1, sizeof(Linear_Scan_Block));
            }
            time_t endEnc = clock();
            double elapsedEnc = (double)(endEnc - startEnc)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("encrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            printf("Linear_EncryptedWrite| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedEnc);
            //free the memory we used
            free(oblivStructures[0]);
            free(b1);
        	break;
        }
        case 6:
        {
            //set up unencrypted linear scan
            printf("setting up unencrypted linear scan write\n");
            setupPerformanceTest(enclave_id, &status, 0, numBlocks, TYPE_LINEAR_UNENCRYPTED);
            if(ret || status != SGX_SUCCESS){
            	printf("setting up unencrypted linear scan write failed.\n");
            	goto CLEANUP;
            }
            Linear_Scan_Block* b2 = (Linear_Scan_Block*)malloc(sizeof(Linear_Scan_Block));
            //run unencrypted linear scan
            //printf("running unencrypted linear scan\n");
            time_t startUnEnc = clock();
            for(int i = 0; i < numQueries; i++) {
                testLinScanBlockUnencryptedWritePerformance(enclave_id, &status, 0, numBlocks/2, b2, sizeof(Linear_Scan_Block));
            }
            time_t endUnEnc = clock();
            double elapsedUnEnc = (double)(endUnEnc - startUnEnc)/(CLOCKS_PER_SEC);
            if(ret || status != SGX_SUCCESS){
            	printf("unencrypted linear scan failed.\n");
            	goto CLEANUP;
            }
            printf("Linear_UnencryptedWrite| numBlocks: %d, BLOCK_DATA_SIZE: %d, numQueries: %d, time: %f\n", numBlocks, BLOCK_DATA_SIZE, numQueries, elapsedUnEnc);
            //free the memory we used
            free(oblivStructures[0]);
            free(b2);
        }
        	break;
        default:
        	printf("invalid TEST_TYPE!\n");
        	break;
        }*/







        //}

        /*testOpOram(enclave_id, &status);
        if(ret || status != SGX_SUCCESS){
        	printf("oram correctness test failed.\n");
        	goto CLEANUP;
        }*/

    }
    /*
     *
     *
     *End Saba's Code
     *
     *
	*/

CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context)
    {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        }
        else
        {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.");
    }

    sgx_destroy_enclave(enclave_id);

    //todo(Saba): need to free stuff that I used in the code I added
    /*moved up
     * ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);

    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);*/
    //printf("\nEnter a character before exit ...\n");
    //getchar();
    return ret;
}

