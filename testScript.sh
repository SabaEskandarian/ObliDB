#!/bin/bash
#get test data we need
#want data for each of the four kinds of tests in a different file
#for each type we want to try block sizes from 2^1 to 2^20
#and number of blocks from 2^1 to 2^20
#expect lots of segfaults for the bigger numbers, but we'll get what we get
#note each one is queried 50 times to get the final time listed

ulimit -s unlimited #probably don't need this
for i in {1..4}
do
    for j in {1..2}
    do
        for k in {1..2}
        do	
		echo "test $i block power $j num block power $k"
		var=$((2**$j))
		make clean
		make SGX_MODE=SIM TEST_TYPE=$i BLOCK_DATA_SIZE=$var NUM_BLOCKS_POW=$k
		./app | grep "|" >> results/resType$i.txt
	done
    done
done
make clean
