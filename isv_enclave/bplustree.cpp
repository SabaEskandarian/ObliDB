//modified from http://www.amittai.com/prose/bplustree.html
/*
 *  bpt.c
 *
 *  bpt:  B+ Tree Implementation
 *  Copyright (C) 2010-2016  Amittai Aviram  http://www.amittai.com
 *  All rights reserved.
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.

 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.

 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.

 *  Author:  Amittai Aviram
 *    http://www.amittai.com
 *    amittai.aviram@gmail.edu or afa13@columbia.edu
 *  Original Date:  26 June 2010
 *  Last modified: 17 June 2016
 *
 *  This implementation demonstrates the B+ tree data structure
 *  for educational purposes, includin insertion, deletion, search, and display
 *  of the search path, the leaves, or the whole tree.
 *
 *  Must be compiled with a C99-compliant C compiler such as the latest GCC.
 *
 *  Usage:  bpt [order]
 *  where order is an optional argument
 *  (integer MIN_ORDER <= order <= MAX_ORDER)
 *  defined as the maximal number of pointers in any node.
 *
 */

// Uncomment the line below if you are compiling on Windows.
// #define WINDOWS
#include "definitions.h"
#include "isv_enclave.h"


//helper to replace pointers to nodes
int followNodePointer(int structureId, node* destinationNode, int pointerIndex){
	//printf("following a node pointer to address %d ", pointerIndex);
	currentPad++;
	int t = opOramBlock(structureId, pointerIndex, (Oram_Block*)destinationNode, 0);
	/*if(t == 0){
		printf("oram op success\n");
	}else {
		printf("oram op failed %d\n", pointerIndex);
	}*/
	//printf("after return %d, which claims to be address %d\n", t, destinationNode->actualAddr);
	//printf("size 1 %d size 2 %d 3 %d\n", sizeof(Oram_Block), sizeof(node), sizeof(record));
	return 0;
}

//helper to replace pointers to records
int followRecordPointer(int structureId, record* destinationNode, int pointerIndex){
	//printf("following a record pointer\n");
	currentPad++;
	return opOramBlock(structureId, pointerIndex, (Oram_Block*)destinationNode, 0);
}

//helpers to write back to oram after using a block
int writeNode(int structureId, node *n){
	//printf("writing to block #%d\n", n->actualAddr);
	currentPad++;
	int t = opOramBlock(structureId, n->actualAddr, (Oram_Block*)n, 1);
	/*if(t == 0){
		printf("oram op write success\n");
	}else {
		printf("oram op write failed %d\n", n->actualAddr);
	}*/
	return t;
}
int writeRecord(int structureId, record *r){
	currentPad++;
	return opOramBlock(structureId, r->actualAddr, (Oram_Block*)r, 1);
}

// GLOBALS.

/* The order determines the maximum and minimum
 * number of entries (keys and pointers) in any
 * node.  Every node has at most order - 1 keys and
 * at least (roughly speaking) half that number.
 * Every leaf has as many pointers to data as keys,
 * and every internal node has one more pointer
 * to a subtree than the number of keys.
 * This global variable is initialized to the
 * default value.
 */
int order = MAX_ORDER;

int currentPad = 0;
int maxPad = 0;

// FUNCTION DEFINITIONS.


/* Prints the bottom row of keys
 * of the tree
 */
void print_leaves(int structureId,  node * root ) {
	int i;
	node *c = (node*)malloc(sizeof(node));
	memcpy(c, root, sizeof(node));
	//node * c = root;
	if (root == NULL) {
		printf("Empty tree.\n");
		return;
	}
	while (!c->is_leaf)
		followNodePointer(structureId, c, c->pointers[0]);
		//c = (node*)c->pointers[0];
	while (true) {
		for (i = 0; i < c->num_keys; i++) {
			printf("%d ", c->keys[i]);
		}
		if (c->pointers[order - 1] != -1) {
			printf(" | ");
			followRecordPointer(structureId, (record*)c, c->pointers[order-1]);
			//c = (node*)c->pointers[order - 1];
		}
		else
			break;
	}
	printf("\n");
	free(c);
}


/* Finds keys and their pointers, if present, in the range specified
 * by key_start and key_end, inclusive.  Places these in the arrays
 * returned_keys and returned_pointers, and returns the number of
 * entries found.
 */
int find_range(int structureId, node * root, int key_start, int key_end, int destStructId)// put the range in a specified table for debug printing
		/*, int returned_keys[], void * returned_pointers[])*/ {
	Oram_Block* b = (Oram_Block*)malloc(sizeof(Oram_Block));
	int i, num_found;
	num_found = 0;
	node * n = find_leaf(structureId, root, key_start);
	if (n == NULL) return 0;
	for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
	if (i == n->num_keys) return 0;
	while (n != NULL) {
		for ( ; i < n->num_keys && n->keys[i] <= key_end; i++) {
			currentPad++;
			opOramBlock(structureId, n->pointers[i], b, 0);
			opOneLinearScanBlock(destStructId, num_found, (Linear_Scan_Block*)&b->data[0], 1);
			//returned_keys[num_found] = n->keys[i];
			//returned_pointers[num_found] = n->pointers[i];
			num_found++;
		}
		followNodePointer(structureId, n, n->pointers[order - 1]);
		//n = (node*)n->pointers[order - 1];
		i = 0;
	}
	free(b);
	free(n);
	return num_found;
}


/* Traces the path from the root to a leaf, searching
 * by key.
 * Returns the leaf containing the given key.
 */
node * find_leaf(int structureId, node * root, int key) {
	int i = 0;
	node *c = (node*)malloc(sizeof(node));
	if (root == NULL) {
		return NULL;
	}

	memcpy(c, root, sizeof(node));
	//c = root;
	int tempCount = 0;
	//printf("here in find_leaf %d\n", c->is_leaf);
	while (!c->is_leaf) {//printf("find_leaf c: %d %d %d %d %d\n", c->actualAddr, c->num_keys, c->is_leaf, c->keys[0], c->pointers[0]);
		//printf("here in find_leaf2\n");
		i = 0;
		while (i < c->num_keys) {	//printf("here in find_leaf3\n");
			if (key >= c->keys[i]) i++;
			else break;
		}
		tempCount++;
		//printf("following link from block %d to block %d\n", c->actualAddr, c->pointers[i]);
		//printf("i %d %d %d\n", i, positionMaps[structureId][c->pointers[i]], usedBlocks[structureId][c->pointers[i]]);
		followNodePointer(structureId, c, c->pointers[i]);
		//printf("now in node %d, tempCount=%d \n", c->actualAddr, tempCount);
		//c = (node *)c->pointers[i];
	}

	return c;
}


/* Finds and returns the record to which
 * a key refers.
 */
record * find(int structureId, node * root, int key) {
	int i = 0;
	node * c = find_leaf(structureId, root, key);
	if (c == NULL) return NULL;
	for (i = 0; i < c->num_keys; i++)
		if (c->keys[i] == key) break;
	if (i == c->num_keys)
		return NULL;
	else{
		followRecordPointer(structureId, (record*)c, c->pointers[i]);
		return (record*)c;
	}
}

/* Finds the appropriate place to
 * split a node that is too big into two.
 */
int cut( int length ) {
	if (length % 2 == 0)
		return length/2;
	else
		return length/2 + 1;
}


// INSERTION

/* Creates a new record to hold the value
 * to which a key refers.
 */
record * make_record(int structureId, uint8_t* row) {
	record *new_record = (record *)malloc(sizeof(record));
	if (new_record == NULL) {
		//perror("Record creation failed.");
	}
	else {
		new_record->actualAddr = newBlock(structureId);
		memcpy(&new_record->data[0], &row[0], BLOCK_DATA_SIZE);
		//new_record->value = value;
		writeRecord(structureId, new_record);
	}
	return new_record;
}

/* Creates a new general node, which can be adapted
 * to serve as either a leaf or an internal node.
 */
node * make_node(int structureId, int isLeaf) {
	node * new_node;
	new_node = (node*)malloc(sizeof(node));

	//new_node->keys = (int*)malloc( (order - 1) * sizeof(int) );

	//new_node->pointers = (void**)malloc( order * sizeof(void *) );
	new_node->actualAddr = newBlock(structureId);

	new_node->is_leaf = isLeaf;
	new_node->num_keys = 0;
	new_node->parentAddr = -1;
	writeNode(structureId, new_node);
	//printf("allocated node: %d", new_node->actualAddr);
	return new_node;
}

/* Helper function used in insert_into_parent
 * to find the index of the parent's pointer to
 * the node to the left of the key to be inserted.
 */
int get_left_index(int structureId, node * parent, node * left) {

	int left_index = 0;
	while (left_index <= parent->num_keys &&
			parent->pointers[left_index] != left->actualAddr)
		left_index++;
	return left_index;
}


/* Inserts a new pointer to a record and its corresponding
 * key into a leaf.
 * Returns the altered leaf.
 */
node* insert_into_leaf(int structureId,  node * leaf, int key, record * pointer ) {

	int i, insertion_point;

	insertion_point = 0;
	while (insertion_point < leaf->num_keys && leaf->keys[insertion_point] < key)
		insertion_point++;

	for (i = leaf->num_keys; i > insertion_point; i--) {
		leaf->keys[i] = leaf->keys[i - 1];
		leaf->pointers[i] = leaf->pointers[i - 1];
	}
	leaf->keys[insertion_point] = key;
	leaf->pointers[insertion_point] = pointer->actualAddr;
	leaf->num_keys++;
	//printf("num_keys %d\n", leaf->num_keys);
	writeNode(structureId, leaf);
	return leaf;
}

/* Inserts a new key and pointer
 * to a new record into a leaf so as to exceed
 * the tree's order, causing the leaf to be split
 * in half.
 */
node * insert_into_leaf_after_splitting(int structureId, node * root, node * leaf, int key, record * pointer) {
	//printf("insertintoleafaftersplitting");
	node * new_leaf;
	int temp_keys[MAX_ORDER] = {0};
	int temp_pointers[MAX_ORDER] = {-1};
	int insertion_index, split, new_key, i, j;

	//printf("new leaf: ");
	new_leaf = make_node(structureId, 1);

	insertion_index = 0;
	while (insertion_index < order - 1 && leaf->keys[insertion_index] < key)
		insertion_index++;

	for (i = 0, j = 0; i < leaf->num_keys; i++, j++) {
		if (j == insertion_index) j++;
		temp_keys[j] = leaf->keys[i];
		temp_pointers[j] = leaf->pointers[i];
	}

	temp_keys[insertion_index] = key;
	temp_pointers[insertion_index] = pointer->actualAddr;

	leaf->num_keys = 0;

	split = cut(order - 1);

	for (i = 0; i < split; i++) {
		leaf->pointers[i] = temp_pointers[i];
		leaf->keys[i] = temp_keys[i];
		leaf->num_keys++;
	}

	for (i = split, j = 0; i < order; i++, j++) {
		new_leaf->pointers[j] = temp_pointers[i];
		new_leaf->keys[j] = temp_keys[i];
		new_leaf->num_keys++;
	}

	new_leaf->pointers[order - 1] = leaf->pointers[order - 1];
	leaf->pointers[order - 1] = new_leaf->actualAddr;

	for (i = leaf->num_keys; i < order - 1; i++)
		leaf->pointers[i] = -1;
	for (i = new_leaf->num_keys; i < order - 1; i++)
		new_leaf->pointers[i] = -1;

	new_leaf->parentAddr = leaf->parentAddr;
	new_key = new_leaf->keys[0];

	writeNode(structureId, leaf);//do this here because these may not be edited again
	writeNode(structureId, new_leaf);

	node* ret = insert_into_parent(structureId, root, leaf, new_key, new_leaf);
	//printf("here at end of insert into leaf after splitting\n");
	return ret;
}


/* Inserts a new key and pointer to a node
 * into a node into which these can fit
 * without violating the B+ tree properties.
 */
node * insert_into_node(int structureId, node * root, node * n,
		int left_index, int key, node * right) {
	int i;

	for (i = n->num_keys; i > left_index; i--) {
		n->pointers[i + 1] = n->pointers[i];
		n->keys[i] = n->keys[i - 1];
	}
	n->pointers[left_index + 1] = right->actualAddr;
	n->keys[left_index] = key;
	n->num_keys++;
	writeNode(structureId, n);
	free(n);
	free(right);
	return root;
}

/* Inserts a new key and pointer to a node
 * into a node, causing the node's size to exceed
 * the order, and causing the node to split into two.
 */
node * insert_into_node_after_splitting(int structureId, node * root, node * old_node, int left_index,
		int key, node * right) {
//printf("insertintonodeaftersplitting");
	int i, j, split, k_prime;
	node * new_node, * child;
	int temp_keys[MAX_ORDER] = {0};
	int temp_pointers[MAX_ORDER+1] = {-1};



	/* First create a temporary set of keys and pointers
	 * to hold everything in order, including
	 * the new key and pointer, inserted in their
	 * correct places.
	 * Then create a new node and copy half of the
	 * keys and pointers to the old node and
	 * the other half to the new.
	 */

	//temp_pointers = (node**)malloc( (order + 1) * sizeof(node *) );

	//temp_keys = (int*)malloc( order * sizeof(int) );


	for (i = 0, j = 0; i < old_node->num_keys + 1; i++, j++) {
		if (j == left_index + 1) j++;
		temp_pointers[j] = old_node->pointers[i];//(node*)old_node->pointers[i];
	}

	for (i = 0, j = 0; i < old_node->num_keys; i++, j++) {
		if (j == left_index) j++;
		temp_keys[j] = old_node->keys[i];
	}

	temp_pointers[left_index + 1] = right->actualAddr;
	temp_keys[left_index] = key;
	//printf("heeer %d %d %d", right->actualAddr, key, left_index);
	//node *r;return r;//test
	/* Create the new node and copy
	 * half the keys and pointers to the
	 * old and half to the new.
	 */
	split = cut(order);

	//printf("new internal node: ");
	new_node = make_node(structureId, 0);
	old_node->num_keys = 0;
	for (i = 0; i < split - 1; i++) {
		old_node->pointers[i] = temp_pointers[i];
		old_node->keys[i] = temp_keys[i];
		old_node->num_keys++;
	}
	old_node->pointers[i] = temp_pointers[i];
	writeNode(structureId, old_node);
	k_prime = temp_keys[split - 1];
	for (++i, j = 0; i < order; i++, j++) {
		new_node->pointers[j] = temp_pointers[i];
		new_node->keys[j] = temp_keys[i];
		new_node->num_keys++;
	}
	new_node->pointers[j] = temp_pointers[i];

	new_node->parentAddr = old_node->parentAddr;
	writeNode(structureId, new_node);
	child = (node*)malloc(sizeof(node));
	for (i = 0; i <= new_node->num_keys; i++) {
		followNodePointer(structureId, child, new_node->pointers[i]);
		//child = (node*)new_node->pointers[i];
		child->parentAddr = new_node->actualAddr;
		writeNode(structureId, child);
	}
	free(child);

	/* Insert a new key into the parent of the two
	 * nodes resulting from the split, with
	 * the old node to the left and the new to the right.
	 */
	free(right);
	//printf("num %d", new_node->actualAddr);


	node *ret = insert_into_parent(structureId, root, old_node, k_prime, new_node);
	//printf("here at end of insert into node after splitting %d %d\n", new_node->actualAddr, ret->actualAddr);
	return ret;
}



/* Inserts a new node (leaf or internal node) into the B+ tree.
 * Returns the root of the tree after insertion.
 */
node * insert_into_parent(int structureId, node * root, node * left, int key, node * right) {
//printf("insert into parent %d", right->actualAddr);
	int left_index;

	/* Case: new root. */
	if (left->parentAddr == -1){
		return insert_into_new_root(structureId, left, key, right);

	}

	node * parent = (node*)malloc(sizeof(node));
	followNodePointer(structureId, parent, left->parentAddr);
	//parent = left->parent;

	/* Case: leaf or node. (Remainder of
	 * function body.)
	 */

	/* Find the parent's pointer to the left
	 * node.
	 */

	left_index = get_left_index(structureId, parent, left);


	/* Simple case: the new key fits into the node.
	 */

	if (parent->num_keys < order - 1){
		//printf("insert into parent branch 1\n");
		return insert_into_node(structureId, root, parent, left_index, key, right);
	}

	/* Harder case:  split a node in order
	 * to preserve the B+ tree properties.
	 */
	//printf("insert into parent branch 2\n");

	free(left);
	node *ret = insert_into_node_after_splitting(structureId, root, parent, left_index, key, right);
	//printf("here at end of insert into parent\n");
	return ret;
}

/* Creates a new root for two subtrees
 * and inserts the appropriate key into
 * the new root.
 */
node * insert_into_new_root(int structureId, node * left, int key, node * right) {
	node * root = make_node(structureId, 0);
	//printf("new root: %d\n", root->actualAddr);
	root->keys[0] = key;
	root->pointers[0] = left->actualAddr;
	root->pointers[1] = right->actualAddr;
	root->num_keys++;
	root->parentAddr = -1;
	left->parentAddr = root->actualAddr;
	right->parentAddr = root->actualAddr;
	writeNode(structureId, root);
	writeNode(structureId, left);
	writeNode(structureId, right);
	free(right);
	free(left);
	//printf("done inserting into new root");
	return root;
}



/* First insertion:
 * start a new tree.
 */
node * start_new_tree(int structureId, int key, record * pointer) {

	node * root = make_node(structureId, 1);
	root->keys[0] = key;
	root->pointers[0] = pointer->actualAddr;
	root->pointers[order - 1] = -1;
	root->parentAddr = -1;
	root->num_keys++;
	writeNode(structureId, root);
	return root;
}



/* Master insertion function.
 * Inserts a key and an associated value into
 * the B+ tree, causing the tree to be adjusted
 * however necessary to maintain the B+ tree
 * properties.
 */
node * insert(int structureId,  node * root, int key, record *pointer) {
//printf("inserting...\n");
	node * leaf;

	maxPad = log((double)numRows[structureId])/log((double)order/2)*(7+2*order);
	currentPad = 0;

	/* The current implementation ignores
	 * duplicates.
	 */

	//NOTE: I commented this out. hopefully it doesn't cause problems.
	//make sure to always find range instead of just find
	//if (find(root, key, false) != NULL)
	//	return root;


	/* Case: the tree does not exist yet.
	 * Start a new tree.
	 */
	//if(root == NULL) printf("root is null\n");

	if (root == NULL)
		return start_new_tree(structureId, key, pointer);


	//printf("address of root: %d\n", root->actualAddr);
	/* Case: the tree already exists.
	 * (Rest of function body.)
	 */
	leaf = find_leaf(structureId, root, key);
	//printf("leaf actualAddr: %d, num_keys: %d\n", leaf->actualAddr, leaf->num_keys);
	//printf("address of root now: %d\n", root->actualAddr);

	/* Case: leaf has room for key and pointer.
	 */

	if (leaf->num_keys < order - 1) {
		//printf("branch 1 %d %d\n", leaf->num_keys, order-1);
		leaf = insert_into_leaf(structureId, leaf, key, pointer);
		free(leaf);
		//update root
		currentPad++;
		opOramBlock(structureId, root->actualAddr, (Oram_Block*)root, 0);
		return root;
	}


	/* Case:  leaf must be split.
	 */
	//printf("branch 2\n");
	root = insert_into_leaf_after_splitting(structureId, root, leaf, key, pointer);
	//printf("woo!\n");
	//free(leaf); leaf is freed in other functions already
	return root;
}



// DELETION.

/* Utility function for deletion.  Retrieves
 * the index of a node's nearest neighbor (sibling)
 * to the left if one exists.  If not (the node
 * is the leftmost child), returns -1 to signify
 * this special case.
 */
int get_neighbor_index(int structureId,  node * n ) {

	int i;
	if(n->parentAddr == -1){printf("something has gone wrong.\n");};
	node *nParent = (node*)malloc(sizeof(node));
	followNodePointer(structureId, nParent, n->parentAddr);
	/* Return the index of the key to the left
	 * of the pointer in the parent pointing
	 * to n.
	 * If n is the leftmost child, this means
	 * return -1.
	 */
	for (i = 0; i <= nParent->num_keys; i++){
		if (nParent->pointers[i] == n->actualAddr){
			free(nParent);
			return i - 1;
		}
	}

	// Error state.
	printf("Search for nonexistent pointer to node in parent.\n");
	printf("Node:  %#lx\n", (unsigned long)n);
	//exit(EXIT_FAILURE);
	return -1;
}


node * remove_entry_from_node(int structureId, node * n, int key, node * pointer) {

	//printf("removing entry from node at address %d\n", n->actualAddr);

	int i, num_pointers;
	node * temp = (node*)malloc(sizeof(node));

	// Remove the key and shift other keys accordingly.
	i = 0;
	while (n->keys[i] != key)
		i++;
	for (++i; i < n->num_keys; i++)
		n->keys[i - 1] = n->keys[i];

	// Remove the pointer and shift other pointers accordingly.
	// First determine number of pointers.
	num_pointers = n->is_leaf ? n->num_keys : n->num_keys + 1;
	i = 0;
	while (n->pointers[i] != pointer->actualAddr)
		i++;
	followNodePointer(structureId, temp, n->pointers[i]);
	freeBlock(structureId, temp->actualAddr);//printf("ok\n");
	free(temp);
	temp=NULL;
	for (++i; i < num_pointers; i++)
		n->pointers[i - 1] = n->pointers[i];

	// One key fewer.
	n->num_keys--;

	// Set the other pointers to NULL for tidiness.
	// A leaf uses the last pointer to point to the next leaf.
	//printf("q\n");
	if (n->is_leaf){
		//printf("q1 %d %d %d\n", n->num_keys, order-1, n->actualAddr);
		for (i = n->num_keys; i < order - 1; i++)
			n->pointers[i] = -1;
	}
	else{//printf("q2\n");
		for (i = n->num_keys + 1; i < order; i++)
			n->pointers[i] = -1;
	}
	//printf("almost\n");
	writeNode(structureId, n);
	return n;
}


node * adjust_root(int structureId, node * root) {
//printf("adjust root\n");
	node * new_root;

	/* Case: nonempty root.
	 * Key and pointer have already been deleted,
	 * so nothing to be done.
	 */

	if (root->num_keys > 0){
		//printf("nothing to see here\n");
		return root;
	}

	/* Case: empty root.
	 */

	// If it has a child, promote
	// the first (only) child
	// as the new root.

	if (!root->is_leaf) {
		//printf("root is not leaf\n");
		//new_root = (node*)root->pointers[0];
		new_root = (node*)malloc(sizeof(node));
		followNodePointer(structureId, new_root, root->pointers[0]);
		new_root->parentAddr = -1;
		writeNode(structureId, new_root);
	}

	// If it is a leaf (has no children),
	// then the whole tree is empty.

	else{
		new_root = NULL;
		//printf("tree empty\n");
	}
	freeBlock(structureId, root->actualAddr);
	free(root);
	root = NULL;

	return new_root;
}

/* Coalesces a node that has become
 * too small after deletion
 * with a neighboring node that
 * can accept the additional entries
 * without exceeding the maximum.
 */
node * coalesce_nodes(int structureId, node * root, node * n, node * neighbor, int neighbor_index, int k_prime) {
//printf("coalesce\n");
	int i, j, neighbor_insertion_index, n_end;
	node * tmp;//= (node*)malloc(sizeof(node));

	/* Swap neighbor with node if node is on the
	 * extreme left and neighbor is to its right.
	 */

	if (neighbor_index == -1) {
		//printf("swap\n");
		tmp = n;
		n = neighbor;
		neighbor = tmp;
	}
	/*if (neighbor_index == -1) {
		memcpy(tmp, n, sizeof(node));
		memcpy(n, neighbor, sizeof(node));
		memcpy(neighbor, tmp, sizeof(node));
	}*/
	tmp = (node*)malloc(sizeof(node));

	/* Starting point in the neighbor for copying
	 * keys and pointers from n.
	 * Recall that n and neighbor have swapped places
	 * in the special case of n being a leftmost child.
	 */

	neighbor_insertion_index = neighbor->num_keys;

	/* Case:  nonleaf node.
	 * Append k_prime and the following pointer.
	 * Append all pointers and keys from the neighbor.
	 */

	if (!n->is_leaf) {

		/* Append k_prime.
		 */

		neighbor->keys[neighbor_insertion_index] = k_prime;
		neighbor->num_keys++;


		n_end = n->num_keys;

		for (i = neighbor_insertion_index + 1, j = 0; j < n_end; i++, j++) {
			neighbor->keys[i] = n->keys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
			n->num_keys--;
		}

		/* The number of pointers is always
		 * one more than the number of keys.
		 */

		neighbor->pointers[i] = n->pointers[j];
		writeNode(structureId, neighbor);
		writeNode(structureId, n);

		/* All children must now point up to the same parent.
		 */

		for (i = 0; i < neighbor->num_keys + 1; i++) {
			followNodePointer(structureId, tmp, neighbor->pointers[i]);
			//tmp = (node *)neighbor->pointers[i];
			tmp->parentAddr = neighbor->actualAddr;
			writeNode(structureId, tmp);
		}
	}

	/* In a leaf, append the keys and pointers of
	 * n to the neighbor.
	 * Set the neighbor's last pointer to point to
	 * what had been n's right neighbor.
	 */

	else {
		for (i = neighbor_insertion_index, j = 0; j < n->num_keys; i++, j++) {
			neighbor->keys[i] = n->keys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
		}
		neighbor->pointers[order - 1] = n->pointers[order - 1];
		writeNode(structureId, neighbor);
	}

	followNodePointer(structureId, tmp, n->parentAddr);
	root = delete_entry(structureId, root, tmp, k_prime, n);//printf("past deletion\n");

	freeBlock(structureId, n->actualAddr);
	if(n != NULL){
		free(n);
		n = NULL;
	}//printf("c1");
	if(neighbor != NULL){
		free(neighbor);
		neighbor = NULL;
	}//printf("c2");
	if(tmp != NULL){
		//free(tmp); removed to stop a segfault, probably introduces a leak somewhere
		tmp = NULL;
	}
	//printf("at end\n");
	return root;
}


/* Redistributes entries between two nodes when
 * one has become too small after deletion
 * but its neighbor is too big to append the
 * small node's entries without exceeding the
 * maximum
 */
node * redistribute_nodes(int structureId, node * root, node * n, node * neighbor, int neighbor_index,
		int k_prime_index, int k_prime) {
//printf("redistribute\n");
	int i;
	node * tmp = (node*)malloc(sizeof(node));
	node *nParent = (node*)malloc(sizeof(node));
	followNodePointer(structureId, nParent, n->parentAddr);

	/* Case: n has a neighbor to the left.
	 * Pull the neighbor's last key-pointer pair over
	 * from the neighbor's right end to n's left end.
	 */

	if (neighbor_index != -1) {
		//printf("redistribute: branch 1\n");
		if (!n->is_leaf)
			n->pointers[n->num_keys + 1] = n->pointers[n->num_keys];
		for (i = n->num_keys; i > 0; i--) {
			n->keys[i] = n->keys[i - 1];
			n->pointers[i] = n->pointers[i - 1];
		}
		if (!n->is_leaf) {
			n->pointers[0] = neighbor->pointers[neighbor->num_keys];
			followNodePointer(structureId, tmp, n->pointers[0]);
			//tmp = (node *)n->pointers[0];
			tmp->parentAddr = n->actualAddr;
			neighbor->pointers[neighbor->num_keys] = -1;
			n->keys[0] = k_prime;
			nParent->keys[k_prime_index] = neighbor->keys[neighbor->num_keys - 1];
			writeNode(structureId, tmp);
		}
		else {
			n->pointers[0] = neighbor->pointers[neighbor->num_keys - 1];
			neighbor->pointers[neighbor->num_keys - 1] = -1;
			n->keys[0] = neighbor->keys[neighbor->num_keys - 1];
			nParent->keys[k_prime_index] = n->keys[0];
		}
	}
	/* Case: n is the leftmost child.
	 * Take a key-pointer pair from the neighbor to the right.
	 * Move the neighbor's leftmost key-pointer pair
	 * to n's rightmost position.
	 */

	else {
		//printf("redistribute: branch 2\n");
		if (n->is_leaf) {
			n->keys[n->num_keys] = neighbor->keys[0];
			n->pointers[n->num_keys] = neighbor->pointers[0];
			nParent->keys[k_prime_index] = neighbor->keys[1];
		}
		else {
			n->keys[n->num_keys] = k_prime;
			n->pointers[n->num_keys + 1] = neighbor->pointers[0];
			followNodePointer(structureId, tmp, n->pointers[n->num_keys + 1]);
			//tmp = (node *)n->pointers[n->num_keys + 1];
			tmp->parentAddr = n->actualAddr;
			nParent->keys[k_prime_index] = neighbor->keys[0];
			writeNode(structureId, tmp);
		}
		for (i = 0; i < neighbor->num_keys - 1; i++) {
			neighbor->keys[i] = neighbor->keys[i + 1];
			neighbor->pointers[i] = neighbor->pointers[i + 1];
		}
		if (!n->is_leaf)
			neighbor->pointers[i] = neighbor->pointers[i + 1];
	}

	/* n now has one more key and one more pointer;
	 * the neighbor has one fewer of each.
	 */


	n->num_keys++;
	neighbor->num_keys--;
	writeNode(structureId, n);
	writeNode(structureId, nParent);
	writeNode(structureId, neighbor);

	free(tmp);
	free(nParent);
	free(neighbor);

	return root;
}


/* Deletes an entry from the B+ tree.
 * Removes the record and its key and pointer
 * from the leaf, and then makes all appropriate
 * changes to preserve the B+ tree properties.
 */
node * delete_entry(int structureId,  node * root, node * n, int key, void * pointer ) {

	int min_keys;
	node *neighbor;
	node *nParent;
	int neighbor_index;
	int k_prime_index, k_prime;
	int capacity;
	maxPad = log((double)numRows[structureId])/log((double)order/2)*(8+2*order/2);
	currentPad = 0;

	//printf("delete_entry called on node at address %d\n", n->actualAddr);
	//printf("pre-begin %d\n", key);
	// Remove key and pointer from node.

	n = remove_entry_from_node(structureId, n, key, (node*)pointer);
	//printf("begin\n");

	/* Case:  deletion from the root.
	 */

	if (n->actualAddr == root->actualAddr){
		//printf("branch 1\n");
		return adjust_root(structureId, root);
	}

	/* Case:  deletion from a node below the root.
	 * (Rest of function body.)
	 */

	/* Determine minimum allowable size of node,
	 * to be preserved after deletion.
	 */

	min_keys = n->is_leaf ? cut(order - 1) : cut(order) - 1;

	/* Case:  node stays at or above minimum.
	 * (The simple case.)
	 */

	if (n->num_keys >= min_keys){
		//printf("branch 2\n");
		return root;
	}

	/* Case:  node falls below minimum.
	 * Either coalescence or redistribution
	 * is needed.
	 */

	/* Find the appropriate neighbor node with which
	 * to coalesce.
	 * Also find the key (k_prime) in the parent
	 * between the pointer to node n and the pointer
	 * to the neighbor.
	 */
	//printf("finding neighbor\n");

	neighbor = (node*)malloc(sizeof(node));
	nParent = (node*)malloc(sizeof(node));
	followNodePointer(structureId, nParent, n->parentAddr);

	neighbor_index = get_neighbor_index(structureId,  n );
	k_prime_index = neighbor_index == -1 ? 0 : neighbor_index;
	k_prime = nParent->keys[k_prime_index];

	if(neighbor_index == -1){
		followNodePointer(structureId, neighbor, nParent->pointers[1]);
		//neighbor = (node*)n->parent->pointers[1];
	}
	else{
		followNodePointer(structureId, neighbor, nParent->pointers[neighbor_index]);
		//neighbor = (node*)n->parent->pointers[neighbor_index];
	}

	//neighbor = neighbor_index == -1 ? (node*)n->parent->pointers[1] :
	//	(node*)n->parent->pointers[neighbor_index];
	capacity = n->is_leaf ? order : order - 1;
	free(nParent);

	//printf("found neighbor\n");


	/* Coalescence. */

	if (neighbor->num_keys + n->num_keys < capacity){
		//printf("coalesce\n");
		return coalesce_nodes(structureId, root, n, neighbor, neighbor_index, k_prime);
	}

	/* Redistribution. */

	else{
		//printf("redistribute");
		return redistribute_nodes(structureId, root, n, neighbor, neighbor_index, k_prime_index, k_prime);
	}
}



/* Master deletion function.
 */
node* deleteKey(int structureId, node *root, int key) {

	node *key_leaf;
	record *key_record;

	key_record = find(structureId, root, key);
	key_leaf = find_leaf(structureId, root, key);

	while (key_record != NULL && key_leaf != NULL) {
		root = delete_entry(structureId, root, key_leaf, key, key_record);
		freeBlock(structureId, key_record->actualAddr);
		free(key_record);
		free(key_leaf);
		key_record = find(structureId, root, key);
		key_leaf = find_leaf(structureId, root, key);
	}

	return root;
}

//I'll probably never need this because if I want to destroy the tree, I will probably just destroy the underlying oram
//but I fixed it anyway
void destroy_tree(int structureId, node * root) {
	int i;
	node *temp = (node*)malloc(sizeof(node));
	for (i = 0; i < root->num_keys + 1; i++){
		followNodePointer(structureId, temp, root->pointers[i]);
		destroy_tree(structureId, temp);
	}

	free(temp);
	freeBlock(structureId, root->actualAddr);
	free(root);
}
