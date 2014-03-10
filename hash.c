/*

The MIT License (MIT)

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Trivial hash tables by evyncke@cisco.com, goal is to make the program more portable by reinventing the wheel

For sake of speed writing, it is actually implemented as linked list...

January 2014, evyncke@cisco.com

***********/

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>
#include "hash.h"

htable * htable_init(const unsigned int key_size) {
	htable * p;
	
	p = malloc(sizeof(htable)) ;
	if (p == NULL) return p ;
	p->entries_count = 0 ;
	p->keys_count = 0 ;
	p->key_size = key_size ;
	p->first = 0 ;
	return p ;
}

static void * alloc_copy(void * data, const unsigned int size) {
	void * p ;
	
	p = malloc(size) ;
	if (p != NULL) memcpy(p, data, size) ;
	return p;
}

static struct hentry * hadd(struct hentry * p, htable * table, void * key) {
	if (p == NULL) {
		struct hentry * new ;
		
		new = malloc(sizeof(struct hentry)) ;
		if (new == NULL) return new ;
		new->key = alloc_copy(key, table->key_size) ;
		if (new->key == NULL) {
				free(new) ;
				return NULL ;
		}
		new->count = 1 ;
		new->next = NULL ;
		table->keys_count ++ ;
		table->entries_count ++ ;
		return new ;
	} else if (memcmp(key, p->key, table->key_size) == 0) {
		p->count ++ ;
		table->entries_count ++ ;
		return p ;	
	} else {
		p->next = hadd(p->next, table, key) ;
		return p ;
	}
}

void htable_add(htable * table, void * key) {
	if (table == NULL) return ;
	table->entries_count ++;
	table->first = hadd(table->first, table, key) ;
}

static int hexists(struct hentry * p, htable * table, void * key) {
	if (p == NULL)
		return 0 ;
	else if (memcmp(key, p->key, table->key_size) == 0)
		return -1 ;
	else
		return hexists(p->next, table, key) ;
}

int htable_exists(htable * table, void * key) {
	if (table == NULL) 	
		return 0 ;
	else
		return hexists(table->first, table, key) ;
}

void htable_dump(htable * table, htable_printer printer) {
	struct hentry * p ;
	int i ;
	
	if (table == NULL) return ;
	for (p = table->first; p != NULL; p = p->next) {
		if (printer == NULL)
			for (i = 0; i < table->key_size; i++)
				printf("%2.2X ", p->key[i]) ;
		else
			printer(p->key, table->key_size) ;
		printf(" (%ld)\n", p->count) ;	
	}
}

void htable_ipv6_printer(unsigned char * key, unsigned int key_size) {
	char s[INET6_ADDRSTRLEN] ;
	
	if (key_size != 16) printf("Invalid key_size(%d) in htable_ipv6_printer", key_size) ;
	printf("%s", inet_ntop(AF_INET6, key, s, INET6_ADDRSTRLEN)) ;
}
	 
unsigned long int htable_size(htable * table) {
		if (table == NULL)
			return 0 ;
		else
			return table->keys_count ;
}
