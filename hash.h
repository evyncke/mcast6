/*

The MIT License (MIT)

Copyright (c) 2014 Eric Vyncke

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

Trivial hash tables by evyncke@cisco.com

January 18, 2014

***********/


struct hentry {
	unsigned long int count ;
	struct hentry * next ;
	unsigned char * key ;
} ;

typedef struct {
	unsigned long entries_count ;
	unsigned long keys_count ;
	unsigned int key_size ;
	struct hentry * first ;
} htable ;

typedef void (*htable_printer)(unsigned char * key, unsigned int key_size) ;

htable * htable_init(const unsigned int key_size) ;

void htable_add(htable * table, void * key) ;

int htable_exists(htable * table, void * key) ;

void htable_dump(htable * table, htable_printer printer) ;

unsigned long int htable_size(htable * table) ;

void htable_ipv6_printer(unsigned char * key, unsigned int key_size) ;
