/*

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
