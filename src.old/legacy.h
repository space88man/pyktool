

typedef struct {
	int sz;
	char *data;
} foo_t;


foo_t  pkcs12_pbe_crypt(int pbe_nid, char *password, int passlen, char* salt, int saltlen, int iter, char *in, int inlen, int op);
foo_t  pkcs12_kdf(int hash, char *password, int passlen, char* salt, int saltlen, int id, int iter, int n);
