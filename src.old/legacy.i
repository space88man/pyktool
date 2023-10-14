%module(package="pyktool") legacy

%begin %{
#define SWIG_FILE_WITH_INIT
#define SWIG_PYTHON_STRICT_BYTE_CHAR
#include "legacy.h"
%}


typedef struct {
	int sz;
	char *data;
} foo_t;

%apply (char *STRING, int LENGTH) { (char *password, int passlen) };
%apply (char *STRING, int LENGTH) { (char *salt, int saltlen) };
%apply (char *STRING, int LENGTH) { (char *in, int inlen) };


%typemap(out) foo_t {
	int len;
	$result = PyList_New(2);
	if ($1.sz < 0) {
		len = 0;
	} else {
		len = $1.sz;
	}
	PyList_SetItem($result, 1, PyBytes_FromStringAndSize($1.data, len));
	PyList_SetItem($result, 0, PyLong_FromLong($1.sz));
}
%typemap(newfree) foo_t {
	free($1.data);
}
%newobject pbe_crypt;
foo_t pkcs12_pbe_crypt(int pbe_nid, char *password, int passlen, char* salt, int saltlen, int iter, char *in, int inlen, int op);
%newobject pkcs12_kdf;
foo_t  pkcs12_kdf(int hash, char *password, int passlen, char* salt, int saltlen, int id, int iter, int n);


