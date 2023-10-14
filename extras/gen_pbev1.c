#include <assert.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

/**
 *  obj_mac.h:#define NID_pbe_WithSHA1And128BitRC4            144
 *  obj_mac.h:#define NID_pbe_WithSHA1And40BitRC4             145
 *  obj_mac.h:#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC          146
 *  obj_mac.h:#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC          147
 *  obj_mac.h:#define NID_pbe_WithSHA1And128BitRC2_CBC                148
 *  obj_mac.h:#define NID_pbe_WithSHA1And40BitRC2_CBC         149
 *
 *  gcc -o gen_pbev1 gen_pbev1.c -lcrypto
 **/


char* tohex(unsigned char *bytes, int len){

	char buffer[256];
	for (int i = 0; i<len; i++) {
		sprintf(buffer+2*i, "%02X", bytes[i]);
	}
	buffer[2*len+1] = '\x00';

	return OPENSSL_memdup(buffer, 2*len+1);
}

int main(int argc, char**argv) {

	unsigned char salt[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
	unsigned char in[37]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a";
	int inlen = strlen(in);
	
	const char *pass = "this_is_a_very_long_secure_Passw0rd";

	int passlen = strlen(pass);
	int rc;
	int outlen;
	unsigned char output[512];
	unsigned char *out;
	char *str;

	const char *names[] = { "RC4_128", "RC4_40", "DES3", "DES2", "RC2_128", "RC2_40" };

	X509_ALGOR *pbe;
	int pbe_nid = -1;
	unsigned char *back;
	int backlen;

	printf("---\n");
	printf("salt: %s\n", salt);
	printf("plaintext: %s\n", in);
	printf("password: %s\n", pass);
		
	for (pbe_nid = 144; pbe_nid < 150; pbe_nid++) {

		printf("%s:\n", names[pbe_nid-144]);

		pbe = PKCS5_pbe_set(pbe_nid, 2000, salt, 32);

		assert(pbe);

		PKCS12_pbe_crypt(pbe, pass, passlen, in, inlen, &out, &outlen, 1);

		str = tohex(out, outlen);
		
		printf("  ciphertext: %s\n", str);
		OPENSSL_free(str);


		PKCS12_pbe_crypt(pbe, pass, passlen, out, outlen, &back, &backlen, 0);
		*(back + backlen) = '\x00';
		//printf("bcklen %d %s\n", backlen, back);

		OPENSSL_free(back);
		OPENSSL_free(out);
	}
        // 145-149
	printf("PKCS12_KDF:\n");
	for (int i = 1; i<4; i++) {
		PKCS12_key_gen_asc(pass, passlen, salt, 32, i, 2000, 40,
				   output, EVP_sha1());
		str = tohex(output, 40);
		printf("  - %s\n", str);
		OPENSSL_free(str);
	}
	printf("PKCS12_KDF_SHA256:\n");
	for (int i = 1; i<4; i++) {
		PKCS12_key_gen_asc(pass, passlen, salt, 32, i, 2000, 40,
				   output, EVP_sha256());
		str = tohex(output, 40);
		printf("  - %s\n", str);
		OPENSSL_free(str);
	}
}
