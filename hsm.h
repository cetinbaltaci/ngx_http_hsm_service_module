#ifndef __HSM_H__
#define __HSM_H__

#include "cryptoki.h"

void HSMClose();
CK_RV HSMOpen(const char *libname, const char *confName) ;
unsigned long HSMGetSlotID(const char *slotName);
char *HSMGetManifactureID();
CK_RV HSMEncryptWithAES(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *plainBuf, size_t plainBufLen, unsigned char **cipherBuf, size_t *cipherBufLen);
CK_RV HSMDecryptWithAES(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *cipherBuf, size_t cipherBufLen, unsigned char **plainBuf, size_t *plainBufLen);

CK_RV HSMSign(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *inBuf, size_t inBufLen, unsigned char **outBuf, size_t *outBufLen) ;

CK_RV HSMVerify(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *inBuf, size_t inBufLen, unsigned char *signBuf, size_t signBufLen) ;
    
#endif