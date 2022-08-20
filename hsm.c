
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <dlfcn.h>

#include "hsm.h"

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
#define GLOBAL_SESSION 0

CK_FUNCTION_LIST    *funcs = NULL;
typedef unsigned long (*C_GetFunctionList_t) (CK_FUNCTION_LIST_PTR_PTR);
void *hHSMLib = NULL;


CK_SLOT_ID C_HSMGetSlotID(const char *tokenName);

CK_SESSION_HANDLE C_HSMOpenSession(CK_SLOT_ID slot, const char *pin);
int C_HSMCloseSession(CK_SESSION_HANDLE *hSession) ;

CK_OBJECT_HANDLE C_HSMFindObjectFromName(CK_SESSION_HANDLE hSession, const char *label) ;
CK_RV C_HSMEncrypt(CK_SESSION_HANDLE hSession, const char *key_label, 
    unsigned char *plainBuf, size_t plainBufLen, 
    unsigned char **cipherBuf, size_t *cipherBufLen);

CK_RV C_HSMDecrypt(CK_SESSION_HANDLE hSession, const char *key_label, 
    unsigned char *cipherBuf, size_t cipherBufLen, 
    unsigned char **plainBuf, size_t *plainBufLen) ;

CK_BYTE IV[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25
};

size_t pkcs7_padding_add(unsigned char *buf, size_t bufLen, unsigned int blockSize, unsigned char **outBuf) {
    unsigned char pad_size = (unsigned char)(( blockSize - (bufLen % blockSize) )  & 0xFF );
    if (pad_size == blockSize) pad_size = 0 ;
    size_t newBuf_size = bufLen + pad_size; 

    *outBuf = (unsigned char *) calloc(newBuf_size, sizeof(unsigned char)) ;
    memcpy(*outBuf, buf, bufLen) ;

    memset(&(*outBuf)[bufLen], pad_size,(size_t)pad_size) ;

    return newBuf_size ;
}

size_t pkcs7_padding_remove(unsigned char *buf, size_t bufLen, unsigned int blockSize) {
    unsigned char pad_size = (unsigned char)( buf[bufLen -1]   & 0xFF );
    
    if (pad_size > 0  && pad_size < blockSize)  {
        unsigned char *tmp = (unsigned char *)calloc(pad_size, sizeof(unsigned char));
        memset(tmp, pad_size, pad_size) ;
        
        if (memcmp(&buf[bufLen - pad_size], tmp, pad_size) == 0 ) {
            memset(&buf[bufLen - pad_size], 0x0, pad_size ) ;
            bufLen -= pad_size; 
        }
        free(tmp);
    } 
    return bufLen ;
}

void HSMClose() {
    if (funcs) 
        funcs->C_Finalize(NULL);
    funcs = NULL ;
    if (hHSMLib) 
        dlclose(hHSMLib) ;
    hHSMLib = NULL ;
}

CK_RV HSMOpen(const char *libname) {
    CK_RV rc = CKR_GENERAL_ERROR ;
    C_GetFunctionList_t fn_C_GetFunctionList ; 

    hHSMLib = dlopen(libname, RTLD_NOW);
    if ( hHSMLib ) {
        fn_C_GetFunctionList = (C_GetFunctionList_t) dlsym(hHSMLib,"C_GetFunctionList");
        if (fn_C_GetFunctionList) {
            rc = fn_C_GetFunctionList(&funcs) ;
            if (rc == CKR_OK) 
                rc = funcs->C_Initialize(NULL);
        }
    }

    if (rc != CKR_OK)  
        HSMClose() ;
    return rc ;
}

char *HSMGetManifactureID() {
    char *msg = NULL; 
    if (funcs) {
        CK_INFO info ;
        memset(&info, 0x0, sizeof(CK_INFO));
        CK_RV rc = funcs->C_GetInfo(&info) ;
        if (rc == CKR_OK) 
            msg = strdup( (char *)info.manufacturerID );
    }
    return msg ;
}

CK_SESSION_HANDLE C_HSMOpenSession(CK_SLOT_ID slot, const char *pin) {
    if (! funcs)
        return CK_INVALID_HANDLE;

    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_RV rv = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
    if (rv == CKR_OK) {
        rv = funcs->C_Login(hSession,CKU_USER, (unsigned char *)pin, strlen(pin));
        if (rv != CKR_OK)
            C_HSMCloseSession(&hSession) ;
    }

    return hSession ;
}


int C_HSMCloseSession(CK_SESSION_HANDLE *hSession)  {
    if (!funcs) 
        return -1 ;

    if (*hSession != CK_INVALID_HANDLE) {
        funcs->C_Logout(*hSession) ;
        funcs->C_CloseSession(*hSession) ;
        *hSession = CK_INVALID_HANDLE ;
    }
    return 0 ;
}



CK_SLOT_ID C_HSMGetSlotID(const char *tokenName) { 
    CK_SLOT_ID slotID = CK_UNAVAILABLE_INFORMATION ;
    
    if (!funcs)
        return slotID ;

    CK_ULONG ulCount = 0 ;
    CK_RV rv = funcs->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
    if (rv != CKR_OK || ulCount == 0)
        return slotID ;

    char name[33] = {0};
    memset(name, 0x20, 32) ;
    memcpy(name, tokenName, strlen(tokenName) ) ;

    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)calloc(ulCount, sizeof(CK_SLOT_ID)) ;
    rv = funcs->C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
    if (rv == CKR_OK) {
        CK_TOKEN_INFO tokenInfo;
        for(unsigned long i = 0 ; i < ulCount ; i++) {
            memset(&tokenInfo, 0x0 , sizeof(tokenInfo));
            rv = funcs->C_GetTokenInfo(pSlotList[i] , &tokenInfo) ;
            if (rv == CKR_OK && strncmp((char *) tokenInfo.label , name, 32) == 0 ) {
                slotID = pSlotList[i] ;
                break ;
            } 
        }
    }

    if(pSlotList) 
        free(pSlotList);

    return slotID ;
}

unsigned long HSMGetSlotID(const char *slotName) {
    return C_HSMGetSlotID(slotName);
}

CK_OBJECT_HANDLE C_HSMFindObjectFromName(CK_SESSION_HANDLE hSession, const char *label) {
    
    /*
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, (void *)label, strlen(label)}
    };
    */
    
    CK_ATTRIBUTE tmpl[] = { {CKA_LABEL, (void *)label, strlen(label)} };

    if (!funcs ) return CK_INVALID_HANDLE ;
    if (hSession == CK_INVALID_HANDLE) return CK_INVALID_HANDLE ;

    CK_RV rc = funcs->C_FindObjectsInit(hSession, tmpl,1) ;
    if (rc != CKR_OK)
        return CK_INVALID_HANDLE ;

    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE ;
    unsigned long objCount = 0 ;

    rc = funcs->C_FindObjects(hSession, &hKey, 1, &objCount) ;

    if (rc != CKR_OK || objCount != 1)
        return CK_INVALID_HANDLE ;

    funcs->C_FindObjectsFinal(hSession) ;
    return hKey ;
}

CK_RV C_HSMEncrypt(CK_SESSION_HANDLE hSession, const char *key_label, 
    unsigned char *plainBuf, size_t plainBufLen, 
    unsigned char **cipherBuf, size_t *cipherBufLen) {
    
    if (!funcs ) return CKR_GENERAL_ERROR ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;

    CK_OBJECT_HANDLE hKey = C_HSMFindObjectFromName(hSession, key_label)  ;
    if (hKey == CK_INVALID_HANDLE) 
        return CKR_GENERAL_ERROR ;

    CK_LONG objSize = 0  ;
    CK_LONG keyType = 0 ;

    CK_ATTRIBUTE template[] = {
        {CKA_KEY_TYPE, &keyType, sizeof(CK_LONG)},
        {CKA_VALUE_LEN, &objSize, sizeof(CK_LONG)}
    };

    CK_RV rv = funcs->C_GetAttributeValue(hSession, hKey, template, ARRAY_LEN(template)) ;
    if (rv != CKR_OK)
        return rv ;
    
    unsigned char *bufWithPadding = NULL ;
    size_t len = pkcs7_padding_add(plainBuf, plainBufLen, objSize, &bufWithPadding) ;

    CK_MECHANISM mechanism ;
    switch (keyType)
    {
        case CKK_AES: 
            mechanism.mechanism = CKM_AES_CBC ;
            break;
        case CKK_DES: 
            mechanism.mechanism = CKM_DES_CBC ;
            break;
        case CKK_DES3:
            mechanism.mechanism = CKM_DES3_CBC ;
            break;                 
        default:
            mechanism.mechanism = 0 ;
            break;
    }
    mechanism.pParameter = IV ;
    mechanism.ulParameterLen = sizeof(IV);

    rv = funcs->C_EncryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) 
        return rv ;

    *cipherBufLen = len + objSize ;
    *cipherBuf = (unsigned char *) calloc(*cipherBufLen , sizeof(unsigned char)) ;

    rv = funcs->C_Encrypt(hSession, bufWithPadding, len, *cipherBuf, cipherBufLen);

    *cipherBuf = realloc(*cipherBuf, *cipherBufLen) ;

    if (bufWithPadding) 
        free(bufWithPadding);
    return rv ;
}


CK_RV C_HSMDecrypt(CK_SESSION_HANDLE hSession, const char *key_label, 
    unsigned char *cipherBuf, size_t cipherBufLen, unsigned char **plainBuf, size_t *plainBufLen) 
{
    
    if (!funcs ) return CKR_GENERAL_ERROR ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;

    CK_OBJECT_HANDLE hKey = C_HSMFindObjectFromName(hSession, key_label)  ;
    if (hKey == CK_INVALID_HANDLE) 
        return CKR_GENERAL_ERROR ;

    CK_LONG objSize = 0  ;
    CK_LONG keyType = 0 ;

    CK_ATTRIBUTE template[] = {
        {CKA_KEY_TYPE, &keyType, sizeof(CK_LONG)},
        {CKA_VALUE_LEN, &objSize, sizeof(CK_LONG)}
    };

    CK_RV rv = funcs->C_GetAttributeValue(hSession, hKey, template, ARRAY_LEN(template)) ;
    if (rv != CKR_OK)
        return rv ;

    CK_MECHANISM mechanism ;
    switch (keyType)
    {
        case CKK_AES: 
            mechanism.mechanism = CKM_AES_CBC ;
            break;
        case CKK_DES: 
            mechanism.mechanism = CKM_DES_CBC ;
            break;
        case CKK_DES3:
            mechanism.mechanism = CKM_DES3_CBC ;
            break;                 
        default:
            mechanism.mechanism = 0 ;
            break;
    }
    mechanism.pParameter = IV ;
    mechanism.ulParameterLen = sizeof(IV);

    rv = funcs->C_DecryptInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) 
        return rv ;

    *plainBufLen = cipherBufLen + objSize ;
    *plainBuf = (unsigned char *) calloc(*plainBufLen , sizeof(unsigned char)) ;
    rv = funcs->C_Decrypt(hSession, cipherBuf, cipherBufLen, *plainBuf, plainBufLen);
    *plainBufLen = pkcs7_padding_remove(*plainBuf, *plainBufLen, objSize) ;
    
    *plainBuf = (unsigned char *)realloc(*plainBuf, *plainBufLen);
    return rv ;
}

CK_RV C_HSMSign(CK_SESSION_HANDLE hSession, const char *key_label, unsigned char *inBuf, size_t inBufLen, 
        unsigned char **outBuf, size_t *outBufLen) 
{
    if (!funcs ) return CKR_GENERAL_ERROR ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;

    CK_OBJECT_HANDLE hKey = C_HSMFindObjectFromName(hSession, key_label)  ;

    if (hKey == CK_INVALID_HANDLE) 
        return CKR_GENERAL_ERROR ;

    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS, NULL_PTR, 0
    } ;

    unsigned char digest_header[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    unsigned char *digest_info = (unsigned char *)calloc(sizeof(digest_header) + inBufLen, sizeof(unsigned char));
    memcpy(digest_info, digest_header, sizeof(digest_header)) ;
    memcpy(&digest_info[sizeof(digest_header)], inBuf, inBufLen) ;

    CK_RV rv = funcs->C_SignInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) return rv ;

    *outBufLen = 512 ;
    *outBuf = (unsigned char *)calloc(*outBufLen, sizeof(unsigned char));
    rv = funcs->C_Sign(hSession, (CK_BYTE_PTR)digest_info, sizeof(digest_header) + inBufLen, *outBuf, outBufLen);
    *outBuf = (unsigned char *)realloc(*outBuf, *outBufLen);
    free(digest_info);
    return rv ;
}

CK_RV C_HSMVerify(CK_SESSION_HANDLE hSession, const char *key_label, unsigned char *inBuf, size_t inBufLen, 
        unsigned char *signBuf, size_t signBufLen) 
{
    if (!funcs ) return CKR_GENERAL_ERROR ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;

    CK_OBJECT_HANDLE hKey = C_HSMFindObjectFromName(hSession, key_label)  ;
    if (hKey == CK_INVALID_HANDLE) 
        return CKR_GENERAL_ERROR ;
    
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS, NULL_PTR, 0
    } ;

    CK_RV rv = funcs->C_VerifyInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK) return rv ;

    unsigned char digest_header[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    unsigned char *digest_info = (unsigned char *)calloc(sizeof(digest_header) + inBufLen, sizeof(unsigned char));
    memcpy(digest_info, digest_header, sizeof(digest_header)) ;
    memcpy(&digest_info[sizeof(digest_header)], inBuf, inBufLen) ;    
    rv = funcs->C_Verify(hSession, (CK_BYTE_PTR)digest_info, sizeof(digest_header) + inBufLen, signBuf, signBufLen);
    free(digest_info);

    return rv ;
}

CK_RV HSMEncrypt(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *plainBuf, size_t plainBufLen, unsigned char **cipherBuf, size_t *cipherBufLen) 
{
    if (slotID == CK_UNAVAILABLE_INFORMATION || !key_label || !plainBuf || !plainBufLen) return CKR_GENERAL_ERROR;

    CK_SESSION_HANDLE hSession = C_HSMOpenSession(slotID, pass ) ;
    if (hSession == CK_INVALID_HANDLE)  return CKR_GENERAL_ERROR ;

    CK_RV rv= C_HSMEncrypt(hSession, key_label, plainBuf, plainBufLen, cipherBuf, cipherBufLen) ;
    C_HSMCloseSession(&hSession);

    return rv  ;
}

CK_RV HSMDecrypt(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *cipherBuf, size_t cipherBufLen, unsigned char **plainBuf, size_t *plainBufLen) 
{
    if (slotID == CK_UNAVAILABLE_INFORMATION || !key_label || !cipherBuf || !cipherBufLen) return CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE hSession = C_HSMOpenSession(slotID, pass ) ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;

    CK_RV rv= C_HSMDecrypt(hSession, key_label, cipherBuf, cipherBufLen, plainBuf, plainBufLen) ;
    C_HSMCloseSession(&hSession);
    return rv  ;
}

CK_RV HSMVerify(unsigned long slotID, const char *user, const char *pass, 
    const char *key_label, unsigned char *inBuf, size_t inBufLen, unsigned char *signBuf, size_t signBufLen) 
{
    if (slotID == CK_UNAVAILABLE_INFORMATION  || !key_label  || !inBuf || !inBufLen || !signBuf || !signBufLen) return CKR_GENERAL_ERROR;

    CK_SESSION_HANDLE hSession = C_HSMOpenSession(slotID, pass ) ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;
    CK_RV rv= C_HSMVerify(hSession, key_label, inBuf, inBufLen, signBuf, signBufLen) ;
    C_HSMCloseSession(&hSession);
    
    return rv  ;
}

CK_RV HSMSign(unsigned long slotID,  const char *user, const char *pass, 
    const char *key_label, unsigned char *inBuf, size_t inBufLen, unsigned char **outBuf, size_t *outBufLen) 
{
    if (slotID == CK_UNAVAILABLE_INFORMATION || !key_label  || !inBuf || !inBufLen ) return CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE hSession = C_HSMOpenSession(slotID, pass ) ;
    if (hSession == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR ;
    CK_RV rv= C_HSMSign(hSession, key_label, inBuf, inBufLen, outBuf, outBufLen) ;
    C_HSMCloseSession(&hSession);
    return rv  ;
}
