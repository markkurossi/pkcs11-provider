//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package ipc

import (
	"fmt"
)

// Flags that describe capabilities of a slot.
const (
	CkfTokenPresent    CKFlags = 0x00000001
	CkfRemovableDevice CKFlags = 0x00000002
	CkfHWSlot          CKFlags = 0x00000004
)

// Flags that describe capabilities of a token.
const (
	CkfRNG                         CKFlags = 0x00000001
	CkfWriteProtected              CKFlags = 0x00000002
	CkfLoginRequired               CKFlags = 0x00000004
	CkfUserPinInitialized          CKFlags = 0x00000008
	CkfRestoreKeyNotNeeded         CKFlags = 0x00000020
	CkfClockOnToken                CKFlags = 0x00000040
	CkfProtectedAuthenticationPath CKFlags = 0x00000100
	CkfDualCryptoOperations        CKFlags = 0x00000200
	CkfTokenInitialized            CKFlags = 0x00000400
	CkfSecondaryAuthentication     CKFlags = 0x00000800
	CkfUserPINCountLow             CKFlags = 0x00010000
	CkfUserPINFinalTry             CKFlags = 0x00020000
	CkfUserPINLocked               CKFlags = 0x00040000
	CkfUserPINToBeChanged          CKFlags = 0x00080000
	CkfSOPINCountLow               CKFlags = 0x00100000
	CkfSOPINFinalTry               CKFlags = 0x00200000
	CkfSOPINLocked                 CKFlags = 0x00400000
	CkfSOPINToBeChanged            CKFlags = 0x00800000
	CkfErrorState                  CKFlags = 0x01000000
)

// Flags that describe capabilities of a mechanism.
const (
	CkfHW              CKFlags = 0x00000001
	CkfMessageEncrypt  CKFlags = 0x00000002
	CkfMessageDecrypt  CKFlags = 0x00000004
	CkfMessageSign     CKFlags = 0x00000008
	CkfMessageVerify   CKFlags = 0x00000010
	CkfMultiMessge     CKFlags = 0x00000020
	CkfFindObjects     CKFlags = 0x00000040
	CkfEncrypt         CKFlags = 0x00000100
	CkfDecrypt         CKFlags = 0x00000200
	CkfDigest          CKFlags = 0x00000400
	CkfSign            CKFlags = 0x00000800
	CkfSignRecover     CKFlags = 0x00001000
	CkfVerify          CKFlags = 0x00002000
	CkfVerifyRecover   CKFlags = 0x00004000
	CkfGenerate        CKFlags = 0x00008000
	CkfGenerateKeyPair CKFlags = 0x00010000
	CkfWrap            CKFlags = 0x00020000
	CkfUnwrap          CKFlags = 0x00040000
	CkfDerive          CKFlags = 0x00080000
	CkfECFP            CKFlags = 0x00100000
	CkfECF2M           CKFlags = 0x00200000
	CkfECECParameters  CKFlags = 0x00400000
	CkfECOID           CKFlags = 0x00800000
	CkfECNamedCurve    CKFlags = 0x00800000
	CkfECUncompress    CKFlags = 0x01000000
	CkfECCompress      CKFlags = 0x02000000
	CkfECCurvename     CKFlags = 0x04000000
	CkfExtension       CKFlags = 0x80000000
)

// Mechanism types.
const (
	CkmRSAPKCSKeyPairGen           CKMechanismType = 0x00000000
	CkmRSAPKCS                     CKMechanismType = 0x00000001
	CkmRSA9796                     CKMechanismType = 0x00000002
	CkmRSAX509                     CKMechanismType = 0x00000003
	CkmMD2RSAPKCS                  CKMechanismType = 0x00000004
	CkmMD5RSAPKCS                  CKMechanismType = 0x00000005
	CkmSHA1RSAPKCS                 CKMechanismType = 0x00000006
	CkmRIPEMD128RSAPKCS            CKMechanismType = 0x00000007
	CkmRIPEMD160RSAPKCS            CKMechanismType = 0x00000008
	CkmRSAPKCSOAEP                 CKMechanismType = 0x00000009
	CkmRSAX931KeyPairGen           CKMechanismType = 0x0000000A
	CkmRSAX931                     CKMechanismType = 0x0000000B
	CkmSHA1RSAX931                 CKMechanismType = 0x0000000C
	CkmRSAPKCSPSS                  CKMechanismType = 0x0000000D
	CkmSHA1RSAPKCSPSS              CKMechanismType = 0x0000000E
	CkmDSAKeyPairGen               CKMechanismType = 0x00000010
	CkmDSA                         CKMechanismType = 0x00000011
	CkmDSASHA1                     CKMechanismType = 0x00000012
	CkmDSASHA224                   CKMechanismType = 0x00000013
	CkmDSASHA256                   CKMechanismType = 0x00000014
	CkmDSASHA384                   CKMechanismType = 0x00000015
	CkmDSASHA512                   CKMechanismType = 0x00000016
	CkmDSASHA3224                  CKMechanismType = 0x00000018
	CkmDSASHA3256                  CKMechanismType = 0x00000019
	CkmDSASHA3384                  CKMechanismType = 0x0000001A
	CkmDSASHA3512                  CKMechanismType = 0x0000001B
	CkmDHPKCSKeyPairGen            CKMechanismType = 0x00000020
	CkmDHPKCSDerive                CKMechanismType = 0x00000021
	CkmX942DHKeyPairGen            CKMechanismType = 0x00000030
	CkmX942DHDerive                CKMechanismType = 0x00000031
	CkmX942DHHybridDerive          CKMechanismType = 0x00000032
	CkmX942MQVDerive               CKMechanismType = 0x00000033
	CkmSHA256RSAPKCS               CKMechanismType = 0x00000040
	CkmSHA384RSAPKCS               CKMechanismType = 0x00000041
	CkmSHA512RSAPKCS               CKMechanismType = 0x00000042
	CkmSHA256RSAPKCSPSS            CKMechanismType = 0x00000043
	CkmSHA384RSAPKCSPSS            CKMechanismType = 0x00000044
	CkmSHA512RSAPKCSPSS            CKMechanismType = 0x00000045
	CkmSHA224RSAPKCS               CKMechanismType = 0x00000046
	CkmSHA224RSAPKCSPSS            CKMechanismType = 0x00000047
	CkmSHA512224                   CKMechanismType = 0x00000048
	CkmSHA512224HMAC               CKMechanismType = 0x00000049
	CkmSHA512224HMACGeneral        CKMechanismType = 0x0000004A
	CkmSHA512224KeyDerivation      CKMechanismType = 0x0000004B
	CkmSHA512256                   CKMechanismType = 0x0000004C
	CkmSHA512256HMAC               CKMechanismType = 0x0000004D
	CkmSHA512256HMACGeneral        CKMechanismType = 0x0000004E
	CkmSHA512256KeyDerivation      CKMechanismType = 0x0000004F
	CkmSHA512T                     CKMechanismType = 0x00000050
	CkmSHA512THMAC                 CKMechanismType = 0x00000051
	CkmSHA512THMACGeneral          CKMechanismType = 0x00000052
	CkmSHA512TKeyDerivation        CKMechanismType = 0x00000053
	CkmSHA3256RSAPKCS              CKMechanismType = 0x00000060
	CkmSHA3384RSAPKCS              CKMechanismType = 0x00000061
	CkmSHA3512RSAPKCS              CKMechanismType = 0x00000062
	CkmSHA3256RSAPKCSPSS           CKMechanismType = 0x00000063
	CkmSHA3384RSAPKCSPSS           CKMechanismType = 0x00000064
	CkmSHA3512RSAPKCSPSS           CKMechanismType = 0x00000065
	CkmSHA3224RSAPKCS              CKMechanismType = 0x00000066
	CkmSHA3224RSAPKCSPSS           CKMechanismType = 0x00000067
	CkmRC2KeyGen                   CKMechanismType = 0x00000100
	CkmRC2ECB                      CKMechanismType = 0x00000101
	CkmRC2CBC                      CKMechanismType = 0x00000102
	CkmRC2MAC                      CKMechanismType = 0x00000103
	CkmRC2MACGeneral               CKMechanismType = 0x00000104
	CkmRC2CBCPad                   CKMechanismType = 0x00000105
	CkmRC4KeyGen                   CKMechanismType = 0x00000110
	CkmRC4                         CKMechanismType = 0x00000111
	CkmDESKeyGen                   CKMechanismType = 0x00000120
	CkmDESECB                      CKMechanismType = 0x00000121
	CkmDESCBC                      CKMechanismType = 0x00000122
	CkmDESMAC                      CKMechanismType = 0x00000123
	CkmDESMACGeneral               CKMechanismType = 0x00000124
	CkmDESCBCPad                   CKMechanismType = 0x00000125
	CkmDES2KeyGen                  CKMechanismType = 0x00000130
	CkmDES3KeyGen                  CKMechanismType = 0x00000131
	CkmDES3ECB                     CKMechanismType = 0x00000132
	CkmDES3CBC                     CKMechanismType = 0x00000133
	CkmDES3MAC                     CKMechanismType = 0x00000134
	CkmDES3MACGeneral              CKMechanismType = 0x00000135
	CkmDES3CBCPad                  CKMechanismType = 0x00000136
	CkmDES3CMACGeneral             CKMechanismType = 0x00000137
	CkmDES3CMAC                    CKMechanismType = 0x00000138
	CkmCDMFKeyGen                  CKMechanismType = 0x00000140
	CkmCDMFECB                     CKMechanismType = 0x00000141
	CkmCDMFCBC                     CKMechanismType = 0x00000142
	CkmCDMFMAC                     CKMechanismType = 0x00000143
	CkmCDMFMACGeneral              CKMechanismType = 0x00000144
	CkmCDMFCBCPad                  CKMechanismType = 0x00000145
	CkmDESOFB64                    CKMechanismType = 0x00000150
	CkmDESOFB8                     CKMechanismType = 0x00000151
	CkmDESCFB64                    CKMechanismType = 0x00000152
	CkmDESCFB8                     CKMechanismType = 0x00000153
	CkmMD2                         CKMechanismType = 0x00000200
	CkmMD2HMAC                     CKMechanismType = 0x00000201
	CkmMD2HMACGeneral              CKMechanismType = 0x00000202
	CkmMD5                         CKMechanismType = 0x00000210
	CkmMD5HMAC                     CKMechanismType = 0x00000211
	CkmMD5HMACGeneral              CKMechanismType = 0x00000212
	CkmSHA1                        CKMechanismType = 0x00000220
	CkmSHA1HMAC                    CKMechanismType = 0x00000221
	CkmSHA1HMACGeneral             CKMechanismType = 0x00000222
	CkmRIPEMD128                   CKMechanismType = 0x00000230
	CkmRIPEMD128HMAC               CKMechanismType = 0x00000231
	CkmRIPEMD128HMACGeneral        CKMechanismType = 0x00000232
	CkmRIPEMD160                   CKMechanismType = 0x00000240
	CkmRIPEMD160HMAC               CKMechanismType = 0x00000241
	CkmRIPEMD160HMACGeneral        CKMechanismType = 0x00000242
	CkmSHA256                      CKMechanismType = 0x00000250
	CkmSHA256HMAC                  CKMechanismType = 0x00000251
	CkmSHA256HMACGeneral           CKMechanismType = 0x00000252
	CkmSHA224                      CKMechanismType = 0x00000255
	CkmSHA224HMAC                  CKMechanismType = 0x00000256
	CkmSHA224HMACGeneral           CKMechanismType = 0x00000257
	CkmSHA384                      CKMechanismType = 0x00000260
	CkmSHA384HMAC                  CKMechanismType = 0x00000261
	CkmSHA384HMACGeneral           CKMechanismType = 0x00000262
	CkmSHA512                      CKMechanismType = 0x00000270
	CkmSHA512HMAC                  CKMechanismType = 0x00000271
	CkmSHA512HMACGeneral           CKMechanismType = 0x00000272
	CkmSecurIDKeyGen               CKMechanismType = 0x00000280
	CkmSecurID                     CKMechanismType = 0x00000282
	CkmHOTPKeyGen                  CKMechanismType = 0x00000290
	CkmHOTP                        CKMechanismType = 0x00000291
	CkmACTI                        CKMechanismType = 0x000002A0
	CkmACTIKeyGen                  CKMechanismType = 0x000002A1
	CkmSHA3256                     CKMechanismType = 0x000002B0
	CkmSHA3256HMAC                 CKMechanismType = 0x000002B1
	CkmSHA3256HMACGeneral          CKMechanismType = 0x000002B2
	CkmSHA3256KeyGen               CKMechanismType = 0x000002B3
	CkmSHA3224                     CKMechanismType = 0x000002B5
	CkmSHA3224HMAC                 CKMechanismType = 0x000002B6
	CkmSHA3224HMACGeneral          CKMechanismType = 0x000002B7
	CkmSHA3224KeyGen               CKMechanismType = 0x000002B8
	CkmSHA3384                     CKMechanismType = 0x000002C0
	CkmSHA3384HMAC                 CKMechanismType = 0x000002C1
	CkmSHA3384HMACGeneral          CKMechanismType = 0x000002C2
	CkmSHA3384KeyGen               CKMechanismType = 0x000002C3
	CkmSHA3512                     CKMechanismType = 0x000002D0
	CkmSHA3512HMAC                 CKMechanismType = 0x000002D1
	CkmSHA3512HMACGeneral          CKMechanismType = 0x000002D2
	CkmSHA3512KeyGen               CKMechanismType = 0x000002D3
	CkmCASTKeyGen                  CKMechanismType = 0x00000300
	CkmCASTECB                     CKMechanismType = 0x00000301
	CkmCASTCBC                     CKMechanismType = 0x00000302
	CkmCASTMAC                     CKMechanismType = 0x00000303
	CkmCASTMACGeneral              CKMechanismType = 0x00000304
	CkmCASTCBCPad                  CKMechanismType = 0x00000305
	CkmCAST3KeyGen                 CKMechanismType = 0x00000310
	CkmCAST3ECB                    CKMechanismType = 0x00000311
	CkmCAST3CBC                    CKMechanismType = 0x00000312
	CkmCAST3MAC                    CKMechanismType = 0x00000313
	CkmCAST3MACGeneral             CKMechanismType = 0x00000314
	CkmCAST3CBCPad                 CKMechanismType = 0x00000315
	CkmCAST5KeyGen                 CKMechanismType = 0x00000320
	CkmCAST128KeyGen               CKMechanismType = 0x00000320
	CkmCAST5ECB                    CKMechanismType = 0x00000321
	CkmCAST128ECB                  CKMechanismType = 0x00000321
	CkmCAST5CBC                    CKMechanismType = 0x00000322
	CkmCAST128CBC                  CKMechanismType = 0x00000322
	CkmCAST5MAC                    CKMechanismType = 0x00000323
	CkmCAST128MAC                  CKMechanismType = 0x00000323
	CkmCAST5MACGeneral             CKMechanismType = 0x00000324
	CkmCAST128MACGeneral           CKMechanismType = 0x00000324
	CkmCAST5CBCPad                 CKMechanismType = 0x00000325
	CkmCAST128CBCPad               CKMechanismType = 0x00000325
	CkmRC5KeyGen                   CKMechanismType = 0x00000330
	CkmRC5ECB                      CKMechanismType = 0x00000331
	CkmRC5CBC                      CKMechanismType = 0x00000332
	CkmRC5MAC                      CKMechanismType = 0x00000333
	CkmRC5MACGeneral               CKMechanismType = 0x00000334
	CkmRC5CBCPad                   CKMechanismType = 0x00000335
	CkmIDEAKeyGen                  CKMechanismType = 0x00000340
	CkmIDEAECB                     CKMechanismType = 0x00000341
	CkmIDEACBC                     CKMechanismType = 0x00000342
	CkmIDEAMAC                     CKMechanismType = 0x00000343
	CkmIDEAMACGeneral              CKMechanismType = 0x00000344
	CkmIDEACBCPad                  CKMechanismType = 0x00000345
	CkmGenericSecretKeyGen         CKMechanismType = 0x00000350
	CkmConcatenateBaseAndKey       CKMechanismType = 0x00000360
	CkmConcatenateBaseAndData      CKMechanismType = 0x00000362
	CkmConcatenateDataAndBase      CKMechanismType = 0x00000363
	CkmXORBaseAndData              CKMechanismType = 0x00000364
	CkmExtractKeyFromKey           CKMechanismType = 0x00000365
	CkmSSL3PreMasterKeyGen         CKMechanismType = 0x00000370
	CkmSSL3MasterKeyDerive         CKMechanismType = 0x00000371
	CkmSSL3KeyAndMACDerive         CKMechanismType = 0x00000372
	CkmSSL3MasterKeyDeriveDH       CKMechanismType = 0x00000373
	CkmTLSPreMasterKeyGen          CKMechanismType = 0x00000374
	CkmTLSMasterKeyDerive          CKMechanismType = 0x00000375
	CkmTLSKeyAndMACDerive          CKMechanismType = 0x00000376
	CkmTLSMasterKeyDeriveDH        CKMechanismType = 0x00000377
	CkmTLSPRF                      CKMechanismType = 0x00000378
	CkmSSL3MD5MAC                  CKMechanismType = 0x00000380
	CkmSSL3SHA1MAC                 CKMechanismType = 0x00000381
	CkmMD5KeyDerivation            CKMechanismType = 0x00000390
	CkmMD2KeyDerivation            CKMechanismType = 0x00000391
	CkmSHA1KeyDerivation           CKMechanismType = 0x00000392
	CkmSHA256KeyDerivation         CKMechanismType = 0x00000393
	CkmSHA384KeyDerivation         CKMechanismType = 0x00000394
	CkmSHA512KeyDerivation         CKMechanismType = 0x00000395
	CkmSHA224KeyDerivation         CKMechanismType = 0x00000396
	CkmSHA3256KeyDerive            CKMechanismType = 0x00000397
	CkmSHA3224KeyDerive            CKMechanismType = 0x00000398
	CkmSHA3384KeyDerive            CKMechanismType = 0x00000399
	CkmSHA3512KeyDerive            CKMechanismType = 0x0000039A
	CkmSHAKE128KeyDerive           CKMechanismType = 0x0000039B
	CkmSHAKE256KeyDerive           CKMechanismType = 0x0000039C
	CkmPBEMD2DESCBC                CKMechanismType = 0x000003A0
	CkmPBEMD5DESCBC                CKMechanismType = 0x000003A1
	CkmPBEMD5CASTCBC               CKMechanismType = 0x000003A2
	CkmPBEMD5CAST3CBC              CKMechanismType = 0x000003A3
	CkmPBEMD5CAST5CBC              CKMechanismType = 0x000003A4
	CkmPBEMD5CAST128CBC            CKMechanismType = 0x000003A4
	CkmPBESHA1CAST5CBC             CKMechanismType = 0x000003A5
	CkmPBESHA1CAST128CBC           CKMechanismType = 0x000003A5
	CkmPBESHA1RC4128               CKMechanismType = 0x000003A6
	CkmPBESHA1RC440                CKMechanismType = 0x000003A7
	CkmPBESHA1DES3EDECBC           CKMechanismType = 0x000003A8
	CkmPBESHA1DES2EDECBC           CKMechanismType = 0x000003A9
	CkmPBESHA1RC2128CBC            CKMechanismType = 0x000003AA
	CkmPBESHA1RC240CBC             CKMechanismType = 0x000003AB
	CkmPKCS5PBKD2                  CKMechanismType = 0x000003B0
	CkmPBASHA1WITHSHA1HMAC         CKMechanismType = 0x000003C0
	CkmWTLSPreMasterKeyGen         CKMechanismType = 0x000003D0
	CkmWTLSMasterKeyDerive         CKMechanismType = 0x000003D1
	CkmWTLSMasterKeyDeriveDHECC    CKMechanismType = 0x000003D2
	CkmWTLSPRF                     CKMechanismType = 0x000003D3
	CkmWTLSServerKeyAndMACDerive   CKMechanismType = 0x000003D4
	CkmWTLSClientKeyAndMACDerive   CKMechanismType = 0x000003D5
	CkmTLS10MACServer              CKMechanismType = 0x000003D6
	CkmTLS10MACClient              CKMechanismType = 0x000003D7
	CkmTLS12MAC                    CKMechanismType = 0x000003D8
	CkmTLS12KDF                    CKMechanismType = 0x000003D9
	CkmTLS12MasterKeyDerive        CKMechanismType = 0x000003E0
	CkmTLS12KeyAndMACDerive        CKMechanismType = 0x000003E1
	CkmTLS12MasterKeyDeriveDH      CKMechanismType = 0x000003E2
	CkmTLS12KeySafeDerive          CKMechanismType = 0x000003E3
	CkmTLSMAC                      CKMechanismType = 0x000003E4
	CkmTLSKDF                      CKMechanismType = 0x000003E5
	CkmKeyWrapLYNKS                CKMechanismType = 0x00000400
	CkmKeyWrapSetOAEP              CKMechanismType = 0x00000401
	CkmCMSSig                      CKMechanismType = 0x00000500
	CkmKIPDerive                   CKMechanismType = 0x00000510
	CkmKIPWRAP                     CKMechanismType = 0x00000511
	CkmKIPMAC                      CKMechanismType = 0x00000512
	CkmCamelliaKeyGen              CKMechanismType = 0x00000550
	CkmCamelliaECB                 CKMechanismType = 0x00000551
	CkmCamelliaCBC                 CKMechanismType = 0x00000552
	CkmCamelliaMAC                 CKMechanismType = 0x00000553
	CkmCamelliaMACGeneral          CKMechanismType = 0x00000554
	CkmCamelliaCBCPad              CKMechanismType = 0x00000555
	CkmCamelliaECBEncryptData      CKMechanismType = 0x00000556
	CkmCamelliaCBCEncryptData      CKMechanismType = 0x00000557
	CkmCamelliaCTR                 CKMechanismType = 0x00000558
	CkmARIAKeyGen                  CKMechanismType = 0x00000560
	CkmARIAECB                     CKMechanismType = 0x00000561
	CkmARIACBC                     CKMechanismType = 0x00000562
	CkmARIAMAC                     CKMechanismType = 0x00000563
	CkmARIAMACGeneral              CKMechanismType = 0x00000564
	CkmARIACBCPad                  CKMechanismType = 0x00000565
	CkmARIAECBEncryptData          CKMechanismType = 0x00000566
	CkmARIACBCEncryptData          CKMechanismType = 0x00000567
	CkmSEEDKeyGen                  CKMechanismType = 0x00000650
	CkmSEEDECB                     CKMechanismType = 0x00000651
	CkmSEEDCBC                     CKMechanismType = 0x00000652
	CkmSEEDMAC                     CKMechanismType = 0x00000653
	CkmSEEDMACGeneral              CKMechanismType = 0x00000654
	CkmSEEDCBCPad                  CKMechanismType = 0x00000655
	CkmSEEDECBEncryptData          CKMechanismType = 0x00000656
	CkmSEEDCBCEncryptData          CKMechanismType = 0x00000657
	CkmSKIPJACKKeyGen              CKMechanismType = 0x00001000
	CkmSKIPJACKECB64               CKMechanismType = 0x00001001
	CkmSKIPJACKCBC64               CKMechanismType = 0x00001002
	CkmSKIPJACKOFB64               CKMechanismType = 0x00001003
	CkmSKIPJACKCFB64               CKMechanismType = 0x00001004
	CkmSKIPJACKCFB32               CKMechanismType = 0x00001005
	CkmSKIPJACKCFB16               CKMechanismType = 0x00001006
	CkmSKIPJACKCFB8                CKMechanismType = 0x00001007
	CkmSKIPJACKWRAP                CKMechanismType = 0x00001008
	CkmSKIPJACKPRIVATEWRAP         CKMechanismType = 0x00001009
	CkmSKIPJACKRELAYX              CKMechanismType = 0x0000100a
	CkmKEAKeyPairGen               CKMechanismType = 0x00001010
	CkmKEAKeyDerive                CKMechanismType = 0x00001011
	CkmKEADerive                   CKMechanismType = 0x00001012
	CkmFORTEZZATIMESTAMP           CKMechanismType = 0x00001020
	CkmBATONKeyGen                 CKMechanismType = 0x00001030
	CkmBATONECB128                 CKMechanismType = 0x00001031
	CkmBATONECB96                  CKMechanismType = 0x00001032
	CkmBATONCBC128                 CKMechanismType = 0x00001033
	CkmBATONCOUNTER                CKMechanismType = 0x00001034
	CkmBATONSHUFFLE                CKMechanismType = 0x00001035
	CkmBATONWRAP                   CKMechanismType = 0x00001036
	CkmECDSAKeyPairGen             CKMechanismType = 0x00001040
	CkmECKeyPairGen                CKMechanismType = 0x00001040
	CkmECDSA                       CKMechanismType = 0x00001041
	CkmECDSASHA1                   CKMechanismType = 0x00001042
	CkmECDSASHA224                 CKMechanismType = 0x00001043
	CkmECDSASHA256                 CKMechanismType = 0x00001044
	CkmECDSASHA384                 CKMechanismType = 0x00001045
	CkmECDSASHA512                 CKMechanismType = 0x00001046
	CkmECDH1Derive                 CKMechanismType = 0x00001050
	CkmECDH1COFACTORDerive         CKMechanismType = 0x00001051
	CkmECMQVDerive                 CKMechanismType = 0x00001052
	CkmECDHAESKeyWRAP              CKMechanismType = 0x00001053
	CkmRSAAESKeyWRAP               CKMechanismType = 0x00001054
	CkmJUNIPERKeyGen               CKMechanismType = 0x00001060
	CkmJUNIPERECB128               CKMechanismType = 0x00001061
	CkmJUNIPERCBC128               CKMechanismType = 0x00001062
	CkmJUNIPERCOUNTER              CKMechanismType = 0x00001063
	CkmJUNIPERSHUFFLE              CKMechanismType = 0x00001064
	CkmJUNIPERWRAP                 CKMechanismType = 0x00001065
	CkmFASTHASH                    CKMechanismType = 0x00001070
	CkmAESXTS                      CKMechanismType = 0x00001071
	CkmAESXTSKeyGen                CKMechanismType = 0x00001072
	CkmAESKeyGen                   CKMechanismType = 0x00001080
	CkmAESECB                      CKMechanismType = 0x00001081
	CkmAESCBC                      CKMechanismType = 0x00001082
	CkmAESMAC                      CKMechanismType = 0x00001083
	CkmAESMACGeneral               CKMechanismType = 0x00001084
	CkmAESCBCPad                   CKMechanismType = 0x00001085
	CkmAESCTR                      CKMechanismType = 0x00001086
	CkmAESGCM                      CKMechanismType = 0x00001087
	CkmAESCCM                      CKMechanismType = 0x00001088
	CkmAESCTS                      CKMechanismType = 0x00001089
	CkmAESCMAC                     CKMechanismType = 0x0000108A
	CkmAESCMACGeneral              CKMechanismType = 0x0000108B
	CkmAESXCBCMAC                  CKMechanismType = 0x0000108C
	CkmAESXCBCMAC96                CKMechanismType = 0x0000108D
	CkmAESGMAC                     CKMechanismType = 0x0000108E
	CkmBLOWFISHKeyGen              CKMechanismType = 0x00001090
	CkmBLOWFISHCBC                 CKMechanismType = 0x00001091
	CkmTWOFISHKeyGen               CKMechanismType = 0x00001092
	CkmTWOFISHCBC                  CKMechanismType = 0x00001093
	CkmBLOWFISHCBCPad              CKMechanismType = 0x00001094
	CkmTWOFISHCBCPad               CKMechanismType = 0x00001095
	CkmDESECBEncryptData           CKMechanismType = 0x00001100
	CkmDESCBCEncryptData           CKMechanismType = 0x00001101
	CkmDES3ECBEncryptData          CKMechanismType = 0x00001102
	CkmDES3CBCEncryptData          CKMechanismType = 0x00001103
	CkmAESECBEncryptData           CKMechanismType = 0x00001104
	CkmAESCBCEncryptData           CKMechanismType = 0x00001105
	CkmGOSTR3410KeyPairGen         CKMechanismType = 0x00001200
	CkmGOSTR3410                   CKMechanismType = 0x00001201
	CkmGOSTR3410WithGOSTR3411      CKMechanismType = 0x00001202
	CkmGOSTR3410KeyWrap            CKMechanismType = 0x00001203
	CkmGOSTR3410Derive             CKMechanismType = 0x00001204
	CkmGOSTR3411                   CKMechanismType = 0x00001210
	CkmGOSTR3411HMAC               CKMechanismType = 0x00001211
	CkmGOST28147KeyGen             CKMechanismType = 0x00001220
	CkmGOST28147ECB                CKMechanismType = 0x00001221
	CkmGOST28147                   CKMechanismType = 0x00001222
	CkmGOST28147MAC                CKMechanismType = 0x00001223
	CkmGOST28147KeyWrap            CKMechanismType = 0x00001224
	CkmCHACHA20KeyGen              CKMechanismType = 0x00001225
	CkmCHACHA20                    CKMechanismType = 0x00001226
	CkmPOLY1305KeyGen              CKMechanismType = 0x00001227
	CkmPOLY1305                    CKMechanismType = 0x00001228
	CkmDSAParameterGen             CKMechanismType = 0x00002000
	CkmDHPKCSParameterGen          CKMechanismType = 0x00002001
	CkmX942DHParameterGen          CKMechanismType = 0x00002002
	CkmDSAProbablisticParameterGen CKMechanismType = 0x00002003
	CkmDSAShaweTaylorparameterGen  CKMechanismType = 0x00002004
	CkmAESOFB                      CKMechanismType = 0x00002104
	CkmAESCFB64                    CKMechanismType = 0x00002105
	CkmAESCFB8                     CKMechanismType = 0x00002106
	CkmAESCFB128                   CKMechanismType = 0x00002107
	CkmAESCFB1                     CKMechanismType = 0x00002108
	CkmAESKeyWrap                  CKMechanismType = 0x00002109
	CkmAESKeyWrapPad               CKMechanismType = 0x0000210A
	CkmAESKeyWrapKWP               CKMechanismType = 0x0000210B
	CkmRSAPKCSTPM11                CKMechanismType = 0x00004001
	CkmRSAPKCSOAEPTPM11            CKMechanismType = 0x00004002
	CkmSHA1KeyGen                  CKMechanismType = 0x00004003
	CkmSHA224KeyGen                CKMechanismType = 0x00004004
	CkmSHA256KeyGen                CKMechanismType = 0x00004005
	CkmSHA384KeyGen                CKMechanismType = 0x00004006
	CkmSHA512KeyGen                CKMechanismType = 0x00004007
	CkmSHA512224KeyGen             CKMechanismType = 0x00004008
	CkmSHA512256KeyGen             CKMechanismType = 0x00004009
	CkmSHA512TKeyGen               CKMechanismType = 0x0000400a
	CkmNL                          CKMechanismType = 0x0000400b
	CkmBLAKE2B160                  CKMechanismType = 0x0000400c
	CkmBLAKE2B160HMAC              CKMechanismType = 0x0000400d
	CkmBLAKE2B160HMACGeneral       CKMechanismType = 0x0000400e
	CkmBLAKE2B160KeyDerive         CKMechanismType = 0x0000400f
	CkmBLAKE2B160KeyGen            CKMechanismType = 0x00004010
	CkmBLAKE2B256                  CKMechanismType = 0x00004011
	CkmBLAKE2B256HMAC              CKMechanismType = 0x00004012
	CkmBLAKE2B256HMACGeneral       CKMechanismType = 0x00004013
	CkmBLAKE2B256KeyDerive         CKMechanismType = 0x00004014
	CkmBLAKE2B256KeyGen            CKMechanismType = 0x00004015
	CkmBLAKE2B384                  CKMechanismType = 0x00004016
	CkmBLAKE2B384HMAC              CKMechanismType = 0x00004017
	CkmBLAKE2B384HMACGeneral       CKMechanismType = 0x00004018
	CkmBLAKE2B384KeyDerive         CKMechanismType = 0x00004019
	CkmBLAKE2B384KeyGen            CKMechanismType = 0x0000401a
	CkmBLAKE2B512                  CKMechanismType = 0x0000401b
	CkmBLAKE2B512HMAC              CKMechanismType = 0x0000401c
	CkmBLAKE2B512HMACGeneral       CKMechanismType = 0x0000401d
	CkmBLAKE2B512KeyDerive         CKMechanismType = 0x0000401e
	CkmBLAKE2B512KeyGen            CKMechanismType = 0x0000401f
	CkmSALSA20                     CKMechanismType = 0x00004020
	CkmCHACHA20POLY1305            CKMechanismType = 0x00004021
	CkmSALSA20POLY1305             CKMechanismType = 0x00004022
	CkmX3DHInitialize              CKMechanismType = 0x00004023
	CkmX3DHRespond                 CKMechanismType = 0x00004024
	CkmX2RATCHETInitialize         CKMechanismType = 0x00004025
	CkmX2RATCHETRespond            CKMechanismType = 0x00004026
	CkmX2RATCHETEncrypt            CKMechanismType = 0x00004027
	CkmX2RATCHETDecrypt            CKMechanismType = 0x00004028
	CkmXEDDSA                      CKMechanismType = 0x00004029
	CkmHKDFDerive                  CKMechanismType = 0x0000402a
	CkmHKDFData                    CKMechanismType = 0x0000402b
	CkmHKDFKeyGen                  CKMechanismType = 0x0000402c
	CkmECDSASHA3224                CKMechanismType = 0x00001047
	CkmECDSASHA3256                CKMechanismType = 0x00001048
	CkmECDSASHA3384                CKMechanismType = 0x00001049
	CkmECDSASHA3512                CKMechanismType = 0x0000104a
	CkmECEdwardsKeyPairGen         CKMechanismType = 0x00001055
	CkmECMontgomeryKeyPairGen      CKMechanismType = 0x00001056
	CkmEDDSA                       CKMechanismType = 0x00001057
	CkmSP800108CounterKDF          CKMechanismType = 0x000003ac
	CkmSP800108FeedbackKDF         CKMechanismType = 0x000003ad
	CkmSP800108DoublePipelineKDF   CKMechanismType = 0x000003ae
	CkmVendorDefined               CKMechanismType = 0x80000000
)

// Attribute types.
const (
	CkfArrayAttribute CKAttributeType = 0x40000000

	CkaClass                   CKAttributeType = 0x00000000
	CkaToken                   CKAttributeType = 0x00000001
	CkaPrivate                 CKAttributeType = 0x00000002
	CkaLabel                   CKAttributeType = 0x00000003
	CkaUniqueID                CKAttributeType = 0x00000004
	CkaApplication             CKAttributeType = 0x00000010
	CkaValue                   CKAttributeType = 0x00000011
	CkaObjectID                CKAttributeType = 0x00000012
	CkaCertificateType         CKAttributeType = 0x00000080
	CkaIssuer                  CKAttributeType = 0x00000081
	CkaSerialNumber            CKAttributeType = 0x00000082
	CkaACIssuer                CKAttributeType = 0x00000083
	CkaOwner                   CKAttributeType = 0x00000084
	CkaAttrTypes               CKAttributeType = 0x00000085
	CkaTrusted                 CKAttributeType = 0x00000086
	CkaCertificateCategory     CKAttributeType = 0x00000087
	CkaJavaMIDPSecurityDomain  CKAttributeType = 0x00000088
	CkaURL                     CKAttributeType = 0x00000089
	CkaHashOfSubjectPublicKey  CKAttributeType = 0x0000008A
	CkaHashOfIssuerPublicKey   CKAttributeType = 0x0000008B
	CkaNameHashAlgorithm       CKAttributeType = 0x0000008C
	CkaCheckValue              CKAttributeType = 0x00000090
	CkaKeyType                 CKAttributeType = 0x00000100
	CkaSubject                 CKAttributeType = 0x00000101
	CkaID                      CKAttributeType = 0x00000102
	CkaSensitive               CKAttributeType = 0x00000103
	CkaEncrypt                 CKAttributeType = 0x00000104
	CkaDecrypt                 CKAttributeType = 0x00000105
	CkaWrap                    CKAttributeType = 0x00000106
	CkaUnwrap                  CKAttributeType = 0x00000107
	CkaSign                    CKAttributeType = 0x00000108
	CkaSignRecover             CKAttributeType = 0x00000109
	CkaVerify                  CKAttributeType = 0x0000010A
	CkaVerifyRecover           CKAttributeType = 0x0000010B
	CkaDerive                  CKAttributeType = 0x0000010C
	CkaStartDate               CKAttributeType = 0x00000110
	CkaEndDate                 CKAttributeType = 0x00000111
	CkaModulus                 CKAttributeType = 0x00000120
	CkaModulusBits             CKAttributeType = 0x00000121
	CkaPublicExponent          CKAttributeType = 0x00000122
	CkaPrivateExponent         CKAttributeType = 0x00000123
	CkaPrime1                  CKAttributeType = 0x00000124
	CkaPrime2                  CKAttributeType = 0x00000125
	CkaExponent1               CKAttributeType = 0x00000126
	CkaExponent2               CKAttributeType = 0x00000127
	CkaCoefficient             CKAttributeType = 0x00000128
	CkaPublicKeyInfo           CKAttributeType = 0x00000129
	CkaPrime                   CKAttributeType = 0x00000130
	CkaSubprime                CKAttributeType = 0x00000131
	CkaBase                    CKAttributeType = 0x00000132
	CkaPrimeBits               CKAttributeType = 0x00000133
	CkaSubPrimeBits            CKAttributeType = 0x00000134
	CkaValueBits               CKAttributeType = 0x00000160
	CkaValueLen                CKAttributeType = 0x00000161
	CkaExtractable             CKAttributeType = 0x00000162
	CkaLocal                   CKAttributeType = 0x00000163
	CkaNeverExtractable        CKAttributeType = 0x00000164
	CkaAlwaysSensitive         CKAttributeType = 0x00000165
	CkaKeyGenMechanism         CKAttributeType = 0x00000166
	CkaModifiable              CKAttributeType = 0x00000170
	CkaCopyable                CKAttributeType = 0x00000171
	CkaDestroyable             CKAttributeType = 0x00000172
	CkaEcdsaParams             CKAttributeType = 0x00000180 /* Deprecated */
	CkaECParams                CKAttributeType = 0x00000180
	CkaECPoint                 CKAttributeType = 0x00000181
	CkaSecondaryAuth           CKAttributeType = 0x00000200 /* Deprecated */
	CkaAuthPinFlags            CKAttributeType = 0x00000201 /* Deprecated */
	CkaAlwaysAuthenticate      CKAttributeType = 0x00000202
	CkaWrapWithTrusted         CKAttributeType = 0x00000210
	CkaWrapTemplate            CKAttributeType = CkfArrayAttribute | 0x00000211
	CkaUnwrapTemplate          CKAttributeType = CkfArrayAttribute | 0x00000212
	CkaDeriveTemplate          CKAttributeType = CkfArrayAttribute | 0x00000213
	CkaOtpFormat               CKAttributeType = 0x00000220
	CkaOtpLength               CKAttributeType = 0x00000221
	CkaOtpTimeInterval         CKAttributeType = 0x00000222
	CkaOtpUserFriendlyMode     CKAttributeType = 0x00000223
	CkaOtpChallengeRequirement CKAttributeType = 0x00000224
	CkaOtpTimeRequirement      CKAttributeType = 0x00000225
	CkaOtpCounterRequirement   CKAttributeType = 0x00000226
	CkaOtpPinRequirement       CKAttributeType = 0x00000227
	CkaOtpCounter              CKAttributeType = 0x0000022E
	CkaOtpTime                 CKAttributeType = 0x0000022F
	CkaOtpUserIdentifier       CKAttributeType = 0x0000022A
	CkaOtpServiceIdentifier    CKAttributeType = 0x0000022B
	CkaOtpServiceLogo          CKAttributeType = 0x0000022C
	CkaOtpServiceLogoType      CKAttributeType = 0x0000022D
	CkaGostr3410Params         CKAttributeType = 0x00000250
	CkaGostr3411Params         CKAttributeType = 0x00000251
	CkaGost28147Params         CKAttributeType = 0x00000252
	CkaHWFeatureType           CKAttributeType = 0x00000300
	CkaResetOnInit             CKAttributeType = 0x00000301
	CkaHasReset                CKAttributeType = 0x00000302
	CkaPixelX                  CKAttributeType = 0x00000400
	CkaPixelY                  CKAttributeType = 0x00000401
	CkaResolution              CKAttributeType = 0x00000402
	CkaCharRows                CKAttributeType = 0x00000403
	CkaCharColumns             CKAttributeType = 0x00000404
	CkaColor                   CKAttributeType = 0x00000405
	CkaBitsPerPixel            CKAttributeType = 0x00000406
	CkaCharSets                CKAttributeType = 0x00000480
	CkaEncodingMethods         CKAttributeType = 0x00000481
	CkaMimeTypes               CKAttributeType = 0x00000482
	CkaMechanismType           CKAttributeType = 0x00000500
	CkaRequiredCMSAttributes   CKAttributeType = 0x00000501
	CkaDefaultCMSAttributes    CKAttributeType = 0x00000502
	CkaSupportedCMSAttributes  CKAttributeType = 0x00000503
	CkaAllowedMechanisms       CKAttributeType = CkfArrayAttribute | 0x00000600
	CkaProfileID               CKAttributeType = 0x00000601
	CkaVendorDefined           CKAttributeType = 0x80000000
)

var ckaNames = map[CKAttributeType]string{
	CkaClass:                   "CKA_CLASS",
	CkaToken:                   "CKA_TOKEN",
	CkaPrivate:                 "CKA_PRIVATE",
	CkaLabel:                   "CKA_LABEL",
	CkaUniqueID:                "CKA_UNIQUE_ID",
	CkaApplication:             "CKA_APPLICATION",
	CkaValue:                   "CKA_VALUE",
	CkaObjectID:                "CKA_OBJECT_ID",
	CkaCertificateType:         "CKA_CERTIFICATE_TYPE",
	CkaIssuer:                  "CKA_ISSUER",
	CkaSerialNumber:            "CKA_SERIAL_NUMBER",
	CkaACIssuer:                "CKA_AC_ISSUER",
	CkaOwner:                   "CKA_OWNER",
	CkaAttrTypes:               "CKA_ATTR_TYPES",
	CkaTrusted:                 "CKA_TRUSTED",
	CkaCertificateCategory:     "CKA_CERTIFICATE_CATEGORY",
	CkaJavaMIDPSecurityDomain:  "CKA_JAVA_MIDP_SECURITY_DOMAIN",
	CkaURL:                     "CKA_URL",
	CkaHashOfSubjectPublicKey:  "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	CkaHashOfIssuerPublicKey:   "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	CkaNameHashAlgorithm:       "CKA_NAME_HASH_ALGORITHM",
	CkaCheckValue:              "CKA_CHECK_VALUE",
	CkaKeyType:                 "CKA_KEY_TYPE",
	CkaSubject:                 "CKA_SUBJECT",
	CkaID:                      "CKA_ID",
	CkaSensitive:               "CKA_SENSITIVE",
	CkaEncrypt:                 "CKA_ENCRYPT",
	CkaDecrypt:                 "CKA_DECRYPT",
	CkaWrap:                    "CKA_WRAP",
	CkaUnwrap:                  "CKA_UNWRAP",
	CkaSign:                    "CKA_SIGN",
	CkaSignRecover:             "CKA_SIGN_RECOVER",
	CkaVerify:                  "CKA_VERIFY",
	CkaVerifyRecover:           "CKA_VERIFY_RECOVER",
	CkaDerive:                  "CKA_DERIVE",
	CkaStartDate:               "CKA_START_DATE",
	CkaEndDate:                 "CKA_END_DATE",
	CkaModulus:                 "CKA_MODULUS",
	CkaModulusBits:             "CKA_MODULUS_BITS",
	CkaPublicExponent:          "CKA_PUBLIC_EXPONENT",
	CkaPrivateExponent:         "CKA_PRIVATE_EXPONENT",
	CkaPrime1:                  "CKA_PRIME_1",
	CkaPrime2:                  "CKA_PRIME_2",
	CkaExponent1:               "CKA_EXPONENT_1",
	CkaExponent2:               "CKA_EXPONENT_2",
	CkaCoefficient:             "CKA_COEFFICIENT",
	CkaPublicKeyInfo:           "CKA_PUBLIC_KEY_INFO",
	CkaPrime:                   "CKA_PRIME",
	CkaSubprime:                "CKA_SUBPRIME",
	CkaBase:                    "CKA_BASE",
	CkaPrimeBits:               "CKA_PRIME_BITS",
	CkaSubPrimeBits:            "CKA_SUB_PRIME_BITS",
	CkaValueBits:               "CKA_VALUE_BITS",
	CkaValueLen:                "CKA_VALUE_LEN",
	CkaExtractable:             "CKA_EXTRACTABLE",
	CkaLocal:                   "CKA_LOCAL",
	CkaNeverExtractable:        "CKA_NEVER_EXTRACTABLE",
	CkaAlwaysSensitive:         "CKA_ALWAYS_SENSITIVE",
	CkaKeyGenMechanism:         "CKA_KEY_GEN_MECHANISM",
	CkaModifiable:              "CKA_MODIFIABLE",
	CkaCopyable:                "CKA_COPYABLE",
	CkaDestroyable:             "CKA_DESTROYABLE",
	CkaECParams:                "CKA_EC_PARAMS",
	CkaECPoint:                 "CKA_EC_POINT",
	CkaSecondaryAuth:           "CKA_SECONDARY_AUTH",
	CkaAuthPinFlags:            "CKA_AUTH_PIN_FLAGS",
	CkaAlwaysAuthenticate:      "CKA_ALWAYS_AUTHENTICATE",
	CkaWrapWithTrusted:         "CKA_WRAP_WITH_TRUSTED",
	CkaWrapTemplate:            "CKA_WRAP_TEMPLATE",
	CkaUnwrapTemplate:          "CKA_UNWRAP_TEMPLATE",
	CkaDeriveTemplate:          "CKA_DERIVE_TEMPLATE",
	CkaOtpFormat:               "CKA_OTP_FORMAT",
	CkaOtpLength:               "CKA_OTP_LENGTH",
	CkaOtpTimeInterval:         "CKA_OTP_TIME_INTERVAL",
	CkaOtpUserFriendlyMode:     "CKA_OTP_USER_FRIENDLY_MODE",
	CkaOtpChallengeRequirement: "CKA_OTP_CHALLENGE_REQUIREMENT",
	CkaOtpTimeRequirement:      "CKA_OTP_TIME_REQUIREMENT",
	CkaOtpCounterRequirement:   "CKA_OTP_COUNTER_REQUIREMENT",
	CkaOtpPinRequirement:       "CKA_OTP_PIN_REQUIREMENT",
	CkaOtpCounter:              "CKA_OTP_COUNTER",
	CkaOtpTime:                 "CKA_OTP_TIME",
	CkaOtpUserIdentifier:       "CKA_OTP_USER_IDENTIFIER",
	CkaOtpServiceIdentifier:    "CKA_OTP_SERVICE_IDENTIFIER",
	CkaOtpServiceLogo:          "CKA_OTP_SERVICE_LOGO",
	CkaOtpServiceLogoType:      "CKA_OTP_SERVICE_LOGO_TYPE",
	CkaGostr3410Params:         "CKA_GOSTR3410_PARAMS",
	CkaGostr3411Params:         "CKA_GOSTR3411_PARAMS",
	CkaGost28147Params:         "CKA_GOST28147_PARAMS",
	CkaHWFeatureType:           "CKA_HW_FEATURE_TYPE",
	CkaResetOnInit:             "CKA_RESET_ON_INIT",
	CkaHasReset:                "CKA_HAS_RESET",
	CkaPixelX:                  "CKA_PIXEL_X",
	CkaPixelY:                  "CKA_PIXEL_Y",
	CkaResolution:              "CKA_RESOLUTION",
	CkaCharRows:                "CKA_CHAR_ROWS",
	CkaCharColumns:             "CKA_CHAR_COLUMNS",
	CkaColor:                   "CKA_COLOR",
	CkaBitsPerPixel:            "CKA_BITS_PER_PIXEL",
	CkaCharSets:                "CKA_CHAR_SETS",
	CkaEncodingMethods:         "CKA_ENCODING_METHODS",
	CkaMimeTypes:               "CKA_MIME_TYPES",
	CkaMechanismType:           "CKA_MECHANISM_TYPE",
	CkaRequiredCMSAttributes:   "CKA_REQUIRED_CMS_ATTRIBUTES",
	CkaDefaultCMSAttributes:    "CKA_DEFAULT_CMS_ATTRIBUTES",
	CkaSupportedCMSAttributes:  "CKA_SUPPORTED_CMS_ATTRIBUTES",
	CkaAllowedMechanisms:       "CKA_ALLOWED_MECHANISMS",
	CkaProfileID:               "CKA_PROFILE_ID",
	CkaVendorDefined:           "CKA_VENDOR_DEFINED",
}

func (t CKAttributeType) String() string {
	name, ok := ckaNames[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{CKAttributeType %d}", t)
}

// Bool returns the attribute value as bool.
func (attr CKAttribute) Bool() (bool, error) {
	switch len(attr.Value) {
	case 1:
		return attr.Value[0] != 0, nil

	default:
		return false, fmt.Errorf("invalid attribute length %d", len(attr.Value))
	}
}

// Uint returns the attribute value as uint64 integer number.
func (attr CKAttribute) Uint() (uint64, error) {
	switch len(attr.Value) {
	case 1:
		return uint64(attr.Value[0]), nil

	case 2:
		return uint64(hbo.Uint16(attr.Value)), nil

	case 4:
		return uint64(hbo.Uint32(attr.Value)), nil

	case 8:
		return uint64(hbo.Uint64(attr.Value)), nil

	default:
		return 0, fmt.Errorf("invalid attribute length %d", len(attr.Value))
	}
}
