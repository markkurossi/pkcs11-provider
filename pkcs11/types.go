//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

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
	CkmCAST128KeyGen               CKMechanismType = 0x00000320
	CkmCAST5ECB                    CKMechanismType = 0x00000321
	CkmCAST128ECB                  CKMechanismType = 0x00000321
	CkmCAST128CBC                  CKMechanismType = 0x00000322
	CkmCAST128MAC                  CKMechanismType = 0x00000323
	CkmCAST128MACGeneral           CKMechanismType = 0x00000324
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
	CkmShake128KeyDerive           CKMechanismType = 0x0000039B
	CkmShake256KeyDerive           CKMechanismType = 0x0000039C
	CkmPBEMD2DESCBC                CKMechanismType = 0x000003A0
	CkmPBEMD5DESCBC                CKMechanismType = 0x000003A1
	CkmPBEMD5CASTCBC               CKMechanismType = 0x000003A2
	CkmPBEMD5CAST3CBC              CKMechanismType = 0x000003A3
	CkmPBEMD5CAST128CBC            CKMechanismType = 0x000003A4
	CkmPBESHA1CAST128CBC           CKMechanismType = 0x000003A5
	CkmPBESHA1RC4128               CKMechanismType = 0x000003A6
	CkmPBESHA1RC440                CKMechanismType = 0x000003A7
	CkmPBESHA1DES3EDECBC           CKMechanismType = 0x000003A8
	CkmPBESHA1DES2EDECBC           CKMechanismType = 0x000003A9
	CkmPBESHA1RC2128CBC            CKMechanismType = 0x000003AA
	CkmPBESHA1RC240CBC             CKMechanismType = 0x000003AB
	CkmPKCS5PBKD2                  CKMechanismType = 0x000003B0
	CkmPBASHA1WithSHA1HMAC         CKMechanismType = 0x000003C0
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
	CkmKIPWrap                     CKMechanismType = 0x00000511
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
	CkmAriaKeyGen                  CKMechanismType = 0x00000560
	CkmAriaECB                     CKMechanismType = 0x00000561
	CkmAriaCBC                     CKMechanismType = 0x00000562
	CkmAriaMAC                     CKMechanismType = 0x00000563
	CkmAriaMACGeneral              CKMechanismType = 0x00000564
	CkmAriaCBCPad                  CKMechanismType = 0x00000565
	CkmAriaECBEncryptData          CKMechanismType = 0x00000566
	CkmAriaCBCEncryptData          CKMechanismType = 0x00000567
	CkmSeedKeyGen                  CKMechanismType = 0x00000650
	CkmSeedECB                     CKMechanismType = 0x00000651
	CkmSeedCBC                     CKMechanismType = 0x00000652
	CkmSeedMAC                     CKMechanismType = 0x00000653
	CkmSeedMACGeneral              CKMechanismType = 0x00000654
	CkmSeedCBCPad                  CKMechanismType = 0x00000655
	CkmSeedECBEncryptData          CKMechanismType = 0x00000656
	CkmSeedCBCEncryptData          CKMechanismType = 0x00000657
	CkmSkipjackKeyGen              CKMechanismType = 0x00001000
	CkmSkipjackECB64               CKMechanismType = 0x00001001
	CkmSkipjackCBC64               CKMechanismType = 0x00001002
	CkmSkipjackOFB64               CKMechanismType = 0x00001003
	CkmSkipjackCFB64               CKMechanismType = 0x00001004
	CkmSkipjackCFB32               CKMechanismType = 0x00001005
	CkmSkipjackCFB16               CKMechanismType = 0x00001006
	CkmSkipjackCFB8                CKMechanismType = 0x00001007
	CkmSkipjackWrap                CKMechanismType = 0x00001008
	CkmSkipjackPrivateWrap         CKMechanismType = 0x00001009
	CkmSkipjackRelayX              CKMechanismType = 0x0000100a
	CkmKeaKeyPairGen               CKMechanismType = 0x00001010
	CkmKeaKeyDerive                CKMechanismType = 0x00001011
	CkmKeaDerive                   CKMechanismType = 0x00001012
	CkmFortezzaTimestamp           CKMechanismType = 0x00001020
	CkmBatonKeyGen                 CKMechanismType = 0x00001030
	CkmBatonECB128                 CKMechanismType = 0x00001031
	CkmBatonEcb96                  CKMechanismType = 0x00001032
	CkmBatonCBC128                 CKMechanismType = 0x00001033
	CkmBatonCounter                CKMechanismType = 0x00001034
	CkmBatonShuffle                CKMechanismType = 0x00001035
	CkmBatonWrap                   CKMechanismType = 0x00001036
	CkmECKeyPairGen                CKMechanismType = 0x00001040
	CkmECDSA                       CKMechanismType = 0x00001041
	CkmECDSASHA1                   CKMechanismType = 0x00001042
	CkmECDSASHA224                 CKMechanismType = 0x00001043
	CkmECDSASHA256                 CKMechanismType = 0x00001044
	CkmECDSASHA384                 CKMechanismType = 0x00001045
	CkmECDSASHA512                 CKMechanismType = 0x00001046
	CkmECDH1Derive                 CKMechanismType = 0x00001050
	CkmECDH1CofactorDerive         CKMechanismType = 0x00001051
	CkmECMQVDerive                 CKMechanismType = 0x00001052
	CkmECDHAESKeyWrap              CKMechanismType = 0x00001053
	CkmRSAAESKeyWrap               CKMechanismType = 0x00001054
	CkmJuniperKeyGen               CKMechanismType = 0x00001060
	CkmJuniperECB128               CKMechanismType = 0x00001061
	CkmJuniperCBC128               CKMechanismType = 0x00001062
	CkmJuniperCounter              CKMechanismType = 0x00001063
	CkmJuniperShuffle              CKMechanismType = 0x00001064
	CkmJuniperWrap                 CKMechanismType = 0x00001065
	CkmFasthash                    CKMechanismType = 0x00001070
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
	CkmBlowfishKeyGen              CKMechanismType = 0x00001090
	CkmBlowfishCBC                 CKMechanismType = 0x00001091
	CkmTwofishKeyGen               CKMechanismType = 0x00001092
	CkmTwofishCBC                  CKMechanismType = 0x00001093
	CkmBlowfishCBCPad              CKMechanismType = 0x00001094
	CkmTwofishCBCPad               CKMechanismType = 0x00001095
	CkmDESECBEncryptData           CKMechanismType = 0x00001100
	CkmDESCBCEncryptData           CKMechanismType = 0x00001101
	CkmDES3ECBEncryptData          CKMechanismType = 0x00001102
	CkmDES3CBCEncryptData          CKMechanismType = 0x00001103
	CkmAESECBEncryptData           CKMechanismType = 0x00001104
	CkmAESCBCEncryptData           CKMechanismType = 0x00001105
	CkmGostR3410KeyPairGen         CKMechanismType = 0x00001200
	CkmGostR3410                   CKMechanismType = 0x00001201
	CkmGostR3410WithGostr3411      CKMechanismType = 0x00001202
	CkmGostR3410KeyWrap            CKMechanismType = 0x00001203
	CkmGostR3410Derive             CKMechanismType = 0x00001204
	CkmGostr3411                   CKMechanismType = 0x00001210
	CkmGostr3411HMAC               CKMechanismType = 0x00001211
	CkmGost28147KeyGen             CKMechanismType = 0x00001220
	CkmGost28147ECB                CKMechanismType = 0x00001221
	CkmGost28147                   CKMechanismType = 0x00001222
	CkmGost28147MAC                CKMechanismType = 0x00001223
	CkmGost28147KeyWrap            CKMechanismType = 0x00001224
	CkmChaCha20KeyGen              CKMechanismType = 0x00001225
	CkmChaCha20                    CKMechanismType = 0x00001226
	CkmPoly1305KeyGen              CKMechanismType = 0x00001227
	CkmPoly1305                    CKMechanismType = 0x00001228
	CkmDSAParameterGen             CKMechanismType = 0x00002000
	CkmDHPKCSParameterGen          CKMechanismType = 0x00002001
	CkmX942DHParameterGen          CKMechanismType = 0x00002002
	CkmDSAProbablisticParameterGen CKMechanismType = 0x00002003
	CkmDSAShaweTaylorParameterGen  CKMechanismType = 0x00002004
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
	CkmNull                        CKMechanismType = 0x0000400b
	CkmBlake2b160                  CKMechanismType = 0x0000400c
	CkmBlake2b160HMAC              CKMechanismType = 0x0000400d
	CkmBlake2b160HMACGeneral       CKMechanismType = 0x0000400e
	CkmBlake2b160KeyDerive         CKMechanismType = 0x0000400f
	CkmBlake2b160KeyGen            CKMechanismType = 0x00004010
	CkmBlake2b256                  CKMechanismType = 0x00004011
	CkmBlake2b256HMAC              CKMechanismType = 0x00004012
	CkmBlake2b256HMACGeneral       CKMechanismType = 0x00004013
	CkmBlake2b256KeyDerive         CKMechanismType = 0x00004014
	CkmBlake2b256KeyGen            CKMechanismType = 0x00004015
	CkmBlake2b384                  CKMechanismType = 0x00004016
	CkmBlake2b384HMAC              CKMechanismType = 0x00004017
	CkmBlake2b384HMACGeneral       CKMechanismType = 0x00004018
	CkmBlake2b384KeyDerive         CKMechanismType = 0x00004019
	CkmBlake2b384KeyGen            CKMechanismType = 0x0000401a
	CkmBlake2b512                  CKMechanismType = 0x0000401b
	CkmBlake2b512HMAC              CKMechanismType = 0x0000401c
	CkmBlake2b512HMACGeneral       CKMechanismType = 0x0000401d
	CkmBlake2b512KeyDerive         CKMechanismType = 0x0000401e
	CkmBlake2b512KeyGen            CKMechanismType = 0x0000401f
	CkmSalsa20                     CKMechanismType = 0x00004020
	CkmChaCha20Poly1305            CKMechanismType = 0x00004021
	CkmSalsa20Poly1305             CKMechanismType = 0x00004022
	CkmX3DHInitialize              CKMechanismType = 0x00004023
	CkmX3DHRespond                 CKMechanismType = 0x00004024
	CkmX2RatchetInitialize         CKMechanismType = 0x00004025
	CkmX2RatchetRespond            CKMechanismType = 0x00004026
	CkmX2RatchetEncrypt            CKMechanismType = 0x00004027
	CkmX2RatchetDecrypt            CKMechanismType = 0x00004028
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

var ckmNames = map[CKMechanismType]string{
	CkmRSAPKCSKeyPairGen:           "CKM_RSA_PKCS_KEY_PAIR_GEN",
	CkmRSAPKCS:                     "CKM_RSA_PKCS",
	CkmRSA9796:                     "CKM_RSA_9796",
	CkmRSAX509:                     "CKM_RSA_X_509",
	CkmMD2RSAPKCS:                  "CKM_MD2_RSA_PKCS",
	CkmMD5RSAPKCS:                  "CKM_MD5_RSA_PKCS",
	CkmSHA1RSAPKCS:                 "CKM_SHA1_RSA_PKCS",
	CkmRIPEMD128RSAPKCS:            "CKM_RIPEMD128_RSA_PKCS",
	CkmRIPEMD160RSAPKCS:            "CKM_RIPEMD160_RSA_PKCS",
	CkmRSAPKCSOAEP:                 "CKM_RSA_PKCS_OAEP",
	CkmRSAX931KeyPairGen:           "CKM_RSA_X9_31_KEY_PAIR_GEN",
	CkmRSAX931:                     "CKM_RSA_X9_31",
	CkmSHA1RSAX931:                 "CKM_SHA1_RSA_X9_31",
	CkmRSAPKCSPSS:                  "CKM_RSA_PKCS_PSS",
	CkmSHA1RSAPKCSPSS:              "CKM_SHA1_RSA_PKCS_PSS",
	CkmDSAKeyPairGen:               "CKM_DSA_KEY_PAIR_GEN",
	CkmDSA:                         "CKM_DSA",
	CkmDSASHA1:                     "CKM_DSA_SHA1",
	CkmDSASHA224:                   "CKM_DSA_SHA224",
	CkmDSASHA256:                   "CKM_DSA_SHA256",
	CkmDSASHA384:                   "CKM_DSA_SHA384",
	CkmDSASHA512:                   "CKM_DSA_SHA512",
	CkmDSASHA3224:                  "CKM_DSA_SHA3_224",
	CkmDSASHA3256:                  "CKM_DSA_SHA3_256",
	CkmDSASHA3384:                  "CKM_DSA_SHA3_384",
	CkmDSASHA3512:                  "CKM_DSA_SHA3_512",
	CkmDHPKCSKeyPairGen:            "CKM_DH_PKCS_KEY_PAIR_GEN",
	CkmDHPKCSDerive:                "CKM_DH_PKCS_DERIVE",
	CkmX942DHKeyPairGen:            "CKM_X9_42_DH_KEY_PAIR_GEN",
	CkmX942DHDerive:                "CKM_X9_42_DH_DERIVE",
	CkmX942DHHybridDerive:          "CKM_X9_42_DH_HYBRID_DERIVE",
	CkmX942MQVDerive:               "CKM_X9_42_MQV_DERIVE",
	CkmSHA256RSAPKCS:               "CKM_SHA256_RSA_PKCS",
	CkmSHA384RSAPKCS:               "CKM_SHA384_RSA_PKCS",
	CkmSHA512RSAPKCS:               "CKM_SHA512_RSA_PKCS",
	CkmSHA256RSAPKCSPSS:            "CKM_SHA256_RSA_PKCS_PSS",
	CkmSHA384RSAPKCSPSS:            "CKM_SHA384_RSA_PKCS_PSS",
	CkmSHA512RSAPKCSPSS:            "CKM_SHA512_RSA_PKCS_PSS",
	CkmSHA224RSAPKCS:               "CKM_SHA224_RSA_PKCS",
	CkmSHA224RSAPKCSPSS:            "CKM_SHA224_RSA_PKCS_PSS",
	CkmSHA512224:                   "CKM_SHA512_224",
	CkmSHA512224HMAC:               "CKM_SHA512_224_HMAC",
	CkmSHA512224HMACGeneral:        "CKM_SHA512_224_HMAC_GENERAL",
	CkmSHA512224KeyDerivation:      "CKM_SHA512_224_KEY_DERIVATION",
	CkmSHA512256:                   "CKM_SHA512_256",
	CkmSHA512256HMAC:               "CKM_SHA512_256_HMAC",
	CkmSHA512256HMACGeneral:        "CKM_SHA512_256_HMAC_GENERAL",
	CkmSHA512256KeyDerivation:      "CKM_SHA512_256_KEY_DERIVATION",
	CkmSHA512T:                     "CKM_SHA512_T",
	CkmSHA512THMAC:                 "CKM_SHA512_T_HMAC",
	CkmSHA512THMACGeneral:          "CKM_SHA512_T_HMAC_GENERAL",
	CkmSHA512TKeyDerivation:        "CKM_SHA512_T_KEY_DERIVATION",
	CkmSHA3256RSAPKCS:              "CKM_SHA3_256_RSA_PKCS",
	CkmSHA3384RSAPKCS:              "CKM_SHA3_384_RSA_PKCS",
	CkmSHA3512RSAPKCS:              "CKM_SHA3_512_RSA_PKCS",
	CkmSHA3256RSAPKCSPSS:           "CKM_SHA3_256_RSA_PKCS_PSS",
	CkmSHA3384RSAPKCSPSS:           "CKM_SHA3_384_RSA_PKCS_PSS",
	CkmSHA3512RSAPKCSPSS:           "CKM_SHA3_512_RSA_PKCS_PSS",
	CkmSHA3224RSAPKCS:              "CKM_SHA3_224_RSA_PKCS",
	CkmSHA3224RSAPKCSPSS:           "CKM_SHA3_224_RSA_PKCS_PSS",
	CkmRC2KeyGen:                   "CKM_RC2_KEY_GEN",
	CkmRC2ECB:                      "CKM_RC2_ECB",
	CkmRC2CBC:                      "CKM_RC2_CBC",
	CkmRC2MAC:                      "CKM_RC2_MAC",
	CkmRC2MACGeneral:               "CKM_RC2_MAC_GENERAL",
	CkmRC2CBCPad:                   "CKM_RC2_CBC_PAD",
	CkmRC4KeyGen:                   "CKM_RC4_KEY_GEN",
	CkmRC4:                         "CKM_RC4",
	CkmDESKeyGen:                   "CKM_DES_KEY_GEN",
	CkmDESECB:                      "CKM_DES_ECB",
	CkmDESCBC:                      "CKM_DES_CBC",
	CkmDESMAC:                      "CKM_DES_MAC",
	CkmDESMACGeneral:               "CKM_DES_MAC_GENERAL",
	CkmDESCBCPad:                   "CKM_DES_CBC_PAD",
	CkmDES2KeyGen:                  "CKM_DES2_KEY_GEN",
	CkmDES3KeyGen:                  "CKM_DES3_KEY_GEN",
	CkmDES3ECB:                     "CKM_DES3_ECB",
	CkmDES3CBC:                     "CKM_DES3_CBC",
	CkmDES3MAC:                     "CKM_DES3_MAC",
	CkmDES3MACGeneral:              "CKM_DES3_MAC_GENERAL",
	CkmDES3CBCPad:                  "CKM_DES3_CBC_PAD",
	CkmDES3CMACGeneral:             "CKM_DES3_CMAC_GENERAL",
	CkmDES3CMAC:                    "CKM_DES3_CMAC",
	CkmCDMFKeyGen:                  "CKM_CDMF_KEY_GEN",
	CkmCDMFECB:                     "CKM_CDMF_ECB",
	CkmCDMFCBC:                     "CKM_CDMF_CBC",
	CkmCDMFMAC:                     "CKM_CDMF_MAC",
	CkmCDMFMACGeneral:              "CKM_CDMF_MAC_GENERAL",
	CkmCDMFCBCPad:                  "CKM_CDMF_CBC_PAD",
	CkmDESOFB64:                    "CKM_DES_OFB64",
	CkmDESOFB8:                     "CKM_DES_OFB8",
	CkmDESCFB64:                    "CKM_DES_CFB64",
	CkmDESCFB8:                     "CKM_DES_CFB8",
	CkmMD2:                         "CKM_MD2",
	CkmMD2HMAC:                     "CKM_MD2_HMAC",
	CkmMD2HMACGeneral:              "CKM_MD2_HMAC_GENERAL",
	CkmMD5:                         "CKM_MD5",
	CkmMD5HMAC:                     "CKM_MD5_HMAC",
	CkmMD5HMACGeneral:              "CKM_MD5_HMAC_GENERAL",
	CkmSHA1:                        "CKM_SHA_1",
	CkmSHA1HMAC:                    "CKM_SHA_1_HMAC",
	CkmSHA1HMACGeneral:             "CKM_SHA_1_HMAC_GENERAL",
	CkmRIPEMD128:                   "CKM_RIPEMD128",
	CkmRIPEMD128HMAC:               "CKM_RIPEMD128_HMAC",
	CkmRIPEMD128HMACGeneral:        "CKM_RIPEMD128_HMAC_GENERAL",
	CkmRIPEMD160:                   "CKM_RIPEMD160",
	CkmRIPEMD160HMAC:               "CKM_RIPEMD160_HMAC",
	CkmRIPEMD160HMACGeneral:        "CKM_RIPEMD160_HMAC_GENERAL",
	CkmSHA256:                      "CKM_SHA256",
	CkmSHA256HMAC:                  "CKM_SHA256_HMAC",
	CkmSHA256HMACGeneral:           "CKM_SHA256_HMAC_GENERAL",
	CkmSHA224:                      "CKM_SHA224",
	CkmSHA224HMAC:                  "CKM_SHA224_HMAC",
	CkmSHA224HMACGeneral:           "CKM_SHA224_HMAC_GENERAL",
	CkmSHA384:                      "CKM_SHA384",
	CkmSHA384HMAC:                  "CKM_SHA384_HMAC",
	CkmSHA384HMACGeneral:           "CKM_SHA384_HMAC_GENERAL",
	CkmSHA512:                      "CKM_SHA512",
	CkmSHA512HMAC:                  "CKM_SHA512_HMAC",
	CkmSHA512HMACGeneral:           "CKM_SHA512_HMAC_GENERAL",
	CkmSecurIDKeyGen:               "CKM_SECURID_KEY_GEN",
	CkmSecurID:                     "CKM_SECURID",
	CkmHOTPKeyGen:                  "CKM_HOTP_KEY_GEN",
	CkmHOTP:                        "CKM_HOTP",
	CkmACTI:                        "CKM_ACTI",
	CkmACTIKeyGen:                  "CKM_ACTI_KEY_GEN",
	CkmSHA3256:                     "CKM_SHA3_256",
	CkmSHA3256HMAC:                 "CKM_SHA3_256_HMAC",
	CkmSHA3256HMACGeneral:          "CKM_SHA3_256_HMAC_GENERAL",
	CkmSHA3256KeyGen:               "CKM_SHA3_256_KEY_GEN",
	CkmSHA3224:                     "CKM_SHA3_224",
	CkmSHA3224HMAC:                 "CKM_SHA3_224_HMAC",
	CkmSHA3224HMACGeneral:          "CKM_SHA3_224_HMAC_GENERAL",
	CkmSHA3224KeyGen:               "CKM_SHA3_224_KEY_GEN",
	CkmSHA3384:                     "CKM_SHA3_384",
	CkmSHA3384HMAC:                 "CKM_SHA3_384_HMAC",
	CkmSHA3384HMACGeneral:          "CKM_SHA3_384_HMAC_GENERAL",
	CkmSHA3384KeyGen:               "CKM_SHA3_384_KEY_GEN",
	CkmSHA3512:                     "CKM_SHA3_512",
	CkmSHA3512HMAC:                 "CKM_SHA3_512_HMAC",
	CkmSHA3512HMACGeneral:          "CKM_SHA3_512_HMAC_GENERAL",
	CkmSHA3512KeyGen:               "CKM_SHA3_512_KEY_GEN",
	CkmCASTKeyGen:                  "CKM_CAST_KEY_GEN",
	CkmCASTECB:                     "CKM_CAST_ECB",
	CkmCASTCBC:                     "CKM_CAST_CBC",
	CkmCASTMAC:                     "CKM_CAST_MAC",
	CkmCASTMACGeneral:              "CKM_CAST_MAC_GENERAL",
	CkmCASTCBCPad:                  "CKM_CAST_CBC_PAD",
	CkmCAST3KeyGen:                 "CKM_CAST3_KEY_GEN",
	CkmCAST3ECB:                    "CKM_CAST3_ECB",
	CkmCAST3CBC:                    "CKM_CAST3_CBC",
	CkmCAST3MAC:                    "CKM_CAST3_MAC",
	CkmCAST3MACGeneral:             "CKM_CAST3_MAC_GENERAL",
	CkmCAST3CBCPad:                 "CKM_CAST3_CBC_PAD",
	CkmCAST128KeyGen:               "CKM_CAST128_KEY_GEN",
	CkmCAST128ECB:                  "CKM_CAST128_ECB",
	CkmCAST128CBC:                  "CKM_CAST128_CBC",
	CkmCAST128MAC:                  "CKM_CAST128_MAC",
	CkmCAST128MACGeneral:           "CKM_CAST128_MAC_GENERAL",
	CkmCAST128CBCPad:               "CKM_CAST128_CBC_PAD",
	CkmRC5KeyGen:                   "CKM_RC5_KEY_GEN",
	CkmRC5ECB:                      "CKM_RC5_ECB",
	CkmRC5CBC:                      "CKM_RC5_CBC",
	CkmRC5MAC:                      "CKM_RC5_MAC",
	CkmRC5MACGeneral:               "CKM_RC5_MAC_GENERAL",
	CkmRC5CBCPad:                   "CKM_RC5_CBC_PAD",
	CkmIDEAKeyGen:                  "CKM_IDEA_KEY_GEN",
	CkmIDEAECB:                     "CKM_IDEA_ECB",
	CkmIDEACBC:                     "CKM_IDEA_CBC",
	CkmIDEAMAC:                     "CKM_IDEA_MAC",
	CkmIDEAMACGeneral:              "CKM_IDEA_MAC_GENERAL",
	CkmIDEACBCPad:                  "CKM_IDEA_CBC_PAD",
	CkmGenericSecretKeyGen:         "CKM_GENERIC_SECRET_KEY_GEN",
	CkmConcatenateBaseAndKey:       "CKM_CONCATENATE_BASE_AND_KEY",
	CkmConcatenateBaseAndData:      "CKM_CONCATENATE_BASE_AND_DATA",
	CkmConcatenateDataAndBase:      "CKM_CONCATENATE_DATA_AND_BASE",
	CkmXORBaseAndData:              "CKM_XOR_BASE_AND_DATA",
	CkmExtractKeyFromKey:           "CKM_EXTRACT_KEY_FROM_KEY",
	CkmSSL3PreMasterKeyGen:         "CKM_SSL3_PRE_MASTER_KEY_GEN",
	CkmSSL3MasterKeyDerive:         "CKM_SSL3_MASTER_KEY_DERIVE",
	CkmSSL3KeyAndMACDerive:         "CKM_SSL3_KEY_AND_MAC_DERIVE",
	CkmSSL3MasterKeyDeriveDH:       "CKM_SSL3_MASTER_KEY_DERIVE_DH",
	CkmTLSPreMasterKeyGen:          "CKM_TLS_PRE_MASTER_KEY_GEN",
	CkmTLSMasterKeyDerive:          "CKM_TLS_MASTER_KEY_DERIVE",
	CkmTLSKeyAndMACDerive:          "CKM_TLS_KEY_AND_MAC_DERIVE",
	CkmTLSMasterKeyDeriveDH:        "CKM_TLS_MASTER_KEY_DERIVE_DH",
	CkmTLSPRF:                      "CKM_TLS_PRF",
	CkmSSL3MD5MAC:                  "CKM_SSL3_MD5_MAC",
	CkmSSL3SHA1MAC:                 "CKM_SSL3_SHA1_MAC",
	CkmMD5KeyDerivation:            "CKM_MD5_KEY_DERIVATION",
	CkmMD2KeyDerivation:            "CKM_MD2_KEY_DERIVATION",
	CkmSHA1KeyDerivation:           "CKM_SHA1_KEY_DERIVATION",
	CkmSHA256KeyDerivation:         "CKM_SHA256_KEY_DERIVATION",
	CkmSHA384KeyDerivation:         "CKM_SHA384_KEY_DERIVATION",
	CkmSHA512KeyDerivation:         "CKM_SHA512_KEY_DERIVATION",
	CkmSHA224KeyDerivation:         "CKM_SHA224_KEY_DERIVATION",
	CkmSHA3256KeyDerive:            "CKM_SHA3_256_KEY_DERIVE",
	CkmSHA3224KeyDerive:            "CKM_SHA3_224_KEY_DERIVE",
	CkmSHA3384KeyDerive:            "CKM_SHA3_384_KEY_DERIVE",
	CkmSHA3512KeyDerive:            "CKM_SHA3_512_KEY_DERIVE",
	CkmShake128KeyDerive:           "CKM_SHAKE_128_KEY_DERIVE",
	CkmShake256KeyDerive:           "CKM_SHAKE_256_KEY_DERIVE",
	CkmPBEMD2DESCBC:                "CKM_PBE_MD2_DES_CBC",
	CkmPBEMD5DESCBC:                "CKM_PBE_MD5_DES_CBC",
	CkmPBEMD5CASTCBC:               "CKM_PBE_MD5_CAST_CBC",
	CkmPBEMD5CAST3CBC:              "CKM_PBE_MD5_CAST3_CBC",
	CkmPBEMD5CAST128CBC:            "CKM_PBE_MD5_CAST128_CBC",
	CkmPBESHA1CAST128CBC:           "CKM_PBE_SHA1_CAST128_CBC",
	CkmPBESHA1RC4128:               "CKM_PBE_SHA1_RC4_128",
	CkmPBESHA1RC440:                "CKM_PBE_SHA1_RC4_40",
	CkmPBESHA1DES3EDECBC:           "CKM_PBE_SHA1_DES3_EDE_CBC",
	CkmPBESHA1DES2EDECBC:           "CKM_PBE_SHA1_DES2_EDE_CBC",
	CkmPBESHA1RC2128CBC:            "CKM_PBE_SHA1_RC2_128_CBC",
	CkmPBESHA1RC240CBC:             "CKM_PBE_SHA1_RC2_40_CBC",
	CkmPKCS5PBKD2:                  "CKM_PKCS5_PBKD2",
	CkmPBASHA1WithSHA1HMAC:         "CKM_PBA_SHA1_WITH_SHA1_HMAC",
	CkmWTLSPreMasterKeyGen:         "CKM_WTLS_PRE_MASTER_KEY_GEN",
	CkmWTLSMasterKeyDerive:         "CKM_WTLS_MASTER_KEY_DERIVE",
	CkmWTLSMasterKeyDeriveDHECC:    "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
	CkmWTLSPRF:                     "CKM_WTLS_PRF",
	CkmWTLSServerKeyAndMACDerive:   "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
	CkmWTLSClientKeyAndMACDerive:   "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
	CkmTLS10MACServer:              "CKM_TLS10_MAC_SERVER",
	CkmTLS10MACClient:              "CKM_TLS10_MAC_CLIENT",
	CkmTLS12MAC:                    "CKM_TLS12_MAC",
	CkmTLS12KDF:                    "CKM_TLS12_KDF",
	CkmTLS12MasterKeyDerive:        "CKM_TLS12_MASTER_KEY_DERIVE",
	CkmTLS12KeyAndMACDerive:        "CKM_TLS12_KEY_AND_MAC_DERIVE",
	CkmTLS12MasterKeyDeriveDH:      "CKM_TLS12_MASTER_KEY_DERIVE_DH",
	CkmTLS12KeySafeDerive:          "CKM_TLS12_KEY_SAFE_DERIVE",
	CkmTLSMAC:                      "CKM_TLS_MAC",
	CkmTLSKDF:                      "CKM_TLS_KDF",
	CkmKeyWrapLYNKS:                "CKM_KEY_WRAP_LYNKS",
	CkmKeyWrapSetOAEP:              "CKM_KEY_WRAP_SET_OAEP",
	CkmCMSSig:                      "CKM_CMS_SIG",
	CkmKIPDerive:                   "CKM_KIP_DERIVE",
	CkmKIPWrap:                     "CKM_KIP_WRAP",
	CkmKIPMAC:                      "CKM_KIP_MAC",
	CkmCamelliaKeyGen:              "CKM_CAMELLIA_KEY_GEN",
	CkmCamelliaECB:                 "CKM_CAMELLIA_ECB",
	CkmCamelliaCBC:                 "CKM_CAMELLIA_CBC",
	CkmCamelliaMAC:                 "CKM_CAMELLIA_MAC",
	CkmCamelliaMACGeneral:          "CKM_CAMELLIA_MAC_GENERAL",
	CkmCamelliaCBCPad:              "CKM_CAMELLIA_CBC_PAD",
	CkmCamelliaECBEncryptData:      "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
	CkmCamelliaCBCEncryptData:      "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
	CkmCamelliaCTR:                 "CKM_CAMELLIA_CTR",
	CkmAriaKeyGen:                  "CKM_ARIA_KEY_GEN",
	CkmAriaECB:                     "CKM_ARIA_ECB",
	CkmAriaCBC:                     "CKM_ARIA_CBC",
	CkmAriaMAC:                     "CKM_ARIA_MAC",
	CkmAriaMACGeneral:              "CKM_ARIA_MAC_GENERAL",
	CkmAriaCBCPad:                  "CKM_ARIA_CBC_PAD",
	CkmAriaECBEncryptData:          "CKM_ARIA_ECB_ENCRYPT_DATA",
	CkmAriaCBCEncryptData:          "CKM_ARIA_CBC_ENCRYPT_DATA",
	CkmSeedKeyGen:                  "CKM_SEED_KEY_GEN",
	CkmSeedECB:                     "CKM_SEED_ECB",
	CkmSeedCBC:                     "CKM_SEED_CBC",
	CkmSeedMAC:                     "CKM_SEED_MAC",
	CkmSeedMACGeneral:              "CKM_SEED_MAC_GENERAL",
	CkmSeedCBCPad:                  "CKM_SEED_CBC_PAD",
	CkmSeedECBEncryptData:          "CKM_SEED_ECB_ENCRYPT_DATA",
	CkmSeedCBCEncryptData:          "CKM_SEED_CBC_ENCRYPT_DATA",
	CkmSkipjackKeyGen:              "CKM_SKIPJACK_KEY_GEN",
	CkmSkipjackECB64:               "CKM_SKIPJACK_ECB64",
	CkmSkipjackCBC64:               "CKM_SKIPJACK_CBC64",
	CkmSkipjackOFB64:               "CKM_SKIPJACK_OFB64",
	CkmSkipjackCFB64:               "CKM_SKIPJACK_CFB64",
	CkmSkipjackCFB32:               "CKM_SKIPJACK_CFB32",
	CkmSkipjackCFB16:               "CKM_SKIPJACK_CFB16",
	CkmSkipjackCFB8:                "CKM_SKIPJACK_CFB8",
	CkmSkipjackWrap:                "CKM_SKIPJACK_WRAP",
	CkmSkipjackPrivateWrap:         "CKM_SKIPJACK_PRIVATE_WRAP",
	CkmSkipjackRelayX:              "CKM_SKIPJACK_RELAYX",
	CkmKeaKeyPairGen:               "CKM_KEA_KEY_PAIR_GEN",
	CkmKeaKeyDerive:                "CKM_KEA_KEY_DERIVE",
	CkmKeaDerive:                   "CKM_KEA_DERIVE",
	CkmFortezzaTimestamp:           "CKM_FORTEZZA_TIMESTAMP",
	CkmBatonKeyGen:                 "CKM_BATON_KEY_GEN",
	CkmBatonECB128:                 "CKM_BATON_ECB128",
	CkmBatonEcb96:                  "CKM_BATON_ECB96",
	CkmBatonCBC128:                 "CKM_BATON_CBC128",
	CkmBatonCounter:                "CKM_BATON_COUNTER",
	CkmBatonShuffle:                "CKM_BATON_SHUFFLE",
	CkmBatonWrap:                   "CKM_BATON_WRAP",
	CkmECKeyPairGen:                "CKM_EC_KEY_PAIR_GEN",
	CkmECDSA:                       "CKM_ECDSA",
	CkmECDSASHA1:                   "CKM_ECDSA_SHA1",
	CkmECDSASHA224:                 "CKM_ECDSA_SHA224",
	CkmECDSASHA256:                 "CKM_ECDSA_SHA256",
	CkmECDSASHA384:                 "CKM_ECDSA_SHA384",
	CkmECDSASHA512:                 "CKM_ECDSA_SHA512",
	CkmECDH1Derive:                 "CKM_ECDH1_DERIVE",
	CkmECDH1CofactorDerive:         "CKM_ECDH1_COFACTOR_DERIVE",
	CkmECMQVDerive:                 "CKM_ECMQV_DERIVE",
	CkmECDHAESKeyWrap:              "CKM_ECDH_AES_KEY_WRAP",
	CkmRSAAESKeyWrap:               "CKM_RSA_AES_KEY_WRAP",
	CkmJuniperKeyGen:               "CKM_JUNIPER_KEY_GEN",
	CkmJuniperECB128:               "CKM_JUNIPER_ECB128",
	CkmJuniperCBC128:               "CKM_JUNIPER_CBC128",
	CkmJuniperCounter:              "CKM_JUNIPER_COUNTER",
	CkmJuniperShuffle:              "CKM_JUNIPER_SHUFFLE",
	CkmJuniperWrap:                 "CKM_JUNIPER_WRAP",
	CkmFasthash:                    "CKM_FASTHASH",
	CkmAESXTS:                      "CKM_AES_XTS",
	CkmAESXTSKeyGen:                "CKM_AES_XTS_KEY_GEN",
	CkmAESKeyGen:                   "CKM_AES_KEY_GEN",
	CkmAESECB:                      "CKM_AES_ECB",
	CkmAESCBC:                      "CKM_AES_CBC",
	CkmAESMAC:                      "CKM_AES_MAC",
	CkmAESMACGeneral:               "CKM_AES_MAC_GENERAL",
	CkmAESCBCPad:                   "CKM_AES_CBC_PAD",
	CkmAESCTR:                      "CKM_AES_CTR",
	CkmAESGCM:                      "CKM_AES_GCM",
	CkmAESCCM:                      "CKM_AES_CCM",
	CkmAESCTS:                      "CKM_AES_CTS",
	CkmAESCMAC:                     "CKM_AES_CMAC",
	CkmAESCMACGeneral:              "CKM_AES_CMAC_GENERAL",
	CkmAESXCBCMAC:                  "CKM_AES_XCBC_MAC",
	CkmAESXCBCMAC96:                "CKM_AES_XCBC_MAC_96",
	CkmAESGMAC:                     "CKM_AES_GMAC",
	CkmBlowfishKeyGen:              "CKM_BLOWFISH_KEY_GEN",
	CkmBlowfishCBC:                 "CKM_BLOWFISH_CBC",
	CkmTwofishKeyGen:               "CKM_TWOFISH_KEY_GEN",
	CkmTwofishCBC:                  "CKM_TWOFISH_CBC",
	CkmBlowfishCBCPad:              "CKM_BLOWFISH_CBC_PAD",
	CkmTwofishCBCPad:               "CKM_TWOFISH_CBC_PAD",
	CkmDESECBEncryptData:           "CKM_DES_ECB_ENCRYPT_DATA",
	CkmDESCBCEncryptData:           "CKM_DES_CBC_ENCRYPT_DATA",
	CkmDES3ECBEncryptData:          "CKM_DES3_ECB_ENCRYPT_DATA",
	CkmDES3CBCEncryptData:          "CKM_DES3_CBC_ENCRYPT_DATA",
	CkmAESECBEncryptData:           "CKM_AES_ECB_ENCRYPT_DATA",
	CkmAESCBCEncryptData:           "CKM_AES_CBC_ENCRYPT_DATA",
	CkmGostR3410KeyPairGen:         "CKM_GOSTR3410_KEY_PAIR_GEN",
	CkmGostR3410:                   "CKM_GOSTR3410",
	CkmGostR3410WithGostr3411:      "CKM_GOSTR3410_WITH_GOSTR3411",
	CkmGostR3410KeyWrap:            "CKM_GOSTR3410_KEY_WRAP",
	CkmGostR3410Derive:             "CKM_GOSTR3410_DERIVE",
	CkmGostr3411:                   "CKM_GOSTR3411",
	CkmGostr3411HMAC:               "CKM_GOSTR3411_HMAC",
	CkmGost28147KeyGen:             "CKM_GOST28147_KEY_GEN",
	CkmGost28147ECB:                "CKM_GOST28147_ECB",
	CkmGost28147:                   "CKM_GOST28147",
	CkmGost28147MAC:                "CKM_GOST28147_MAC",
	CkmGost28147KeyWrap:            "CKM_GOST28147_KEY_WRAP",
	CkmChaCha20KeyGen:              "CKM_CHACHA20_KEY_GEN",
	CkmChaCha20:                    "CKM_CHACHA20",
	CkmPoly1305KeyGen:              "CKM_POLY1305_KEY_GEN",
	CkmPoly1305:                    "CKM_POLY1305",
	CkmDSAParameterGen:             "CKM_DSA_PARAMETER_GEN",
	CkmDHPKCSParameterGen:          "CKM_DH_PKCS_PARAMETER_GEN",
	CkmX942DHParameterGen:          "CKM_X9_42_DH_PARAMETER_GEN",
	CkmDSAProbablisticParameterGen: "CKM_DSA_PROBABLISTIC_PARAMETER_GEN",
	CkmDSAShaweTaylorParameterGen:  "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN",
	CkmAESOFB:                      "CKM_AES_OFB",
	CkmAESCFB64:                    "CKM_AES_CFB64",
	CkmAESCFB8:                     "CKM_AES_CFB8",
	CkmAESCFB128:                   "CKM_AES_CFB128",
	CkmAESCFB1:                     "CKM_AES_CFB1",
	CkmAESKeyWrap:                  "CKM_AES_KEY_WRAP",
	CkmAESKeyWrapPad:               "CKM_AES_KEY_WRAP_PAD",
	CkmAESKeyWrapKWP:               "CKM_AES_KEY_WRAP_KWP",
	CkmRSAPKCSTPM11:                "CKM_RSA_PKCS_TPM_1_1",
	CkmRSAPKCSOAEPTPM11:            "CKM_RSA_PKCS_OAEP_TPM_1_1",
	CkmSHA1KeyGen:                  "CKM_SHA_1_KEY_GEN",
	CkmSHA224KeyGen:                "CKM_SHA224_KEY_GEN",
	CkmSHA256KeyGen:                "CKM_SHA256_KEY_GEN",
	CkmSHA384KeyGen:                "CKM_SHA384_KEY_GEN",
	CkmSHA512KeyGen:                "CKM_SHA512_KEY_GEN",
	CkmSHA512224KeyGen:             "CKM_SHA512_224_KEY_GEN",
	CkmSHA512256KeyGen:             "CKM_SHA512_256_KEY_GEN",
	CkmSHA512TKeyGen:               "CKM_SHA512_T_KEY_GEN",
	CkmNull:                        "CKM_NULL",
	CkmBlake2b160:                  "CKM_BLAKE2B_160",
	CkmBlake2b160HMAC:              "CKM_BLAKE2B_160_HMAC",
	CkmBlake2b160HMACGeneral:       "CKM_BLAKE2B_160_HMAC_GENERAL",
	CkmBlake2b160KeyDerive:         "CKM_BLAKE2B_160_KEY_DERIVE",
	CkmBlake2b160KeyGen:            "CKM_BLAKE2B_160_KEY_GEN",
	CkmBlake2b256:                  "CKM_BLAKE2B_256",
	CkmBlake2b256HMAC:              "CKM_BLAKE2B_256_HMAC",
	CkmBlake2b256HMACGeneral:       "CKM_BLAKE2B_256_HMAC_GENERAL",
	CkmBlake2b256KeyDerive:         "CKM_BLAKE2B_256_KEY_DERIVE",
	CkmBlake2b256KeyGen:            "CKM_BLAKE2B_256_KEY_GEN",
	CkmBlake2b384:                  "CKM_BLAKE2B_384",
	CkmBlake2b384HMAC:              "CKM_BLAKE2B_384_HMAC",
	CkmBlake2b384HMACGeneral:       "CKM_BLAKE2B_384_HMAC_GENERAL",
	CkmBlake2b384KeyDerive:         "CKM_BLAKE2B_384_KEY_DERIVE",
	CkmBlake2b384KeyGen:            "CKM_BLAKE2B_384_KEY_GEN",
	CkmBlake2b512:                  "CKM_BLAKE2B_512",
	CkmBlake2b512HMAC:              "CKM_BLAKE2B_512_HMAC",
	CkmBlake2b512HMACGeneral:       "CKM_BLAKE2B_512_HMAC_GENERAL",
	CkmBlake2b512KeyDerive:         "CKM_BLAKE2B_512_KEY_DERIVE",
	CkmBlake2b512KeyGen:            "CKM_BLAKE2B_512_KEY_GEN",
	CkmSalsa20:                     "CKM_SALSA20",
	CkmChaCha20Poly1305:            "CKM_CHACHA20_POLY1305",
	CkmSalsa20Poly1305:             "CKM_SALSA20_POLY1305",
	CkmX3DHInitialize:              "CKM_X3DH_INITIALIZE",
	CkmX3DHRespond:                 "CKM_X3DH_RESPOND",
	CkmX2RatchetInitialize:         "CKM_X2RATCHET_INITIALIZE",
	CkmX2RatchetRespond:            "CKM_X2RATCHET_RESPOND",
	CkmX2RatchetEncrypt:            "CKM_X2RATCHET_ENCRYPT",
	CkmX2RatchetDecrypt:            "CKM_X2RATCHET_DECRYPT",
	CkmXEDDSA:                      "CKM_XEDDSA",
	CkmHKDFDerive:                  "CKM_HKDF_DERIVE",
	CkmHKDFData:                    "CKM_HKDF_DATA",
	CkmHKDFKeyGen:                  "CKM_HKDF_KEY_GEN",
	CkmECDSASHA3224:                "CKM_ECDSA_SHA3_224",
	CkmECDSASHA3256:                "CKM_ECDSA_SHA3_256",
	CkmECDSASHA3384:                "CKM_ECDSA_SHA3_384",
	CkmECDSASHA3512:                "CKM_ECDSA_SHA3_512",
	CkmECEdwardsKeyPairGen:         "CKM_EC_EDWARDS_KEY_PAIR_GEN",
	CkmECMontgomeryKeyPairGen:      "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
	CkmEDDSA:                       "CKM_EDDSA",
	CkmSP800108CounterKDF:          "CKM_SP800_108_COUNTER_KDF",
	CkmSP800108FeedbackKDF:         "CKM_SP800_108_FEEDBACK_KDF",
	CkmSP800108DoublePipelineKDF:   "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
	CkmVendorDefined:               "CKM_VENDOR_DEFINED",
}

func (t CKMechanismType) String() string {
	name, ok := ckmNames[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{CKMechanismType %d}", t)
}

func (m CKMechanism) String() string {
	if len(m.Parameter) > 0 {
		return fmt.Sprintf("%s: %x", m.Mechanism, m.Parameter)
	}
	return fmt.Sprintf("%s", m.Mechanism)
}

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

// Template defines attributes for objects.
type Template []CKAttribute
