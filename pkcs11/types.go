//
// Copyright (c) 2021-2023 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"math/bits"
)

// Flags that describe capabilities of a slot.
const (
	CkfTokenPresent    Flags = 0x00000001
	CkfRemovableDevice Flags = 0x00000002
	CkfHWSlot          Flags = 0x00000004
)

// Flags that describe capabilities of a token.
const (
	CkfRNG                         Flags = 0x00000001
	CkfWriteProtected              Flags = 0x00000002
	CkfLoginRequired               Flags = 0x00000004
	CkfUserPinInitialized          Flags = 0x00000008
	CkfRestoreKeyNotNeeded         Flags = 0x00000020
	CkfClockOnToken                Flags = 0x00000040
	CkfProtectedAuthenticationPath Flags = 0x00000100
	CkfDualCryptoOperations        Flags = 0x00000200
	CkfTokenInitialized            Flags = 0x00000400
	CkfSecondaryAuthentication     Flags = 0x00000800
	CkfUserPINCountLow             Flags = 0x00010000
	CkfUserPINFinalTry             Flags = 0x00020000
	CkfUserPINLocked               Flags = 0x00040000
	CkfUserPINToBeChanged          Flags = 0x00080000
	CkfSOPINCountLow               Flags = 0x00100000
	CkfSOPINFinalTry               Flags = 0x00200000
	CkfSOPINLocked                 Flags = 0x00400000
	CkfSOPINToBeChanged            Flags = 0x00800000
	CkfErrorState                  Flags = 0x01000000
)

// Flags that describe capabilities of a mechanism.
const (
	CkfHW              Flags = 0x00000001
	CkfMessageEncrypt  Flags = 0x00000002
	CkfMessageDecrypt  Flags = 0x00000004
	CkfMessageSign     Flags = 0x00000008
	CkfMessageVerify   Flags = 0x00000010
	CkfMultiMessge     Flags = 0x00000020
	CkfFindObjects     Flags = 0x00000040
	CkfEncrypt         Flags = 0x00000100
	CkfDecrypt         Flags = 0x00000200
	CkfDigest          Flags = 0x00000400
	CkfSign            Flags = 0x00000800
	CkfSignRecover     Flags = 0x00001000
	CkfVerify          Flags = 0x00002000
	CkfVerifyRecover   Flags = 0x00004000
	CkfGenerate        Flags = 0x00008000
	CkfGenerateKeyPair Flags = 0x00010000
	CkfWrap            Flags = 0x00020000
	CkfUnwrap          Flags = 0x00040000
	CkfDerive          Flags = 0x00080000
	CkfECFP            Flags = 0x00100000
	CkfECF2M           Flags = 0x00200000
	CkfECECParameters  Flags = 0x00400000
	CkfECOID           Flags = 0x00800000
	CkfECNamedCurve    Flags = 0x00800000
	CkfECUncompress    Flags = 0x01000000
	CkfECCompress      Flags = 0x02000000
	CkfECCurvename     Flags = 0x04000000
	CkfExtension       Flags = 0x80000000
)

// Mechanism types.
const (
	CkmRSAPKCSKeyPairGen           MechanismType = 0x00000000
	CkmRSAPKCS                     MechanismType = 0x00000001
	CkmRSA9796                     MechanismType = 0x00000002
	CkmRSAX509                     MechanismType = 0x00000003
	CkmMD2RSAPKCS                  MechanismType = 0x00000004
	CkmMD5RSAPKCS                  MechanismType = 0x00000005
	CkmSHA1RSAPKCS                 MechanismType = 0x00000006
	CkmRIPEMD128RSAPKCS            MechanismType = 0x00000007
	CkmRIPEMD160RSAPKCS            MechanismType = 0x00000008
	CkmRSAPKCSOAEP                 MechanismType = 0x00000009
	CkmRSAX931KeyPairGen           MechanismType = 0x0000000A
	CkmRSAX931                     MechanismType = 0x0000000B
	CkmSHA1RSAX931                 MechanismType = 0x0000000C
	CkmRSAPKCSPSS                  MechanismType = 0x0000000D
	CkmSHA1RSAPKCSPSS              MechanismType = 0x0000000E
	CkmDSAKeyPairGen               MechanismType = 0x00000010
	CkmDSA                         MechanismType = 0x00000011
	CkmDSASHA1                     MechanismType = 0x00000012
	CkmDSASHA224                   MechanismType = 0x00000013
	CkmDSASHA256                   MechanismType = 0x00000014
	CkmDSASHA384                   MechanismType = 0x00000015
	CkmDSASHA512                   MechanismType = 0x00000016
	CkmDSASHA3224                  MechanismType = 0x00000018
	CkmDSASHA3256                  MechanismType = 0x00000019
	CkmDSASHA3384                  MechanismType = 0x0000001A
	CkmDSASHA3512                  MechanismType = 0x0000001B
	CkmDHPKCSKeyPairGen            MechanismType = 0x00000020
	CkmDHPKCSDerive                MechanismType = 0x00000021
	CkmX942DHKeyPairGen            MechanismType = 0x00000030
	CkmX942DHDerive                MechanismType = 0x00000031
	CkmX942DHHybridDerive          MechanismType = 0x00000032
	CkmX942MQVDerive               MechanismType = 0x00000033
	CkmSHA256RSAPKCS               MechanismType = 0x00000040
	CkmSHA384RSAPKCS               MechanismType = 0x00000041
	CkmSHA512RSAPKCS               MechanismType = 0x00000042
	CkmSHA256RSAPKCSPSS            MechanismType = 0x00000043
	CkmSHA384RSAPKCSPSS            MechanismType = 0x00000044
	CkmSHA512RSAPKCSPSS            MechanismType = 0x00000045
	CkmSHA224RSAPKCS               MechanismType = 0x00000046
	CkmSHA224RSAPKCSPSS            MechanismType = 0x00000047
	CkmSHA512224                   MechanismType = 0x00000048
	CkmSHA512224HMAC               MechanismType = 0x00000049
	CkmSHA512224HMACGeneral        MechanismType = 0x0000004A
	CkmSHA512224KeyDerivation      MechanismType = 0x0000004B
	CkmSHA512256                   MechanismType = 0x0000004C
	CkmSHA512256HMAC               MechanismType = 0x0000004D
	CkmSHA512256HMACGeneral        MechanismType = 0x0000004E
	CkmSHA512256KeyDerivation      MechanismType = 0x0000004F
	CkmSHA512T                     MechanismType = 0x00000050
	CkmSHA512THMAC                 MechanismType = 0x00000051
	CkmSHA512THMACGeneral          MechanismType = 0x00000052
	CkmSHA512TKeyDerivation        MechanismType = 0x00000053
	CkmSHA3256RSAPKCS              MechanismType = 0x00000060
	CkmSHA3384RSAPKCS              MechanismType = 0x00000061
	CkmSHA3512RSAPKCS              MechanismType = 0x00000062
	CkmSHA3256RSAPKCSPSS           MechanismType = 0x00000063
	CkmSHA3384RSAPKCSPSS           MechanismType = 0x00000064
	CkmSHA3512RSAPKCSPSS           MechanismType = 0x00000065
	CkmSHA3224RSAPKCS              MechanismType = 0x00000066
	CkmSHA3224RSAPKCSPSS           MechanismType = 0x00000067
	CkmRC2KeyGen                   MechanismType = 0x00000100
	CkmRC2ECB                      MechanismType = 0x00000101
	CkmRC2CBC                      MechanismType = 0x00000102
	CkmRC2MAC                      MechanismType = 0x00000103
	CkmRC2MACGeneral               MechanismType = 0x00000104
	CkmRC2CBCPad                   MechanismType = 0x00000105
	CkmRC4KeyGen                   MechanismType = 0x00000110
	CkmRC4                         MechanismType = 0x00000111
	CkmDESKeyGen                   MechanismType = 0x00000120
	CkmDESECB                      MechanismType = 0x00000121
	CkmDESCBC                      MechanismType = 0x00000122
	CkmDESMAC                      MechanismType = 0x00000123
	CkmDESMACGeneral               MechanismType = 0x00000124
	CkmDESCBCPad                   MechanismType = 0x00000125
	CkmDES2KeyGen                  MechanismType = 0x00000130
	CkmDES3KeyGen                  MechanismType = 0x00000131
	CkmDES3ECB                     MechanismType = 0x00000132
	CkmDES3CBC                     MechanismType = 0x00000133
	CkmDES3MAC                     MechanismType = 0x00000134
	CkmDES3MACGeneral              MechanismType = 0x00000135
	CkmDES3CBCPad                  MechanismType = 0x00000136
	CkmDES3CMACGeneral             MechanismType = 0x00000137
	CkmDES3CMAC                    MechanismType = 0x00000138
	CkmCDMFKeyGen                  MechanismType = 0x00000140
	CkmCDMFECB                     MechanismType = 0x00000141
	CkmCDMFCBC                     MechanismType = 0x00000142
	CkmCDMFMAC                     MechanismType = 0x00000143
	CkmCDMFMACGeneral              MechanismType = 0x00000144
	CkmCDMFCBCPad                  MechanismType = 0x00000145
	CkmDESOFB64                    MechanismType = 0x00000150
	CkmDESOFB8                     MechanismType = 0x00000151
	CkmDESCFB64                    MechanismType = 0x00000152
	CkmDESCFB8                     MechanismType = 0x00000153
	CkmMD2                         MechanismType = 0x00000200
	CkmMD2HMAC                     MechanismType = 0x00000201
	CkmMD2HMACGeneral              MechanismType = 0x00000202
	CkmMD5                         MechanismType = 0x00000210
	CkmMD5HMAC                     MechanismType = 0x00000211
	CkmMD5HMACGeneral              MechanismType = 0x00000212
	CkmSHA1                        MechanismType = 0x00000220
	CkmSHA1HMAC                    MechanismType = 0x00000221
	CkmSHA1HMACGeneral             MechanismType = 0x00000222
	CkmRIPEMD128                   MechanismType = 0x00000230
	CkmRIPEMD128HMAC               MechanismType = 0x00000231
	CkmRIPEMD128HMACGeneral        MechanismType = 0x00000232
	CkmRIPEMD160                   MechanismType = 0x00000240
	CkmRIPEMD160HMAC               MechanismType = 0x00000241
	CkmRIPEMD160HMACGeneral        MechanismType = 0x00000242
	CkmSHA256                      MechanismType = 0x00000250
	CkmSHA256HMAC                  MechanismType = 0x00000251
	CkmSHA256HMACGeneral           MechanismType = 0x00000252
	CkmSHA224                      MechanismType = 0x00000255
	CkmSHA224HMAC                  MechanismType = 0x00000256
	CkmSHA224HMACGeneral           MechanismType = 0x00000257
	CkmSHA384                      MechanismType = 0x00000260
	CkmSHA384HMAC                  MechanismType = 0x00000261
	CkmSHA384HMACGeneral           MechanismType = 0x00000262
	CkmSHA512                      MechanismType = 0x00000270
	CkmSHA512HMAC                  MechanismType = 0x00000271
	CkmSHA512HMACGeneral           MechanismType = 0x00000272
	CkmSecurIDKeyGen               MechanismType = 0x00000280
	CkmSecurID                     MechanismType = 0x00000282
	CkmHOTPKeyGen                  MechanismType = 0x00000290
	CkmHOTP                        MechanismType = 0x00000291
	CkmACTI                        MechanismType = 0x000002A0
	CkmACTIKeyGen                  MechanismType = 0x000002A1
	CkmSHA3256                     MechanismType = 0x000002B0
	CkmSHA3256HMAC                 MechanismType = 0x000002B1
	CkmSHA3256HMACGeneral          MechanismType = 0x000002B2
	CkmSHA3256KeyGen               MechanismType = 0x000002B3
	CkmSHA3224                     MechanismType = 0x000002B5
	CkmSHA3224HMAC                 MechanismType = 0x000002B6
	CkmSHA3224HMACGeneral          MechanismType = 0x000002B7
	CkmSHA3224KeyGen               MechanismType = 0x000002B8
	CkmSHA3384                     MechanismType = 0x000002C0
	CkmSHA3384HMAC                 MechanismType = 0x000002C1
	CkmSHA3384HMACGeneral          MechanismType = 0x000002C2
	CkmSHA3384KeyGen               MechanismType = 0x000002C3
	CkmSHA3512                     MechanismType = 0x000002D0
	CkmSHA3512HMAC                 MechanismType = 0x000002D1
	CkmSHA3512HMACGeneral          MechanismType = 0x000002D2
	CkmSHA3512KeyGen               MechanismType = 0x000002D3
	CkmCASTKeyGen                  MechanismType = 0x00000300
	CkmCASTECB                     MechanismType = 0x00000301
	CkmCASTCBC                     MechanismType = 0x00000302
	CkmCASTMAC                     MechanismType = 0x00000303
	CkmCASTMACGeneral              MechanismType = 0x00000304
	CkmCASTCBCPad                  MechanismType = 0x00000305
	CkmCAST3KeyGen                 MechanismType = 0x00000310
	CkmCAST3ECB                    MechanismType = 0x00000311
	CkmCAST3CBC                    MechanismType = 0x00000312
	CkmCAST3MAC                    MechanismType = 0x00000313
	CkmCAST3MACGeneral             MechanismType = 0x00000314
	CkmCAST3CBCPad                 MechanismType = 0x00000315
	CkmCAST128KeyGen               MechanismType = 0x00000320
	CkmCAST5ECB                    MechanismType = 0x00000321
	CkmCAST128ECB                  MechanismType = 0x00000321
	CkmCAST128CBC                  MechanismType = 0x00000322
	CkmCAST128MAC                  MechanismType = 0x00000323
	CkmCAST128MACGeneral           MechanismType = 0x00000324
	CkmCAST128CBCPad               MechanismType = 0x00000325
	CkmRC5KeyGen                   MechanismType = 0x00000330
	CkmRC5ECB                      MechanismType = 0x00000331
	CkmRC5CBC                      MechanismType = 0x00000332
	CkmRC5MAC                      MechanismType = 0x00000333
	CkmRC5MACGeneral               MechanismType = 0x00000334
	CkmRC5CBCPad                   MechanismType = 0x00000335
	CkmIDEAKeyGen                  MechanismType = 0x00000340
	CkmIDEAECB                     MechanismType = 0x00000341
	CkmIDEACBC                     MechanismType = 0x00000342
	CkmIDEAMAC                     MechanismType = 0x00000343
	CkmIDEAMACGeneral              MechanismType = 0x00000344
	CkmIDEACBCPad                  MechanismType = 0x00000345
	CkmGenericSecretKeyGen         MechanismType = 0x00000350
	CkmConcatenateBaseAndKey       MechanismType = 0x00000360
	CkmConcatenateBaseAndData      MechanismType = 0x00000362
	CkmConcatenateDataAndBase      MechanismType = 0x00000363
	CkmXORBaseAndData              MechanismType = 0x00000364
	CkmExtractKeyFromKey           MechanismType = 0x00000365
	CkmSSL3PreMasterKeyGen         MechanismType = 0x00000370
	CkmSSL3MasterKeyDerive         MechanismType = 0x00000371
	CkmSSL3KeyAndMACDerive         MechanismType = 0x00000372
	CkmSSL3MasterKeyDeriveDH       MechanismType = 0x00000373
	CkmTLSPreMasterKeyGen          MechanismType = 0x00000374
	CkmTLSMasterKeyDerive          MechanismType = 0x00000375
	CkmTLSKeyAndMACDerive          MechanismType = 0x00000376
	CkmTLSMasterKeyDeriveDH        MechanismType = 0x00000377
	CkmTLSPRF                      MechanismType = 0x00000378
	CkmSSL3MD5MAC                  MechanismType = 0x00000380
	CkmSSL3SHA1MAC                 MechanismType = 0x00000381
	CkmMD5KeyDerivation            MechanismType = 0x00000390
	CkmMD2KeyDerivation            MechanismType = 0x00000391
	CkmSHA1KeyDerivation           MechanismType = 0x00000392
	CkmSHA256KeyDerivation         MechanismType = 0x00000393
	CkmSHA384KeyDerivation         MechanismType = 0x00000394
	CkmSHA512KeyDerivation         MechanismType = 0x00000395
	CkmSHA224KeyDerivation         MechanismType = 0x00000396
	CkmSHA3256KeyDerive            MechanismType = 0x00000397
	CkmSHA3224KeyDerive            MechanismType = 0x00000398
	CkmSHA3384KeyDerive            MechanismType = 0x00000399
	CkmSHA3512KeyDerive            MechanismType = 0x0000039A
	CkmShake128KeyDerive           MechanismType = 0x0000039B
	CkmShake256KeyDerive           MechanismType = 0x0000039C
	CkmPBEMD2DESCBC                MechanismType = 0x000003A0
	CkmPBEMD5DESCBC                MechanismType = 0x000003A1
	CkmPBEMD5CASTCBC               MechanismType = 0x000003A2
	CkmPBEMD5CAST3CBC              MechanismType = 0x000003A3
	CkmPBEMD5CAST128CBC            MechanismType = 0x000003A4
	CkmPBESHA1CAST128CBC           MechanismType = 0x000003A5
	CkmPBESHA1RC4128               MechanismType = 0x000003A6
	CkmPBESHA1RC440                MechanismType = 0x000003A7
	CkmPBESHA1DES3EDECBC           MechanismType = 0x000003A8
	CkmPBESHA1DES2EDECBC           MechanismType = 0x000003A9
	CkmPBESHA1RC2128CBC            MechanismType = 0x000003AA
	CkmPBESHA1RC240CBC             MechanismType = 0x000003AB
	CkmPKCS5PBKD2                  MechanismType = 0x000003B0
	CkmPBASHA1WithSHA1HMAC         MechanismType = 0x000003C0
	CkmWTLSPreMasterKeyGen         MechanismType = 0x000003D0
	CkmWTLSMasterKeyDerive         MechanismType = 0x000003D1
	CkmWTLSMasterKeyDeriveDHECC    MechanismType = 0x000003D2
	CkmWTLSPRF                     MechanismType = 0x000003D3
	CkmWTLSServerKeyAndMACDerive   MechanismType = 0x000003D4
	CkmWTLSClientKeyAndMACDerive   MechanismType = 0x000003D5
	CkmTLS10MACServer              MechanismType = 0x000003D6
	CkmTLS10MACClient              MechanismType = 0x000003D7
	CkmTLS12MAC                    MechanismType = 0x000003D8
	CkmTLS12KDF                    MechanismType = 0x000003D9
	CkmTLS12MasterKeyDerive        MechanismType = 0x000003E0
	CkmTLS12KeyAndMACDerive        MechanismType = 0x000003E1
	CkmTLS12MasterKeyDeriveDH      MechanismType = 0x000003E2
	CkmTLS12KeySafeDerive          MechanismType = 0x000003E3
	CkmTLSMAC                      MechanismType = 0x000003E4
	CkmTLSKDF                      MechanismType = 0x000003E5
	CkmKeyWrapLYNKS                MechanismType = 0x00000400
	CkmKeyWrapSetOAEP              MechanismType = 0x00000401
	CkmCMSSig                      MechanismType = 0x00000500
	CkmKIPDerive                   MechanismType = 0x00000510
	CkmKIPWrap                     MechanismType = 0x00000511
	CkmKIPMAC                      MechanismType = 0x00000512
	CkmCamelliaKeyGen              MechanismType = 0x00000550
	CkmCamelliaECB                 MechanismType = 0x00000551
	CkmCamelliaCBC                 MechanismType = 0x00000552
	CkmCamelliaMAC                 MechanismType = 0x00000553
	CkmCamelliaMACGeneral          MechanismType = 0x00000554
	CkmCamelliaCBCPad              MechanismType = 0x00000555
	CkmCamelliaECBEncryptData      MechanismType = 0x00000556
	CkmCamelliaCBCEncryptData      MechanismType = 0x00000557
	CkmCamelliaCTR                 MechanismType = 0x00000558
	CkmAriaKeyGen                  MechanismType = 0x00000560
	CkmAriaECB                     MechanismType = 0x00000561
	CkmAriaCBC                     MechanismType = 0x00000562
	CkmAriaMAC                     MechanismType = 0x00000563
	CkmAriaMACGeneral              MechanismType = 0x00000564
	CkmAriaCBCPad                  MechanismType = 0x00000565
	CkmAriaECBEncryptData          MechanismType = 0x00000566
	CkmAriaCBCEncryptData          MechanismType = 0x00000567
	CkmSeedKeyGen                  MechanismType = 0x00000650
	CkmSeedECB                     MechanismType = 0x00000651
	CkmSeedCBC                     MechanismType = 0x00000652
	CkmSeedMAC                     MechanismType = 0x00000653
	CkmSeedMACGeneral              MechanismType = 0x00000654
	CkmSeedCBCPad                  MechanismType = 0x00000655
	CkmSeedECBEncryptData          MechanismType = 0x00000656
	CkmSeedCBCEncryptData          MechanismType = 0x00000657
	CkmSkipjackKeyGen              MechanismType = 0x00001000
	CkmSkipjackECB64               MechanismType = 0x00001001
	CkmSkipjackCBC64               MechanismType = 0x00001002
	CkmSkipjackOFB64               MechanismType = 0x00001003
	CkmSkipjackCFB64               MechanismType = 0x00001004
	CkmSkipjackCFB32               MechanismType = 0x00001005
	CkmSkipjackCFB16               MechanismType = 0x00001006
	CkmSkipjackCFB8                MechanismType = 0x00001007
	CkmSkipjackWrap                MechanismType = 0x00001008
	CkmSkipjackPrivateWrap         MechanismType = 0x00001009
	CkmSkipjackRelayX              MechanismType = 0x0000100a
	CkmKeaKeyPairGen               MechanismType = 0x00001010
	CkmKeaKeyDerive                MechanismType = 0x00001011
	CkmKeaDerive                   MechanismType = 0x00001012
	CkmFortezzaTimestamp           MechanismType = 0x00001020
	CkmBatonKeyGen                 MechanismType = 0x00001030
	CkmBatonECB128                 MechanismType = 0x00001031
	CkmBatonEcb96                  MechanismType = 0x00001032
	CkmBatonCBC128                 MechanismType = 0x00001033
	CkmBatonCounter                MechanismType = 0x00001034
	CkmBatonShuffle                MechanismType = 0x00001035
	CkmBatonWrap                   MechanismType = 0x00001036
	CkmECKeyPairGen                MechanismType = 0x00001040
	CkmECDSA                       MechanismType = 0x00001041
	CkmECDSASHA1                   MechanismType = 0x00001042
	CkmECDSASHA224                 MechanismType = 0x00001043
	CkmECDSASHA256                 MechanismType = 0x00001044
	CkmECDSASHA384                 MechanismType = 0x00001045
	CkmECDSASHA512                 MechanismType = 0x00001046
	CkmECDH1Derive                 MechanismType = 0x00001050
	CkmECDH1CofactorDerive         MechanismType = 0x00001051
	CkmECMQVDerive                 MechanismType = 0x00001052
	CkmECDHAESKeyWrap              MechanismType = 0x00001053
	CkmRSAAESKeyWrap               MechanismType = 0x00001054
	CkmJuniperKeyGen               MechanismType = 0x00001060
	CkmJuniperECB128               MechanismType = 0x00001061
	CkmJuniperCBC128               MechanismType = 0x00001062
	CkmJuniperCounter              MechanismType = 0x00001063
	CkmJuniperShuffle              MechanismType = 0x00001064
	CkmJuniperWrap                 MechanismType = 0x00001065
	CkmFasthash                    MechanismType = 0x00001070
	CkmAESXTS                      MechanismType = 0x00001071
	CkmAESXTSKeyGen                MechanismType = 0x00001072
	CkmAESKeyGen                   MechanismType = 0x00001080
	CkmAESECB                      MechanismType = 0x00001081
	CkmAESCBC                      MechanismType = 0x00001082
	CkmAESMAC                      MechanismType = 0x00001083
	CkmAESMACGeneral               MechanismType = 0x00001084
	CkmAESCBCPad                   MechanismType = 0x00001085
	CkmAESCTR                      MechanismType = 0x00001086
	CkmAESGCM                      MechanismType = 0x00001087
	CkmAESCCM                      MechanismType = 0x00001088
	CkmAESCTS                      MechanismType = 0x00001089
	CkmAESCMAC                     MechanismType = 0x0000108A
	CkmAESCMACGeneral              MechanismType = 0x0000108B
	CkmAESXCBCMAC                  MechanismType = 0x0000108C
	CkmAESXCBCMAC96                MechanismType = 0x0000108D
	CkmAESGMAC                     MechanismType = 0x0000108E
	CkmBlowfishKeyGen              MechanismType = 0x00001090
	CkmBlowfishCBC                 MechanismType = 0x00001091
	CkmTwofishKeyGen               MechanismType = 0x00001092
	CkmTwofishCBC                  MechanismType = 0x00001093
	CkmBlowfishCBCPad              MechanismType = 0x00001094
	CkmTwofishCBCPad               MechanismType = 0x00001095
	CkmDESECBEncryptData           MechanismType = 0x00001100
	CkmDESCBCEncryptData           MechanismType = 0x00001101
	CkmDES3ECBEncryptData          MechanismType = 0x00001102
	CkmDES3CBCEncryptData          MechanismType = 0x00001103
	CkmAESECBEncryptData           MechanismType = 0x00001104
	CkmAESCBCEncryptData           MechanismType = 0x00001105
	CkmGostR3410KeyPairGen         MechanismType = 0x00001200
	CkmGostR3410                   MechanismType = 0x00001201
	CkmGostR3410WithGostr3411      MechanismType = 0x00001202
	CkmGostR3410KeyWrap            MechanismType = 0x00001203
	CkmGostR3410Derive             MechanismType = 0x00001204
	CkmGostr3411                   MechanismType = 0x00001210
	CkmGostr3411HMAC               MechanismType = 0x00001211
	CkmGost28147KeyGen             MechanismType = 0x00001220
	CkmGost28147ECB                MechanismType = 0x00001221
	CkmGost28147                   MechanismType = 0x00001222
	CkmGost28147MAC                MechanismType = 0x00001223
	CkmGost28147KeyWrap            MechanismType = 0x00001224
	CkmChaCha20KeyGen              MechanismType = 0x00001225
	CkmChaCha20                    MechanismType = 0x00001226
	CkmPoly1305KeyGen              MechanismType = 0x00001227
	CkmPoly1305                    MechanismType = 0x00001228
	CkmDSAParameterGen             MechanismType = 0x00002000
	CkmDHPKCSParameterGen          MechanismType = 0x00002001
	CkmX942DHParameterGen          MechanismType = 0x00002002
	CkmDSAProbablisticParameterGen MechanismType = 0x00002003
	CkmDSAShaweTaylorParameterGen  MechanismType = 0x00002004
	CkmAESOFB                      MechanismType = 0x00002104
	CkmAESCFB64                    MechanismType = 0x00002105
	CkmAESCFB8                     MechanismType = 0x00002106
	CkmAESCFB128                   MechanismType = 0x00002107
	CkmAESCFB1                     MechanismType = 0x00002108
	CkmAESKeyWrap                  MechanismType = 0x00002109
	CkmAESKeyWrapPad               MechanismType = 0x0000210A
	CkmAESKeyWrapKWP               MechanismType = 0x0000210B
	CkmRSAPKCSTPM11                MechanismType = 0x00004001
	CkmRSAPKCSOAEPTPM11            MechanismType = 0x00004002
	CkmSHA1KeyGen                  MechanismType = 0x00004003
	CkmSHA224KeyGen                MechanismType = 0x00004004
	CkmSHA256KeyGen                MechanismType = 0x00004005
	CkmSHA384KeyGen                MechanismType = 0x00004006
	CkmSHA512KeyGen                MechanismType = 0x00004007
	CkmSHA512224KeyGen             MechanismType = 0x00004008
	CkmSHA512256KeyGen             MechanismType = 0x00004009
	CkmSHA512TKeyGen               MechanismType = 0x0000400a
	CkmNull                        MechanismType = 0x0000400b
	CkmBlake2b160                  MechanismType = 0x0000400c
	CkmBlake2b160HMAC              MechanismType = 0x0000400d
	CkmBlake2b160HMACGeneral       MechanismType = 0x0000400e
	CkmBlake2b160KeyDerive         MechanismType = 0x0000400f
	CkmBlake2b160KeyGen            MechanismType = 0x00004010
	CkmBlake2b256                  MechanismType = 0x00004011
	CkmBlake2b256HMAC              MechanismType = 0x00004012
	CkmBlake2b256HMACGeneral       MechanismType = 0x00004013
	CkmBlake2b256KeyDerive         MechanismType = 0x00004014
	CkmBlake2b256KeyGen            MechanismType = 0x00004015
	CkmBlake2b384                  MechanismType = 0x00004016
	CkmBlake2b384HMAC              MechanismType = 0x00004017
	CkmBlake2b384HMACGeneral       MechanismType = 0x00004018
	CkmBlake2b384KeyDerive         MechanismType = 0x00004019
	CkmBlake2b384KeyGen            MechanismType = 0x0000401a
	CkmBlake2b512                  MechanismType = 0x0000401b
	CkmBlake2b512HMAC              MechanismType = 0x0000401c
	CkmBlake2b512HMACGeneral       MechanismType = 0x0000401d
	CkmBlake2b512KeyDerive         MechanismType = 0x0000401e
	CkmBlake2b512KeyGen            MechanismType = 0x0000401f
	CkmSalsa20                     MechanismType = 0x00004020
	CkmChaCha20Poly1305            MechanismType = 0x00004021
	CkmSalsa20Poly1305             MechanismType = 0x00004022
	CkmX3DHInitialize              MechanismType = 0x00004023
	CkmX3DHRespond                 MechanismType = 0x00004024
	CkmX2RatchetInitialize         MechanismType = 0x00004025
	CkmX2RatchetRespond            MechanismType = 0x00004026
	CkmX2RatchetEncrypt            MechanismType = 0x00004027
	CkmX2RatchetDecrypt            MechanismType = 0x00004028
	CkmXEDDSA                      MechanismType = 0x00004029
	CkmHKDFDerive                  MechanismType = 0x0000402a
	CkmHKDFData                    MechanismType = 0x0000402b
	CkmHKDFKeyGen                  MechanismType = 0x0000402c
	CkmECDSASHA3224                MechanismType = 0x00001047
	CkmECDSASHA3256                MechanismType = 0x00001048
	CkmECDSASHA3384                MechanismType = 0x00001049
	CkmECDSASHA3512                MechanismType = 0x0000104a
	CkmECEdwardsKeyPairGen         MechanismType = 0x00001055
	CkmECMontgomeryKeyPairGen      MechanismType = 0x00001056
	CkmEDDSA                       MechanismType = 0x00001057
	CkmSP800108CounterKDF          MechanismType = 0x000003ac
	CkmSP800108FeedbackKDF         MechanismType = 0x000003ad
	CkmSP800108DoublePipelineKDF   MechanismType = 0x000003ae
	CkmVendorDefined               MechanismType = 0x80000000
)

var ckmNames = map[MechanismType]string{
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

func (t MechanismType) String() string {
	name, ok := ckmNames[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{MechanismType %d}", t)
}

func (m Mechanism) String() string {
	if len(m.Parameter) > 0 {
		return fmt.Sprintf("%s: %x", m.Mechanism, m.Parameter)
	}
	return fmt.Sprintf("%s", m.Mechanism)
}

// Attribute types.
const (
	CkfArrayAttribute AttributeType = 0x40000000

	CkaClass                   AttributeType = 0x00000000
	CkaToken                   AttributeType = 0x00000001
	CkaPrivate                 AttributeType = 0x00000002
	CkaLabel                   AttributeType = 0x00000003
	CkaUniqueID                AttributeType = 0x00000004
	CkaApplication             AttributeType = 0x00000010
	CkaValue                   AttributeType = 0x00000011
	CkaObjectID                AttributeType = 0x00000012
	CkaCertificateType         AttributeType = 0x00000080
	CkaIssuer                  AttributeType = 0x00000081
	CkaSerialNumber            AttributeType = 0x00000082
	CkaACIssuer                AttributeType = 0x00000083
	CkaOwner                   AttributeType = 0x00000084
	CkaAttrTypes               AttributeType = 0x00000085
	CkaTrusted                 AttributeType = 0x00000086
	CkaCertificateCategory     AttributeType = 0x00000087
	CkaJavaMIDPSecurityDomain  AttributeType = 0x00000088
	CkaURL                     AttributeType = 0x00000089
	CkaHashOfSubjectPublicKey  AttributeType = 0x0000008A
	CkaHashOfIssuerPublicKey   AttributeType = 0x0000008B
	CkaNameHashAlgorithm       AttributeType = 0x0000008C
	CkaCheckValue              AttributeType = 0x00000090
	CkaKeyType                 AttributeType = 0x00000100
	CkaSubject                 AttributeType = 0x00000101
	CkaID                      AttributeType = 0x00000102
	CkaSensitive               AttributeType = 0x00000103
	CkaEncrypt                 AttributeType = 0x00000104
	CkaDecrypt                 AttributeType = 0x00000105
	CkaWrap                    AttributeType = 0x00000106
	CkaUnwrap                  AttributeType = 0x00000107
	CkaSign                    AttributeType = 0x00000108
	CkaSignRecover             AttributeType = 0x00000109
	CkaVerify                  AttributeType = 0x0000010A
	CkaVerifyRecover           AttributeType = 0x0000010B
	CkaDerive                  AttributeType = 0x0000010C
	CkaStartDate               AttributeType = 0x00000110
	CkaEndDate                 AttributeType = 0x00000111
	CkaModulus                 AttributeType = 0x00000120
	CkaModulusBits             AttributeType = 0x00000121
	CkaPublicExponent          AttributeType = 0x00000122
	CkaPrivateExponent         AttributeType = 0x00000123
	CkaPrime1                  AttributeType = 0x00000124
	CkaPrime2                  AttributeType = 0x00000125
	CkaExponent1               AttributeType = 0x00000126
	CkaExponent2               AttributeType = 0x00000127
	CkaCoefficient             AttributeType = 0x00000128
	CkaPublicKeyInfo           AttributeType = 0x00000129
	CkaPrime                   AttributeType = 0x00000130
	CkaSubprime                AttributeType = 0x00000131
	CkaBase                    AttributeType = 0x00000132
	CkaPrimeBits               AttributeType = 0x00000133
	CkaSubPrimeBits            AttributeType = 0x00000134
	CkaValueBits               AttributeType = 0x00000160
	CkaValueLen                AttributeType = 0x00000161
	CkaExtractable             AttributeType = 0x00000162
	CkaLocal                   AttributeType = 0x00000163
	CkaNeverExtractable        AttributeType = 0x00000164
	CkaAlwaysSensitive         AttributeType = 0x00000165
	CkaKeyGenMechanism         AttributeType = 0x00000166
	CkaModifiable              AttributeType = 0x00000170
	CkaCopyable                AttributeType = 0x00000171
	CkaDestroyable             AttributeType = 0x00000172
	CkaEcdsaParams             AttributeType = 0x00000180 /* Deprecated */
	CkaECParams                AttributeType = 0x00000180
	CkaECPoint                 AttributeType = 0x00000181
	CkaSecondaryAuth           AttributeType = 0x00000200 /* Deprecated */
	CkaAuthPinFlags            AttributeType = 0x00000201 /* Deprecated */
	CkaAlwaysAuthenticate      AttributeType = 0x00000202
	CkaWrapWithTrusted         AttributeType = 0x00000210
	CkaWrapTemplate            AttributeType = CkfArrayAttribute | 0x00000211
	CkaUnwrapTemplate          AttributeType = CkfArrayAttribute | 0x00000212
	CkaDeriveTemplate          AttributeType = CkfArrayAttribute | 0x00000213
	CkaOtpFormat               AttributeType = 0x00000220
	CkaOtpLength               AttributeType = 0x00000221
	CkaOtpTimeInterval         AttributeType = 0x00000222
	CkaOtpUserFriendlyMode     AttributeType = 0x00000223
	CkaOtpChallengeRequirement AttributeType = 0x00000224
	CkaOtpTimeRequirement      AttributeType = 0x00000225
	CkaOtpCounterRequirement   AttributeType = 0x00000226
	CkaOtpPinRequirement       AttributeType = 0x00000227
	CkaOtpCounter              AttributeType = 0x0000022E
	CkaOtpTime                 AttributeType = 0x0000022F
	CkaOtpUserIdentifier       AttributeType = 0x0000022A
	CkaOtpServiceIdentifier    AttributeType = 0x0000022B
	CkaOtpServiceLogo          AttributeType = 0x0000022C
	CkaOtpServiceLogoType      AttributeType = 0x0000022D
	CkaGostr3410Params         AttributeType = 0x00000250
	CkaGostr3411Params         AttributeType = 0x00000251
	CkaGost28147Params         AttributeType = 0x00000252
	CkaHWFeatureType           AttributeType = 0x00000300
	CkaResetOnInit             AttributeType = 0x00000301
	CkaHasReset                AttributeType = 0x00000302
	CkaPixelX                  AttributeType = 0x00000400
	CkaPixelY                  AttributeType = 0x00000401
	CkaResolution              AttributeType = 0x00000402
	CkaCharRows                AttributeType = 0x00000403
	CkaCharColumns             AttributeType = 0x00000404
	CkaColor                   AttributeType = 0x00000405
	CkaBitsPerPixel            AttributeType = 0x00000406
	CkaCharSets                AttributeType = 0x00000480
	CkaEncodingMethods         AttributeType = 0x00000481
	CkaMimeTypes               AttributeType = 0x00000482
	CkaMechanismType           AttributeType = 0x00000500
	CkaRequiredCMSAttributes   AttributeType = 0x00000501
	CkaDefaultCMSAttributes    AttributeType = 0x00000502
	CkaSupportedCMSAttributes  AttributeType = 0x00000503
	CkaAllowedMechanisms       AttributeType = CkfArrayAttribute | 0x00000600
	CkaProfileID               AttributeType = 0x00000601
	CkaVendorDefined           AttributeType = 0x80000000
)

var ckaNames = map[AttributeType]string{
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

func (t AttributeType) String() string {
	name, ok := ckaNames[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{AttributeType %d}", t)
}

// Bool returns the attribute value as bool.
func (attr Attribute) Bool() (bool, error) {
	switch len(attr.Value) {
	case 1:
		return attr.Value[0] != 0, nil

	default:
		return false, ErrTemplateInconsistent
	}
}

// Int returns the attribute value as integer number.
func (attr Attribute) Int() (int, error) {
	switch len(attr.Value) {
	case 1:
		return int(attr.Value[0]), nil

	case 2:
		return int(HBO.Uint16(attr.Value)), nil

	case 4:
		return int(HBO.Uint32(attr.Value)), nil

	case 8:
		return int(HBO.Uint64(attr.Value)), nil

	default:
		return 0, fmt.Errorf("invalid attribute length %d", len(attr.Value))
	}
}

// BigInt returns the attribute valiue as *big.Int.
func (attr Attribute) BigInt() (*big.Int, error) {
	return new(big.Int).SetBytes(attr.Value), nil
}

// Object classes.
const (
	CkoData             ObjectClass = 0x00000000
	CkoCertificate      ObjectClass = 0x00000001
	CkoPublicKey        ObjectClass = 0x00000002
	CkoPrivateKey       ObjectClass = 0x00000003
	CkoSecretKey        ObjectClass = 0x00000004
	CkoHWFeature        ObjectClass = 0x00000005
	CkoDomainParameters ObjectClass = 0x00000006
	CkoMechanism        ObjectClass = 0x00000007
	CkoOtpKey           ObjectClass = 0x00000008
	CkoProfile          ObjectClass = 0x00000009
	CkoVendorDefined    ObjectClass = 0x80000000
)

var ckoNames = map[ObjectClass]string{
	CkoData:             "CKO_DATA",
	CkoCertificate:      "CKO_CERTIFICATE",
	CkoPublicKey:        "CKO_PUBLIC_KEY",
	CkoPrivateKey:       "CKO_PRIVATE_KEY",
	CkoSecretKey:        "CKO_SECRET_KEY",
	CkoHWFeature:        "CKO_HW_FEATURE",
	CkoDomainParameters: "CKO_DOMAIN_PARAMETERS",
	CkoMechanism:        "CKO_MECHANISM",
	CkoOtpKey:           "CKO_OTP_KEY",
	CkoProfile:          "CKO_PROFILE",
	CkoVendorDefined:    "CKO_VENDOR_DEFINED",
}

func (c ObjectClass) String() string {
	name, ok := ckoNames[c]
	if ok {
		return name
	}
	return fmt.Sprintf("{ObjectClass %d}", c)
}

// User types.
const (
	CkuSO UserType = iota
	CkuUser
	CkuContextSpecific
)

// Session states.
const (
	CksROPublicSession State = iota
	CksROUserFunctions
	CksRWPublicSession
	CksRWUserFunctions
	CksRWSOFunctions
)

// Key types.
const (
	CkkRSA            KeyType = 0x00000000
	CkkDSA            KeyType = 0x00000001
	CkkDH             KeyType = 0x00000002
	CkkEC             KeyType = 0x00000003
	CkkX942DH         KeyType = 0x00000004
	CkkKea            KeyType = 0x00000005
	CkkGenericSecret  KeyType = 0x00000010
	CkkRC2            KeyType = 0x00000011
	CkkRC4            KeyType = 0x00000012
	CkkDES            KeyType = 0x00000013
	CkkDES2           KeyType = 0x00000014
	CkkDES3           KeyType = 0x00000015
	CkkCAST           KeyType = 0x00000016
	CkkCAST3          KeyType = 0x00000017
	CkkCAST128        KeyType = 0x00000018
	CkkRC5            KeyType = 0x00000019
	CkkIDEA           KeyType = 0x0000001A
	CkkSkipjack       KeyType = 0x0000001B
	CkkBaton          KeyType = 0x0000001C
	CkkJuniper        KeyType = 0x0000001D
	CkkCDMF           KeyType = 0x0000001E
	CkkAES            KeyType = 0x0000001F
	CkkBlowfish       KeyType = 0x00000020
	CkkTwofish        KeyType = 0x00000021
	CkkSecurID        KeyType = 0x00000022
	CkkHOTP           KeyType = 0x00000023
	CkkACTI           KeyType = 0x00000024
	CkkCamellia       KeyType = 0x00000025
	CkkAria           KeyType = 0x00000026
	CkkMD5HMAC        KeyType = 0x00000027
	CkkSHA1HMAC       KeyType = 0x00000028
	CkkRIPEMD128HMAC  KeyType = 0x00000029
	CkkRIPEMD160HMAC  KeyType = 0x0000002A
	CkkSHA256HMAC     KeyType = 0x0000002B
	CkkSHA384HMAC     KeyType = 0x0000002C
	CkkSHA512HMAC     KeyType = 0x0000002D
	CkkSHA224HMAC     KeyType = 0x0000002E
	CkkSeed           KeyType = 0x0000002F
	CkkGostR3410      KeyType = 0x00000030
	CkkGostr3411      KeyType = 0x00000031
	CkkGost28147      KeyType = 0x00000032
	CkkChaCha20       KeyType = 0x00000033
	CkkPoly1305       KeyType = 0x00000034
	CkkAESXTS         KeyType = 0x00000035
	CkkSHA3224HMAC    KeyType = 0x00000036
	CkkSHA3256HMAC    KeyType = 0x00000037
	CkkSHA3384HMAC    KeyType = 0x00000038
	CkkSHA3512HMAC    KeyType = 0x00000039
	CkkBlake2b160HMAC KeyType = 0x0000003a
	CkkBlake2b256HMAC KeyType = 0x0000003b
	CkkBlake2b384HMAC KeyType = 0x0000003c
	CkkBlake2b512HMAC KeyType = 0x0000003d
	CkkSalsa20        KeyType = 0x0000003e
	CkkX2Ratchet      KeyType = 0x0000003f
	CkkECEdwards      KeyType = 0x00000040
	CkkECMontgomery   KeyType = 0x00000041
	CkkHKDF           KeyType = 0x00000042
	CkkVendorDefined  KeyType = 0x80000000
)

var ckkNames = map[KeyType]string{
	CkkRSA:            "CKK_RSA",
	CkkDSA:            "CKK_DSA",
	CkkDH:             "CKK_DH",
	CkkEC:             "CKK_EC",
	CkkX942DH:         "CKK_X9_42_DH",
	CkkKea:            "CKK_KEA",
	CkkGenericSecret:  "CKK_GENERIC_SECRET",
	CkkRC2:            "CKK_RC2",
	CkkRC4:            "CKK_RC4",
	CkkDES:            "CKK_DES",
	CkkDES2:           "CKK_DES2",
	CkkDES3:           "CKK_DES3",
	CkkCAST:           "CKK_CAST",
	CkkCAST3:          "CKK_CAST3",
	CkkCAST128:        "CKK_CAST128",
	CkkRC5:            "CKK_RC5",
	CkkIDEA:           "CKK_IDEA",
	CkkSkipjack:       "CKK_SKIPJACK",
	CkkBaton:          "CKK_BATON",
	CkkJuniper:        "CKK_JUNIPER",
	CkkCDMF:           "CKK_CDMF",
	CkkAES:            "CKK_AES",
	CkkBlowfish:       "CKK_BLOWFISH",
	CkkTwofish:        "CKK_TWOFISH",
	CkkSecurID:        "CKK_SECURID",
	CkkHOTP:           "CKK_HOTP",
	CkkACTI:           "CKK_ACTI",
	CkkCamellia:       "CKK_CAMELLIA",
	CkkAria:           "CKK_ARIA",
	CkkMD5HMAC:        "CKK_MD5_HMAC",
	CkkSHA1HMAC:       "CKK_SHA_1_HMAC",
	CkkRIPEMD128HMAC:  "CKK_RIPEMD128_HMAC",
	CkkRIPEMD160HMAC:  "CKK_RIPEMD160_HMAC",
	CkkSHA256HMAC:     "CKK_SHA256_HMAC",
	CkkSHA384HMAC:     "CKK_SHA384_HMAC",
	CkkSHA512HMAC:     "CKK_SHA512_HMAC",
	CkkSHA224HMAC:     "CKK_SHA224_HMAC",
	CkkSeed:           "CKK_SEED",
	CkkGostR3410:      "CKK_GOSTR3410",
	CkkGostr3411:      "CKK_GOSTR3411",
	CkkGost28147:      "CKK_GOST28147",
	CkkChaCha20:       "CKK_CHACHA20",
	CkkPoly1305:       "CKK_POLY1305",
	CkkAESXTS:         "CKK_AES_XTS",
	CkkSHA3224HMAC:    "CKK_SHA3_224_HMAC",
	CkkSHA3256HMAC:    "CKK_SHA3_256_HMAC",
	CkkSHA3384HMAC:    "CKK_SHA3_384_HMAC",
	CkkSHA3512HMAC:    "CKK_SHA3_512_HMAC",
	CkkBlake2b160HMAC: "CKK_BLAKE2B_160_HMAC",
	CkkBlake2b256HMAC: "CKK_BLAKE2B_256_HMAC",
	CkkBlake2b384HMAC: "CKK_BLAKE2B_384_HMAC",
	CkkBlake2b512HMAC: "CKK_BLAKE2B_512_HMAC",
	CkkSalsa20:        "CKK_SALSA20",
	CkkX2Ratchet:      "CKK_X2RATCHET",
	CkkECEdwards:      "CKK_EC_EDWARDS",
	CkkECMontgomery:   "CKK_EC_MONTGOMERY",
	CkkHKDF:           "CKK_HKDF",
	CkkVendorDefined:  "CKK_VENDOR_DEFINED",
}

func (t KeyType) String() string {
	name, ok := ckkNames[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{KeyType %d}", t)
}

// Template defines attributes for objects.
type Template []Attribute

// Match matches the template to the argument template. The template
// matches if all attributes of the argument template are found.
func (tmpl Template) Match(t Template) bool {
	for _, attr := range t {
		if !tmpl.matchAttr(attr) {
			return false
		}
	}
	return true
}

func (tmpl Template) matchAttr(a Attribute) bool {
	for _, attr := range tmpl {
		if attr.Type == a.Type && bytes.Compare(attr.Value, a.Value) == 0 {
			return true
		}
	}
	return false
}

// Set sets the value of the attribute t to value v in the
// template. The function returns a new template.
func (tmpl Template) Set(t AttributeType, v []Byte) Template {
	var result Template

	// Filter attribute from template.
	for _, attr := range tmpl {
		if attr.Type != t {
			result = append(result, attr)
		}
	}
	// Add new type-value pair.
	return append(result, Attribute{
		Type:  t,
		Value: v,
	})
}

// SetInt sets the integer value of the attribute.
func (tmpl Template) SetInt(t AttributeType, v int) Template {
	var buf [8]byte

	switch bits.UintSize {
	case 32:
		HBO.PutUint32(buf[:4], uint32(v))
		return tmpl.Set(t, buf[:4])

	case 64:
		HBO.PutUint64(buf[:8], uint64(v))
		return tmpl.Set(t, buf[:8])

	default:
		panic("unexpected bits.UintSize")
	}
}

// SetBool sets the boolean value of the attribute.
func (tmpl Template) SetBool(t AttributeType, v bool) Template {
	var buf [1]byte

	if v {
		buf[0] = 0x1
	}

	return tmpl.Set(t, buf[:])
}

// Bool returns attribute value as bool.
func (tmpl Template) Bool(t AttributeType) (bool, error) {
	for _, attr := range tmpl {
		if attr.Type == t {
			return attr.Bool()
		}
	}
	return false, ErrTemplateIncomplete
}

// OptBool returns an optional attribute value as bool. The PKCS #11
// standard default values will be used for attributes which has not
// been set in the template.
func (tmpl Template) OptBool(t AttributeType) (bool, error) {
	for _, attr := range tmpl {
		if attr.Type == t {
			return attr.Bool()
		}
	}
	// Default values.
	switch t {
	case CkaToken, CkaPrivate, CkaSensitive, CkaWrapWithTrusted, CkaExtractable:
		return false, nil

	case CkaModifiable, CkaCopyable, CkaDestroyable:
		return true, nil

	default:
		log.Printf("no default value for attribute %s", t)
		return false, ErrTemplateIncomplete
	}
}

// Int returns the attribute value as an integer number.
func (tmpl Template) Int(t AttributeType) (int, error) {
	for _, attr := range tmpl {
		if attr.Type == t {
			return attr.Int()
		}
	}
	return 0, ErrTemplateIncomplete
}

// OptInt returns the optional attribute value as an integer
// number. If the attribute is not defined in the template, the
// function returns the default value.
func (tmpl Template) OptInt(t AttributeType, def int) int {
	for _, attr := range tmpl {
		if attr.Type == t {
			v, err := attr.Int()
			if err != nil {
				break
			}
			return v
		}
	}
	return def
}

// BigInt returns the attribute value as *big.Int.
func (tmpl Template) BigInt(t AttributeType) (*big.Int, error) {
	for _, attr := range tmpl {
		if attr.Type == t {
			return attr.BigInt()
		}
	}
	return nil, ErrTemplateIncomplete
}

// OptBytes returns an optional attribute value as byte array.
func (tmpl Template) OptBytes(t AttributeType) ([]byte, error) {
	for _, attr := range tmpl {
		if attr.Type == t {
			return attr.Value, nil
		}
	}
	return nil, ErrTemplateIncomplete
}
