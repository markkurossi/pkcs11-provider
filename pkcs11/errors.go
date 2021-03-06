//
// Copyright (c) 2021 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"fmt"
)

// CKRV defines the API function return value.
type CKRV uint32

func (rv CKRV) Error() string {
	name, ok := ckrvs[rv]
	if ok {
		return name
	}
	return fmt.Sprintf("{CKRV %d}", rv)
}

// API return values.
const (
	ErrOk                            CKRV = 0x00000000
	ErrCancel                        CKRV = 0x00000001
	ErrHostMemory                    CKRV = 0x00000002
	ErrSlotIDInvalid                 CKRV = 0x00000003
	ErrGeneralError                  CKRV = 0x00000005
	ErrFunctionFailed                CKRV = 0x00000006
	ErrArgumentsBad                  CKRV = 0x00000007
	ErrNoEvent                       CKRV = 0x00000008
	ErrNeedToCreateThreads           CKRV = 0x00000009
	ErrCantLock                      CKRV = 0x0000000A
	ErrAttributeReadOnly             CKRV = 0x00000010
	ErrAttributeSensitive            CKRV = 0x00000011
	ErrAttributeTypeInvalid          CKRV = 0x00000012
	ErrAttributeValueInvalid         CKRV = 0x00000013
	ErrActionProhibited              CKRV = 0x0000001B
	ErrDataInvalid                   CKRV = 0x00000020
	ErrDataLenRange                  CKRV = 0x00000021
	ErrDeviceError                   CKRV = 0x00000030
	ErrDeviceMemory                  CKRV = 0x00000031
	ErrDeviceRemoved                 CKRV = 0x00000032
	ErrEncryptedDataInvalid          CKRV = 0x00000040
	ErrEncryptedDataLenRange         CKRV = 0x00000041
	ErrAeadDecryptFailed             CKRV = 0x00000042
	ErrFunctionCanceled              CKRV = 0x00000050
	ErrFunctionNotParallel           CKRV = 0x00000051
	ErrFunctionNotSupported          CKRV = 0x00000054
	ErrKeyHandleInvalid              CKRV = 0x00000060
	ErrKeySizeRange                  CKRV = 0x00000062
	ErrKeyTypeInconsistent           CKRV = 0x00000063
	ErrKeyNotNeeded                  CKRV = 0x00000064
	ErrKeyChanged                    CKRV = 0x00000065
	ErrKeyNeeded                     CKRV = 0x00000066
	ErrKeyIndigestible               CKRV = 0x00000067
	ErrKeyFunctionNotPermitted       CKRV = 0x00000068
	ErrKeyNotWrappable               CKRV = 0x00000069
	ErrKeyUnextractable              CKRV = 0x0000006A
	ErrMechanismInvalid              CKRV = 0x00000070
	ErrMechanismParamInvalid         CKRV = 0x00000071
	ErrObjectHandleInvalid           CKRV = 0x00000082
	ErrOperationActive               CKRV = 0x00000090
	ErrOperationNotInitialized       CKRV = 0x00000091
	ErrPinIncorrect                  CKRV = 0x000000A0
	ErrPinInvalid                    CKRV = 0x000000A1
	ErrPinLenRange                   CKRV = 0x000000A2
	ErrPinExpired                    CKRV = 0x000000A3
	ErrPinLocked                     CKRV = 0x000000A4
	ErrSessionClosed                 CKRV = 0x000000B0
	ErrSessionCount                  CKRV = 0x000000B1
	ErrSessionHandleInvalid          CKRV = 0x000000B3
	ErrSessionParallelNotSupported   CKRV = 0x000000B4
	ErrSessionReadOnly               CKRV = 0x000000B5
	ErrSessionExists                 CKRV = 0x000000B6
	ErrSessionReadOnlyExists         CKRV = 0x000000B7
	ErrSessionReadWriteSoExists      CKRV = 0x000000B8
	ErrSignatureInvalid              CKRV = 0x000000C0
	ErrSignatureLenRange             CKRV = 0x000000C1
	ErrTemplateIncomplete            CKRV = 0x000000D0
	ErrTemplateInconsistent          CKRV = 0x000000D1
	ErrTokenNotPresent               CKRV = 0x000000E0
	ErrTokenNotRecognized            CKRV = 0x000000E1
	ErrTokenWriteProtected           CKRV = 0x000000E2
	ErrUnwrappingKeyHandleInvalid    CKRV = 0x000000F0
	ErrUnwrappingKeySizeRange        CKRV = 0x000000F1
	ErrUnwrappingKeyTypeInconsistent CKRV = 0x000000F2
	ErrUserAlreadyLoggedIn           CKRV = 0x00000100
	ErrUserNotLoggedIn               CKRV = 0x00000101
	ErrUserPinNotInitialized         CKRV = 0x00000102
	ErrUserTypeInvalid               CKRV = 0x00000103
	ErrUserAnotherAlreadyLoggedIn    CKRV = 0x00000104
	ErrUserTooManyTypes              CKRV = 0x00000105
	ErrWrappedKeyInvalid             CKRV = 0x00000110
	ErrWrappedKeyLenRange            CKRV = 0x00000112
	ErrWrappingKeyHandleInvalid      CKRV = 0x00000113
	ErrWrappingKeySizeRange          CKRV = 0x00000114
	ErrWrappingKeyTypeInconsistent   CKRV = 0x00000115
	ErrRandomSeedNotSupported        CKRV = 0x00000120
	ErrRandomNoRng                   CKRV = 0x00000121
	ErrDomainParamsInvalid           CKRV = 0x00000130
	ErrCurveNotSupported             CKRV = 0x00000140
	ErrBufferTooSmall                CKRV = 0x00000150
	ErrSavedStateInvalid             CKRV = 0x00000160
	ErrInformationSensitive          CKRV = 0x00000170
	ErrStateUnsaveable               CKRV = 0x00000180
	ErrCryptokiNotInitialized        CKRV = 0x00000190
	ErrCryptokiAlreadyInitialized    CKRV = 0x00000191
	ErrMutexBad                      CKRV = 0x000001A0
	ErrMutexNotLocked                CKRV = 0x000001A1
	ErrNewPinMode                    CKRV = 0x000001B0
	ErrNextOtp                       CKRV = 0x000001B1
	ErrExceededMaxIterations         CKRV = 0x000001B5
	ErrFipsSelfTestFailed            CKRV = 0x000001B6
	ErrLibraryLoadFailed             CKRV = 0x000001B7
	ErrPinTooWeak                    CKRV = 0x000001B8
	ErrPublicKeyInvalid              CKRV = 0x000001B9
	ErrFunctionRejected              CKRV = 0x00000200
	ErrTokenResourceExceeded         CKRV = 0x00000201
	ErrVendorDefined                 CKRV = 0x80000000
)

var ckrvs = map[CKRV]string{
	ErrOk:                            "CKR_OK",
	ErrCancel:                        "CKR_CANCEL",
	ErrHostMemory:                    "CKR_HOST_MEMORY",
	ErrSlotIDInvalid:                 "CKR_SLOT_ID_INVALID",
	ErrGeneralError:                  "CKR_GENERAL_ERROR",
	ErrFunctionFailed:                "CKR_FUNCTION_FAILED",
	ErrArgumentsBad:                  "CKR_ARGUMENTS_BAD",
	ErrNoEvent:                       "CKR_NO_EVENT",
	ErrNeedToCreateThreads:           "CKR_NEED_TO_CREATE_THREADS",
	ErrCantLock:                      "CKR_CANT_LOCK",
	ErrAttributeReadOnly:             "CKR_ATTRIBUTE_READ_ONLY",
	ErrAttributeSensitive:            "CKR_ATTRIBUTE_SENSITIVE",
	ErrAttributeTypeInvalid:          "CKR_ATTRIBUTE_TYPE_INVALID",
	ErrAttributeValueInvalid:         "CKR_ATTRIBUTE_VALUE_INVALID",
	ErrActionProhibited:              "CKR_ACTION_PROHIBITED",
	ErrDataInvalid:                   "CKR_DATA_INVALID",
	ErrDataLenRange:                  "CKR_DATA_LEN_RANGE",
	ErrDeviceError:                   "CKR_DEVICE_ERROR",
	ErrDeviceMemory:                  "CKR_DEVICE_MEMORY",
	ErrDeviceRemoved:                 "CKR_DEVICE_REMOVED",
	ErrEncryptedDataInvalid:          "CKR_ENCRYPTED_DATA_INVALID",
	ErrEncryptedDataLenRange:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
	ErrAeadDecryptFailed:             "CKR_AEAD_DECRYPT_FAILED",
	ErrFunctionCanceled:              "CKR_FUNCTION_CANCELED",
	ErrFunctionNotParallel:           "CKR_FUNCTION_NOT_PARALLEL",
	ErrFunctionNotSupported:          "CKR_FUNCTION_NOT_SUPPORTED",
	ErrKeyHandleInvalid:              "CKR_KEY_HANDLE_INVALID",
	ErrKeySizeRange:                  "CKR_KEY_SIZE_RANGE",
	ErrKeyTypeInconsistent:           "CKR_KEY_TYPE_INCONSISTENT",
	ErrKeyNotNeeded:                  "CKR_KEY_NOT_NEEDED",
	ErrKeyChanged:                    "CKR_KEY_CHANGED",
	ErrKeyNeeded:                     "CKR_KEY_NEEDED",
	ErrKeyIndigestible:               "CKR_KEY_INDIGESTIBLE",
	ErrKeyFunctionNotPermitted:       "CKR_KEY_FUNCTION_NOT_PERMITTED",
	ErrKeyNotWrappable:               "CKR_KEY_NOT_WRAPPABLE",
	ErrKeyUnextractable:              "CKR_KEY_UNEXTRACTABLE",
	ErrMechanismInvalid:              "CKR_MECHANISM_INVALID",
	ErrMechanismParamInvalid:         "CKR_MECHANISM_PARAM_INVALID",
	ErrObjectHandleInvalid:           "CKR_OBJECT_HANDLE_INVALID",
	ErrOperationActive:               "CKR_OPERATION_ACTIVE",
	ErrOperationNotInitialized:       "CKR_OPERATION_NOT_INITIALIZED",
	ErrPinIncorrect:                  "CKR_PIN_INCORRECT",
	ErrPinInvalid:                    "CKR_PIN_INVALID",
	ErrPinLenRange:                   "CKR_PIN_LEN_RANGE",
	ErrPinExpired:                    "CKR_PIN_EXPIRED",
	ErrPinLocked:                     "CKR_PIN_LOCKED",
	ErrSessionClosed:                 "CKR_SESSION_CLOSED",
	ErrSessionCount:                  "CKR_SESSION_COUNT",
	ErrSessionHandleInvalid:          "CKR_SESSION_HANDLE_INVALID",
	ErrSessionParallelNotSupported:   "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	ErrSessionReadOnly:               "CKR_SESSION_READ_ONLY",
	ErrSessionExists:                 "CKR_SESSION_EXISTS",
	ErrSessionReadOnlyExists:         "CKR_SESSION_READ_ONLY_EXISTS",
	ErrSessionReadWriteSoExists:      "CKR_SESSION_READ_WRITE_SO_EXISTS",
	ErrSignatureInvalid:              "CKR_SIGNATURE_INVALID",
	ErrSignatureLenRange:             "CKR_SIGNATURE_LEN_RANGE",
	ErrTemplateIncomplete:            "CKR_TEMPLATE_INCOMPLETE",
	ErrTemplateInconsistent:          "CKR_TEMPLATE_INCONSISTENT",
	ErrTokenNotPresent:               "CKR_TOKEN_NOT_PRESENT",
	ErrTokenNotRecognized:            "CKR_TOKEN_NOT_RECOGNIZED",
	ErrTokenWriteProtected:           "CKR_TOKEN_WRITE_PROTECTED",
	ErrUnwrappingKeyHandleInvalid:    "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	ErrUnwrappingKeySizeRange:        "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	ErrUnwrappingKeyTypeInconsistent: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTEN",
	ErrUserAlreadyLoggedIn:           "CKR_USER_ALREADY_LOGGED_IN",
	ErrUserNotLoggedIn:               "CKR_USER_NOT_LOGGED_IN",
	ErrUserPinNotInitialized:         "CKR_USER_PIN_NOT_INITIALIZED",
	ErrUserTypeInvalid:               "CKR_USER_TYPE_INVALID",
	ErrUserAnotherAlreadyLoggedIn:    "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	ErrUserTooManyTypes:              "CKR_USER_TOO_MANY_TYPES",
	ErrWrappedKeyInvalid:             "CKR_WRAPPED_KEY_INVALID",
	ErrWrappedKeyLenRange:            "CKR_WRAPPED_KEY_LEN_RANGE",
	ErrWrappingKeyHandleInvalid:      "CKR_WRAPPING_KEY_HANDLE_INVALID",
	ErrWrappingKeySizeRange:          "CKR_WRAPPING_KEY_SIZE_RANGE",
	ErrWrappingKeyTypeInconsistent:   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	ErrRandomSeedNotSupported:        "CKR_RANDOM_SEED_NOT_SUPPORTED",
	ErrRandomNoRng:                   "CKR_RANDOM_NO_RNG",
	ErrDomainParamsInvalid:           "CKR_DOMAIN_PARAMS_INVALID",
	ErrCurveNotSupported:             "CKR_CURVE_NOT_SUPPORTED",
	ErrBufferTooSmall:                "CKR_BUFFER_TOO_SMALL",
	ErrSavedStateInvalid:             "CKR_SAVED_STATE_INVALID",
	ErrInformationSensitive:          "CKR_INFORMATION_SENSITIVE",
	ErrStateUnsaveable:               "CKR_STATE_UNSAVEABLE",
	ErrCryptokiNotInitialized:        "CKR_CRYPTOKI_NOT_INITIALIZED",
	ErrCryptokiAlreadyInitialized:    "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	ErrMutexBad:                      "CKR_MUTEX_BAD",
	ErrMutexNotLocked:                "CKR_MUTEX_NOT_LOCKED",
	ErrNewPinMode:                    "CKR_NEW_PIN_MODE",
	ErrNextOtp:                       "CKR_NEXT_OTP",
	ErrExceededMaxIterations:         "CKR_EXCEEDED_MAX_ITERATIONS",
	ErrFipsSelfTestFailed:            "CKR_FIPS_SELF_TEST_FAILED",
	ErrLibraryLoadFailed:             "CKR_LIBRARY_LOAD_FAILED",
	ErrPinTooWeak:                    "CKR_PIN_TOO_WEAK",
	ErrPublicKeyInvalid:              "CKR_PUBLIC_KEY_INVALID",
	ErrFunctionRejected:              "CKR_FUNCTION_REJECTED",
	ErrTokenResourceExceeded:         "CKR_TOKEN_RESOURCE_EXCEEDED",
	ErrVendorDefined:                 "CKR_VENDOR_DEFINED",
}
