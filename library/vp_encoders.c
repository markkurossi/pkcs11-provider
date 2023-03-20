/*
 * Copyright (c) 2023 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

typedef struct CK_GCM_PARAMS_V230 {
    CK_BYTE_PTR       pIv;
    CK_ULONG          ulIvLen;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulTagBits;
} CK_GCM_PARAMS_V230;

typedef CK_GCM_PARAMS_V230 CK_PTR CK_GCM_PARAMS_V230_PTR;


CK_RV
vp_encode_mechanism(VPBuffer *buf, CK_MECHANISM_PTR m)
{
  CK_RV ret = CKR_OK;
  VPBuffer b;

  vp_buffer_init(&b);

  vp_buffer_add_ulong(buf, m->mechanism);

  switch (m->mechanism)
    {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_PKCS:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
    case CKM_EC_KEY_PAIR_GEN:
    case CKM_ECDSA_SHA512:
    case CKM_AES_KEY_GEN:
    case CKM_AES_ECB:
      if (m->ulParameterLen != 0)
        {
          vp_log(LOG_ERR, "mechanism: %08x: unexpected parameter: len=%d",
                 m->mechanism, m->ulParameterLen);
          return CKR_MECHANISM_INVALID;
        }
      vp_buffer_add_byte_arr(buf, m->pParameter, m->ulParameterLen);
      break;

    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      if (m->ulParameterLen != 16)
        {
          vp_log(LOG_ERR, "mechanism: %08x: invalid IV: len=%d",
                 m->mechanism, m->ulParameterLen);
          return CKR_MECHANISM_INVALID;
        }
      vp_buffer_add_byte_arr(buf, m->pParameter, m->ulParameterLen);
      break;

    case CKM_AES_CTR:
      if (m->ulParameterLen == sizeof(CK_AES_CTR_PARAMS))
        {
          CK_AES_CTR_PARAMS_PTR p = (CK_AES_CTR_PARAMS_PTR) m->pParameter;

          vp_buffer_add_ulong(&b, p->ulCounterBits);
          vp_buffer_add_byte_arr(&b, p->cb, sizeof(p->cb));

          if (vp_buffer_error(&b, &ret))
            goto out;

          vp_buffer_add_byte_arr(buf, vp_buffer_ptr(&b), vp_buffer_len(&b));
        }
      else
        {
          vp_log(LOG_ERR,
                 "mechanism: %08x: invalid CK_AES_CTR_PARAMS: len=%d (%d)",
                 m->mechanism, m->ulParameterLen, sizeof(CK_AES_CTR_PARAMS));
          return CKR_MECHANISM_INVALID;
        }

      break;

    case CKM_AES_GCM:
      if (m->ulParameterLen == sizeof(CK_GCM_PARAMS_V230))
        {
          CK_GCM_PARAMS_V230_PTR p = (CK_GCM_PARAMS_V230_PTR) m->pParameter;

          vp_buffer_add_byte_arr(&b, p->pIv, p->ulIvLen);
          vp_buffer_add_ulong(&b, p->ulIvLen * 8);
          vp_buffer_add_byte_arr(&b, p->pAAD, p->ulAADLen);
          vp_buffer_add_ulong(&b, p->ulTagBits);

          if (vp_buffer_error(&b, &ret))
            goto out;

          vp_buffer_add_byte_arr(buf, vp_buffer_ptr(&b), vp_buffer_len(&b));
        }
      else if (m->ulParameterLen == sizeof(CK_GCM_PARAMS))
        {
          CK_GCM_PARAMS_PTR p = (CK_GCM_PARAMS_PTR) m->pParameter;

          vp_buffer_add_byte_arr(&b, p->pIv, p->ulIvLen);
          vp_buffer_add_ulong(&b, p->ulIvBits);
          vp_buffer_add_byte_arr(&b, p->pAAD, p->ulAADLen);
          vp_buffer_add_ulong(&b, p->ulTagBits);

          if (vp_buffer_error(&b, &ret))
            goto out;

          vp_buffer_add_byte_arr(buf, vp_buffer_ptr(&b), vp_buffer_len(&b));
        }
      else
        {
          vp_log(LOG_ERR, "mechanism: %08x: invalid CK_GCM_PARAMS: len=%d (%d)",
                 m->mechanism, m->ulParameterLen, sizeof(CK_GCM_PARAMS));
          return CKR_MECHANISM_INVALID;
        }
      break;

    default:
      vp_log(LOG_ERR, "mechanism: %08x: unsupported: ulParameterLen=%d",
             m->mechanism, m->ulParameterLen);
      return CKR_MECHANISM_INVALID;
    }


 out:

  vp_buffer_uninit(&b);

  return ret;
}
