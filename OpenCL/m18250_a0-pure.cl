/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Kerberos 5, etype 23, AS-REP (NT)
 * Variant of -m 18200 where the input candidate is a raw NT hash (32 hex -> 16 bytes).
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

#ifndef FIXED_LOCAL_SIZE
#define FIXED_LOCAL_SIZE 32
#endif

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;
  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);
  return v;
}
#endif

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;
} krb5asrep_t;

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, PRIVATE_AS const u32 *K2, PRIVATE_AS const u32 *checksum, const u64 lid)
{
  rc4_init_128 (S, data, lid);

  u32 out0[4];

  // ASN.1 sanity (APPLICATION 25 / 0x79, then SEQUENCE / 0x30)
  rc4_next_16_global (S, 0, 0, edata2 + 0, out0, lid);

  if (((out0[2] & 0x00ff80ff) != 0x00300079) &&
      ((out0[2] & 0xFF00FFFF) != 0x30008179) &&
      ((out0[2] & 0x0000FFFF) != 0x00008279 || (out0[3] & 0x000000FF) != 0x00000030))
  {
    return 0;
  }

  rc4_init_128 (S, data, lid);

  u8 i = 0;
  u8 j = 0;

  u32 w0[4], w1[4], w2[4], w3[4];

  w0[0] = K2[0];
  w0[1] = K2[1];
  w0[2] = K2[2];
  w0[3] = K2[3];
  w1[0] = w1[1] = w1[2] = w1[3] = 0;
  w2[0] = w2[1] = w2[2] = w2[3] = 0;
  w3[0] = w3[1] = w3[2] = w3[3] = 0;

  md5_hmac_ctx_t ctx;
  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  int edata2_left;

  for (edata2_left = edata2_len; edata2_left >= 64; edata2_left -= 64)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;

    md5_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0]=w0[1]=w0[2]=w0[3]=0;
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  if (edata2_left < 16)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    truncate_block_4x4_le_S (w0, edata2_left & 0x0f);
  }
  else if (edata2_left < 32)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    truncate_block_4x4_le_S (w1, edata2_left & 0x0f);
  }
  else if (edata2_left < 48)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    truncate_block_4x4_le_S (w2, edata2_left & 0x0f);
  }
  else
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;
    truncate_block_4x4_le_S (w3, edata2_left & 0x0f);
  }

  md5_hmac_update_64 (&ctx, w0, w1, w2, w3, edata2_left);
  md5_hmac_final (&ctx);

  if (checksum[0] != ctx.opad.h[0]) return 0;
  if (checksum[1] != ctx.opad.h[1]) return 0;
  if (checksum[2] != ctx.opad.h[2]) return 0;
  if (checksum[3] != ctx.opad.h[3]) return 0;

  return 1;
}

/* K1 = HMAC-MD5(K, 0x01000000 LE on 4 bytes), digest = HMAC-MD5(K1, checksum), K2 = K1
   K is the 16-byte NT hash (already decoded to raw bytes). */
DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *K, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest, PRIVATE_AS u32 *K2)
{
  u32 w0[4], w1[4], w2[4], w3[4];

  w0[0]=K[0]; w0[1]=K[1]; w0[2]=K[2]; w0[3]=K[3];
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  md5_hmac_ctx_t ctx1;
  md5_hmac_init_64 (&ctx1, w0, w1, w2, w3);

  // message length = 4 bytes (value 1 LE), fast-path helper encoding
  w0[0]=8; w0[1]=0; w0[2]=0; w0[3]=0;
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  md5_hmac_update_64 (&ctx1, w0, w1, w2, w3, 4);
  md5_hmac_final (&ctx1);

  w0[0]=ctx1.opad.h[0]; w0[1]=ctx1.opad.h[1]; w0[2]=ctx1.opad.h[2]; w0[3]=ctx1.opad.h[3];
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  md5_hmac_ctx_t ctx;
  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  w0[0]=checksum[0]; w0[1]=checksum[1]; w0[2]=checksum[2]; w0[3]=checksum[3];
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  md5_hmac_update_64 (&ctx, w0, w1, w2, w3, 16);
  md5_hmac_final (&ctx);

  digest[0]=ctx.opad.h[0];
  digest[1]=ctx.opad.h[1];
  digest[2]=ctx.opad.h[2];
  digest[3]=ctx.opad.h[3];

  K2[0]=ctx1.opad.h[0];
  K2[1]=ctx1.opad.h[1];
  K2[2]=ctx1.opad.h[2];
  K2[3]=ctx1.opad.h[3];
}

/* Decode 32 ASCII hex chars from tmp.i[0..7] -> 16 raw bytes in out[4] */
DECLSPEC void decode_nt_hex_32_to_u32x4 (PRIVATE_AS const pw_t *tmp, PRIVATE_AS u32 out[4])
{
  u32 in[8];
  in[0]=tmp->i[0]; in[1]=tmp->i[1]; in[2]=tmp->i[2]; in[3]=tmp->i[3];
  in[4]=tmp->i[4]; in[5]=tmp->i[5]; in[6]=tmp->i[6]; in[7]=tmp->i[7];

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

  for (int i = 0, j = 0; i < 16; i++, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }
}

/* a0 mxx: don’t apply rules to binary key; hex-decode candidate first */
KERNEL_FQ KERNEL_FA void m18250_mxx (KERN_ATTR_RULES_ESALT (krb5asrep_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];
  checksum[0]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    u32 K[4];         // 16-byte NT hash (raw)
    decode_nt_hex_32_to_u32x4 (&tmp, K);

    u32 digest[4];
    u32 K2[4];
    kerb_prepare (K, checksum, digest, K2);

    if (decrypt_and_check (S, digest,
                           esalt_bufs[DIGESTS_OFFSET_HOST].edata2,
                           esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len,
                           K2, checksum, lid) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0,
                   DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

/* a0 sxx: same as mxx */
KERNEL_FQ KERNEL_FA void m18250_sxx (KERN_ATTR_RULES_ESALT (krb5asrep_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];
  checksum[0]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3]=esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    u32 K[4];
    decode_nt_hex_32_to_u32x4 (&tmp, K);

    u32 digest[4];
    u32 K2[4];
    kerb_prepare (K, checksum, digest, K2);

    if (decrypt_and_check (S, digest,
                           esalt_bufs[DIGESTS_OFFSET_HOST].edata2,
                           esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len,
                           K2, checksum, lid) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0,
                   DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

