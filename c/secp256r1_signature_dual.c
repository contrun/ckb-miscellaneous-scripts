// # secp256r1-signature-dual

#include <stdio.h>

#include "blockchain.h"
#include "common.h"
#include "ckb_dlfcn.h"

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

static const char *ec_name = "SECP256R1";
static const char *ec_sig_name = "ECDSA";
static const char *hash_algorithm = "SHA256";

const uint32_t projective_buffer_size = 96;
const uint32_t affine_buffer_size = 64;

int get_random(unsigned char *buf, u16 len) {
  for (int i = 0; i < len; i++) {
    buf[i] = 0;
  }
  return 0;
}

static int string_to_params(const char *ec_name, const char *ec_sig_name,
                            ec_sig_alg_type *sig_type,
                            const ec_str_params **ec_str_p,
                            const char *hash_name, hash_alg_type *hash_type) {
  const ec_str_params *curve_params;
  const ec_sig_mapping *sm;
  const hash_mapping *hm;
  uint32_t curve_name_len;

  if (sig_type != NULL) {
    sm = get_sig_by_name(ec_sig_name);
    if (!sm) {
      return ERROR_ENCODING;
    }
    *sig_type = sm->type;
  }

  if (ec_str_p != NULL) {
    curve_name_len = local_strlen((const char *)ec_name) + 1;
    if (curve_name_len > 255) {
      return ERROR_ENCODING;
    }
    curve_params =
        ec_get_curve_params_by_name((const uint8_t *)ec_name, (uint8_t)curve_name_len);
    if (!curve_params) {
      return ERROR_ENCODING;
    }
    *ec_str_p = curve_params;
  }

  if (hash_type != NULL) {
    hm = get_hash_by_name(hash_name);
    if (!hm) {
      return ERROR_ENCODING;
    }
    *hash_type = hm->type;
  }

  return 0;
}

void convert_aff_buf_to_prj_buf(const uint8_t *aff_buf, uint32_t aff_buf_len, uint8_t *prj_buf,
                                uint32_t prj_buf_len) {
  static const uint8_t z_buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  MUST_HAVE(aff_buf_len == affine_buffer_size);
  MUST_HAVE(prj_buf_len == projective_buffer_size);
  memcpy(prj_buf, aff_buf, aff_buf_len);
  memcpy(prj_buf + aff_buf_len, z_buf, sizeof(z_buf));
}

__attribute__((visibility("default"))) int verify_signature(const uint8_t *sig, uint8_t siglen, const uint8_t *pk, uint32_t pklen,
                     const uint8_t *m, uint32_t mlen) {
  const ec_str_params *ec_str_p;
  ec_sig_alg_type sig_type;
  hash_alg_type hash_type;
  ec_pub_key pub_key;
  ec_params params;
  int ret;

  uint8_t pj_pk_buf[projective_buffer_size];
  convert_aff_buf_to_prj_buf(pk, pklen, pj_pk_buf, sizeof(pj_pk_buf));

  MUST_HAVE(ec_name != NULL);

  ret = string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p, hash_algorithm, &hash_type);
  if (ret) {
    return ERROR_ENCODING;
  }
  import_params(&params, ec_str_p);

  ret = ec_pub_key_import_from_buf(&pub_key, &params, pj_pk_buf, sizeof(pj_pk_buf), sig_type);
  if (ret) {
    return ERROR_ENCODING;
  }

  ret = ec_verify(sig, siglen, &pub_key, m, mlen, sig_type, hash_type);
  if (ret) {
    return ERROR_SECP_VERIFICATION;
  }

  return 0;
}

#define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

typedef struct {
  uint64_t type;
  uint64_t value;
} Elf64_Dynamic;

int main() {
  /*
   * A simply inlined program interpreter.
   *
   * Assuming ELF header lives at 0x0, also avoiding deferencing
   * NULL pointer.
   */
  uint64_t *phoff = (uint64_t *) OFFSETOF(Elf64_Ehdr, e_phoff);
  uint16_t *phnum = (uint16_t *) OFFSETOF(Elf64_Ehdr, e_phnum);
  Elf64_Phdr *program_headers = (Elf64_Phdr *) (*phoff);
;
  for (int i = 0; i < *phnum; i++) {
    Elf64_Phdr *program_header = &program_headers[i];
    if (program_header->p_type == PT_DYNAMIC) {
      Elf64_Dynamic *d = (Elf64_Dynamic *) program_header->p_vaddr;
      uint64_t rela_address = 0;
      uint64_t rela_count = 0;
      while (d->type != 0) {
        if (d->type == 0x7) {
          rela_address = d->value;
        } else if (d->type == 0x6ffffff9) {
          rela_count = d->value;
        }
        d++;
      }
      if (rela_address > 0 && rela_count > 0) {
        Elf64_Rela *relocations = (Elf64_Rela *) rela_address;
        for (int j = 0; j < rela_count; j++) {
          Elf64_Rela *relocation = &relocations[j];
          if (relocation->r_info != R_RISCV_RELATIVE) {
            return ERROR_INVALID_ELF;
          }
          *((uint64_t *)(relocation->r_offset)) = (uint64_t)(relocation->r_addend);
        }
      }
    }
  }
  return 0;
}
