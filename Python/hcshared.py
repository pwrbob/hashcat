import struct
import sys
from pathlib import Path
import hcsp
import pickle

# Extract a blob that is a list of salt_t entries and convert it to a list of dictionaries
# The salt_t is a fixed data-type so we can handle it here

def extract_salts(salts_buf) -> list:
  salts=[]
  for salt_buf, salt_buf_pc, salt_len, salt_len_pc, salt_iter, salt_iter2, salt_dimy, salt_sign, salt_repeats, orig_pos, digests_cnt, digests_done, digests_offset, scrypt_N, scrypt_r, scrypt_p in struct.iter_unpack("256s 256s I I I I I 8s I I I I I I I I", salts_buf):
    salt_buf = salt_buf[0:salt_len]
    salt_buf_pc = salt_buf_pc[0:salt_len_pc]
    salts.append({ "salt_buf":      salt_buf,     \
                   "salt_buf_pc":   salt_buf_pc,  \
                   "salt_iter":     salt_iter,    \
                   "salt_iter2":    salt_iter2,   \
                   "salt_dimy":     salt_dimy,    \
                   "salt_sign":     salt_sign,    \
                   "salt_repeats":  salt_repeats, \
                   "orig_pos":      orig_pos,     \
                   "digests_cnt":   digests_cnt,  \
                   "digests_done":  digests_done, \
                   "scrypt_N":      scrypt_N,     \
                   "scrypt_r":      scrypt_r,     \
                   "scrypt_p":      scrypt_p,     \
                   "esalt":         None })
  return salts

def get_salt_buf(salt: dict) -> bytes:
  return salt["esalt"]["salt_buf"]

def get_salt_buf_pc(salt: dict) -> bytes:
  return salt["esalt"]["salt_buf_pc"]

def get_salt_iter(salt: dict) -> int:
  return salt["esalt"]["salt_iter"]

def get_salt_iter2(salt: dict) -> int:
  return salt["esalt"]["salt_iter2"]

def get_salt_sign(salt: dict) -> bytes:
  return salt["esalt"]["salt_sign"]

def get_salt_repeats(salt: dict) -> int:
  return salt["esalt"]["salt_repeats"]

def get_orig_pos(salt: dict) -> int:
  return salt["esalt"]["orig_pos"]

def get_digests_cnt(salt: dict) -> int:
  return salt["esalt"]["digests_cnt"]

def get_digests_done(salt: dict) -> int:
  return salt["esalt"]["digests_done"]

def get_digests_offset(salt: dict) -> int:
  return salt["esalt"]["digests_offset"]

def get_scrypt_N(salt: dict) -> int:
  return salt["esalt"]["scrypt_N"]

def get_scrypt_r(salt: dict) -> int:
  return salt["esalt"]["scrypt_r"]

def _worker_batch(passwords, salt_id, is_selftest, user_fn, salts, st_salts):
    salt = st_salts[salt_id] if is_selftest else salts[salt_id]
    hashes = []
    for pw in passwords:
        try:
            hash=user_fn(pw, salt)
            hashes.append(hash)
        except Exception as e:
            print(e, file=sys.stderr)
            hashes.append("invalid-password")
    return hashes

def dump_hashcat_ctx(ctx):
  print("Dumping hashcat ctx...")
  script_dir = Path(__file__).resolve().parent
  with open(script_dir.joinpath("hashcat.ctx"), "wb") as f:
    pickle.dump(ctx, f)
    print(f"Dumped hashcat ctx to: \n {script_dir.joinpath('hashcat.ctx')} \n")
  print("Press [q] to quit hashcat.")
  hcsp.term(ctx)

def load_ctx(python_arguments):
  if len(python_arguments) > 1 :
    hashcat_ctx = Path(python_arguments[1])
    if hashcat_ctx.exists():
      with open(hashcat_ctx, "rb") as f:
        return pickle.load(f)
  else:
    print(f"There is no hashcat ctx file to load. Assuming your hashes are unsalted.")
    return {
      "salts_buf": bytes(572),
      "esalts_buf": bytes(2056),
      "st_salts_buf": bytes(572),
      "st_esalts_buf": bytes(2056),
      "parallelism": 4
    }


def add_hashcat_path_to_environment():
  # add the hashcat path to the environment to import the hcshared and hcmp libraries
  script_dir = Path(__file__).resolve().parent
  if script_dir.name == "Python" and script_dir.parent.name == "hashcat":
    sys.path.insert(0, script_dir)
  else:
    print(f"script ({script_dir}) is not running from the hashcat/Python folder, so the debugging of hcmp.py and hcshared.py is disabled", file=sys.stderr)
