#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${1:-}" ]]; then
#   echo "❌ Missing argument: password"
  password=""
else
  password=$1
fi

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"

# Example arrays (adjust to your real ones)
ARGON_KDFS=("argon2id" "argon2i")

ARGON_TIMES=(4 5 6)
ARGON_MEMORY=(16 32 64 128 256 512 1024)
ARGON_THREADS=(1 2 3 4) # max is 4 https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/configure.ac?ref_type=heads#L787

declare -A CIPHERS=(
  ["aes"]="aes-xts-plain64"
#   ["serpent"]="serpent-xts-plain64" # not supported by 34100 yet
#   ["twofish"]="twofish-xts-plain64" # not supported by 34100 yet
)

size=20   # MiB

OUTPUT_DIR="/tmp/out"
mkdir -p "$OUTPUT_DIR"
MOUNT_DIR="/tmp/mnt"
mkdir -p "$MOUNT_DIR"

create_luks_container() {
  local PASSWORD="$1"
  local filename="$2"
  local luks_type="$3"
  local cipher="$4"
  local hash="$5"
  local size_mb="$6"
  shift 6
  local extra_opts=("$@")


  # echo  "🔧 Creating $filename (size ${size_mb}MiB) with password length ${#PASSWORD}: $PASSWORD..."
  dd if=/dev/zero of="$filename" bs=1M count="$size_mb" status=none

  loopdev=$(sudo losetup --show -f "$filename")

cat >> /tmp/m34100.sh.log <<EOF
sudo cryptsetup luksFormat \
--batch-mode \
--type "$luks_type" \
--cipher "$cipher" \
--key-size 512 \
--hash "$hash" \
${extra_opts:+${extra_opts[@]}} \
"$loopdev" <<< "$PASSWORD" # $filename
EOF
chmod +x /tmp/m34100.sh.log

  if sudo cryptsetup luksFormat \
      --batch-mode \
      --type "$luks_type" \
      --cipher "$cipher" \
      --key-size 512 \
      --hash "$hash" \
      "${extra_opts[@]}" \
      "$loopdev" <<< "$PASSWORD"; then
      true
      echo "✅ Formatted: $filename" >> /tmp/m34100.sh
  else
    echo "❌ Failed to format: $filename" >> /tmp/m34100.sh
    sudo losetup -d "$loopdev"
    rm -f "$filename"
    return
  fi

  name="luks$(basename "$filename" | sha1sum | cut -c1-8)"

  if [ -e "/dev/mapper/$name" ]; then
    echo "⚠️  Device $name already exists. Closing it first." >> /tmp/m34100.sh
    sudo cryptsetup close "$name" || true
  fi

  if sudo cryptsetup open "$loopdev" "$name" <<< "$PASSWORD"; then
    true
    echo "✅ Decrypted: $filename" >> /tmp/m34100.sh
  else
    echo  "❌ Failed to decrypt: $filename" >> /tmp/m34100.sh
    sudo losetup -d "$loopdev"
    rm -f "$filename"
    return
  fi

  mkfs.ext4 -q /dev/mapper/"$name" 2>/dev/null

  mount_point="$MOUNT_DIR/$name"
  mkdir -p "$mount_point"
  sudo mount /dev/mapper/"$name" "$mount_point"

  echo "Hello from $filename" > "$mount_point/info.txt"
  while ! sudo umount "$mount_point"; do
    # echo  "Waiting for $mount_point to become free..."
    sleep 1
  done

  sudo cryptsetup close "$name"

  # echo  "✅ ext4: $filename"

  sudo losetup -D
}


# --- random picks ---
kdf=${ARGON_KDFS[$RANDOM % ${#ARGON_KDFS[@]}]}
time=${ARGON_TIMES[$RANDOM % ${#ARGON_TIMES[@]}]}
memory=${ARGON_MEMORY[$RANDOM % ${#ARGON_MEMORY[@]}]}
threads=${ARGON_THREADS[$RANDOM % ${#ARGON_THREADS[@]}]}
cipher_name=$(printf "%s\n" "${!CIPHERS[@]}" | shuf -n1)
cipher=${CIPHERS[$cipher_name]}

file="${OUTPUT_DIR}/luks2-${cipher_name}-${kdf}-t${time}-m${memory}-p${threads}-size${size}MiB_$(date +%Y%m%d%H%M%S%6N).img"

# echo  "➡️  Creating $file with:"
# echo  "   kdf=$kdf time=$time memory=$memory threads=$threads cipher=$cipher"

create_luks_container "$password" "$file" luks2 "$cipher" sha256 "$size" \
  --pbkdf "$kdf" \
  --pbkdf-force-iterations "$time" \
  --pbkdf-memory "$((memory * 1024))" \
  --pbkdf-parallel "$threads"


${TDIR}/luks2hashcat.py $file | grep -vE '^[0-9]+$' > $file.hash

echo $file.hash