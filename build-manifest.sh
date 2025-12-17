#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
manifest-builder.sh — build a JSON manifest for a dataset (UUID + hash + metadata)

USAGE:
  ./manifest-builder.sh -r ROOT -n NEW_MANIFEST [-o OLD_MANIFEST] [-w WHITELIST]
  ./manifest-builder.sh --help

ARGS:
  -r ROOT
      Root of storage (e.g. /srv/data). Root path will NOT be written into manifest.

  -n NEW_MANIFEST
      Output manifest.json to create (written atomically).

  -o OLD_MANIFEST (optional)
      Old manifest.json used to reuse UUIDs.
      UUID reuse rule: same (path + hash) => same UUID.

  -w WHITELIST (optional)
      Comma-separated list of TOP-LEVEL folders under ROOT to index.
      Example: -w "A,B,C"
      If omitted, everything under ROOT is indexed.

BEHAVIOR:
  - Scans directories and regular files only (ignores symlinks).
  - Enforces strict perms within indexed scope:
      files: 0444 (read-only, no exec)
      dirs : 0555 (read-only + traversal)
  - Manifest paths are relative to ROOT.

DEPENDENCIES:
  bash 4+, jq, sha256sum, stat, file, uuidgen OR python3

EXAMPLES:
  ./manifest-builder.sh -r /srv/data -n ./manifest.json
  ./manifest-builder.sh -r /srv/data -o ./manifest.json -n ./manifest.new.json
  ./manifest-builder.sh -r /srv/data -w "A,B,C" -n ./manifest.json
EOF
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 2; }; }

uuid_new() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  elif command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
  else
    echo "Need uuidgen or python3 to generate UUIDs." >&2
    exit 2
  fi
}

# Support --help
if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT=""
OLD_MANIFEST=""
NEW_MANIFEST=""
WHITELIST=""

while getopts ":r:o:n:w:h" opt; do
  case "$opt" in
    r) ROOT="$OPTARG" ;;
    o) OLD_MANIFEST="$OPTARG" ;;
    n) NEW_MANIFEST="$OPTARG" ;;
    w) WHITELIST="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 2 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done

[[ -n "$ROOT" && -n "$NEW_MANIFEST" ]] || { usage; exit 2; }
[[ -d "$ROOT" ]] || { echo "ROOT is not a directory: $ROOT" >&2; exit 2; }

need_cmd jq
need_cmd sha256sum
need_cmd stat
need_cmd file

# Normalize ROOT without trailing slash (except "/")
if [[ "$ROOT" != "/" ]]; then
  ROOT="${ROOT%/}"
fi

# Build scan roots
declare -a SCAN_ROOTS=()
if [[ -n "${WHITELIST}" ]]; then
  IFS=',' read -r -a WL <<<"$WHITELIST"
  for name in "${WL[@]}"; do
    name="${name#"${name%%[![:space:]]*}"}" # ltrim
    name="${name%"${name##*[![:space:]]}"}" # rtrim
    [[ -z "$name" ]] && continue
    p="$ROOT/$name"
    if [[ -d "$p" ]]; then
      SCAN_ROOTS+=("$p")
    else
      echo "Warning: whitelisted folder not found or not a dir, skipping: $p" >&2
    fi
  done
else
  SCAN_ROOTS+=("$ROOT")
fi

[[ ${#SCAN_ROOTS[@]} -gt 0 ]] || { echo "Nothing to scan (empty whitelist?)" >&2; exit 2; }

# Exclude manifest files if they live under ROOT
exclude_find_args=()
for mf in "$NEW_MANIFEST" "$OLD_MANIFEST"; do
  [[ -z "$mf" ]] && continue
  case "$mf" in
    "$ROOT"/*) exclude_find_args+=( -not -path "$mf" ) ;;
  esac
done

# Helper: absolute -> ROOT-relative, no leading slash
relpath_of() {
  local abs="$1"
  if [[ "$abs" == "$ROOT" ]]; then
    echo ""
    return
  fi
  echo "${abs#"$ROOT"/}"
}

# -------- load old manifest mapping (path+hash -> uuid) --------
declare -A OLD_UUID_BY_PATH_HASH=()

if [[ -n "$OLD_MANIFEST" ]]; then
  [[ -f "$OLD_MANIFEST" ]] || { echo "OLD_MANIFEST not found: $OLD_MANIFEST" >&2; exit 2; }

  # IMPORTANT: no pipe into while-loop (subshell). Use process substitution.
  if jq -e 'type=="object" and .entries and (.entries|type=="array")' "$OLD_MANIFEST" >/dev/null 2>&1; then
    while IFS=$'\t' read -r p u h; do
      [[ -n "$p" && -n "$u" ]] || continue
      OLD_UUID_BY_PATH_HASH["$p|$h"]="$u"
    done < <(jq -r '.entries[]
      | select(.path and .uuid)
      | [.path, .uuid, (.hash // "")] | @tsv' "$OLD_MANIFEST")
  else
    while IFS=$'\t' read -r p u h; do
      [[ -n "$p" && -n "$u" ]] || continue
      OLD_UUID_BY_PATH_HASH["$p|$h"]="$u"
    done < <(jq -r '.[]
      | select(.path and .uuid)
      | [.path, .uuid, (.hash // "")] | @tsv' "$OLD_MANIFEST")
  fi
fi

# -------- enforce strict permissions within indexed scope --------
for sr in "${SCAN_ROOTS[@]}"; do
  find "$sr" -xdev "${exclude_find_args[@]}" -type d -print0 | xargs -0r chmod 0555
  find "$sr" -xdev "${exclude_find_args[@]}" -type f -print0 | xargs -0r chmod 0444
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

entries_ndjson="$tmpdir/entries.ndjson"
paths_tmp="$tmpdir/paths.txt"

# Collect all dirs + files (no symlinks), then process in stable order
: >"$paths_tmp"
for sr in "${SCAN_ROOTS[@]}"; do
  find "$sr" -xdev "${exclude_find_args[@]}" \( -type d -o -type f \) -print0 \
    | tr '\0' '\n' >>"$paths_tmp"
done

# sort stable
LC_ALL=C sort -u "$paths_tmp" >"$paths_tmp.sorted"

total_entries=0
total_files=0
total_dirs=0
total_bytes=0

: >"$entries_ndjson"

while IFS= read -r p; do
  [[ -n "$p" ]] || continue
  rel="$(relpath_of "$p")"
  [[ -n "$rel" ]] || continue

  mode="$(stat -c '%a' "$p")"
  mtime="$(stat -c '%Y' "$p")"

  if [[ -d "$p" ]]; then
    # directories have no hash; reuse by (path + empty-hash)
    key="$rel|"
    uuid="${OLD_UUID_BY_PATH_HASH[$key]:-$(uuid_new)}"

    jq -n \
      --arg uuid "$uuid" \
      --arg path "$rel" \
      --arg type "directory" \
      --argjson size 0 \
      --argjson mtime "$mtime" \
      --arg mode "$mode" \
      '{uuid:$uuid, path:$path, type:$type, size:$size, hash:null, mtime:$mtime, mode:$mode}' \
      >>"$entries_ndjson"

    total_entries=$((total_entries + 1))
    total_dirs=$((total_dirs + 1))

  elif [[ -f "$p" ]]; then
    size="$(stat -c '%s' "$p")"
    hash="$(sha256sum "$p" | awk '{print $1}')"
    mime="$(file --mime-type -b "$p" || true)"

    key="$rel|$hash"
    uuid="${OLD_UUID_BY_PATH_HASH[$key]:-$(uuid_new)}"

    jq -n \
      --arg uuid "$uuid" \
      --arg path "$rel" \
      --arg type "$mime" \
      --argjson size "$size" \
      --arg hash "$hash" \
      --argjson mtime "$mtime" \
      --arg mode "$mode" \
      '{uuid:$uuid, path:$path, type:$type, size:$size, hash:$hash, mtime:$mtime, mode:$mode}' \
      >>"$entries_ndjson"

    total_entries=$((total_entries + 1))
    total_files=$((total_files + 1))
    total_bytes=$((total_bytes + size))
  fi
done <"$paths_tmp.sorted"

generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

tmp_out="$tmpdir/manifest.json"
jq -s \
  --arg generated_at "$generated_at" \
  --argjson total_entries "$total_entries" \
  --argjson total_files "$total_files" \
  --argjson total_dirs "$total_dirs" \
  --argjson total_bytes "$total_bytes" \
  '
  {
    version: 1,
    generated_at: $generated_at,
    stats: {
      total_entries: $total_entries,
      total_files: $total_files,
      total_dirs: $total_dirs,
      total_bytes: $total_bytes
    },
    entries: .
  }
  ' "$entries_ndjson" >"$tmp_out"

chmod 0444 "$tmp_out"
mv -f "$tmp_out" "$NEW_MANIFEST"

echo "Wrote manifest: $NEW_MANIFEST"
echo "Stats: entries=$total_entries files=$total_files dirs=$total_dirs bytes=$total_bytes"
