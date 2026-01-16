nm -C -n $1 | awk '{ if ($2 != "a") print; }' > kernel.map

OBJCOPY="${OBJCOPY:-objcopy}"
content=$(mktemp)

cat kernel.map > "$content"

"$OBJCOPY" --update-section .debug_symbols="$content" $1

rm "$content"
