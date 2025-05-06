#!/bin/bash

mkdir -p cjs

for file in esm/*.js; do
	out="cjs/$(basename "${file%.js}.js")"
	ids=()

	content=$(sed -E '
		s/^import[[:space:]]+\{([^}]+)\}[[:space:]]+from[[:space:]]+["'\'']([^"'\'']+)["'\''];?/const {\1} = require("\2");/;
		s/^import[[:space:]]+([a-zA-Z0-9_$]+)[[:space:]]+from[[:space:]]+["'\'']([^"'\'']+)["'\''];?/const \1 = require("\2");/;
		s/^import[[:space:]]+["'\'']([^"'\'']+)["'\''];?/require("\1");/;
		s/^export[[:space:]]+default[[:space:]]+([a-zA-Z0-9_$]+)/module.exports = \1/;
		s/^export[[:space:]]+//;
	' "$file")

	while read -r line; do
		if [[ $line =~ ^export[[:space:]]+(const|let|var|async[[:space:]]+function|function|class)[[:space:]]+([a-zA-Z0-9_$]+) ]]; then
			ids+=("${BASH_REMATCH[2]}")
		fi
	done < "$file"

	content=$(echo "$content" | sed 's/^export[[:space:]]\+\(const\|let\|var\|async[[:space:]]\+function\|function\|class\)[[:space:]]\+/\1 /')

	echo "$content" > "$out"

	echo "" >> "$out"
	for id in "${ids[@]}"; do
		echo "module.exports.$id = $id;" >> "$out"
	done
done
