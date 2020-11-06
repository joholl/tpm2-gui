#!/bin/sh

module="tpm2-gui"  # TODO _
files=$(find ${module} -name '*.py')
license_tmplate="setup.py"

# Check that licenses are consistent
license=$(sed -n '/#/,/^$/p' ${license_tmplate})
license_lines=$(echo "${license}" | wc -l)
for f in ${files}; do
    f_license="$(head -n${license_lines} ${f})"
    if [ "${f_license}" != "${license}" ]; then
        echo "ERROR: License does not match ${license_tmplate}: ${f}" >&2
        exit 1
    fi
done
