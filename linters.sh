#!/bin/sh

module="tpm2_gui"
files="$(find ${module} -name '*.py' | xargs)"
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

isort ${files}
black ${module}
pylint ${module}
mypy ${module}  #TODO
flake8 ${module}
bandit -r ${module}
