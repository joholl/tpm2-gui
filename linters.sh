#!/bin/sh

module="tpm2_gui"
files="$(find ${module} -name '*.py' | xargs)"
license_tmplate="setup.py"

exitcode=0

# Check that licenses are consistent
echo "################################ LICENSE ################################"
license=$(sed -n '/#/,/^$/p' ${license_tmplate})
license_lines=$(echo "${license}" | wc -l)
for f in ${files}; do
    f_license="$(head -n${license_lines} ${f})"
    if [ "${f_license}" != "${license}" ]; then
        echo "ERROR: License does not match ${license_tmplate}: ${f}" >&2
        exitcode=1
    fi
done

echo "################################# ISORT #################################"
isort ${files} || exitcode=1
echo "################################# BLACK #################################"
black --quiet --check --diff ${module} || exitcode=1
# black ${module} 2>&1  | grep -P '^\d+ files left unchanged.' || echo error
echo "################################# PYLINT ################################"
pylint --score=n ${module} || exitcode=1
# echo "################################## MYPY #################################"
#mypy ${module}  || exitcode=1 #TODO
echo "################################# FLAKE8 ################################"
flake8 ${module} || exitcode=1
echo "################################# BANDIT ################################"
bandit --quiet --recursive ${module} || exitcode=1

test "${exitcode}" = 0
