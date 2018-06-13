#!/bin/bash

args=("$@")
test_report=${args[0]}
env=${args[1]}
testtorun=${args[2]}

if [ "$test_report" == "-h" ]
then
    echo "Usage: runtests.sh results.xml env [testtorun]"
    exit 0
else
    echo "Starting tests for $env"
    if [ ! -d signer_tests ]; then
        echo "Creating virtual env"
        virtualenv signer_tests
    fi
    . signer_tests/bin/activate

    pip install setuptools-scm==1.15.0
    pip install -r ./requirements.txt

    cd test_api/

    if [ "$testtorun" != "" ]
    then
        py.test -v --env=$env --junitxml="$test_report" -s -k $testtorun
    else
        py.test -v -n 4 --env=$env --junitxml="$test_report"
    fi

    test_result_code=$?

    deactivate
    cd ../
    exit $test_result_code
fi
