#!/bin/bash

# 22-grading.sh

rm -f ./text.txt
rm -f ./tools/text.txt
rm -f ./complete.tmp
rm -f ./test.result

cp ./tools/text.txt.bak ./text.txt

echo "Run 1 test case..."

./tools/sbt-tracker 60207 ./tools/test-2.torrent > /dev/null 2>&1 &

sleep 1

./tools/sbt-peer 11111 ./tools/test-2.torrent ./tools/ SIMPLEBT.TEST.111111 -d &

sleep 1

./build/simple-bt 60207 ./tools/test-2.torrent &

sleep 5

killall sbt-tracker > /dev/null 2>&1

rm -f ./text.txt
rm -f ./tools/text.txt
rm -f ./complete.tmp
rm -f ./test.result
