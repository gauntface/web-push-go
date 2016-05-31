#!/bin/bash
set -e

function finish {
  echo ""
  echo ""
  echo "Killing Selenium"
  echo ""
  echo ""
  kill $seleniumPID;
}
trap finish EXIT

if [ ! -f "./test/selenium-server-standalone-2.53.0.jar" ]; then
  echo ""
  echo ""
  echo "Downloading Selenium"
  echo ""
  echo ""
  wget -P ./test/ https://selenium-release.storage.googleapis.com/2.53/selenium-server-standalone-2.53.0.jar
fi

echo ""
echo ""
echo "Start Selenium Server"
echo ""
echo ""
java -jar ./test/selenium-server-standalone-2.53.0.jar &
seleniumPID=$!;

# Give selenium server time to warm up
sleep 2s;


echo ""
echo ""
echo "Start Go Tests"
echo ""
echo ""
cd ./webpush
go test
cd ..
