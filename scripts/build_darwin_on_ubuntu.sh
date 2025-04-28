# Prerequisites
# build osxcross locally
# https://github.com/tpoechtrager/osxcross
# make sure clang is installed o64-clang
# Create dist directory if it doesn't exist
mkdir -p dist

extra_build_args=""
if [ "${LEDGER_SIM:-}" == true ]
then
	extra_build_args="-tags ledger_zemu"
fi 

echo "building avalanche for darwin"
VERSION=`cat VERSION`
echo $VERSION

BIN=bin/avalanche-darwin-amd64
echo $BIN

GOOS=darwin \
BIN=$BIN \
GOARCH=amd64 \
CGO_ENABLED=1 \
CC=o64-clang \
VERSION=$VERSION \
TELEMETRY_TOKEN="" \
CGO_CFLAGS="-O -D__BLST_PORTABLE__" \
go build -v -ldflags="-X 'github.com/ava-labs/avalanche-cli/cmd.Version=$VERSION' -X github.com/ava-labs/avalanche-cli/pkg/metrics.telemetryToken=$TELEMETRY_TOKEN" $extra_build_args -o "$BIN"
