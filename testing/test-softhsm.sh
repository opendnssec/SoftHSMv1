#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

check_if_tested softhsm && exit 0
start_test softhsm

test_ok=0
(
	log_this softhsm-init-token softhsm --init-token --slot 0 --label OpenDNSSEC --pin 1234 --so-pin 1234 &&
	log_grep softhsm-init-token stdout "The token has been initialized."
) &&
test_ok=1

stop_test
finish

if [ "$test_ok" -eq 1 ]; then
	log_cleanup
	set_test_ok softhsm || exit 1
	exit 0
fi

exit 1
