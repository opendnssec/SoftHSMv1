#!/bin/sh

sh autogen.sh && \
./configure --with-botan=/usr && \
make all check
