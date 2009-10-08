#!/bin/sh
#
# $Id$

regress()
{
	ALGORITHM=$1
	KEYSIZE=$2

	DOMAIN=`echo ${KEYSIZE}.${ALGORITHM}.example.com. | tr '[:upper:]' '[:lower:]'`
	KEYFILE_P8=test-${ALGORITHM}.pkcs8

	echo "Testing with ${ALGORITHM} keysize ${KEYSIZE}: ${DOMAIN}"

	echo "Generating key using dnssec-keygen from BIND"
	dnssec-keygen -a $ALGORITHM -b $KEYSIZE -n ZONE $DOMAIN

	PUBLIC=`ls -1 K${DOMAIN}+*.key`
	PRIVATE=`ls -1 K${DOMAIN}+*.private`

	echo $PUBLIC

	echo "Converting key from BIND to PKCS#8"
	../src/bin/softhsm-keyconv \
		--topkcs8 \
		--in $PRIVATE \
		--out $KEYFILE_P8

	mv ${PUBLIC} ${PUBLIC}.orig
	mv ${PRIVATE} ${PRIVATE}.orig

	echo "Converting key from PKCS#8 to BIND"
	../src/bin/softhsm-keyconv \
		--tobind \
		--in $KEYFILE_P8 \
		--algorithm $ALGORITHM \
		--name $DOMAIN

	ls -l K${DOMAIN}+*
}

regress RSASHA1 1024
regress RSASHA1 2048
regress RSASHA256 1024
regress RSASHA256 2048
