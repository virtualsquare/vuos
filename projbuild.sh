#!/bin/bash

ROOTDIR=$PWD
DEFAULT_BUILDDIR=build

if [ -z ${BUILDDIR:+x} ];
	then 
		echo Using default build directory;
		BUILDDIR=$ROOTDIR/$DEFAULT_BUILDDIR
	else
		BUILDDIR=$ROOTDIR/$1
fi

rm -rf $BUILDDIR
mkdir -p $BUILDDIR
cd $BUILDDIR

cmake $ROOTDIR
make
make install
