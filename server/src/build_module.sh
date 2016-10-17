#!/bin/bash


prepare() {
	export CPLUS_INCLUDE_PATH=$PWD/slog
	export LD_LIBRARY_PATH=$PWD/slog
	export LIBRARY_PATH=$PWD/slog:$LIBRARY_PATH

	if [ ! -d lib ]
	then
		mkdir lib
	fi
	
	cp base/libbase.a lib/

        mkdir -p base/slog/lib
        cp slog/slog_api.h base/slog/
        cp slog/libslog.so base/slog/lib/
} 

prepare
echo $PWD
cd $PWD/$1
cmake .
make
