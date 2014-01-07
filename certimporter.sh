#!/bin/sh

appname=certimporter

cp ./buildscript/makexpi.sh ./
./makexpi.sh -n $appname -o
rm ./makexpi.sh
