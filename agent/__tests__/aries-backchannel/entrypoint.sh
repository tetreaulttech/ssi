#!/bin/sh

while getopts p: option
do
case "${option}"
in
p) PORT=${OPTARG};;
esac
done

/app/backchannel