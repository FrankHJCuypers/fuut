#! /bin/bash
#
# Concatenates all Gaai record files of the given type into 1 file, respecting timing order 
# $1 Serial number of the charger (like 2303-00005-E3)
# $2: type of the record files to concatenate: CDR, CCDT, EVENT, METRIC
# $3: directory in which to read/write files
# 

if [[ "$#" -ne 3 ]]; then
    echo "Illegal number of parameters; expecting three" >&2
    exit 1
fi

if [[ ! -d "$3" ]]; then
  echo "Directory $3 does not exist"  >&2
  exit 1
fi

ls $3/$1* 1> /dev/null 2>&1 || { echo "There are no files for charger $1 in $3"  >&2; exit 1; }

case $2 in 
  CDR|CCDT|EVENT|METRIC) echo $2 is a valid type;;
  *) echo "$1 is not a valid type. Expecting CDR, CCDT, EVENT or METRIC"  >&2
     exit 1
esac



pushd $3 > /dev/null
# command argument expansion returns all matching files in alphabetical order.
cat $1_$2_[0-9]*.txt > $1_$2_all.txt

popd > /dev/null