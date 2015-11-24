#!/bin/sh

if [ $# -eq 2 ]
then
    FILE=$1
    DIR=$2
elif [ $# -eq 1 ]
then
    FILE=$1
    DIR="."
elif [ $# -eq 0 ]
then
    FILE="target"
    DIR="."
else
    echo "."
    echo "Usage: getpcap target dest"
fi

if [ -f $FILE ]
then
#    if [ -d $DIR ]
#    then
        cat $FILE | while read ligne
	do
#	    echo "$ligne"
	    wget "$ligne" -P "$DIR" 
##	    cp "$ligne" "$DIR"
##	    echo "Copie de $ligne effectuee"
	done
  #  else
#	echo "$DIR est introuvable"
#    fi
else
    echo "$FILE est introuvable"
    fi
