#!/bin/bash
while IFS= read -r line
do
    # Setting actual option
    actual_option=$line
    echo $actual_option
    echo -e "DELAY 1000 \nSTRING $actual_option \nENTER" > $actual_option.txt

    # user=$(echo $line | cut -d ":" -f1)
    # password=$(echo $line | cut -d ":" -f2 | base64 -d | base64 -d)
    # echo "$user:$password"

done < $1