# Malduino Elite

## Files
Scripts válidos con su configuración de switches.

## Folder creator
Script to probe the valid switch combinations


## Consideraciones importantes
El máximo número de caracteres por línea es 127
+ https://github.com/Seytonic/malduino/issues/21

## Scripts funcionales
+ 00 - 0000 [ok]
+ 01 - 0001 [ok]
+ 02 - 0010 [ok]
+ 03 - 0011 [ok]
+ 08 - 1000 [ok]
+ 09 - 1001 [ok]
+ 10 - 1010 [ok]
+ 11 - 1011 [ok]

## Todas las posibles combinaciones
+ 00 - 0000 => 0000 - 00 [ok]
+ 01 - 0001 => 0001 - 01 [ok]
+ 02 - 0010 => 0010 - 02 [ok]
+ 03 - 0011 => 0011 - 03 [ok]
+ 04 - 0100 => 0000 - 00 [no]
+ 05 - 0101 => 0001 - 01 [no]
+ 06 - 0110 => 0010 - 02 [no]
+ 07 - 0111 => 0011 - 03 [no]
+ 08 - 1000 => 1000 - 08 [ok]
+ 09 - 1001 => 1001 - 09 [ok]
+ 10 - 1010 => 1010 - 10 [ok]
+ 11 - 1011 => 1011 - 11 [ok]
+ 12 - 1100 => 1000 - 08 [no]
+ 13 - 1101 => 1001 - 09 [no]
+ 14 - 1110 => 1010 - 10 [no]
+ 15 - 1111 => 1011 - 11 [no]