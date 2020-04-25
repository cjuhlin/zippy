# zippy
Script for unpacking nested archive and support diffrent formats(zip,tar and gz). It can also bruteforce zip file with help of a wordlist
Made for a CTF-challenge , Zip-a-Dee-Doo-Dah @ houseplant 2020.

USEAGE:
```
usage: zippy.py [-h] -w WORDLIST -a ARCHIVE [-log LOG]

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        wordlist with password
  -a ARCHIVE, --archive ARCHIVE
                        archive file to decompress
  -log LOG, --log LOG   Provide logging level. Example --log debug', default='info'
```