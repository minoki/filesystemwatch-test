all: rdc-sync.exe rdc-async.exe

rdc-sync.exe: rdc-sync.c
	gcc -o $@ -Wall $<

rdc-async.exe: rdc-async.c
	gcc -o $@ -Wall $<

.PHONY: all
