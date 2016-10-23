I1 = /I.\..\include
I2 = /I.\..\ext\include
I3 = /I.
I4 = /I.\Capstone
I5 = /I.\Capstone\include

INCLUDES = $(I1) $(I2) $(I3) $(I4) $(I5)

FLAGS = /GS- /DWINDOWS /DX86_32 

L1 = .\..\lib32\release\dynamorio.lib
L2 = .\..\ext\lib32\release\drmgr.lib
L3 = .\..\ext\lib32\release\drwrap.lib
L4 = .\..\ext\lib32\release\drutil.lib
L5 = .\Capstone\capstone.lib

LINKING = /link $(L1) $(L2) $(L3) $(L4) $(L5)
AFTER_FLAGS = /dll

OUT = /out:unpacker.dll
CC = cl

CFILES = main.c hashtable.c


all: main

main:
	$(CC) $(CFILES) $(INCLUDES) $(FLAGS) $(LINKING) $(AFTER_FLAGS) $(OUT)
