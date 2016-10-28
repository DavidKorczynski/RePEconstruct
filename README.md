# RePEconstruct

RePEconstruct is a tool for automatically unpacking binaries and rebuild the binaries in a manner well-suited for further analysis, specially focused on further manual analysis in IDA pro.

The main idea behind RePEconstruct is to use information collected dynamic analysis for unpacking self-modifying code and then use extra information collected during dynamic analysis to feed into our disassembler, which will rebuild the import table and also locate instructions that branch to dynamically loaded code (including obfuscated calls, as shown in Example 1). Our disassembler can also produce IDA python scripts for each memory dump it disassembles, which will than add cross-references into the IDA db. The other approach is to have our disassembler try and re-locate instructions and effectively the rebuild binary can be applied to other interactive disassemblers and still leverage results from RePEconstruct. 

First example: 

In this example we use a dump from the dynamic tracer to show the use of our the static component which will rebuild the import table and also locate any obfuscated calls in the dump. 

The dump we will be using is a memory dump produced by our dynamic analysis component and the initial file is a binary that was packed with the Petite packer. We will now use this dump as input to our static analyser and view the output in IDA pro. 

The file PEtite_example/entire_unpacked-3 is the dump of the third wave of self-modifying code produced by a packed Petite example. Note that this is merely a toy example produced by a synthetic application! 

In the binary, you will see at address 0x40f031 an obfuscated call that was used by the packed binary which at runtime constituted a call to dynamically loaded code. However, this is not resolved by IDA pro when we load a given memory dump into the disassembler. The exact purpose of RePEconstruct is to automatically thwart self-modifying code and find calls like this.

Simply execute main.py and you will see the result! The result is composed of two files: reconstructedDirect and ida_script.py The reconstructedDirect is the binary file with instructions relocated where possible, and the ida_script.py is an IDA python script which setup cross-references and also comments.

Before picture: 
![alt tag](http://imageshack.com/a/img921/6003/nAOlGQ.png)

After picture (loaded reconstructedDirect into IDA and also run the ida_script.py in IDA):
![alt tag](http://imageshack.com/a/img921/7296/TjrV2k.png)

The main.py should be easy to follow and see what is needed to run any type of binary through the disassembler! 

Second example:
In this example we will use the dynamic analysis component to unpack a simple application that was packed with the Petite packer. 

Simply run the command from the main DynamoRIO folder:

bin32\drrun.exe -max_bb_instrs 128 -c unpacker.dll –Petite_packed.exe

Note that you must have a folder namer ”Refactor_output” in the folder of which you are executing this command. Also note that unpacker.dll is the DLL from Tracer/Pre_compiled_dll/unpacker.dll and the ”Petite_packed.exe” is the binary given in Tracer/Example_of_packed_file/Petite_packed.exe

This experiment was done on a Windows 32-bit SP3 VM, with DynamoRIO 6.1.1-3

The result from the unpacker is generated in the Refactor_output folder. Here you will find several files: 
entire_unpacked-x means a memory dump of the ”x”'th layer of self-modifying code that has been prepared for IAT rebuilding. Specifically, this means we have constructed a new section where we will build the new IAT, as done in the example just above.

entire_unpacked_clean-x are files that are clean memory dumps of each layer of self-modifying code. These are not used by the static disassembler, but are provided in case needed.

exports_wave-x are files that contain addresses of dynamically loaded modules and the functions they export. This is used by the static rebuilder to map which instructions branch to dynamically loaded functions.

The files ”trace_output” amd ”wave_entrypoints” are also used by the static rebuilder. The main.py file from the example above shows in a simple manner how they are to be used!


The tool is used in the 2016 MALWARE paper "RePEconstruct: reconstructing packed binaries with self-modifying code and import table destruction". 
