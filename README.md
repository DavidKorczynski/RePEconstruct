# RePEconstruct

RePEconstruct is a tool for automatically unpacking a binary and also rebuilding
the import address table.

It uses DynamoRIO for dynamic binary instrumentation and then deploys
a disassembler and PE rebuilder, built in Python.

The tool is used in the 2016 MALWARE paper "RePEconstruct: reconstructing packed binaries with self-modifying code and import table destruction". 
