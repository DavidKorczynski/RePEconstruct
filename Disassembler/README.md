# Disassembler

The main idea with this disassembler is to use information from a concrete execution to support commonly done reverse engineering tasks. Specifically, the disassembler uses information about *branch instruction, memory reads and the modules exported by dynamically loaded libraries* from the concrete execution by our tracer, to rebuild the IAT of an unpacked binary and also relocate instructions or produce IDA scripts if desired. The relocation of instructions is a neat way to automatically patch the binary to something more useful than a binary with broken branching to imports. The point of the IDA script is to annotate and insert cross-references from branch calls (including obfuscated calls observed during the concrete execution) to imported functions.  

The *main.py* function gives a concrete example of how to use the disassembler, which should be fairly straight forward to interpret. When you have installed the software mentioned below, you should be able to simply run the main.py and see some results!

To run the disassembler you need to have Capstone installed.
**Note that you need to have the ["next" branch](https://github.com/aquynh/capstone/wiki/Next-branch) of Capstone installed.** There is a link on the home README file.  **You also need [PEfile](https://github.com/erocarrera/pefile)**. 



