import disassembler
import pefile


Main_folder = "./Example_Trace_Output/"

file_name = Main_folder + "entire_unpacked-1"
exports = Main_folder + "exports_wave-1"
trace = Main_folder + "trace_output"
wave_entry_file = Main_folder + "wave_entrypoints"


def get_wave_EP(wave_file, wave):
	with open(wave_file) as f:
		for line in f.readlines():
			#print line
			split_line = line.split()

			if int(split_line[1]) == wave:
				entry_point = int(split_line[6], 16)
				return entry_point

def get_PE_entry_point(binary_file):
	b = pefile.PE(binary_file)

	entry_point = b.OPTIONAL_HEADER.AddressOfEntryPoint
	base_address = b.OPTIONAL_HEADER.ImageBase

	return entry_point + base_address

def main():

	wave_entry = get_wave_EP(wave_entry_file, 1)
	print hex(wave_entry)

	entry_point = get_PE_entry_point(file_name)
	print hex(entry_point)
	
	# Initiate disassembler
	disasm = disassembler.RPE_disassembler(file_name, exports, trace, 1)

	# Perform disassembly
	disasm.recursive_disassemble([wave_entry, entry_point])

	# Build the import table
	disasm.build_import_table()

	# Relocate instructions 
	disasm.relocate_instructions()

	# Dump file and dump IDA script
	disasm.dump_file()
	disasm.output_ida_script()



if __name__ == "__main__":
	main()