from collections import deque
from struct import *
from capstone import *
from capstone.x86 import *
import pefile
import struct


class RPE_XREF_type:
    branch = 1
    mem_read = 2
    mem_write = 3

    def __init__():
        None


class RPE_instruction:

    def __init__(self):
        self.address = None
        self.decoded_instr = None
        self.branch_destinations = set()
        self.values_read = set()

    def add_branch_destination(self, dst_address):
        self.branch_destinations.add(dst_address)

    def get_branch_destinations(self):
        return self.branch_destinations

    def add_values_read(self, value_read):
        self.values_read.add(value_read)

    def get_values_read(self):
        return self.values_read


class RPE_instruction_graph:
    """
    A representation of the binary as a directed graph where each node
    is an instruction of the binary. 
    
    The graph is represented as a mapping:
    instruction_address -> RPE_instruction
    
    
    """

    def __init__(self):
        self.graph = dict()

    def add_edge(self, src_instr, dst_address, ref_type):
        """
        
        :param RPE_instruction src_instr:
        :param unsigned int dst_address:
        :param REFERENCE_TYPE ref_type:
        
        :return: None
        """
        source_addr = src_instr.address
        self.graph[source_addr].add_branch_destination(dst_address)

    def add_node(self, instr):
        """
        :param RPE_instruction instr:
        
        :return: None
        """
        self.graph[instr.address] = instr

    def is_analysed(self, instr_addr):
        """
        
        :param unsigned int instr_addr:
        
        :return Boolean: whether the address is contained in the graph as a node.
        """
        return instr_addr in self.graph

    def get_instruction(self, instr_addr):
        """
        
        :param unsigned int instr_addr:
        
        :return RPE_instruction: The RPE_instruction at the instruction address. 
                                 None if the node is not in the graph.
        """
        if instr_addr in self.graph:
            return self.graph[instr_addr]
        print 'no such instruction'

    def number_of_instructions(self):
        return len(self.graph)

    def print_calls_to_exports(self):
        for instr_addr in self.graph:
            instr = self.graph[instr_addr]
            dec_instr = instr.decoded_instr
            for branch_dst in instr.branch_destinations:
                if branch_dst > 6291456:
                    print '0x%x:\t%s\t%s' % (dec_instr.address, dec_instr.mnemonic, dec_instr.op_str)
                    print '\t: ' + hex(branch_dst)


class RPE_program_dump:

    def __init__(self, file_name):
        self.endian = '<L'
        pe = pefile.PE(file_name)
        self.base_address = pe.OPTIONAL_HEADER.ImageBase
        with open(file_name, 'rb') as f:
            self.dump = f.read()
            self.module_size = len(self.dump)

    def read_address(self, address):
        file_offset = address - self.base_address
        buf = self.dump[file_offset:file_offset + 4]
        if len(buf) == 4:
            address = unpack(self.endian, buf)
        else:
            address = (0, 0)
        return address

    def read_memory(self, address, size):
        file_offset = address - self.base_address
        return self.dump[file_offset:file_offset + size]

    def is_it_in_module(self, address):
        if address > self.base_address and address < self.base_address + self.module_size:
            return True
        return False

    def write_address(self, lvalue, value_to_write, add_base = 1):
        if add_base == 1:
            # Little endian is being written
            file_offset = lvalue - self.base_address

            #print("writing %x at %x"%(value_to_write, file_offset))
            bytes_to_write = struct.pack("<L", value_to_write)

            self.dump = self.dump[:file_offset] + bytes_to_write + self.dump[file_offset+4:]

            return 1
        else:
            # Write big endian -- Not supported now.
            None

        return 0

    def overwrite_memory(self, start_address, memory):
        None

    def write_file(self, file_name = 'output'):
        None

    def append_memory_before_end(self, memory, start_append):
        self.dump = self.dump[:start_append] + memory

    def dump_file(self, filename="reconstructedDirect"):
        with open(filename, 'wb') as f:
            f.write(self.dump)


class RPE_dynamic_memory:

    def __init__(self, file_name, wave):
        self.file_name = file_name
        self.branching = dict()
        self.wave = wave
        self.instr_to_reads = dict()
        self.lvalue_to_rvalue = dict()
        if file_name != None:
            self.parse_file()

    def parse_file(self):
        with open(self.file_name) as f:
            for line in f.readlines():
                splitted_line = line.split()
                if len(splitted_line) < 4:
                    continue
                wave = int(splitted_line[1])
                if wave == self.wave and splitted_line[2] == 'B':
                    source = splitted_line[3]
                    destination = splitted_line[5]
                    source_addr = int(source, 16)
                    destination_addr = int(destination, 16)
                    if source_addr not in self.branching:
                        self.branching[source_addr] = set()
                    self.branching[source_addr].add(destination_addr)
                if wave == self.wave and splitted_line[2] == 'I':
                    instr_address = int(splitted_line[3], 16)
                    lvalue = int(splitted_line[4], 16)
                    rvalue = int(splitted_line[5], 16)
                    if instr_address not in self.instr_to_reads:
                        self.instr_to_reads[instr_address] = set()
                    self.instr_to_reads[instr_address].add((lvalue, rvalue))
                    if lvalue not in self.lvalue_to_rvalue:
                        self.lvalue_to_rvalue[lvalue] = set()
                    self.lvalue_to_rvalue[lvalue].add(rvalue)

    def get_branch_destinations(self, instr_address):
        if instr_address in self.branching:
            return list(self.branching[instr_address])
        return []

    def get_instr_memory_reads(self, instr_address):
        if instr_address not in self.instr_to_reads:
            return None
        return self.instr_to_reads[instr_address]

    def get_lvalue_to_rvalues(self, lvalue):
        if lvalue not in self.lvalue_to_rvalue:
            return None
        return self.lvalue_to_rvalue[lvalue]


class RPE_exported_modules:

    def __init__(self, export_dump_file = None):
        self.export_file = export_dump_file
        self.exports = dict()
        if self.export_file != None:
            self.parse_file()

    def parse_file(self):
        with open(self.export_file) as f:
            for line in f.readlines():
                dll_name, function_name, function_addr = line.split()
                self.insert_export(dll_name, function_name, int(function_addr, 16))

    def insert_export(self, dll_name, function_name, function_address):
        self.exports[function_address] = (dll_name, function_name)

    def get_dll_and_function(self, address):
        if address not in self.exports:
            return None
        return self.exports[address]

    def contains_address(self, address):
        if address not in self.exports:
            return False
        return True


class RPE_import_entry:

    def __init__(self, function_name):
        self.function_name = function_name
        self.thunk_addr = None
        self.jump_addr = None
        self.is_imported_via_static = False
        self.is_imported_via_dynamic = False
        self.referenced_instructions = set()

    def __eq__(self, other):
        return self.function_name == `other`

    def __ne__(self, other):
        return not self.__eq__(other)


class RPE_import_table:

    def __init__(self):
        self.dlls = dict()

    def add_function(self, dll_name, function_name, import_type, instr):
        if dll_name not in self.dlls:
            self.dlls[dll_name] = dict()
        if function_name not in self.dlls[dll_name]:
            new_import = RPE_import_entry(function_name)
            self.dlls[dll_name][function_name] = new_import
        self.dlls[dll_name][function_name].referenced_instructions.add(instr)
        if import_type == 0:
            self.dlls[dll_name][function_name].is_imported_via_static = True
        elif import_type == 1:
            self.dlls[dll_name][function_name].is_imported_via_dynamic = True
        return 1

    def set_thunk_addr(self, dll_name, function_name, thunk_position):
        self.dlls[dll_name][function_name].thunk_addr = thunk_position

    def get_thunk_addr(self, dll_name, function_name):
        return self.dlls[dll_name][function_name].thunk_addr

    def set_jump_addr(self, dll_name, function_name, jump_position):
    	self.dlls[dll_name][function_name].jump_addr = jump_position

    def get_jump_addr(self, dll_name, function_name):
    	return self.dlls[dll_name][function_name].jump_addr

    def raw_memory_size(self):
        size = 0
        for dll_name in self.dlls:
            size += len(dll_name) + 1
            size += 20
            for function_name in self.dlls[dll_name]:
                size += len(function_name) + 1
                size += 8

                # Jump table too

            size += 4

        return size

    def get_jump_table_size(self):
    	size = 0
    	for dll_name in self.dlls:
    		size += len(self.dlls[dll_name])

    	# We multiply the size by 6, because a jmp instruction 
    	# using direct addressing is 6 bytes long.
    	return size*6


    def get_import_set(self):
        import_set = set()
        for dll in self.dlls:
            for func in self.dlls[dll]:
                import_set.add((dll, func))

        return import_set

    def print_statistics(self):
        number_of_functions = self.number_of_functions()
        dynamic_imports = 0
        static_imports = 0
        hybrid_imports = 0
        for dll in self.dlls:
            for func in self.dlls[dll]:
                stat = self.dlls[dll][func].is_imported_via_static
                dyn = self.dlls[dll][func].is_imported_via_dynamic
                if stat and dyn:
                    hybrid_imports += 1
                elif stat and not dyn:
                    static_imports += 1
                elif not stat and dyn:
                    dynamic_imports += 1

        print 'static imports: ' + `static_imports`
        print 'dynamic imports: ' + `dynamic_imports`
        print 'hybrid imports: ' + `hybrid_imports`

    def to_string(self):
        returner = ''
        for dll in self.dlls:
            returner = returner + 'dll: ' + dll + '\n'
            for func in self.dlls[dll]:
                returner = returner + '\t' + func
                if self.dlls[dll][func].thunk_addr == None:
                    returner += '\tNo thunk\n'
                else:
                    returner += '\t' + hex(self.dlls[dll][func].thunk_addr) + '\n'

        return returner

    def number_of_functions(self):
        functions = 0
        for dll in self.dlls:
            for func_name in self.dlls[dll]:
                functions += 1

        return functions


class RPE_disassembler:

    def __init__(self, binary, exported_file = None, trace_file = None, wave = 0):
        self.instr_decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        self.instr_decoder.detail = True
        self.instr_graph = RPE_instruction_graph()
        self.import_table = RPE_import_table()
        self.instructions_to_relocate = []
        self.mem_dump = RPE_program_dump(binary)
        self.exported_modules = RPE_exported_modules(exported_file)
        self.ida_xrefs = set()
        self.ida_comments = set()
        if trace_file != None:
            self.dynamic_memory = RPE_dynamic_memory(trace_file, wave)
            self.use_trace_file = True
            self.trace_file = trace_file
            self.wave = wave
        else:
            self.use_trace_file = False

    def insert_branches_from_trace_file(self, queue):
        """
        Inserts into the queue, the address of each instructions 
        that was observed during the dynamic analysis to have a branch. 
        
        These are then later used in combination with the disassembly
        engine, since it will look for dynamically observed branches.
        
        :param dequeue queue: The queue of instruction addresses
        
        :return: None
        """
        with open(self.trace_file) as f:
            for line in f.readlines():
                splitted_line = line.split()
                if len(splitted_line) < 4:
                    continue
                wave = int(splitted_line[1])
                if wave == self.wave and splitted_line[2] == 'B':
                    source = splitted_line[3]
                    destination = splitted_line[5]
                    source_addr = int(source, 16)
                    destination_addr = int(destination, 16)
                    queue.append(source_addr)

    def recursive_disassemble(self, start_addresses):
        """
        Perform a recursive disassemble.
        
        :param list start_addresses:    A list of instruction addresses to 
                                        start disassemly from.
        
        :return: None
        """
        self.instr_queue = deque()
        for address in start_addresses:
            self.instr_queue.append(address)

        if self.use_trace_file == True:
            self.insert_branches_from_trace_file(self.instr_queue)
        limit = 0
        disassembled = 0
        while len(self.instr_queue) > 0:
            instr_addr = self.instr_queue.popleft()
            if self.instr_graph.is_analysed(instr_addr) == True or self.mem_dump.is_it_in_module(instr_addr) == False:
                continue
            disassembled += 1
            instr = RPE_instruction()
            buf = self.mem_dump.read_memory(instr_addr, 15)
            try:
                dec_instr = self.instr_decoder.disasm(buf, instr_addr).next()
            except StopIteration:
                continue

            instr.address = instr_addr
            instr.decoded_instr = dec_instr
            self.instr_graph.add_node(instr)
            branch_dsts = self.get_branch_destinations(instr)
            for dst_addr in branch_dsts:
                self.instr_graph.add_edge(instr, dst_addr, 3)
                self.instr_queue.append(dst_addr)

            self.handle_branch_destination(instr)
            self.handle_memory_reads(instr)

        print 'Disassembled in total: ' + `disassembled`
        print 'number of nodes in graph: ' + `(len(self.instr_graph.graph))`
        print 'Instructions to relocate: ' + `(len(self.instructions_to_relocate))`
        print 'Number of functions in import table: ' + `(self.import_table.number_of_functions())`
        relocate_set = set(self.instructions_to_relocate)
        print 'Size of set to relocate: ' + `(len(relocate_set))`
        #for instr_address in relocate_set:
        #    print '%x\t' % instr_address

    def build_import_table(self):
        """
        Builds the new import table in the section added by the 
        tracer.
        """
        self.section_alignment = 4096
        pe = pefile.PE(data=self.mem_dump.dump)
        IAT_addr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        print 'IAT_addr: ' + hex(IAT_addr)
        raw_size = self.import_table.raw_memory_size()
        jump_table_size = self.import_table.get_jump_table_size()

        print "raw_size: ", `raw_size`
        print "jump table size: ", `jump_table_size`

        size = ((raw_size+jump_table_size) / self.section_alignment + 1) * self.section_alignment
        print size
        byte_array = bytearray(size)
        IID_pos = 0
        content_pos = (len(self.import_table.dlls) + 1) * 20

        jump_table_pos = IID_pos + raw_size

        print "jump table position: ", hex(jump_table_pos)

        for dll in self.import_table.dlls:
            print dll
            thunk_position = content_pos + len(dll) + 1
            byte_array[IID_pos + 12:IID_pos + 16] = pack('<L', content_pos + IAT_addr)
            byte_array[IID_pos + 16:IID_pos + 20] = pack('<L', thunk_position + IAT_addr)

            print 'Dll position: ', content_pos
            byte_array[content_pos:content_pos + len(dll)] = dll
            names_pos = thunk_position + (len(self.import_table.dlls[dll]) + 1) * 4

            for function_name in self.import_table.dlls[dll]:
                self.import_table.set_thunk_addr(dll, function_name, thunk_position + IAT_addr)
                byte_array[thunk_position:thunk_position + 4] = pack('<L', names_pos + IAT_addr)
                func_name = '\x00\x00' + function_name
                func_name_len = len(function_name) + 2
                byte_array[names_pos:names_pos + func_name_len] = func_name


                # Write the jump table entry 
                byte_array[jump_table_pos] = 0xFF
                byte_array[jump_table_pos+1] = 0x25
                byte_array[jump_table_pos+2:jump_table_pos+6] = pack("<L", thunk_position + IAT_addr + self.mem_dump.base_address)

                self.import_table.set_jump_addr(dll, function_name, jump_table_pos + IAT_addr)

                # Accumulate the new counters
                thunk_position += 4
                names_pos += func_name_len
                jump_table_pos += 6

            IID_pos += 20
            content_pos = names_pos + 1

        self.mem_dump.append_memory_before_end(byte_array, IAT_addr)


    def relocate_single_instruction2(self, instr, dll_name, function_name):
		test = 1
		decoded_instr = instr.decoded_instr
		bytes = instr.decoded_instr.bytes
		opcode = bytes[0]

		for group in decoded_instr.groups:
			if group == X86_GRP_JUMP:
				# We chec if it is a direct or indirect jmp.
				if opcode == 0xFF:
					# It uses addressing, so we need to 
					# relocate to point to a THUNK address
					thunk_addr = self.import_table.get_thunk_addr(dll_name, function_name)
					thunk_addr += self.mem_dump.base_address
					MOD = (bytes[1] & 0xC0)

					if MOD == 0x00:
						self.mem_dump.write_address(instr.address + 2, thunk_addr)

			# Check call instruction
			if group == X86_GRP_CALL:

				if opcode == 0xFF:
					# We have a call instruction that does memory referencing.
					bytes = instr.decoded_instr.bytes
					thunk_addr = self.import_table.get_thunk_addr(dll_name, function_name)
					thunk_addr += self.mem_dump.base_address
					MOD = (bytes[1] & 0xC0)
					if MOD == 0x00:
						if decoded_instr.address == 0x40101a:
							print "Relocating call instruction to %x", hex(thunk_addr)
						self.mem_dump.write_address(instr.address + 2, thunk_addr)

				elif opcode == 0xE8:
					# Direct call

					jmp_addr = self.import_table.get_jump_addr(dll_name, function_name)
					jmp_addr += self.mem_dump.base_address

					# Then we need to get the address of the next instruction, because
					# we need to calculate an offset.
					next_instr_addr = decoded_instr.address + decoded_instr.size

					# Then we relocate the instruction to point into our jump table
					offset = jmp_addr - next_instr_addr

                    			print "This is what we write: ", hex(offset)
					self.mem_dump.write_address(instr.address+1, offset)



		if opcode == 0x8B:
            # Get MOD 
			MOD = (bytes[1] & 0xC0)

			if MOD == 0x00:
                # We can relocate
				thunk_addr = self.import_table.get_thunk_addr(dll_name, function_name)
				thunk_addr += self.mem_dump.base_address
				self.mem_dump.write_address(instr.address + 2, thunk_addr)
				print "Relocating mov instruction"

    def relocate_single_instruction(self, instr, new_address):
        """
        
        :return None:
        """
        #print "first"
        decoded_instr = instr.decoded_instr
        for group in decoded_instr.groups:
            if group == X86_GRP_JUMP:
                # Can we relocate this instruction?
                bytes = instr.decoded_instr.bytes

                opcode = bytes[0]
                if opcode == 0xFF:
                    MOD = (bytes[1] & 0xC0)

                    if MOD == 0x00:
                        self.mem_dump.write_address(instr.address + 2, new_address)

                return
            if group == X86_GRP_CALL:
                # Try to replace it, if it is a register or something else
                # then we won't re-arrange the diassembly.
                #print("Instruction address: %x"%(instr.address))
                bytes = instr.decoded_instr.bytes
                #print "bytes:"
                #for x in bytes:
                #    print("%.2x"%(x))


                if decoded_instr.address == 0x40101a:
                	print "We got the instruction, now let's check the destination addr"
                	print "New address: ", hex(new_address)

                # Get the OP code
                opcode = bytes[0]
                if (opcode == 0xFF):
                    # We got a potential candidate

                    MOD = (bytes[1] & 0xC0)
                    if MOD == 0x00:
                        # We can relocate
                        #print "yeah"

                        # Write
                        self.mem_dump.write_address(instr.address + 2, new_address)

                elif (opcode == 0xE8):
                	print "We have a direct call"


                return

        # Those that we do not have any instruction groups on, let 
        bytes = instr.decoded_instr.bytes

        # OP code
        # MOV instruction
        if bytes[0] == 0x8B:
            # Get MOD 
            MOD = (bytes[1] & 0xC0)

            if MOD == 0x00:
                # We can relocate
                self.mem_dump.write_address(instr.address + 2, new_address)
                print "Relocating mov instruction"



                

    def dump_file(self):
        self.mem_dump.dump_file()

    def output_ida_script(self):
        """
                Outputs a script to be run in IDA, that will insert comments
                and add cross-references.
        """
        with open('ida_script.py', 'w') as f:
            f.write('import idaapi\n')
            f.write('import idautils\n')
            for source_addr, dst_addr in self.ida_xrefs:
                #print 'idaapi.add_cref(0x%x, 0x%x, fl_CF)\n' % (source_addr, dst_addr)
                f.write('idaapi.add_cref(0x%x, 0x%x, fl_CF)\n' % (source_addr, dst_addr))

            for source_addr, comment, function_name in self.ida_comments:
                #print 'idc.MakeComm(0x%x, %s%s)\n' % (source_addr, comment, function_name)
                f.write('idc.MakeComm(0x%x, "%s%s")\n' % (source_addr, comment, function_name))

    def ida_branch_exporter(self, source_addr, dst_addr, function_name):
        """
                Adds a cref to the IDAPython output script
        """
        self.ida_xrefs.add((source_addr, dst_addr))
        self.ida_comments.add((source_addr, '[RePEconstruct] Branches to ', function_name))

    def ida_indir_read_exporter(self, source_addr, dst_addr, function_name):

        self.ida_xrefs.add((source_addr, dst_addr))
        self.ida_comments.add((source_addr, '[RePEconstruct] indirectly reads ', function_name))

    def relocate_instructions(self):
        """
        Relocates all the instructions possible.
        """
        for instr_address in self.instructions_to_relocate:
            instr = self.instr_graph.get_instruction(instr_address)
            #print '%x %s' % (instr.address, instr.decoded_instr.mnemonic)
            address_of_export_function = 0
            for dst_addr in instr.get_branch_destinations():
                #print '\tB %x' % dst_addr
                if self.exported_modules.contains_address(dst_addr):
                    dll_name, function_name = self.exported_modules.get_dll_and_function(dst_addr)
                    new_thunk_addr = self.import_table.get_thunk_addr(dll_name, function_name)
                    #print 'dll: %s\tfunction: %s\tthunk_addr %x' % (dll_name, function_name, new_thunk_addr)
                    
                    # IDA relocation
                    new_thunk_addr += self.mem_dump.base_address
                    self.ida_branch_exporter(instr_address, new_thunk_addr, function_name)

                    # Actual relocation
                    #self.relocate_single_instruction(instr, new_thunk_addr)
                    self.relocate_single_instruction2(instr, dll_name, function_name)

            for value in instr.get_values_read():
                #print '\tR %x' % value
                if self.exported_modules.contains_address(value):
                    dll_name, function_name = self.exported_modules.get_dll_and_function(value)
                    new_thunk_addr = self.import_table.get_thunk_addr(dll_name, function_name)
                    #print 'dll: %s\tfunction: %s\tthunk_addr %x' % (dll_name, function_name, new_thunk_addr)
                    new_thunk_addr += self.mem_dump.base_address
                    #self.relocate_single_instruction(instr, new_thunk_addr)
                    self.relocate_single_instruction2(instr, dll_name, function_name)
                    self.ida_indir_read_exporter(instr_address, new_thunk_addr, function_name)

    def handle_branch_destination(self, instr):
        """
        Analyse the branch destinations to verify if any are inside
        an exported library. For each there is, insert the 
        library being called into the import table, and also insert
        the instruction into the list of instructions to relocate.
        
        :param RPE_instruction instr: instruction to analyse.
        
        :return: None
        """
        if self.use_trace_file == True:
            dyn_got_branches = self.get_branch_destinations_dynamic_analysis(instr)
            for dst_addr in dyn_got_branches:
                if self.exported_modules.contains_address(dst_addr) == True:
                    dll_name, function_name = self.exported_modules.get_dll_and_function(dst_addr)
                    self.import_table.add_function(dll_name, function_name, 1, instr)
                    self.instructions_to_relocate.append(instr.address)

        stat_got_branches = self.get_branch_destinations_static_analysis(instr)
        for dst_addr in stat_got_branches:
            if self.exported_modules.contains_address(dst_addr) == True:
                dll_name, function_name = self.exported_modules.get_dll_and_function(dst_addr)
                self.import_table.add_function(dll_name, function_name, 0, instr)
                self.instructions_to_relocate.append(instr.address)

    def handle_memory_reads(self, instr):
        """
        Analyses the instruction in terms of what values it reads.
        Based on these values it will add the instruction to the list
        of instructions to relocate, and also add the function
        it referes into the import table.
        
        We only add imports if it reads the address of only one
        import function. This is because otherwise instructions
        that are used to iterate over all DLLs and their functions
        will cause a blow up. 
        
        Note that the technique here should be substituted for 
        data-flow analysis instead. 
        
        :param RPE_instruction instr:   The instruction to analyse.
        
        :return: None
        """
        reading_export_address = 0
        number_of_exports_read = 0
        dyn_import_pair = set()
        stat_import_pair = set()
        if self.use_trace_file == True:
            dynamic_values_read = self.get_dynamic_memory_reads(instr)
            for value in dynamic_values_read:
                if self.exported_modules.contains_address(value) == True:
                    dll_name, function_name = self.exported_modules.get_dll_and_function(value)
                    dyn_import_pair.add((dll_name, function_name, value))

        static_values_read = list(self.get_static_memory_read(instr))
        for value in static_values_read:
            if self.exported_modules.contains_address(value) == True:
                dll_name, function_name = self.exported_modules.get_dll_and_function(value)
                stat_import_pair.add((dll_name, function_name, value))

        combined_pairs = dyn_import_pair.union(stat_import_pair)
        if len(combined_pairs) == 1:
            if len(dyn_import_pair) == 1:
                for dll_name, function_name, value in dyn_import_pair:
                    self.import_table.add_function(dll_name, function_name, 1, instr)
                    instr.add_values_read(value)
                    reading_export_address = 1

            if len(stat_import_pair) == 1:
                for dll_name, function_name, value in stat_import_pair:
                    self.import_table.add_function(dll_name, function_name, 0, instr)
                    instr.add_values_read(value)
                    reading_export_address = 1

        if reading_export_address == 1:
            self.instructions_to_relocate.append(instr.address)

    def analyse_instruction_reads(self, instr):
        values_read = []
        dec_instr = instr.decoded_instr
        if self.use_trace_file == True:
            ref_value_list = self.dynamic_memory.get_instr_memory_reads(instr.address)
            if ref_value_list != None:
                for lvalue, rvalue in ref_value_list:
                    values_read.append(rvalue)

        values_read += list(self.get_static_memory_read(instr))
        return values_read

    def get_dynamic_memory_reads(self, instr):
        values_read = []
        dec_instr = instr.decoded_instr
        if self.use_trace_file == True:
            ref_value_list = self.dynamic_memory.get_instr_memory_reads(instr.address)
            if ref_value_list != None:
                for lvalue, rvalue in ref_value_list:
                    values_read.append(rvalue)

        first_opnd = 0
        for opnd in dec_instr.operands:
            if first_opnd == 0:
                first_opnd += 1
                continue
            if opnd.type != X86_OP_MEM:
                continue
            lvalue = opnd.mem.disp
            if self.use_trace_file == True:
                dyn_rvalues = self.dynamic_memory.get_lvalue_to_rvalues(lvalue)
                if dyn_rvalues != None:
                    for val in dyn_rvalues:
                        values_read.append(val)

        return values_read

    def get_static_memory_read(self, instr):
        dec_instr = instr.decoded_instr
        values_read = set()
        for opnd in dec_instr.operands:
            if opnd.access == CS_AC_READ:
                if opnd.mem.segment != X86_REG_INVALID:
                    continue
                if opnd.mem.base != X86_REG_INVALID:
                    continue
                if opnd.mem.base != X86_REG_INVALID:
                    continue
                if opnd.mem.disp != 0:
                    lvalue = opnd.mem.disp
                    static_rvalue = self.mem_dump.read_memory(lvalue, 4)
                    if static_rvalue != None and len(static_rvalue) == 4:
                        unpacked_val = unpack('<L', static_rvalue)
                        values_read.add(unpacked_val[0])
            if opnd.type != X86_OP_MEM:
                continue

        return values_read

    def get_branch_destinations(self, instr):
        branch_destinations = []
        branch_destinations += self.get_branch_destinations_static_analysis(instr)
        if self.use_trace_file == True:
            branch_destinations += self.get_branch_destinations_dynamic_analysis(instr)
        return branch_destinations

    def get_branch_destinations_dynamic_analysis(self, instr):
        dec_instr = instr.decoded_instr
        destinations = self.dynamic_memory.get_branch_destinations(dec_instr.address)
        return destinations

    def get_branch_destinations_static_analysis(self, instr):
        branch_destinations = []
        dec_instr = instr.decoded_instr
        is_ret_instr = False

        for group in dec_instr.groups:

            if group == X86_GRP_JUMP:
                target = self.get_branch_destination_address(instr)

                if target != None:
                    branch_destinations.append(target)

            elif group == X86_GRP_CALL:

            	if dec_instr.address == 0x40101a:
            		print("%x calls"%(dec_instr.address))

                target = self.get_branch_destination_address(instr)

                if dec_instr.address == 0x40101a:
                	print "targets: ", hex(target)

                if target != None:
                    branch_destinations.append(target)

            elif group == X86_GRP_RET:
                is_ret_instr = True

            elif group == X86_GRP_INT:
                None

            elif group == X86_GRP_INVALID:
                None

        if is_ret_instr == False:
            next_instr_addr = dec_instr.address + dec_instr.size
            next_dword = self.mem_dump.read_memory(next_instr_addr, 2)
            if next_dword != '\x00\x00':
                branch_destinations.append(next_instr_addr)
        return branch_destinations

    def get_branch_destination_address(self, instr):
        dec_instr = instr.decoded_instr
        for group in dec_instr.groups:
            if group == X86_GRP_JUMP:
                for opnd in dec_instr.operands:
                    if opnd.type == X86_OP_MEM:
                        memory_address = opnd.mem
                        if memory_address.disp == 0:
                            continue
                        value = self.mem_dump.read_address(memory_address.disp)
                        return value[0]
                    if opnd.type == X86_OP_IMM:
                        immediate_address = opnd.imm
                        return immediate_address
                    if opnd.type == X86_OP_REG:
                        None

            elif group == X86_GRP_CALL:
                for opnd in dec_instr.operands:
                    if opnd.type == X86_OP_MEM:
                        memory_address = opnd.mem
                        if memory_address.disp == 0:
                            continue
                        if memory_address.segment != X86_REG_INVALID:
                            continue
                        if memory_address.base != X86_REG_INVALID:
                            continue
                        if memory_address.base != X86_REG_INVALID:
                            continue
                        value = self.mem_dump.read_address(memory_address.disp)
                        return value[0]
                    if opnd.type == X86_OP_IMM:
                        immediate_address = opnd.imm

                        return immediate_address
                    if opnd.type == X86_OP_REG:
                        None

    def print_instruction(self, instr_address):
        if not self.instr_graph.is_analysed(instr_address):
            print 'instruction not in graph'
            return
        instr = self.instr_graph.get_instruction(instr_address)
        if instr != None:
            dec_instr = instr.decoded_instr
            print '0x%x:\t%s\t%s' % (dec_instr.address, dec_instr.mnemonic, dec_instr.op_str)
            destinations = instr.get_branch_destinations()
            for dst in destinations:
                print hex(dst)
