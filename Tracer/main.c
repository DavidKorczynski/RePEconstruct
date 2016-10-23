/*
 * Author: David Korczynski
 * Email:  david.korczynski@linacre.ox.ac.uk
 * 
 * Copyright 2016.
 * All rights reserved.
 *
 *
 */

#include <Windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* for offsetof */
#include <stddef.h>

// DynamoRIO imports
#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"

// Function declarations
#include "unpacker.h"

// Capstone
#include "Capstone/include/capstone.h"


#define SAVE_REG(_reg, _slot)\
	dr_save_reg(drcontext, bb, instr, _reg, _slot);

#define RESTORE_REG(_reg, _slot)\
	dr_restore_reg(drcontext, bb, instr, _reg, _slot);


// Used by the library referencer
unsigned int module_base_address = 0;
unsigned int module_base_size = 0;

/* Helper for dumping process */
//#define IMAGE_DOS_SIGNATURE 0x5a4d

typedef struct mapped_pe_t {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_SECTION_HEADER pSectHeader;
} mapped_pe;

mapped_pe dump_pe_header;

/* number of waves in the packer */
int dump_wave = 0;

#define new_import_section_size_definition 0x1000


// Capstone
// handle to disassembler
csh handle;


/* we have several number of operands */
typedef struct {
       unsigned int mem_ref1;
       unsigned int mem_ref2;
       unsigned int mem_ref3;
       unsigned int mem_ref4;
       unsigned int size_of_mem_write;
       app_pc pc;
       unsigned int reads_memory;
       unsigned int address_being_read;
       unsigned int number_of_refs; /* this indicates how many of the operands are used */
       unsigned int instr_size;
       unsigned int old_instr_size;
       unsigned int old_pc;
} tls_storage;


// Output file, with trace information
FILE *output_file;
FILE *wave_file;

static uint64 global_count;

/* hashtable */
#define SIZE 25000
#define HASHFUNCTION(n) (n) % (unsigned int) SIZE

struct node {
	unsigned int address;
	struct node *next;
	struct node *prev;
};

/* initiate the data structures used for collecting all the 
 * functions exported by various modules.
 */

struct node *hashtable [SIZE];
int table_size = 0;

int tls_index;

tls_storage *mem_buffer;

/* hashtable implementation */
int
is_in(unsigned int address)
{
        struct node *tmp;
        unsigned int place;

        place = HASHFUNCTION(address);
        tmp = hashtable[place];

        while (tmp != NULL)
        {
                if (tmp->address == address)
                        return 1;
                tmp = tmp->next;
        }

        return 0;
}

int
insert(unsigned int address)
{
        struct node *holder;
        unsigned int place;

        place = HASHFUNCTION(address);

        holder = (struct node *) dr_global_alloc(sizeof(struct node));
        holder->address = address;


        holder->next = hashtable[place];
        holder->prev = NULL;

        if (hashtable[place] != NULL)
                hashtable[place]->prev = holder;

        hashtable[place] = holder;

        table_size++;

        return 1;
}

/* 
 * Clear the hashtable containing dynamically written memory 
 */ 
void
delete_all()
{
	int i;
        struct node *tmp;

        for (i=0; i < SIZE; i++)
        {
                tmp = hashtable[i];
                while (tmp != NULL)
                {
                        struct node *tmp2;

                        tmp2 = tmp->next;
                        dr_global_free(tmp, sizeof(struct node));
                        tmp = tmp2;
                        table_size--;
                }
		hashtable[i] = NULL;
        }
	if (table_size < 0)
		DR_ASSERT(false);
}

/* 
 * Input: The address of a module
 *
 * Functionality:
 * 	Iterate the exported functions of the module
 * 	For each function, save the virtual address and the function name in the Dll_list 
 *
 */
void
TraverseExportedFunctions(HANDLE base_address, char *dll_name, FILE *output_file)
{
	/* The PE header */
	mapped_pe pe;
	PIMAGE_EXPORT_DIRECTORY export_directory;
	IMAGE_DATA_DIRECTORY export_data_dir;
	unsigned int AddressOfNames_array;
	char *func_name;
	int i;
	unsigned int *function_name_offset;
	unsigned int ordinal_addr_arr;
	short int ordinal;

	unsigned int function_addr_arr;
	unsigned int function;

	char output_line[512];

	// Get DOS header of module
	pe.pDosHeader = (PIMAGE_DOS_HEADER) base_address;

	if (pe.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		dr_fprintf(STDERR, "DOS signature not correct\n");

	// Get PE header of module
	pe.pNtHeader = (PIMAGE_NT_HEADERS) ((unsigned int)base_address + pe.pDosHeader->e_lfanew);

	/* Is PE header valid? */
	if (pe.pNtHeader->Signature !=  IMAGE_NT_SIGNATURE)
		dr_fprintf(STDERR, "NT signature not correct\n");

	// Get optional header
	pe.pOptHeader = &(pe.pNtHeader->OptionalHeader);

	/* Get the export directory */
	export_data_dir = pe.pOptHeader->DataDirectory[0];
	export_directory = (PIMAGE_EXPORT_DIRECTORY) ((unsigned int)base_address + export_data_dir.VirtualAddress);

	/* Return if we don't export any functions */
	if (export_directory->NumberOfFunctions == 0)
		return;

	// Get the address to the string of names
	// AddressOfNames is an RVA that points to an array of RVAs of the functions/symbols in the module
	AddressOfNames_array = ((unsigned int)base_address + export_directory->AddressOfNames);


	i = 0;

	// For each address in the array pointed to by AddressOfNames
	// This one only iterates NAMES - modify so it also iterates Ordinals.
	while (function_name_offset = (unsigned int *)AddressOfNames_array + i)
	{
		func_name = (char *)((unsigned int)base_address + *function_name_offset);
		// End of function list
		if (*func_name == '\0')
			return;

		/* Get the ordinal of what we are doing */
		ordinal_addr_arr = (unsigned int)base_address + export_directory->AddressOfNameOrdinals;
		ordinal = *((short *)ordinal_addr_arr + i);

		/* Get the address of the function */
		function_addr_arr = (unsigned int)base_address + export_directory->AddressOfFunctions;
		function = *((unsigned int*)function_addr_arr+ordinal);

		function += (unsigned int)base_address;

		/* Write to output */
		sprintf(output_line, "%s %s %x\n", dll_name, func_name, function);
		fwrite(output_line, strlen(output_line), 1, output_file);

		// Insert the function name and its address into our Dll_list list.
		//insert_exported_function(dll_name, func_name, function);

		i += 1;

		if (i >= export_directory->NumberOfNames)
			return;
	}
}


/* 
 * Gets the name and exported functions from each module
 * in the process. Save this in the Dll_list data
 * structure.
 */
void
GetAllDllNames()
{
	HANDLE snapshot;
	MODULEENTRY32 module;
	FILE *export_output;
	char export_filename[255];
	

	// TH32CS_SNAPSHOT == 0x08
	snapshot = CreateToolhelp32Snapshot(0x08, 0);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		module.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(snapshot, &module))
		{
			/* Open file we write to */
			sprintf(export_filename, ".\\Refactor_output\\exports_wave-%d", dump_wave);
			export_output = fopen(export_filename, "w");

			if (export_output == NULL)
			{
				dr_fprintf(STDERR, "Error opening export file, exiting\n");
				exit(1);
			}

			module.dwSize = sizeof(MODULEENTRY32);

			do // Iterate each module of the process to collect export functions
			{
				// Insert all the exported functions from the DLL into
				// our Dll_list doubly linked list.
				TraverseExportedFunctions(module.modBaseAddr, module.szModule, export_output);
			}
			while (Module32Next(snapshot, &module));

			fclose(export_output);
		}
	}
}

#define FILE_ALIGNMENT      0x200
#define SECT_ALIGNMENT      0x1000

void
write_new_section(byte *memory_dump, unsigned int base_address)
{
	unsigned int i;

	unsigned int max_section_address;
	unsigned int max_section_size;

	PIMAGE_SECTION_HEADER new_import_section;

	// Get section header
	new_import_section = (PIMAGE_SECTION_HEADER) dump_pe_header.pSectHeader;

	// max_section_address represents the address of the last section
	max_section_address = 0;

	// max_section_size represents the size of the last section.
	max_section_size = 0;

	// find the offset in the section header where our new section will be
	for (i=0; i < (unsigned int)(dump_pe_header.pFileHeader->NumberOfSections); i++)
	{
		//if (new_import_section->
		if (new_import_section->VirtualAddress > max_section_address)
		{
			max_section_address = new_import_section->VirtualAddress;
			max_section_size = new_import_section->Misc.VirtualSize;
		}
		new_import_section++;
	}

	// Increase the number of sections
	dump_pe_header.pFileHeader->NumberOfSections++;
	
	// ## Create the new section ##
	// Set Name
	strcpy(new_import_section->Name, "new_imp");	
	
	// Set virtual size of the section of new import table
	new_import_section->Misc.VirtualSize = new_import_section_size_definition;

	// Set a valid section Virtual Address of new import table
	max_section_address += max_section_size;
	max_section_address = 
		((max_section_address%SECT_ALIGNMENT) != 0) ? 
			(max_section_address/SECT_ALIGNMENT+1)*SECT_ALIGNMENT : max_section_address;

	new_import_section->VirtualAddress = max_section_address;

	// set a valid Raw offset of new import table, this is equal to the RVA 
	// indicated by VirtualAddress because we dump the image as it is in the binary.
	new_import_section->PointerToRawData = new_import_section->VirtualAddress;
	
	// set raw size - similar to VirtualSize
	new_import_section->SizeOfRawData = new_import_section->Misc.VirtualSize;

	// Set characteristics of the section
	new_import_section->Characteristics = 0xc0300040;

	/* set size and addr of new section */
	dump_pe_header.pOptHeader->DataDirectory[1].VirtualAddress = max_section_address;
	dump_pe_header.pOptHeader->DataDirectory[1].Size = 
					new_import_section->Misc.VirtualSize;

	/* Zero old data directory with fast address for import table */
	dump_pe_header.pOptHeader->DataDirectory[12].VirtualAddress = 0x0;
	dump_pe_header.pOptHeader->DataDirectory[12].Size = 0x0;

	/* Size of the new image */
	dump_pe_header.pOptHeader->SizeOfImage = (dump_pe_header.pOptHeader->SizeOfImage + new_import_section->Misc.VirtualSize);
}


/*
 * Sets PointerToRawData and SizeOfRawData in each section
 * in the section table, equal to the sizes and virtual
 * addresses in the virtual memory.
 *
 * We need this because we drop the entire Binary as it is in memory.
 */ 
void
configure_section_offsets(byte *memory_dump, unsigned int base)
{
	int i;

	/* we iterate through the sections */
	for (i = 0; i < dump_pe_header.pFileHeader->NumberOfSections; i++)
	{
		/* Raw offset should remain the same as virtual address offset.  */
		dump_pe_header.pSectHeader[i].PointerToRawData = dump_pe_header.pSectHeader[i].VirtualAddress;
		dump_pe_header.pSectHeader[i].SizeOfRawData = dump_pe_header.pSectHeader[i].Misc.VirtualSize;
	}
}

void
write_entry_point(unsigned int new_entry_point, unsigned int base_address, byte *memory_dump)
{
	dump_pe_header.pOptHeader->AddressOfEntryPoint = (new_entry_point - base_address);
}

/* Sets the elements of dump_pe_header according to the new memory_dump */
int
Set_PE_header(byte *memory_dump)
{
	dump_pe_header.pDosHeader = (PIMAGE_DOS_HEADER) memory_dump;
	
	if (dump_pe_header.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		dr_fprintf(STDERR, "DOS signature not correct\n");


	dump_pe_header.pNtHeader = (PIMAGE_NT_HEADERS)(memory_dump + 
						dump_pe_header.pDosHeader->e_lfanew);

	/* set nt header */
	if (dump_pe_header.pNtHeader->Signature !=  IMAGE_NT_SIGNATURE)
		dr_fprintf(STDERR, "NT signature not correct\n");

	/* Set optional header */
	dump_pe_header.pOptHeader = (PIMAGE_OPTIONAL_HEADER) 
					&(dump_pe_header.pNtHeader->OptionalHeader);
	
	/* Set file header */
	dump_pe_header.pFileHeader = (PIMAGE_FILE_HEADER) 
					&(dump_pe_header.pNtHeader->FileHeader);

	if (dump_pe_header.pFileHeader == NULL)
		dr_fprintf(STDERR, "File header == NULL");

	/* Set section header */
	dump_pe_header.pSectHeader = (PIMAGE_SECTION_HEADER)
					((unsigned long)dump_pe_header.pNtHeader + 
					 			sizeof(IMAGE_NT_HEADERS));


	return 1;
}


int
write_process_image(unsigned int new_entry_point)
{
	HANDLE snapshot;
	MODULEENTRY32 module;
	FILE *image;
	char entire_dump_name[255];
	byte *memory_dump;
	unsigned int import_section_size;
	unsigned int total_size;

	snapshot = CreateToolhelp32Snapshot(0x08, 0x00);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		module.dwSize = sizeof(MODULEENTRY32);

		// Get main module
		if (Module32First(snapshot, &module))
		{

			if (module.modBaseSize != 0xffffffff)
			{
		
				module_base_address = (unsigned int)module.modBaseAddr;
				module_base_size = (unsigned int) module.modBaseSize;

				// Name of the file we dump to.
				sprintf(entire_dump_name, ".\\Refactor_output\\entire_unpacked-%d", dump_wave);

				// Size of the new import section.
				import_section_size = new_import_section_size_definition;

				// Size of the copied module + size of new import section
				total_size = module.modBaseSize + import_section_size;

				// Allocate space for the copied module.
				memory_dump = dr_global_alloc(total_size);

				if (memory_dump == 0)
				{
					dr_fprintf(STDERR, "error when allocating space for copy of memory\n");
					exit(1);
				}


				// Copy main module into our newly allocated space.
				memcpy(memory_dump, module.modBaseAddr, module.modBaseSize);
					
				Set_PE_header(memory_dump);

				// Set the section headers' PointerToRawData and SizeOfRawData
				// to be equal that which it is in virtual memory. This is because
				// we dump the image as it looks like in memory.
				configure_section_offsets(memory_dump, (unsigned int)module.modBaseAddr);

				// Set entry point of module to be equal the first instruction in our
				// dynamically generated code.

				/*
				 * In the experiments of the paper we actually sat the entry point.
				 * However, we later observed this not to be the best choice and 
				 * instead do not do it now. 
				 */
				//write_entry_point(new_entry_point, (unsigned int)module.modBaseAddr, memory_dump);

				// Write the new import section to the image, extending the size of it.
				write_new_section(memory_dump, (unsigned int) module.modBaseAddr);

				/* Open the file we dump to. */
				image = fopen(entire_dump_name, "wb");

				// Write the memory to file
				fwrite(memory_dump, total_size, 1, image);

				fclose(image);
			}
		}
	}	

	return 1;
}


int
dump_clean()
{
	HANDLE snapshot;
	MODULEENTRY32 module;
	FILE *image;
	char entire_dump_name[255];
	byte *memory_dump;
	unsigned int import_section_size;
	unsigned int total_size;

	snapshot = CreateToolhelp32Snapshot(0x08, 0x00);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		module.dwSize = sizeof(MODULEENTRY32);

		// Get main module
		if (Module32First(snapshot, &module))
		{

			if (module.modBaseSize != 0xffffffff)
			{
		
				// Name of the file we dump to.
				sprintf(entire_dump_name, ".\\Refactor_output\\entire_unpacked_clean-%d", dump_wave);

				// Size of the copied module + size of new import section
				total_size = module.modBaseSize;

				// Allocate space for the copied module.
				memory_dump = dr_global_alloc(total_size);

				if (memory_dump == 0)
				{
					dr_fprintf(STDERR, "error when allocating space for copy of memory\n");
					exit(1);
				}


				// Copy main module into our newly allocated space.
				memcpy(memory_dump, module.modBaseAddr, module.modBaseSize);
					
				Set_PE_header(memory_dump);

				// Set the section headers' PointerToRawData and SizeOfRawData
				// to be equal that which it is in virtual memory. This is because
				// we dump the image as it looks like in memory.
				configure_section_offsets(memory_dump, (unsigned int)module.modBaseAddr);

				/* Open the file we dump to. */
				image = fopen(entire_dump_name, "wb");

				// Write the memory to file
				fwrite(memory_dump, total_size, 1, image);

				fclose(image);
			}
		}
	}	

	return 1;
}

int dump_clean_also = 1;

void
DumpProcess(unsigned int entry_point)
{
	// Get name and exported functions of modules in the process
	// The data is inserted in Dll_list
	//
	/* Keep this call */

	/* Write exports */
	GetAllDllNames();

	// Drop the binary and reconstruct import table
	write_process_image(entry_point);

	if (dump_clean_also)
	{
		dump_clean();
	}
	
	// Increase the wave number
//	dump_wave++;
}

static void
clean_call(void)
{
	unsigned int mem_refs;
	unsigned int mem_reference;
	unsigned int value_being_read;
	tls_storage *data;
	int i;
	void *drcontext;

	drcontext = dr_get_current_drcontext();
	data = (tls_storage *) drmgr_get_tls_field(drcontext, tls_index);
	mem_refs = data->number_of_refs;


	// Branch instructions
	if (data->old_pc != 0 && 
		data->old_pc < (module_base_address+module_base_size) &&
		data->old_pc > (module_base_address) &&
		((data->old_pc + data->old_instr_size) != (unsigned int)data->pc))
	{
		char output_line[100];
		int c;
			
		for (c = 0; c < 100; c++)
			output_line[c] = '\0';

		sprintf(output_line, "W %d B %x to %x\n", 
				dump_wave, data->old_pc, data->pc);

		write_to_output(output_line, strlen(output_line));
	}

	data->old_pc = (unsigned int)data->pc;
	data->old_instr_size = data->instr_size;
	

	// Is the instruction part of written memory?
	for (i = 0; i < data->instr_size; i++)
	{
		if (is_in((unsigned int)data->pc + i))
		{
			char output_line[60];
			int c;

			dump_wave++; 
		
			for (c = 0; c<60; c++)
			{
				output_line[c] = '\0';
			}


			sprintf(output_line, "W %d First executed instruction at "PFX"\n",
					dump_wave, data->pc);

			write_wave_and_entrypoint(output_line, strlen(output_line));
			


			//dr_fprintf(STDERR, "Wave %d detected with entrypoint at "PFX"\n", dump_wave, data->pc);
			//dr_printf("Executing dynamically generated code at "PFX"\n", data->pc);
			// Clear hashtable of dynamically written memory
			delete_all();

			DumpProcess((unsigned int)data->pc);

			// We only need to capture it once.
			break;
		}
	}

	/* 
	 * Check memory references and insert if necessary 
         * We can optimize this by instead of having both is_in and insert, rather
	 * have insert_if_not_in. 
	 * */
	switch(mem_refs)
	{
		int i;

		case 4:
			mem_reference = data->mem_ref4;
			for (i = 0; i < data->size_of_mem_write; i++)
				if (is_in(mem_reference+i) == 0) insert(mem_reference+i);
		case 3: 
			mem_reference = data->mem_ref3;
			for (i = 0; i < data->size_of_mem_write; i++)
				if (is_in(mem_reference+i) == 0) insert(mem_reference+i);
		case 2:
			mem_reference = data->mem_ref2;
			for (i = 0; i < data->size_of_mem_write; i++)
				if (is_in(mem_reference+i) == 0) insert(mem_reference+i);
		case 1: 
			mem_reference = data->mem_ref1;
			for (i = 0; i < data->size_of_mem_write; i++)
				if (is_in(mem_reference+i) == 0) insert(mem_reference+i);
	}


	/* Check if it is an indirect reference */
	if (data->reads_memory)
	{
		if ((unsigned int)data->pc >= module_base_address && \
			(unsigned int)data->pc < (module_base_address+module_base_size))
		{
			value_being_read = *(unsigned int*)data->address_being_read;

			// Is address of memory being read inside module?
			if (value_being_read <= module_base_address || value_being_read > (module_base_address+module_base_size))
			{
				char output_line[50];
				int c;
				
				for (c=0; c<50; c++)
					output_line[c] = '\0';

				// format:
				// wave #num I #instruction_address #address_being_read #value_of_addr_being_read
				sprintf(output_line, "W %d I %x %x %x\n",
						dump_wave, // Fix
						data->pc, 
						data->address_being_read, 
						value_being_read);

				write_to_output(output_line, strlen(output_line));
			}
		}
	}
	
	/* set reference number to 0 */
	/* ensure you don't have to use drmgr_set_tls_field here */
	data->number_of_refs = 0;
	data->reads_memory = 0;
}

/*
 *
 * Writes the output_text to the output file. 
 * Writes "text_length" number of bytes.
 *
 */
static void
write_to_output(char *output_text, int text_length)
{
	fwrite(output_text, text_length, 1, output_file);
	fflush(output_file);
}

static void
write_wave_and_entrypoint(char *output_text, int text_length)
{
	fwrite(output_text, text_length, 1, wave_file);
	fflush(wave_file);
}

/* 
 *
 * End of analysis
 *
 */
static void
event_exit(void)
{
	// Close the output file
	fclose(output_file);

	// Close the wave file
	fclose(wave_file);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
	int i;

	global_count = 0;
	dump_wave = 0;

	/* if we can't print, then return */
	if (!dr_enable_console_printing())
		return;


	/* init hash table */
	for (i = 0; i < SIZE; i++)
	{
		hashtable[i] = NULL;
	}

	dr_set_client_name("DynamoRIO Sample Client 'memtrace'",
				"http://dynamorio.org/issues");


	/* initialize manager and util */
	if (!drmgr_init() || !drutil_init())
		DR_ASSERT(false);

	dr_register_exit_event(event_exit);

	// setup disassembler
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	{
		dr_fprintf(STDERR, "Could not initialize disassembler\n");	
		DR_ASSERT(false);
	}	

	// Open output file
	output_file = fopen(".\\Refactor_output\\trace_output", "w");
	if (output_file == NULL)
	{
		dr_fprintf(STDERR, "Error opening output file\n");
		exit(1);
	}

	wave_file = fopen(".\\Refactor_output\\wave_entrypoints", "w");
	if (wave_file == NULL)
	{
		dr_fprintf(STDERR, "Error opening wave file\n");
		exit(1);
	}

	/* we must call our initialization events */
	if (!drmgr_register_thread_init_event(event_thread_init) ||
	    !drmgr_register_thread_exit_event(event_thread_exit))
		DR_ASSERT(false);

	// Instrumentation
	if (!drmgr_register_bb_app2app_event(event_bb_app2app, NULL) || 
	    !drmgr_register_bb_instrumentation_event(event_bb_analysis,
						     event_bb_insert,
						     NULL))
	{
		DR_ASSERT(false);
		return;
	}	

	/* initialize TLS */
	tls_index = drmgr_register_tls_field();
	DR_ASSERT(tls_index != -1);
}

static void
event_thread_init(void *drcontext)
{
	tls_storage *data;

	data = dr_thread_alloc(drcontext, sizeof(tls_storage));

	drmgr_set_tls_field(drcontext, tls_index, data);
	dr_printf("Thread init\n");
}

static void
event_thread_exit(void *drcontext)
{
	tls_storage *data;

	data = drmgr_get_tls_field(drcontext, tls_index);

	dr_thread_free(drcontext, data, sizeof(tls_storage));
	dr_printf("Thread exit\n");
}

/* we transform string loops into regular loops so we can more easily
 * monitor every memory reference they make
 */
static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                 bool for_trace, bool translating)
{
    //if (!drutil_expand_rep_string(drcontext, bb)) {
      //  DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    //}
    return DR_EMIT_DEFAULT;
}


// Do nothing
static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
		  bool for_trace, bool translating,
		  OUT void **user_data)
{
	return DR_EMIT_DEFAULT;
}

/* 
 *
 * Main instrumentation function.
 *
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                  bool for_trace, bool translating,
                  OUT void **user_data)
{
    int i;
    int memory_references, total_refs;
    int instruction_opcode;
    int indirect_call = 0;
    int bytes_occupied;

	// Capstone stuff
	cs_insn *insn;
	unsigned int size;
	int count;

    if (!instr_is_app(instr))
		    return DR_EMIT_DEFAULT;

    memory_references = 0;
    total_refs = 0;

    if (instr_get_app_pc(instr) == NULL)
	    return DR_EMIT_DEFAULT;

    instruction_opcode = instr_get_opcode(instr);

	// Instrumentation for getting the readings of indirect references
	if (instr_reads_memory(instr))
	{
		//dr_printf("It reads memory\n");
		if (opnd_is_memory_reference(instr_get_src(instr, 0)))
		{
			instrument_read_memory(drcontext, bb, instr, 0);
			instrument_set_value(drcontext, bb, instr,
				(int) 1, offsetof(tls_storage, reads_memory));
			indirect_call = 1;
		}
	}


	// Instrumentation for getting the addresses being written
    if (instr_writes_memory(instr))
    {
	unsigned int write_size;

	// How many writes do we have in all
	for (i = 0; i < instr_num_dsts(instr); i++)
	{
	    if (opnd_is_memory_reference(instr_get_dst(instr, i)))
		    total_refs++;
	}

	// Instrument each write
	for (i = 0; i < instr_num_dsts(instr); i++)
	{
	    if (opnd_is_memory_reference(instr_get_dst(instr, i)))
	    {
		    // i = operand number
		    // memory_reference = the operand number which is a memory reference
	        instrument_mem(drcontext, bb, instr, i, true, memory_references);
	        memory_references++;
	    }
	}
	
	// Write size of the memory written
	write_size = instr_memory_reference_size(instr);

	instrument_set_value(drcontext, bb, instr,
			(int)write_size, offsetof(tls_storage, size_of_mem_write));
    }

	// Save the number of addresses the instruction writes to.
	instrument_set_value(drcontext, bb, instr,
			(int) total_refs, offsetof(tls_storage, number_of_refs));

	// Save the address of the instruction
	instrument_set_value(drcontext, bb, instr, 
			(int)instr_get_app_pc(instr), offsetof(tls_storage, pc));

	// Save the size of the instruction
	// We use capstone to disassemble
	count = cs_disasm(handle, instr_get_app_pc(instr), 15, (unsigned int)instr_get_app_pc(instr), 0, &insn);
	if (count > 0)
	{
		size = (insn[0].size & 0xffff);
		instrument_set_value(drcontext, bb, instr,
			size, offsetof(tls_storage, instr_size));
		//dr_printf("0x%llx\t%s\t%s\t%u\n", 
		//		insn[0].address,
		//		insn[0].mnemonic, 
		//		insn[0].op_str,
		//		(insn[0].size & 0xffff));
	}

    dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call, true, 0);

    return DR_EMIT_DEFAULT;
}


/*
 *
 * Writes a value to a field in a TLS structure.
 * The field is indicated by offset.
 * The value is given by value.
 *
 *
 * param ilist : basic block where instruction to instrument is
 * param where : instruction to instrument
 * param offset : offset of field in tls structure we are writing to
 * param value : value to be written in tls field.
 *
 */
static void instrument_set_value(
		void *drcontext, instrlist_t *ilist, instr_t *where, 
		int value, unsigned int offset)
{
	tls_storage *data;
	reg_id_t reg1 = DR_REG_XBX;
	reg_id_t reg2 = DR_REG_XCX;
	opnd_t ref;
	opnd_t opnd1, opnd2;


	dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
        
	// Instrumentation for writing "reads_memory" value into
	// LTS->reads_memory
	drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);
	
	opnd1 = OPND_CREATE_MEM32(reg2, offset);
	opnd2 = OPND_CREATE_INT32(value);
	
	instrlist_meta_preinsert(ilist, where, 
		INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2));	
	
	dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

}

/*
 * Add instrumentation to read the value of the memory
 * address given by the "pos" operand in instruction
 * "where" in the basic block ilist.
 * The value is stored in the TLS struct at "address_being_read" field
 *
 * param pos : the position of operand to be read
 * param ilist : the basic block with instruction to be instrumented
 * param where : the instruction the be instrumented
 *
 */ 
static void instrument_read_memory(void *drcontext, instrlist_t *ilist, instr_t *where,
		int pos)
{
	tls_storage *data;
	reg_id_t reg1 = DR_REG_XBX;
	reg_id_t reg2 = DR_REG_XCX;
	app_pc pc;
	opnd_t ref;
	opnd_t opnd1, opnd2;

	/* useless call, but they have something similar in memtrace_x86 */	
//	data = drmgr_get_tls_field(drcontext, tls_index);

	dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

	/* read the memory reference */
	ref = instr_get_src(where, pos);
	
	/* put memory address being read into reg1 */
	drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1, reg2);
	opnd1 = opnd_create_reg(reg1);

	/* read TLS field into reg2 */
	drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);

	/* read the field */
	instrlist_meta_preinsert(ilist, where,
			INSTR_CREATE_mov_st(drcontext,
				OPND_CREATE_MEMPTR(reg2, offsetof(tls_storage, address_being_read)),
				opnd1));

	dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}
		


/*
 *
 * Read the memory address holding by instruction "where" with
 * operand "pos" into the mem_refX field in the LTS struct,
 * where X is the number indicated by memory_reference.
 *
 * param ilist : basic block where instruction to be instrumented is
 * param where : instruction to be instrumented
 * param pos : position of operand that contains the address being
 *             written to.
 * param write : NOT USED ANYMORE
 * param memory_reference : the number mem_refX the written address
			    is written to in our LTS struct.
 *
 */
static void instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
		int pos, bool write, int memory_reference)
{
	tls_storage *data;
	reg_id_t reg1 = DR_REG_XBX;
	reg_id_t reg2 = DR_REG_XCX;
	app_pc pc;
	opnd_t ref;
	opnd_t opnd1, opnd2;

	if (memory_reference > 3)
	{
		dr_printf("Memory reference too large\n");
		DR_ASSERT(0);
	}

	/* useless call, but they have something similar in memtrace_x86 */	
//	data = drmgr_get_tls_field(drcontext, tls_index);

	dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

	/* read the first memory reference */
	ref = instr_get_dst(where, pos);
	
	/* put memory address being written into reg1 */
	drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1, reg2);
	opnd1 = opnd_create_reg(reg1);

	/* read TLS field into reg2 */
	drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);

	/* read the field */
	if (memory_reference == 0)
	{
		instrlist_meta_preinsert(ilist, where,
				INSTR_CREATE_mov_st(drcontext,
					OPND_CREATE_MEMPTR(reg2, offsetof(tls_storage, mem_ref1)),
					opnd1));
	}
	else if (memory_reference == 1)
	{
		instrlist_meta_preinsert(ilist, where,
				INSTR_CREATE_mov_st(drcontext,
					OPND_CREATE_MEMPTR(reg2, offsetof(tls_storage, mem_ref2)),
					opnd1));
	}
	else if (memory_reference == 2)
	{
		instrlist_meta_preinsert(ilist, where,
				INSTR_CREATE_mov_st(drcontext,
					OPND_CREATE_MEMPTR(reg2, offsetof(tls_storage, mem_ref3)),
					opnd1));
	}
	else if (memory_reference == 3)
	{
		instrlist_meta_preinsert(ilist, where,
				INSTR_CREATE_mov_st(drcontext,
					OPND_CREATE_MEMPTR(reg2, offsetof(tls_storage, mem_ref4)),
					opnd1));
	}

	dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
	dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
}

// Capstone needs this, otherwise it complains
__declspec(noreturn) void __cdecl __report_rangecheckfailure(void)
{
    exit(1);
}
