static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating,
                                         OUT void **user_data);

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                  bool for_trace, bool translating,
                  OUT void **user_data);

static void instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
		int pos, bool write, int memory_reference);

static void instrument_read_memory(void *drcontext, instrlist_t *ilist, instr_t *where, int pos);

static void
write_to_output(char *output_text, int text_length);

static void
write_wave_and_entrypoint(char *output_text, int text_length);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                 bool for_trace, bool translating);


static void instrument_set_value(
		void *drcontext, instrlist_t *ilist, instr_t *where, 
		int value, unsigned int offset);
