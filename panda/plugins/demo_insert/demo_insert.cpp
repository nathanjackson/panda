/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

void panda_insert_call_before(target_ulong pc,
                              void (*callee)(CPUState *, target_ulong));
}

static void foo(CPUState *cpu, target_ulong pc) {
  printf("hello from 0x%lX\n", (uint64_t)pc);
}

bool insn_translate(CPUState *cpu, target_ulong pc) {
  panda_insert_call_before(pc, foo);
  return false; // we don't want insn_exec for this, we're just inserting code
}

bool init_plugin(void *self) {
  panda_cb pcb;
  pcb.insn_translate = insn_translate;
  panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
  return true;
}

void uninit_plugin(void *self) { }
