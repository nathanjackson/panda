/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <string>

#include "panda/plugin.h"

// syscalls2 includes
#include "syscalls2/gen_syscalls_ext_typedefs.h"

// OSI includes
#include "osi/osi_types.h"

#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

#include "taint2/taint2_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

static std::string target_file;
static uint32_t label = 0x8BADF00D;
static bool positional_labels = false;

bool filename_matches(const std::string &fn)
{
    size_t pos = fn.rfind(target_file);
    return pos != std::string::npos &&
           fn.substr(pos).size() == target_file.size();
}

/**
 * Checks to see if the filename is a match. If so, taint is applied to the
 * buffer address.
 */
void read_return_normalized(const std::string &filename,
                            uint32_t physical_address, uint64_t count)
{
    if (filename_matches(filename)) {
        printf(
            "read return (filename = %s, buffer address = 0x%X, count = %lu)\n",
            filename.c_str(), physical_address, count);
        for (auto i = 0; i < count; i++) {
            if (positional_labels) {
                taint2_label_ram(physical_address + i, label++);
            } else {
                taint2_label_ram(physical_address + i, label);
            }
        }
    }
}

/**
 * Windows read return callback. Extract filename and call the normalized read
 * return.
 */
void windows_read_return(CPUState *cpu, target_ulong pc, uint32_t file_handle,
                         uint32_t event, uint32_t user_apc_routine,
                         uint32_t user_apc_context,
                         uint32_t io_status_block_ptr, uint32_t buffer,
                         uint32_t buffer_length, uint32_t byte_offset,
                         uint32_t key)
{
    char *filename = get_handle_name(cpu, get_current_proc(cpu), file_handle);
    uint32_t actually_read = buffer_length;
    struct {
        uint32_t nothing;
        uint32_t information;
    } io_status_block;
    if (panda_virtual_memory_read(cpu, (target_ulong)io_status_block_ptr,
                                  (uint8_t *)&io_status_block,
                                  sizeof(io_status_block)) != -1) {
        actually_read = io_status_block.information;
    } else {
        fprintf(stderr,
                "file_taint: warning, could not read IO Status Block\n");
    }
    read_return_normalized(filename, panda_virt_to_phys(cpu, buffer),
                           actually_read);
    free(filename);
}

void read_enter_normalized(const std::string &filename)
{
    if (!taint2_enabled() && filename_matches(filename)) {
        taint2_enable_taint();
    }
}

void linux_read_enter(CPUState *cpu, target_ulong pc, uint32_t fd,
                      uint32_t buffer, uint32_t count)
{
    OsiProc *process = get_current_process(cpu);
    char *filename = osi_linux_fd_to_filename(cpu, process, fd);
    read_enter_normalized(filename);
    free(filename);
}

void windows_read_enter(CPUState *cpu, target_ulong pc, uint32_t file_handle,
                        uint32_t event, uint32_t user_apc_routine,
                        uint32_t user_apc_context, uint32_t io_status_block_ptr,
                        uint32_t buffer, uint32_t buffer_length,
                        uint32_t byte_offset, uint32_t key)
{
    char *filename = get_handle_name(cpu, get_current_proc(cpu), file_handle);
    read_enter_normalized(filename);
    free(filename);
}

/**
 * Linux read return callback. Extract filename and call the normalized read
 * return.
 */
void linux_read_return(CPUState *cpu, target_ulong pc, uint32_t fd,
                       uint32_t buffer, uint32_t count)
{
    OsiProc *process = get_current_process(cpu);
    char *filename = osi_linux_fd_to_filename(cpu, process, fd);
    target_ulong actually_read = count;
#ifdef TARGET_I386
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    actually_read = env->regs[R_EAX];
#endif
    read_return_normalized(filename, panda_virt_to_phys(cpu, buffer),
                           actually_read);
    free(filename);
}

bool init_plugin(void *self)
{
    panda_require("syscalls2");
    panda_require("osi");
    assert(init_osi_api());
    panda_require("taint2");
    assert(init_taint2_api());

    switch (panda_os_familyno) {
    case OS_WINDOWS: {
#ifdef TARGET_I386
        PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
        PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);
        panda_require("wintrospection");
        assert(init_wintrospection_api());
#endif
    } break;
    case OS_LINUX: {
#ifndef TARGET_PPC
        PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
        PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
        panda_require("osi_linux");
        assert(init_osi_linux_api());
#endif
    } break;
    default:
        assert(0 && "not yet implemented");
        break;
    }

    panda_arg_list *args = panda_get_args("file_taint");
    target_file =
        panda_parse_string_req(args, "filename", "Name of the file to taint.");
    label = panda_parse_uint32_opt(args, "label", 0x8BADF00D,
                                   "the label to apply to the read buffer");
    positional_labels = panda_parse_bool_opt(args, "positional_labels",
                                             "enables positional labels");
    if (positional_labels) {
        label = 0;
    }

    return true;
}

void uninit_plugin(void *self) { }
