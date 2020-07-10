/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <memory>
#include <string>

#include "panda/plugin.h"

// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "AlwaysTruePredicate.h"
#include "PcRangePredicate.h"
#include "CompoundPredicate.h"
#include "ProcessNamePredicate.h"
#include "UniqueAsidPredicate.h"
#include "UniqueOsiPredicate.h"

#include "CoverageMode.h"

#include "MonitorRequest.h"
#include "DisableMonitorRequest.h"
#include "EnableMonitorRequest.h"

const char *DEFAULT_FILE = "coverage.csv";

// commands that can be accessed through the QEMU monitor
const char *MONITOR_HELP = "help";
constexpr size_t MONITOR_HELP_LEN = 4;
const std::string MONITOR_ENABLE = "coverage_enable";
const std::string MONITOR_DISABLE = "coverage_disable";

using namespace coverage2;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

#include "tcg.h"
//extern TCGContext tcg_ctx;

}

static std::unique_ptr<MonitorRequest> monitor_request;
static std::unique_ptr<Predicate> predicate;
static std::unique_ptr<CoverageMode> mode;

static void log_message(const char *message1, const char *message2)
{

    printf("%s%s %s\n", PANDA_MSG, message1, message2);
}

//static void log_message(const char *message, uint32_t number)
//{
//    printf("%s%s %d\n", PANDA_MSG, message, number);
//}

static void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb)
{
    if (nullptr != monitor_request) {
        monitor_request->handle();
        monitor_request.reset();
    }

    if (!predicate->eval(cpu, tb)) {
        return;
    }

    if (nullptr != mode) {
        mode->process_block(cpu, tb);
    }
}

int monitor_callback(Monitor *mon, const char *cmd_cstr)
{
    panda_do_flush_tb();

    std::string cmd = cmd_cstr;
    auto index = cmd.find("=");
    std::string filename = DEFAULT_FILE;
    if (std::string::npos != index) {
        filename = cmd.substr(index+1);
    }
    if (0 == cmd.find(MONITOR_DISABLE)) {
        monitor_request.reset(new DisableMonitorRequest(mode));
    } else if (0 == cmd.find(MONITOR_ENABLE)) {
        monitor_request.reset(new EnableMonitorRequest(mode, filename));
    }
    return 0;
}


bool init_plugin(void *self)
{
    predicate = std::unique_ptr<Predicate>(new AlwaysTruePredicate);

    panda_arg_list *args = panda_get_args("coverage2");
    std::string pc_arg = panda_parse_string_opt(args, "pc", "",
                                                "program counter range");
    if ("" != pc_arg) {
        auto dash_idx = pc_arg.find("-");
        auto start_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(0, dash_idx), NULL, 0));
        auto end_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(dash_idx + 1), NULL, 0));
        std::unique_ptr<Predicate> pcrp(new PcRangePredicate(start_pc, end_pc));
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(pcrp)));
    }

    std::string process_name = panda_parse_string_opt(args, "process_name", "", "the process to collect coverage from");
    if ("" != process_name) {
        std::unique_ptr<Predicate> pnpred(new ProcessNamePredicate(process_name));
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(pnpred)));
    }

    std::string unique = panda_parse_string_opt(args, "unique", "", "only output unique blocks (asid or osi)");
    if ("asid" == unique) {
        std::unique_ptr<Predicate> uapred(new UniqueAsidPredicate);
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(uapred)));
    } else if ("osi" == unique) {
        std::unique_ptr<Predicate> uosipred(new UniqueOsiPredicate);
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(uosipred)));
    }

    panda_cb pcb;

    pcb.before_tcg_codegen = before_tcg_codegen;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, pcb);

    bool start_disabled = panda_parse_bool_opt(args, "start_disabled",
            "start the plugin with instrumentation disabled");
    log_message("start disabled", PANDA_FLAG_STATUS(start_disabled));

    bool all_ok = true;
    if (!start_disabled)
    {
        monitor_request.reset(new EnableMonitorRequest(mode, DEFAULT_FILE));
    }

    if (all_ok)
    {
        pcb.monitor = monitor_callback;
        panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    }

    return all_ok;
}

void uninit_plugin(void *self)
{
    if (nullptr != mode) {
        mode->process_results();
        mode.reset();
    }
}
