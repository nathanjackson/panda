#include "AsidBlockCoverageMode.h"

namespace coverage2
{

AsidBlockCoverageMode::AsidBlockCoverageMode(const std::string &filename)
        : output_stream(filename)
{
    output_stream << "asid\n";
    output_stream << "asid,in kernel,block address,block size\n";
}

void AsidBlockCoverageMode::process_block(CPUState *cpu, TranslationBlock *tb)
{
    output_stream << "0x" << std::hex << panda_current_asid(cpu) << ",";
    output_stream << std::dec << panda_in_kernel(cpu) << ",";
    output_stream << "0x" << std::hex << tb->pc << ",";
    output_stream << std::dec << tb->size << "\n";
}


void AsidBlockCoverageMode::process_results()
{
}

}
