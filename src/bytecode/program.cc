#include "program.h"

#include "../common/log.h"

namespace Wge {
namespace Bytecode {
void Program::emit(const Instruction& instruction) {
  instructions_.emplace_back(instruction);
  WGE_LOG_TRACE("emit instruction: {}", instruction.toString());
}
} // namespace Bytecode
} // namespace Wge