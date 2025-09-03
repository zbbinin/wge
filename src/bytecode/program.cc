#include "program.h"

#include "../common/log.h"

namespace Wge {
namespace Bytecode {
void Program::emit(const Instruction& instruction) {
  instructions_.emplace_back(instruction);
  WGE_LOG_TRACE("emit instruction: {}", instruction.toString());
}

void Program::relocate(size_t index, GeneralRegisterValue new_address) {
  if (index < instructions_.size()) {
    auto& instruction = instructions_[index];
    if (instruction.op_code_ != OpCode::JMP && instruction.op_code_ != OpCode::JZ &&
        instruction.op_code_ != OpCode::JNZ) {
      WGE_LOG_ERROR(
          "relocate jump address error: instruction at index {} is not a jump instruction", index);
      return;
    }

    instruction.op1_.address_ = new_address;
  }
}
} // namespace Bytecode
} // namespace Wge