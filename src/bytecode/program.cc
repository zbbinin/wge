#include "program.h"

#include "../common/log.h"

namespace Wge {
namespace Bytecode {
void Program::emit(const Instruction& instruction) {
  instructions_.emplace_back(instruction);
  WGE_LOG_TRACE("emit[0x{:x}]: {}", instructions_.size() - 1, instruction.toString());
}

void Program::relocate(size_t index, GeneralRegisterValue new_address) {
  if (index < instructions_.size()) {
    auto& instruction = instructions_[index];
    if (instruction.op_code_ != OpCode::JMP && instruction.op_code_ != OpCode::JZ &&
        instruction.op_code_ != OpCode::JNZ && instruction.op_code_ != OpCode::JOM &&
        instruction.op_code_ != OpCode::JNOM && instruction.op_code_ != OpCode::JMP_IF_REMOVED) {
      WGE_LOG_ERROR(
          "relocate jump address error: instruction at index 0x{:x} is not a jump instruction",
          index);
      return;
    }

    instruction.op1_.address_ = new_address;
    WGE_LOG_TRACE("relocate: 0x{:x}, 0x{:x}", index, new_address);
  }
}

} // namespace Bytecode
} // namespace Wge