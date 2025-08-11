#include "program.h"

namespace Wge {
namespace Bytecode {
void Program::emit(const Instruction& instruction) {}

void Program::emit(OpCode opcode) {}

void Program::emit(OpCode opcode, Register operand1) {}

void Program::emit(OpCode opcode, Register operand1, Register operand2) {}

void Program::emit(OpCode opcode, Register operand1, Register operand2, Register operand3) {}
} // namespace Bytecode
} // namespace Wge