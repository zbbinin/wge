#include "instruction.h"

#include <unordered_map>

namespace Wge {
namespace Bytecode {
std::string Instruction::toString() const {
  static std::unordered_map<OpCode, std::string> opCodeToString = {
      {OpCode::LOAD_VAR, "LOAD_VAR"},
  };

  static std::unordered_map<Register, std::string> registerToString = {
      {Register::RAX, "RAX"}, {Register::RBX, "RBX"}, {Register::RCX, "RCX"},
      {Register::RDX, "RDX"}, {Register::RSI, "RSI"}, {Register::RDI, "RDI"},
      {Register::RBP, "RBP"}, {Register::RSP, "RSP"}, {Register::R8, "R8"},
      {Register::R9, "R9"},   {Register::R10, "R10"}, {Register::R11, "R11"},
      {Register::R12, "R12"}, {Register::R13, "R13"}, {Register::R14, "R14"},
      {Register::R15, "R15"}};

  std::string str;
  str += opCodeToString[op_code_];
  if (dst_ != Register::UNKNOWN) {
    str += " " + registerToString[dst_];
  }
  if (src_ != Register::UNKNOWN) {
    str += " " + registerToString[src_];
  }
  if (aux_ != Register::UNKNOWN) {
    str += " " + registerToString[aux_];
  }

  return str;
}
} // namespace Bytecode
} // namespace Wge