#include "instruction.h"

#include <format>
#include <functional>
#include <unordered_map>

#include "../variable/variable_base.h"

namespace Wge {
namespace Bytecode {
std::string Instruction::toString() const {
  static const std::unordered_map<Register, std::string> registerToString = {
      {Register::RAX, "RAX"}, {Register::RBX, "RBX"},      {Register::RCX, "RCX"},
      {Register::RDX, "RDX"}, {Register::RSI, "RSI"},      {Register::RDI, "RDI"},
      {Register::RBP, "RBP"}, {Register::RSP, "RSP"},      {Register::R8, "R8"},
      {Register::R9, "R9"},   {Register::R10, "R10"},      {Register::R11, "R11"},
      {Register::R12, "R12"}, {Register::R13, "R13"},      {Register::R14, "R14"},
      {Register::R15, "R15"}, {Register::RFLAGS, "RFLAGS"}};

  static const std::unordered_map<OpCode, std::function<std::string(const Instruction&)>>
      to_string_map = {
          {OpCode::MOV,
           [](const Instruction& instruction) {
             return std::format("MOV {}, {}", registerToString.at(instruction.op1_.reg_),
                                instruction.op2_.imm_);
           }},
          {OpCode::JMP,
           [](const Instruction& instruction) {
             return std::format("JMP {}", instruction.op1_.address_);
           }},
          {OpCode::JZ,
           [](const Instruction& instruction) {
             return std::format("JZ {}", instruction.op1_.address_);
           }},
          {OpCode::JNZ,
           [](const Instruction& instruction) {
             return std::format("JNZ {}", instruction.op1_.address_);
           }},
          {OpCode::NOP, [](const Instruction&) { return "NOP"; }},
          {OpCode::LOAD_VAR,
           [](const Instruction& instruction) {
             std::string var_name =
                 reinterpret_cast<const Variable::VariableBase*>(instruction.op3_.ptr_)
                     ->fullName()
                     .tostring();
             return std::format("LOAD_VAR {}, {}, {}", registerToString.at(instruction.op1_.reg_),
                                instruction.op2_.index_, var_name);
           }},
      };

  std::string result;
  auto iter = to_string_map.find(op_code_);
  if (iter == to_string_map.end()) {
    assert(false);
    result = "UNKNOWN";
  }

  result = iter->second(*this);
  return result;
}
} // namespace Bytecode
} // namespace Wge