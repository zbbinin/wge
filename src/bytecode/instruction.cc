#include "instruction.h"

#include <format>
#include <functional>
#include <unordered_map>

#include "../action/action_base.h"
#include "../operator/operator_base.h"
#include "../transformation/transform_base.h"
#include "../variable/variable_base.h"

namespace Wge {
namespace Bytecode {
std::string Instruction::toString() const {
  static const std::unordered_map<GeneralRegister, std::string> GeneralRegister2String = {
      {GeneralRegister::RAX, "RAX"}, {GeneralRegister::RBX, "RBX"}, {GeneralRegister::RCX, "RCX"},
      {GeneralRegister::RDX, "RDX"}, {GeneralRegister::RSI, "RSI"}, {GeneralRegister::RDI, "RDI"},
      {GeneralRegister::RBP, "RBP"}, {GeneralRegister::RSP, "RSP"}};
  static const std::unordered_map<ExtendedRegister, std::string> ExtendedRegister2String = {
      {ExtendedRegister::R8, "R8"},   {ExtendedRegister::R9, "R9"},
      {ExtendedRegister::R10, "R10"}, {ExtendedRegister::R11, "R11"},
      {ExtendedRegister::R12, "R12"}, {ExtendedRegister::R13, "R13"},
      {ExtendedRegister::R14, "R14"}, {ExtendedRegister::R15, "R15"}};
  static const std::unordered_map<ExtraRegister, std::string> ExtraRegister2String = {
      {ExtraRegister::R16, "R16"}, {ExtraRegister::R17, "R17"}, {ExtraRegister::R18, "R18"},
      {ExtraRegister::R19, "R19"}, {ExtraRegister::R20, "R20"}, {ExtraRegister::R21, "R21"},
      {ExtraRegister::R22, "R22"}, {ExtraRegister::R23, "R23"}};

  static const std::unordered_map<OpCode, std::function<std::string(const Instruction&)>>
      to_string_map = {
          {OpCode::MOV,
           [](const Instruction& instruction) {
             return std::format("MOV {}, {}", GeneralRegister2String.at(instruction.op1_.g_reg_),
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
             return std::format("LOAD_VAR {}, {}, {}",
                                ExtraRegister2String.at(instruction.op1_.ex_reg_),
                                instruction.op2_.index_, var_name);
           }},
          {OpCode::TRANSFORM,
           [](const Instruction& instruction) {
             std::string transform_name =
                 reinterpret_cast<const Transformation::TransformBase*>(instruction.op4_.ptr_)
                     ->name();
             return std::format("TRANSFORM {}, {}, {}, {}",
                                ExtraRegister2String.at(instruction.op1_.ex_reg_),
                                ExtraRegister2String.at(instruction.op2_.ex_reg_),
                                instruction.op3_.index_, transform_name);
           }},
          {OpCode::OPERATE,
           [](const Instruction& instruction) {
             std::string operator_name =
                 reinterpret_cast<const Operator::OperatorBase*>(instruction.op4_.ptr_)->name();
             return std::format("OPERATE {}, {}, {}, {}",
                                ExtraRegister2String.at(instruction.op1_.ex_reg_),
                                ExtraRegister2String.at(instruction.op2_.ex_reg_),
                                instruction.op3_.index_, operator_name);
           }},
          {OpCode::ACTION,
           [](const Instruction& instruction) {
             std::string action_name =
                 reinterpret_cast<const Action::ActionBase*>(instruction.op3_.ptr_)->name();
             return std::format("ACTION {}, {}, {}",
                                ExtraRegister2String.at(instruction.op1_.ex_reg_),
                                instruction.op2_.index_, action_name);
           }},
          {OpCode::UNC_ACTION,
           [](const Instruction& instruction) {
             std::string action_name =
                 reinterpret_cast<const Action::ActionBase*>(instruction.op2_.ptr_)->name();
             return std::format("UNC_ACTION {}, {}", instruction.op2_.index_, action_name);
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