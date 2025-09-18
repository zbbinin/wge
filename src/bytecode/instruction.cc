#include "instruction.h"

#include <format>
#include <functional>
#include <unordered_map>

#include "compiler/variable_travel_helper.h"

#include "../action/action_base.h"
#include "../macro/macro_base.h"
#include "../operator/operator_base.h"
#include "../transformation/transform_base.h"
#include "../variable/variable_base.h"

namespace Wge {
namespace Bytecode {
std::string Instruction::toString() const {
  static const std::unordered_map<GeneralRegister, std::string> GeneralRegister2String = {
      {GeneralRegister::RAX, "RAX"},
      {GeneralRegister::RBX, "RBX"},
      {GeneralRegister::RCX, "RCX"},
      {GeneralRegister::RDX, "RDX"}};
  static const std::unordered_map<ExtendedRegister, std::string> ExtendedRegister2String = {
      {ExtendedRegister::R8, "R8"},
      {ExtendedRegister::R9, "R9"},
      {ExtendedRegister::R10, "R10"},
      {ExtendedRegister::R11, "R11"}};

  static auto loadVariable2String = [](const Instruction& instruction, const std::string& op_name) {
    std::string var_name = reinterpret_cast<const Variable::VariableBase*>(instruction.op3_.cptr_)
                               ->fullName()
                               .tostring();
    return std::format("{} {}, {}, {}({})", op_name,
                       ExtendedRegister2String.at(instruction.op1_.x_reg_), instruction.op2_.index_,
                       instruction.op3_.cptr_, var_name);
  };
  static const std::unordered_map<OpCode, std::function<std::string(const Instruction&)>>
      to_string_map = {
          {OpCode::MOV,
           [](const Instruction& instruction) {
             return std::format("MOV {}, 0x{:x}",
                                GeneralRegister2String.at(instruction.op1_.g_reg_),
                                instruction.op2_.imm_);
           }},
          {OpCode::JMP,
           [](const Instruction& instruction) {
             return std::format("JMP 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::JZ,
           [](const Instruction& instruction) {
             return std::format("JZ 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::JNZ,
           [](const Instruction& instruction) {
             return std::format("JNZ 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::NOP, [](const Instruction&) { return "NOP"; }},
          {OpCode::DEBUG,
           [](const Instruction& instruction) {
             return std::format("DEBUG {}", reinterpret_cast<const char*>(instruction.op1_.cptr_));
           }},
          {OpCode::LOAD_VAR,
           [](const Instruction& instruction) {
             std::string var_name =
                 reinterpret_cast<const Variable::VariableBase*>(instruction.op3_.cptr_)
                     ->fullName()
                     .tostring();
             return std::format("LOAD_VAR {}, {}, {}({})",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                instruction.op2_.index_, instruction.op3_.cptr_, var_name);
           }},
          {OpCode::TRANSFORM,
           [](const Instruction& instruction) {
             std::string transform_name =
                 reinterpret_cast<const Transformation::TransformBase*>(instruction.op4_.cptr_)
                     ->name();
             return std::format("TRANSFORM {}, {}, {}, {}({})",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                ExtendedRegister2String.at(instruction.op2_.x_reg_),
                                instruction.op3_.index_, instruction.op4_.cptr_, transform_name);
           }},
          {OpCode::OPERATE,
           [](const Instruction& instruction) {
             std::string operator_name =
                 reinterpret_cast<const Operator::OperatorBase*>(instruction.op4_.cptr_)->name();
             return std::format("OPERATE {}, {}, {}, {}({})",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                ExtendedRegister2String.at(instruction.op2_.x_reg_),
                                instruction.op3_.index_, instruction.op4_.cptr_, operator_name);
           }},
          {OpCode::ACTION,
           [](const Instruction& instruction) {
             std::string action_names;
             const std::vector<Program::ActionInfo>& action_infos =
                 *reinterpret_cast<const std::vector<Program::ActionInfo>*>(instruction.op2_.cptr_);
             for (auto& action_info : action_infos) {
               if (!action_names.empty()) {
                 action_names += ", ";
               }
               action_names +=
                   reinterpret_cast<const Action::ActionBase*>(action_info.action_)->name();
             }

             return std::format("ACTION {}, {}({})",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                instruction.op2_.cptr_, action_names);
           }},
          {OpCode::UNC_ACTION,
           [](const Instruction& instruction) {
             std::string action_names;
             const std::vector<Program::ActionInfo>& action_infos =
                 *reinterpret_cast<const std::vector<Program::ActionInfo>*>(instruction.op1_.cptr_);
             for (auto& action_info : action_infos) {
               if (!action_names.empty()) {
                 action_names += ", ";
               }
               action_names +=
                   reinterpret_cast<const Action::ActionBase*>(action_info.action_)->name();
             }
             return std::format("UNC_ACTION {}({})", instruction.op1_.cptr_, action_names);
           }},
          {OpCode::EXPAND_MACRO,
           [](const Instruction& instruction) {
             std::string msg_macro_name =
                 instruction.op2_.cptr_
                     ? reinterpret_cast<const Macro::MacroBase*>(instruction.op2_.cptr_)->name()
                     : "nullptr";
             std::string log_macro_name =
                 instruction.op4_.cptr_
                     ? reinterpret_cast<const Macro::MacroBase*>(instruction.op4_.cptr_)->name()
                     : "nullptr";
             return std::format("EXPAND_MACRO {}, {}({}), {}, {}({})", instruction.op1_.index_,
                                instruction.op2_.cptr_, msg_macro_name, instruction.op3_.index_,
                                instruction.op4_.cptr_, log_macro_name);
           }},
#define TO_STRING(var_type)                                                                        \
  {OpCode::LOAD_##var_type##_CC,                                                                   \
   [](const Instruction& instruction) {                                                            \
     return loadVariable2String(instruction, "LOAD_" #var_type "_CC");                             \
   }},                                                                                             \
      {OpCode::LOAD_##var_type##_CS,                                                               \
       [](const Instruction& instruction) {                                                        \
         return loadVariable2String(instruction, "LOAD_" #var_type "_CS");                         \
       }},                                                                                         \
      {OpCode::LOAD_##var_type##_VC,                                                               \
       [](const Instruction& instruction) {                                                        \
         return loadVariable2String(instruction, "LOAD_" #var_type "_VC");                         \
       }},                                                                                         \
      {OpCode::LOAD_##var_type##_VR,                                                               \
       [](const Instruction& instruction) {                                                        \
         return loadVariable2String(instruction, "LOAD_" #var_type "_VR");                         \
       }},                                                                                         \
      {OpCode::LOAD_##var_type##_VS, [](const Instruction& instruction) {                          \
         return loadVariable2String(instruction, "LOAD_" #var_type "_VS");                         \
       }},
          TRAVEL_VARIABLES(TO_STRING)
#undef TO_STRING
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