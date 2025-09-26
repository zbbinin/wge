#include "instruction.h"

#include <format>
#include <functional>
#include <unordered_map>

#include "compiler/action_travel_helper.h"
#include "compiler/transform_travel_helper.h"
#include "compiler/variable_travel_helper.h"

#include "../action/action_base.h"
#include "../macro/macro_base.h"
#include "../operator/operator_base.h"
#include "../rule.h"
#include "../transformation/transform_base.h"
#include "../variable/variable_base.h"

#define LOAD_VAR_TO_STRING(var_type)                                                               \
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

#define TRANSFORM_TO_STRING(transform_type)                                                        \
  {OpCode::TRANSFORM_##transform_type, [](const Instruction& instruction) {                        \
     std::string op_name = "TRANSFORM_" #transform_type;                                           \
     std::string transform_name =                                                                  \
         reinterpret_cast<const Transformation::TransformBase*>(instruction.op3_.cptr_)->name();   \
     return std::format("{} {}, {}, {}({})", op_name,                                              \
                        ExtendedRegister2String.at(instruction.op1_.x_reg_),                       \
                        ExtendedRegister2String.at(instruction.op2_.x_reg_),                       \
                        instruction.op3_.cptr_, transform_name);                                   \
   }},

#define OPERATOR_TO_STRING(operator_type)                                                          \
  {OpCode::OPERATOR_##operator_type, [](const Instruction& instruction) {                          \
     std::string op_name = "OPERATOR_" #operator_type;                                             \
     std::string operator_name =                                                                   \
         reinterpret_cast<const Operator::OperatorBase*>(instruction.op3_.cptr_)->name();          \
     return std::format("{} {}, {}, {}({})", op_name,                                              \
                        ExtendedRegister2String.at(instruction.op1_.x_reg_),                       \
                        ExtendedRegister2String.at(instruction.op2_.x_reg_),                       \
                        instruction.op3_.cptr_, operator_name);                                    \
   }},

#define ACTION_TO_STRING(action_type)                                                              \
  {OpCode::ACTION_##action_type, [](const Instruction& instruction) {                              \
     std::string op_name = "ACTION_" #action_type;                                                 \
     std::string action_name =                                                                     \
         reinterpret_cast<const Action::ActionBase*>(instruction.op2_.cptr_)->name();              \
     return std::format("{} {}, {}({})", op_name,                                                  \
                        ExtendedRegister2String.at(instruction.op1_.x_reg_),                       \
                        instruction.op2_.cptr_, action_name);                                      \
   }},

#define UNC_ACTION_TO_STRING(action_type)                                                          \
  {OpCode::UNC_ACTION_##action_type, [](const Instruction& instruction) {                          \
     std::string op_name = "UNC_ACTION_" #action_type;                                             \
     std::string action_name =                                                                     \
         reinterpret_cast<const Action::ActionBase*>(instruction.op1_.cptr_)->name();              \
     return std::format("{} {}({})", op_name, instruction.op1_.cptr_, action_name);                \
   }},

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
    std::string var_name = reinterpret_cast<const Variable::VariableBase*>(instruction.op2_.cptr_)
                               ->fullName()
                               .tostring();
    return std::format("{} {}, {}({})", op_name,
                       ExtendedRegister2String.at(instruction.op1_.x_reg_), instruction.op2_.cptr_,
                       var_name);
  };
  static const std::unordered_map<OpCode, std::function<std::string(const Instruction&)>>
      to_string_map = {
          {OpCode::MOV,
           [](const Instruction& instruction) {
             return std::format("MOV {}, 0x{:x}",
                                GeneralRegister2String.at(instruction.op1_.g_reg_),
                                instruction.op2_.imm_);
           }},
          {OpCode::ADD,
           [](const Instruction& instruction) {
             return std::format("ADD {}, 0x{:x}",
                                GeneralRegister2String.at(instruction.op1_.g_reg_),
                                instruction.op2_.imm_);
           }},
          {OpCode::CMP,
           [](const Instruction& instruction) {
             return std::format("CMP {}, {}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                                GeneralRegister2String.at(instruction.op2_.g_reg_));
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
          {OpCode::JOM,
           [](const Instruction& instruction) {
             return std::format("JOM 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::JNOM,
           [](const Instruction& instruction) {
             return std::format("JNOM 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::JRM,
           [](const Instruction& instruction) {
             return std::format("JRM 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::JNRM,
           [](const Instruction& instruction) {
             return std::format("JNRM 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::NOP, [](const Instruction&) { return "NOP"; }},
          {OpCode::DEBUG,
           [](const Instruction& instruction) {
             return std::format("DEBUG {}", reinterpret_cast<const char*>(instruction.op1_.cptr_));
           }},
          {OpCode::RULE_START,
           [](const Instruction& instruction) {
             const Rule* rule = reinterpret_cast<const Rule*>(instruction.op1_.cptr_);
             return std::format("RULE_START {}(id:{} [{}:{}])", instruction.op1_.cptr_, rule->id(),
                                rule->filePath(), rule->line());
           }},
          {OpCode::JMP_IF_REMOVED,
           [](const Instruction& instruction) {
             return std::format("JMP_IF_REMOVED 0x{:x}", instruction.op1_.address_);
           }},
          {OpCode::SIZE,
           [](const Instruction& instruction) {
             return std::format("SIZE {}, {}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                                ExtendedRegister2String.at(instruction.op2_.x_reg_));
           }},
          {OpCode::PUSH_MATCHED,
           [](const Instruction& instruction) {
             return std::format("PUSH_MATCHED {}, {}, {}",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                ExtendedRegister2String.at(instruction.op2_.x_reg_),
                                GeneralRegister2String.at(instruction.op3_.g_reg_));
           }},
          {OpCode::PUSH_ALL_MATCHED,
           [](const Instruction& instruction) {
             return std::format("PUSH_ALL_MATCHED {}, {}",
                                ExtendedRegister2String.at(instruction.op1_.x_reg_),
                                ExtendedRegister2String.at(instruction.op2_.x_reg_));
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
          {OpCode::CHAIN_START,
           [](const Instruction& instruction) {
             return std::format("CHAIN_START {}", instruction.op1_.cptr_);
           }},
          {OpCode::CHAIN_END,
           [](const Instruction& instruction) {
             return std::format("CHAIN_END {}", instruction.op1_.cptr_);
           }},
          {OpCode::LOG_CALLBACK,
           [](const Instruction& instruction) { return std::format("LOG_CALLBACK"); }},
          {OpCode::EXIT_IF_DISRUPTIVE,
           [](const Instruction& instruction) { return std::format("EXIT_IF_DISRUPTIVE"); }},
          // clang-format off
          TRAVEL_VARIABLES(LOAD_VAR_TO_STRING)
          TRAVEL_TRANSFORMATIONS(TRANSFORM_TO_STRING)
          TRAVEL_OPERATORS(OPERATOR_TO_STRING)
          TRAVEL_ACTIONS(ACTION_TO_STRING)
          TRAVEL_ACTIONS(UNC_ACTION_TO_STRING)
          // clang-format on
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