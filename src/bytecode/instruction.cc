/**
 * Copyright (c) 2024-2025 Stone Rhino and contributors.
 *
 * MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
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

  // If we write a lot of lambdas here directly, IntelliSense of VSCode will slow down a lot. So we
  // put it in a separate file. This is a reluctant move.
#include "instruction.inl"

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