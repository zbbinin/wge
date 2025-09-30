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
#pragma once

#include <bitset>

#include "compiler/action_travel_helper.h"
#include "compiler/operator_travel_helper.h"
#include "compiler/transform_travel_helper.h"
#include "compiler/variable_travel_helper.h"
#include "program.h"
#include "register.h"

namespace Wge {
class Transaction;
namespace Jit {
namespace Compiler {
class VariableCompiler;
}
} // namespace Jit
} // namespace Wge

namespace Wge {
namespace Bytecode {
/**
 * Bytecode Virtual Machine
 * Executes compiled bytecode programs for rule evaluation
 */
class VirtualMachine {
  friend class Wge::Jit::Compiler::VariableCompiler;

public:
  VirtualMachine(Transaction& transaction) : transaction_(transaction) {}

public:
  enum class Rflags : uint8_t {
    // Zero Flag: Set if the result of OpCode::CMP is zero
    ZF = 0,
    // Operator Matched Flag: Set if the last OPERATE instruction matched
    OMF = 1,
    // Rule Matched Flag: Set if the rule matched
    RMF = 2,
  };

public:
  /**
   * Execute a bytecode program
   * @param program The compiled bytecode program
   * @return true if the request is safe, false otherwise that means need to deny the request.
   */
  bool execute(const Program& program);

  // For testing purposes
public:
  /**
   * Get the current state of the general registers
   * @return reference to the array of register values
   */
  GeneralRegisterArray& generalRegisters() { return general_registers_; }

  /**
   * Get the current state of the extended registers
   * @return reference to the array of extended register values
   */
  ExtendedRegisterArray& extendedRegisters() { return extended_registers_; }

  /**
   * Get the current state of the RFLAGS register
   * @return reference to the bitset representing RFLAGS
   */
  std::bitset<8>& rflags() { return rflags_; }

private:
  inline void execMov(const Instruction& instruction);
  inline void execAdd(const Instruction& instruction);
  inline void execCmp(const Instruction& instruction);
  inline void execJmp(const Instruction& instruction,
                      const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                      std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);
  inline void execJumpIfFlag(const Instruction& instruction,
                             const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                             std::vector<Wge::Bytecode::Instruction>::const_iterator& iter,
                             VirtualMachine::Rflags flag, bool is_set);
  inline void execDebug(const Instruction& instruction);
  inline void execRuleStart(const Instruction& instruction);
  inline void execJmpIfRemoved(const Instruction& instruction,
                               const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                               std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);
  inline void execTransformStart(const Instruction& instruction);
  inline void execSize(const Instruction& instruction);
  inline void execPushMatched(const Instruction& instruction);
  inline void execPushAllMatched(const Instruction& instruction);
  inline void execExpandMacro(const Instruction& instruction);
  inline void execMsgExpandMacro(const Instruction& instruction);
  inline void execLogDataExpandMacro(const Instruction& instruction);
  inline void execChainStart(const Instruction& instruction);
  inline void execChainEnd(const Instruction& instruction);
  inline void execLogCallback(const Instruction& instruction);
  inline void execExitIfDisruptive(const Instruction& instruction,
                                   const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                                   std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);

private:
  // Load variable handlers
#define DECLARE_LOAD_VAR_PROC(var_tyep)                                                            \
   void execLoad##var_tyep##_CC(const Instruction& instruction);                             \
   void execLoad##var_tyep##_CS(const Instruction& instruction);                             \
   void execLoad##var_tyep##_VC(const Instruction& instruction);                             \
   void execLoad##var_tyep##_VR(const Instruction& instruction);                             \
   void execLoad##var_tyep##_VS(const Instruction& instruction);

  TRAVEL_VARIABLES(DECLARE_LOAD_VAR_PROC)
#undef DECLARE_LOAD_VAR_PROC

// Transformation handlers
#define DECLARE_TRANSFORM_PROC(transform_type)                                                     \
  inline void execTransform##transform_type(const Instruction& instruction);
  TRAVEL_TRANSFORMATIONS(DECLARE_TRANSFORM_PROC)
#undef DECLARE_TRANSFORM_PROC

// Operator handlers
#define DECLARE_OPERATOR_PROC(operator_type)                                                       \
  inline void execOperator##operator_type(const Instruction& instruction);
  TRAVEL_OPERATORS(DECLARE_OPERATOR_PROC)
#undef DECLARE_OPERATOR_PROC

  // Action handlers
#define DECLARE_ACTION_PROC(action_type)                                                           \
  inline void execAction##action_type(const Instruction& instruction);
  TRAVEL_ACTIONS(DECLARE_ACTION_PROC)
#undef DECLARE_ACTION_PROC

  // Uncondition action handlers
#define DECLARE_UNC_ACTION_PROC(action_type)                                                       \
  inline void execUncAction##action_type(const Instruction& instruction);
  TRAVEL_ACTIONS(DECLARE_UNC_ACTION_PROC)
#undef DECLARE_UNC_ACTION_PROC

private:
  // Registers
  GeneralRegisterArray general_registers_{};
  ExtendedRegisterArray extended_registers_{};
  std::bitset<8> rflags_;

  Transaction& transaction_;
  bool disruptive_;
};
} // namespace Bytecode
} // namespace Wge