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

#include "compiler/variable_travel_helper.h"
#include "program.h"
#include "register.h"

namespace Wge {
class Transaction;
}

namespace Wge {
namespace Bytecode {
/**
 * Bytecode Virtual Machine
 * Executes compiled bytecode programs for rule evaluation
 */
class VirtualMachine {
public:
  VirtualMachine(Transaction& transaction) : transaction_(transaction) {}

public:
  /**
   * Execute a bytecode program
   * @param program The compiled bytecode program
   * @return true if associated rule matched, false otherwise
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

private:
  inline void execMov(const Instruction& instruction);
  inline void execJmp(const Instruction& instruction,
                      const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                      std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);
  inline void execJz(const Instruction& instruction,
                     const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                     std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);
  inline void execJnz(const Instruction& instruction,
                      const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                      std::vector<Wge::Bytecode::Instruction>::const_iterator& iter);
  inline void execDebug(const Instruction& instruction);
  inline void execLoadVar(const Instruction& instruction);
  inline void execTransform(const Instruction& instruction);
  inline void execOperate(const Instruction& instruction);
  inline void execAction(const Instruction& instruction);
  inline void execUncAction(const Instruction& instruction);
  inline void execExpandMacro(const Instruction& instruction);
  inline void execMsgExpandMacro(const Instruction& instruction);
  inline void execLogDataExpandMacro(const Instruction& instruction);
  inline void execChain(const Instruction& instruction);

  // Load variable handlers
private:
#define DECLARE_LOAD_VAR_PROC(var_tyep)                                                            \
  inline void execLoad##var_tyep##_CC(const Instruction& instruction);                             \
  inline void execLoad##var_tyep##_CS(const Instruction& instruction);                             \
  inline void execLoad##var_tyep##_VC(const Instruction& instruction);                             \
  inline void execLoad##var_tyep##_VR(const Instruction& instruction);                             \
  inline void execLoad##var_tyep##_VS(const Instruction& instruction);

  TRAVEL_VARIABLES(DECLARE_LOAD_VAR_PROC)
#undef DECLARE_LOAD_VAR_PROC
private:
  // Registers
  GeneralRegisterArray general_registers_{};
  ExtendedRegisterArray extended_registers_{};

  Transaction& transaction_;
};
} // namespace Bytecode
} // namespace Wge