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
   */
  void execute(const Program& program);

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
   * Get the current state of the flags register
   * @return reference to the flags register value
   */
  int64_t& rflags() { return rflags_; }

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
  inline void execLoadVar(const Instruction& instruction);
  inline void execTransform(const Instruction& instruction);
  inline void execOperate(const Instruction& instruction);
  inline void execAction(const Instruction& instruction);
  inline void execUncAction(const Instruction& instruction);
  inline void execExpandMacro(const Instruction& instruction);
  inline void execMsgExpandMacro(const Instruction& instruction);
  inline void execLogDataExpandMacro(const Instruction& instruction);

private:
  // Registers
  GeneralRegisterArray general_registers_{};
  ExtendedRegisterArray extended_registers_{};

  // Simple flag register for conditions
  int64_t rflags_ = 0;

  Transaction& transaction_;
};
} // namespace Bytecode
} // namespace Wge