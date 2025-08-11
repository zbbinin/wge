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

#include <vector>

#include "instruction.h"

namespace Wge {
namespace Bytecode {
/**
 * Bytecode program represents a compiled rule or set of rules
 */
class Program {
public:
  Program() {
    // Preallocate space for instructions
    instructions_.reserve(1024);
  }

public:
  // Add instruction to the program
  void emit(const Instruction& instruction);
  void emit(OpCode opcode);
  void emit(OpCode opcode, Register operand1);
  void emit(OpCode opcode, Register operand1, Register operand2);
  void emit(OpCode opcode, Register operand1, Register operand2, Register operand3);

  /**
   * Get the list of instructions in the program
   * @return vector of instructions
   */
  const std::vector<Instruction>& instructions() const { return instructions_; }

private:
  std::vector<Instruction> instructions_;
};
} // namespace Bytecode
} // namespace Wge