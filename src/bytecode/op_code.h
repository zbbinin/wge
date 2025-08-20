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

namespace Wge {
namespace Bytecode {

/**
 * Bytecode operation codes for register-based rule evaluation
 * The bytecode provides a linear execution model that's more cache-friendly
 * and suitable for future JIT compilation
 */
enum class OpCode {
  // Set immediate value to destination register
  // Syntax: MOV dst_register, immediate_value
  // Example: MOV EAX, 123456
  MOV,
  // Unconditional jump
  // Syntax: JMP target_address
  // Example: JMP 123
  JMP,
  // If the front value of the RFLAGS register is zero, jump to the target address
  // Syntax: JZ target_address
  // Example: JZ 123
  JZ,
  // If the front value of the RFLAGS register is non-zero, jump to the target address
  // Syntax: JNZ target_address
  // Example: JNZ 123
  JNZ,
  // No operation
  // Syntax: NOP
  // Example: NOP
  NOP,
  // Load variable value
  // Syntax: LOAD_VAR dst_register, variable_index, variable_instance_pointer
  // Example: LOAD_VAR RDI, 1, 123456
  LOAD_VAR,
};
} // namespace Bytecode
} // namespace Wge