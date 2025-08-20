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

#include "../common/evaluate_result.h"

namespace Wge {
namespace Bytecode {
using RegisterValue = Common::EvaluateResults;

/**
 * x86-64 style register enumeration for the virtual machine
 * Using standard register names for better assembly-like syntax
 */
enum class Register : int64_t {
  // General purpose registers (64-bit equivalents)
  RAX = 0, // Accumulator register
  RBX = 1, // Base register
  RCX = 2, // Counter register
  RDX = 3, // Data register
  RSI = 4, // Source index register
  RDI = 5, // Destination index register
  RBP = 6, // Base pointer register
  RSP = 7, // Stack pointer register

  // Extended registers R8-R15
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,

  // Flag register
  RFLAGS, // Flags register

  MAX_REGISTER,
  UNKNOWN = MAX_REGISTER
}; // namespace Bytecode
} // namespace Bytecode
} // namespace Wge