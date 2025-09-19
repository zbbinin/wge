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

#include <array>

#include "../common/evaluate_result.h"

namespace Wge {
namespace Bytecode {
/**
 * General purpose registers (64-bit equivalents)
 * x86-64 style register enumeration for the virtual machine
 * Using standard register names for better assembly-like syntax
 */
enum class GeneralRegister : uint64_t {
  RAX = 0, // Accumulator register
  RBX,     // Base register
  RCX,     // Counter register
  RDX,     // Data register
  RFLAGS,  // Flags register (for condition codes)

  MAX_GENERAL_REGISTER
};
using GeneralRegisterValue = int64_t;

/**
 * Extra registers R8-R23 (Common::EvaluateResults equivalents)
 * x86-64 style register enumeration for the virtual machine
 * Using standard register names for better assembly-like syntax
 */
enum class ExtendedRegister : uint64_t {
  R8 = 0,
  R9,
  R10,
  R11,

  MAX_EXTENDED_REGISTER
};
using ExtendedRegisterValue = Common::EvaluateResults;

template <class EnumType, class ValueType, std::size_t size>
class RegisterArray : public std::array<ValueType, size> {
public:
  ValueType& operator[](EnumType reg) {
    return std::array<ValueType, size>::operator[](static_cast<size_t>(reg));
  }
  const ValueType& operator[](EnumType reg) const {
    return std::array<ValueType, size>::operator[](static_cast<size_t>(reg));
  }
};

using GeneralRegisterArray =
    RegisterArray<GeneralRegister, GeneralRegisterValue,
                  static_cast<size_t>(GeneralRegister::MAX_GENERAL_REGISTER)>;

using ExtendedRegisterArray =
    RegisterArray<ExtendedRegister, ExtendedRegisterValue,
                  static_cast<size_t>(ExtendedRegister::MAX_EXTENDED_REGISTER)>;

} // namespace Bytecode
} // namespace Wge