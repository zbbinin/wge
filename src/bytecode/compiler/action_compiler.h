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

#include <memory>
#include <optional>
#include <unordered_map>

#include <stdint.h>

#include "../op_code.h"
#include "../register.h"

namespace Wge {
namespace Action {
class ActionBase;
}
} // namespace Wge

namespace Wge {
namespace Bytecode {
class CompilerTest;
class VirtualMachineTest;
class Program;
namespace Compiler {
class ActionCompiler {
  friend class Wge::Bytecode::CompilerTest;
  friend class Wge::Bytecode::VirtualMachineTest;

public:
  static void compileAction(const Action::ActionBase* action, ExtendedRegister op_res_reg,
                            Program& program);
  static void compileUncAction(const Action::ActionBase* action, Program& program);

private:
  inline static std::optional<OpCode> calcOpCode(const Action::ActionBase* action,
                                                 OpCode base_opcode);

private:
  static const std::unordered_map<const char*, OpCode> action_opcode_map_;
  static const std::unordered_map<const char*, OpCode> unc_action_opcode_map_;
};

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge