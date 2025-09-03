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
#include <unordered_map>
#include <vector>

#include "program.h"

namespace Wge {
class Rule;
namespace Variable {
class VariableBase;
}
namespace Transformation {
class TransformBase;
}
namespace Operator {
class OperatorBase;
}
namespace Action {
class ActionBase;
}
} // namespace Wge

namespace Wge {
namespace Bytecode {
class Compiler {
public:
  /**
   * Compile multiple rules into a program
   * @param rules The rules to compile
   * @param default_action The default action for the program
   * @return Compiled bytecode program
   */
  std::unique_ptr<Program> compile(const std::vector<const Rule*>& rules,
                                   const Rule* default_action);

public:
  // The current rule register
  static constexpr GeneralRegister curr_rule_reg_{GeneralRegister::RCX};
  // The current variable register
  static constexpr GeneralRegister curr_variable_reg_{GeneralRegister::RDX};
  // The result register of LOAD_VAR instruction (variable value)
  static constexpr ExtraRegister load_var_reg_{ExtraRegister::R16};
  // The result register of OPERATE instruction (capture string)
  static constexpr ExtraRegister op_res_reg_{ExtraRegister::R19};
  // Register index that points to the storage transformed value for OPERATE instruction
  static constexpr GeneralRegister op_src_reg_{GeneralRegister::RBX};

private:
  void compileRule(const Rule* rule, const Rule* default_action, Program& program);
};
} // namespace Bytecode
} // namespace Wge