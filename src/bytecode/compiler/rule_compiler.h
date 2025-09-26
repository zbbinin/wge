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
#include <variant>
#include <vector>

#include "../../config.h"
#include "../program.h"

namespace Wge {
class Engine;
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
namespace Compiler {

class RuleCompiler {
public:
  /**
   * Compile rule into a program
   * @param rule The rule to compile
   * @param default_action_rule The default action rule for the program
   * @param engine The wge engine
   * @return Compiled bytecode program
   */
  static std::unique_ptr<Program> compile(const Rule* rule, const Rule* default_action_rule,
                                          const Engine* engine);

  /**
   * Compile a list of rules into a program
   * @param rules The list of rules to compile
   * @param default_action_rule The default action rule for the program
   * @param engine The wge engine
   * @return Compiled bytecode program
   */
  static std::unique_ptr<Program> compile(const std::vector<const Rule*>& rules,
                                          const Rule* default_action_rule, const Engine* engine);

private:
  struct SkipInfo {
    using Skip = int;
    using SkipAfter = std::string;
    std::variant<Skip, SkipAfter> target_;
    size_t jom_index_;
  };

private:
  static void compileRule(const Rule* rule, const Rule* default_action, const Engine* engine,
                          Program& program, std::vector<SkipInfo>* skip_info_array = nullptr);
  static void updateSkipInfo(Program& program, std::vector<SkipInfo>& skip_info_array,
                             const Rule* rule,const Engine* engine);

public:
  // The loop count
  static constexpr GeneralRegister loop_count_{GeneralRegister::RAX};
  // The loop cursor
  static constexpr GeneralRegister loop_cursor_{GeneralRegister::RCX};
  // The current variable register
  static constexpr GeneralRegister curr_variable_reg_{GeneralRegister::RDX};
  // The result register of LOAD_VAR instruction (variable value)
  static constexpr ExtendedRegister load_var_reg_{ExtendedRegister::R8};
  // The result register of OPERATE instruction (capture string)
  static constexpr ExtendedRegister op_res_reg_{ExtendedRegister::R11};
  // Temporary register for transformation
  static constexpr ExtendedRegister transform_tmp_reg1_{ExtendedRegister::R9};
  static constexpr ExtendedRegister transform_tmp_reg2_{ExtendedRegister::R10};
};

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge