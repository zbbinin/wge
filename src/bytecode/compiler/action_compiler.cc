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
#include "action_compiler.h"

#include "action_travel_helper.h"

#include "../../action/actions_include.h"
#include "../../common/log.h"
#include "../program.h"

#define ACTION_OPCODE(action_type)                                                                 \
  {Action::action_type::name_, Wge::Bytecode::OpCode::ACTION_##action_type},

#define UNC_ACTION_OPCODE(action_type)                                                             \
  {Action::action_type::name_, Wge::Bytecode::OpCode::UNC_ACTION_##action_type},

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, OpCode> ActionCompiler::action_opcode_map_ = {
    TRAVEL_ACTIONS(ACTION_OPCODE)};
const std::unordered_map<const char*, OpCode> ActionCompiler::unc_action_opcode_map_ = {
    TRAVEL_ACTIONS(UNC_ACTION_OPCODE)};

void ActionCompiler::compileAction(const Action::ActionBase* action, ExtendedRegister op_res_reg,
                                   Program& program) {
  auto iter = action_opcode_map_.find(action->name());
  assert(iter != action_opcode_map_.end());
  if (iter == action_opcode_map_.end()) {
    UNREACHABLE();
    WGE_LOG_CRITICAL("action compile error: unknown action {}", action->name());
    return;
  }

  program.emit({iter->second, {.x_reg_ = op_res_reg}, {.cptr_ = action}});
}

void ActionCompiler::compileUncAction(const Action::ActionBase* action, Program& program) {
  auto iter = unc_action_opcode_map_.find(action->name());
  assert(iter != unc_action_opcode_map_.end());
  if (iter == unc_action_opcode_map_.end()) {
    UNREACHABLE();
    WGE_LOG_CRITICAL("unc action compile error: unknown action {}", action->name());
    return;
  }
  program.emit({iter->second, {.cptr_ = action}});
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef ACTION_INDEX