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

#include "../../action/actions_include.h"
#include "../program.h"

#define ACTION_INDEX(name)                                                                         \
  { Action::name::name_, __COUNTER__ }

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, int64_t> ActionCompiler::action_index_map_ = {
    ACTION_INDEX(Ctl),    ACTION_INDEX(InitCol), ACTION_INDEX(SetEnv), ACTION_INDEX(SetRsc),
    ACTION_INDEX(SetSid), ACTION_INDEX(SetUid),  ACTION_INDEX(SetVar),
};

void ActionCompiler::initProgramActionInfo(
    int chain_index, const std::vector<std::unique_ptr<Action::ActionBase>>* default_actions,
    const std::vector<std::unique_ptr<Action::ActionBase>>* actions, Program& program) {
  program.initActionInfo(chain_index, default_actions, actions,
                         [&](Action::ActionBase* action) -> int {
                           auto iter = action_index_map_.find(action->name());
                           assert(iter != action_index_map_.end());
                           if (iter != action_index_map_.end()) {
                             return iter->second;
                           } else {
                             return -1;
                           }
                         });
}

void ActionCompiler::compile(int chain_index, ExtendedRegister op_res_reg, Program& program) {
  program.emit(
      {OpCode::ACTION, {.x_reg_ = op_res_reg}, {.cptr_ = program.actionInfos(chain_index)}});
}

void ActionCompiler::compile(int chain_index, ExtendedRegister op_src_reg,
                             ExtendedRegister op_res_reg, Program& program) {
  program.emit({OpCode::ACTION_PUSH_MATCHED,
                {.x_reg_ = op_src_reg},
                {.x_reg_ = op_res_reg},
                {.cptr_ = program.actionInfos(chain_index)}});
}

void ActionCompiler::compile(int chain_index, Program& program) {
  program.emit({OpCode::UNC_ACTION, {.cptr_ = program.actionInfos(chain_index)}});
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef ACTION_INDEX