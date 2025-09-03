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

#include "program.h"

#include "../action/actions_include.h"

#define ACTION_INDEX(name)                                                                         \
  { Action::name::name_, __COUNTER__ }

namespace Wge {
namespace Bytecode {
const std::unordered_map<const char*, int64_t> ActionCompiler::action_index_map_ = {
    ACTION_INDEX(Ctl),    ACTION_INDEX(InitCol), ACTION_INDEX(SetEnv), ACTION_INDEX(SetRsc),
    ACTION_INDEX(SetSid), ACTION_INDEX(SetUid),  ACTION_INDEX(SetVar),
};

void ActionCompiler::compile(ExtraRegister src_reg, const Action::ActionBase* action,
                             Program& program) {
  auto iter = action_index_map_.find(action->name());
  assert(iter != action_index_map_.end());
  if (iter != action_index_map_.end()) {
    int64_t index = iter->second;
    int64_t action_ptr = reinterpret_cast<int64_t>(action);
    program.emit({OpCode::ACTION,
                  {.ex_reg_ = src_reg},
                  {.index_ = index},
                  {.cptr_ = reinterpret_cast<const void*>(action_ptr)}});
  }
}

void ActionCompiler::compile(const Action::ActionBase* action, Program& program) {
  auto iter = action_index_map_.find(action->name());
  assert(iter != action_index_map_.end());
  if (iter != action_index_map_.end()) {
    int64_t index = iter->second;
    int64_t action_ptr = reinterpret_cast<int64_t>(action);
    program.emit({OpCode::UNC_ACTION,
                  {.index_ = index},
                  {.cptr_ = reinterpret_cast<const void*>(action_ptr)}});
  }
}
} // namespace Bytecode
} // namespace Wge

#undef ACTION_INDEX