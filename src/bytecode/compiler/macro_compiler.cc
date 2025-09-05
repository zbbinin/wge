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
#include "macro_compiler.h"

#include "../../macro/macro_include.h"
#include "../program.h"

#define MACRO_INDEX(name)                                                                          \
  { Macro::name::name_, __COUNTER__ }

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, int64_t> MacroCompiler::macro_index_map_ = {
    MACRO_INDEX(MultiMacro),
    MACRO_INDEX(VariableMacro),
};

void MacroCompiler::compile(const Macro::MacroBase* msg_macro,
                            const Macro::MacroBase* log_data_macro, Program& program) {
  if (msg_macro == nullptr && log_data_macro == nullptr) {
    return;
  }

  int64_t msg_macro_index;
  int64_t log_data_macro_index;

  if (msg_macro) {
    auto msg_macro_iter = macro_index_map_.find(msg_macro->name());
    assert(msg_macro_iter != macro_index_map_.end());
    if (msg_macro_iter != macro_index_map_.end()) {
      msg_macro_index = msg_macro_iter->second;
    }
  }

  if (log_data_macro) {
    auto log_data_macro_iter = macro_index_map_.find(log_data_macro->name());
    assert(log_data_macro_iter != macro_index_map_.end());
    if (log_data_macro_iter != macro_index_map_.end()) {
      log_data_macro_index = log_data_macro_iter->second;
    }
  }

  program.emit({OpCode::EXPAND_MACRO,
                {.index_ = msg_macro_index},
                {.cptr_ = msg_macro},
                {.index_ = log_data_macro_index},
                {.cptr_ = log_data_macro}});
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef MACRO_INDEX