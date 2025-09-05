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

#include <unordered_map>

#include <stdint.h>

namespace Wge {
namespace Macro {
class MacroBase;
}
} // namespace Wge

namespace Wge {
namespace Bytecode {
class CompilerTest;
class VirtualMachineTest;
class Program;
namespace Compiler {

class MacroCompiler {
  friend class Wge::Bytecode::CompilerTest;
  friend class Wge::Bytecode::VirtualMachineTest;

public:
  static void compile(const Macro::MacroBase* msg_macro, const Macro::MacroBase* log_data_macro,
                      Program& program);

private:
  static const std::unordered_map<const char*, int64_t> macro_index_map_;
};

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge