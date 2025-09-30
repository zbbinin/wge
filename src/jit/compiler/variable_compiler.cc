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
#include "variable_compiler.h"

#include "../../bytecode/compiler/variable_travel_helper.h"
#include "../../bytecode/virtual_machine.h"

namespace Wge {
namespace Jit {
namespace Compiler {
VariableCompiler::VariableCompiler(LlvmWrapper& llvm) : llvm_(llvm) {
  using VM = Bytecode::VirtualMachine;
#define ASSIGN_LOAD_VARIABLE_FUNC(var_type)                                                        \
  llvm_.createCall<&VM::execLoad##var_type##_CC>("load_" #var_type "_cc");                         \
  llvm_.createCall<&VM::execLoad##var_type##_CS>("load_" #var_type "_cs");                         \
  llvm_.createCall<&VM::execLoad##var_type##_VC>("load_" #var_type "_vc");                         \
  llvm_.createCall<&VM::execLoad##var_type##_VR>("load_" #var_type "_vr");                         \
  llvm_.createCall<&VM::execLoad##var_type##_VS>("load_" #var_type "_vs");
  TRAVEL_VARIABLES(ASSIGN_LOAD_VARIABLE_FUNC)
#undef ASSIGN_LOAD_VARIABLE_FUNC
}

void VariableCompiler::compile(const Bytecode::Instruction& instruction) {}

} // namespace Compiler
} // namespace Jit
} // namespace Wge