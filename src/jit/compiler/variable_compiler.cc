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

// Dispatch instruction with index
#define DISPATCH(opcode) goto* opcode

namespace Wge {
namespace Jit {
namespace Compiler {
VariableCompiler::VariableCompiler(const Bytecode::VirtualMachine& vm, LlvmWrapper& llvm)
    : vm_(vm), llvm_(llvm) {
  using VM = Bytecode::VirtualMachine;
#define ASSIGN_LOAD_VARIABLE_FUNC(var_type)                                                        \
  llvm_.registerFunction<&VM::execLoad##var_type##_CC>("execLoad" #var_type "_CC");                \
  llvm_.registerFunction<&VM::execLoad##var_type##_CS>("execLoad" #var_type "_CS");                \
  llvm_.registerFunction<&VM::execLoad##var_type##_VC>("execLoad" #var_type "_VC");                \
  llvm_.registerFunction<&VM::execLoad##var_type##_VR>("execLoad" #var_type "_VR");                \
  llvm_.registerFunction<&VM::execLoad##var_type##_VS>("execLoad" #var_type "_VS");
  TRAVEL_VARIABLES(ASSIGN_LOAD_VARIABLE_FUNC)
}

void VariableCompiler::compile(const Bytecode::Instruction& instruction) {
#define LABEL(variable_type)                                                                       \
  &&LOAD_##variable_type##_CC, &&LOAD_##variable_type##_CS, &&LOAD_##variable_type##_VC,           \
      &&LOAD_##variable_type##_VR, &&LOAD_##variable_type##_VS,
  static constexpr void* dispatch_table[] = {TRAVEL_VARIABLES(LABEL)};

#define CASE(label, func_name)                                                                     \
  label:                                                                                           \
  llvm_.createCall(func_name, &vm_, &instruction);                                                 \
  return;
#define CASE_LOAD_VAR(var_type)                                                                    \
  CASE(LOAD_##var_type##_CC, "execLoad" #var_type "_CC");                                          \
  CASE(LOAD_##var_type##_CS, "execLoad" #var_type "_CS");                                          \
  CASE(LOAD_##var_type##_VC, "execLoad" #var_type "_VC");                                          \
  CASE(LOAD_##var_type##_VR, "execLoad" #var_type "_VR");                                          \
  CASE(LOAD_##var_type##_VS, "execLoad" #var_type "_VS");

  DISPATCH(dispatch_table[static_cast<size_t>(instruction.op_code_)]);
  TRAVEL_VARIABLES(CASE_LOAD_VAR)
}

} // namespace Compiler
} // namespace Jit
} // namespace Wge