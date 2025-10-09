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
#include "code_generator.h"

#include "../bytecode/virtual_machine.h"
#include "../common/log.h"

// Dispatch instruction with index
#define DISPATCH(index) goto* index

namespace Wge {
namespace Jit {
CodeGenerator::CodeGenerator() : variable_compiler_(llvm_) {
  if (llvm_.ok()) {
    // llvm_.registerFunction<&Bytecode::VirtualMachine::execMov>("execMov");
    // llvm_.registerFunction<&Bytecode::VirtualMachine::execAdd>("execAdd");
    // llvm_.registerFunction<&Bytecode::VirtualMachine::execCmp>("execCmp");
  } else {
    WGE_LOG_ERROR("Failed to initialize LLVM JIT ExecutionEngine: {}", llvm_.error());
  }
}

void CodeGenerator::generate(Bytecode::Program& program) {
// clang-format off
#define LOAD_VAR_LABEL(var_type)                                                                                                              \
  &&LOAD_##var_type##_CC,                                                                                                                     \
  &&LOAD_##var_type##_CS,                                                                                                                     \
  &&LOAD_##var_type##_VC,                                                                                                                     \
  &&LOAD_##var_type##_VR,                                                                                                                     \
  &&LOAD_##var_type##_VS,

#define TRANSFORM_LABEL(transform_type) &&TRANSFORM_##transform_type,
#define OPERATOR_LABEL(operator_type) &&OPERATOR_##operator_type,
#define ACTION_LABEL(action_tyep) &&ACTION_##action_tyep,
#define UNC_ACTION_LABEL(action_tyep) &&UNC_ACTION_##action_tyep,

  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* dispatch_table[] = {
                                            //  &&MOV,
                                            //  &&ADD,
                                            //  &&CMP,
                                            //  &&JMP,
                                            //  &&JZ,
                                            //  &&JNZ,
                                            //  &&JOM,
                                            //  &&JNOM,
                                            //  &&JRM,
                                            //  &&JNRM,
                                            //  &&NOP,
                                            //  &&DEBUG,
                                            //  &&RULE_START,
                                            //  &&JMP_IF_REMOVED,
                                            //  &&TRANSFORM_START,
                                            //  &&SIZE,
                                            //  &&PUSH_MATCHED,
                                            //  &&PUSH_ALL_MATCHED,
                                            //  &&EXPAND_MACRO,
                                            //  &&CHAIN_START,
                                            //  &&CHAIN_END,
                                            //  &&LOG_CALLBACK,
                                            //  &&EXIT_IF_DISRUPTIVE,
                                             TRAVEL_VARIABLES(LOAD_VAR_LABEL)
                                            //  TRAVEL_TRANSFORMATIONS(TRANSFORM_LABEL)
                                            //  TRAVEL_OPERATORS(OPERATOR_LABEL)
                                            //  TRAVEL_ACTIONS(ACTION_LABEL)
                                            //  TRAVEL_ACTIONS(UNC_ACTION_LABEL)
                                          };
  // clang-format on

#define CASE(ins, proc)                                                                            \
  ins:                                                                                             \
  WGE_LOG_TRACE("gen[0x{:x}]: {}", std::distance(begin, iter), iter->toString());                  \
  proc;                                                                                            \
  ++iter;                                                                                          \
  if (iter == instructions.end()) {                                                                \
    return;                                                                                        \
  }                                                                                                \
  assert(static_cast<size_t>(iter->op_code_) < std::size(dispatch_table));                         \
  goto* dispatch_table[static_cast<size_t>(iter->op_code_)];

  // Get instruction iterator
  auto& instructions = program.instructions();
  auto begin = instructions.begin();
  auto iter = begin;
  if (iter == instructions.end()) {
    return;
  }

#define CASE_LOAD_VAR(var_type)                                                                    \
  CASE(LOAD_##var_type##_CC, (llvm_.createCall("execLoad" #var_type "_CC", &(*iter))));            \
  CASE(LOAD_##var_type##_CS, (llvm_.createCall("execLoad" #var_type "_CS", &(*iter))));            \
  CASE(LOAD_##var_type##_VC, (llvm_.createCall("execLoad" #var_type "_VC", &(*iter))));            \
  CASE(LOAD_##var_type##_VR, (llvm_.createCall("execLoad" #var_type "_VR", &(*iter))));            \
  CASE(LOAD_##var_type##_VS, (llvm_.createCall("execLoad" #var_type "_VS", &(*iter))));

  // Create function and basic blocks
  auto main = llvm_.createFunction<void (*)(Bytecode::VirtualMachine*)>("main");
  auto entry_block = llvm_.createBasicBlock("entry", main);
  auto exit_block = llvm_.createBasicBlock("exit", main);
  llvm_.setInsertPoint(entry_block);

  // Dispatch instructions
  DISPATCH(dispatch_table[static_cast<size_t>(iter->op_code_)]);
  // CASE(MOV, genMov(*iter));
  // CASE(ADD, genAdd(*iter));
  // CASE(CMP, genCmp(*iter));
  // CASE(JMP, genJmp(*iter));
  // CASE(JZ, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::ZF, true));
  // CASE(JNZ, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::ZF, false));
  // CASE(JOM, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::OMF, true));
  // CASE(JNOM, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::OMF, false));
  // CASE(JRM, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::RMF, true));
  // CASE(JNRM, genJumpIfFlag(*iter, Bytecode::VirtualMachine::Rflags::RMF, false));
  // CASE(NOP, {});
  // CASE(DEBUG, genDebug(*iter));
  // CASE(RULE_START, genRuleStart(*iter));
  // CASE(JMP_IF_REMOVED, genJmpIfRemoved(*iter));
  // CASE(TRANSFORM_START, genTransformStart(*iter));
  // CASE(SIZE, genSize(*iter));
  // CASE(PUSH_MATCHED, genPushMatched(*iter));
  // CASE(PUSH_ALL_MATCHED, genPushAllMatched(*iter));
  // CASE(EXPAND_MACRO, genExpandMacro(*iter));
  // CASE(CHAIN_START, genChainStart(*iter));
  // CASE(CHAIN_END, genChainEnd(*iter));
  // CASE(LOG_CALLBACK, genLogCallback(*iter));
  // CASE(EXIT_IF_DISRUPTIVE, genExitIfDisruptive(*iter));
  TRAVEL_VARIABLES(CASE_LOAD_VAR)
  // TRAVEL_TRANSFORMATIONS(CASE_TRANSFORM)
  // TRAVEL_OPERATORS(CASE_OPERATOR)
  // TRAVEL_ACTIONS(CASE_ACTION)
  // TRAVEL_ACTIONS(CASE_UNC_ACTION)

  llvm_.setInsertPoint(exit_block);
  llvm_.createReturn();
  llvm_.optimizeFunction(main);

  program.jitFunc([&](Bytecode::VirtualMachine& vm) { llvm_.runFunction("main", &vm); });
}

} // namespace Jit
} // namespace Wge