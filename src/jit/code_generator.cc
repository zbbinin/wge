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

#include "llvm_wrapper.h"

#include "../bytecode/virtual_machine.h"
#include "../common/log.h"

// Dispatch instruction with index
#define DISPATCH(index) goto* index

namespace Wge {
namespace Jit {
CodeGenerator::CodeGenerator() : llvm_(std::make_unique<LlvmWrapper>()) {
  if (llvm_->ok()) {
    registerFunctions();
  } else {
    WGE_LOG_ERROR("Failed to initialize LLVM JIT ExecutionEngine: {}", llvm_->error());
  }
}

CodeGenerator::~CodeGenerator() = default;

void CodeGenerator::generate(Bytecode::Program& program, std::string_view func_name) {
  if (!llvm_->ok()) {
    return;
  }

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
  static constexpr void* dispatch_table[] = {&&MOV,
                                             &&ADD,
                                             &&CMP,
                                             &&JMP,
                                             &&JZ,
                                             &&JNZ,
                                             &&JOM,
                                             &&JNOM,
                                             &&JRM,
                                             &&JNRM,
                                             &&NOP,
                                             &&DEBUG,
                                             &&RULE_START,
                                             &&JMP_IF_REMOVED,
                                             &&TRANSFORM_START,
                                             &&SIZE,
                                             &&PUSH_MATCHED,
                                             &&PUSH_ALL_MATCHED,
                                             &&EXPAND_MACRO,
                                             &&CHAIN_START,
                                             &&CHAIN_END,
                                             &&LOG_CALLBACK,
                                             &&EXIT_IF_DISRUPTIVE,
                                             TRAVEL_VARIABLES(LOAD_VAR_LABEL)
                                             TRAVEL_TRANSFORMATIONS(TRANSFORM_LABEL)
                                             TRAVEL_OPERATORS(OPERATOR_LABEL)
                                             TRAVEL_ACTIONS(ACTION_LABEL)
                                             TRAVEL_ACTIONS(UNC_ACTION_LABEL)
                                          };
  // clang-format on

#define CASE(ins, proc)                                                                            \
  ins:                                                                                             \
  WGE_LOG_TRACE("code_generator[0x{:x}]: {}", std::distance(begin, iter), iter->toString());       \
  proc;                                                                                            \
  ++iter;                                                                                          \
  if (iter == instructions.end()) {                                                                \
    goto EXIT;                                                                                     \
  }                                                                                                \
  assert(static_cast<size_t>(iter->op_code_) < std::size(dispatch_table));                         \
  goto* dispatch_table[static_cast<size_t>(iter->op_code_)];

#define CASE_LOAD_VAR(var_type)                                                                    \
  CASE(LOAD_##var_type##_CC, (llvm_->createCall("execLoad" #var_type "_CC", &(*iter))));           \
  CASE(LOAD_##var_type##_CS, (llvm_->createCall("execLoad" #var_type "_CS", &(*iter))));           \
  CASE(LOAD_##var_type##_VC, (llvm_->createCall("execLoad" #var_type "_VC", &(*iter))));           \
  CASE(LOAD_##var_type##_VR, (llvm_->createCall("execLoad" #var_type "_VR", &(*iter))));           \
  CASE(LOAD_##var_type##_VS, (llvm_->createCall("execLoad" #var_type "_VS", &(*iter))));

#define CASE_TRANSFORM(transform_type)                                                             \
  CASE(TRANSFORM_##transform_type, (llvm_->createCall("execTransform" #transform_type, &(*iter))));
#define CASE_OPERATOR(operator_type)                                                               \
  CASE(OPERATOR_##operator_type, (llvm_->createCall("execOperator" #operator_type, &(*iter))));
#define CASE_ACTION(action_type)                                                                   \
  CASE(ACTION_##action_type, (llvm_->createCall("execAction" #action_type, &(*iter))));
#define CASE_UNC_ACTION(action_type)                                                               \
  CASE(UNC_ACTION_##action_type, (llvm_->createCall("execUncAction" #action_type, &(*iter))));

  // Create function and basic blocks
  auto func = llvm_->createFunction<void (*)(Bytecode::VirtualMachine*)>(func_name);
  auto entry_block = llvm_->createBasicBlock("entry", func);
  auto exit_block = llvm_->createBasicBlock("exit", func);
  llvm_->setInsertPoint(entry_block);

  // Get instruction iterator
  auto& instructions = program.instructions();
  auto begin = instructions.begin();
  auto iter = begin;
  if (iter == instructions.end()) {
    goto EXIT;
  }

  // Dispatch instructions
  DISPATCH(dispatch_table[static_cast<size_t>(iter->op_code_)]);
  CASE(MOV, (llvm_->createCall("execMov", &(*iter))));
  CASE(ADD, (llvm_->createCall("execAdd", &(*iter))));
  CASE(CMP, (llvm_->createCall("execCmp", &(*iter))));
  // CASE(JMP, (llvm_->createCall("execJmp", &(*iter))));
  // CASE(JZ, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  // CASE(JNZ, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  // CASE(JOM, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  // CASE(JNOM, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  // CASE(JRM, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  // CASE(JNRM, (llvm_->createCall("execJumpIfFlag", &(*iter))));
  CASE(JMP, {});
  CASE(JZ, {});
  CASE(JNZ, {});
  CASE(JOM, {});
  CASE(JNOM, {});
  CASE(JRM, {});
  CASE(JNRM, {});
  CASE(NOP, {});
  CASE(DEBUG, (llvm_->createCall("execDebug", &(*iter))));
  CASE(RULE_START, (llvm_->createCall("execRuleStart", &(*iter))));
  // CASE(JMP_IF_REMOVED, (llvm_->createCall("execJmpIfRemoved", &(*iter))));
  CASE(JMP_IF_REMOVED, {});
  CASE(TRANSFORM_START, (llvm_->createCall("execTransformStart", &(*iter))));
  CASE(SIZE, (llvm_->createCall("execSize", &(*iter))));
  CASE(PUSH_MATCHED, (llvm_->createCall("execPushMatched", &(*iter))));
  CASE(PUSH_ALL_MATCHED, (llvm_->createCall("execPushAllMatched", &(*iter))));
  CASE(EXPAND_MACRO, (llvm_->createCall("execExpandMacro", &(*iter))));
  CASE(CHAIN_START, (llvm_->createCall("execChainStart", &(*iter))));
  CASE(CHAIN_END, (llvm_->createCall("execChainEnd", &(*iter))));
  CASE(LOG_CALLBACK, (llvm_->createCall("execLogCallback", &(*iter))));
  // CASE(EXIT_IF_DISRUPTIVE, (llvm_->createCall("execExitIfDisruptive", &(*iter))));
  CASE(EXIT_IF_DISRUPTIVE, {});
  TRAVEL_VARIABLES(CASE_LOAD_VAR)
  TRAVEL_TRANSFORMATIONS(CASE_TRANSFORM)
  TRAVEL_OPERATORS(CASE_OPERATOR)
  TRAVEL_ACTIONS(CASE_ACTION)
  TRAVEL_ACTIONS(CASE_UNC_ACTION)

EXIT:
  llvm_->createBranch(exit_block);
  llvm_->setInsertPoint(exit_block);
  llvm_->createReturn();
  llvm_->optimizeFunction(func);

  std::string name_holder(func_name.data(), func_name.size());
  program.jitFunc(
      [&, name_holder](Bytecode::VirtualMachine& vm) { llvm_->runFunction(name_holder, &vm); });
}

void CodeGenerator::optimize() {
  if (!llvm_->ok()) {
    return;
  }
  llvm_->optimizeModule();
}

void CodeGenerator::registerFunctions() {
  using VM = Bytecode::VirtualMachine;
  llvm_->registerFunction<&VM::execMov>("execMov");
  llvm_->registerFunction<&VM::execAdd>("execAdd");
  llvm_->registerFunction<&VM::execCmp>("execCmp");
  llvm_->registerFunction<&VM::execJmp>("execJmp");
  llvm_->registerFunction<&VM::execJumpIfFlag>("execJumpIfFlag");
  llvm_->registerFunction<&VM::execDebug>("execDebug");
  llvm_->registerFunction<&VM::execRuleStart>("execRuleStart");
  llvm_->registerFunction<&VM::execJmpIfRemoved>("execJmpIfRemoved");
  llvm_->registerFunction<&VM::execTransformStart>("execTransformStart");
  llvm_->registerFunction<&VM::execSize>("execSize");
  llvm_->registerFunction<&VM::execPushMatched>("execPushMatched");
  llvm_->registerFunction<&VM::execPushAllMatched>("execPushAllMatched");
  llvm_->registerFunction<&VM::execExpandMacro>("execExpandMacro");
  llvm_->registerFunction<&VM::execChainStart>("execChainStart");
  llvm_->registerFunction<&VM::execChainEnd>("execChainEnd");
  llvm_->registerFunction<&VM::execLogCallback>("execLogCallback");
  llvm_->registerFunction<&VM::execExitIfDisruptive>("execExitIfDisruptive");

#define REGISTER_VARIABLE_FUNC(var_type)                                                           \
  llvm_->registerFunction<&VM::execLoad##var_type##_CC>("execLoad" #var_type "_CC");               \
  llvm_->registerFunction<&VM::execLoad##var_type##_CS>("execLoad" #var_type "_CS");               \
  llvm_->registerFunction<&VM::execLoad##var_type##_VC>("execLoad" #var_type "_VC");               \
  llvm_->registerFunction<&VM::execLoad##var_type##_VR>("execLoad" #var_type "_VR");               \
  llvm_->registerFunction<&VM::execLoad##var_type##_VS>("execLoad" #var_type "_VS");
  TRAVEL_VARIABLES(REGISTER_VARIABLE_FUNC)

#define REGISTER_TRANSFORM_FUNC(transform_type)                                                    \
  llvm_->registerFunction<&VM::execTransform##transform_type>("execTransform" #transform_type);
  TRAVEL_TRANSFORMATIONS(REGISTER_TRANSFORM_FUNC)

#define REGISTER_OPERATOR_FUNC(operator_type)                                                      \
  llvm_->registerFunction<&VM::execOperator##operator_type>("execOperator" #operator_type);
  TRAVEL_OPERATORS(REGISTER_OPERATOR_FUNC)

#define REGISTER_ACTION_FUNC(action_type)                                                          \
  llvm_->registerFunction<&VM::execAction##action_type>("execAction" #action_type);
  TRAVEL_ACTIONS(REGISTER_ACTION_FUNC)

#define REGISTER_UNC_ACTION_FUNC(action_type)                                                      \
  llvm_->registerFunction<&VM::execUncAction##action_type>("execUncAction" #action_type);
  TRAVEL_ACTIONS(REGISTER_UNC_ACTION_FUNC)
}

} // namespace Jit
} // namespace Wge