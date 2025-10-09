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
#include "virtual_machine.h"

#include <assert.h>

#include "compiler/rule_compiler.h"
#include "program.h"

#include "../action/actions_include.h"
#include "../macro/macro_include.h"
#include "../operator/operator_include.h"
#include "../rule.h"
#include "../transformation/transform_include.h"
#include "../variable/evaluate_help.h"
#include "../variable/variables_include.h"

// Dispatch instruction with index
#define DISPATCH(index) goto* index

namespace Wge {
namespace Bytecode {
bool VirtualMachine::execute(const Program& program) {
  // If the program is JIT compiled, execute the JIT function
  auto jit_func = program.jitFunc();
  if (jit_func != nullptr) {
    jit_func(*this);
    return !disruptive_;
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

#define CASE(ins, proc, forward)                                                                   \
  ins:                                                                                             \
  WGE_LOG_TRACE("exec[0x{:x}]: {}", std::distance(begin, iter), iter->toString());                 \
  proc;                                                                                            \
  forward;                                                                                         \
  if (iter == instructions.end()) {                                                                \
    return !disruptive_;                                                                           \
  }                                                                                                \
  assert(static_cast<size_t>(iter->op_code_) < std::size(dispatch_table));                         \
  goto* dispatch_table[static_cast<size_t>(iter->op_code_)];

#define CASE_LOAD_VAR(var_type)                                                                    \
  CASE(LOAD_##var_type##_CC, execLoad##var_type##_CC(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_CS, execLoad##var_type##_CS(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VC, execLoad##var_type##_VC(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VR, execLoad##var_type##_VR(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VS, execLoad##var_type##_VS(*iter), ++iter);

#define CASE_TRANSFORM(transform_type)                                                             \
  CASE(TRANSFORM_##transform_type, execTransform##transform_type(*iter), ++iter);
#define CASE_OPERATOR(operator_type)                                                               \
  CASE(OPERATOR_##operator_type, execOperator##operator_type(*iter), ++iter);
#define CASE_ACTION(action_type) CASE(ACTION_##action_type, execAction##action_type(*iter), ++iter);
#define CASE_UNC_ACTION(action_type)                                                               \
  CASE(UNC_ACTION_##action_type, execUncAction##action_type(*iter), ++iter);

  // Get instruction iterator
  auto& instructions = program.instructions();
  auto begin = instructions.begin();
  auto iter = begin;
  if (iter == instructions.end())
    [[unlikely]] { return rflags_.test(static_cast<size_t>(Rflags::RMF)); }

  disruptive_ = false;

  // Dispatch instructions
  DISPATCH(dispatch_table[static_cast<size_t>(iter->op_code_)]);
  CASE(MOV, execMov(*iter), ++iter);
  CASE(ADD, execAdd(*iter), ++iter);
  CASE(CMP, execCmp(*iter), ++iter);
  CASE(JMP, execJmp(*iter, instructions, iter), {});
  CASE(JZ, execJumpIfFlag(*iter, instructions, iter, Rflags::ZF, true), {});
  CASE(JNZ, execJumpIfFlag(*iter, instructions, iter, Rflags::ZF, false), {});
  CASE(JOM, execJumpIfFlag(*iter, instructions, iter, Rflags::OMF, true), {});
  CASE(JNOM, execJumpIfFlag(*iter, instructions, iter, Rflags::OMF, false), {});
  CASE(JRM, execJumpIfFlag(*iter, instructions, iter, Rflags::RMF, true), {});
  CASE(JNRM, execJumpIfFlag(*iter, instructions, iter, Rflags::RMF, false), {});
  CASE(NOP, {}, ++iter);
  CASE(DEBUG, execDebug(*iter), ++iter);
  CASE(RULE_START, execRuleStart(*iter), ++iter);
  CASE(JMP_IF_REMOVED, execJmpIfRemoved(*iter, instructions, iter), {});
  CASE(TRANSFORM_START, execTransformStart(*iter), ++iter);
  CASE(SIZE, execSize(*iter), ++iter);
  CASE(PUSH_MATCHED, execPushMatched(*iter), ++iter);
  CASE(PUSH_ALL_MATCHED, execPushAllMatched(*iter), ++iter);
  CASE(EXPAND_MACRO, execExpandMacro(*iter), ++iter);
  CASE(CHAIN_START, execChainStart(*iter), ++iter);
  CASE(CHAIN_END, execChainEnd(*iter), ++iter);
  CASE(LOG_CALLBACK, execLogCallback(*iter), ++iter);
  CASE(EXIT_IF_DISRUPTIVE, execExitIfDisruptive(*iter, instructions, iter), {});
  TRAVEL_VARIABLES(CASE_LOAD_VAR)
  TRAVEL_TRANSFORMATIONS(CASE_TRANSFORM)
  TRAVEL_OPERATORS(CASE_OPERATOR)
  TRAVEL_ACTIONS(CASE_ACTION)
  TRAVEL_ACTIONS(CASE_UNC_ACTION)
#undef CASE
}

void VirtualMachine::execMov(const Instruction& instruction) {
  general_registers_[instruction.op1_.g_reg_] = instruction.op2_.imm_;
}

void VirtualMachine::execAdd(const Instruction& instruction) {
  general_registers_[instruction.op1_.g_reg_] += instruction.op2_.imm_;
}

void VirtualMachine::execCmp(const Instruction& instruction) {
  rflags_.set(static_cast<size_t>(Rflags::ZF), general_registers_[instruction.op1_.g_reg_] ==
                                                   general_registers_[instruction.op2_.g_reg_]);
}

void VirtualMachine::execJmp(const Instruction& instruction,
                             const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                             std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  const int64_t target_address = instruction.op1_.address_;
  assert(target_address > 0);
  if (target_address < 0 || target_address >= instruction_array.size())
    [[unlikely]] { iter = instruction_array.end(); }
  else {
    iter = instruction_array.begin() + target_address;
  }
}

void VirtualMachine::execJumpIfFlag(
    const Instruction& instruction,
    const std::vector<Wge::Bytecode::Instruction>& instruction_array,
    std::vector<Wge::Bytecode::Instruction>::const_iterator& iter, VirtualMachine::Rflags flag,
    bool is_set) {
  if (rflags_.test(static_cast<size_t>(flag)) == is_set) {
    const int64_t target_address = instruction.op1_.address_;
    assert(target_address > 0);
    if (target_address < 0 || target_address >= instruction_array.size())
      [[unlikely]] { iter = instruction_array.end(); }
    else {
      iter = instruction_array.begin() + target_address;
    }
  } else {
    ++iter;
  }
}

void VirtualMachine::execDebug(const Instruction& instruction) {
  const char* msg = reinterpret_cast<const char*>(instruction.op1_.cptr_);
  WGE_LOG_DEBUG("{}", msg);
}

void VirtualMachine::execRuleStart(const Instruction& instruction) {
  // Reset RMF
  rflags_.reset(static_cast<size_t>(Rflags::RMF));

  const Rule* rule = reinterpret_cast<const Rule*>(instruction.op1_.cptr_);
  transaction_.setCurrentEvaluateRule(rule);
  transaction_.clearCapture();
  transaction_.clearMatchedVariables();

  WGE_LOG_TRACE("start of rule execution");
  WGE_LOG_TRACE("------------------------------------");
}

void VirtualMachine::execJmpIfRemoved(
    const Instruction& instruction,
    const std::vector<Wge::Bytecode::Instruction>& instruction_array,
    std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  const Rule* curr_rule = transaction_.getCurrentEvaluateRule();
  if (transaction_.isRuleRemoved(curr_rule)) {
    const int64_t target_address = instruction.op1_.address_;
    if (target_address < 0 || target_address >= instruction_array.size())
      [[unlikely]] { iter = instruction_array.end(); }
    else {
      iter = instruction_array.begin() + target_address;
    }
  } else {
    ++iter;
  }
}

void VirtualMachine::execTransformStart(const Instruction& instruction) {
  auto& results = extended_registers_[instruction.op1_.x_reg_];
  transaction_.trasnformListBuffer().clear();
  transaction_.trasnformListBuffer().resize(results.size());
}

void VirtualMachine::execSize(const Instruction& instruction) {
  auto& results = extended_registers_[instruction.op2_.x_reg_];
  general_registers_[instruction.op1_.g_reg_] = results.size();
}

void VirtualMachine::execPushMatched(const Instruction& instruction) {
  const Rule* curr_rule = transaction_.getCurrentEvaluateRule();
  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);
  auto& transformed_value = extended_registers_[instruction.op1_.x_reg_];
  auto& operate_results = extended_registers_[instruction.op2_.x_reg_];
  auto& original_value = extended_registers_[Compiler::RuleCompiler::load_var_reg_];

  assert(operate_results.size() == original_value.size());
  assert(original_value.size() == transformed_value.size());

  size_t operate_results_size = operate_results.size();
  size_t i = general_registers_[instruction.op3_.g_reg_];

  // Not matched
  if (IS_INT_VARIANT(operate_results.get(i).variant_)) {
    return;
  }

  auto& transform_list_buffer = transaction_.trasnformListBuffer();
  assert(transform_list_buffer.size() > i);
  std::list<const Transformation::TransformBase*>& transform_list = transform_list_buffer[i];

  transaction_.pushMatchedVariable((*curr_var).get(), curr_rule->chainIndex(),
                                   original_value.move(i), transformed_value.move(i),
                                   operate_results.move(i), std::move(transform_list));
}

void VirtualMachine::execPushAllMatched(const Instruction& instruction) {
  const Rule* curr_rule = transaction_.getCurrentEvaluateRule();
  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);
  auto& transformed_value = extended_registers_[instruction.op1_.x_reg_];
  auto& operate_results = extended_registers_[instruction.op2_.x_reg_];
  auto& original_value = extended_registers_[Compiler::RuleCompiler::load_var_reg_];

  assert(operate_results.size() == original_value.size());
  assert(original_value.size() == transformed_value.size());

  size_t operate_results_size = operate_results.size();
  auto& transform_list_buffer = transaction_.trasnformListBuffer();
  assert(transform_list_buffer.size() == operate_results_size);
  for (size_t i = 0; i < operate_results_size; ++i) {
    // Not matched
    if (IS_INT_VARIANT(operate_results.get(i).variant_)) {
      continue;
    }

    std::list<const Transformation::TransformBase*>& transform_list = transform_list_buffer[i];

    transaction_.pushMatchedVariable((*curr_var).get(), curr_rule->chainIndex(),
                                     original_value.move(i), transformed_value.move(i),
                                     operate_results.move(i), std::move(transform_list));
  }
}

void VirtualMachine::execExpandMacro(const Instruction& instruction) {
  if (instruction.op2_.cptr_) {
    execMsgExpandMacro(instruction);
  }
  if (instruction.op4_.cptr_) {
    execLogDataExpandMacro(instruction);
  }
}

template <class MacroType> void dispatchMsgMacro(const MacroType* macro, Transaction& t) {
  Common::EvaluateResults results;
  macro->MacroType::evaluate(t, results);
  t.setMsgMacroExpanded(results.move(0));
}

template <class MacroType> void dispatchLogDataMacro(const MacroType* macro, Transaction& t) {
  Common::EvaluateResults results;
  macro->MacroType::evaluate(t, results);
  t.setLogDataMacroExpanded(results.move(0));
}

void VirtualMachine::execMsgExpandMacro(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* macro_dispatch_table[] = {&&MultiMacro, &&VariableMacro};
#define CASE(macro)                                                                                \
  macro:                                                                                           \
  dispatchMsgMacro(reinterpret_cast<const Macro::macro*>(instruction.op2_.cptr_), transaction_);   \
  return;

  DISPATCH(macro_dispatch_table[instruction.op1_.index_]);
  CASE(MultiMacro);
  CASE(VariableMacro);
#undef CASE
}

void VirtualMachine::execLogDataExpandMacro(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* macro_dispatch_table[] = {&&MultiMacro, &&VariableMacro};
#define CASE(macro)                                                                                \
  macro:                                                                                           \
  dispatchLogDataMacro(reinterpret_cast<const Macro::macro*>(instruction.op4_.cptr_),              \
                       transaction_);                                                              \
  return;

  DISPATCH(macro_dispatch_table[instruction.op3_.index_]);
  CASE(MultiMacro);
  CASE(VariableMacro);
#undef CASE
}

void VirtualMachine::execChainStart(const Instruction& instruction) {
  // Reset RMF
  rflags_.reset(static_cast<size_t>(Rflags::RMF));

  // Set current evaluate rule
  const Rule* rule = reinterpret_cast<const Rule*>(instruction.op1_.cptr_);
  transaction_.setCurrentEvaluateRule(rule);
  WGE_LOG_TRACE("start of rule chain execution");
  WGE_LOG_TRACE("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓");
}

void VirtualMachine::execChainEnd(const Instruction& instruction) {
  // Set current evaluate rule
  const Rule* rule = reinterpret_cast<const Rule*>(instruction.op1_.cptr_);
  transaction_.setCurrentEvaluateRule(rule);
}

void VirtualMachine::execLogCallback(const Instruction& instruction) {
  auto& log_callback = transaction_.getLogCallback();
  if (log_callback) {
    log_callback(*transaction_.getCurrentEvaluateRule());
  }
}

void VirtualMachine::execExitIfDisruptive(
    const Instruction& instruction,
    const std::vector<Wge::Bytecode::Instruction>& instruction_array,
    std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  std::optional<bool> disruptive =
      transaction_.doDisruptive(*transaction_.getCurrentEvaluateRule());
  if (disruptive.has_value()) {
    disruptive_ = disruptive.value();
    iter = instruction_array.end();
  } else {
    ++iter;
  }
}

#define IMPL(var_type, proc)                                                                       \
  const Variable::var_type* v =                                                                    \
      reinterpret_cast<const Variable::var_type*>(instruction.op2_.cptr_);                         \
  auto& output = extended_registers_[instruction.op1_.x_reg_];                                     \
  output.clear();                                                                                  \
  proc;

#define IMPL_LOAD_VAR(var_type, cc_proc, cs_proc, vc_proc, vr_proc, vs_proc)                       \
  void VirtualMachine::execLoad##var_type##_CC(const Instruction& instruction) {                   \
    IMPL(var_type, cc_proc);                                                                       \
  }                                                                                                \
  void VirtualMachine::execLoad##var_type##_CS(const Instruction& instruction) {                   \
    IMPL(var_type, cs_proc);                                                                       \
  }                                                                                                \
  void VirtualMachine::execLoad##var_type##_VC(const Instruction& instruction) {                   \
    IMPL(var_type, vc_proc);                                                                       \
  }                                                                                                \
  void VirtualMachine::execLoad##var_type##_VR(const Instruction& instruction) {                   \
    IMPL(var_type, vr_proc);                                                                       \
  }                                                                                                \
  void VirtualMachine::execLoad##var_type##_VS(const Instruction& instruction) {                   \
    IMPL(var_type, vs_proc);                                                                       \
  }

#define IMPL_LOAD_VAR_PROC(var_type)                                                               \
  IMPL_LOAD_VAR(                                                                                   \
      var_type, { (v->evaluate<IS_COUNTER, IS_COLLECTION>(transaction_, output)); },               \
      { (v->evaluate<IS_COUNTER, NOT_COLLECTION>(transaction_, output)); },                        \
      { (v->evaluate<NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output)); },  \
      { (v->evaluate<NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(transaction_, output)); },   \
      { (v->evaluate<NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output)); })

IMPL_LOAD_VAR_PROC(ArgsCombinedSize);
IMPL_LOAD_VAR_PROC(ArgsGetNames);
IMPL_LOAD_VAR_PROC(ArgsGet);
IMPL_LOAD_VAR_PROC(ArgsNames);
IMPL_LOAD_VAR_PROC(ArgsPostNames);
IMPL_LOAD_VAR_PROC(ArgsPost);
IMPL_LOAD_VAR_PROC(Args);
IMPL_LOAD_VAR_PROC(AuthType);
IMPL_LOAD_VAR_PROC(Duration);
IMPL_LOAD_VAR_PROC(Env);
IMPL_LOAD_VAR_PROC(FilesCombinedSize);
IMPL_LOAD_VAR_PROC(FilesNames);
IMPL_LOAD_VAR_PROC(FilesSizes);
IMPL_LOAD_VAR_PROC(FilesTmpContent);
IMPL_LOAD_VAR_PROC(FilesTmpNames);
IMPL_LOAD_VAR_PROC(Files);
IMPL_LOAD_VAR_PROC(FullRequestLength);
IMPL_LOAD_VAR_PROC(FullRequest);
IMPL_LOAD_VAR_PROC(Geo);
IMPL_LOAD_VAR_PROC(Global);
IMPL_LOAD_VAR_PROC(HighestSeverity);
IMPL_LOAD_VAR_PROC(InboundDataError);
IMPL_LOAD_VAR_PROC(Ip);
IMPL_LOAD_VAR_PROC(MatchedVarName);
IMPL_LOAD_VAR_PROC(MatchedVar);
IMPL_LOAD_VAR_PROC(MatchedVarsNames);
IMPL_LOAD_VAR_PROC(MatchedVars);
IMPL_LOAD_VAR_PROC(ModSecBuild);
IMPL_LOAD_VAR_PROC(MscPcreLimitsExceeded);
IMPL_LOAD_VAR_PROC(MultipartBoundaryQuoted);
IMPL_LOAD_VAR_PROC(MultipartBoundaryWhitespace);
IMPL_LOAD_VAR_PROC(MultipartCrlfLfLines);
IMPL_LOAD_VAR_PROC(MultipartDataAfter);
IMPL_LOAD_VAR_PROC(MultipartDataBefore);
IMPL_LOAD_VAR_PROC(MultipartFileLimitExceeded);
IMPL_LOAD_VAR_PROC(MultipartFileName);
IMPL_LOAD_VAR_PROC(MultipartHeaderFolding);
IMPL_LOAD_VAR_PROC(MultipartInvalidHeaderFolding);
IMPL_LOAD_VAR_PROC(MultipartInvalidPart);
IMPL_LOAD_VAR_PROC(MultipartInvalidQuoting);
IMPL_LOAD_VAR_PROC(MultipartLfLine);
IMPL_LOAD_VAR_PROC(MultipartMissingSemicolon);
IMPL_LOAD_VAR_PROC(MultipartName);
IMPL_LOAD_VAR(
    MultipartPartHeaders_IsCharSet,
    { (v->evaluate<true, IS_COUNTER, IS_COLLECTION>(transaction_, output)); },
    { (v->evaluate<true, IS_COUNTER, NOT_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<true, NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    },
    { (v->evaluate<true, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<true, NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    MultipartPartHeaders_NotCharSet,
    { (v->evaluate<false, IS_COUNTER, IS_COLLECTION>(transaction_, output)); },
    { (v->evaluate<false, IS_COUNTER, NOT_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<false, NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<false, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<false, NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR_PROC(MultipartStrictError);
IMPL_LOAD_VAR_PROC(MultipartUnmatchedBoundary);
IMPL_LOAD_VAR_PROC(OutboundDataError);
IMPL_LOAD_VAR_PROC(PathInfo);
IMPL_LOAD_VAR_PROC(QueryString);
IMPL_LOAD_VAR_PROC(RemoteAddr);
IMPL_LOAD_VAR_PROC(RemoteHost);
IMPL_LOAD_VAR_PROC(RemotePort);
IMPL_LOAD_VAR_PROC(RemoteUser);
IMPL_LOAD_VAR_PROC(ReqBodyErrorMsg);
IMPL_LOAD_VAR_PROC(ReqBodyError);
IMPL_LOAD_VAR_PROC(ReqbodyProcessorError);
IMPL_LOAD_VAR_PROC(ReqBodyProcessor);
IMPL_LOAD_VAR_PROC(RequestBaseName);
IMPL_LOAD_VAR_PROC(RequestBodyLength);
IMPL_LOAD_VAR_PROC(RequestBody);
IMPL_LOAD_VAR_PROC(RequestCookiesNames);
IMPL_LOAD_VAR_PROC(RequestCookies);
IMPL_LOAD_VAR_PROC(RequestFileName);
IMPL_LOAD_VAR_PROC(RequestHeadersNames);
IMPL_LOAD_VAR_PROC(RequestHeaders);
IMPL_LOAD_VAR_PROC(RequestLine);
IMPL_LOAD_VAR_PROC(RequestMothod);
IMPL_LOAD_VAR_PROC(RequestProtocol);
IMPL_LOAD_VAR_PROC(RequestUriRaw);
IMPL_LOAD_VAR_PROC(RequestUri);
IMPL_LOAD_VAR_PROC(Resource);
IMPL_LOAD_VAR_PROC(ResponseBody);
IMPL_LOAD_VAR_PROC(ResponseContentLength);
IMPL_LOAD_VAR_PROC(ResponseContentType);
IMPL_LOAD_VAR_PROC(ResponseHeadersNames);
IMPL_LOAD_VAR_PROC(ResponseHeaders);
IMPL_LOAD_VAR_PROC(ResponseProtocol);
IMPL_LOAD_VAR_PROC(ResponseStatus);
IMPL_LOAD_VAR(
    Rule_Id,
    {
      (v->evaluate<Variable::Rule::SubNameType::Id, IS_COUNTER, IS_COLLECTION>(transaction_,
                                                                               output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Id, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                                output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Id, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Id, NOT_COUNTER, IS_COLLECTION,
                   IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Id, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Rule_Phase,
    {
      (v->evaluate<Variable::Rule::SubNameType::Phase, IS_COUNTER, IS_COLLECTION>(transaction_,
                                                                                  output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Phase, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                                   output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Phase, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Phase, NOT_COUNTER, IS_COLLECTION,
                   IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::Phase, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Rule_OperatorValue,
    {
      (v->evaluate<Variable::Rule::SubNameType::OperatorValue, IS_COUNTER, IS_COLLECTION>(
          transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::OperatorValue, IS_COUNTER, NOT_COLLECTION>(
          transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::OperatorValue, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::OperatorValue, NOT_COUNTER, IS_COLLECTION,
                   IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Rule::SubNameType::OperatorValue, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR_PROC(ServerAddr);
IMPL_LOAD_VAR_PROC(ServerName);
IMPL_LOAD_VAR_PROC(ServerPort);
IMPL_LOAD_VAR_PROC(Session);
IMPL_LOAD_VAR_PROC(SessionId);
IMPL_LOAD_VAR_PROC(StatusLine);
IMPL_LOAD_VAR_PROC(TimeDay);
IMPL_LOAD_VAR_PROC(TimeEpoch);
IMPL_LOAD_VAR_PROC(TimeHour);
IMPL_LOAD_VAR_PROC(TimeMin);
IMPL_LOAD_VAR_PROC(TimeMon);
IMPL_LOAD_VAR_PROC(TimeSec);
IMPL_LOAD_VAR_PROC(TimeWDay);
IMPL_LOAD_VAR_PROC(TimeYear);
IMPL_LOAD_VAR_PROC(Time);
IMPL_LOAD_VAR(
    Tx_IsCaptureIndex, { (v->evaluate<true, IS_COUNTER, IS_COLLECTION>(transaction_, output)); },
    { (v->evaluate<true, IS_COUNTER, NOT_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<true, NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    },
    { (v->evaluate<true, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<true, NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Tx_NotCaptureIndex, { (v->evaluate<false, IS_COUNTER, IS_COLLECTION>(transaction_, output)); },
    { (v->evaluate<false, IS_COUNTER, NOT_COLLECTION>(transaction_, output)); },
    {
      (v->evaluate<false, NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<false, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<false, NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR_PROC(UniqueId);
IMPL_LOAD_VAR_PROC(UrlenCodedError);
IMPL_LOAD_VAR_PROC(User);
IMPL_LOAD_VAR_PROC(UserId);
IMPL_LOAD_VAR_PROC(WebAppId);
IMPL_LOAD_VAR(
    Xml_AttrValue,
    {
      (v->evaluate<Variable::Xml::Type::AttrValue, IS_COUNTER, IS_COLLECTION>(transaction_,
                                                                              output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValue, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                               output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValue, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValue, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(
          transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValue, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Xml_TagValue,
    {
      (v->evaluate<Variable::Xml::Type::TagValue, IS_COUNTER, IS_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValue, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                              output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValue, NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(
          transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValue, NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(
          transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValue, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Xml_AttrValuePmf,
    {
      (v->evaluate<Variable::Xml::Type::AttrValuePmf, IS_COUNTER, IS_COLLECTION>(transaction_,
                                                                                 output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValuePmf, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                                  output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValuePmf, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValuePmf, NOT_COUNTER, IS_COLLECTION,
                   IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::AttrValuePmf, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
IMPL_LOAD_VAR(
    Xml_TagValuePmf,
    {
      (v->evaluate<Variable::Xml::Type::TagValuePmf, IS_COUNTER, IS_COLLECTION>(transaction_,
                                                                                output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValuePmf, IS_COUNTER, NOT_COLLECTION>(transaction_,
                                                                                 output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValuePmf, NOT_COUNTER, IS_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValuePmf, NOT_COUNTER, IS_COLLECTION,
                   IS_REGEX_COLLECTION>(transaction_, output));
    },
    {
      (v->evaluate<Variable::Xml::Type::TagValuePmf, NOT_COUNTER, NOT_COLLECTION,
                   NOT_REGEX_COLLECTION>(transaction_, output));
    });
#undef IMPL
#undef IMPL_LOAD_VAR
#undef IMPL_LOAD_VAR_PROC

template <class TransformType>
void dispatchTransform(const TransformType* transform, Transaction& t,
                       const std::unique_ptr<Wge::Variable::VariableBase>* curr_var,
                       const Common::EvaluateResults& input, Common::EvaluateResults& output) {
  std::vector<std::list<const Transformation::TransformBase*>>& transform_list_buffer =
      t.trasnformListBuffer();
  size_t input_size = input.size();
  assert(input_size == transform_list_buffer.size());
  for (size_t i = 0; i < input_size; ++i) {
    const Common::EvaluateResults::Element& input_element = input.get(i);
    if (!IS_STRING_VIEW_VARIANT(input_element.variant_)) {
      // Not a string, just pass it through. The OPERATE instruction use the output as the input, so
      // we need to keep the size consistent
      output.append(input_element.variant_);
      continue;
    }

    /* Check the cache */
    std::string_view input_data_view = std::get<std::string_view>(input_element.variant_);
    Common::EvaluateResults::Element output_element;
    std::optional<bool> cache_result = transform->TransformType::getCache(
        t, input_element, transform->TransformType::name(), output_element);
    if (cache_result.has_value()) {
      WGE_LOG_TRACE(
          "transform cache hit: {} {}",
          [&]() {
            if (curr_var) {
              if (input_element.variable_sub_name_.empty()) {
                return std::string((*curr_var)->fullName().main_name_);
              } else {
                return std::format("{}:{}", (*curr_var)->fullName().main_name_,
                                   input_element.variable_sub_name_);
              }
            } else {
              return std::string();
            }
          }(),
          transform->TransformType::name());
      if (!*cache_result) {
        output_element.variant_ = input_data_view;
        output_element.variable_sub_name_ = input_element.variable_sub_name_;
      } else {
        transform_list_buffer[i].emplace_back(transform);
      }
      output.append(std::move(output_element));
      continue;
    }

    /* Evaluate the transformation and store the result in the cache */
    std::string output_buffer;
    bool ret = transform->TransformType::evaluate(input_data_view, output_buffer);
    if (ret) {
      auto& result = transform->TransformType::setCache(
          t, input_data_view, transform->TransformType::name(), std::move(output_buffer));
      output_element.variant_ = result.variant_;
      transform_list_buffer[i].emplace_back(transform);
    } else {
      transform->TransformType::setEmptyCache(t, input_data_view, transform->TransformType::name());
      output_element.variant_ = input_data_view;
    }
    output_element.variable_sub_name_ = input_element.variable_sub_name_;
    output.append(std::move(output_element));
    WGE_LOG_TRACE("evaluate action defined transformation: {} {}", transform->TransformType::name(),
                  ret);
  }
}

#define IMPL_TRANSFORM_PROC(transform_type)                                                        \
  void VirtualMachine::execTransform##transform_type(const Instruction& instruction) {             \
    const std::unique_ptr<Variable::VariableBase>* curr_var =                                      \
        reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(                          \
            general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);                       \
    const Transformation::transform_type* transform =                                              \
        reinterpret_cast<const Transformation::transform_type*>(instruction.op3_.cptr_);           \
    const auto& input = extended_registers_[instruction.op2_.x_reg_];                              \
    auto& output = extended_registers_[instruction.op1_.x_reg_];                                   \
    output.clear();                                                                                \
    dispatchTransform(transform, transaction_, curr_var, input, output);                           \
  }
TRAVEL_TRANSFORMATIONS(IMPL_TRANSFORM_PROC);
#undef IMPL_TRANSFORM_PROC

template <class OperatorType>
bool dispatchOperator(const OperatorType* op, Transaction& t, const Rule* curr_rule,
                      const std::unique_ptr<Wge::Variable::VariableBase>* curr_var,
                      const Common::EvaluateResults& input, Common::EvaluateResults& output) {
  bool rule_matched = false;
  size_t input_size = input.size();
  for (size_t i = 0; i < input_size; ++i) {
    auto& var_value = input.get(i).variant_;
    bool variable_matched = op->OperatorType::evaluate(t, var_value);
    variable_matched = op->OperatorType::isNot() ^ variable_matched;

    // Call additional conditions if they are defined
    if (variable_matched && t.getAdditionalCond()) {
      if (IS_STRING_VIEW_VARIANT(var_value)) {
        variable_matched =
            t.getAdditionalCond()(*curr_rule, std::get<std::string_view>(var_value), *curr_var);
        WGE_LOG_TRACE("call additional condition: {}", variable_matched);
      }
    }

    if (variable_matched) {
      auto merged_count = t.mergeCapture();
      if (merged_count) {
        std::string_view tx_0 = std::get<std::string_view>(t.getCapture(0));

        // Copy the first captured value to the capture_value. The copy is necessary because
        // the captured value may be modified later.
        output.append(std::string(tx_0.data(), tx_0.size()));
      } else {
        output.append(std::string_view());
      }

      rule_matched = true;
    } else {
      t.clearTempCapture();
      output.append(0);
    }

    WGE_LOG_TRACE("evaluate operator: {} {}@{} {} = {}", VISTIT_VARIANT_AS_STRING(var_value),
                  op->OperatorType::isNot() ? "!" : "", op->OperatorType::name(),
                  op->OperatorType::macro() ? op->OperatorType::macro()->literalValue()
                                            : op->OperatorType::literalValue(),
                  variable_matched);
  }

  return rule_matched;
}

#define IMPL_OPERATOR_PROC(operator_type)                                                          \
  void VirtualMachine::execOperator##operator_type(const Instruction& instruction) {               \
    const Rule* curr_rule = transaction_.getCurrentEvaluateRule();                                 \
    const std::unique_ptr<Variable::VariableBase>* curr_var =                                      \
        reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(                          \
            general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);                       \
    const Operator::operator_type* op =                                                            \
        reinterpret_cast<const Operator::operator_type*>(instruction.op3_.cptr_);                  \
    const auto& input = extended_registers_[instruction.op2_.x_reg_];                              \
    auto& output = extended_registers_[instruction.op1_.x_reg_];                                   \
    output.clear();                                                                                \
    bool matched = dispatchOperator(op, transaction_, curr_rule, curr_var, input, output);         \
    rflags_.set(static_cast<size_t>(Rflags::OMF), matched);                                        \
    if (matched) {                                                                                 \
      rflags_.set(static_cast<size_t>(Rflags::RMF));                                               \
    }                                                                                              \
  }
TRAVEL_OPERATORS(IMPL_OPERATOR_PROC)
#undef IMPL_OPERATOR_PROC

#define IMPL_ACTION(action_type, proc)                                                             \
  void VirtualMachine::execAction##action_type(const Instruction& instruction) {                   \
    auto& results = extended_registers_[instruction.op1_.x_reg_];                                  \
    size_t i = general_registers_[Compiler::RuleCompiler::loop_cursor_];                           \
    auto& element = results.get(i);                                                                \
    if (!IS_INT_VARIANT(element.variant_)) {                                                       \
      const Action::action_type* action =                                                          \
          reinterpret_cast<const Action::action_type*>(instruction.op2_.cptr_);                    \
      proc;                                                                                        \
    }                                                                                              \
  }

#define IMPL_ACTION_PROC(action_type) IMPL_ACTION(action_type, action->evaluate(transaction_))

IMPL_ACTION(Ctl_AuditEngine, (action->evaluate<Action::Ctl::CtlType::AuditEngine>(transaction_)));
IMPL_ACTION(Ctl_AuditLogParts,
            (action->evaluate<Action::Ctl::CtlType::AuditLogParts>(transaction_)));
IMPL_ACTION(Ctl_ParseXmlIntoArgs,
            (action->evaluate<Action::Ctl::CtlType::ParseXmlIntoArgs>(transaction_)));
IMPL_ACTION(Ctl_RequestBodyAccess,
            (action->evaluate<Action::Ctl::CtlType::RequestBodyAccess>(transaction_)));
IMPL_ACTION(Ctl_RequestBodyProcessor,
            (action->evaluate<Action::Ctl::CtlType::RequestBodyProcessor>(transaction_)));
IMPL_ACTION(Ctl_RuleEngine, (action->evaluate<Action::Ctl::CtlType::RuleEngine>(transaction_)));
IMPL_ACTION(Ctl_RuleRemoveById,
            (action->evaluate<Action::Ctl::CtlType::RuleRemoveById>(transaction_)));
IMPL_ACTION(Ctl_RuleRemoveByIdRange,
            (action->evaluate<Action::Ctl::CtlType::RuleRemoveByIdRange>(transaction_)));
IMPL_ACTION(Ctl_RuleRemoveByTag,
            (action->evaluate<Action::Ctl::CtlType::RuleRemoveByTag>(transaction_)));
IMPL_ACTION(Ctl_RuleRemoveTargetById,
            (action->evaluate<Action::Ctl::CtlType::RuleRemoveTargetById>(transaction_)));
IMPL_ACTION(Ctl_RuleRemoveTargetByTag,
            (action->evaluate<Action::Ctl::CtlType::RuleRemoveTargetByTag>(transaction_)));
IMPL_ACTION_PROC(InitCol);
IMPL_ACTION_PROC(SetEnv);
IMPL_ACTION_PROC(SetRsc);
IMPL_ACTION_PROC(SetSid);
IMPL_ACTION_PROC(SetUid);
IMPL_ACTION(SetVar_Create_TF,
            (action->evaluate<Action::SetVar::EvaluateType::Create, true, false>(transaction_)));
IMPL_ACTION(SetVar_Create_FF,
            (action->evaluate<Action::SetVar::EvaluateType::Create, false, false>(transaction_)));
IMPL_ACTION(
    SetVar_CreateAndInit_TT,
    (action->evaluate<Action::SetVar::EvaluateType::CreateAndInit, true, true>(transaction_)));
IMPL_ACTION(
    SetVar_CreateAndInit_TF,
    (action->evaluate<Action::SetVar::EvaluateType::CreateAndInit, true, false>(transaction_)));
IMPL_ACTION(
    SetVar_CreateAndInit_FT,
    (action->evaluate<Action::SetVar::EvaluateType::CreateAndInit, false, true>(transaction_)));
IMPL_ACTION(
    SetVar_CreateAndInit_FF,
    (action->evaluate<Action::SetVar::EvaluateType::CreateAndInit, false, false>(transaction_)));
IMPL_ACTION(SetVar_Remove_TF,
            (action->evaluate<Action::SetVar::EvaluateType::Remove, true, false>(transaction_)));
IMPL_ACTION(SetVar_Remove_FF,
            (action->evaluate<Action::SetVar::EvaluateType::Remove, false, false>(transaction_)));
IMPL_ACTION(SetVar_Increase_TT,
            (action->evaluate<Action::SetVar::EvaluateType::Increase, true, true>(transaction_)));
IMPL_ACTION(SetVar_Increase_TF,
            (action->evaluate<Action::SetVar::EvaluateType::Increase, true, false>(transaction_)));
IMPL_ACTION(SetVar_Increase_FT,
            (action->evaluate<Action::SetVar::EvaluateType::Increase, false, true>(transaction_)));
IMPL_ACTION(SetVar_Increase_FF,
            (action->evaluate<Action::SetVar::EvaluateType::Increase, false, false>(transaction_)));
IMPL_ACTION(SetVar_Decrease_TT,
            (action->evaluate<Action::SetVar::EvaluateType::Decrease, true, true>(transaction_)));
IMPL_ACTION(SetVar_Decrease_TF,
            (action->evaluate<Action::SetVar::EvaluateType::Decrease, true, false>(transaction_)));
IMPL_ACTION(SetVar_Decrease_FT,
            (action->evaluate<Action::SetVar::EvaluateType::Decrease, false, true>(transaction_)));
IMPL_ACTION(SetVar_Decrease_FF,
            (action->evaluate<Action::SetVar::EvaluateType::Decrease, false, false>(transaction_)));

#undef IMPL_ACTION
#undef IMPL_ACTION_PROC

#define IMPL_UNC_ACTION_PROC(action_type)                                                          \
  void VirtualMachine::execUncAction##action_type(const Instruction& instruction) {                \
    const Action::action_type* action =                                                            \
        reinterpret_cast<const Action::action_type*>(instruction.op1_.cptr_);                      \
    action->evaluate(transaction_);                                                                \
  }
TRAVEL_ACTIONS(IMPL_UNC_ACTION_PROC);
#undef IMPL_UNC_ACTION_PROC

} // namespace Bytecode
} // namespace Wge

#undef DISPATCH