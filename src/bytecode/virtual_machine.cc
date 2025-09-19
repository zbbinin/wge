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
// clang-format off
#define LOAD_VAR_LABEL(var_type)                                                                                                              \
  &&LOAD_##var_type##_CC,                                                                                                                     \
  &&LOAD_##var_type##_CS,                                                                                                                     \
  &&LOAD_##var_type##_VC,                                                                                                                     \
  &&LOAD_##var_type##_VR,                                                                                                                     \
  &&LOAD_##var_type##_VS,
  // clang-format on

  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* dispatch_table[] = {&&MOV,        &&JMP,
                                             &&JZ,         &&JNZ,
                                             &&NOP,        &&DEBUG,
                                             &&LOAD_VAR,   &&TRANSFORM,
                                             &&OPERATE,    &&ACTION,
                                             &&UNC_ACTION, &&EXPAND_MACRO,
                                             &&CHAIN,      TRAVEL_VARIABLES(LOAD_VAR_LABEL)};
#undef LOAD_VAR_LABEL
#define CASE(ins, proc, forward)                                                                   \
  ins:                                                                                             \
  WGE_LOG_TRACE("exec[{}]: {}", std::distance(begin, iter), iter->toString());                     \
  proc;                                                                                            \
  forward;                                                                                         \
  if (iter == instructions.end()) {                                                                \
    return general_registers_[GeneralRegister::RFLAGS] != 0;                                       \
  }                                                                                                \
  assert(static_cast<size_t>(iter->op_code_) < std::size(dispatch_table));                         \
  goto* dispatch_table[static_cast<size_t>(iter->op_code_)];

#define CASE_LOAD_VAR(var_type)                                                                    \
  CASE(LOAD_##var_type##_CC, execLoad##var_type##_CC(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_CS, execLoad##var_type##_CS(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VC, execLoad##var_type##_VC(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VR, execLoad##var_type##_VR(*iter), ++iter);                              \
  CASE(LOAD_##var_type##_VS, execLoad##var_type##_VS(*iter), ++iter);

  // Get instruction iterator
  auto& instructions = program.instructions();
  auto begin = instructions.begin();
  auto iter = begin;
  if (iter == instructions.end())
    [[unlikely]] { return general_registers_[GeneralRegister::RFLAGS] != 0; }

  WGE_LOG_TRACE("------------------------------------");
  WGE_LOG_TRACE("{}", [&]() {
    const Rule* rule = program.rule();
    if (rule) {
      return std::format("executing bytecode program. rule id:{} [{}:{}]", rule->id(),
                         rule->filePath(), rule->line());
    } else {
      return std::format("executing bytecode program without rule.", instructions.size());
    }
  }());

  // Reset RFLAGS
  general_registers_[GeneralRegister::RFLAGS] = 0;

  // Dispatch instructions
  DISPATCH(dispatch_table[static_cast<size_t>(iter->op_code_)]);
  CASE(MOV, execMov(*iter), ++iter);
  CASE(JMP, execJmp(*iter, instructions, iter), {});
  CASE(JZ, execJz(*iter, instructions, iter), {});
  CASE(JNZ, execJnz(*iter, instructions, iter), {});
  CASE(NOP, {}, ++iter);
  CASE(DEBUG, execDebug(*iter), ++iter);
  CASE(LOAD_VAR, execLoadVar(*iter), ++iter);
  CASE(TRANSFORM, execTransform(*iter), ++iter);
  CASE(OPERATE, execOperate(*iter), ++iter);
  CASE(ACTION, execAction(*iter), ++iter);
  CASE(UNC_ACTION, execUncAction(*iter), ++iter);
  CASE(EXPAND_MACRO, execExpandMacro(*iter), ++iter);
  CASE(CHAIN, execChain(*iter), ++iter);
  TRAVEL_VARIABLES(CASE_LOAD_VAR)
#undef CASE
}

void VirtualMachine::execMov(const Instruction& instruction) {
  general_registers_[instruction.op1_.g_reg_] = instruction.op2_.imm_;
}

void VirtualMachine::execJmp(const Instruction& instruction,
                             const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                             std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  const int64_t target_address = instruction.op1_.address_;
  if (target_address < 0 || target_address >= instruction_array.size())
    [[unlikely]] { iter = instruction_array.end(); }
  else {
    iter = instruction_array.begin() + target_address;
  }
}

void VirtualMachine::execJz(const Instruction& instruction,
                            const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                            std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  if (!general_registers_[GeneralRegister::RFLAGS]) {
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

void VirtualMachine::execJnz(const Instruction& instruction,
                             const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                             std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  if (general_registers_[GeneralRegister::RFLAGS]) {
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

inline void VirtualMachine::execDebug(const Instruction& instruction) {
  const char* msg = reinterpret_cast<const char*>(instruction.op1_.cptr_);
  WGE_LOG_DEBUG("{}", msg);
}

template <class VariableType>
void dispatchVariable(const VariableType* variable, Transaction& t,
                      Common::EvaluateResults& output) {
  variable->VariableType::evaluate(t, output);
  WGE_LOG_TRACE([&]() {
    if (!variable->VariableType::isCollection()) {
      return std::format(
          "evaluate variable: {}{}{}{} = {}", variable->VariableType::isNot() ? "!" : "",
          variable->VariableType::isCounter() ? "&" : "", variable->VariableType::mainName(),
          variable->VariableType::subName().empty() ? "" : ":" + variable->VariableType::subName(),
          VISTIT_VARIANT_AS_STRING(output.front().variant_));
    } else {
      if (variable->VariableType::isCounter()) {
        return std::format(
            "evaluate collection: {}&{} = {}", variable->VariableType::isNot() ? "!" : "",
            variable->VariableType::mainName(), VISTIT_VARIANT_AS_STRING(output.front().variant_));
      } else {
        return std::format("evaluate collection: {}{}, size: {}",
                           variable->VariableType::isNot() ? "!" : "",
                           variable->VariableType::mainName(), output.size());
      }
    }
  }());
}

void VirtualMachine::execLoadVar(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* load_var_dispatch_table[] = {&&ArgsCombinedSize,
                                                      &&ArgsGetNames,
                                                      &&ArgsGet,
                                                      &&ArgsNames,
                                                      &&ArgsPostNames,
                                                      &&ArgsPost,
                                                      &&Args,
                                                      &&AuthType,
                                                      &&Duration,
                                                      &&Env,
                                                      &&FilesCombinedSize,
                                                      &&FilesNames,
                                                      &&FilesSizes,
                                                      &&FilesTmpContent,
                                                      &&FilesTmpNames,
                                                      &&Files,
                                                      &&FullRequestLength,
                                                      &&FullRequest,
                                                      &&Geo,
                                                      &&Global,
                                                      &&HighestSeverity,
                                                      &&InboundDataError,
                                                      &&Ip,
                                                      &&MatchedVarName,
                                                      &&MatchedVar,
                                                      &&MatchedVarsNames,
                                                      &&MatchedVars,
                                                      &&ModSecBuild,
                                                      &&MscPcreLimitsExceeded,
                                                      &&MultipartBoundaryQuoted,
                                                      &&MultipartBoundaryWhitespace,
                                                      &&MultipartCrlfLfLines,
                                                      &&MultipartDataAfter,
                                                      &&MultipartDataBefore,
                                                      &&MultipartFileLimitExceeded,
                                                      &&MultipartFileName,
                                                      &&MultipartHeaderFolding,
                                                      &&MultipartInvalidHeaderFolding,
                                                      &&MultipartInvalidPart,
                                                      &&MultipartInvalidQuoting,
                                                      &&MultipartLfLine,
                                                      &&MultipartMissingSemicolon,
                                                      &&MultipartName,
                                                      &&MultipartPartHeaders,
                                                      &&MultipartStrictError,
                                                      &&MultipartUnmatchedBoundary,
                                                      &&OutboundDataError,
                                                      &&PathInfo,
                                                      &&QueryString,
                                                      &&RemoteAddr,
                                                      &&RemoteHost,
                                                      &&RemotePort,
                                                      &&RemoteUser,
                                                      &&ReqBodyErrorMsg,
                                                      &&ReqBodyError,
                                                      &&ReqbodyProcessorError,
                                                      &&ReqBodyProcessor,
                                                      &&RequestBaseName,
                                                      &&RequestBodyLength,
                                                      &&RequestBody,
                                                      &&RequestCookiesNames,
                                                      &&RequestCookies,
                                                      &&RequestFileName,
                                                      &&RequestHeadersNames,
                                                      &&RequestHeaders,
                                                      &&RequestLine,
                                                      &&RequestMothod,
                                                      &&RequestProtocol,
                                                      &&RequestUriRaw,
                                                      &&RequestUri,
                                                      &&Resource,
                                                      &&ResponseBody,
                                                      &&ResponseContentLength,
                                                      &&ResponseContentType,
                                                      &&ResponseHeadersNames,
                                                      &&ResponseHeaders,
                                                      &&ResponseProtocol,
                                                      &&ResponseStatus,
                                                      &&Rule,
                                                      &&ServerAddr,
                                                      &&ServerName,
                                                      &&ServerPort,
                                                      &&Session,
                                                      &&SessionId,
                                                      &&StatusLine,
                                                      &&TimeDay,
                                                      &&TimeEpoch,
                                                      &&TimeHour,
                                                      &&TimeMin,
                                                      &&TimeMon,
                                                      &&TimeSec,
                                                      &&TimeWDay,
                                                      &&TimeYear,
                                                      &&Time,
                                                      &&Tx,
                                                      &&UniqueId,
                                                      &&UrlenCodedError,
                                                      &&User,
                                                      &&UserId,
                                                      &&WebAppId,
                                                      &&Xml};
#define CASE(variable)                                                                             \
  variable:                                                                                        \
  dispatchVariable(reinterpret_cast<const Variable::variable*>(instruction.op3_.cptr_),            \
                   transaction_, output);                                                          \
  return;

  auto& output = extended_registers_[instruction.op1_.x_reg_];
  output.clear();

  DISPATCH(load_var_dispatch_table[instruction.op2_.index_]);
  CASE(ArgsCombinedSize);
  CASE(ArgsGetNames);
  CASE(ArgsGet);
  CASE(ArgsNames);
  CASE(ArgsPostNames);
  CASE(ArgsPost);
  CASE(Args);
  CASE(AuthType);
  CASE(Duration);
  CASE(Env);
  CASE(FilesCombinedSize);
  CASE(FilesNames);
  CASE(FilesSizes);
  CASE(FilesTmpContent);
  CASE(FilesTmpNames);
  CASE(Files);
  CASE(FullRequestLength);
  CASE(FullRequest);
  CASE(Geo);
  CASE(Global);
  CASE(HighestSeverity);
  CASE(InboundDataError);
  CASE(Ip);
  CASE(MatchedVarName);
  CASE(MatchedVar);
  CASE(MatchedVarsNames);
  CASE(MatchedVars);
  CASE(ModSecBuild);
  CASE(MscPcreLimitsExceeded);
  CASE(MultipartBoundaryQuoted);
  CASE(MultipartBoundaryWhitespace);
  CASE(MultipartCrlfLfLines);
  CASE(MultipartDataAfter);
  CASE(MultipartDataBefore);
  CASE(MultipartFileLimitExceeded);
  CASE(MultipartFileName);
  CASE(MultipartHeaderFolding);
  CASE(MultipartInvalidHeaderFolding);
  CASE(MultipartInvalidPart);
  CASE(MultipartInvalidQuoting);
  CASE(MultipartLfLine);
  CASE(MultipartMissingSemicolon);
  CASE(MultipartName);
  CASE(MultipartPartHeaders);
  CASE(MultipartStrictError);
  CASE(MultipartUnmatchedBoundary);
  CASE(OutboundDataError);
  CASE(PathInfo);
  CASE(QueryString);
  CASE(RemoteAddr);
  CASE(RemoteHost);
  CASE(RemotePort);
  CASE(RemoteUser);
  CASE(ReqBodyErrorMsg);
  CASE(ReqBodyError);
  CASE(ReqbodyProcessorError);
  CASE(ReqBodyProcessor);
  CASE(RequestBaseName);
  CASE(RequestBodyLength);
  CASE(RequestBody);
  CASE(RequestCookiesNames);
  CASE(RequestCookies);
  CASE(RequestFileName);
  CASE(RequestHeadersNames);
  CASE(RequestHeaders);
  CASE(RequestLine);
  CASE(RequestMothod);
  CASE(RequestProtocol);
  CASE(RequestUriRaw);
  CASE(RequestUri);
  CASE(Resource);
  CASE(ResponseBody);
  CASE(ResponseContentLength);
  CASE(ResponseContentType);
  CASE(ResponseHeadersNames);
  CASE(ResponseHeaders);
  CASE(ResponseProtocol);
  CASE(ResponseStatus);
  CASE(Rule);
  CASE(ServerAddr);
  CASE(ServerName);
  CASE(ServerPort);
  CASE(Session);
  CASE(SessionId);
  CASE(StatusLine);
  CASE(TimeDay);
  CASE(TimeEpoch);
  CASE(TimeHour);
  CASE(TimeMin);
  CASE(TimeMon);
  CASE(TimeSec);
  CASE(TimeWDay);
  CASE(TimeYear);
  CASE(Time);
  CASE(Tx);
  CASE(UniqueId);
  CASE(UrlenCodedError);
  CASE(User);
  CASE(UserId);
  CASE(WebAppId);
  CASE(Xml);
#undef CASE
}

template <class TransformType>
void dispatchTransform(const TransformType* transform, Transaction& t,
                       const std::unique_ptr<Wge::Variable::VariableBase>* curr_var,
                       const Common::EvaluateResults& input, Common::EvaluateResults& output) {
  size_t input_size = input.size();
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

void VirtualMachine::execTransform(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* transform_dispatch_table[] = {&&Base64DecodeExt,    &&Base64Decode,
                                                       &&Base64Encode,       &&CmdLine,
                                                       &&CompressWhiteSpace, &&CssDecode,
                                                       &&EscapeSeqDecode,    &&HexDecode,
                                                       &&HexEncode,          &&HtmlEntityDecode,
                                                       &&JsDecode,           &&Length,
                                                       &&LowerCase,          &&Md5,
                                                       &&NormalisePathWin,   &&NormalisePath,
                                                       &&NormalizePathWin,   &&NormalizePath,
                                                       &&ParityEven7Bit,     &&ParityOdd7Bit,
                                                       &&ParityZero7Bit,     &&RemoveCommentsChar,
                                                       &&RemoveComments,     &&RemoveNulls,
                                                       &&RemoveWhitespace,   &&ReplaceComments,
                                                       &&ReplaceNulls,       &&Sha1,
                                                       &&SqlHexDecode,       &&TrimLeft,
                                                       &&TrimRight,          &&Trim,
                                                       &&UpperCase,          &&UrlDecodeUni,
                                                       &&UrlDecode,          &&UrlEncode,
                                                       &&Utf8ToUnicode};
#define CASE(transform)                                                                            \
  transform:                                                                                       \
  dispatchTransform(reinterpret_cast<const Transformation::transform*>(instruction.op4_.cptr_),    \
                    transaction_, curr_var, input, output);                                        \
  return;

  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);
  const auto& input = extended_registers_[instruction.op2_.x_reg_];
  auto& output = extended_registers_[instruction.op1_.x_reg_];
  output.clear();

  DISPATCH(transform_dispatch_table[instruction.op3_.index_]);
  CASE(Base64DecodeExt);
  CASE(Base64Decode);
  CASE(Base64Encode);
  CASE(CmdLine);
  CASE(CompressWhiteSpace);
  CASE(CssDecode);
  CASE(EscapeSeqDecode);
  CASE(HexDecode);
  CASE(HexEncode);
  CASE(HtmlEntityDecode);
  CASE(JsDecode);
  CASE(Length);
  CASE(LowerCase);
  CASE(Md5);
  CASE(NormalisePathWin);
  CASE(NormalisePath);
  CASE(NormalizePathWin);
  CASE(NormalizePath);
  CASE(ParityEven7Bit);
  CASE(ParityOdd7Bit);
  CASE(ParityZero7Bit);
  CASE(RemoveCommentsChar);
  CASE(RemoveComments);
  CASE(RemoveNulls);
  CASE(RemoveWhitespace);
  CASE(ReplaceComments);
  CASE(ReplaceNulls);
  CASE(Sha1);
  CASE(SqlHexDecode);
  CASE(TrimLeft);
  CASE(TrimRight);
  CASE(Trim);
  CASE(UpperCase);
  CASE(UrlDecodeUni);
  CASE(UrlDecode);
  CASE(UrlEncode);
  CASE(Utf8ToUnicode);
#undef CASE
}

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

void VirtualMachine::execOperate(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* operate_dispatch_table[] = {&&BeginsWith,
                                                     &&ContainsWord,
                                                     &&Contains,
                                                     &&DetectSqli,
                                                     &&DetectXSS,
                                                     &&EndsWith,
                                                     &&Eq,
                                                     &&FuzzyHash,
                                                     &&Ge,
                                                     &&GeoLookup,
                                                     &&Gt,
                                                     &&InspectFile,
                                                     &&IpMatchFromFile,
                                                     &&IpMatch,
                                                     &&Le,
                                                     &&Lt,
                                                     &&NoMatch,
                                                     &&PmFromFile,
                                                     &&Pm,
                                                     &&Rbl,
                                                     &&Rsub,
                                                     &&RxGlobal,
                                                     &&Rx,
                                                     &&Streq,
                                                     &&Strmatch,
                                                     &&UnconditionalMatch,
                                                     &&ValidateByteRange,
                                                     &&ValidateDTD,
                                                     &&ValidateSchema,
                                                     &&ValidateUrlEncoding,
                                                     &&ValidateUtf8Encoding,
                                                     &&VerifyCC,
                                                     &&VerifyCPF,
                                                     &&VerifySSN,
                                                     &&Within};
#define CASE(operator)                                                                             \
  operator: matched = dispatchOperator(reinterpret_cast <                                          \
                                           const Operator::operator*>(instruction.op4_.cptr_),     \
                                       transaction_, curr_rule, curr_var, input, output);          \
  general_registers_[GeneralRegister::RFLAGS] |= matched;                                          \
  return;

  const Rule* curr_rule =
      reinterpret_cast<const Rule*>(general_registers_[Compiler::RuleCompiler::curr_rule_reg_]);
  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);
  const auto& input = extended_registers_[instruction.op2_.x_reg_];
  auto& output = extended_registers_[instruction.op1_.x_reg_];
  output.clear();
  bool matched = false;

  DISPATCH(operate_dispatch_table[instruction.op3_.index_]);
  CASE(BeginsWith);
  CASE(ContainsWord);
  CASE(Contains);
  CASE(DetectSqli);
  CASE(DetectXSS);
  CASE(EndsWith);
  CASE(Eq);
  CASE(FuzzyHash);
  CASE(Ge);
  CASE(GeoLookup);
  CASE(Gt);
  CASE(InspectFile);
  CASE(IpMatchFromFile);
  CASE(IpMatch);
  CASE(Le);
  CASE(Lt);
  CASE(NoMatch);
  CASE(PmFromFile);
  CASE(Pm);
  CASE(Rbl);
  CASE(Rsub);
  CASE(RxGlobal);
  CASE(Rx);
  CASE(Streq);
  CASE(Strmatch);
  CASE(UnconditionalMatch);
  CASE(ValidateByteRange);
  CASE(ValidateDTD);
  CASE(ValidateSchema);
  CASE(ValidateUrlEncoding);
  CASE(ValidateUtf8Encoding);
  CASE(VerifyCC);
  CASE(VerifyCPF);
  CASE(VerifySSN);
  CASE(Within);
#undef CASE
}

template <class ActionType> void dispatchAction(const ActionType* action, Transaction& t) {
  action->ActionType::evaluate(t);
}

void VirtualMachine::execAction(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* action_dispatch_table[] = {&&Ctl,    &&InitCol, &&SetEnv, &&SetRsc,
                                                    &&SetSid, &&SetUid,  &&SetVar};
#define CASE(action)                                                                               \
  action:                                                                                          \
  dispatchAction(reinterpret_cast<const Action::action*>(action_info.action_), transaction_);      \
  continue;

  const Rule* curr_rule =
      reinterpret_cast<const Rule*>(general_registers_[Compiler::RuleCompiler::curr_rule_reg_]);
  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::RuleCompiler::curr_variable_reg_]);
  auto& operate_results = extended_registers_[instruction.op1_.x_reg_];
  auto& original_value = extended_registers_[Compiler::RuleCompiler::load_var_reg_];
  auto& transformed_value = extended_registers_[static_cast<ExtendedRegister>(
      general_registers_[Compiler::RuleCompiler::op_src_reg_])];
  const std::vector<Program::ActionInfo>& action_infos =
      *reinterpret_cast<const std::vector<Program::ActionInfo>*>(instruction.op2_.cptr_);

  assert(operate_results.size() == original_value.size());
  assert(original_value.size() == transformed_value.size());

  size_t operate_results_size = operate_results.size();
  for (size_t i = 0; i < operate_results_size; ++i) {
    // Not matched
    if (IS_INT_VARIANT(operate_results.get(i).variant_)) {
      continue;
    }

    // TODO(zhouyu 2025-09-02): fix the transformation list
    std::list<const Transformation::TransformBase*> transform_list;

    transaction_.pushMatchedVariable((*curr_var).get(), curr_rule->chainIndex(),
                                     original_value.move(i), transformed_value.move(i),
                                     operate_results.move(i), std::move(transform_list));

    for (auto& action_info : action_infos) {
      DISPATCH(action_dispatch_table[action_info.index_]);
      CASE(Ctl);
      CASE(InitCol);
      CASE(SetEnv);
      CASE(SetRsc);
      CASE(SetSid);
      CASE(SetUid);
      CASE(SetVar);
    }
  }
#undef CASE
}

void VirtualMachine::execUncAction(const Instruction& instruction) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* action_dispatch_table[] = {&&Ctl,    &&InitCol, &&SetEnv, &&SetRsc,
                                                    &&SetSid, &&SetUid,  &&SetVar};

#define CASE(action)                                                                               \
  action:                                                                                          \
  dispatchAction(reinterpret_cast<const Action::action*>(action_info.action_), transaction_);      \
  continue;

  const std::vector<Program::ActionInfo>& action_infos =
      *reinterpret_cast<const std::vector<Program::ActionInfo>*>(instruction.op1_.cptr_);
  for (auto& action_info : action_infos) {
    DISPATCH(action_dispatch_table[action_info.index_]);
    CASE(Ctl);
    CASE(InitCol);
    CASE(SetEnv);
    CASE(SetRsc);
    CASE(SetSid);
    CASE(SetUid);
    CASE(SetVar);
  }
#undef CASE
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

void VirtualMachine::execChain(const Instruction& instruction) {
  // Reset RFLAGS
  general_registers_[GeneralRegister::RFLAGS] = 0;
  WGE_LOG_TRACE("start of rule chain execution");
  WGE_LOG_TRACE("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓");
}

#define IMPL(var_type, proc)                                                                       \
  const Variable::var_type* v =                                                                    \
      reinterpret_cast<const Variable::var_type*>(instruction.op3_.cptr_);                         \
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
#undef IMPL_LOAD_VAR_PROCESSOR
#undef IMPL_LOAD_VAR_PROCESSOR_PROC
} // namespace Bytecode
} // namespace Wge

#undef DISPATCH