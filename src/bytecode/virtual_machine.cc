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

#include "compiler.h"

#include "../operator/operator_include.h"
#include "../rule.h"
#include "../transformation/transform_include.h"
#include "../variable/variables_include.h"

// Dispatch the next instruction
#define DISPATCH_NEXT()                                                                            \
  do {                                                                                             \
    ++iter;                                                                                        \
    if (iter == instructions.end()) {                                                              \
      return;                                                                                      \
    }                                                                                              \
    goto* dispatch_table[static_cast<size_t>(iter->op_code_)];                                     \
  } while (0)

#define DISPATCH_NEXT_NO_ITER()                                                                    \
  do {                                                                                             \
    if (iter == instructions.end()) {                                                              \
      return;                                                                                      \
    }                                                                                              \
    goto* dispatch_table[static_cast<size_t>(iter->op_code_)];                                     \
  } while (0)

namespace Wge {
namespace Bytecode {
void VirtualMachine::execute(const Program& program) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static constexpr void* dispatch_table[] = {&&MOV, &&JMP,      &&JZ,        &&JNZ,
                                             &&NOP, &&LOAD_VAR, &&TRANSFORM, &&OPERATE};

  // Get instruction iterator
  auto& instructions = program.instructions();
  auto iter = instructions.begin();
  if (iter == instructions.end())
    [[unlikely]] { return; }

  // Dispatch first instruction
  goto* dispatch_table[static_cast<size_t>(iter->op_code_)];

MOV:
  execMov(*iter);
  DISPATCH_NEXT();
JMP:
  execJmp(*iter, instructions, iter);
  DISPATCH_NEXT_NO_ITER();
JZ:
  execJz(*iter, instructions, iter);
  DISPATCH_NEXT_NO_ITER();
JNZ:
  execJnz(*iter, instructions, iter);
  DISPATCH_NEXT_NO_ITER();
NOP:
  DISPATCH_NEXT();
LOAD_VAR:
  execLoadVar(*iter);
  DISPATCH_NEXT();
TRANSFORM:
  execTransform(*iter);
  DISPATCH_NEXT();
OPERATE:
  execOperate(*iter);
  DISPATCH_NEXT();
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
  if (!rflags_) {
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
  if (rflags_) {
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
  goto* load_var_dispatch_table[instruction.op2_.index_];

#define DISPATCH(variable)                                                                         \
  variable:                                                                                        \
  const Variable::variable* v_##variable =                                                         \
      reinterpret_cast<const Variable::variable*>(instruction.op3_.cptr_);                         \
  extra_registers_[instruction.op1_.ex_reg_].clear();                                              \
  v_##variable->evaluate(transaction_, extra_registers_[instruction.op1_.ex_reg_]);                \
  return;

  DISPATCH(ArgsCombinedSize);
  DISPATCH(ArgsGetNames);
  DISPATCH(ArgsGet);
  DISPATCH(ArgsNames);
  DISPATCH(ArgsPostNames);
  DISPATCH(ArgsPost);
  DISPATCH(Args);
  DISPATCH(AuthType);
  DISPATCH(Duration);
  DISPATCH(Env);
  DISPATCH(FilesCombinedSize);
  DISPATCH(FilesNames);
  DISPATCH(FilesSizes);
  DISPATCH(FilesTmpContent);
  DISPATCH(FilesTmpNames);
  DISPATCH(Files);
  DISPATCH(FullRequestLength);
  DISPATCH(FullRequest);
  DISPATCH(Geo);
  DISPATCH(Global);
  DISPATCH(HighestSeverity);
  DISPATCH(InboundDataError);
  DISPATCH(Ip);
  DISPATCH(MatchedVarName);
  DISPATCH(MatchedVar);
  DISPATCH(MatchedVarsNames);
  DISPATCH(MatchedVars);
  DISPATCH(ModSecBuild);
  DISPATCH(MscPcreLimitsExceeded);
  DISPATCH(MultipartBoundaryQuoted);
  DISPATCH(MultipartBoundaryWhitespace);
  DISPATCH(MultipartCrlfLfLines);
  DISPATCH(MultipartDataAfter);
  DISPATCH(MultipartDataBefore);
  DISPATCH(MultipartFileLimitExceeded);
  DISPATCH(MultipartFileName);
  DISPATCH(MultipartHeaderFolding);
  DISPATCH(MultipartInvalidHeaderFolding);
  DISPATCH(MultipartInvalidPart);
  DISPATCH(MultipartInvalidQuoting);
  DISPATCH(MultipartLfLine);
  DISPATCH(MultipartMissingSemicolon);
  DISPATCH(MultipartName);
  DISPATCH(MultipartPartHeaders);
  DISPATCH(MultipartStrictError);
  DISPATCH(MultipartUnmatchedBoundary);
  DISPATCH(OutboundDataError);
  DISPATCH(PathInfo);
  DISPATCH(QueryString);
  DISPATCH(RemoteAddr);
  DISPATCH(RemoteHost);
  DISPATCH(RemotePort);
  DISPATCH(RemoteUser);
  DISPATCH(ReqBodyErrorMsg);
  DISPATCH(ReqBodyError);
  DISPATCH(ReqbodyProcessorError);
  DISPATCH(ReqBodyProcessor);
  DISPATCH(RequestBaseName);
  DISPATCH(RequestBodyLength);
  DISPATCH(RequestBody);
  DISPATCH(RequestCookiesNames);
  DISPATCH(RequestCookies);
  DISPATCH(RequestFileName);
  DISPATCH(RequestHeadersNames);
  DISPATCH(RequestHeaders);
  DISPATCH(RequestLine);
  DISPATCH(RequestMothod);
  DISPATCH(RequestProtocol);
  DISPATCH(RequestUriRaw);
  DISPATCH(RequestUri);
  DISPATCH(Resource);
  DISPATCH(ResponseBody);
  DISPATCH(ResponseContentLength);
  DISPATCH(ResponseContentType);
  DISPATCH(ResponseHeadersNames);
  DISPATCH(ResponseHeaders);
  DISPATCH(ResponseProtocol);
  DISPATCH(ResponseStatus);
  DISPATCH(Rule);
  DISPATCH(ServerAddr);
  DISPATCH(ServerName);
  DISPATCH(ServerPort);
  DISPATCH(Session);
  DISPATCH(SessionId);
  DISPATCH(StatusLine);
  DISPATCH(TimeDay);
  DISPATCH(TimeEpoch);
  DISPATCH(TimeHour);
  DISPATCH(TimeMin);
  DISPATCH(TimeMon);
  DISPATCH(TimeSec);
  DISPATCH(TimeWDay);
  DISPATCH(TimeYear);
  DISPATCH(Time);
  DISPATCH(Tx);
  DISPATCH(UniqueId);
  DISPATCH(UrlenCodedError);
  DISPATCH(User);
  DISPATCH(UserId);
  DISPATCH(WebAppId);
  DISPATCH(Xml);

#undef DISPATCH
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
  goto* transform_dispatch_table[instruction.op3_.index_];

#define DISPATCH(transform)                                                                        \
  transform : {                                                                                    \
    const Transformation::transform* v_##transform =                                               \
        reinterpret_cast<const Transformation::transform*>(instruction.op4_.cptr_);                \
                                                                                                   \
    auto& input = extra_registers_[instruction.op2_.ex_reg_];                                      \
    auto& output = extra_registers_[instruction.op1_.ex_reg_];                                     \
    size_t input_size = input.size();                                                              \
    for (size_t i = 0; i < input_size; ++i) {                                                      \
      const Common::EvaluateResults::Element& input_element = input.get(i);                        \
      if (!IS_STRING_VIEW_VARIANT(input_element.variant_)) {                                       \
        continue;                                                                                  \
      }                                                                                            \
                                                                                                   \
      /* Check the cache */                                                                        \
      std::string_view input_data_view = std::get<std::string_view>(input_element.variant_);       \
      Common::EvaluateResults::Element output_element;                                             \
      std::optional<bool> cache_result = v_##transform->getCache(                                  \
          transaction_, input_element, v_##transform->Transformation::transform::name(),           \
          output_element);                                                                         \
      if (cache_result.has_value()) {                                                              \
        if (!*cache_result) {                                                                      \
          output_element.variant_ = input_data_view;                                               \
          output_element.variable_sub_name_ = input_element.variable_sub_name_;                    \
        }                                                                                          \
        output.append(std::move(output_element));                                                  \
        continue;                                                                                  \
      }                                                                                            \
                                                                                                   \
      /* Evaluate the transformation and store the result in the cache */                          \
      std::string output_buffer;                                                                   \
      bool ret =                                                                                   \
          v_##transform->Transformation::transform::evaluate(input_data_view, output_buffer);      \
      if (ret) {                                                                                   \
        auto& result = v_##transform->setCache(transaction_, input_data_view,                      \
                                               v_##transform->Transformation::transform::name(),   \
                                               std::move(output_buffer));                          \
        output_element.variant_ = result.variant_;                                                 \
      } else {                                                                                     \
        v_##transform->setEmptyCache(transaction_, input_data_view,                                \
                                     v_##transform->Transformation::transform::name());            \
        output_element.variant_ = input_data_view;                                                 \
      }                                                                                            \
      output_element.variable_sub_name_ = input_element.variable_sub_name_;                        \
      output.append(std::move(output_element));                                                    \
    }                                                                                              \
    return;                                                                                        \
  }

  DISPATCH(Base64DecodeExt);
  DISPATCH(Base64Decode);
  DISPATCH(Base64Encode);
  DISPATCH(CmdLine);
  DISPATCH(CompressWhiteSpace);
  DISPATCH(CssDecode);
  DISPATCH(EscapeSeqDecode);
  DISPATCH(HexDecode);
  DISPATCH(HexEncode);
  DISPATCH(HtmlEntityDecode);
  DISPATCH(JsDecode);
  DISPATCH(Length);
  DISPATCH(LowerCase);
  DISPATCH(Md5);
  DISPATCH(NormalisePathWin);
  DISPATCH(NormalisePath);
  DISPATCH(NormalizePathWin);
  DISPATCH(NormalizePath);
  DISPATCH(ParityEven7Bit);
  DISPATCH(ParityOdd7Bit);
  DISPATCH(ParityZero7Bit);
  DISPATCH(RemoveCommentsChar);
  DISPATCH(RemoveComments);
  DISPATCH(RemoveNulls);
  DISPATCH(RemoveWhitespace);
  DISPATCH(ReplaceComments);
  DISPATCH(ReplaceNulls);
  DISPATCH(Sha1);
  DISPATCH(SqlHexDecode);
  DISPATCH(TrimLeft);
  DISPATCH(TrimRight);
  DISPATCH(Trim);
  DISPATCH(UpperCase);
  DISPATCH(UrlDecodeUni);
  DISPATCH(UrlDecode);
  DISPATCH(UrlEncode);
  DISPATCH(Utf8ToUnicode);

#undef DISPATCH
}

template <class OperatorType>
void dispatchOperator(const OperatorType* op, Transaction& t, const Rule* rule,
                      const std::unique_ptr<Wge::Variable::VariableBase>* var,
                      const Common::EvaluateResults& input, Common::EvaluateResults& output) {
  size_t input_size = input.size();
  for (size_t i = 0; i < input_size; ++i) {
    auto& var_value = input.get(i).variant_;
    bool matched = op->OperatorType::evaluate(t, var_value);
    matched = op->OperatorType::isNot() ^ matched;

    // Call additional conditions if they are defined
    if (matched && t.getAdditionalCond()) {
      if (IS_STRING_VIEW_VARIANT(var_value)) {
        if (rule && var) {
          matched = t.getAdditionalCond()(*rule, std::get<std::string_view>(var_value), *var);
          WGE_LOG_TRACE("call additional condition: {}", matched);
        }
      }
    }

    if (matched) {
      auto merged_count = t.mergeCapture();
      if (merged_count) {
        std::string_view tx_0 = std::get<std::string_view>(t.getCapture(0));

        // Copy the first captured value to the capture_value. The copy is necessary because
        // the captured value may be modified later.
        output.append(std::string(tx_0.data(), tx_0.size()));
      } else {
        output.append(std::string());
      }
    } else {
      t.clearTempCapture();
    }

    WGE_LOG_TRACE("evaluate operator: {} {}@{} {} = {}", VISTIT_VARIANT_AS_STRING(var_value),
                  op->OperatorType::isNot() ? "!" : "", op->OperatorType::name(),
                  op->OperatorType::macro() ? op->OperatorType::macro()->literalValue()
                                            : op->OperatorType::literalValue(),
                  matched);
  }
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

  const Rule* curr_rule =
      reinterpret_cast<const Rule*>(general_registers_[Compiler::curr_rule_reg_]);
  const std::unique_ptr<Variable::VariableBase>* curr_var =
      reinterpret_cast<const std::unique_ptr<Variable::VariableBase>*>(
          general_registers_[Compiler::curr_variable_reg_]);
  const auto& input = extra_registers_[instruction.op2_.ex_reg_];
  auto& output = extra_registers_[instruction.op1_.ex_reg_];

  goto* operate_dispatch_table[instruction.op3_.index_];

#define DISPATCH(operator)                                                                         \
  operator                                                                                         \
      : dispatchOperator(reinterpret_cast < const Operator::operator*>(instruction.op4_.cptr_),    \
                         transaction_, curr_rule, curr_var, input, output);                        \
  return;

  DISPATCH(BeginsWith);
  DISPATCH(ContainsWord);
  DISPATCH(Contains);
  DISPATCH(DetectSqli);
  DISPATCH(DetectXSS);
  DISPATCH(EndsWith);
  DISPATCH(Eq);
  DISPATCH(FuzzyHash);
  DISPATCH(Ge);
  DISPATCH(GeoLookup);
  DISPATCH(Gt);
  DISPATCH(InspectFile);
  DISPATCH(IpMatchFromFile);
  DISPATCH(IpMatch);
  DISPATCH(Le);
  DISPATCH(Lt);
  DISPATCH(NoMatch);
  DISPATCH(PmFromFile);
  DISPATCH(Pm);
  DISPATCH(Rbl);
  DISPATCH(Rsub);
  DISPATCH(RxGlobal);
  DISPATCH(Rx);
  DISPATCH(Streq);
  DISPATCH(Strmatch);
  DISPATCH(UnconditionalMatch);
  DISPATCH(ValidateByteRange);
  DISPATCH(ValidateDTD);
  DISPATCH(ValidateSchema);
  DISPATCH(ValidateUrlEncoding);
  DISPATCH(ValidateUtf8Encoding);
  DISPATCH(VerifyCC);
  DISPATCH(VerifyCPF);
  DISPATCH(VerifySSN);
  DISPATCH(Within);

#undef DISPATCH
} // namespace Bytecode

} // namespace Bytecode
} // namespace Wge

#undef DISPATCH_NEXT
#undef REG_DST
#undef REG_SRC
#undef REG_AUX