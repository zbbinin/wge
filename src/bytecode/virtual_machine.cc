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

#define REG_DST(instruction) registers_[static_cast<size_t>(instruction.dst_)]
#define REG_SRC(instruction) registers_[static_cast<size_t>(instruction.src_)]
#define REG_AUX(instruction) registers_[static_cast<size_t>(instruction.aux_)]

namespace Wge {
namespace Bytecode {
void VirtualMachine::execute(const Program& program) {
  // Dispatch table for bytecode instructions. We use computed gotos for efficiency
  static const void* dispatch_table[] = {&&MOV, &&JMP, &&JZ, &&JNZ, &&NOP, &&LOAD_VAR};

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
}

void VirtualMachine::execMov(const Instruction& instruction) {
  auto& results = REG_DST(instruction);
  results.clear();
  results.append(static_cast<int64_t>(instruction.src_));
}

void VirtualMachine::execJmp(const Instruction& instruction,
                             const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                             std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  int64_t target_address = static_cast<int64_t>(instruction.dst_);
  if (target_address < 0 || target_address >= instruction_array.size())
    [[unlikely]] { iter = instruction_array.end(); }
  else {
    iter = instruction_array.begin() + target_address;
  }
}

void VirtualMachine::execJz(const Instruction& instruction,
                            const std::vector<Wge::Bytecode::Instruction>& instruction_array,
                            std::vector<Wge::Bytecode::Instruction>::const_iterator& iter) {
  int64_t condition =
      std::get<int64_t>(registers_[static_cast<size_t>(Register::RFLAGS)].front().variant_);
  if (!condition) {
    int64_t target_address = static_cast<int64_t>(instruction.dst_);
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
  int64_t condition =
      std::get<int64_t>(registers_[static_cast<size_t>(Register::RFLAGS)].front().variant_);
  if (condition) {
    int64_t target_address = static_cast<int64_t>(instruction.dst_);
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
  static const void* load_var_dispatch_table[] = {&&ArgsCombinedSize,
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
  const int64_t index = static_cast<int64_t>(instruction.src_);
  goto* load_var_dispatch_table[index];

#define DISPATCH(variable)                                                                         \
  variable:                                                                                        \
  Variable::variable* v_##variable =                                                               \
      reinterpret_cast<Variable::variable*>(static_cast<int64_t>(instruction.aux_));               \
  REG_DST(instruction).clear();                                                                    \
  v_##variable->evaluate(transaction_, REG_DST(instruction));                                      \
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
} // namespace Bytecode
} // namespace Wge

#undef DISPATCH_NEXT
#undef REG_DST
#undef REG_SRC
#undef REG_AUX
#undef REG_DST_AS_INT64
#undef REG_SRC_AS_INT64
#undef REG_AUX_AS_INT64