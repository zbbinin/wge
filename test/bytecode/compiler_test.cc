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
#include <gtest/gtest.h>

#include "bytecode/compiler.h"
#include "bytecode/variable_compiler.h"
#include "engine.h"
#include "rule.h"
#include "variable/variables_include.h"

namespace Wge {
namespace Bytecode {
TEST(CompilerTest, compileVariable) {
  // Just for init main thread id
  Engine engine;

  Rule rule("", 0);
  std::vector<const Rule*> rules = {&rule};

  rule.appendVariable(std::make_unique<Variable::ArgsCombinedSize>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ArgsGetNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ArgsGet>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ArgsNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ArgsPostNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ArgsPost>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::AuthType>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Duration>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Env>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FilesCombinedSize>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FilesNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FilesSizes>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FilesTmpContent>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FilesTmpNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Files>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FullRequestLength>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::FullRequest>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Geo>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Global>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::HighestSeverity>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::InboundDataError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Ip>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MatchedVarName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MatchedVar>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MatchedVarsNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MatchedVars>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ModSecBuild>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MscPcreLimitsExceeded>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartBoundaryQuoted>("", false, false, ""));
  rule.appendVariable(
      std::make_unique<Variable::MultipartBoundaryWhitespace>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartCrlfLfLines>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartDataAfter>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartDataBefore>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartFileLimitExceeded>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartFileName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartHeaderFolding>("", false, false, ""));
  rule.appendVariable(
      std::make_unique<Variable::MultipartInvalidHeaderFolding>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartInvalidPart>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartInvalidQuoting>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartLfLine>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartMissingSemicolon>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartPartHeaders>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartStrictError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::MultipartUnmatchedBoundary>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::OutboundDataError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::PathInfo>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::QueryString>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RemoteAddr>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RemoteHost>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RemotePort>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RemoteUser>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ReqBodyErrorMsg>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ReqBodyError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ReqbodyProcessorError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ReqBodyProcessor>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestBaseName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestBodyLength>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestBody>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestCookiesNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestCookies>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestFileName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestHeadersNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestHeaders>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestLine>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestMothod>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestProtocol>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestUriRaw>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::RequestUri>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Resource>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseBody>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseContentLength>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseContentType>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseHeadersNames>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseHeaders>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseProtocol>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ResponseStatus>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Rule>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ServerAddr>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ServerName>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::ServerPort>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Session>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::SessionId>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::StatusLine>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeDay>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeEpoch>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeHour>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeMin>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeMon>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeSec>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeWDay>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::TimeYear>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Time>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Tx>("", 0, false, false, ""));
  rule.appendVariable(std::make_unique<Variable::UniqueId>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::UrlenCodedError>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::User>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::UserId>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::WebAppId>("", false, false, ""));
  rule.appendVariable(std::make_unique<Variable::Xml>("", false, false, ""));

  Wge::Bytecode::Compiler compiler;
  auto program = compiler.compile(rules, nullptr);
  auto& instructions = program->instructions();

  constexpr size_t variable_count = 101;
  EXPECT_EQ(instructions.size(), variable_count);

  auto& variable_index_map = Wge::Bytecode::VariableCompiler::getVariableIndexMap();
  for (auto& instruction : instructions) {
    EXPECT_EQ(instruction.op_code_, Bytecode::OpCode::LOAD_VAR);
    EXPECT_EQ(instruction.op1_.reg_, Bytecode::Register::RDI);
    const Variable::VariableBase* var =
        reinterpret_cast<const Variable::VariableBase*>(instruction.op3_.cptr_);
    EXPECT_EQ(instruction.op2_.index_, variable_index_map.at(var->mainName().data()));
  }
}
} // namespace Bytecode
} // namespace Wge