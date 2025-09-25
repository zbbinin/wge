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

#include "action/actions_include.h"
#include "bytecode/compiler/action_compiler.h"
#include "bytecode/compiler/macro_compiler.h"
#include "bytecode/compiler/operator_compiler.h"
#include "bytecode/compiler/rule_compiler.h"
#include "bytecode/compiler/transform_compiler.h"
#include "bytecode/compiler/variable_compiler.h"
#include "bytecode/program.h"
#include "engine.h"
#include "macro/macro_include.h"
#include "operator/operator_include.h"
#include "rule.h"
#include "transformation/transform_include.h"
#include "variable/variables_include.h"

namespace Wge {
namespace Bytecode {
class CompilerTest : public testing::Test {
public:
  const std::unordered_map<const char*, Compiler::VariableCompiler::VariableTypeInfo>&
      variable_type_info_map_{Compiler::VariableCompiler::variable_type_info_map_};
  const std::unordered_map<const char*, int64_t>& transform_index_map_{
      Compiler::TransformCompiler::transform_index_map_};
  const std::unordered_map<const char*, int64_t>& operator_index_map_{
      Compiler::OperatorCompiler::operator_index_map_};
  const std::unordered_map<const char*, int64_t>& action_index_map_{
      Compiler::ActionCompiler::action_index_map_};
  const std::unordered_map<const char*, int64_t>& macro_index_map_{
      Compiler::MacroCompiler::macro_index_map_};

public:
  Engine engine_;
};

TEST_F(CompilerTest, compileVariable) {
  // Create a rule with all variables
  Rule rule("", 0);
  rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));

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
  rule.appendVariable(std::make_unique<Variable::Rule>("id", false, false, ""));
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

  auto program =
      Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, nullptr, EngineConfig::Option::On);
  auto& instructions = program->instructions();

  size_t load_var_count = 0;
  for (auto& instruction : instructions) {
    if (instruction.op_code_ >= Bytecode::LOAD_VAR_INSTRUCTIONS_START &&
        instruction.op_code_ <= Bytecode::LOAD_VAR_INSTRUCTIONS_END) {
      ++load_var_count;
      EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::load_var_reg_);
      const Variable::VariableBase* var =
          reinterpret_cast<const Variable::VariableBase*>(instruction.op3_.cptr_);
      EXPECT_EQ(instruction.op2_.index_, variable_type_info_map_.at(var->mainName().data()).index_);
    }
  }
  EXPECT_EQ(load_var_count, rule.variables().size());
}

TEST_F(CompilerTest, compileTransform) {
  // Create a rule with all transformations
  Rule rule("", 0);
  rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));
  rule.appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
  auto& transforms = rule.transforms();

  Rule default_action("", 0);
  default_action.transforms().emplace_back(std::make_unique<Transformation::Base64DecodeExt>());
  default_action.transforms().emplace_back(std::make_unique<Transformation::Base64Decode>());
  default_action.transforms().emplace_back(std::make_unique<Transformation::Base64Encode>());
  default_action.transforms().emplace_back(std::make_unique<Transformation::CmdLine>());

  // transforms.emplace_back(std::make_unique<Transformation::Base64DecodeExt>());
  // transforms.emplace_back(std::make_unique<Transformation::Base64Decode>());
  // transforms.emplace_back(std::make_unique<Transformation::Base64Encode>());
  // transforms.emplace_back(std::make_unique<Transformation::CmdLine>());
  transforms.emplace_back(std::make_unique<Transformation::CompressWhiteSpace>());
  transforms.emplace_back(std::make_unique<Transformation::CssDecode>());
  transforms.emplace_back(std::make_unique<Transformation::EscapeSeqDecode>());
  transforms.emplace_back(std::make_unique<Transformation::HexDecode>());
  transforms.emplace_back(std::make_unique<Transformation::HexEncode>());
  transforms.emplace_back(std::make_unique<Transformation::HtmlEntityDecode>());
  transforms.emplace_back(std::make_unique<Transformation::JsDecode>());
  transforms.emplace_back(std::make_unique<Transformation::Length>());
  transforms.emplace_back(std::make_unique<Transformation::LowerCase>());
  transforms.emplace_back(std::make_unique<Transformation::Md5>());
  transforms.emplace_back(std::make_unique<Transformation::NormalisePathWin>());
  transforms.emplace_back(std::make_unique<Transformation::NormalisePath>());
  transforms.emplace_back(std::make_unique<Transformation::NormalizePathWin>());
  transforms.emplace_back(std::make_unique<Transformation::NormalizePath>());
  transforms.emplace_back(std::make_unique<Transformation::ParityEven7Bit>());
  transforms.emplace_back(std::make_unique<Transformation::ParityOdd7Bit>());
  transforms.emplace_back(std::make_unique<Transformation::ParityZero7Bit>());
  transforms.emplace_back(std::make_unique<Transformation::RemoveCommentsChar>());
  transforms.emplace_back(std::make_unique<Transformation::RemoveComments>());
  transforms.emplace_back(std::make_unique<Transformation::RemoveNulls>());
  transforms.emplace_back(std::make_unique<Transformation::RemoveWhitespace>());
  transforms.emplace_back(std::make_unique<Transformation::ReplaceComments>());
  transforms.emplace_back(std::make_unique<Transformation::ReplaceNulls>());
  transforms.emplace_back(std::make_unique<Transformation::Sha1>());
  transforms.emplace_back(std::make_unique<Transformation::SqlHexDecode>());
  transforms.emplace_back(std::make_unique<Transformation::TrimLeft>());
  transforms.emplace_back(std::make_unique<Transformation::TrimRight>());
  transforms.emplace_back(std::make_unique<Transformation::Trim>());
  transforms.emplace_back(std::make_unique<Transformation::UpperCase>());
  transforms.emplace_back(std::make_unique<Transformation::UrlDecodeUni>());
  transforms.emplace_back(std::make_unique<Transformation::UrlDecode>());
  transforms.emplace_back(std::make_unique<Transformation::UrlEncode>());
  transforms.emplace_back(std::make_unique<Transformation::Utf8ToUnicode>());

  auto program = Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, &default_action,
                                                                EngineConfig::Option::On);

  size_t count = 0;
  for (auto& instruction : program->instructions()) {
    if (instruction.op_code_ == Bytecode::OpCode::TRANSFORM) {
      ++count;
      if (count == 1) {
        EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::transform_tmp_reg1_);
        EXPECT_EQ(instruction.op2_.x_reg_, Compiler::RuleCompiler::load_var_reg_);
      } else {
        if (count % 2 == 0) {
          EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::transform_tmp_reg2_);
          EXPECT_EQ(instruction.op2_.x_reg_, Compiler::RuleCompiler::transform_tmp_reg1_);
        } else {
          EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::transform_tmp_reg1_);
          EXPECT_EQ(instruction.op2_.x_reg_, Compiler::RuleCompiler::transform_tmp_reg2_);
        }
      }

      const Transformation::TransformBase* transform =
          reinterpret_cast<const Transformation::TransformBase*>(instruction.op4_.cptr_);
      EXPECT_EQ(instruction.op3_.index_, transform_index_map_.at(transform->name()));
    }
  }
  EXPECT_EQ(count, transforms.size() + default_action.transforms().size());
}

TEST_F(CompilerTest, compileOperator) {
  std::vector<std::unique_ptr<Rule>> rules;

#define CREATE_RULE(op)                                                                            \
  rules.emplace_back(std::make_unique<Rule>("", 0));                                               \
  rules.back()->setOperator(std::make_unique<Operator::op>("", false, ""));                        \
  rules.back()->appendVariable(std::make_unique<Variable::Args>("", false, false, ""));

  CREATE_RULE(BeginsWith);
  CREATE_RULE(ContainsWord);
  CREATE_RULE(Contains);
  CREATE_RULE(DetectSqli);
  CREATE_RULE(DetectXSS);
  CREATE_RULE(EndsWith);
  CREATE_RULE(Eq);
  CREATE_RULE(FuzzyHash);
  CREATE_RULE(Ge);
  CREATE_RULE(GeoLookup);
  CREATE_RULE(Gt);
  CREATE_RULE(InspectFile);
  CREATE_RULE(IpMatchFromFile);
  CREATE_RULE(IpMatch);
  CREATE_RULE(Le);
  CREATE_RULE(Lt);
  CREATE_RULE(NoMatch);
  CREATE_RULE(PmFromFile);
  CREATE_RULE(Pm);
  CREATE_RULE(Rbl);
  CREATE_RULE(Rsub);
  CREATE_RULE(RxGlobal);
  CREATE_RULE(Rx);
  CREATE_RULE(Streq);
  CREATE_RULE(Strmatch);
  CREATE_RULE(UnconditionalMatch);
  CREATE_RULE(ValidateByteRange);
  CREATE_RULE(ValidateDTD);
  CREATE_RULE(ValidateSchema);
  CREATE_RULE(ValidateUrlEncoding);
  CREATE_RULE(ValidateUtf8Encoding);
  CREATE_RULE(VerifyCC);
  CREATE_RULE(VerifyCPF);
  CREATE_RULE(VerifySSN);
  CREATE_RULE(Within);
#undef CREATE_RULE

  std::vector<std::unique_ptr<Program>> programs;
  for (auto& rule : rules) {
    programs.emplace_back(Wge::Bytecode::Compiler::RuleCompiler::compile(rule.get(), nullptr,
                                                                         EngineConfig::Option::On));
  }

  size_t count = 0;
  for (auto& program : programs) {
    for (auto& instruction : program->instructions()) {
      if (instruction.op_code_ == Bytecode::OpCode::OPERATE) {
        ++count;
        EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::op_res_reg_);
        EXPECT_EQ(instruction.op2_.x_reg_, Compiler::RuleCompiler::load_var_reg_);
        const Operator::OperatorBase* var =
            reinterpret_cast<const Operator::OperatorBase*>(instruction.op4_.cptr_);
        EXPECT_EQ(instruction.op3_.index_, operator_index_map_.at(var->name()));
      }
    }
  }

  const size_t operator_count = rules.size();
  EXPECT_EQ(operator_count, count);
}

TEST_F(CompilerTest, compileAction) {
  // Create a rule with all actions
  Rule rule("", 0);
  rule.appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
  auto& actions = rule.actions();

  rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));

  Rule default_action("", 0);
  default_action.actions().emplace_back(std::make_unique<Action::SetUid>(""));
  default_action.actions().emplace_back(std::make_unique<Action::SetSid>(""));

  actions.emplace_back(std::make_unique<Action::Ctl>(Action::Ctl::CtlType::RuleRemoveById, 1));
  actions.emplace_back(
      std::make_unique<Action::InitCol>(PersistentStorage::Storage::Type::GLOBAL, "", ""));
  actions.emplace_back(std::make_unique<Action::SetEnv>("", ""));
  actions.emplace_back(std::make_unique<Action::SetRsc>(""));
  actions.emplace_back(std::make_unique<Action::SetSid>(""));
  actions.emplace_back(std::make_unique<Action::SetUid>(""));
  actions.emplace_back(
      std::make_unique<Action::SetVar>("", 0, 0, Action::SetVar::EvaluateType::CreateAndInit));

  auto program = Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, &default_action,
                                                                EngineConfig::Option::On);

  size_t count = 0;
  const std::vector<Bytecode::Program::ActionInfo>* action_infos = nullptr;
  for (auto& instruction : program->instructions()) {
    if (instruction.op_code_ == Bytecode::OpCode::ACTION) {
      ++count;
      EXPECT_EQ(instruction.op1_.x_reg_, Compiler::RuleCompiler::op_res_reg_);
      action_infos = reinterpret_cast<const std::vector<Bytecode::Program::ActionInfo>*>(
          instruction.op2_.cptr_);
    }
  }
  EXPECT_EQ(count, 1);
  EXPECT_EQ(action_infos, program->actionInfos(-1));
  EXPECT_EQ(action_infos->size(), default_action.actions().size() + actions.size());
}

TEST_F(CompilerTest, compileUncAction) {
  // Create a rule with all actions
  Rule rule("", 0);
  rule.appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
  auto& actions = rule.actions();

  // rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));

  Rule default_action("", 0);
  default_action.actions().emplace_back(std::make_unique<Action::SetUid>(""));
  default_action.actions().emplace_back(std::make_unique<Action::SetSid>(""));

  actions.emplace_back(std::make_unique<Action::Ctl>(Action::Ctl::CtlType::RuleRemoveById, 1));
  actions.emplace_back(
      std::make_unique<Action::InitCol>(PersistentStorage::Storage::Type::GLOBAL, "", ""));
  actions.emplace_back(std::make_unique<Action::SetEnv>("", ""));
  actions.emplace_back(std::make_unique<Action::SetRsc>(""));
  actions.emplace_back(std::make_unique<Action::SetSid>(""));
  actions.emplace_back(std::make_unique<Action::SetUid>(""));
  actions.emplace_back(
      std::make_unique<Action::SetVar>("", 0, 0, Action::SetVar::EvaluateType::CreateAndInit));

  auto program = Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, &default_action,
                                                                EngineConfig::Option::On);

  size_t count = 0;
  const std::vector<Bytecode::Program::ActionInfo>* action_infos = nullptr;
  for (auto& instruction : program->instructions()) {
    if (instruction.op_code_ == Bytecode::OpCode::UNC_ACTION) {
      ++count;
      action_infos = reinterpret_cast<const std::vector<Bytecode::Program::ActionInfo>*>(
          instruction.op1_.cptr_);
    }
  }
  EXPECT_EQ(count, 1);
  EXPECT_EQ(action_infos, program->actionInfos(-1));
  EXPECT_EQ(action_infos->size(), actions.size());
}

TEST_F(CompilerTest, compileChainRule) {
  // Create a rule with chained rules
  Rule rule("", 0);
  rule.appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
  rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));

  // Append chain rules
  constexpr size_t chain_rule_count = 20;
  Rule* parent_rule = &rule;
  for (size_t i = 0; i < chain_rule_count; ++i) {
    Rule* chain_rule = (*parent_rule->appendChainRule(0)).get();
    chain_rule->appendVariable(std::make_unique<Variable::Args>("", false, false, ""));
    chain_rule->setOperator(std::make_unique<Operator::Lt>("", false, ""));
    parent_rule = chain_rule;
  }

  auto program =
      Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, nullptr, EngineConfig::Option::On);

  size_t operator_count = 0;
  size_t jz_count = 0;
  for (auto& instruction : program->instructions()) {
    if (instruction.op_code_ == Bytecode::OpCode::OPERATE) {
      ++operator_count;
    } else if (instruction.op_code_ == Bytecode::OpCode::JZ) {
      ++jz_count;
    }
  }
  EXPECT_EQ(operator_count, chain_rule_count + 1);
  EXPECT_EQ(jz_count, chain_rule_count * 2 + 1);
}

TEST_F(CompilerTest, compileExpandMacro) {
  Rule rule("", 0);
  rule.setOperator(std::make_unique<Operator::Lt>("", false, ""));
  rule.msg(std::make_unique<Macro::MultiMacro>(std::string(),
                                               std::vector<std::shared_ptr<Macro::MacroBase>>()));
  rule.logData(std::make_unique<Macro::VariableMacro>(
      std::string(), std::make_shared<Variable::Args>("", false, false, "")));

  auto program =
      Wge::Bytecode::Compiler::RuleCompiler::compile(&rule, nullptr, EngineConfig::Option::On);

  size_t expand_macro_count = 0;
  for (auto& instruction : program->instructions()) {
    if (instruction.op_code_ == Bytecode::OpCode::EXPAND_MACRO) {
      ++expand_macro_count;
      const Macro::MacroBase* msg_macro =
          reinterpret_cast<const Macro::MacroBase*>(instruction.op2_.cptr_);
      EXPECT_EQ(instruction.op1_.index_, macro_index_map_.at(msg_macro->name()));
      const Macro::MacroBase* log_data_macro =
          reinterpret_cast<const Macro::MacroBase*>(instruction.op4_.cptr_);
      EXPECT_EQ(instruction.op3_.index_, macro_index_map_.at(log_data_macro->name()));
    }
  }
  EXPECT_EQ(expand_macro_count, 1);
}
} // namespace Bytecode
} // namespace Wge