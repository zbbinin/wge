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
#include "bytecode/compiler/operator_compiler.h"
#include "bytecode/compiler/rule_compiler.h"
#include "bytecode/compiler/transform_compiler.h"
#include "bytecode/compiler/variable_compiler.h"
#include "bytecode/virtual_machine.h"
#include "engine.h"
#include "operator/operator_include.h"
#include "transformation/transform_include.h"
#include "variable/variables_include.h"

namespace Wge {
namespace Bytecode {
class VirtualMachineTest : public testing::Test {
public:
  VirtualMachineTest() : engine_(spdlog::level::off) {}

  void SetUp() override {
    engine_.init();
    t_ = engine_.makeTransaction();
    vm_ = std::make_unique<VirtualMachine>(*t_);
    tx_variables_ = &(t_->tx_variables_);
  }

public:
  Engine engine_;
  std::unique_ptr<VirtualMachine> vm_;
  TransactionPtr t_;
  const std::unordered_map<const char*, int64_t>& variable_index_map_{
      Compiler::VariableCompiler::variable_index_map_};
  const std::unordered_map<const char*, int64_t>& transform_index_map_{
      Compiler::TransformCompiler::transform_index_map_};
  const std::unordered_map<const char*, int64_t>& operator_index_map_{
      Compiler::OperatorCompiler::operator_index_map_};
  const std::unordered_map<const char*, int64_t>& action_index_map_{
      Compiler::ActionCompiler::action_index_map_};
  std::vector<Common::EvaluateResults::Element>* tx_variables_{nullptr};
}; // namespace Bytecode

TEST_F(VirtualMachineTest, execMov) {
  Program program;
  Instruction instruction = {OpCode::MOV, {.g_reg_ = GeneralRegister::RAX}, {.imm_ = 123456}};
  program.emit(instruction);

  vm_->execute(program);

  auto& registers = vm_->generalRegisters();
  EXPECT_EQ(registers[GeneralRegister::RAX], 123456);
}

TEST_F(VirtualMachineTest, execJmp) {
  Program program;
  program.emit({OpCode::JMP, {.address_ = 2}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RAX}, {.imm_ = 100}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RBX}, {.imm_ = 100}});

  auto& registers = vm_->generalRegisters();
  registers[GeneralRegister::RAX] = 0;
  registers[GeneralRegister::RBX] = 0;

  vm_->execute(program);

  EXPECT_EQ(registers[GeneralRegister::RAX], 0);
  EXPECT_EQ(registers[GeneralRegister::RBX], 100);
}

TEST_F(VirtualMachineTest, execJz) {
  Program program;

  vm_->rflags() = 1;

  program.emit({OpCode::JZ, {.address_ = 2}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RAX}, {.imm_ = 100}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RBX}, {.imm_ = 100}});

  auto& registers = vm_->generalRegisters();
  registers[GeneralRegister::RAX] = 0;
  registers[GeneralRegister::RBX] = 0;

  vm_->execute(program);

  EXPECT_EQ(registers[GeneralRegister::RAX], 100);
  EXPECT_EQ(registers[GeneralRegister::RBX], 100);
}

TEST_F(VirtualMachineTest, execJnz) {
  Program program;

  vm_->rflags() = 1;

  program.emit({OpCode::JNZ, {.address_ = 2}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RAX}, {.imm_ = 100}});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RBX}, {.imm_ = 100}});

  auto& registers = vm_->generalRegisters();
  registers[GeneralRegister::RAX] = 0;
  registers[GeneralRegister::RBX] = 0;

  vm_->execute(program);

  EXPECT_EQ(registers[GeneralRegister::RAX], 0);
  EXPECT_EQ(registers[GeneralRegister::RBX], 100);
}

TEST_F(VirtualMachineTest, execNop) {
  Program program;

  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RAX}, {.imm_ = 100}});
  program.emit({OpCode::NOP});
  program.emit({OpCode::MOV, {.g_reg_ = GeneralRegister::RBX}, {.imm_ = 100}});
  program.emit({OpCode::NOP});

  auto& registers = vm_->generalRegisters();
  registers[GeneralRegister::RAX] = 0;
  registers[GeneralRegister::RBX] = 0;

  vm_->execute(program);

  EXPECT_EQ(registers[GeneralRegister::RAX], 100);
  EXPECT_EQ(registers[GeneralRegister::RBX], 100);
}

TEST_F(VirtualMachineTest, execLoadVar) {
  Variable::Args args("", false, false, "");

  // Mock the request processing to extract query parameters
  t_->processUri("GET /?a=value1&b=value2&c=value3 HTTP/1.1");

  // Create a dummy program with LOAD_VAR instruction
  Program program;
  Instruction instruction = {OpCode::LOAD_VAR,
                             {.ex_reg_ = ExtraRegister::R16},
                             {.index_ = variable_index_map_.at(Variable::Args::main_name_.data())},
                             {.cptr_ = &args}};
  program.emit(instruction);

  // Execute the program
  vm_->execute(program);

  // Check if the variable was loaded correctly
  auto& dst = vm_->extraRegisters()[ExtraRegister::R16];
  EXPECT_EQ(dst.size(), 3);
  EXPECT_EQ(std::get<std::string_view>(dst.get(0).variant_), "value1");
  EXPECT_EQ(std::get<std::string_view>(dst.get(1).variant_), "value2");
  EXPECT_EQ(std::get<std::string_view>(dst.get(2).variant_), "value3");
}

TEST_F(VirtualMachineTest, execTransform) {
  Transformation::LowerCase lower_cast;

  // Create a dummy program with TRANSFORM instruction
  Program program;
  Instruction instruction = {OpCode::TRANSFORM,
                             {.ex_reg_ = ExtraRegister::R17},
                             {.ex_reg_ = ExtraRegister::R16},
                             {.imm_ = transform_index_map_.at(lower_cast.name_)},
                             {.cptr_ = &lower_cast}};
  program.emit(instruction);

  // Initialize registers
  auto& src = vm_->extraRegisters()[ExtraRegister::R16];
  auto& dst = vm_->extraRegisters()[ExtraRegister::R17];
  src.clear();
  dst.clear();
  src.append(std::string("VALUE1"), "sub1");
  src.append(std::string("VALUE2"), "sub2");
  src.append(std::string("VALUE3"), "sub3");

  vm_->execute(program);

  EXPECT_EQ(dst.size(), 3);
  EXPECT_EQ(std::get<std::string_view>(dst.get(0).variant_), "value1");
  EXPECT_EQ(std::get<std::string_view>(dst.get(1).variant_), "value2");
  EXPECT_EQ(std::get<std::string_view>(dst.get(2).variant_), "value3");
}

TEST_F(VirtualMachineTest, execOperate) {
  Operator::Rx rx(std::string("hello"), false, "");

  // Create a dummy program with OPERATE instruction
  Program program;
  Instruction instruction = {OpCode::OPERATE,
                             {.ex_reg_ = ExtraRegister::R17},
                             {.ex_reg_ = ExtraRegister::R16},
                             {.imm_ = operator_index_map_.at(rx.name_)},
                             {.cptr_ = &rx}};
  program.emit(instruction);

  // Initialize registers
  auto& src = vm_->extraRegisters()[ExtraRegister::R16];
  auto& res = vm_->extraRegisters()[ExtraRegister::R17];
  src.clear();
  res.clear();
  src.append(std::string("helloworld"), "sub1");
  src.append(std::string("111helloworld222"), "sub2");
  src.append(std::string("111world222"), "sub3");

  vm_->execute(program);

  EXPECT_EQ(res.size(), src.size());
  EXPECT_EQ(std::get<std::string_view>(res.get(0).variant_), "hello");
  EXPECT_EQ(std::get<std::string_view>(res.get(1).variant_), "hello");
  EXPECT_EQ(std::get<int64_t>(res.get(2).variant_), 0);
}

TEST_F(VirtualMachineTest, execAction) {
  // Create a SetVar instance
  std::vector<std::unique_ptr<Action::ActionBase>> actions;
  actions.emplace_back(
      std::make_unique<Action::SetVar>("foo", 0, 1, Action::SetVar::EvaluateType::Increase));

  // Create a dummy program with ACTION instruction
  Program program;
  Compiler::ActionCompiler::initProgramActionInfo(-1, nullptr, &actions, program);
  Instruction instruction = {OpCode::ACTION,
                             {.ex_reg_ = Compiler::RuleCompiler::op_res_reg_},
                             {.cptr_ = program.actionInfos(-1)}};
  program.emit(instruction);

  // Mock the transaction variables
  tx_variables_->resize(1);

  // Mock the current rule and current variable
  Wge::Rule rule("", 0);
  std::unique_ptr<Wge::Variable::Args> var_args =
      std::make_unique<Wge::Variable::Args>("", false, false, "");
  vm_->generalRegisters()[Compiler::RuleCompiler::curr_rule_reg_] =
      reinterpret_cast<int64_t>(&rule);
  vm_->generalRegisters()[Compiler::RuleCompiler::curr_variable_reg_] =
      reinterpret_cast<int64_t>(&var_args);

  // Mock the original value(results of LOAD_VAR)
  auto& original_value = vm_->extraRegisters()[Compiler::RuleCompiler::load_var_reg_];
  original_value.append(std::string("HELLOWORLD"));
  original_value.append(std::string("--HELLOWORLD--"));
  original_value.append(std::string("--HELLO--"));

  // Mock the transformed value(the input of OPERATE)
  auto& transform_value = vm_->extraRegisters()[ExtraRegister::R17];
  transform_value.append(std::string("helloworld"));
  transform_value.append(std::string("--helloworld--"));
  transform_value.append(std::string("--hello--"));
  vm_->generalRegisters()[Compiler::RuleCompiler::op_src_reg_] =
      static_cast<GeneralRegisterValue>(ExtraRegister::R17);

  // Mock the results of OPERATE(capture string)
  auto& src = vm_->extraRegisters()[Compiler::RuleCompiler::op_res_reg_];
  src.clear();
  src.append(std::string("hello"));
  src.append(std::string("hello"));
  src.append(std::string("hello"));

  vm_->execute(program);

  // Check if the set_var was applied correctly
  EXPECT_EQ(std::get<int64_t>(static_cast<const Transaction&>(*t_).getVariable(0)), 3);

  // Check if the MATCHED_VARS were updated correctly
  auto& matched_vars = t_->getMatchedVariables(-1);
  EXPECT_EQ(matched_vars.size(), 3);
  EXPECT_EQ(matched_vars[0].variable_, var_args.get());
  EXPECT_EQ(matched_vars[1].variable_, var_args.get());
  EXPECT_EQ(matched_vars[2].variable_, var_args.get());
  EXPECT_EQ(std::get<std::string_view>(matched_vars[0].original_value_.variant_), "HELLOWORLD");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[1].original_value_.variant_), "--HELLOWORLD--");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[2].original_value_.variant_), "--HELLO--");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[0].transformed_value_.variant_), "helloworld");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[1].transformed_value_.variant_),
            "--helloworld--");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[2].transformed_value_.variant_), "--hello--");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[0].captured_value_.variant_), "hello");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[1].captured_value_.variant_), "hello");
  EXPECT_EQ(std::get<std::string_view>(matched_vars[2].captured_value_.variant_), "hello");
}

TEST_F(VirtualMachineTest, execUncAction) {
  // Create a SetVar instance
  std::vector<std::unique_ptr<Action::ActionBase>> actions;
  actions.emplace_back(
      std::make_unique<Action::SetVar>("foo", 0, 3, Action::SetVar::EvaluateType::CreateAndInit));

  // Create a dummy program with ACTION instruction
  Program program;
  Compiler::ActionCompiler::initProgramActionInfo(-1, nullptr, &actions, program);
  Instruction instruction = {OpCode::UNC_ACTION, {.cptr_ = program.actionInfos(-1)}};
  program.emit(instruction);

  // Mock the transaction variables
  tx_variables_->resize(1);
  t_->setVariable(0, Common::Variant(0));

  vm_->execute(program);

  // Check if the set_var was applied correctly
  EXPECT_EQ(std::get<int64_t>(static_cast<const Transaction&>(*t_).getVariable(0)), 3);
}

} // namespace Bytecode
} // namespace Wge