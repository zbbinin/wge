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

#include "bytecode/operator_compiler.h"
#include "bytecode/transform_compiler.h"
#include "bytecode/variable_compiler.h"
#include "bytecode/virtual_machine.h"
#include "engine.h"
#include "operator/operator_include.h"
#include "transformation/transform_include.h"

#include "../mock/variable.h"

namespace Wge {
namespace Bytecode {

using ::testing::_;
using ::testing::NiceMock;

class VirtualMachineTest : public testing::Test {
public:
  VirtualMachineTest() : engine_(spdlog::level::off) {}

  void SetUp() override {
    engine_.init();
    t_ = engine_.makeTransaction();
    vm_ = std::make_unique<VirtualMachine>(*t_);
  }

public:
  Engine engine_;
  std::unique_ptr<VirtualMachine> vm_;
  TransactionPtr t_;
  const std::unordered_map<const char*, int64_t>& variable_index_map_{
      VariableCompiler::getVariableIndexMap()};
  const std::unordered_map<const char*, int64_t>& transform_index_map_{
      TransformCompiler::getTransformIndexMap()};
  const std::unordered_map<const char*, int64_t>& operator_index_map_{
      OperatorCompiler::getOperatorIndexMap()};
  NiceMock<Mock::MockVariable> mock_args_;
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
  // Create a dummy program with a load variable instruction
  Program program;
  Instruction instruction = {OpCode::LOAD_VAR,
                             {.ex_reg_ = ExtraRegister::R16},
                             {.index_ = variable_index_map_.at(Variable::Args::main_name_.data())},
                             {.cptr_ = &mock_args_}};
  program.emit(instruction);

  EXPECT_CALL(mock_args_, evaluate(::testing::_, ::testing::_))
      .WillOnce(::testing::Invoke([](Transaction& t, Common::EvaluateResults& result) {
        result.append(std::string("value1"));
        result.append(std::string("value2"));
        result.append(std::string("value3"));
      }));

  // Execute the program
  vm_->execute(program);

  // Check if the variable was loaded correctly
  auto& registers = vm_->extraRegisters();
  auto& results = registers[ExtraRegister::R16];
  EXPECT_EQ(results.size(), 3);
  EXPECT_EQ(std::get<std::string_view>(results.get(0).variant_), "value1");
  EXPECT_EQ(std::get<std::string_view>(results.get(1).variant_), "value2");
  EXPECT_EQ(std::get<std::string_view>(results.get(2).variant_), "value3");
}

TEST_F(VirtualMachineTest, execTransform) {
  Transformation::LowerCase lower_cast;

  // Create a dummy program with a transform instruction
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

  // Create a dummy program with a operate instruction
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

  EXPECT_EQ(res.size(), 2);
  EXPECT_EQ(std::get<std::string_view>(res.get(0).variant_), "hello");
  EXPECT_EQ(std::get<std::string_view>(res.get(1).variant_), "hello");
}
} // namespace Bytecode
} // namespace Wge