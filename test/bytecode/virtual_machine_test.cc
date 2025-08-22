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

#include "bytecode/variable_compiler.h"
#include "bytecode/virtual_machine.h"
#include "engine.h"

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
    vm_ = std::make_unique<VirtualMachine>(*engine_.makeTransaction());
  }

public:
  Engine engine_;
  std::unique_ptr<VirtualMachine> vm_;
  const std::unordered_map<const char*, int64_t>& variable_index_map_{
      VariableCompiler::getVariableIndexMap()};
  NiceMock<Mock::MockVariable> mock_args_;
}; // namespace Bytecode

TEST_F(VirtualMachineTest, execMov) {
  Program program;
  Instruction instruction = {OpCode::MOV, Register::R8, static_cast<Register>(123456)};
  program.emit(instruction);

  vm_->execute(program);

  auto& registers = vm_->registers();
  auto& results = registers[static_cast<size_t>(Register::R8)];
  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(std::get<std::int64_t>(results.get(0).variant_), 123456);
}

TEST_F(VirtualMachineTest, execJmp) {
  Program program;
  program.emit({OpCode::JMP, static_cast<Register>(2)});
  program.emit({OpCode::MOV, Register::R8, static_cast<Register>(100)});
  program.emit({OpCode::MOV, Register::R9, static_cast<Register>(100)});

  auto& registers = vm_->registers();
  auto& r8 = registers[static_cast<size_t>(Register::R8)];
  auto& r9 = registers[static_cast<size_t>(Register::R9)];
  const_cast<Wge::Bytecode::RegisterValue&>(r8).clear();

  vm_->execute(program);

  EXPECT_EQ(r8.size(), 0);
  EXPECT_EQ(r9.size(), 1);
  EXPECT_EQ(std::get<std::int64_t>(r9.get(0).variant_), 100);
}

TEST_F(VirtualMachineTest, execJz) {
  Program program;

  program.emit({OpCode::MOV, Register::RFLAGS, static_cast<Register>(1)});
  program.emit({OpCode::JZ, static_cast<Register>(3)});
  program.emit({OpCode::MOV, Register::R8, static_cast<Register>(100)});
  program.emit({OpCode::MOV, Register::R9, static_cast<Register>(100)});

  auto& registers = vm_->registers();
  auto& r8 = registers[static_cast<size_t>(Register::R8)];
  auto& r9 = registers[static_cast<size_t>(Register::R9)];
  const_cast<Wge::Bytecode::RegisterValue&>(r8).clear();

  vm_->execute(program);

  EXPECT_EQ(r8.size(), 1);
  EXPECT_EQ(r9.size(), 1);
  EXPECT_EQ(std::get<std::int64_t>(r8.get(0).variant_), 100);
  EXPECT_EQ(std::get<std::int64_t>(r9.get(0).variant_), 100);
}

TEST_F(VirtualMachineTest, execJnz) {
  Program program;

  program.emit({OpCode::MOV, Register::RFLAGS, static_cast<Register>(1)});
  program.emit({OpCode::JNZ, static_cast<Register>(3)});
  program.emit({OpCode::MOV, Register::R8, static_cast<Register>(100)});
  program.emit({OpCode::MOV, Register::R9, static_cast<Register>(100)});

  auto& registers = vm_->registers();
  auto& r8 = registers[static_cast<size_t>(Register::R8)];
  auto& r9 = registers[static_cast<size_t>(Register::R9)];
  const_cast<Wge::Bytecode::RegisterValue&>(r8).clear();

  vm_->execute(program);

  EXPECT_EQ(r8.size(), 0);
  EXPECT_EQ(r9.size(), 1);
  EXPECT_EQ(std::get<std::int64_t>(r9.get(0).variant_), 100);
}

TEST_F(VirtualMachineTest, execNop) {
  Program program;

  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::NOP});
  program.emit({OpCode::MOV, Register::R8, static_cast<Register>(100)});
  program.emit({OpCode::NOP});
  program.emit({OpCode::MOV, Register::R9, static_cast<Register>(100)});
  program.emit({OpCode::NOP});

  auto& registers = vm_->registers();
  auto& r8 = registers[static_cast<size_t>(Register::R8)];
  auto& r9 = registers[static_cast<size_t>(Register::R9)];

  vm_->execute(program);

  EXPECT_EQ(r8.size(), 1);
  EXPECT_EQ(r9.size(), 1);
  EXPECT_EQ(std::get<std::int64_t>(r8.get(0).variant_), 100);
  EXPECT_EQ(std::get<std::int64_t>(r9.get(0).variant_), 100);
}

TEST_F(VirtualMachineTest, execLoadVar) {
  // Create a dummy program with a load variable instruction
  Program program;
  Instruction instruction = {
      OpCode::LOAD_VAR, Register::RDI,
      static_cast<Register>(variable_index_map_.at(Variable::Args::main_name_.data())),
      static_cast<Register>(reinterpret_cast<int64_t>(&mock_args_))};
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
  auto& registers = vm_->registers();
  auto& results = registers[static_cast<size_t>(Register::RDI)];
  EXPECT_EQ(results.size(), 3);
  EXPECT_EQ(std::get<std::string_view>(results.get(0).variant_), "value1");
  EXPECT_EQ(std::get<std::string_view>(results.get(1).variant_), "value2");
  EXPECT_EQ(std::get<std::string_view>(results.get(2).variant_), "value3");
}

TEST_F(VirtualMachineTest, execTransform) {
  // Create a dummy program with a load variable instruction
  Program program;
  Instruction instruction = {
      OpCode::LOAD_VAR, Register::RDI,
      static_cast<Register>(variable_index_map_.at(Variable::Args::main_name_.data())),
      static_cast<Register>(reinterpret_cast<int64_t>(&mock_args_))};
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
  auto& registers = vm_->registers();
  auto& results = registers[static_cast<size_t>(Register::RDI)];
  EXPECT_EQ(results.size(), 3);
  EXPECT_EQ(std::get<std::string_view>(results.get(0).variant_), "value1");
  EXPECT_EQ(std::get<std::string_view>(results.get(1).variant_), "value2");
  EXPECT_EQ(std::get<std::string_view>(results.get(2).variant_), "value3");
}
} // namespace Bytecode
} // namespace Wge