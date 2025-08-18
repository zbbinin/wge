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
      Compiler::getVariableIndexMap()};
  NiceMock<Mock::MockVariable> mock_args_;
}; // namespace Bytecode

TEST_F(VirtualMachineTest, executeLoadVar) {
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