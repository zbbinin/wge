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
#pragma once

#include <gmock/gmock.h>

#include "variable/variables_include.h"

namespace Wge {
namespace Mock {
class MockVariable : public Variable::VariableBase {
public:
  MockVariable() : VariableBase("", false, false) {
    ON_CALL(*this, evaluate(::testing::_, ::testing::_))
        .WillByDefault(::testing::Invoke([this](Transaction& t, Common::EvaluateResults& result) {
          size_t size = evaluate_results_.size();
          for (size_t i = 0; i < size; ++i) {
            result.append(evaluate_results_.get(i).variant_);
          }
        }));
    ON_CALL(*this, fullName()).WillByDefault(::testing::Return(full_name_));
    ON_CALL(*this, mainName()).WillByDefault(::testing::Return(main_name_));
    ON_CALL(*this, isCollection()).WillByDefault(::testing::Return(is_collection_));
  }

public:
  MOCK_METHOD(void, evaluate, (Transaction&, Common::EvaluateResults&), (const));
  MOCK_METHOD(Variable::FullName, fullName, (), (const));
  MOCK_METHOD(std::string_view, mainName, (), (const));
  MOCK_METHOD(bool, isCollection, (), (const));

public:
  Common::EvaluateResults evaluate_results_;
  Variable::FullName full_name_{"fake_main_name", "fake_sub_name"};
  std::string_view main_name_{"fake_main_name"};
  bool is_collection_{false};
};
} // namespace Mock
} // namespace Wge