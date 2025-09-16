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

#include <functional>
#include <unordered_map>

#include "evaluate_help.h"
#include "variable_base.h"

#include "../rule.h"

namespace Wge {
namespace Variable {
class Rule final : public VariableBase {
  DECLARE_VIRABLE_NAME(RULE);

public:
  enum class SubNameType { Unkown, Id, Phase, OperatorValue };

public:
  Rule(std::string&& sub_name, bool is_not, bool is_counter, std::string_view curr_rule_file_path)
      : VariableBase(std::move(sub_name), is_not, is_counter) {
    static std::unordered_map<std::string, SubNameType> sub_name_type_map = {
        {"id", SubNameType::Id},
        {"phase", SubNameType::Phase},
        {"operator_value", SubNameType::OperatorValue}};
    std::string sub_name_ignore_case;
    sub_name_ignore_case.reserve(sub_name_.size());
    std::transform(sub_name_.begin(), sub_name_.end(), std::back_inserter(sub_name_ignore_case),
                   ::tolower);
    auto iter = sub_name_type_map.find(sub_name_ignore_case);
    if (iter != sub_name_type_map.end()) {
      sub_name_type_ = iter->second;
    }
  }

public:
  void evaluate(Transaction& t, Common::EvaluateResults& result) const override {
    if (is_counter_) {
      evaluateBySubname<IS_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(t, result);
    } else {
      evaluateBySubname<NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(t, result);
    }
  }

private:
  template <bool is_counter, bool is_collection, bool is_regex>
  void evaluateBySubname(Transaction& t, Common::EvaluateResults& result) const {
    switch (sub_name_type_) {
    case SubNameType::Id:
      evaluate<SubNameType::Id, is_counter, is_collection, is_regex>(t, result);
      break;
    case SubNameType::Phase:
      evaluate<SubNameType::Phase, is_counter, is_collection, is_regex>(t, result);
      break;
    case SubNameType::OperatorValue:
      evaluate<SubNameType::OperatorValue, is_counter, is_collection, is_regex>(t, result);
      break;
    default:
      break;
    }
  }

public:
  template <SubNameType sub_name_type, bool is_counter, bool is_collection, bool is_regex = false>
  void evaluate(Transaction& t, Common::EvaluateResults& result) const {
    if constexpr (sub_name_type == SubNameType::Id) {
      if constexpr (is_counter) {
        result.append(t.getCurrentEvaluateRule()->id() == 0 ? 0 : 1);
      } else {
        result.append(static_cast<int64_t>(t.getCurrentEvaluateRule()->id()), "id");
      }
    } else if constexpr (sub_name_type == SubNameType::Phase) {
      if constexpr (is_counter) {
        result.append(t.getCurrentEvaluateRule()->phase() == -1 ? 0 : 1);
      } else {
        result.append(t.getCurrentEvaluateRule()->phase(), "phase");
      }
    } else if constexpr (sub_name_type == SubNameType::OperatorValue) {
      if constexpr (is_counter) {
        if (t.getCurrentEvaluateRule()->getOperator()->literalValue().empty() &&
            t.getCurrentEvaluateRule()->getOperator()->macro() == nullptr) {
          result.append(0, "operator_value");
        } else {
          result.append(1, "operator_value");
        }
      } else {
        if (!t.getCurrentEvaluateRule()->getOperator()->literalValue().empty()) {
          result.append(t.getCurrentEvaluateRule()->getOperator()->literalValue(),
                        "operator_value");
        }
      }
    }
  }

  SubNameType subNameType() const { return sub_name_type_; }

private:
  SubNameType sub_name_type_{SubNameType::Unkown};
};
} // namespace Variable
} // namespace Wge