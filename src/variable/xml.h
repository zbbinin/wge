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

#include "collection_base.h"
#include "evaluate_help.h"
#include "variable_base.h"

namespace Wge {
namespace Variable {
/**
 * XML variable. Supports the following syntax:
 * - `XML://@*` for all attributes of all tags. When filling Common::EvaluateResults, each element
 * corresponds to the attribute value of a tag.
 * - `XML:/*` for all tag values. When filling Common::EvaluateResults, there is only one element,
 * which concatenates all XML tag values into a string.
 * - `XML://@*@file@` for multi-pattern matching of attributes based on the specified file. When
 * filling Common::EvaluateResults, each element corresponds to the attribute value of a tag.
 * - `XML:/*@file@` for multi-pattern matching of tag values based on the specified file. When
 * filling Common::EvaluateResults, each element corresponds to the value of a tag.
 */
class Xml final : public VariableBase, public CollectionBase {
  DECLARE_VIRABLE_NAME(XML);

public:
  Xml(std::string&& sub_name, bool is_not, bool is_counter, std::string_view curr_rule_file_path)
      : VariableBase(std::move(sub_name), is_not, is_counter),
        CollectionBase(
            [&]() -> std::string {
              std::string collection_sub_name;
              if (sub_name_ == "//@*") {
                type_ = Type::AttrValue;
              } else if (sub_name_ == "/*") {
                type_ = Type::TagValue;
              } else if (sub_name_.ends_with("@")) {
                if (sub_name_.starts_with("//@*@")) {
                  type_ = Type::AttrValuePmf;
                  collection_sub_name = sub_name_.substr(4);
                } else if (sub_name_.starts_with("/*@")) {
                  type_ = Type::TagValuePmf;
                  collection_sub_name = sub_name_.substr(2);
                }
              }

              return collection_sub_name;
            }(),
            curr_rule_file_path) {}

public:
  enum class Type { AttrValue, TagValue, AttrValuePmf, TagValuePmf };

public:
  void evaluate(Transaction& t, Common::EvaluateResults& result) const override {
    RETURN_IF_COUNTER(
        // collection
        { (evaluate<Type::AttrValue, IS_COUNTER, IS_COLLECTION>(t, result)); },
        // specify subname
        { (evaluate<Type::AttrValue, IS_COUNTER, NOT_COLLECTION>(t, result)); });

    RETURN_VALUE(
        // collection
        { (evaluateByType<NOT_COUNTER, IS_COLLECTION, NOT_REGEX_COLLECTION>(t, result)); },
        // collection regex
        { (evaluateByType<NOT_COUNTER, IS_COLLECTION, IS_REGEX_COLLECTION>(t, result)); },
        // specify subname
        { (evaluateByType<NOT_COUNTER, NOT_COLLECTION, NOT_REGEX_COLLECTION>(t, result)); });
  }

  bool isCollection() const override { return true; };

private:
  template <bool is_counter, bool is_collection, bool is_regex>
  void evaluateByType(Transaction& t, Common::EvaluateResults& result) const {
    switch (type_) {
    case Type::AttrValue:
      evaluate<Type::AttrValue, is_counter, is_collection, is_regex>(t, result);
      break;
    case Type::TagValue:
      evaluate<Type::TagValue, is_counter, is_collection, is_regex>(t, result);
      break;
    case Type::AttrValuePmf:
      evaluate<Type::AttrValuePmf, is_counter, is_collection, is_regex>(t, result);
      break;
    case Type::TagValuePmf:
      evaluate<Type::TagValuePmf, is_counter, is_collection, is_regex>(t, result);
      break;
    default:
      UNREACHABLE();
    }
  }

public:
  template <Type type, bool is_counter, bool is_collection, bool is_regex = false>
  void evaluate(Transaction& t, Common::EvaluateResults& result) const {
    const std::vector<std::pair<std::string_view, std::string_view>>* kv_pairs = nullptr;
    if constexpr (type == Type::TagValue || type == Type::TagValuePmf) {
      kv_pairs = &(t.getBodyXml().getTags());
    } else {
      kv_pairs = &(t.getBodyXml().getAttributes());
    }

    RETURN_IF_COUNTER_CT(
        // collection
        { result.append(static_cast<int64_t>(kv_pairs->size())); },
        // specify subname
        { result.append(static_cast<int64_t>(kv_pairs->size())); });

    if constexpr (type == Type::AttrValue) {
      RETURN_VALUE_CT(
          // collection
          {
            for (auto& elem : *kv_pairs) {
              result.append(elem.second);
            }
          },
          // collection regex
          { UNREACHABLE(); },
          // specify subname
          {
            for (auto& elem : *kv_pairs) {
              result.append(elem.second);
            }
          });
    } else if constexpr (type == Type::TagValue) {
      RETURN_VALUE_CT(
          // collection
          {
            auto& tag_value_str = t.getBodyXml().getTagValuesStr();
            if (!tag_value_str.empty()) {
              result.append(tag_value_str);
            }
          },
          // collection regex
          { UNREACHABLE(); },
          // specify subname
          {
            auto& tag_value_str = t.getBodyXml().getTagValuesStr();
            if (!tag_value_str.empty()) {
              result.append(tag_value_str);
            }
          });
    } else if constexpr (type == Type::AttrValuePmf || type == Type::TagValuePmf) {
      RETURN_VALUE_CT(
          // collection
          { UNREACHABLE(); },
          // collection regex
          {
            for (auto& elem : *kv_pairs) {
              if (elem.second.empty()) {
                continue;
              }

              if (!hasExceptVariable(t, main_name_, elem.first))
                [[likely]] {
                  if (match(elem.first)) {
                    result.append(elem.second, elem.first);
                  }
                }
            }
          },
          // specify subname
          { UNREACHABLE(); });
    } else {
      UNREACHABLE();
    }
  }

public:
  Type type() const { return type_; }

private:
  Type type_;
};
} // namespace Variable
} // namespace Wge