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

// Suppress warnings from LLVM headers
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/TargetSelect.h>

#pragma GCC diagnostic pop

namespace Wge {
namespace Jit {
// A simple wrapper around LLVM to facilitate JIT compilation and function calls.
class LlvmWrapper {
public:
  LlvmWrapper();

public:
  /**
   * Check if the LLVM ExecutionEngine was created successfully.
   * @return true if the engine is valid, false otherwise.
   */
  bool ok() const { return engine_ != nullptr; }

  /**
   * Get the error message if the LLVM ExecutionEngine failed to initialize.
   * @return Error message string.
   */
  const std::string& error() const { return error_; }

  /**
   * Register a function to be callable from LLVM JITed code.
   * @tparam func_ptr Function or member function pointer.
   * @name Name of the function in LLVM module.
   */
  template <auto func_ptr> void registerFunction(std::string_view name);

  /**
   * Create a call to a registered function
   * @tparam ArgTypes Argument types
   * @param name Name of the function to call
   * @param args Arguments to pass to the function
   * @return Function call instruction
   */
  template <class... ArgTypes> void createCall(std::string_view name, ArgTypes... args);

private:
  class InitHelper {
  public:
    InitHelper() {
      // Initialize LLVM targets
      llvm::InitializeNativeTarget();
      llvm::InitializeNativeTargetAsmPrinter();
      llvm::InitializeNativeTargetAsmParser();
    }
  };

  struct Types {
    llvm::Type* void_;
    llvm::Type* int64_t_;
    llvm::Type* ptr_;
    Types(llvm::LLVMContext& context) {
      void_ = llvm::Type::getVoidTy(context);
      int64_t_ = llvm::Type::getInt64Ty(context);
      ptr_ = int64_t_;
    }
  };

  // Helper to extract function traits
private:
  template <typename T> struct FunctionTraits;

  template <typename RetType, typename... ArgTypes>
  struct FunctionTraits<RetType (*)(ArgTypes...)> {
    using return_type = RetType;
    using class_type = void;
    using args_tuple = std::tuple<ArgTypes...>;
    static constexpr size_t arity = sizeof...(ArgTypes);

    template <size_t N> using arg_type = typename std::tuple_element<N, args_tuple>::type;
  };

  template <typename RetType, typename ClassType, typename... ArgTypes>
  struct FunctionTraits<RetType (ClassType::*)(ArgTypes...)> {
    using return_type = RetType;
    using class_type = ClassType;
    using args_tuple = std::tuple<ArgTypes...>;
    static constexpr size_t arity = sizeof...(ArgTypes);

    template <size_t N> using arg_type = typename std::tuple_element<N, args_tuple>::type;
  };

private:
  // Get LLVM type from C++ type
  template <class T> llvm::Type* getType() const {
    using DecayT = std::decay_t<T>;
    if constexpr (std::is_same_v<DecayT, void>) {
      return types_.void_;
    } else if constexpr (std::is_same_v<DecayT, int64_t>) {
      return types_.int64_t_;
    } else if constexpr (std::is_pointer_v<DecayT>) {
      return types_.ptr_;
    } else if constexpr (std::is_reference_v<T>) {
      return types_.ptr_;
    } else {
      static_assert(!std::is_same_v<DecayT, DecayT>, "Unsupported type");
    }
  }

  // Fold expression to add argument types
  template <class FuncType, size_t... Is>
  void addArgs(std::vector<llvm::Type*>& args, std::index_sequence<Is...>) const {
    (args.emplace_back(getType<typename FunctionTraits<FuncType>::template arg_type<Is>>()), ...);
  }

  // Create a wrapper function for member function calls
  template <auto func_ptr, typename FuncType, size_t... Is>
  auto createMemberCallWrapper(std::index_sequence<Is...>) const {
    using ClassType = typename FunctionTraits<FuncType>::class_type;
    using RetType = typename FunctionTraits<FuncType>::return_type;

    return +[](void* this_ptr,
               typename FunctionTraits<FuncType>::template arg_type<Is>... args) -> RetType {
      auto* obj = static_cast<ClassType*>(this_ptr);
      if constexpr (std::is_void_v<RetType>) {
        (obj->*func_ptr)(args...);
      } else {
        return (obj->*func_ptr)(args...);
      }
    };
  }

  // Create pointer constant from C++ object pointer
  template <typename T> llvm::Value* createPointerConstant(T* ptr) {
    return llvm::ConstantInt::get(llvm::Type::getInt64Ty(context_),
                                  reinterpret_cast<uintptr_t>(ptr));
  }

private:
  static InitHelper init_helper_;
  llvm::LLVMContext context_;
  llvm::IRBuilder<> builder_;
  llvm::DataLayout data_layout_;
  std::unique_ptr<llvm::Module> module_;
  std::unique_ptr<llvm::ExecutionEngine> engine_;
  Types types_;
  std::string error_;
};

template <auto func_ptr> void LlvmWrapper::registerFunction(std::string_view name) {
  using FuncType = decltype(func_ptr);

  static_assert(std::is_pointer_v<FuncType> || std::is_member_function_pointer_v<FuncType>,
                "Template parameter must be a function pointer, or member function pointer");

  // Trait to extract class type and return type
  using ClassType = typename FunctionTraits<FuncType>::class_type;
  using RetType = typename FunctionTraits<FuncType>::return_type;

  // If it's a member function, the first argument is the 'this' pointer.
  std::vector<llvm::Type*> args;
  if constexpr (!std::is_same_v<ClassType, void>) {
    args.emplace_back(getType<ClassType*>());
  }

  addArgs<FuncType>(args, std::make_index_sequence<FunctionTraits<FuncType>::arity>{});

  // Create the function in the LLVM module.
  llvm::Type* ret_type = getType<RetType>();
  llvm::Function* func = llvm::Function::Create(llvm::FunctionType::get(ret_type, args, false),
                                                llvm::Function::ExternalLinkage, name, *module_);

  // Add the function mapping to the execution engine.
  if constexpr (std::is_pointer_v<FuncType>) {
    engine_->addGlobalMapping(func, func_ptr);
  } else {
    // If it's a member function, we need to create a wrapper function.
    auto wrapper = createMemberCallWrapper<func_ptr, FuncType>(
        std::make_index_sequence<FunctionTraits<FuncType>::arity>{});
    engine_->addGlobalMapping(func, reinterpret_cast<void*>(wrapper));
  }
}

template <class... ArgTypes> void LlvmWrapper::createCall(std::string_view name, ArgTypes... args) {
  // Get the function from the module
  llvm::Function* func = module_->getFunction(name);
  if (!func) {
    assert(false && "Function not found in module");
    return;
  }

  std::vector<llvm::Value*> arg_values;
  (arg_values.emplace_back(createPointerConstant(args)), ...);

  // Call the function
  builder_.CreateCall(func, arg_values);
}
} // namespace Jit
} // namespace Wge