#include "compiler.h"

#include "../rule.h"
#include "../variable/variables_include.h"

#define VAR_INDEX(name)                                                                            \
  { Variable::name::main_name_.data(), __COUNTER__ }

namespace Wge {
namespace Bytecode {
const std::unordered_map<const char*, int64_t> Compiler::variable_index_map_ = {
    VAR_INDEX(ArgsCombinedSize),
    VAR_INDEX(ArgsGetNames),
    VAR_INDEX(ArgsGet),
    VAR_INDEX(ArgsNames),
    VAR_INDEX(ArgsPostNames),
    VAR_INDEX(ArgsPost),
    VAR_INDEX(Args),
    VAR_INDEX(AuthType),
    VAR_INDEX(Duration),
    VAR_INDEX(Env),
    VAR_INDEX(FilesCombinedSize),
    VAR_INDEX(FilesNames),
    VAR_INDEX(FilesSizes),
    VAR_INDEX(FilesTmpContent),
    VAR_INDEX(FilesTmpNames),
    VAR_INDEX(Files),
    VAR_INDEX(FullRequestLength),
    VAR_INDEX(FullRequest),
    VAR_INDEX(Geo),
    VAR_INDEX(Global),
    VAR_INDEX(HighestSeverity),
    VAR_INDEX(InboundDataError),
    VAR_INDEX(Ip),
    VAR_INDEX(MatchedVarName),
    VAR_INDEX(MatchedVar),
    VAR_INDEX(MatchedVarsNames),
    VAR_INDEX(MatchedVars),
    VAR_INDEX(ModSecBuild),
    VAR_INDEX(MscPcreLimitsExceeded),
    VAR_INDEX(MultipartBoundaryQuoted),
    VAR_INDEX(MultipartBoundaryWhitespace),
    VAR_INDEX(MultipartCrlfLfLines),
    VAR_INDEX(MultipartDataAfter),
    VAR_INDEX(MultipartDataBefore),
    VAR_INDEX(MultipartFileLimitExceeded),
    VAR_INDEX(MultipartFileName),
    VAR_INDEX(MultipartHeaderFolding),
    VAR_INDEX(MultipartInvalidHeaderFolding),
    VAR_INDEX(MultipartInvalidPart),
    VAR_INDEX(MultipartInvalidQuoting),
    VAR_INDEX(MultipartLfLine),
    VAR_INDEX(MultipartMissingSemicolon),
    VAR_INDEX(MultipartName),
    VAR_INDEX(MultipartPartHeaders),
    VAR_INDEX(MultipartStrictError),
    VAR_INDEX(MultipartUnmatchedBoundary),
    VAR_INDEX(OutboundDataError),
    VAR_INDEX(PathInfo),
    VAR_INDEX(QueryString),
    VAR_INDEX(RemoteAddr),
    VAR_INDEX(RemoteHost),
    VAR_INDEX(RemotePort),
    VAR_INDEX(RemoteUser),
    VAR_INDEX(ReqBodyErrorMsg),
    VAR_INDEX(ReqBodyError),
    VAR_INDEX(ReqbodyProcessorError),
    VAR_INDEX(ReqBodyProcessor),
    VAR_INDEX(RequestBaseName),
    VAR_INDEX(RequestBodyLength),
    VAR_INDEX(RequestBody),
    VAR_INDEX(RequestCookiesNames),
    VAR_INDEX(RequestCookies),
    VAR_INDEX(RequestFileName),
    VAR_INDEX(RequestHeadersNames),
    VAR_INDEX(RequestHeaders),
    VAR_INDEX(RequestLine),
    VAR_INDEX(RequestMothod),
    VAR_INDEX(RequestProtocol),
    VAR_INDEX(RequestUriRaw),
    VAR_INDEX(RequestUri),
    VAR_INDEX(Resource),
    VAR_INDEX(ResponseBody),
    VAR_INDEX(ResponseContentLength),
    VAR_INDEX(ResponseContentType),
    VAR_INDEX(ResponseHeadersNames),
    VAR_INDEX(ResponseHeaders),
    VAR_INDEX(ResponseProtocol),
    VAR_INDEX(ResponseStatus),
    VAR_INDEX(Rule),
    VAR_INDEX(ServerAddr),
    VAR_INDEX(ServerName),
    VAR_INDEX(ServerPort),
    VAR_INDEX(Session),
    VAR_INDEX(SessionId),
    VAR_INDEX(StatusLine),
    VAR_INDEX(TimeDay),
    VAR_INDEX(TimeEpoch),
    VAR_INDEX(TimeHour),
    VAR_INDEX(TimeMin),
    VAR_INDEX(TimeMon),
    VAR_INDEX(TimeSec),
    VAR_INDEX(TimeWDay),
    VAR_INDEX(TimeYear),
    VAR_INDEX(Time),
    VAR_INDEX(Tx),
    VAR_INDEX(UniqueId),
    VAR_INDEX(UrlenCodedError),
    VAR_INDEX(User),
    VAR_INDEX(UserId),
    VAR_INDEX(WebAppId),
    VAR_INDEX(Xml)};

std::unique_ptr<Program> Compiler::compile(const std::vector<const Rule*>& rules) {
  auto program = std::make_unique<Program>();

  // Compile each rule into program
  for (const Rule* rule : rules) {
    compileRule(rule, *program);
  }

  return program;
}

void Compiler::compileRule(const Rule* rule, Program& program) {
  // Compile each variable in the rule
  auto& variables = rule->variables();
  for (const auto& var : variables) {
    compileVariable(var.get(), program);
  }

  // Compile operator
  auto& op = rule->getOperator();
  compileOperator(op.get(), program);

  // Compile each action in the rule
  auto& actions = rule->actions();
  for (const auto& action : actions) {
    compileAction(action.get(), program);
  }
}

void Compiler::compileVariable(const Variable::VariableBase* variable, Program& program) {
  auto iter = variable_index_map_.find(variable->mainName().data());
  assert(iter != variable_index_map_.end());
  if (iter != variable_index_map_.end()) {
    int64_t index = iter->second;
    int64_t var_ptr = reinterpret_cast<int64_t>(variable);
    program.emit({OpCode::LOAD_VAR, Register::RDI, static_cast<Register>(index),
                  static_cast<Register>(var_ptr)});
  }
}

void Compiler::compileOperator(const Operator::OperatorBase* op, Program& program) {}

void Compiler::compileAction(const Action::ActionBase* action, Program& program) {}
} // namespace Bytecode
} // namespace Wge

#undef VAR_INDEX
