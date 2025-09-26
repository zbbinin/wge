
static const std::unordered_map<OpCode, std::function<std::string(const Instruction&)>>
    to_string_map = {
        {OpCode::MOV,
         [](const Instruction& instruction) {
           return std::format("MOV {}, 0x{:x}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                              instruction.op2_.imm_);
         }},
        {OpCode::ADD,
         [](const Instruction& instruction) {
           return std::format("ADD {}, 0x{:x}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                              instruction.op2_.imm_);
         }},
        {OpCode::CMP,
         [](const Instruction& instruction) {
           return std::format("CMP {}, {}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                              GeneralRegister2String.at(instruction.op2_.g_reg_));
         }},
        {OpCode::JMP,
         [](const Instruction& instruction) {
           return std::format("JMP 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JZ,
         [](const Instruction& instruction) {
           return std::format("JZ 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JNZ,
         [](const Instruction& instruction) {
           return std::format("JNZ 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JOM,
         [](const Instruction& instruction) {
           return std::format("JOM 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JNOM,
         [](const Instruction& instruction) {
           return std::format("JNOM 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JRM,
         [](const Instruction& instruction) {
           return std::format("JRM 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::JNRM,
         [](const Instruction& instruction) {
           return std::format("JNRM 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::NOP, [](const Instruction&) { return "NOP"; }},
        {OpCode::DEBUG,
         [](const Instruction& instruction) {
           return std::format("DEBUG {}", reinterpret_cast<const char*>(instruction.op1_.cptr_));
         }},
        {OpCode::RULE_START,
         [](const Instruction& instruction) {
           const Rule* rule = reinterpret_cast<const Rule*>(instruction.op1_.cptr_);
           return std::format("RULE_START {}(id:{} [{}:{}])", instruction.op1_.cptr_, rule->id(),
                              rule->filePath(), rule->line());
         }},
        {OpCode::JMP_IF_REMOVED,
         [](const Instruction& instruction) {
           return std::format("JMP_IF_REMOVED 0x{:x}", instruction.op1_.address_);
         }},
        {OpCode::SIZE,
         [](const Instruction& instruction) {
           return std::format("SIZE {}, {}", GeneralRegister2String.at(instruction.op1_.g_reg_),
                              ExtendedRegister2String.at(instruction.op2_.x_reg_));
         }},
        {OpCode::PUSH_MATCHED,
         [](const Instruction& instruction) {
           return std::format("PUSH_MATCHED {}, {}, {}",
                              ExtendedRegister2String.at(instruction.op1_.x_reg_),
                              ExtendedRegister2String.at(instruction.op2_.x_reg_),
                              GeneralRegister2String.at(instruction.op3_.g_reg_));
         }},
        {OpCode::PUSH_ALL_MATCHED,
         [](const Instruction& instruction) {
           return std::format("PUSH_ALL_MATCHED {}, {}",
                              ExtendedRegister2String.at(instruction.op1_.x_reg_),
                              ExtendedRegister2String.at(instruction.op2_.x_reg_));
         }},
        {OpCode::EXPAND_MACRO,
         [](const Instruction& instruction) {
           std::string msg_macro_name =
               instruction.op2_.cptr_
                   ? reinterpret_cast<const Macro::MacroBase*>(instruction.op2_.cptr_)->name()
                   : "nullptr";
           std::string log_macro_name =
               instruction.op4_.cptr_
                   ? reinterpret_cast<const Macro::MacroBase*>(instruction.op4_.cptr_)->name()
                   : "nullptr";
           return std::format("EXPAND_MACRO {}, {}({}), {}, {}({})", instruction.op1_.index_,
                              instruction.op2_.cptr_, msg_macro_name, instruction.op3_.index_,
                              instruction.op4_.cptr_, log_macro_name);
         }},
        {OpCode::CHAIN_START,
         [](const Instruction& instruction) {
           return std::format("CHAIN_START {}", instruction.op1_.cptr_);
         }},
        {OpCode::CHAIN_END,
         [](const Instruction& instruction) {
           return std::format("CHAIN_END {}", instruction.op1_.cptr_);
         }},
        {OpCode::LOG_CALLBACK,
         [](const Instruction& instruction) { return std::format("LOG_CALLBACK"); }},
        {OpCode::EXIT_IF_DISRUPTIVE,
         [](const Instruction& instruction) { return std::format("EXIT_IF_DISRUPTIVE"); }},
        // clang-format off
          TRAVEL_VARIABLES(LOAD_VAR_TO_STRING)
          TRAVEL_TRANSFORMATIONS(TRANSFORM_TO_STRING)
          TRAVEL_OPERATORS(OPERATOR_TO_STRING)
          TRAVEL_ACTIONS(ACTION_TO_STRING)
          TRAVEL_ACTIONS(UNC_ACTION_TO_STRING)
        // clang-format on
};