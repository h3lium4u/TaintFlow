use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Int(i64),
    Bool(bool),
    Str(String),
    Char(char),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Number(i64),
    Bool(bool),
    Char(char),
    Str(String),
    OpCmp(String),
    OpLog(String),
    OpMath(char),
    LParen,
    RParen,
    Var(String),
}

pub fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            let val = s.parse::<i64>().map_err(|e| e.to_string())?;
            tokens.push(Token::Number(val));
            continue;
        }
        if c == '\'' {
            if i + 2 < chars.len() && chars[i + 2] == '\'' {
                let val = chars[i + 1];
                tokens.push(Token::Char(val));
                i += 3;
                continue;
            } else {
                return Err("Malformed char literal".to_string());
            }
        }
        if c == '"' {
            let start = i + 1;
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("Unterminated string literal".to_string());
            }
            let s: String = chars[start..i].iter().collect();
            tokens.push(Token::Str(s));
            i += 1;
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }
        if c == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
            tokens.push(Token::OpLog("&&".to_string()));
            i += 2;
            continue;
        }
        if c == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
            tokens.push(Token::OpLog("||".to_string()));
            i += 2;
            continue;
        }
        if c == '=' && i + 1 < chars.len() && chars[i + 1] == '=' {
            tokens.push(Token::OpCmp("==".to_string()));
            i += 2;
            continue;
        }
        if c == '!' {
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                tokens.push(Token::OpCmp("!=".to_string()));
                i += 2;
            } else {
                tokens.push(Token::OpLog("!".to_string()));
                i += 1;
            }
            continue;
        }
        if c == '>' {
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                tokens.push(Token::OpCmp(">=".to_string()));
                i += 2;
            } else {
                tokens.push(Token::OpCmp(">".to_string()));
                i += 1;
            }
            continue;
        }
        if c == '<' {
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                tokens.push(Token::OpCmp("<=".to_string()));
                i += 2;
            } else {
                tokens.push(Token::OpCmp("<".to_string()));
                i += 1;
            }
            continue;
        }
        if c == '+' || c == '-' || c == '*' || c == '/' || c == '%' {
            tokens.push(Token::OpMath(c));
            i += 1;
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            let lower_s = s.to_lowercase();
            if lower_s == "true" {
                tokens.push(Token::Bool(true));
            } else if lower_s == "false" {
                tokens.push(Token::Bool(false));
            } else if lower_s == "not" {
                tokens.push(Token::OpLog("not".to_string()));
            } else {
                tokens.push(Token::Var(s));
            }
            continue;
        }
        // Fallback or ignore unknown characters
        i += 1;
    }
    Ok(tokens)
}

pub struct Evaluator<'a> {
    pub constants: &'a HashMap<String, ConstantValue>,
    tokens: Vec<Token>,
    pos: usize,
}

impl<'a> Evaluator<'a> {
    pub fn new(constants: &'a HashMap<String, ConstantValue>) -> Self {
        Self {
            constants,
            tokens: Vec::new(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn consume(&mut self) -> Result<Token, String> {
        let tok = self
            .peek()
            .cloned()
            .ok_or_else(|| "Unexpected end of input".to_string())?;
        self.pos += 1;
        Ok(tok)
    }

    pub fn evaluate(&mut self, expr: &str) -> Option<ConstantValue> {
        let clean_expr = expr.trim();
        self.tokens = tokenize(clean_expr).ok()?;
        self.pos = 0;
        let val = self.parse_logical_or().ok()?;
        if self.pos < self.tokens.len() {
            None
        } else {
            Some(val)
        }
    }

    fn parse_logical_or(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_logical_and()?;
        while let Some(Token::OpLog(op)) = self.peek() {
            if op == "||" {
                self.consume()?;
                let right = self.parse_logical_and()?;
                match (&node, &right) {
                    (ConstantValue::Bool(a), ConstantValue::Bool(b)) => {
                        node = ConstantValue::Bool(*a || *b);
                    }
                    _ => return Err("Invalid operands for ||".to_string()),
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_logical_and(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_equality()?;
        while let Some(Token::OpLog(op)) = self.peek() {
            if op == "&&" {
                self.consume()?;
                let right = self.parse_equality()?;
                match (&node, &right) {
                    (ConstantValue::Bool(a), ConstantValue::Bool(b)) => {
                        node = ConstantValue::Bool(*a && *b);
                    }
                    _ => return Err("Invalid operands for &&".to_string()),
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_equality(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_relational()?;
        while let Some(Token::OpCmp(op)) = self.peek() {
            if op == "==" || op == "!=" {
                let op = op.clone();
                self.consume()?;
                let right = self.parse_relational()?;
                let eq = match (&node, &right) {
                    (ConstantValue::Int(a), ConstantValue::Int(b)) => a == b,
                    (ConstantValue::Bool(a), ConstantValue::Bool(b)) => a == b,
                    (ConstantValue::Str(a), ConstantValue::Str(b)) => a == b,
                    (ConstantValue::Char(a), ConstantValue::Char(b)) => a == b,
                    // Allow comparison between Char and Int if needed
                    (ConstantValue::Char(a), ConstantValue::Int(b)) => (*a as i64) == *b,
                    (ConstantValue::Int(a), ConstantValue::Char(b)) => *a == (*b as i64),
                    _ => false,
                };
                let val = if op == "==" { eq } else { !eq };
                node = ConstantValue::Bool(val);
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_relational(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_additive()?;
        while let Some(Token::OpCmp(op)) = self.peek() {
            if op == ">" || op == "<" || op == ">=" || op == "<=" {
                let op = op.clone();
                self.consume()?;
                let right = self.parse_additive()?;
                match (&node, &right) {
                    (ConstantValue::Int(a), ConstantValue::Int(b)) => {
                        let val = match op.as_str() {
                            ">" => a > b,
                            "<" => a < b,
                            ">=" => a >= b,
                            "<=" => a <= b,
                            _ => unreachable!(),
                        };
                        node = ConstantValue::Bool(val);
                    }
                    _ => return Err("Invalid operands for relational".to_string()),
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_additive(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_multiplicative()?;
        while let Some(Token::OpMath(op)) = self.peek() {
            let op = *op;
            if op == '+' || op == '-' {
                self.consume()?;
                let right = self.parse_multiplicative()?;
                match (&node, &right) {
                    (ConstantValue::Int(a), ConstantValue::Int(b)) => {
                        let val = if op == '+' { a + b } else { a - b };
                        node = ConstantValue::Int(val);
                    }
                    _ => return Err("Invalid operands for additive".to_string()),
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_multiplicative(&mut self) -> Result<ConstantValue, String> {
        let mut node = self.parse_primary()?;
        while let Some(Token::OpMath(op)) = self.peek() {
            let op = *op;
            if op == '*' || op == '/' || op == '%' {
                self.consume()?;
                let right = self.parse_primary()?;
                match (&node, &right) {
                    (ConstantValue::Int(a), ConstantValue::Int(b)) => {
                        let val = match op {
                            '*' => a * b,
                            '/' => {
                                if *b == 0 {
                                    return Err("Division by zero".to_string());
                                }
                                a / b
                            }
                            '%' => {
                                if *b == 0 {
                                    return Err("Modulo by zero".to_string());
                                }
                                a % b
                            }
                            _ => unreachable!(),
                        };
                        node = ConstantValue::Int(val);
                    }
                    _ => return Err("Invalid operands for multiplicative".to_string()),
                }
            } else {
                break;
            }
        }
        Ok(node)
    }

    fn parse_primary(&mut self) -> Result<ConstantValue, String> {
        let next_tok = self.peek().cloned();
        if let Some(tok) = next_tok {
            match &tok {
                Token::OpMath('-') => {
                    self.consume()?;
                    let val = self.parse_primary()?;
                    match val {
                        ConstantValue::Int(v) => Ok(ConstantValue::Int(-v)),
                        _ => Err("Invalid operand for unary minus".to_string()),
                    }
                }
                Token::OpLog(op) if op == "!" || op == "not" => {
                    self.consume()?;
                    let val = self.parse_primary()?;
                    match val {
                        ConstantValue::Bool(v) => Ok(ConstantValue::Bool(!v)),
                        _ => Err("Invalid operand for unary not".to_string()),
                    }
                }
                _ => {
                    let tok = self.consume()?;
                    match tok {
                        Token::Number(val) => Ok(ConstantValue::Int(val)),
                        Token::Bool(val) => Ok(ConstantValue::Bool(val)),
                        Token::Char(val) => Ok(ConstantValue::Char(val)),
                        Token::Str(val) => Ok(ConstantValue::Str(val)),
                        Token::Var(name) => {
                            if let Some(val) = self.constants.get(&name) {
                                Ok(val.clone())
                            } else {
                                Err(format!("Unknown variable: {}", name))
                            }
                        }
                        Token::LParen => {
                            let node = self.parse_logical_or()?;
                            let next = self.consume()?;
                            if let Token::RParen = next {
                                Ok(node)
                            } else {
                                Err("Expected )".to_string())
                            }
                        }
                        _ => Err(format!("Unexpected token: {:?}", tok)),
                    }
                }
            }
        } else {
            Err("Unexpected end of input".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_expressions() {
        let constants = HashMap::new();
        let mut eval = Evaluator::new(&constants);

        // Logical
        assert_eq!(
            eval.evaluate("true && false"),
            Some(ConstantValue::Bool(false))
        );
        assert_eq!(
            eval.evaluate("false || false"),
            Some(ConstantValue::Bool(false))
        );
        assert_eq!(
            eval.evaluate("true || false"),
            Some(ConstantValue::Bool(true))
        );

        // Unary
        assert_eq!(eval.evaluate("!true"), Some(ConstantValue::Bool(false)));
        assert_eq!(eval.evaluate("not false"), Some(ConstantValue::Bool(true)));
        assert_eq!(eval.evaluate("-5"), Some(ConstantValue::Int(-5)));

        // Relational / Equality
        assert_eq!(eval.evaluate("1 == 2"), Some(ConstantValue::Bool(false)));
        assert_eq!(eval.evaluate("3 > 2"), Some(ConstantValue::Bool(true)));
        assert_eq!(eval.evaluate("5 < 1"), Some(ConstantValue::Bool(false)));
        assert_eq!(
            eval.evaluate("'a' == 'b'"),
            Some(ConstantValue::Bool(false))
        );
        assert_eq!(eval.evaluate("'a' == 'a'"), Some(ConstantValue::Bool(true)));

        // Arithmetic
        assert_eq!(eval.evaluate("3 + 4"), Some(ConstantValue::Int(7)));
        assert_eq!(eval.evaluate("10 - 5"), Some(ConstantValue::Int(5)));
        assert_eq!(eval.evaluate("2 * 8"), Some(ConstantValue::Int(16)));

        // Nested
        assert_eq!(
            eval.evaluate("(7 * 42) - 86 > 200"),
            Some(ConstantValue::Bool(true))
        );
    }

    #[test]
    fn test_evaluator_constants() {
        let mut constants = HashMap::new();
        constants.insert("mode".to_string(), ConstantValue::Str("safe".to_string()));
        constants.insert("num".to_string(), ConstantValue::Int(86));

        let mut eval = Evaluator::new(&constants);
        assert_eq!(
            eval.evaluate("mode == \"safe\""),
            Some(ConstantValue::Bool(true))
        );
        assert_eq!(
            eval.evaluate("mode == \"unsafe\""),
            Some(ConstantValue::Bool(false))
        );
        assert_eq!(eval.evaluate("num > 50"), Some(ConstantValue::Bool(true)));
    }
}
