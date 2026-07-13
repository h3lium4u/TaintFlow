use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeKind {
    CallExpression,
    AssignmentExpression,
    VariableDeclarator,
    ReturnStatement,
    Identifier,
    Literal,
    IfStatement,
    WhileStatement,
    ForStatement,
    DoWhileStatement,
    TryStatement,
    CatchClause,
    WithStatement,
    WithItem,
    Block,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstNode {
    pub id: String,
    pub kind: NodeKind,
    pub span: Span,
    pub children: Vec<AstNode>,
    pub raw: String,
}

pub struct UnifiedParser;

impl UnifiedParser {
    pub fn parse(code: &str, language: &str) -> Result<AstNode, String> {
        let mut parser = tree_sitter::Parser::new();
        let lang = match language.to_lowercase().as_str() {
            "python" => tree_sitter_python::language(),
            "java" => tree_sitter_java::language(),
            _ => return Err(format!("Unsupported language: {}", language)),
        };

        parser.set_language(lang).map_err(|e| e.to_string())?;

        let preprocessed_code;
        let code_to_parse = if language.to_lowercase() == "python" {
            preprocessed_code = preprocess_python(code);
            &preprocessed_code
        } else {
            code
        };

        let tree = parser
            .parse(code_to_parse, None)
            .ok_or_else(|| "Failed to parse code".to_string())?;

        let root_node = tree.root_node();
        Ok(Self::convert_node(root_node, code_to_parse, language))
    }

    fn convert_node(node: tree_sitter::Node, code: &str, language: &str) -> AstNode {
        let node_type = node.kind();
        let raw = node.utf8_text(code.as_bytes()).unwrap_or("").to_string();

        let start = node.start_position();
        let end = node.end_position();
        let span = Span {
            start_line: start.row + 1,
            start_column: start.column,
            end_line: end.row + 1,
            end_column: end.column,
        };

        let kind = match (language.to_lowercase().as_str(), node_type) {
            // Python Mapping
            ("python", "call") => NodeKind::CallExpression,
            ("python", "assignment")
            | ("python", "augmented_assignment")
            | ("python", "named_expression") => NodeKind::AssignmentExpression,
            ("python", "identifier") => NodeKind::Identifier,
            ("python", "string")
            | ("python", "integer")
            | ("python", "float")
            | ("python", "true")
            | ("python", "false")
            | ("python", "none") => NodeKind::Literal,
            ("python", "if_statement") => NodeKind::IfStatement,
            ("python", "while_statement") => NodeKind::WhileStatement,
            ("python", "for_statement") => NodeKind::ForStatement,
            ("python", "try_statement") => NodeKind::TryStatement,
            ("python", "except_clause") => NodeKind::CatchClause,
            ("python", "with_statement") => NodeKind::WithStatement,
            ("python", "with_item") => NodeKind::WithItem,
            ("python", "block") => NodeKind::Block,
            ("python", "return_statement") => NodeKind::ReturnStatement,

            // Java Mapping
            ("java", "method_invocation") | ("java", "object_creation_expression") => {
                NodeKind::CallExpression
            }
            ("java", "assignment_expression") => NodeKind::AssignmentExpression,
            ("java", "variable_declarator") => NodeKind::VariableDeclarator,
            ("java", "identifier") => NodeKind::Identifier,
            ("java", "string_literal")
            | ("java", "decimal_integer_literal")
            | ("java", "boolean_literal")
            | ("java", "null_literal") => NodeKind::Literal,
            ("java", "if_statement") => NodeKind::IfStatement,
            ("java", "while_statement") => NodeKind::WhileStatement,
            ("java", "for_statement") | ("java", "enhanced_for_statement") => {
                NodeKind::ForStatement
            }
            ("java", "do_statement") => NodeKind::DoWhileStatement,
            ("java", "try_statement") => NodeKind::TryStatement,
            ("java", "catch_clause") => NodeKind::CatchClause,
            ("java", "block") => NodeKind::Block,
            ("java", "return_statement") => NodeKind::ReturnStatement,

            // Fallbacks
            (_, other) => NodeKind::Unknown(other.to_string()),
        };

        let mut children = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.is_named() {
                    children.push(Self::convert_node(child, code, language));
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        AstNode {
            id: Uuid::new_v4().to_string(),
            kind,
            span,
            children,
            raw,
        }
    }
}

fn preprocess_python(code: &str) -> String {
    // Guard: only preprocess if the first non-empty line has indent >= 8.
    let first_nonempty_indent = code
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(0);
    if first_nonempty_indent < 8 {
        return code.to_string();
    }

    let mut cleaned_lines = Vec::new();
    let mut in_top_level = true;
    let mut in_class_header = false;
    let mut open_parens = 0;
    let mut inserted_pass = false;

    for line in code.split('\n') {
        let stripped = line.trim();
        if stripped.is_empty() {
            cleaned_lines.push(line.to_string());
            continue;
        }

        if in_top_level {
            if stripped.starts_with("class ") || stripped.starts_with("def ") {
                in_top_level = false;
            }
        }

        let mut line_to_add = if in_top_level {
            line.trim_start().to_string()
        } else {
            line.to_string()
        };

        let is_class = stripped.starts_with("class ");
        let is_def = stripped.starts_with("def ");

        if is_class {
            in_class_header = true;
            inserted_pass = false;
        } else if is_def {
            in_class_header = false;
        }

        if in_class_header && !is_class {
            let mut line_parens = 0i32;
            for c in stripped.chars() {
                if c == '(' || c == '[' || c == '{' {
                    line_parens += 1;
                } else if c == ')' || c == ']' || c == '}' {
                    line_parens -= 1;
                }
            }

            let indent = line.len() - line.trim_start().len();
            let is_comment = stripped.starts_with('#');
            let is_docstring = stripped.starts_with("\"\"\"") || stripped.starts_with("'''");

            if (line_parens < 0 && open_parens == 0)
                || (indent >= 12 && !is_comment && !is_docstring)
            {
                if !inserted_pass {
                    line_to_add = "    pass".to_string();
                    inserted_pass = true;
                } else {
                    line_to_add = format!("# stripped: {}", stripped);
                }
            } else {
                open_parens = std::cmp::max(0, open_parens + line_parens);
            }
        }

        cleaned_lines.push(line_to_add);
    }

    cleaned_lines.join("\n")
}
