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

        let tree = parser
            .parse(code, None)
            .ok_or_else(|| "Failed to parse code".to_string())?;

        let root_node = tree.root_node();
        Ok(Self::convert_node(root_node, code, language))
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
