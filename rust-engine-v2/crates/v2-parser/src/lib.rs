use serde::{Deserialize, Serialize};
use v2_common::Span;

pub trait CstNode {
    fn kind(&self) -> &str;
    fn span(&self) -> Span;
    fn raw(&self) -> &str;
    fn children(&self) -> Vec<&dyn CstNode>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleCstNode {
    pub kind: String,
    pub span: Span,
    pub raw: String,
    pub children: Vec<SimpleCstNode>,
}

impl CstNode for SimpleCstNode {
    fn kind(&self) -> &str {
        &self.kind
    }
    fn span(&self) -> Span {
        self.span.clone()
    }
    fn raw(&self) -> &str {
        &self.raw
    }
    fn children(&self) -> Vec<&dyn CstNode> {
        self.children.iter().map(|c| c as &dyn CstNode).collect()
    }
}

pub fn parse_python(code: &str) -> Result<Box<dyn CstNode>, String> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_python::language();
    parser.set_language(language).map_err(|e| e.to_string())?;

    let preprocessed = preprocess_python(code);
    let tree = parser
        .parse(&preprocessed, None)
        .ok_or_else(|| "Failed to parse Python code".to_string())?;

    let root_node = tree.root_node();
    let converted = convert_node(root_node, &preprocessed);
    Ok(Box::new(converted))
}

fn convert_node(node: tree_sitter::Node, code: &str) -> SimpleCstNode {
    let node_type = node.kind();
    let raw = node.utf8_text(code.as_bytes()).unwrap_or("").to_string();

    let start = node.start_position();
    let end = node.end_position();
    let span = Span {
        start_line: start.row + 1,
        start_col: start.column,
        end_line: end.row + 1,
        end_col: end.column,
    };

    let kind = match node_type {
        "call" => "CallExpression",
        "assignment" | "augmented_assignment" | "named_expression" => "AssignmentExpression",
        "identifier" => "Identifier",
        "string" | "integer" | "float" | "true" | "false" | "none" => "Literal",
        "if_statement" => "IfStatement",
        "while_statement" => "WhileStatement",
        "for_statement" => "ForStatement",
        "try_statement" => "TryStatement",
        "except_clause" => "CatchClause",
        "with_statement" => "WithStatement",
        "with_item" => "WithItem",
        "block" => "Block",
        "return_statement" => "ReturnStatement",
        "function_definition" => "FunctionDefinition",
        "class_definition" => "ClassDefinition",
        "import_statement" | "import_from_statement" => "ImportStatement",
        other => other,
    };

    let mut children = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() {
                children.push(convert_node(child, code));
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    SimpleCstNode {
        kind: kind.to_string(),
        span,
        raw,
        children,
    }
}

fn preprocess_python(code: &str) -> String {
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

            if (line_parens < 0 && open_parens == 0) || (indent >= 12 && !is_comment && !is_docstring) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_python() {
        let code = "def add(x, y):\n    return x + y\n";
        let cst = parse_python(code).unwrap();
        assert_eq!(cst.kind(), "module");
        
        let children = cst.children();
        assert!(!children.is_empty());
        let func = children[0];
        assert_eq!(func.kind(), "FunctionDefinition");
        assert!(func.raw().contains("def add(x, y):"));
    }
}
