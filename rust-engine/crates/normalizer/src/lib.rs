use parser::{AstNode, NodeKind, Span};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NormalizedKind {
    Call {
        callee: String,
        arguments: Vec<NormalizedNode>,
        star_args: Option<String>,
        kw_args: Option<String>,
    },
    Assignment {
        lhs: Box<NormalizedNode>,
        rhs: Box<NormalizedNode>,
    },
    Concat {
        parts: Vec<NormalizedNode>,
    },
    Identifier(String),
    Literal(String),
    Block(Vec<NormalizedNode>),
    Import {
        class_name: String,
        full_path: String,
    },
    TypeDeclaration {
        name: String,
        declared_type: String,
    },
    If {
        condition: Box<NormalizedNode>,
        consequent: Box<NormalizedNode>,
        alternate: Option<Box<NormalizedNode>>,
    },
    Unknown(String),
    FunctionDefinition {
        name: String,
        params: Vec<String>,
        body: Vec<NormalizedNode>,
    },
    Return(Box<NormalizedNode>),
    For {
        init: Option<Box<NormalizedNode>>,
        condition: Option<Box<NormalizedNode>>,
        update: Option<Box<NormalizedNode>>,
        body: Box<NormalizedNode>,
    },
    While {
        condition: Box<NormalizedNode>,
        body: Box<NormalizedNode>,
    },
    DoWhile {
        body: Box<NormalizedNode>,
        condition: Box<NormalizedNode>,
    },
    Try {
        body: Box<NormalizedNode>,
        catch_clauses: Vec<NormalizedNode>,
        finally_clause: Option<Box<NormalizedNode>>,
    },
    Catch {
        parameter: Option<String>,
        body: Box<NormalizedNode>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedNode {
    pub id: String,
    pub kind: NormalizedKind,
    pub span: Span,
    pub raw: String,
}

pub struct Normalizer {
    import_table: HashMap<String, String>,
    type_table: HashMap<String, String>,
}

impl Normalizer {
    pub fn new() -> Self {
        Self {
            import_table: HashMap::new(),
            type_table: HashMap::new(),
        }
    }

    pub fn normalize(&mut self, root: &AstNode, language: &str) -> NormalizedNode {
        self.convert(root, language)
    }

    fn convert(&mut self, node: &AstNode, language: &str) -> NormalizedNode {
        let kind = match &node.kind {
            NodeKind::Identifier => NormalizedKind::Identifier(node.raw.clone()),
            NodeKind::Literal => {
                if language.to_lowercase() == "python" && node.raw.starts_with('f') {
                    // 1. Python F-String Normalization
                    self.normalize_fstring(node)
                } else {
                    NormalizedKind::Literal(node.raw.clone())
                }
            }
            NodeKind::CallExpression => {
                if language.to_lowercase() == "python" && node.raw.starts_with("setattr") {
                    // 4. Python setattr Normalization
                    return self.normalize_setattr(node);
                }

                // 2 & 3. Python *args & **kwargs Normalization
                let callee = if language.to_lowercase() == "java" && node.raw.starts_with("new ") {
                    // Java object_creation_expression: "new File(...)" -> callee = "File"
                    node.children
                        .first()
                        .map(|c| c.raw.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                } else if language.to_lowercase() == "java" && node.children.len() >= 3 {
                    format!("{}.{}", node.children[0].raw, node.children[1].raw)
                } else {
                    node.children
                        .first()
                        .map(|c| c.raw.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                };

                let mut args = Vec::new();
                let mut star_args = None;
                let mut kw_args = None;

                let skip_count =
                    if language.to_lowercase() == "java" && node.raw.starts_with("new ") {
                        1 // object_creation_expression: skip just the type name
                    } else if language.to_lowercase() == "java" && node.children.len() >= 3 {
                        2 // method_invocation: skip receiver + method name
                    } else {
                        1 // python and others: skip the callee name
                    };

                let mut actual_children = Vec::new();
                for child in node.children.iter().skip(skip_count) {
                    let child_typ = match &child.kind {
                        NodeKind::Unknown(t) => t.as_str(),
                        _ => "",
                    };
                    if child_typ == "argument_list" || child_typ == "formal_parameters" {
                        for sub in &child.children {
                            actual_children.push(sub.clone());
                        }
                    } else {
                        actual_children.push(child.clone());
                    }
                }

                for child in &actual_children {
                    let child_raw = child.raw.trim();
                    if child_raw.starts_with("**") {
                        kw_args = Some(child_raw[2..].to_string());
                    } else if child_raw.starts_with('*') {
                        star_args = Some(child_raw[1..].to_string());
                    } else {
                        args.push(self.convert(child, language));
                    }
                }

                NormalizedKind::Call {
                    callee,
                    arguments: args,
                    star_args,
                    kw_args,
                }
            }
            NodeKind::AssignmentExpression => {
                let lhs = node
                    .children
                    .first()
                    .map(|c| self.convert(c, language))
                    .unwrap_or_else(|| self.dummy_node(node.span.clone()));
                let rhs = if node.children.len() >= 3 {
                    node.children.get(2)
                } else {
                    node.children.get(1)
                }
                .map(|c| self.convert(c, language))
                .unwrap_or_else(|| self.dummy_node(node.span.clone()));

                // Java Type Propagation Hook
                if language.to_lowercase() == "java" {
                    if let NormalizedKind::Identifier(name) = &lhs.kind {
                        if rhs.raw.contains("new StringBuilder") {
                            self.type_table
                                .insert(name.clone(), "StringBuilder".to_string());
                        }
                    }
                }

                NormalizedKind::Assignment {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                }
            }
            NodeKind::VariableDeclarator => {
                // Java Symbol Mapping & Type Propagation
                let name = node
                    .children
                    .first()
                    .map(|c| c.raw.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let declared_type = if node.raw.starts_with("String ") {
                    "String".to_string()
                } else if node.raw.starts_with("StringBuilder ") {
                    "StringBuilder".to_string()
                } else {
                    self.type_table
                        .get(&name)
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string())
                };

                self.type_table.insert(name.clone(), declared_type.clone());

                let type_decl = NormalizedNode {
                    id: uuid::Uuid::new_v4().to_string(),
                    kind: NormalizedKind::TypeDeclaration {
                        name: name.clone(),
                        declared_type,
                    },
                    span: node.span.clone(),
                    raw: node.raw.clone(),
                };

                if node.children.len() >= 2 {
                    let lhs = NormalizedNode {
                        id: uuid::Uuid::new_v4().to_string(),
                        kind: NormalizedKind::Identifier(name.clone()),
                        span: node.children[0].span.clone(),
                        raw: name,
                    };
                    let rhs = self.convert(&node.children[1], language);
                    let assignment = NormalizedNode {
                        id: uuid::Uuid::new_v4().to_string(),
                        kind: NormalizedKind::Assignment {
                            lhs: Box::new(lhs),
                            rhs: Box::new(rhs),
                        },
                        span: node.span.clone(),
                        raw: node.raw.clone(),
                    };
                    NormalizedKind::Block(vec![type_decl, assignment])
                } else {
                    type_decl.kind
                }
            }
            NodeKind::ReturnStatement => {
                let expr = node
                    .children
                    .first()
                    .map(|c| self.convert(c, language))
                    .unwrap_or_else(|| self.dummy_node(node.span.clone()));
                NormalizedKind::Return(Box::new(expr))
            }
            NodeKind::IfStatement => {
                let cond = node
                    .children
                    .first()
                    .map(|c| self.convert(c, language))
                    .unwrap_or_else(|| self.dummy_node(node.span.clone()));
                let cons = node
                    .children
                    .get(1)
                    .map(|c| self.convert(c, language))
                    .unwrap_or_else(|| self.dummy_node(node.span.clone()));
                let alt = node.children.get(2).map(|c| self.convert(c, language));

                NormalizedKind::If {
                    condition: Box::new(cond),
                    consequent: Box::new(cons),
                    alternate: alt.map(Box::new),
                }
            }
            NodeKind::WhileStatement => {
                let cond = if node.children.len() >= 2 {
                    self.convert(&node.children[0], language)
                } else {
                    self.dummy_node(node.span.clone())
                };
                let body = if node.children.len() >= 2 {
                    self.convert(&node.children[1], language)
                } else if !node.children.is_empty() {
                    self.convert(&node.children[0], language)
                } else {
                    self.dummy_node(node.span.clone())
                };
                NormalizedKind::While {
                    condition: Box::new(cond),
                    body: Box::new(body),
                }
            }
            NodeKind::ForStatement => {
                if node.children.is_empty() {
                    NormalizedKind::Block(Vec::new())
                } else if node.raw.contains(':') && language.to_lowercase() == "java" {
                    let body = self.convert(node.children.last().unwrap(), language);
                    let var_node = if node.children.len() >= 3 {
                        Some(Box::new(
                            self.convert(&node.children[node.children.len() - 3], language),
                        ))
                    } else {
                        None
                    };
                    let iterable_node = if node.children.len() >= 2 {
                        Some(Box::new(
                            self.convert(&node.children[node.children.len() - 2], language),
                        ))
                    } else {
                        None
                    };
                    NormalizedKind::For {
                        init: var_node,
                        condition: iterable_node,
                        update: None,
                        body: Box::new(body),
                    }
                } else if language.to_lowercase() == "python" {
                    let body = self.convert(node.children.last().unwrap(), language);
                    let var_node = if node.children.len() >= 3 {
                        Some(Box::new(self.convert(&node.children[0], language)))
                    } else {
                        None
                    };
                    let iterable_node = if node.children.len() >= 2 {
                        Some(Box::new(self.convert(&node.children[1], language)))
                    } else {
                        None
                    };
                    NormalizedKind::For {
                        init: var_node,
                        condition: iterable_node,
                        update: None,
                        body: Box::new(body),
                    }
                } else {
                    let body = self.convert(node.children.last().unwrap(), language);
                    let init = if node.children.len() >= 3 {
                        Some(Box::new(self.convert(&node.children[0], language)))
                    } else {
                        None
                    };
                    let condition = if node.children.len() >= 4 {
                        Some(Box::new(self.convert(&node.children[1], language)))
                    } else if node.children.len() == 3 {
                        Some(Box::new(self.convert(&node.children[1], language)))
                    } else {
                        None
                    };
                    let update = if node.children.len() >= 4 {
                        Some(Box::new(self.convert(&node.children[2], language)))
                    } else {
                        None
                    };
                    NormalizedKind::For {
                        init,
                        condition,
                        update,
                        body: Box::new(body),
                    }
                }
            }
            NodeKind::DoWhileStatement => {
                let body = if !node.children.is_empty() {
                    self.convert(&node.children[0], language)
                } else {
                    self.dummy_node(node.span.clone())
                };
                let cond = if node.children.len() >= 2 {
                    self.convert(&node.children[1], language)
                } else {
                    self.dummy_node(node.span.clone())
                };
                NormalizedKind::DoWhile {
                    body: Box::new(body),
                    condition: Box::new(cond),
                }
            }
            NodeKind::TryStatement => {
                if node.children.is_empty() {
                    NormalizedKind::Block(Vec::new())
                } else {
                    let try_body = self.convert(&node.children[0], language);
                    let mut catch_clauses = Vec::new();
                    let mut finally_clause = None;

                    for child in node.children.iter().skip(1) {
                        if child.kind == NodeKind::CatchClause || child.raw.starts_with("except") {
                            catch_clauses.push(self.convert(child, language));
                        } else if child.raw.starts_with("finally") {
                            finally_clause = Some(Box::new(self.convert(child, language)));
                        } else {
                            catch_clauses.push(self.convert(child, language));
                        }
                    }

                    NormalizedKind::Try {
                        body: Box::new(try_body),
                        catch_clauses,
                        finally_clause,
                    }
                }
            }
            NodeKind::CatchClause => {
                if node.children.is_empty() {
                    NormalizedKind::Block(Vec::new())
                } else {
                    let body = self.convert(node.children.last().unwrap(), language);
                    let param = if node.children.len() >= 2 {
                        Some(node.children[0].raw.clone())
                    } else {
                        None
                    };
                    NormalizedKind::Catch {
                        parameter: param,
                        body: Box::new(body),
                    }
                }
            }
            NodeKind::WithStatement => {
                let mut block_children = Vec::new();
                if !node.children.is_empty() {
                    let body = self.convert(node.children.last().unwrap(), language);
                    for child in node.children.iter().take(node.children.len() - 1) {
                        block_children.push(self.convert(child, language));
                    }
                    block_children.push(body);
                }
                NormalizedKind::Block(block_children)
            }
            NodeKind::WithItem => {
                if node.children.len() >= 2 {
                    let rhs = self.convert(&node.children[0], language);
                    let lhs = self.convert(&node.children[1], language);
                    NormalizedKind::Assignment {
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    }
                } else if !node.children.is_empty() {
                    self.convert(&node.children[0], language).kind
                } else {
                    NormalizedKind::Block(Vec::new())
                }
            }
            NodeKind::Unknown(typ) => {
                if typ == "function_definition" || typ == "method_declaration" {
                    let mut name = "unknown".to_string();
                    let mut params = Vec::new();
                    let mut body = Vec::new();

                    for child in &node.children {
                        let child_typ = match &child.kind {
                            NodeKind::Unknown(t) => t.as_str(),
                            _ => "",
                        };

                        if child.kind == NodeKind::Identifier {
                            if params.is_empty() && name == "unknown" {
                                name = child.raw.clone();
                            }
                        } else if child_typ == "parameters" || child_typ == "formal_parameters" {
                            for param_child in &child.children {
                                if param_child.kind == NodeKind::Identifier {
                                    params.push(param_child.raw.clone());
                                } else {
                                    // For Java typed params like "String p", push the full raw text
                                    // so the taint engine can see the type prefix
                                    let param_child_typ = match &param_child.kind {
                                        NodeKind::Unknown(t) => t.as_str(),
                                        _ => "",
                                    };
                                    if param_child_typ == "formal_parameter"
                                        || param_child_typ == "spread_parameter"
                                    {
                                        // Push full typed param text e.g. "String p"
                                        params.push(param_child.raw.clone());
                                    } else {
                                        for sub in &param_child.children {
                                            if sub.kind == NodeKind::Identifier {
                                                params.push(sub.raw.clone());
                                            }
                                        }
                                    }
                                }
                            }
                        } else if child.kind == NodeKind::Block || child_typ == "block" {
                            let converted_body = self.convert(child, language);
                            match converted_body.kind {
                                NormalizedKind::Block(children) => {
                                    body = children;
                                }
                                _ => {
                                    body = vec![converted_body];
                                }
                            }
                        }
                    }

                    NormalizedKind::FunctionDefinition { name, params, body }
                } else if language.to_lowercase() == "java"
                    && (typ == "local_variable_declaration" || typ == "field_declaration")
                {
                    let mut type_name = "Unknown".to_string();
                    let mut var_decl_node = None;
                    for child in &node.children {
                        match &child.kind {
                            NodeKind::Unknown(child_typ) => {
                                if child_typ.contains("type") || child_typ.contains("identifier") {
                                    type_name = child.raw.clone();
                                }
                            }
                            NodeKind::Identifier => {
                                type_name = child.raw.clone();
                            }
                            NodeKind::VariableDeclarator => {
                                var_decl_node = Some(child);
                            }
                            _ => {}
                        }
                    }

                    if let Some(var_decl) = var_decl_node {
                        let name = var_decl
                            .children
                            .first()
                            .map(|c| c.raw.clone())
                            .unwrap_or_else(|| "unknown".to_string());
                        self.type_table.insert(name, type_name);
                    }

                    let children = node
                        .children
                        .iter()
                        .map(|c| self.convert(c, language))
                        .collect();
                    NormalizedKind::Block(children)
                } else if language.to_lowercase() == "java" && typ == "import_declaration" {
                    let full_path = node
                        .children
                        .first()
                        .map(|c| c.raw.clone())
                        .unwrap_or_else(|| "".to_string());
                    let class_name = full_path.split('.').last().unwrap_or("").to_string();
                    self.import_table
                        .insert(class_name.clone(), full_path.clone());

                    NormalizedKind::Import {
                        class_name,
                        full_path,
                    }
                } else {
                    let children = node
                        .children
                        .iter()
                        .map(|c| self.convert(c, language))
                        .collect();
                    NormalizedKind::Block(children)
                }
            }
            _ => {
                let children = node
                    .children
                    .iter()
                    .map(|c| self.convert(c, language))
                    .collect();
                NormalizedKind::Block(children)
            }
        };

        NormalizedNode {
            id: node.id.clone(),
            kind,
            span: node.span.clone(),
            raw: node.raw.clone(),
        }
    }

    fn normalize_fstring(&self, node: &AstNode) -> NormalizedKind {
        // Simple f-string parsing regex replacement equivalent:
        // Extract content between braces {...} as identifiers, others as literals
        let content = &node.raw[2..node.raw.len() - 1]; // Strip f" and "
        let mut parts = Vec::new();

        let mut current_literal = String::new();
        let mut in_brace = false;
        let mut current_brace = String::new();

        for char in content.chars() {
            if char == '{' {
                if !current_literal.is_empty() {
                    parts.push(NormalizedNode {
                        id: uuid::Uuid::new_v4().to_string(),
                        kind: NormalizedKind::Literal(current_literal.clone()),
                        span: node.span.clone(),
                        raw: current_literal.clone(),
                    });
                    current_literal.clear();
                }
                in_brace = true;
            } else if char == '}' {
                if !current_brace.is_empty() {
                    parts.push(NormalizedNode {
                        id: uuid::Uuid::new_v4().to_string(),
                        kind: NormalizedKind::Identifier(current_brace.clone()),
                        span: node.span.clone(),
                        raw: current_brace.clone(),
                    });
                    current_brace.clear();
                }
                in_brace = false;
            } else if in_brace {
                current_brace.push(char);
            } else {
                current_literal.push(char);
            }
        }

        if !current_literal.is_empty() {
            parts.push(NormalizedNode {
                id: uuid::Uuid::new_v4().to_string(),
                kind: NormalizedKind::Literal(current_literal.clone()),
                span: node.span.clone(),
                raw: current_literal.clone(),
            });
        }

        NormalizedKind::Concat { parts }
    }

    fn normalize_setattr(&mut self, node: &AstNode) -> NormalizedNode {
        // setattr(obj, "name", user_input) -> obj.name = user_input
        let mut actual_children = Vec::new();
        for child in node.children.iter().skip(1) {
            let child_typ = match &child.kind {
                NodeKind::Unknown(t) => t.as_str(),
                _ => "",
            };
            if child_typ == "argument_list" || child_typ == "formal_parameters" {
                for sub in &child.children {
                    actual_children.push(sub.clone());
                }
            } else {
                actual_children.push(child.clone());
            }
        }

        let obj_name = actual_children
            .get(0)
            .map(|c| c.raw.clone())
            .unwrap_or_else(|| "obj".to_string());
        let prop_name = actual_children
            .get(1)
            .map(|c| c.raw.replace('"', "").replace('\'', ""))
            .unwrap_or_else(|| "prop".to_string());
        let val_node = actual_children
            .get(2)
            .map(|c| self.convert(c, "python"))
            .unwrap_or_else(|| self.dummy_node(node.span.clone()));

        let lhs = NormalizedNode {
            id: uuid::Uuid::new_v4().to_string(),
            kind: NormalizedKind::Identifier(format!("{}.{}", obj_name, prop_name)),
            span: node.span.clone(),
            raw: format!("{}.{}", obj_name, prop_name),
        };

        NormalizedNode {
            id: node.id.clone(),
            kind: NormalizedKind::Assignment {
                lhs: Box::new(lhs),
                rhs: Box::new(val_node),
            },
            span: node.span.clone(),
            raw: node.raw.clone(),
        }
    }

    fn dummy_node(&self, span: Span) -> NormalizedNode {
        NormalizedNode {
            id: uuid::Uuid::new_v4().to_string(),
            kind: NormalizedKind::Literal("".to_string()),
            span,
            raw: "".to_string(),
        }
    }

    pub fn get_import_path(&self, class_name: &str) -> Option<&String> {
        self.import_table.get(class_name)
    }

    pub fn get_type(&self, var_name: &str) -> Option<&String> {
        self.type_table.get(var_name)
    }
}
