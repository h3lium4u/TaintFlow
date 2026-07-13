pub trait LanguageFrontend {
    fn lower(
        &self,
        code: &str,
        semantic_info: &v2_semantic::SemanticInfo,
        file_path: &std::path::Path,
    ) -> Result<v2_ir::Program, String>;
}

pub fn init() {
    println!("v2-frontend-base initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }
}
