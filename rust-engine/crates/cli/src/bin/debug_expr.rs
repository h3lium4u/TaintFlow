fn main() {
    let expr = "f'wget -O {tmp_fullname} -t {DOWNLOAD_RETRY_LIMIT} {url}'";
    let var = "url";
    let clean_expr = expr.trim().to_lowercase();
    let clean_var = var.trim().to_lowercase();
    let contains_check = expr.contains(&format!("{{{}}}", var));
    println!("contains_check: {}", contains_check);
}
