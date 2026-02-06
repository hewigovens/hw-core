use std::io::{self, Write};

pub fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn prompt_nonempty(prompt: &str) -> std::result::Result<String, String> {
    loop {
        let input = prompt_line(prompt).map_err(|e| e.to_string())?;
        if input.trim().is_empty() {
            println!("Input cannot be empty.");
            continue;
        }
        return Ok(input.trim().to_string());
    }
}
