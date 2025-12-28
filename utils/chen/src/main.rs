use std::io::Write;

fn main() {
    let binary_file = match std::env::args().skip(1).next() {
        Some(path) => path,
        None => {
            eprintln!(
                "Usage: {} <kernel file path>",
                std::env::args().next().unwrap()
            );
            std::process::exit(1);
        }
    };

    let exists = std::fs::exists(&binary_file).unwrap_or(false);

    if !exists {
        eprintln!("Failed to find a file!");
        std::process::exit(1);
    }

    let command = std::process::Command::new("nm")
        .arg("-C")
        .arg("-n")
        .arg(&binary_file)
        .output();

    let data = String::from_utf8(command.unwrap().stdout).unwrap();

    let mut final_result: Vec<u8> = Vec::with_capacity(data.len());

    for i in data.split("\n") {
        if i.is_empty() {
            continue;
        }

        let mut stems = i.split(" ");

        let address = stems.next().unwrap();
        let _type = stems.next().unwrap();

        if _type.to_lowercase() != "t" {
            continue;
        }

        let address: u32 = u32::from_str_radix(address, 16).unwrap();
        let mut name = stems.collect::<String>();

        if name.len() > 64 {
            name = name.chars().take(64).collect::<String>() + "...";
        }

        final_result.extend_from_slice(&address.to_le_bytes());
        final_result.extend_from_slice(&(name.len() as u8).to_le_bytes());
        final_result.extend_from_slice(name.as_bytes());
    }

    let outfilename = binary_file + ".map";

    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(outfilename)
            .unwrap();

        file.write(&final_result).unwrap();
        file.set_len(final_result.len() as u64).unwrap();
    }
}
