mod analysis;

use std::fs;
use std::env;
use analysis::{parse_solidity_code, find_vulnerabilities};
use serde_json;
use actix_web::{post, App, HttpResponse, HttpServer, Responder};
use actix_files::Files;

#[post("/analyze")]
async fn analyze(body: String) -> impl Responder {
    let parsed_lines = parse_solidity_code(&body);
    let result = find_vulnerabilities(&parsed_lines);
    HttpResponse::Ok().json(result)
}

async fn run_server() -> std::io::Result<()> {
    let static_root = "/home/datavaultsec/intelligent-contract-security/intelligent-contract-security/web";
    HttpServer::new(move || {
        App::new()
            .service(analyze)
            .service(Files::new("/", static_root).index_file("index.html"))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}

#[actix_web::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let file_path = &args[1];
        let code = match fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("Dosya okunamadı: {}", err);
                std::process::exit(1);
            }
        };
        let parsed_lines = parse_solidity_code(&code);
        let result = find_vulnerabilities(&parsed_lines);
        let json_output = serde_json::to_string_pretty(&result)
            .expect("JSON'a dönüştürülemedi");
        println!("{}", json_output);
        return;
    }

    if let Err(err) = run_server().await {
        eprintln!("Sunucu başlatılırken hata: {}", err);
        std::process::exit(1);
    }
}
