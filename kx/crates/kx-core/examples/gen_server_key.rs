//! Erzeugt das Schluesselpaar des C2-Servers.
//!
//! Der Operator braucht zwei Dateien:
//! - `server_key.json` — das geheime Schluesselpaar. Liegt **nur** beim
//!   Operator, nie auf einem Zielsystem.
//! - `server_pub.json` — der oeffentliche Schluessel. Der Agent bekommt ihn
//!   ueber `--server-key` und versiegelt damit seine Master-Keys.
//!
//! Aufruf:
//! ```text
//! cargo run -p kx-core --example gen_server_key -- hybrid server_key.json server_pub.json
//! cargo run -p kx-core --example gen_server_key -- x25519 server_key.json server_pub.json
//! ```

use kx_core::hostkey::ServerKeyBundle;
use kx_core::kex::KexId;

fn main() {
    let argumente: Vec<String> = std::env::args().collect();
    if argumente.len() != 4 {
        eprintln!("Aufruf: gen_server_key <hybrid|x25519> <bundle.json> <public.json>");
        std::process::exit(2);
    }

    let kex = match argumente[1].as_str() {
        "hybrid" => KexId::HybridX25519MlKem768,
        "x25519" => KexId::X25519,
        other => {
            eprintln!("unbekannter Modus: {other}");
            std::process::exit(2);
        }
    };

    let mut rng = rand_core::OsRng;
    let bundle = ServerKeyBundle::generate(kex, &mut rng);
    let public = bundle.public().expect("oeffentlicher Schluessel");

    std::fs::write(&argumente[2], bundle.to_json_pretty().expect("bundle"))
        .expect("bundle schreiben");
    std::fs::write(
        &argumente[3],
        serde_json::to_string_pretty(&public).expect("public"),
    )
    .expect("public schreiben");

    println!("geheimes Buendel:  {}", argumente[2]);
    println!("oeffentlicher Key: {}", argumente[3]);
    println!("Kex: {:?}", kex);
}
