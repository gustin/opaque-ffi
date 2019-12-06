use rocksdb::*;
use std::path::{Path, PathBuf};
use std::str;

pub fn store(key: &str, value: &[u8]) {
    let path = Path::new("_plaintext");
    let db = DB::open_default(&path).unwrap();

    db.put(key.as_bytes(), value);
}

pub fn retrieve(key: &str) -> String {
    let path = Path::new("_plaintext");
    let db = DB::open_default(&path).unwrap();

    match db.get(key.as_bytes()) {
        Ok(Some(value)) => str::from_utf8(&value).unwrap().to_string(),
        Ok(None) => "value not found".to_string(),
        Err(e) => "operational problem encountered.".to_string(),
    }
}

#[test]
fn test_storing_data() {
    store("user_id_1", "secret_1".as_bytes());

    let path = Path::new("_plaintext");
    let db = DB::open_default(&path).unwrap();

    let mut iter =
        db.iterator(IteratorMode::From(b"user_id_1", Direction::Forward));
    for (key, value) in iter {
        println!(
            "=> {:?}:{:?}",
            str::from_utf8(&key).unwrap(),
            str::from_utf8(&value).unwrap()
        );
    }

    db.delete(b"user_id_1");
}
