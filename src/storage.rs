use rocksdb::*;
use std::path::{Path, PathBuf};
use std::str;

fn store(key, value) {
    let path = Path::new("_plaintext");
    let db = DB::open_default(&path).unwrap();

    db.put(key, value);
}


#[test]
fn test_storing_data() {
    store(b"user_id_1", b"secret_1");

    let db = DB::open_default(&path).unwrap();

    let mut iter = db.iterator(IteratorMode::From(b"user_id_1", Direction::Forward));
    for (key, value) in iter {
        println!(
            "=> {:?}:{:?}",
            str::from_utf8(&key).unwrap(),
            str::from_utf8(&value).unwrap()
        );
    }

    db.delete(b"user_id_1");
}
