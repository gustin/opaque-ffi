use rocksdb::*;
use std::path::{Path, PathBuf};

fn store_some_things() {
    let path = Path::new("_plaintext");
    let db = DB::open_default(&path).unwrap();

    db.put(b"user_id_1", b"secret_1");
    db.put(b"user_id_1", b"secret_2");

    //   let r: Result<Option<DBVector>, Error> = db.get(b"user_id_1");

    let mut iter = db.iterator(IteratorMode::From(b"user_id_1", Direction::Forward));
    for (key, value) in iter {
        println!("Saw {:?} {:?}", key, value);
    }
    db.delete(b"k1");
}

#[test]
fn test_storing_data() {
    store_some_things();
}
