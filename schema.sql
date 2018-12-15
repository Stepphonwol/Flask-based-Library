DROP TABLE IF EXISTS reader;
DROP TABLE IF EXISTS borrow;
DROP TABLE IF EXISTS book;

CREATE TABLE reader (
  reader_id INTEGER PRIMARY KEY AUTOINCREMENT,
  reader_name VARCHAR NOT NULL,
  gender VARCHAR,
  department VARCHAR,
  user_grade INTEGER,
  password VARCHAR NOT NULL
);

CREATE TABLE borrow(
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    borrow_date VARCHAR NOT NULL,
    book_id INTEGER,
    reader_id INTEGER,
    return_date INTEGER,
    returned INTEGER
);

CREATE TABLE book(
    book_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ISBN INTEGER,
    book_name VARCHAR,
    press VARCHAR,
    publicating_date VARCHAR,
    author VARCHAR,
    abstract VARCHAR,
    num INTEGER
);