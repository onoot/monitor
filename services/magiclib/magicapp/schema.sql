DROP TABLE IF EXISTS magic;

CREATE TABLE IF NOT EXISTS magic
(
    id SERIAL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    magicword TEXT NOT NULL
);

INSERT INTO magic (username, password, magicword) VALUES ('Albus Dumbledore', 'Percival Wulfric', 'Brian');
INSERT INTO magic (username, password, magicword) VALUES ('Sonic Sverhzvukovich', 'FutabaIgarashi', 'YONAYONA');
INSERT INTO magic (username, password, magicword) VALUES ('Mash Burnedead', 'GordonAgrippa', 'discord');
INSERT INTO magic (username, password, magicword) VALUES ('Alisa Kujou', 'turbobabka', 'didedodicheap');
INSERT INTO magic (username, password, magicword) VALUES ('Kuroto Nakano', ' Gokushufudou', 'spiceandwolf');
