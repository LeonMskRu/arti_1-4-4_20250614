# Dircache Storage

This document tries to document the storage model on how the (future) dircache
module stores data internally.

## Requirements

1. Be fault resilient (e.g. power-loss/sudden crashes *MUST NOT* result in data loss)
2. Be fast with lookups by various keys (e.g. fingerprint, digest, ...)
3. Have everything in one place
4. Avoid redundant copies of (frequently used) data

## SQLite as the fundamental primitive

*SQLite* has been chosen as the primitive data storage back-end, because it
offers a neat read performance and acceptable write performance, although the
latter one is more critical for dirauths rather than dircaches due to the
frequently uploaded descriptors and data, besides it satisfies the first two
requirements trivially and the latter two if we add additional constraints
and middleware (more on that later).

## Future extension towards a dirauth

A dircache forms the basis of a dirauth.  The current plan is to design the
dircache as an independent component of which the dirauth related code is merely
an extension.  Due to this design decision, all dirauth related data structures
*SHOULD* have to be in their own tables.

## Caching as a middle layer

Right now, there is a problem that we avoid redundant copies of the same data
in memory.  Let's say 10,000 clients request the same piece of data.  In that
sense, we should not store the same data 10,000 times in memory but only once
and read from the same reference in 10,000 different contextes.

To achieve this, various techniques in the database scheme and database access
are being used, which is being explained later in the document.

## Structure of the database

The database contains a table for each document type the dircache serves.
Such a table *MUST* contain the following three fields:
* `rowid`
	* Serves as the primary key.
* `content_sha256`
	* Uniquely identifies the data by `content`.
	* Required for caching.
* `content`
	* The actual raw content of the document.
	* *MUST* be valid UTF-8 under all circumstances.

Additionally, a table may contain more fields, particularly information
extracted from the consensus that may be used for addressing certain
information, such as relay fingerprints, SHA-1 digests, ...

`consensus` and `consensus_md` are special in the sense that they have an
additional `lzma` column containing the precomputed LZMA compression of
`content`.

Tables that do not represent network documents do not have any requirements.
At the moment, the only such table is `vote`, representing an N:M relationship
between `authority` and `consensus`.

```sql
-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus.z
-- http://<hostname>/tor/status-vote/current/consensus/<F1>+<F2>+<F3>.z
CREATE TABLE consensus(
	rowid				INTEGER NOT NULL,
	content_sha256		TEXT NOT NULL UNIQUE,
	content				TEXT NOT NULL UNIQUE,
	content_lzma		BLOB NOT NULL UNIQUE,
	content_lzma_sha256	TEXT NOT NULL UNIQUE,
	valid_after			INTEGER NOT NULL, -- Unix timestamp of `valid-after`.
	fresh_until			INTEGER NOT NULL, -- Unix timestamp of `fresh-until`.
	valid_until			INTEGER NOT NULL, -- Unix timestamp of `valid-until`.
	PRIMARY KEY(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_lzma_sha256) == 64)
) STRICT;

CREATE INDEX idx_consensus ON consensus(valid_after, content_sha256, content_lzma_sha256);

-- Stores microdescriptor consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus-microdesc.z
CREATE TABLE consensus_md(
	rowid				INTEGER NOT NULL,
	content_sha256		TEXT NOT NULL UNIQUE,
	content				TEXT NOT NULL UNIQUE,
	content_lzma		BLOB NOT NULL UNIQUE,
	content_lzma_sha256	TEXT NOT NULL UNIQUE,
	valid_after			INTEGER NOT NULL, -- Unix timestamp of `valid-after`.
	fresh_until			INTEGER NOT NULL, -- Unix timestamp of `fresh-until`.
	valid_until			INTEGER NOT NULL, -- Unix timestamp of `valid-until`.
	PRIMARY KEY(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_lzma_sha256) == 64)
) STRICT;

CREATE INDEX idx_consensus_md ON consensus_md(valid_after, content_sha256, content_lzma_sha256);

-- Directory authority key certificates.
--
-- This information is derived from the consensus documents.
--
-- http://<hostname>/tor/keys/all.z
-- http://<hostname>/tor/keys/authority.z
-- http://<hostname>/tor/keys/fp/<F>.z
-- http://<hostname>/tor/keys/sk/<F>-<S>.z
CREATE TABLE authority(
	rowid					INTEGER NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL UNIQUE,
	kp_auth_id_rsa_sha1		TEXT NOT NULL,
	kp_auth_sign_rsa_sha1	TEXT NOT NULL,
	last_consensus_rowid	INTEGER NOT NULL,
	PRIMARY KEY(rowid),
	FOREIGN KEY(last_consensus_rowid) REFERENCES consensus(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
	CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_authority ON authority(kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1);

-- Stores the router descriptors.
--
-- http://<hostname>/tor/server/fp/<F>.z
-- http://<hostname>/tor/server/d/<D>.z
-- http://<hostname>/tor/server/authority.z
-- http://<hostname>/tor/server/all.z
CREATE TABLE router(
	rowid					INTEGER NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL UNIQUE,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	last_consensus_rowid	INTEGER NOT NULL,
	router_extra_info_rowid	INTEGER,
	PRIMARY KEY(rowid),
	FOREIGN KEY(last_consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(router_extra_info_rowid) REFERENCES router_extra_info(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha1) == 40),
	CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_router ON router(kp_relay_id_rsa_sha1, content_sha1);

-- Stores micro router descriptors.
--
-- http://<hostname>/tor/micro/d/<D>[.z]
CREATE TABLE router_md(
	rowid					INTEGER NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL UNIQUE,
	last_consensus_md_rowid	INTEGER NOT NULL,
	PRIMARY KEY(rowid),
	FOREIGN KEY(last_consensus_md_rowid) REFERENCES consensus_md(rowid),
	CHECK(LENGTH(content_sha256) == 64)
) STRICT;

CREATE INDEX idx_router_md ON router_md(content_sha256);

-- Stores extra-info documents.
--
-- http://<hostname>/tor/extra/d/<D>.z
-- http://<hostname>/tor/extra/fp/<FP>.z
-- http://<hostname>/tor/extra/all.z
-- http://<hostname>/tor/extra/authority.z
CREATE TABLE router_extra_info(
	rowid			INTEGER NOT NULL,
	content_sha256	TEXT NOT NULL UNIQUE,
	content			TEXT NOT NULL UNIQUE,
	content_sha1	TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa	TEXT NOT NULL,
	PRIMARY KEY(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha1) == 40),
	CHECK(LENGTH(kp_relay_id_rsa) == 40)
) STRICT;

CREATE INDEX idx_router_extra_info ON router_extra_info(content_sha1, kp_relay_id_rsa);

-- Stores which authority voted on which consensus.
--
-- Required to implement the consensus retrieval by authority fingerprints.
-- http://<hostname>/tor/status-vote/current/consensus/<F1>+<F2>+<F3>.z
CREATE TABLE consensus_authority_voter(
	consensus_rowid	INTEGER NOT NULL,
	authority_rowid	INTEGER NOT NULL,
	PRIMARY KEY(consensus_rowid, authority_rowid),
	FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(authority_rowid) REFERENCES authority(rowid)
) STRICT;
```

## Cache access to the database

The cache is implemented in a `HashMap<Sha256, Arc<[u8]>>` with some respective
wrappers around it for concurrenct access.  In the cache, the key corresponds to
the `sha256` column that exists in all document tables.

Each `HTTP GET` request is processed as follows (in terms of caching):
```
// This is pseudo-code!

// Search for the requested document and obtain the SHA-256.
let sha256 = sql("SELECT sha256 FROM table WHERE column_name = ?;");

let content;
if cache.contains_key(sha256) {
	// Read from cache.
	content = Arc::clone(&cache.get(sha256));
} else {
	// Read from db and insert into cache.
	let tmp = sql("SELECT content FROM table WHERE sha256 = ?", sha256);
	cache.insert(sha256, Arc::new(tmp));
	content = Arc::clone(&cache.get(sha256));
}

// Actually handle the request.

drop(content);
if cache.get(sha256).ref_count == 1 {
	cache.remove(sha256);
}
```

The purpose of this pseudo-code is to ensure that when parallel requests
requesting the same resource do not result in having to store the same data
more than once in memory at the same time.  Once the last request of that
resource has finished, we delete it from our cache.  This comes of the downside
that two independent requests that missed a short time window in which they
could have been parallel will result in a read from the database that might have
been redundant.  However, we trust in the OS buffer cache and SQLite internals
here to tackle this problem for us.

## Cache invalidation

Cache invalidation is not a problem because all resources are identified by a
unique hash.  The moment it is no longer in the database, it will no longer
be served, because the appropriate SHA256 hash is no longer returned.  Finally,
it will be eliminated from the cache when the last HTTP request still associated
with it terminates.

## Access to the database

It remains an open question which SQL backend to use.