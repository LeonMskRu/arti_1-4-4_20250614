# Dircache Storage

This document tries to explain the storage model on how the dircache stores
data internally.

## Requirements

1. Be fault resilient (e.g. power-loss/sudden crashes *MUST NOT* result in data loss)
2. Be fast with lookups by various keys (e.g. fingerprint, digest, ...)
3. Have everything in one place
4. Avoid redundant copies of (frequently used) data

## SQLite as the fundamental primitive

*SQLite* has been chosen as the primitive data storage back-end, because it
offers a neat read performance and acceptable write performance, although the
latter one is more critical for dirauths rather than dircaches due to the
frequently uploaded descriptors and data; besides it satisfies the first two
requirements trivially and the latter two if we add certain constraints outlined
below.

## Future extension towards a dirauth

A dircache forms the basis of a dirauth.  The current plan is to design the
dircache as an independent component of which the dirauth related code is merely
an extension.  Due to this design decision, all dirauth related data structures
*SHOULD* have their own tables.

## Caching as a middle layer

As outlined above, we want to avoid having the same data multiple times in
memory.  Let's say we serve the same request a thousand times in parallel,
then we do not want to store the same data 10,000 times in memory but rather
only once.

The goal of the cache *IS NOT* to reduce the number of disk reads for frequently
requested data.  We rely on SQLite internals and the operating system's buffer
cache to handle this well-enough for us.  Besides, in times of solid state
drives, disk access is in the microseconds and no longer a bottle neck as it
once used to be.

The cache is implemented by a
```rust
RwLock<HashMap<Sha256, Arc<[u8]>>>
```

## Compression

## Structure of the database

The database schema consists of two types of tables:
* Document tables
	* Represent actual documents that are served by the dircache
	* Those documents are: consensuses, consensus diffs, authority information,
	  router descriptors, and extra-info documents
* Helper tables
	* Tables that contain additional information about documents we serve
	* For example: compressed data, authority votes on consensuses, ...

A *document table* has a few mandatory columns, whereas *helper tables* are too
domain specific to impose any restrictions on them.

A *document table* *MUST* the following columns:
* `rowid`
	* Serves as the primary key
* `content_sha256`
	* Uniquely identifies and addresses the data by `content`
* `content`
	* The actual raw content of the document
	* *MUST* be valid UTF-8 under all circumstandes

Besides, every document table *MUST* have an index on `content_sha256` as well
as any other key by which clients may query it. (Such as the fingerprint for
router descriptors).

Below, we suggest various `CREATE INDEX` to help with queries.
The precise set of indices we will create is not yet finalised.
We'll adjust those after we see the query code and the resulting query plans.

The actual SQL schema is outlined below:
```sql
-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>.z
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>.z
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>.z
CREATE TABLE consensus(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256		TEXT NOT NULL UNIQUE,
	content				TEXT NOT NULL,
	content_sha3_256	TEXT NOT NULL UNIQUE,
	flavor				TEXT NOT NULL,
	valid_after			INTEGER NOT NULL, -- Unix timestamp of `valid-after`.
	fresh_until			INTEGER NOT NULL, -- Unix timestamp of `fresh-until`.
	valid_until			INTEGER NOT NULL, -- Unix timestamp of `valid-until`.
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha3_256) == 64),
	CHECK(flavor IN ('ns', 'md'))
) STRICT;

CREATE INDEX idx_consensus ON consensus(
	content_sha256,
	content_sha3_256,
	valid_after
);

-- Stores consensus diffs.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>.z
--
-- TODO: Enforce on DB level that only diffs of the same flavor may be stored
-- within the table, old_consensus_rowid.flavor = new_consensus_rowid.flavor.
CREATE TABLE consensus_diff(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256		TEXT NOT NULL UNIQUE,
	content				TEXT NOT NULL,
	old_consensus_rowid	INTEGER NOT NULL,
	new_consensus_rowid	INTEGER NOT NULL,
	last_seen			INTEGER NOT NULL,
	FOREIGN KEY(old_consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(new_consensus_rowid) REFERENCES consensus(rowid),
	CHECK(LENGTH(content_sha256) == 64)
) STRICT;

CREATE INDEX idx_consensus_diff ON consensus_diff(
	content_sha256
);

-- Directory authority key certificates.
--
-- This information is derived from the consensus documents.
--
-- http://<hostname>/tor/keys/all.z
-- http://<hostname>/tor/keys/authority.z
-- http://<hostname>/tor/keys/fp/<F>.z
-- http://<hostname>/tor/keys/sk/<F>-<S>.z
CREATE TABLE authority_key_certificate(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL,
	kp_auth_id_rsa_sha1		TEXT NOT NULL,
	kp_auth_sign_rsa_sha1	TEXT NOT NULL,
	last_seen				INTEGER NOT NULL,
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
	CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_authority ON authority_key_certificate(
	content_sha256,
	kp_auth_id_rsa_sha1,
	kp_auth_sign_rsa_sha1
);

-- Stores the router descriptors.
--
-- http://<hostname>/tor/server/fp/<F>.z
-- http://<hostname>/tor/server/d/<D>.z
-- http://<hostname>/tor/server/authority.z
-- http://<hostname>/tor/server/all.z
CREATE TABLE router(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL,
	flavor					TEXT NOT NULL,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	last_seen				INTEGER NOT NULL,
	router_extra_info_rowid	INTEGER,
	FOREIGN KEY(router_extra_info_rowid) REFERENCES router_extra_info(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(flavor IN ('ns', 'md')),
	CHECK(LENGTH(content_sha1) == 40),
	CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_router ON router(
	content_sha256,
	content_sha1,
	kp_relay_id_rsa_sha1
);

-- Stores extra-info documents.
--
-- http://<hostname>/tor/extra/d/<D>.z
-- http://<hostname>/tor/extra/fp/<FP>.z
-- http://<hostname>/tor/extra/all.z
-- http://<hostname>/tor/extra/authority.z
CREATE TABLE router_extra_info(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	last_seen				INTEGER NOT NULL,
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha1) == 40),
	CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_router_extra_info ON router_extra_info(
	content_sha256,
	content_sha1,
	kp_relay_id_rsa_sha1
);

-- Helper table to store which authority voted on which consensus.
--
-- Required to implement the consensus retrieval by authority fingerprints.
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>.z
CREATE TABLE consensus_authority_voter(
	consensus_rowid	INTEGER NOT NULL,
	authority_rowid	INTEGER NOT NULL,
	last_seen		INTEGER NOT NULL,
	PRIMARY KEY(consensus_rowid, authority_rowid),
	FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(authority_rowid) REFERENCES authority_key_certificate(rowid)
) STRICT;

-- Helper table to store compressed documents.
CREATE TABLE compressed_document(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	algorithm			TEXT NOT NULL,
	identity_sha256		TEXT NOT NULL,
	compressed_sha256	TEXT NOT NULL,
	compressed			BLOB NOT NULL,
	last_seen			INTEGER NOT NULL,
	CHECK(LENGTH(identity_sha256) == 64),
	CHECK(LENGTH(compressed_sha256) == 64)
) STRICT;

CREATE UNIQUE INDEX idx_compressed_document ON compressed_document(
	identity_sha256,
	algorithm,
);
```

## General operations

The following outlines some pseudo code for common operations.

### Request of an arbitrary document

The following models in pseudo code on how a network document is queried and
served:
1. Search for the appropriate document and store `content_sha256`
2. Check whether the `content_sha256` is in the cache
	* If so, clone the `Arc`
	* If not, query `content` with `WHERE content_sha256 = ?` and insert it into
	  the cache
3. Transmit the data to the client
4. Check whether the reference counter is `1` (Controversial, see "Cleaning the cache")
	* If so, remove `content_sha256` entirely from the cache, as we are the last
	  active server of the resource.
	* If not, do nothing except.
	* For improving the development experience, it is probably best to implement
	  that in a `Drop` trait.

TODO: Do this for compression, I doubt it will be much different though ...

Below is some Rust-like pseudo code demonstrating it.
It follows a locking hierarchy where none of the locks (db and cache) may be
held simultanously.
```rust
// (1)
let sha256 = db.lock().query("SELECT content_sha256 FROM table WHERE column_name = column_value");

let content = if cache.read().contains_key(sha256) {
	// Read from the cache.
	Arc::clone(&cache.read().get(sha256))
} else {
	// Read from db and insert into cache.
	// `db` and `cache` are not hold simultanously but only for each operation.
	let content = Arc::new(db.lock().query(format!("SELECT content FROM table WHERE content_sha256 = {sha256}")));
	cache.write().insert(sha256, Arc::clone(&content));
	content
};
```

### Example `SELECT` queries

* Query a consensus:
	```sql
	SELECT content_sha256
	FROM consensus
	WHERE flavor = 'ns'
	ORDER BY valid_after DESC
	LIMIT 1;
	```
* Query a consensus diff from a given hash `HHH` to the newest consensus:
	```sql
	SELECT content_sha256
	FROM consensus_diff
	WHERE old_consensus_rowid = (
		SELECT rowid
		FROM consensus
		WHERE flavor = 'ns' AND content_sha3_256 = 'HHH'
	) AND new_consensus_rowid = (
		SELECT rowid
		FROM consensus
		WHERE flavor = 'ns'
		ORDER BY valid_after DESC
		LIMIT 1
	);
	```
* Obtain the key certificate of a certain authority:
	```sql
	SELECT content_sha256
	FROM authority_key_certificate
	WHERE kp_auth_id_rsa_sha1 = 'HHH'
	ORDER BY last_seen DESC
	LIMIT 1;
	```
* Obtain a specific router descriptor:
	```sql
	SELECT content_sha256
	FROM router
	WHERE kp_relay_id_rsa_sha1 = 'HHH'
	AND flavor = 'ns'
	ORDER BY last_seen DESC
	LIMIT 1;
	```
* Obtain extra-info:
	```sql
	SELECT content_sha256
	FROM router_extra_info
	WHERE rowid = (
		SELECT router_extra_info_rowid
		FROM router
		WHERE kp_relayid_rsa_sha1 = 'HHH'
		ORDER BY last_seen DESC
		LIMIT 1
	)
	ORDER BY last_seen
	LIMIT 1;
	```

### Garbage Collection

Over time, the dircache will collect some garbage.  This is intentional,
as various documents are not deleted the moment they are no longer listed in
a consensus.

```sql
BEGIN TRANSACTION;

DELETE
FROM consensus_diff
WHERE last_seen <= unixepoch() - (60 * 60 * 24 * 7);

DELETE
FROM consensus_authority_voter
WHERE last_seen <= unixepoch() - (60 * 60 * 24 * 7);

DELETE FROM
consensus_authority_voter
INNER JOIN consensus AS cons ON consensus_rowid = cons.rowid
INNER JOIN authority_key_certificate AS auth ON authority_rowid = auth.rowid
WHERE auth.last_seen <= unixepoch() - (60 * 60 * 24 * 7)
OR cons.last_seen <= unixepoch() - (60 * 60 * 24 * 7);

DELETE
FROM consensus
WHERE valid_after <= unixepoch() - (60 * 60 * 24 * 7);

DELETE
FROM authority_key_certificate
WHERE last_seen <= unixepoch() - (60 * 60 * 24 * 7);

DELETE
FROM router
WHERE last_seen <= unixepoch() - (60 * 60 * 24 * 7);

DELETE
FROM compressed_documents
WHERE last_seen <= unixepoch() - (60 * 60 * 24 * 7);

END TRANSACTION;
```

### Insertion of a new consensus

This one explains how we insert a new consensus into the dircache.
It works similarly for `consensus-md`.

1. Download the consensus from an authority
2. Parse and validate it accordingly to the specification
3. Figure out the missing router descriptors and extra-info documents
4. Download the missing router descriptors and extra-info documents from
   directory authorities in an asynchronous task that modifies the database
   as it goes along.
5. Compute consensus diffs
6. Compute compressions
7. Insert everything in one transaction into the database and update the
   `last_seen` fields.

## Cleaning the cache

Right now, there are two proposals for cleaning the cache:

1. Utilize `Drop` traits
* A wrapper around the end of each HTTP callback which checks the `Arc`'s
	  reference count and deletes it in the case that it is currently no longer
	  used by any other active HTTP request.
	  The wrapper must contain a clone of the `Arc<RwLock<HashMap<..>>>`.
	  This is the approach presented in the text above.
2. Put `Weak` in the hash map.  Clean up dangling entries later.
    * Using `Weak` in the map means data is discarded as soon as it's no
          longer being served, but leaves dangling entries in the `HashMap`.
	* Periodically scan the `HashMap` for dangling `Weak`s.  This could
	  be done with an asynchronous task, or after database garbage collection..

## HTTP backend

The current plan is to use warp as the HTTP backend.

## SQL backend

The current plan is to use SQLx as the SQL backend.