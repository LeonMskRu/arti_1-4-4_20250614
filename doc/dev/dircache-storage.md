# Dircache Storage

This document tries to explain the storage model on how the dirache model stores
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
	content				TEXT NOT NULL UNIQUE,
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
	content				TEXT NOT NULL UNIQUE,
	old_consensus_rowid	INTEGER NOT NULL,
	new_consensus_rowid	INTEGER NOT NULL,
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
CREATE TABLE authority(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL UNIQUE,
	kp_auth_id_rsa_sha1		TEXT NOT NULL,
	kp_auth_sign_rsa_sha1	TEXT NOT NULL,
	last_consensus_rowid	INTEGER NOT NULL,
	FOREIGN KEY(last_consensus_rowid) REFERENCES consensus(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
	CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40)
) STRICT;

CREATE INDEX idx_authority ON authority(
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
--
-- TODO: Ensure on DB level that last_consensus_rowid.flavor = flavor.
CREATE TABLE router(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content_sha256			TEXT NOT NULL UNIQUE,
	content					TEXT NOT NULL UNIQUE,
	flavor					TEXT NOT NULL,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	last_consensus_rowid	INTEGER NOT NULL,
	router_extra_info_rowid	INTEGER,
	FOREIGN KEY(last_consensus_rowid) REFERENCES consensus(rowid),
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
	content					TEXT NOT NULL UNIQUE,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	last_consensus_rowid	INTEGER NOT NULL UNIQUE,
	FOREIGN KEY(last_router_rowid) REFERENCES consensus(rowid),
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
	PRIMARY KEY(consensus_rowid, authority_rowid),
	FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(authority_rowid) REFERENCES authority(rowid)
) STRICT;

-- Helper table to store compressed documents.
CREATE TABLE compressed_document(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	algorithm			TEXT NOT NULL,
	identity_sha256		TEXT NOT NULL UNIQUE,
	compressed_sha256	TEXT NOT NULL,
	compressed			BLOB NOT NULL,
	CHECK(LENGTH(identity_sha256) == 64),
	CHECK(LENGTH(compressed_sha256) == 64)
) STRICT;

CREATE INDEX idx_compressed_document ON compressed_document(
	algorithm,
	identity_sha256
);
```

## General operations

The following outlines some pseudo code for common operations.

### Request of an arbitrary document

The following models in pseudo code on how a network document is queried and
served:
* Search for the appropriate document and store `content_sha256`
	* Query a consensus:
		```sql
		SELECT content_sha256
		FROM consensus
		WHERE flavor = 'ns'
		ORDER BY valid_after DESC
		LIMIT 1;
		```
	* Query a consensus diff from a given hash `XXX` to the newest consensus:
		```sql
		SELECT content_sha256
		FROM consensus_diff
		WHERE old_consensus_rowid = (
			SELECT rowid
			FROM consensus
			WHERE flavor = 'ns' AND content_sha3_256 = 'XXX'
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
		FROM authority
		INNER JOIN consensus ON consensus.rowid = authority.last_consensus_rowid
		WHERE authority.kp_auth_id_rsa_sha1 = 'XXX'
		ORDER BY valid_after DESC
		LIMIT 1;
		```
	* Obtain a specific router descriptor:
		```sql
		SELECT content_sha256
		FROM router
		INNER JOIN consensus ON consensus.rowid = router.last_consensus_rowid
		WHERE router.kp_relay_id_rsa_sha1 = 'XXX'
		AND router.flavor = 'ns'
		AND consensus.flavor = 'ns'
		ORDER BY valid_after DESC
		LIMIT 1;
		```
	* Obtain extra-info:
		```sql
		SELECT content_sha256
		FROM router_extra_info

		```
* Check whether the `content_sha256` is in the cache
	* If so, clone the `Arc`
	* If not, query `content` with `WHERE content_sha256 = ?` and insert it into
	  the cache
* Transmit the data to the client
* Check whether the reference counter is `1`
	* If so, remove `content_sha256` entirely from the cache, as we are the last
	  active server of the resource.
	* If not, do nothing except.

TODO: Do this for caching, I doubt it will be much different though ...

### Insertion of a new consensus

1. Download the consensus and consensus-md from an authority
2. Parse and validate it accordingly to the specification
3. Figure out the missing router descriptors and extra-info documents
4. Download the missing router descriptors and extra-info documents from
   directory authorities
5. Compute consensus diffs
6. Compute compressions
7. Insert everything in one transaction into the database and update the
   `last_consensus_rowid` fields.

### Garbage Collection

Over time, the dircache will collect some garbage.  This is intentional,
as various documents are not deleted the moment they are no longer listed in
a consensus.

Regularly, the following SQL transaction is executed:
```sql
BEGIN TRANSACTION;

-- Temporary table storing all old consensuses we will delete.
CREATE TEMP TABLE old_consensus(
	consensus_rowid	INTEGER NOT NULL
);

-- Populate `old_consensus` with all consensuses older than seven days.
INSERT INTO old_consensus(consensus_rowid)
SELECT rowid
FROM consensus
WHERE valid_until <= (NOW - 7 DAYS); -- Pseudo-code I know

-- Temporary table storing all old authorities we will delete.
CREATE TEMP TABLE old_authority(
	authority_rowid	INTEGER NOT NULL
);

-- Populate `old_authority`.
INSERT INTO old_authority(authority_rowid)
SELECT rowid
FROM authority
WHERE last_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus);

-- Temporary table storing all old router descriptors we will delete.
CREATE TEMP TABLE old_router(
	router_rowid INTEGER NOT NULL
);

-- Populate `old_router` with all routers who were last seen in a consensus that
-- will be deleted.
INSERT INTO old_router(router_rowid)
SELECT rowid
FROM router
WHERE last_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus);

-- Now actually delete data.
DELETE
FROM router
WHERE last_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus);

DELETE
FROM router_extra_info
WHERE last_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus);

DELETE
FROM consensus_authority_voter
WHERE consensus_rowid IN (SELECT consensus_rowid FROM old_consensus) OR
authority_rowid IN (SELECT authority_rowid FROM old_authority);

DELETE
FROM authority
WHERE rowid IN (SELECT authority_rowid FROM old_authority);

DELETE
FROM consensus_diff
WHERE old_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus) OR
new_consensus_rowid IN (SELECT consensus_rowid FROM old_consensus);

DELETE
FROM consensus
WHERE rowid IN (SELECT consensus_rowid FROM old_consensus);

DELETE FROM compressed_document
WHERE identity_sha256 NOT IN
(SELECT content_sha256 FROM consensus) OR
(SELECT content_sha256 FROM authority) OR
(SELECT content_sha256 FROM router) OR
(SELECT content_sha256 FROM router_extra_info);

END TRANSACTION;
```

## HTTP backend

The current plan is to use warp as the HTTP backend.

## SQL backend

The current plan is to use SQLx as the SQL backend.