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

Reading data from disk is very expensive compared to storing it in the memory,
hence why we need to implement some sort of caching facility in order to not
always read large blobs of data (such as all server descriptors, which make up
to around 6MB) from the disk, every time an onion proxy requests them from us.

To tackle this problem, we add a caching layer as an intermediate layer between
interfacing code and actual database access, as well as designing our database
structure in a way that allows fast look-ups, in case an actual reading from
disk is required.

In general, all `HTTP GET` requests that request some sort of directory
information *SHOULD* go through the cache.

## Structure of the database

The database schema is highly linked to the
[General use HTTP URLs](https://spec.torproject.org/dir-spec/general-use-http-urls.html)
found in the dircache specification, in almost all aspects.

In general, every document type for which there exists a query *MUST* have a
corresponding table of similar.  Document type hereby references to the document
format behind each endpoint, such as `consensus`, `consensus-microdesc`, `keys`,
`server`, `micro`, ...

Each table *MUST* contain at least one field named `content` which is of type
`BLOB`. This field contains the raw document as it is, without any compression
applied.

Next to the `content` field, each table *MUST* contain a field named `sha512` of
type `BLOB`, whose value *MUST* correspond to the SHA-512 checksum of `content`,
making it therefore content-adressable, as it also *MUST* serve as the primary
key for this table.

Now, a table *MUST* contain at least as many additional columns, as there are
ways to query that specific resource.  This means, that if a resource is
queryable via SHA1 digest or fingerprint, then the table must contain these
two items as additional columns.

Applying all of this together, we end of up with the following schema:

```sql
PRAGMA foreign_keys = ON;

-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus.z
-- http://<hostname>/tor/status-vote/current/consensus/<F1>+<F2>+<F3>.z
CREATE TABLE consensuses(
	sha512		BLOB NOT NULL UNIQUE,
	content		BLOB NOT NULL UNIQUE,
	valid_after	INTEGER NOT NULL, -- Unix timestamp of `valid-after`
	fresh_until	INTEGER NOT NULL, -- Unix timestamp of `fresh-until`
	valid_until	INTEGER NOT NULL, -- Unix timestamp of `valid-until`
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64)
) STRICT;

-- Helper table to model which authority voted on which consensus.
--
-- An entry in this table means that `authority` voted on `consensus`.
--
-- Required to implement:
-- http://<hostname>/tor/status-vote/current/consensus/<F1>+<F2>+<F3>.z
CREATE TABLE consensuses_votes(
	sha512		BLOB NOT NULL, -- SHA-512 of the consensus in binary
	authority	BLOB NOT NULL, -- SHA-1 fingerprint of the authority in binary
	PRIMARY KEY(sha512, authority),
	FOREIGN KEY(sha512) REFERENCES consensuses(sha512),
	CHECK(authority IN (
		-- Last updated on May 30th, 2024.
		X'27102BC123E7AF1D4741AE047E160C91ADC76B21', -- bastet
		X'0232AF901C31A04EE9848595AF9BB7620D4C5B2E', -- dannenberg
		X'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58', -- dizum
		X'70849B868D606BAECFB6128C5E3D782029AA394F', -- faravahar
		X'ED03BB616EB2F60BEC80151114BB25CEF515B226', -- gabelmoo
		X'23D15D965BC35114467363C165C4F724B64B4F66', -- longclaw
		X'49015F787433103580E3B66A1707A00E60F2D15B', -- maatuska
		X'F533C81CEF0BC0267857C99B2F471ADF249FA232', -- moria1
		X'2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C' -- tor26
	))
) STRICT;

-- Stores the microdescriptor consensus.
--
-- http://<hostname>/tor/status-vote/current/consensus-microdesc.z
CREATE TABLE consensuses_microdesc(
	sha512		BLOB NOT NULL UNIQUE,
	content		BLOB NOT NULL UNIQUE,
	valid_after	INTEGER NOT NULL, -- Unix timestamp of `valid-after`
	fresh_until	INTEGER NOT NULL, -- Unix timestamp of `fresh-until`
	valid_until	INTEGER NOT NULL, -- Unix timestamp of `valid-until`
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64)
);

-- Stores the key certificates.
--
-- http://<hostname>/tor/keys/all.z
-- http://<hostname>/tor/keys/authority.z
-- http://<hostname>/tor/keys/fp/<F>.z
-- http://<hostname>/tor/keys/sk/<F>-<S>.z
CREATE TABLE keys(
	sha512		BLOB NOT NULL UNIQUE,
	content		BLOB NOT NULL UNIQUE,
	fingerprint	BLOB NOT NULL, -- Identity key fingerprint (binary SHA-1)
	signing_key	BLOB NOT NULL, -- Signing key fingerprint (binary SHA-1)
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64),
	CHECK(LENGTH(fingerprint) == 20),
	CHECK(LENGTH(signing_key) == 20)
) STRICT;

-- Stores the router descriptors.
--
-- http://<hostname>/tor/server/fp/<F>.z
-- http://<hostname>/tor/server/d/<D>.z
-- http://<hostname>/tor/server/authority.z
-- http://<hostname>/tor/server/all.z
CREATE TABLE servers(
	sha512		BLOB NOT NULL UNIQUE,
	content		BLOB NOT NULL UNIQUE,
	fingerprint	BLOB NOT NULL, -- Identity key fingerprint (binary SHA-1)
	sha1		BLOB NOT NULL UNIQUE, -- Binary SHA-1 of `content`
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64),
	CHECK(LENGTH(fingerprint) == 20),
	CHECK(LENGTH(sha1) == 20)
) STRICT;

-- Stores which router descriptors were present in which consensuses.
--
-- This information is required for cleaning up old router descriptors, as we
-- may not delete them the moment they are no longer listed in a consensus.
CREATE TABLE servers_consensuses(
	server		BLOB NOT NULL,
	consensus	BLOB NOT NULL,
	PRIMARY KEY(server, consensus),
	FOREIGN KEY(server) REFERENCES servers(sha512),
	FOREIGN KEY(consensus) REFERENCES consensuses(sha512)
) STRICT;

-- Stores micro router descriptors.
--
-- http://<hostname>/tor/micro/d/<D>[.z]
CREATE TABLE microdescs(
	sha512	BLOB NOT NULL UNIQUE,
	content	BLOB NOT NULL UNIQUE,
	sha256	BLOB NOT NULL UNIQUE, -- Binary SHA-256 of `content`
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64),
	CHECK(LENGTH(sha256) == 32)
) STRICT;

-- Stores which micro router descriptors are present in which microdescriptor consensuses.
--
-- This is required for cleaning up old micro descriptors.
CREATE TABLE microdescs_consensuses(
	microdesc	BLOB NOT NULL,
	consensus	BLOB NOT NULL,
	PRIMARY KEY(microdesc, consensus),
	FOREIGN KEY(microdesc) REFERENCES microdescs(sha512),
	FOREIGN KEY(consensus) REFERENCES consensus_microdescs(sha512)
) STRICT;

-- Stores extra-info documents.
--
-- http://<hostname>/tor/extra/d/<D>.z
-- http://<hostname>/tor/extra/fp/<FP>.z
-- http://<hostname>/tor/extra/all.z
-- http://<hostname>/tor/extra/authority.z
CREATE TABLE extras(
	sha512		BLOB NOT NULL UNIQUE,
	content		BLOB NOT NULL UNIQUE,
	fingerprint	BLOB NOT NULL, -- Identity key fingerprint (binary SHA-1)
	sha1		BLOB NOT NULL UNIQUE, -- Binary SHA-1 of `content`
	PRIMARY KEY(sha512),
	CHECK(LENGTH(sha512) == 64),
	CHECK(LENGTH(fingerprint) == 32),
	CHECK(LENGTH(sha1) == 20)
) STRICT;
```

## Cache access to the database

*(cve: I feel like this is not very good, I am currently thinking about a better
model that simply uses the HTTP paths as the keys, as that makes it trivial
to also cache things such as `all.z`)*

This section only defines the API that is used for frequent read access to the
database, further design is needed for other scenarios where the database has
to be accessed.

Let us begin by defining a new type called `Cache`, which is created using a
database handle.

Internally, the cache consists of a `HashMap<[u8; 64], Vec<u8>>`, where the
key refers to a SHA-512 hash and the `Vec<u8>` to the actual data adressed by
that hash.  This serves as the fundament of the cache, as it contains the
backbone of all data.

Next to this `HashMap`, there also exist other `HashMap`'s, which mainly map
other keys to SHA-512 hashes, which is required for lookups, those `HashMap`'s
are:
* `HashMap<[u8; 32], [u8; 64]>` -- Maps microdescriptor SHA-2 hashes to SHA-512
* `HashMap<[u8; 20], [u8; 64]>` -- Maps router descriptor SHA-1 to SHA-512
* `HashMap<[u8; 20], [u8; 64]>` -- Maps extra-info SHA-1 to SHA-512
* `HashMap<[u8; 20], [u8; 64]>` -- Maps router desc fingerprints to SHA-512
* `HashMap<[u8; 20], [u8; 64]>` -- Maps extra-info fingerprints to SHA-512

Now when we get an incoming `HTTP GET` request, depending on the request, the
general procedure for lookups is as follows:
* Check whether there exists an entry in the corresponding hash map for the given information to a SHA-512 hash.
    * If so, obtain the SHA-512 hash and look it up in the big hash map above.
	* If not, query the database first for the corresponding resource and insert it into the respective maps.

It remains an open question on how we should store compressed elements.
Probably an additional layer above the `HashMap<[u8; 64], Vec<u8>>`.

## Cache invalidation

Every time a new consensus has been obtained, the cache has to be cleaned,
primarily due to fingerprints that must now match to newer SHA-512s.

## Access to the database

It remains an open question on how the code, outside of the cache, accesses the
database.  Do we use an ORM?  How beefed up should our SQLite provider be?
