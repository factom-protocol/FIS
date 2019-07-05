| FIS   | Title         | Status | Category               | Author                                     | Created    |
| ----- | ------------- | ------ | ---------------------- | ------------------------------------------ | ---------- |
| -     | Factom Decentralized Identifiers (DID)  | Draft  | Identities       |  | 20190702   |

_Factomatic LLC: Valentin Ganev & Peter Asenov, Sphereon BV: Niels Klomp, Factom Inc: Carl Diclimenti, Sam Barnes

# Summary


# Motivation


# Specification

---
title: Factom Decentralized Identifiers (DID) Specification
---



Version 1.0.0

Introduction
============

This specification describes [decentralized
identifiers](https://w3c-ccg.github.io/did-spec/) (DIDs) for the Factom
blockchain. DIDs are an emerging effort for establishing a standard for
self-sovereign digital identities from the W3C [Credentials Community
Group](https://www.w3.org/community/credentials/). They provide entities with a
means to self-manage cryptographic key material and other metadata about their
identity. These data can be used by the entity to authenticate itself to third
parties or to request authorization for access to a given resource. In addition
to this -- due to the public nature of the DIDs -- they allow third parties to
discover this information and define ways in which to communicate with a given
digital identity.

Next, we provide a short overview of the actors involved in a DID system as well
as the terminology and the basic building blocks of a decentralized identifier.
Please note that implementers of this spec are expected to have knowledge of the
W3C specification.

Actors
------

There are three main entities involved in a DID system: a Controller, a Relying
Party and a Subject.

Controllers create and control DIDs, while Relying Parties rely on DIDs as an
identifier for interactions related to the Subject.

The Subject is the entity referred to by the DID, which can be literally
anything: a person, an organization, a device, a location, even a concept.
Typically, the Subject is also the Controller, but in cases of guardianship,
agents (human or software), and inanimate Subjects, this is not possible. As
such, the Subject has no functional role. When the Subject and Controller
coincide, we consider the action of the Controller, to be on behalf of
themselves as the Subject. When the Subject is not the Controller, the
Controller is said to be taking action on behalf of the Subject, such as when an
employee manages a DID on behalf of their employer or a parent uses a DID on
behalf of their child. [1]

DID Schemes
-----------

A DID scheme is the formal syntax, which defines how a decentralized identifier
should look like. The generic DID scheme is defined in [2]. A DID method
specification, such as the one in this document, defines a specific DID scheme,
conforming to the generic one in [2], and utilized in a specific DID method.

DID Methods
-----------

A definition of how a specific DID scheme can be implemented on a specific
distributed ledger or network, including the precise method(s) by which DIDs and
DID Documents can be read, written, updated and deactivated [2].

DID Documents
-------------

A set of data that describes a DID, including mechanisms, such as public keys
and pseudonymous biometrics, that an entity can use to authenticate itself as
the DID. A DID Document may also contain other
[claims](https://en.wikipedia.org/wiki/Claims-based_identity) describing the
entity, as well as rules for delegating certain rights to another DID. DID
documents are graph-based data structures that are typically expressed using
[JSON-LD](https://w3c-ccg.github.io/did-spec/#bib-json-ld), but may be expressed
using other compatible graph-based data formats [2].

DID Resolvers & Registrars
--------------------------

A DID system has two main software components: a
[resolver](https://github.com/decentralized-identity/universal-resolver) and a
[registrar](https://github.com/decentralized-identity/universal-registrar/blob/master/docs/api-documentation.md).
The role of the resolver is to return the valid DID document for a given DID. On
the other hand, the role of the registrar is to allow the creation of new DIDs
and DID documents.

DID Format
----------

The DID format is inspired from the basic pattern used in the specification of
[URNs](https://tools.ietf.org/html/rfc8141):

![](media/4967f209e7bf06357fc186608e2cba34.png)

For DIDs, the namespace component identifies a DID method, while the namespace
specific string is used to represent the DID method specific string:

![](media/db3c7e52fe497bf07f691842b6d15325.png)

All DID method specifications **must** define the format and generation of the
DID method specific string. Note that this string **must** be unique in the
namespace of that DID method [3].

Factom DID Method
=================

DID Method Name
---------------

The namestring that shall identify this DID method is: factom

A DID that uses this method MUST begin with the following prefix: did:factom.
Per the DID specification, this string MUST be in lowercase. The remainder of
the DID, after the prefix is specified below.

Method Specific Identifier
--------------------------

The method specific name string is composed of an optional Factom network
identifier with a :separator, followed by a hex-encoded Factom chain ID.

| factom-did = "did:factom:" factom-specific-idstring                                                                                                                                    |
| factom-specific-idstring = [ factom-network ":" ] factom-chain-id                                                                                                                      |
| factom-network = "mainnet" / "testnet"                                                                                                                                                 |
| factom-chain-id = 64\*HEXDIG                                                                                                                                                           |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


The factom-chain-id is case-insensitive.

This specification currently only supports Factom "mainnet" and "testnet", but
can be extended to support any number of public or private Factom networks. If
you leave out the factom-network mainnet is assumed typically, but in reality it
is left up to the resolver. If the resolver is only hooked up to a specific
network it will on look at that network.

Example factom DIDs:

-   did:factom:f26e1c422c657521861ced450442d0c664702f49480aec67805822edfcfee758

-   did:factom:mainnet:f26e1c422c657521861ced450442d0c664702f49480aec67805822edfcfee758

-   did:factom:testnet:

DID Management (CRUD operations, entry structures, validation rules)
====================================================================

Creation
--------

Purpose: A valid entry of this type creates the DID document, located at the DID
URI: did:factom:{chain-id}

The purpose of the nonce is to make the chain ID for the new DID unique. It is
up to the implementor to assure this. The SHA256 hash of the Content field might
be a nice suitable default.

The JSON-LD context is the default context for DIDs [2]. Future versions of the
specification could migrate to a Factom-specific context.

The format of the publicKey, authentication and service values are described in
later sections in this document.

Resolution Rules:

-   MUST be the first entry of the chain

-   MUST have a valid didMethodVersion specified (currently only "1.0.0"
    supported)

-   MUST have at least one management key at priority 0

Entry Structure:

| **ExtIDs** [0] = "DIDManagement"                         // UTF-8 encoded [1] = \<entry schema version tag\>              // UTF-8 encoded (ex: "1.0.0") [semantic versioned](https://snowplowanalytics.com/blog/2014/05/13/introducing-schemaver-for-semantic-versioning-of-schemas/) [2] = \<misc tags / identity names\>            // UTF-8 encoded (2nd ExtID must be unique (recommended 32 byte nonce)) ... [n] = \<misc tags / identity names\>            // UTF-8 encoded (note: content JSON always minified) **Content** "{   "didMethodVersion": \<new method spec version tag as string\>,   "managementKey": [     {       "id": \<key identifier\>,       "type": \<key type ("Ed25519VerificationKey", "ECDSASecp256k1VerificationKey", "RSAVerificationKey")\>,       "controller": \<DID which controls this key\>,       "publicKeyBase58": \<public key value\>,       "priorityRequirement": \<positive integer priority\>,       "bip44": \<bip44 derivation path string\> // (optional)     },     ...   ],   "didKey": [ // (optional)     {       "id": \<key identifier\>,       "type": \<key type ("Ed25519VerificationKey", "ECDSASecp256k1VerificationKey", "RSAVerificationKey")\>,       "controller": \<DID which controls this key\>,       "publicKeyBase58": \<public key value\>,       "purpose": ["publicKey", "authentication"],       "priorityRequirement": \<positive integer priority required to remove this key\>, // (optional)       "bip44": \<bip44 derivation path string\> // (optional)     },     ...   ],   "service": [ // (optional)     {                                                                                                                                                                                                                                                    |
|       "id”: \<service identifier\>,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|       "type”: \<service type\>,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|       "serviceEndpoint”: \<URL for service endpoint\>,       "priorityRequirement": \<positive integer priority required to remove this service (optional)\>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|     },     ...   ] }"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Example:

| **ExtIDs** [0] = "DIDManagement" [1] = "1.0.0" [2] = "d9fc30722f88ed15e98b8c256b79242df8d00c042d703306c7720796d4f0f7cd"  // UTF-8 32 bytes of randomness **Content** "{   "didMethodVersion": "0.1.0",   "managementKey": [     {       "id": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-1",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|       "type": "Ed25519VerificationKey",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|       "controller": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|       "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",       "priorityRequirement": 1     }   ],   "didKey": [     {       "id": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#public-1",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|       "type": "Ed25519VerificationKey",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|       "controller": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|       "publicKeyBase58": "3uVAjZpfMv6gmMNam3uVAjZpfkcJCwDwnZn6MNam3uVA"       "purpose": ["publicKey", "authentication"]     },     {       "id": "did:factom:76c58916c58916ec258f246851bea091d14d4247a2fc3e18694461b14247a2f\#authentication-1",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|       "type": "ECDSASecp256k1VerificationKey",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|       "controller": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|       "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",       "purpose": ["authentication"],       "priorityRequirement": 1,       "bip44": "m / 44' / 0' / 0' / 0 / 0"     }   ],   "service": [     {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|       “id”: “did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#cr”,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|       “type”: “CredentialRepositoryService”,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|       “serviceEndpoint”: “https://repository.example.com/service/8377464”       "priorityRequirement": 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|     }   ] }"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Notes:

-   Explicitly did not include "\@context" in the content as the resolver can
    add this when creating the DID document for a given schema version

    -   Our DID Method Spec version determines the DID Spec version that we
        return 

Update
------

Purpose: A valid entry of this type signifies an attempt to update the DID
Document's (public keys, authentication, service endpoints)

Resolution Rules:

-   Signer key MUST be a management key

-   Signer key MUST be currently active at this point in the chain

-   Signer key MUST be of the same or higher priority than all keys being
    added/replaced/retired (checking the optional priorityRequirement element) 

-   Signer key CAN NOT add another management key at the same priority level,
    unless it is also removing itself

-   Signature MUST be over sha256( sha256( ExtID[0] + ExtID[1] + ExtID[2] +
    ExtID[4] + … + ExtID[n] + Content) )

-   Entry hash serves as the nonce and MUST be unique

-   Adding Keys

    -   A key being added must never have been previously active for this
        identity

    -   A key being added must have a key-identifier that has never been
        previously used for this identity

-   Removing Keys

    -   A key being removed must be currently active

Entry Structure:

| ExtIDs [0] = "DIDUpdate"                                                   // UTF-8 encoded [1] = \<entry schema version tag\>                                    // UTF-8 encoded [2] = \<full key identifier of the management key used for signing\>  // UTF-8 encoded (signature type inferred from key type) [3] = \<signature over sha256d(all other ext-ids + content)\>         // raw bytes, N bytes (signature type dependent) [4] = \<misc tags\>                                                   // encoding not enforced ... [n] = \<misc tags\>                                                   // encoding not enforced Content = " {     "revoke": {         "managementKey": array of management key identifiers to retire (optional),         "didKey": array of other key identifiers to retire (optional),         "service": array of service ids to retire (optional)     } (optional),     "add": {         "managementKey": array of management key objects to add (optional),         "didKey": array of other key object to add (optional),         "service": array of service object to add (optional)     } (optional) } " |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Example:

| ExtIDs [0] = "DIDUpdate"                                                                                 // UTF-8 encoded [1] = "1.0.0"                                                                                     // UTF-8 encoded [2] = "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-1"  // UTF-8 encoded [3] = 0xf88ed15e98b8cb8c256b79242df8d00c042d70330a7edf56c772079256b79242                          // raw bytes, N bytes Content = " {     "revoke": {         "managementKey": [           "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-1",           "management-2"         ],         "didKey": [           "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#public-1"         ],         "service": [           "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#cr"         ]     },     "add": {         "managementKey": [{           "id": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-2",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|           "type": "Ed25519VerificationKey",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|           "controller": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|           "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",           "priority": 1         }],         "didKey": [{           "id": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#authentication-2",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|           "type": "Ed25519VerificationKey",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|           "controller": "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|           "publicKeyBase58": "3uVAjZpfMv6gmMNH3C2AVjZpfkcJCwDwnZn6z3DwnZn6",           "purpose": ["publicKey", "authentication"],           "priorityRequirement": 2,         }],         "service": [{                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|             "id”: "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#inbox"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|           "type”: "SocialWebInboxService",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|           "serviceEndpoint": "https://social.example.com/83hfh37dj",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|           "description": "My public social inbox",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|           "spamCost": {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|             "amount": "0.50",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|             "currency": "USD"            }         }]     } } "                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Method Spec Version Upgraded
----------------------------

Purpose: A valid entry of this type signifies that the chain should stop being
parsed using its currently declared version, and from this point forward be
parsed according to the rules of the new version.

Resolution Rules:

-   Signer key MUST be a management key

-   Signer key MUST be currently active at this point in the chain

-   New method spec version must be greater than the currently active version
    for this identity

-   Signature MUST be over sha256( sha256( ExtID[0] + ExtID[1] + ExtID[2] +
    ExtID[4] + … + ExtID[n] + Content) )

-   Entry hash serves as the nonce and MUST be unique

Entry Structure:

| ExtIDs [0] = "DIDMethodVersionUpgrade"                                    // UTF-8 encoded [1] = \<entry schema version tag\>                                   // UTF-8 encoded [2] = \<full key identifier of the management key used for signing\> // UTF-8 encoded (signature type inferred from key type) [3] = \<signature over sha256d(all other ext-ids + content)\>        // raw bytes, N bytes (signature type dependent) [4] = \<misc tags\>                                                  // encoding not enforced …. [n] = \<misc tags\>                                                  // encoding not enforced Content = '{"didMethodVersion": \<new method spec version tag as a string\>}' |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Example:

| ExtIDs [0] = "DIDMethodVersionUpgrade" [1] = "1.0.0" [2] = "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-1" [3] = 0xf88ed15e98b8cb8c256b79242df8d00c042d70330a7edf56c772079256b79242 Content = '{"didMethodVersion": "0.2.0"}' |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Deactivation
------------

Purpose: A valid entry of this type signifies the deactivation of the identity
and the termination of all further chain parsing

Resolution Rules:

-   Signer key MUST be a management key

-   Signer key MUST be currently active at this point in the chain

-   Signer key MUST be of the highest priority for this identity

-   Signature MUST be over sha256( sha256( ExtID[0] + ExtID[1] + ExtID[2] +
    ExtID[4] + … + ExtID[n] + Content) )

-   Entry hash serves as the nonce and MUST be unique

Entry Structure:

| ExtIDs [0] = "DIDDeactivation"                                             // UTF-8 encoded [1] = \<entry schema version tag\>                                    // UTF-8 encoded [2] = \<full key identifier of the management key used for signing\>  // UTF-8 encoded (signature type inferred from key type) [3] = \<signature over sha256d(all other ext-ids + content)\>         // raw bytes, N bytes (signature type dependent) [4] = \<misc tags\>                                                   // encoding not enforced ... [n] = \<misc tags\>                                                   // encoding not enforced Content = None |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


Example:

| ExtIDs [0] = "DIDDeactivation" [1] = "1.0.0" [2] = "did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#management-1" [3] = 0xf88ed15e98b8cb8c256b79242df8d00c042d70330a7edf56c772079256b79242 Content = None |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


### Public Keys

The didKey values are the cryptographic keying material that is associated with
the DID subject. They are used for digital signatures, encryption and other
cryptographic operations, which in turn are the basis for purposes such as
authentication or establishing secure communication with service endpoints. In
addition, public keys may play a role in authorization mechanisms of DID CRUD
operations.

The managementKey are quite similar except these do not end up in the DID
document and are being used to perform the CRUD operation on the Factom
blockchain itself.

The object for a single key has the following schema:

{  
“id”: a valid DID with a
[fragment](https://w3c-ccg.github.io/did-spec/#dfn-did-fragment) for identifying
the key (required),  
“type”: the type of the key (required),  
“controller”: the controller of the key (required),  
“publicKeyBase58”: the public key, encoded in base58 (required)  
}

The id must be a valid DID with the format did:factom:CHAIN_ID\#KEY_IDENTIFIER,
where:

-   CHAIN_ID is the ID of the current chain

-   KEY_IDENTIFIER is a sequence of up to 32 lowercase alphanumeric characters,
    plus hyphen, without spaces (i.e. KEY_IDENTIFIER matches the regular
    expression \^[a-z0-9-]{1,32}\$). The intended usage of KEY_IDENTIFIER is to
    serve as a nickname/alias for the key and it should be unique across the
    keys defined in the DID document.

The type field can be any value, which identifies the type of signature to be
used and is left for implementers of this specification to decide. Good examples
of values are widespread or unambiguous abbreviations of different signatures
schemes, such as “Ed25519” or “ECDSASecp256k1”, while bad examples include
“EdDSA” (ambiguous as it specifies the signature scheme, but does not specify
the elliptic curve over which the keys are generated) or “Secp256k1” (ambiguous
as it specifies the elliptic curve, but does not specify the signature scheme).

The controller field must be a valid DID.

Note that the public key is stored in the publicKeyBase58 field using a base58
encoding. Other valid formats for storing the public keys are: publicKeyPem,
publicKeyHex, publicKeyBase64, publicKeyMultibase. We defer the readers
unfamiliar with the PEM format to [5] and the ones not familiar with multibase
encoding to [6] and [7]. Similar to publicKeyBase58, the base64 and hex variants
of the field name for storing the public keys represent the widespread base64
and hex encodings of the public keys.

### Authentication

The authentication values specify public keys, which can be used specifically
for authenticating the DID subject. The keys used can be either those defined in
publicKey or freshly defined ones.

To reference an existing key, the id of the key must be used. To add a new key,
the same format as the one for publicKey must be used. Below is an example,
which demonstrates both usages:  
  
“authentication”: [  
// this key is referenced, it may be used for other purposes besides
authentication  
“did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#keys-1”,  
// this key is embedded and may \*only\* be used for authentication  
{  
“id”:  
“did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#keys-2”,  
“type”: “Ed25519VerificationKey”,  
“controller”:  
“did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b”,  
“publicKeyBase58”: “H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV”  
}  
]

### <br>Services

The service values specify endpoints, which can be used to interact with the DID
subject. Each service endpoint must include id, type, and serviceEndpoint
properties, and may include additional properties. The value of the
serviceEndpoint property must be a valid URI conforming to [RFC
3986](https://tools.ietf.org/html/rfc3986). The id should be a unique value and
a valid DID with the following format did:factom:CHAIN_ID\#SERVICE_IDENTIFIER,
where SERVICE_IDENTIFIER matches the regular expression \^[a-z0-9-]{1,32}\$.

Below are two examples of service entries, adapted from [2], with the first one
containing only the mandatory fields for the service and the second one
containing additional data:

“service”: [{  
“id”:
“did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#cr”,  
“type”: “CredentialRepositoryService”,  
“serviceEndpoint”: “https://repository.example.com/service/8377464”  
},  
{  
“id”:
“did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\#inbox”  
“type”: “SocialWebInboxService”,  
“serviceEndpoint”: "https://social.example.com/83hfh37dj",  
“description”: “My public social inbox”,  
“spamCost”: {  
“amount”: “0.50”,  
“currency”: “USD”  
}]

DID Resolution
--------------

The resolution of a DID is the process of constructing a DID document by
sequentially scanning the entries recorded in the DID chain. Next, we outline
the rules, which must be followed by resolvers for the Factom DID method:

-   A CreateDID entry must appear only as the first entry in a chain

-   UpdateDID and DeactivateDID entries must be signed by an unrevoked key
    defined in publicKey. The key must be referenced by its KEY_IDENTIFIER in
    the ExtID of the entry. If multiple keys in publicKey have the same
    KEY_IDENTIFIER, a signature is considered valid if it comes from any of the
    keys with this identifier.

-   If the signature of an UpdateDID entry is from a key which is listed for
    revoking in the same entry, the signature is still considered valid.

-   UpdateDID and DeactivateDID entries with invalid signatures must be ignored.

-   UpdateDID entries with a non-unique nonce must be ignored, i.e. if two
    entries in the DID chain have the same nonce, the second entry must be
    ignored. This is done to prevent intra-chain replay attacks.

-   If a DeactivateDID entry is encountered, scanning must be terminated
    immediately and the resolver must return an appropriate response, signifying
    that this DID has been deactivated and is no longer valid. А DeactivateDID
    entry is always the last valid entry in a DID chain.

-   If an UpdateDID entry contains a publicKey KEY_IDENTIFIER in its revoke
    section and the same key is referenced in the authentication section, the
    key should be removed from both the public and authentication keys.

-   If an UpdateDID entry references a publicKey, authentication or service ID
    in its revoke section, all respective instances must be revoked (including
    duplicates with the same ID)

**Security Considerations**
===========================

*TODO*

**Recovery From Key Compromise**
================================

Factom DID's have a hierarchical structure of public keys, where \#key-0 is the
highest priority and \#key-n the lowest. A key replacement can be authorized by
any key at the same or higher priority. Such a scheme allows for an entity to
store their keys in various levels of security. For example:

-   \#key-0 - in cold storage

-   \#key-1 - on an airgapped machine

-   \#key-2 - used in applications (a.k.a. the hot key)

If the hot key is lost or compromised, the other two higher priority keys are
able to authorize a replacement.

**Privacy Considerations**
==========================

*TODO*

**Performance Considerations**
==============================

*TODO*

References
----------

[1] <https://w3c-ccg.github.io/did-use-cases/>  

[2] [https://w3c-ccg.github.io/did-spec/](https://w3c-ccg.github.io/did-spec/#the-generic-did-scheme)  

[3] <https://w3c-ccg.github.io/did-primer/>  

[4] <https://w3c-ccg.github.io/did-method-registry/>

[5]<https://tools.ietf.org/html/rfc7468>

[6]<https://github.com/w3c-dvcg/multibase>

[7]<https://github.com/multiformats/multibase>




# Copyright

Copyright and related rights waived via
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).
