PKCS#12
========================================

PKCS#12 (also known as PFX) is a file format defined in :rfc:`7292` for
storing cryptographic objects — typically a private key and its associated
X.509 certificate chain — protected by a password. It is widely used for
importing and exporting credentials in TLS servers, browsers, and
certificate management tools.

This API is defined in ``botan/pkcs12.h`` and is available since Botan 3.11.

.. versionadded:: 3.11

PKCS12_Options
-----------------------------------------

.. cpp:class:: PKCS12_Options

   Options controlling how a PKCS#12 file is generated.

   .. cpp:member:: std::string password

      Password used to encrypt the private key and optionally the
      certificates. If empty, no encryption is applied (not recommended for
      production use).

   .. cpp:member:: std::string friendly_name

      Optional human-readable label attached to the key and end-entity
      certificate as a ``friendlyName`` PKCS#9 attribute.

   .. cpp:member:: size_t iterations = 100000

      Number of KDF iterations for key derivation. Higher values slow down
      brute-force attacks at the cost of slightly longer export/import times.
      Default: 100 000. Values below 10 000 are not recommended.
      For maximum compatibility with legacy software, use 2 048.

   .. cpp:member:: std::string key_encryption_algo

      Algorithm used to encrypt the private key (PKCS8ShroudedKeyBag).
      Supported values:

      - ``"PBES2-SHA256-AES256"`` — **default**, modern, requires PBES2 module
      - ``"PBES2-SHA256-AES128"`` — modern, requires PBES2 module
      - ``"PBE-SHA1-3DES"`` — legacy, widest compatibility with old software
      - ``"PBE-SHA1-2DES"`` — legacy

   .. cpp:member:: std::string cert_encryption_algo

      Algorithm used to encrypt the certificates. If empty (default),
      certificates are stored unencrypted. Accepts the same values as
      ``key_encryption_algo``.

   .. cpp:member:: bool include_mac = true

      Whether to include a PKCS#12 MAC for integrity protection.
      Recommended to keep enabled.

   .. cpp:member:: std::string mac_digest

      Hash algorithm for the MAC. Default is ``"SHA-256"``.
      Use ``"SHA-1"`` for maximum compatibility with legacy software.
      Supported: ``"SHA-1"``, ``"SHA-256"``, ``"SHA-384"``, ``"SHA-512"``.

   .. cpp:member:: bool legacy_compat = false

      If ``true``, the ``key_encryption_algo``, ``mac_digest``, and
      ``iterations`` fields are overridden with legacy-compatible values
      (``"PBE-SHA1-3DES"``, ``"SHA-1"``, 2048) regardless of what was set.
      Use when generating files that must be read by old software (Java
      keytool pre-2019, legacy OpenSSL builds).

PKCS12_Data
-----------------------------------------

.. cpp:class:: PKCS12_Data

   Result of parsing a PKCS#12 file. Holds the extracted key and
   certificates.

   .. cpp:function:: const std::shared_ptr<Private_Key>& private_key() const

      Returns the private key, or ``nullptr`` if not present.

   .. cpp:function:: const std::shared_ptr<X509_Certificate>& certificate() const

      Returns the end-entity certificate, or ``nullptr`` if not present.

   .. cpp:function:: const std::vector<std::shared_ptr<X509_Certificate>>& ca_certificates() const

      Returns the intermediate/CA certificates included in the file.

   .. cpp:function:: std::vector<std::shared_ptr<X509_Certificate>> all_certificates() const

      Returns all certificates: end-entity (if present) followed by the CA chain.

   .. cpp:function:: const std::string& friendly_name() const

      Returns the ``friendlyName`` attribute, or an empty string if absent.

   .. cpp:function:: bool has_private_key() const
   .. cpp:function:: bool has_certificate() const
   .. cpp:function:: bool has_ca_certificates() const
   .. cpp:function:: bool has_friendly_name() const

      Convenience predicates.

   .. cpp:function:: const std::vector<uint8_t>& local_key_id() const

      Returns the ``localKeyId`` bag attribute of the private key, or an
      empty vector if absent. Used to correlate the private key with its
      end-entity certificate.

   .. cpp:function:: bool has_local_key_id() const

      Returns ``true`` if a ``localKeyId`` attribute is present.

   .. cpp:function:: const std::vector<OID>& unknown_bag_types() const

      Returns OIDs of bag types encountered during parsing but not handled
      (e.g. ``SecretBag``). Empty for normal PKCS#12 files.

PKCS12
-----------------------------------------

.. cpp:class:: PKCS12

   Static-only class providing PKCS#12 parsing and generation. Cannot be
   instantiated.

   Parsing
   ^^^^^^^

   .. cpp:function:: static PKCS12_Data parse(std::span<const uint8_t> data, std::string_view password)

      Parse a DER-encoded PFX file from a byte span.

      Throws ``Decoding_Error`` if the file is malformed, or
      ``Invalid_Authentication_Tag`` if MAC verification fails.

   .. cpp:function:: static PKCS12_Data parse(DataSource& source, std::string_view password)

      Parse a PFX file from a :cpp:class:`DataSource`.

   Creation
   ^^^^^^^^

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key& key, const X509_Certificate& cert, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Create a PFX containing a key and its end-entity certificate.
      Throws ``Invalid_Argument`` if the key does not correspond to the
      certificate.

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key& key, const X509_Certificate& cert, const std::vector<X509_Certificate>& ca_certs, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Create a PFX with a key, end-entity certificate, and a CA chain.

   .. cpp:function:: static std::vector<uint8_t> create(const Private_Key* key, const X509_Certificate* cert, const std::vector<X509_Certificate>& ca_certs, const PKCS12_Options& options, RandomNumberGenerator& rng)

      Low-level overload accepting nullable pointers. At least one of *key*,
      *cert*, or *ca_certs* must be non-null/non-empty.

Example
-----------------------------------------

Generating a PFX file:

.. code-block:: cpp

   #include <botan/pkcs12.h>
   #include <botan/auto_rng.h>
   #include <botan/ec_group.h>
   #include <botan/ecdsa.h>
   #include <botan/x509self.h>

   Botan::AutoSeeded_RNG rng;
   Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group::from_name("secp256r1"));

   Botan::X509_Cert_Options opts("CN=example.com");
   auto cert = Botan::X509::create_self_signed_cert(opts, key, "SHA-256", rng);

   Botan::PKCS12_Options p12_opts;
   p12_opts.password      = "secret";
   p12_opts.friendly_name = "My Key";
   // Default: PBES2-SHA256-AES256 encryption, SHA-256 MAC, 100000 iterations.
   // For legacy compatibility: p12_opts.legacy_compat = true;

   std::vector<uint8_t> pfx = Botan::PKCS12::create(key, cert, p12_opts, rng);

Parsing a PFX file:

.. code-block:: cpp

   #include <botan/pkcs12.h>
   #include <botan/exceptn.h>

   // pfx_bytes loaded from file
   try {
      Botan::PKCS12_Data data = Botan::PKCS12::parse(pfx_bytes, "secret");

      if(data.has_private_key()) {
         // private_key() returns const std::shared_ptr<Private_Key>&
         const auto& key = data.private_key();
         // key->algo_name(), key->key_length(), ...
      }
      if(data.has_certificate()) {
         const auto& cert = data.certificate();
         // cert->subject_dn(), cert->fingerprint("SHA-256"), ...
      }
      for(const auto& ca : data.ca_certificates()) {
         // Process CA chain entries
      }
   } catch(const Botan::Invalid_Authentication_Tag&) {
      // Wrong password or corrupted MAC
   } catch(const Botan::Decoding_Error& e) {
      // Malformed or unsupported PFX file
   }

Creating a PFX with a certificate chain:

.. code-block:: cpp

   // Assuming key, end_cert, and ca_certs are already available
   std::vector<Botan::X509_Certificate> ca_chain = { intermediate_cert, root_cert };

   Botan::PKCS12_Options opts;
   opts.password      = "secret";
   opts.friendly_name = "Server Key";

   std::vector<uint8_t> pfx = Botan::PKCS12::create(key, end_cert, ca_chain, opts, rng);

.. note::

   The default encryption algorithm is ``PBES2-SHA256-AES256`` with
   ``SHA-256`` MAC and 100 000 KDF iterations. For maximum compatibility
   with legacy software (older Java keytool, legacy OpenSSL builds), set
   ``legacy_compat = true`` or explicitly configure ``key_encryption_algo =
   "PBE-SHA1-3DES"``, ``mac_digest = "SHA-1"``, and ``iterations = 2048``.

Supported Algorithms
-----------------------------------------

The following algorithms are available depending on which Botan modules are built:

.. list-table::
   :header-rows: 1
   :widths: 25 30 25 20

   * - Field
     - Value
     - Required module
     - Notes
   * - ``key_encryption_algo``
     - ``"PBES2-SHA256-AES256"``
     - ``pbes2``, ``aes``
     - Default; recommended for modern use
   * - ``key_encryption_algo``
     - ``"PBES2-SHA256-AES128"``
     - ``pbes2``, ``aes``
     - Modern
   * - ``key_encryption_algo``
     - ``"PBE-SHA1-3DES"``
     - ``pkcs12_pbe``, ``des``
     - Legacy; widest compatibility
   * - ``key_encryption_algo``
     - ``"PBE-SHA1-2DES"``
     - ``pkcs12_pbe``, ``des``
     - Legacy
   * - ``cert_encryption_algo``
     - Same as above, or ``""``
     - —
     - Empty = certificates stored unencrypted
   * - ``mac_digest``
     - ``"SHA-256"``
     - ``sha2_32``
     - Default; required by OpenSSL 3.x default policy
   * - ``mac_digest``
     - ``"SHA-1"``
     - ``sha1``
     - Legacy; widest compatibility
   * - ``mac_digest``
     - ``"SHA-384"``, ``"SHA-512"``
     - ``sha2_64``
     - Uncommon; supported for parsing and generation

Command Line Interface
-----------------------------------------

Two CLI commands are available when Botan is built with filesystem support.

``pkcs12_export``
^^^^^^^^^^^^^^^^^

.. code-block:: none

   botan pkcs12_export [--pass=<pfx-password>] [--key-pass=<key-password>]
                       [--friendly-name=<name>]
                       [--key-cipher=<algo>]   (default: PBES2-SHA256-AES256)
                       [--cert-cipher=<algo>]  (default: unencrypted)
                       [--no-mac]
                       [--mac-digest=<SHA-256|SHA-1>]
                       [--iterations=<n>]      (default: 100000)
                       <key-file> <cert-file> [ca-cert ...]

Exports a private key and certificate(s) to a PFX file written to stdout
or ``--output``.

``pkcs12_import``
^^^^^^^^^^^^^^^^^

.. code-block:: none

   botan pkcs12_import [--pass=<pfx-password>]
                       [--key-out=<file>]    (PEM private key)
                       [--cert-out=<file>]   (PEM end-entity certificate)
                       [--chain-out=<file>]  (PEM CA certificate chain)
                       [--key-pass=<password>]
                       [--key-cipher=<algo>]  (default: AES-256/CBC)
                       [--key-pbkdf-iter=<n>] (default: 100000)
                       <pfx-file>

Parses a PFX file. Without output file arguments, prints a summary of the
contents to stdout including subject, issuer, validity, serial number, and
both SHA-1 and SHA-256 fingerprints of the end-entity certificate.
