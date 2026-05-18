/*
* PKCS#12
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs12.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/data_src.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pkcs12_kdf.h>
#include <botan/internal/pkcs12_pbe.h>
#include <algorithm>
#include <array>

namespace Botan {

namespace {

// Associates a parsed certificate with its localKeyId bag attribute
struct ParsedCert {
      std::shared_ptr<X509_Certificate> cert;
      std::vector<uint8_t> local_key_id;
};

/*
* Encode a friendly name as a BMPString (UTF-16BE)
* ASN1_String doesn't support encoding BMPStrings, so we do it manually
*/
void encode_bmpstring(DER_Encoder& enc, std::string_view str) {
   // Convert the string to UTF-16BE
   const std::vector<uint8_t> utf16be = utf8_to_ucs2(std::string(str));
   enc.add_object(ASN1_Type::BmpString, ASN1_Class::Universal, utf16be);
}

/*
* Resolve a MAC digest OID to a hash name, throwing on unsupported algorithms.
* Compares OID objects directly to avoid fragility of formatted-string matching.
*/
std::string resolve_mac_hash(const OID& oid) {
   static const OID sha1_oid = OID::from_string("SHA-1");
   static const OID sha256_oid = OID::from_string("SHA-256");
   static const OID sha384_oid = OID::from_string("SHA-384");
   static const OID sha512_oid = OID::from_string("SHA-512");
   if(oid == sha1_oid)
      return "SHA-1";
   if(oid == sha256_oid)
      return "SHA-256";
   if(oid == sha384_oid)
      return "SHA-384";
   if(oid == sha512_oid)
      return "SHA-512";
   throw Decoding_Error(fmt("Unsupported PKCS#12 MAC digest: {}", oid.to_formatted_string()));
}

/*
* Apply legacy-compatibility defaults to PKCS12_Options when legacy_compat is set.
* Unconditionally sets key_encryption_algo, mac_digest and iterations to their
* legacy values so that the generated file is readable by old software.
*/
PKCS12_Options apply_legacy_compat(PKCS12_Options opts) {
   if(opts.legacy_compat) {
      opts.key_encryption_algo = "PBE-SHA1-3DES";
      opts.mac_digest = "SHA-1";
      opts.iterations = 2048;
   }
   return opts;
}

/*
* Validate PKCS12_Options before starting generation. Throws Invalid_Argument
* on unsupported or incoherent option values.
*/
void validate_options(const PKCS12_Options& opts) {
   if(opts.iterations == 0) {
      throw Invalid_Argument("PKCS#12: iteration count must be at least 1");
   }
   static const std::array<std::string_view, 6> supported_key_algos = {
      "PBE-SHA1-3DES",
      "PBE-SHA1-2DES",
      "PBES2-SHA256-AES256",
      "PBES2(AES-256/CBC,SHA-256)",
      "PBES2-SHA256-AES128",
      "PBES2(AES-128/CBC,SHA-256)",
   };
   if(std::find(supported_key_algos.begin(), supported_key_algos.end(), opts.key_encryption_algo) ==
      supported_key_algos.end()) {
      throw Invalid_Argument(fmt("PKCS#12: unsupported key encryption algorithm '{}'", opts.key_encryption_algo));
   }
   if(!opts.cert_encryption_algo.empty()) {
      if(std::find(supported_key_algos.begin(), supported_key_algos.end(), opts.cert_encryption_algo) ==
         supported_key_algos.end()) {
         throw Invalid_Argument(fmt("PKCS#12: unsupported cert encryption algorithm '{}'", opts.cert_encryption_algo));
      }
   }
   if(opts.include_mac && !opts.password.empty()) {
      static const std::array<std::string_view, 4> supported_mac_digests = {"SHA-1", "SHA-256", "SHA-384", "SHA-512"};
      if(std::find(supported_mac_digests.begin(), supported_mac_digests.end(), opts.mac_digest) ==
         supported_mac_digests.end()) {
         throw Invalid_Argument(fmt("PKCS#12: unsupported MAC digest '{}'", opts.mac_digest));
      }
   }
}

/*
* Verify PKCS#12 MAC — password_bytes are used verbatim (no UTF-16BE conversion).
*/
void verify_mac(std::span<const uint8_t> auth_safe_data,
                std::span<const uint8_t> mac_value,
                std::span<const uint8_t> mac_salt,
                size_t iterations,
                const OID& digest_algo_oid,
                std::span<const uint8_t> password_bytes) {
   const std::string hash_name = resolve_mac_hash(digest_algo_oid);
   auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash_name));
   const size_t mac_key_len = hmac->output_length();

   secure_vector<uint8_t> mac_key(mac_key_len);
   pkcs12_kdf(mac_key.data(), mac_key_len, password_bytes, mac_salt.data(), mac_salt.size(), iterations, 3, hash_name);
   hmac->set_key(mac_key);
   hmac->update(auth_safe_data);
   if(!constant_time_compare(hmac->final(), mac_value)) {
      throw Invalid_Authentication_Tag("PKCS#12 MAC verification failed");
   }
}

/*
* Parse attributes from a SafeBag
*/
void parse_bag_attributes(BER_Decoder& decoder, std::string& friendly_name, std::vector<uint8_t>& local_key_id) {
   if(!decoder.more_items()) {
      return;
   }

   // Only FriendlyName and LocalKeyId are handled; all other attributes are
   // silently skipped, in accordance with RFC 7292 §4.2.
   static const OID friendly_name_oid = OID::from_string("PKCS9.FriendlyName");
   static const OID local_key_id_oid = OID::from_string("PKCS9.LocalKeyId");

   BER_Decoder attrs = decoder.start_set();
   while(attrs.more_items()) {
      OID attr_oid;
      BER_Decoder attr_seq = attrs.start_sequence();
      attr_seq.decode(attr_oid);

      BER_Decoder values = attr_seq.start_set();
      if(attr_oid == friendly_name_oid) {
         ASN1_String str;
         values.decode(str);
         friendly_name = str.value();
      } else if(attr_oid == local_key_id_oid) {
         values.decode(local_key_id, ASN1_Type::OctetString);
      }
   }
}

/*
* Parse SafeContents (sequence of SafeBag)
*/
void parse_safe_contents(BER_Decoder& decoder,
                         std::string_view password,
                         std::vector<ParsedCert>& cert_entries,
                         std::shared_ptr<Private_Key>& key,
                         std::vector<uint8_t>& key_local_key_id,
                         std::string& friendly_name,
                         std::vector<OID>& unknown_bag_types) {
   static const OID cert_bag_oid = OID::from_string("PKCS12.CertBag");
   static const OID shrouded_key_bag_oid = OID::from_string("PKCS12.PKCS8ShroudedKeyBag");
   static const OID key_bag_oid = OID::from_string("PKCS12.KeyBag");
   static const OID x509_cert_oid = OID::from_string("PKCS9.X509Certificate");

   while(decoder.more_items()) {
      OID bag_type;
      std::string bag_friendly_name;
      std::vector<uint8_t> bag_key_id;

      BER_Decoder bag_seq = decoder.start_sequence();
      bag_seq.decode(bag_type);

      // bagValue is [0] EXPLICIT
      BER_Decoder bag_value = bag_seq.start_context_specific(0);

      bool is_cert_bag = false;
      bool is_key_bag = false;

      if(bag_type == cert_bag_oid) {
         is_cert_bag = true;
         OID cert_type;
         BER_Decoder cert_bag = bag_value.start_sequence();
         cert_bag.decode(cert_type);

         if(cert_type == x509_cert_oid) {
            // x509Certificate [0] EXPLICIT OCTET STRING
            std::vector<uint8_t> cert_data;
            BER_Decoder cert_value = cert_bag.start_context_specific(0);
            cert_value.decode(cert_data, ASN1_Type::OctetString);

            cert_entries.push_back({std::make_shared<X509_Certificate>(cert_data), {}});
         }
      } else if(bag_type == shrouded_key_bag_oid) {
         is_key_bag = true;
         // PKCS8ShroudedKeyBag - encrypted private key; keep only the first one
         if(key == nullptr) {
            AlgorithmIdentifier pbe_algo;
            std::vector<uint8_t> encrypted_key;

            BER_Decoder shrouded = bag_value.start_sequence();
            shrouded.decode(pbe_algo);
            shrouded.decode(encrypted_key, ASN1_Type::OctetString);

            auto decrypted = pkcs12_pbe_decrypt(encrypted_key, password, pbe_algo);
            DataSource_Memory src(decrypted);
            key = PKCS8::load_key(src);
         }
      } else if(bag_type == key_bag_oid) {
         is_key_bag = true;
         // KeyBag - unencrypted private key (rarely used); keep only the first one
         if(key == nullptr) {
            secure_vector<uint8_t> key_data;
            bag_value.raw_bytes(key_data);
            DataSource_Memory src(key_data);
            key = PKCS8::load_key(src);
         }
      } else {
         // Unknown or unsupported bag type — record it for diagnostics
         unknown_bag_types.push_back(bag_type);
      }

      bag_value.end_cons();

      // Parse attributes and associate with the bag they came from
      parse_bag_attributes(bag_seq, bag_friendly_name, bag_key_id);

      if(!bag_friendly_name.empty() && friendly_name.empty()) {
         friendly_name = bag_friendly_name;
      }
      if(!bag_key_id.empty()) {
         if(is_cert_bag && !cert_entries.empty()) {
            cert_entries.back().local_key_id = bag_key_id;
         } else if(is_key_bag && key_local_key_id.empty()) {
            key_local_key_id = bag_key_id;
         }
      }
   }
}

/*
* Parse AuthenticatedSafe (sequence of ContentInfo)
*/
void parse_authenticated_safe(std::span<const uint8_t> data,
                              std::string_view password,
                              std::vector<ParsedCert>& cert_entries,
                              std::shared_ptr<Private_Key>& key,
                              std::vector<uint8_t>& key_local_key_id,
                              std::string& friendly_name,
                              std::vector<OID>& unknown_bag_types) {
   static const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   static const OID pkcs7_enc_data_oid = OID::from_string("PKCS7.EncryptedData");

   BER_Decoder auth_safe(data);
   BER_Decoder seq = auth_safe.start_sequence();

   while(seq.more_items()) {
      OID content_type;
      BER_Decoder content_info = seq.start_sequence();
      content_info.decode(content_type);

      if(content_type == pkcs7_data_oid) {
         // Unencrypted data: [0] EXPLICIT OCTET STRING containing SafeContents
         std::vector<uint8_t> safe_contents_data;
         BER_Decoder content = content_info.start_context_specific(0);
         content.decode(safe_contents_data, ASN1_Type::OctetString);

         BER_Decoder safe_contents(safe_contents_data);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key, key_local_key_id, friendly_name, unknown_bag_types);
      } else if(content_type == pkcs7_enc_data_oid) {
         // Encrypted data
         BER_Decoder content = content_info.start_context_specific(0);
         BER_Decoder enc_data = content.start_sequence();

         size_t version = 0;
         enc_data.decode(version);

         if(version != 0) {
            throw Decoding_Error(fmt("PKCS#12: unsupported EncryptedData version: {}", version));
         }

         // EncryptedContentInfo
         BER_Decoder enc_content_info = enc_data.start_sequence();
         OID enc_content_type;
         AlgorithmIdentifier enc_algo;
         enc_content_info.decode(enc_content_type);
         enc_content_info.decode(enc_algo);

         std::vector<uint8_t> encrypted_content;
         const BER_Object enc_content_obj = enc_content_info.get_next_object();

         if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific) ||
            enc_content_obj.is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
            const std::span<const uint8_t> raw(enc_content_obj.bits(), enc_content_obj.length());
            // Try to decode as explicit OCTET STRING (OpenSSL constructed encoding)
            if(!raw.empty() && raw[0] == static_cast<uint8_t>(ASN1_Type::OctetString)) {
               try {
                  BER_Decoder inner(raw);
                  inner.decode(encrypted_content, ASN1_Type::OctetString);
               } catch(const BER_Decoding_Error&) {
                  encrypted_content.assign(raw.begin(), raw.end());
               }
            } else {
               encrypted_content.assign(raw.begin(), raw.end());
            }
         } else {
            throw Decoding_Error("PKCS#12: Expected [0] context-specific for encrypted content");
         }

         // Decrypt
         const secure_vector<uint8_t> decrypted = pkcs12_pbe_decrypt(encrypted_content, password, enc_algo);

         BER_Decoder safe_contents(decrypted);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key, key_local_key_id, friendly_name, unknown_bag_types);
      }
   }
}

}  // namespace

std::vector<std::shared_ptr<X509_Certificate>> PKCS12_Data::all_certificates() const {
   std::vector<std::shared_ptr<X509_Certificate>> result;
   if(m_certificate) {
      result.push_back(m_certificate);
   }
   result.insert(result.end(), m_ca_certs.begin(), m_ca_certs.end());
   return result;
}

PKCS12_Data PKCS12::parse(std::span<const uint8_t> data, std::string_view password) {
   DataSource_Memory src(data.data(), data.size());
   return parse(src, password);
}

PKCS12_Data PKCS12::parse(DataSource& source, std::string_view password) {
   PKCS12_Data result;
   std::vector<ParsedCert> cert_entries;

   BER_Decoder pfx(source);
   BER_Decoder pfx_seq = pfx.start_sequence();

   // Version (should be 3)
   size_t version = 0;
   pfx_seq.decode(version);
   if(version != 3) {
      throw Decoding_Error(fmt("Unsupported PKCS#12 version: {}", version));
   }

   // authSafe ContentInfo
   OID auth_safe_type;
   std::vector<uint8_t> auth_safe_content;

   BER_Decoder auth_safe_info = pfx_seq.start_sequence();
   auth_safe_info.decode(auth_safe_type);

   static const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   if(auth_safe_type != pkcs7_data_oid) {
      throw Decoding_Error("PKCS#12 authSafe must be of type Data");
   }

   BER_Decoder auth_safe_content_wrapper = auth_safe_info.start_context_specific(0);
   auth_safe_content_wrapper.decode(auth_safe_content, ASN1_Type::OctetString);

   // MacData (optional)
   if(pfx_seq.more_items()) {
      BER_Decoder mac_data = pfx_seq.start_sequence();

      // DigestInfo
      BER_Decoder digest_info = mac_data.start_sequence();
      AlgorithmIdentifier digest_algo;
      std::vector<uint8_t> mac_value;
      digest_info.decode(digest_algo);
      digest_info.decode(mac_value, ASN1_Type::OctetString);

      std::vector<uint8_t> mac_salt;
      size_t iterations = 1;
      mac_data.decode(mac_salt, ASN1_Type::OctetString);
      if(mac_data.more_items()) {
         mac_data.decode(iterations);
      }
      if(iterations == 0 || iterations > 1'000'000) {
         throw Decoding_Error(fmt("PKCS#12 MAC has invalid iteration count: {}", iterations));
      }

      // First attempt: RFC 7292 encoding (UTF-16BE with null terminator).
      // For empty passwords two encodings exist in the wild:
      //   1. RFC 7292: {0x00, 0x00} — used by Botan and RFC-conformant implementations
      //   2. OpenSSL-style: passlen=0 (no P bytes) — used by OpenSSL and most real-world tooling
      // For non-empty passwords only the RFC 7292 encoding is valid; fail immediately on mismatch.
      bool verified = false;
      try {
         verify_mac(
            auth_safe_content, mac_value, mac_salt, iterations, digest_algo.oid(), pkcs12_encode_password(password));
         verified = true;
      } catch(const Invalid_Authentication_Tag&) {
         if(!password.empty()) {
            throw;
         }
      }

      if(!verified) {
         // Second attempt: OpenSSL-style empty password (passlen=0, no P contribution).
         // Propagates Invalid_Authentication_Tag if this also fails.
         verify_mac(auth_safe_content, mac_value, mac_salt, iterations, digest_algo.oid(), std::span<const uint8_t>{});
      }
   }

   // Parse AuthenticatedSafe
   std::shared_ptr<Private_Key> key;
   std::vector<uint8_t> key_local_key_id;
   parse_authenticated_safe(auth_safe_content,
                            password,
                            cert_entries,
                            key,
                            key_local_key_id,
                            result.m_friendly_name,
                            result.m_unknown_bag_types);

   result.m_private_key = key;
   result.m_local_key_id = key_local_key_id;

   // Separate end-entity cert from CA certs.
   // Prefer matching via localKeyId (the attribute is designed for this purpose),
   // fall back to public key comparison only if localKeyId is absent.
   if(!cert_entries.empty()) {
      if(key != nullptr) {
         // Try localKeyId match first
         if(!key_local_key_id.empty()) {
            for(auto it = cert_entries.begin(); it != cert_entries.end(); ++it) {
               if(it->local_key_id == key_local_key_id) {
                  result.m_certificate = it->cert;
                  cert_entries.erase(it);
                  break;
               }
            }
         }

         // Fall back to public key comparison
         if(!result.m_certificate) {
            for(auto it = cert_entries.begin(); it != cert_entries.end(); ++it) {
               try {
                  auto cert_pk = it->cert->subject_public_key();
                  if(cert_pk && key->public_key_bits() == cert_pk->public_key_bits()) {
                     result.m_certificate = it->cert;
                     cert_entries.erase(it);
                     break;
                  }
               } catch(const Decoding_Error&) {
                  // Certificate with unsupported key algorithm — skip
               }
            }
         }
      }

      // If still no match, use the first cert as the end-entity
      if(!result.m_certificate && !cert_entries.empty()) {
         result.m_certificate = cert_entries.front().cert;
         cert_entries.erase(cert_entries.begin());
      }

      for(auto& entry : cert_entries) {
         result.m_ca_certs.push_back(entry.cert);
      }
   }

   // Verify no trailing data
   pfx_seq.verify_end();

   return result;
}

std::vector<uint8_t> PKCS12::create(const Private_Key* key,
                                    const X509_Certificate* cert,
                                    const std::vector<X509_Certificate>& ca_certs,
                                    const PKCS12_Options& options,
                                    RandomNumberGenerator& rng) {
   if(key == nullptr && cert == nullptr && ca_certs.empty()) {
      throw Invalid_Argument("PKCS#12::create requires at least a key or certificate");
   }

   // Apply legacy compatibility overrides first, then validate
   const PKCS12_Options opts = apply_legacy_compat(options);
   validate_options(opts);

   if(key != nullptr && cert != nullptr) {
      if(key->subject_public_key() != cert->subject_public_key_info()) {
         throw Invalid_Argument("PKCS#12::create: private key does not match certificate");
      }
   }

   static const OID cert_bag_oid = OID::from_string("PKCS12.CertBag");
   static const OID shrouded_key_oid = OID::from_string("PKCS12.PKCS8ShroudedKeyBag");
   static const OID x509_cert_oid = OID::from_string("PKCS9.X509Certificate");
   static const OID friendly_name_oid = OID::from_string("PKCS9.FriendlyName");
   static const OID local_key_id_oid = OID::from_string("PKCS9.LocalKeyId");
   static const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   static const OID pkcs7_enc_data_oid = OID::from_string("PKCS7.EncryptedData");

   std::vector<uint8_t> auth_safe_content;

   // Generate local key ID from certificate (SHA-1 of public key)
   std::vector<uint8_t> local_key_id;
   if(cert != nullptr) {
      auto hash = HashFunction::create_or_throw("SHA-1");
      hash->update(cert->subject_public_key_bitstring());
      local_key_id.resize(hash->output_length());
      hash->final(local_key_id.data());
   }

   // Create CertBags
   std::vector<uint8_t> cert_safe_contents;
   {
      DER_Encoder cert_bags(cert_safe_contents);
      cert_bags.start_sequence();

      auto add_cert_bag = [&](const X509_Certificate& c, bool add_attrs) {
         cert_bags.start_sequence();
         cert_bags.encode(cert_bag_oid);

         // CertBag [0] EXPLICIT
         cert_bags.start_context_specific(0);
         cert_bags.start_sequence();
         cert_bags.encode(x509_cert_oid);
         // x509Certificate [0] EXPLICIT OCTET STRING
         cert_bags.start_context_specific(0);
         cert_bags.encode(c.BER_encode(), ASN1_Type::OctetString);
         cert_bags.end_cons();
         cert_bags.end_cons();
         cert_bags.end_cons();

         // Attributes
         if(add_attrs && (!opts.friendly_name.empty() || !local_key_id.empty())) {
            cert_bags.start_set();
            if(!opts.friendly_name.empty()) {
               cert_bags.start_sequence();
               cert_bags.encode(friendly_name_oid);
               cert_bags.start_set();
               encode_bmpstring(cert_bags, opts.friendly_name);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            if(!local_key_id.empty()) {
               cert_bags.start_sequence();
               cert_bags.encode(local_key_id_oid);
               cert_bags.start_set();
               cert_bags.encode(local_key_id, ASN1_Type::OctetString);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            cert_bags.end_cons();
         }

         cert_bags.end_cons();
      };

      if(cert != nullptr) {
         add_cert_bag(*cert, true);
      }
      for(const auto& ca : ca_certs) {
         add_cert_bag(ca, false);
      }

      cert_bags.end_cons();
   }

   // Create key SafeBag if key is provided
   std::vector<uint8_t> key_safe_contents;
   if(key != nullptr) {
      DER_Encoder key_bags(key_safe_contents);
      key_bags.start_sequence();
      key_bags.start_sequence();
      key_bags.encode(shrouded_key_oid);

      // Encrypt the private key
      secure_vector<uint8_t> pkcs8_key = PKCS8::BER_encode(*key);
      auto [enc_algo, enc_key] =
         pkcs12_pbe_encrypt(pkcs8_key, opts.password, opts.key_encryption_algo, opts.iterations, rng);

      // PKCS8ShroudedKeyBag [0] EXPLICIT
      key_bags.start_context_specific(0);
      key_bags.start_sequence();
      key_bags.encode(enc_algo);
      key_bags.encode(enc_key, ASN1_Type::OctetString);
      key_bags.end_cons();
      key_bags.end_cons();

      // Attributes
      if(!opts.friendly_name.empty() || !local_key_id.empty()) {
         key_bags.start_set();
         if(!opts.friendly_name.empty()) {
            key_bags.start_sequence();
            key_bags.encode(friendly_name_oid);
            key_bags.start_set();
            encode_bmpstring(key_bags, opts.friendly_name);
            key_bags.end_cons();
            key_bags.end_cons();
         }
         if(!local_key_id.empty()) {
            key_bags.start_sequence();
            key_bags.encode(local_key_id_oid);
            key_bags.start_set();
            key_bags.encode(local_key_id, ASN1_Type::OctetString);
            key_bags.end_cons();
            key_bags.end_cons();
         }
         key_bags.end_cons();
      }

      key_bags.end_cons();
      key_bags.end_cons();
   }

   // Build AuthenticatedSafe
   DER_Encoder auth_safe(auth_safe_content);
   auth_safe.start_sequence();

   // First ContentInfo: certificates (optionally encrypted)
   if(cert != nullptr || !ca_certs.empty()) {
      if(!opts.cert_encryption_algo.empty() && !opts.password.empty()) {
         // Encrypt certificates
         auto [enc_algo, enc_data] =
            pkcs12_pbe_encrypt(cert_safe_contents, opts.password, opts.cert_encryption_algo, opts.iterations, rng);

         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_enc_data_oid);
         auth_safe.start_context_specific(0);
         auth_safe.start_sequence();
         auth_safe.encode(size_t(0));  // version
         // EncryptedContentInfo
         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_data_oid);
         auth_safe.encode(enc_algo);
         auth_safe.add_object(ASN1_Type(0), ASN1_Class::ContextSpecific, enc_data);
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
      } else {
         // Unencrypted certificates
         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_data_oid);
         auth_safe.start_context_specific(0);
         auth_safe.encode(cert_safe_contents, ASN1_Type::OctetString);
         auth_safe.end_cons();
         auth_safe.end_cons();
      }
   }

   // Second ContentInfo: private key (always encrypted via PKCS8ShroudedKeyBag)
   if(!key_safe_contents.empty()) {
      auth_safe.start_sequence();
      auth_safe.encode(pkcs7_data_oid);
      auth_safe.start_context_specific(0);
      auth_safe.encode(key_safe_contents, ASN1_Type::OctetString);
      auth_safe.end_cons();
      auth_safe.end_cons();
   }

   auth_safe.end_cons();

   // Build PFX
   std::vector<uint8_t> pfx_data;
   DER_Encoder pfx(pfx_data);
   pfx.start_sequence();
   pfx.encode(size_t(3));  // version

   // authSafe ContentInfo
   pfx.start_sequence();
   pfx.encode(pkcs7_data_oid);
   pfx.start_context_specific(0);
   pfx.encode(auth_safe_content, ASN1_Type::OctetString);
   pfx.end_cons();
   pfx.end_cons();

   // MacData (optional but recommended)
   if(opts.include_mac && !opts.password.empty()) {
      const std::string& mac_hash = opts.mac_digest;

      std::vector<uint8_t> mac_salt(16);
      rng.randomize(mac_salt.data(), mac_salt.size());

      // Derive MAC key using PKCS#12 KDF with ID=3
      auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", mac_hash));
      const size_t mac_key_len = hmac->output_length();
      secure_vector<uint8_t> mac_key(mac_key_len);
      pkcs12_kdf(mac_key.data(),
                 mac_key_len,
                 pkcs12_encode_password(opts.password),
                 mac_salt.data(),
                 mac_salt.size(),
                 opts.iterations,
                 3,
                 mac_hash);

      // Compute HMAC
      hmac->set_key(mac_key);
      hmac->update(auth_safe_content);
      const secure_vector<uint8_t> mac_value = hmac->final();

      // MacData
      pfx.start_sequence();
      // DigestInfo
      pfx.start_sequence();
      pfx.encode(AlgorithmIdentifier(OID::from_string(mac_hash), AlgorithmIdentifier::USE_NULL_PARAM));
      pfx.encode(mac_value, ASN1_Type::OctetString);
      pfx.end_cons();
      pfx.encode(mac_salt, ASN1_Type::OctetString);
      if(opts.iterations != 1) {
         pfx.encode(opts.iterations);
      }
      pfx.end_cons();
   }

   pfx.end_cons();

   return pfx_data;
}

}  // namespace Botan
