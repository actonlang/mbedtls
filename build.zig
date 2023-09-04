const std = @import("std");
const print = @import("std").debug.print;

pub fn build(b: *std.build.Builder) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const libcrypto = b.addStaticLibrary(.{
        .name = "mbedcrypto",
        .target = target,
        .optimize = optimize,
    });

    const libx509 = b.addStaticLibrary(.{
        .name = "mbedx509",
        .target = target,
        .optimize = optimize,
    });

    const libtls = b.addStaticLibrary(.{
        .name = "mbedtls",
        .target = target,
        .optimize = optimize,
    });

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    libcrypto.addCSourceFiles(&.{
        "library/aes.c",
        "library/aesni.c",
        "library/aesce.c",
        "library/aria.c",
        "library/asn1parse.c",
        "library/asn1write.c",
        "library/base64.c",
        "library/bignum.c",
        "library/bignum_core.c",
        "library/bignum_mod.c",
        "library/bignum_mod_raw.c",
        "library/camellia.c",
        "library/ccm.c",
        "library/chacha20.c",
        "library/chachapoly.c",
        "library/cipher.c",
        "library/cipher_wrap.c",
        "library/constant_time.c",
        "library/cmac.c",
        "library/ctr_drbg.c",
        "library/des.c",
        "library/dhm.c",
        "library/ecdh.c",
        "library/ecdsa.c",
        "library/ecjpake.c",
        "library/ecp.c",
        "library/ecp_curves.c",
        "library/entropy.c",
        "library/entropy_poll.c",
        "library/error.c",
        "library/gcm.c",
        "library/hash_info.c",
        "library/hkdf.c",
        "library/hmac_drbg.c",
        "library/lmots.c",
        "library/lms.c",
        "library/md.c",
        "library/md5.c",
        "library/memory_buffer_alloc.c",
        "library/nist_kw.c",
        "library/oid.c",
        "library/padlock.c",
        "library/pem.c",
        "library/pk.c",
        "library/pk_wrap.c",
        "library/pkcs12.c",
        "library/pkcs5.c",
        "library/pkparse.c",
        "library/pkwrite.c",
        "library/platform.c",
        "library/platform_util.c",
        "library/poly1305.c",
        "library/psa_crypto.c",
        "library/psa_crypto_aead.c",
        "library/psa_crypto_cipher.c",
        "library/psa_crypto_client.c",
        "library/psa_crypto_driver_wrappers.c",
        "library/psa_crypto_ecp.c",
        "library/psa_crypto_hash.c",
        "library/psa_crypto_mac.c",
        "library/psa_crypto_pake.c",
        "library/psa_crypto_rsa.c",
        "library/psa_crypto_se.c",
        "library/psa_crypto_slot_management.c",
        "library/psa_crypto_storage.c",
        "library/psa_its_file.c",
        "library/psa_util.c",
        "library/ripemd160.c",
        "library/rsa.c",
        "library/rsa_alt_helpers.c",
        "library/sha1.c",
        "library/sha256.c",
        "library/sha512.c",
        "library/threading.c",
        "library/timing.c",
        "library/version.c",
        "library/version_features.c",
        }, flags.items);

    libx509.addCSourceFiles(&.{
        "library/pkcs7.c",
        "library/x509.c",
        "library/x509_create.c",
        "library/x509_crl.c",
        "library/x509_crt.c",
        "library/x509_csr.c",
        "library/x509write_crt.c",
        "library/x509write_csr.c",
        }, flags.items);

    libtls.addCSourceFiles(&.{
        "library/debug.c",
        "library/mps_reader.c",
        "library/mps_trace.c",
        "library/net_sockets.c",
        "library/ssl_cache.c",
        "library/ssl_ciphersuites.c",
        "library/ssl_client.c",
        "library/ssl_cookie.c",
        "library/ssl_debug_helpers_generated.c",
        "library/ssl_msg.c",
        "library/ssl_ticket.c",
        "library/ssl_tls.c",
        "library/ssl_tls12_client.c",
        "library/ssl_tls12_server.c",
        "library/ssl_tls13_keys.c",
        "library/ssl_tls13_server.c",
        "library/ssl_tls13_client.c",
        "library/ssl_tls13_generic.c",
        }, flags.items);

    libcrypto.addIncludePath(.{ .path = "include" });
    libcrypto.linkLibC();
    libx509.addIncludePath(.{ .path = "include" });
    libx509.linkLibC();
    libtls.addIncludePath(.{ .path = "include" });
    libtls.linkLibC();

    libtls.installHeadersDirectory("include/mbedtls", "mbedtls");
    libtls.installHeadersDirectory("include/psa", "psa");

    b.installArtifact(libcrypto);
    b.installArtifact(libx509);
    b.installArtifact(libtls);
}
