def build(gen, env):
    env = env.clone()

    env['CPPFLAGS'] += [
        '-DOPENSSLDIR="\\"build/openssl\\""',
        '-DENGINESDIR="\\"build/openssl\\""',
        '-DOPENSSL_NO_DGRAM=1',
        '-DDSO_NONE=1',
        '-DOPENSSL_NO_SECURE_MEMORY=1',
        '-DOPENSSL_SYS_L4=1',
        '-DOPENSSL_NO_UI_CONSOLE=1',
        '-D_GNU_SOURCE',
        '-DOPENSSL_NO_ASM',
    ]
    env['CPPPATH'] += [
        'src/libs/openssl',
        'src/libs/openssl/include',
        'src/libs/openssl/crypto/modes',
    ]

    # shut off warnings
    env['CFLAGS'] += [
        '-Wno-sign-conversion',
        '-Wno-unused-parameter',
        '-Wno-missing-field-initializers',
        '-Wno-sign-compare',
        '-Wno-unused-but-set-variable',
        '-Wno-unused-variable',
    ]

    # the following occur on ARM; not sure if everything still works :/
    if env['ISA'] == 'arm':
        env['CFLAGS'] += [
            '-Wno-format',
            '-Wno-overflow',
            '-Wno-shift-count-overflow',
        ]

    # workaround the problem that strerror_r of musl returns an int, not char*
    # when we don't define _GNU_SOURCE, a different function is called.
    nognuenv = env.clone()
    nognuenv['CPPFLAGS'] += ['-U_GNU_SOURCE']
    objs = nognuenv.objs(gen, ins = ['crypto/o_str.c'])

    # build libcrypto.a
    crypto_files = [
        'crypto/cpt_err.c',
        'crypto/cryptlib.c',
        'crypto/ctype.c',
        'crypto/cversion.c',
        'crypto/ex_data.c',
        'crypto/getenv.c',
        'crypto/init.c',
        'crypto/mem.c',
        'crypto/mem_clr.c',
        'crypto/mem_dbg.c',
        'crypto/mem_sec.c',
        'crypto/o_dir.c',
        'crypto/o_fips.c',
        'crypto/o_fopen.c',
        'crypto/o_init.c',
        'crypto/o_time.c',
        'crypto/threads_none.c',
        'crypto/uid.c',
    ]
    crypto_files += env.glob('crypto/aria/*.c')
    crypto_files += env.glob('crypto/aes/*.c')
    crypto_files += env.glob('crypto/asn1/*.c')
    crypto_files += env.glob('crypto/async/arch/*.c')
    crypto_files += env.glob('crypto/async/*.c')
    crypto_files += env.glob('crypto/bf/*.c')
    crypto_files += env.glob('crypto/bio/*.c')
    crypto_files += env.glob('crypto/blake2/*.c')
    crypto_files += env.glob('crypto/bn/*.c')
    crypto_files += env.glob('crypto/buffer/*.c')
    crypto_files += env.glob('crypto/camellia/*.c')
    crypto_files += env.glob('crypto/cast/*.c')
    crypto_files += env.glob('crypto/cmac/*.c')
    crypto_files += env.glob('crypto/cms/*.c')
    crypto_files += env.glob('crypto/comp/*.c')
    crypto_files += env.glob('crypto/conf/*.c')
    crypto_files += env.glob('crypto/ct/*.c')
    crypto_files += env.glob('crypto/des/*.c')
    crypto_files += env.glob('crypto/dh/*.c')
    crypto_files += env.glob('crypto/dsa/*.c')
    crypto_files += env.glob('crypto/dso/*.c')
    crypto_files += env.glob('crypto/engine/*.c')
    crypto_files += env.glob('crypto/err/*.c')
    crypto_files += env.glob('crypto/evp/*.c')
    crypto_files += env.glob('crypto/hmac/*.c')
    crypto_files += env.glob('crypto/idea/*.c')
    crypto_files += env.glob('crypto/kdf/*.c')
    crypto_files += env.glob('crypto/lhash/*.c')
    crypto_files += env.glob('crypto/md4/*.c')
    crypto_files += env.glob('crypto/md5/*.c')
    crypto_files += env.glob('crypto/mdc2/*.c')
    crypto_files += env.glob('crypto/modes/*.c')
    crypto_files += env.glob('crypto/objects/*.c')
    crypto_files += env.glob('crypto/ocsp/*.c')
    crypto_files += env.glob('crypto/pem/*.c')
    crypto_files += env.glob('crypto/pkcs7/*.c')
    crypto_files += env.glob('crypto/pkcs12/*.c')
    crypto_files += env.glob('crypto/rc2/*.c')
    crypto_files += env.glob('crypto/rc4/*.c')
    crypto_files += env.glob('crypto/rand/*.c')
    crypto_files += env.glob('crypto/ripemd/*.c')
    crypto_files += env.glob('crypto/rsa/*.c')
    crypto_files += env.glob('crypto/seed/*.c')
    crypto_files += env.glob('crypto/sha/*.c')
    crypto_files += env.glob('crypto/sm4/*.c')
    crypto_files += env.glob('crypto/srp/*.c')
    crypto_files += env.glob('crypto/ssl/*.c')
    crypto_files += env.glob('crypto/stack/*.c')
    crypto_files += env.glob('crypto/store/*.c')
    crypto_files += env.glob('crypto/ts/*.c')
    crypto_files += env.glob('crypto/txt_db/*.c')
    crypto_files += env.glob('crypto/ui/*.c')
    crypto_files += env.glob('crypto/whrlpool/*.c')
    crypto_files += env.glob('crypto/x509/*.c')
    crypto_files += env.glob('crypto/x509v3/*.c')
    lib = env.static_lib(gen, out = 'libcrypto', ins = crypto_files + objs)
    env.install(gen, env['LIBDIR'], lib)

    # build libssl.a
    ssl_files = []
    ssl_files += env.glob('ssl/record/*.c')
    ssl_files += env.glob('ssl/statem/*.c')
    ssl_files += env.glob('ssl/*.c')
    lib = env.static_lib(gen, out = 'libssl', ins = ssl_files)
    env.install(gen, env['LIBDIR'], lib)
