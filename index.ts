import { createHmac } from 'node:crypto';


type Algorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
type Encoding = 'hex' | 'ascii'

interface Options {
    digits?: number
    algorithm?: Algorithm
    encoding?: Encoding
    period?: number
    timestamp?: number
}

const base32BinValues : { [key: string]: string } = {
    A: '00000',
    B: '00001',
    C: '00010',
    D: '00011',
    E: '00100',
    F: '00101',
    G: '00110',
    H: '00111',
    I: '01000',
    J: '01001',
    K: '01010',
    L: '01011',
    M: '01100',
    N: '01101',
    O: '01110',
    P: '01111',
    Q: '10000',
    R: '10001',
    S: '10010',
    T: '10011',
    U: '10100',
    V: '10101',
    W: '10110',
    X: '10111',
    Y: '11000',
    Z: '11001',
    2: '11010',
    3: '11011',
    4: '11100',
    5: '11101',
    6: '11110',
    7: '11111',
}

const initializeOptions = (options: Options): Required<Options> => {
    return {
        digits: 6,
        algorithm: 'SHA-1',
        encoding: 'hex',
        period: 30,
        timestamp: Date.now(),
        ...options,
    };
};
/**
 *  Hexadecimal to bytes conversion
 *
 * @param {string} hex
 * @returns {Uint8Array}
 * @example hexStr2Bytes('0000000002e94d7c') // bytes Uint8Array(8) [ 0, 0, 0, 0, 2, 233, 77, 124 ]
 */
const hexStr2Bytes = (hex: string): Uint8Array => {
    const length = hex.length / 2;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
};

/**
 * hexadecimal to buffer conversion
 *
 * @param {string} hex
 * @returns {*}
 * @example hex2buf('0000000002e94d7c') // <Buffer 00 00 00 00 02 e9 4d 7c>
]
 */
const hex2buf = (hex: string) => {
    return Buffer.from(hexStr2Bytes(hex));
}

/**
 * hexadecimal to decimal conversion
 *
 * @param {string} hex
 * @returns {*}
 * @example hex2dec('0c') // 12
 */
const hex2dec = (hex: string) => {
    return parseInt(hex, 16);
}
/**
 * Decimal to hexadecimal conversion add padding of 2 characters
 *
 * @param {number} dec
 * @returns {string}
 * @example dec2hex(12) // 0c
 */
const dec2hex = (dec: number) => {
    return dec.toString(16).padStart(2, '0');
}

/**
 * Description placeholder
 *
 * @param {string} algorithm
 * @param {Buffer} key
 * @param {Buffer} data
 * @returns {*}
 */
const hmacSha = (algorithm: string, key: Buffer, data: Buffer) => {
    const hmac = createHmac(algorithm, key);
    hmac.update(data);
    return hmac.digest('hex');
}
/**
 * Converts a string to a Buffer using ASCII encoding.
 * 
 * @param str - The string to convert.
 * @returns The Buffer representation of the string.
 */
const asciiToBuffer = (str: string): Buffer => {
    return Buffer.from(str, 'ascii');
};
/**
 * Converts a base32 encoded string to a Buffer.
 * 
 * @param {string} str - The base32 encoded string to convert.
 * @returns The converted Buffer.
 * @throws {Error} If the input contains invalid base32 characters.
 * @example base32ToBuffer('JBSWY3DPEHPK3PXP') // ArrayBuffer <48 65 6c 6c 6f 21 de ad be ef>
 */
const base32ToBuffer = (str: string): Buffer => {
    // return error if invalid base32 character
    if (str.match(/[^A-Z2-7]/)) {
        throw new Error('Invalid base32 character');
    }
    const binaryString = str.split('').map((char) => base32BinValues[char]).join('');
    // Convert the binary string to a buffer
    const buffer = Buffer.alloc(binaryString.length / 8);
    for (let i = 0; i < binaryString.length; i += 8) {
        buffer[i / 8] = parseInt(binaryString.slice(i, i + 8), 2);
    }
    return buffer;
}
/**
 * Calculate the time hex with padding of 16 characters
 *
 * @param {number} timestamp - The timestamp in milliseconds.
 * @param {number} period - The time period in seconds.
 * @returns {string}
 * @example calculateTimeHex(1465324707000, 30) // 0000000002e94d7c
 */
const calculateTimeHex = (timestamp: number, period: number): string => {
    const epochSeconds = Math.floor(timestamp / 1000);
    return dec2hex(Math.floor(epochSeconds / period)).padStart(16, '0');
};

/**
 * Calculate the HMAC signature in hexadecimal format
 *
 * @param {string} algorithm - The algorithm used for the HMAC calculation.
 * @param {string} key - The key used for the HMAC calculation.
 * @param {string} timeHex - The time value in hexadecimal format.
 * @returns {string}
 * @example calculateSignatureHex("SHA-256", "JBSWY3DPEHPK3PXP", "0000000002e94d7c") // b6a9dcc66852d95d39faec22a0fd2719d9441f9a4108969507e710d17dacf72c
 */
const calculateSignatureHex = (algorithm: string, key: Buffer, timeHex: string): string => {
    return hmacSha(algorithm, key, hex2buf(timeHex));
};

/**
 * Calculate the offset for the OTP calculation.
 *
 * @param {string} signatureHex - The hexadecimal signature.
 * @returns {number}
 * @example calculateOffset("b6a9dcc66852d95d39faec22a0fd2719d9441f9a4108969507e710d17dacf72c") // 24
 */
const calculateOffset = (signatureHex: string): number => {
    // Get the last 4 bits of the signature
    return hex2dec(signatureHex.slice(-1)) * 2;
};

/**
 * Calculate the masked value for the OTP calculation.
 *
 * @param {string} signatureHex - The hexadecimal signature.
 * @param {number} offset - The offset value.
 * @returns {number}
 * @example calculateMaskedValue("b6a9dcc66852d95d39faec22a0fd2719d9441f9a4108969507e710d17dacf72c", 24) // 553461529
 */
const calculateMaskedValue = (signatureHex: string, offset: number): number => {
    // Get the 4 bytes at the offset
    // Slice the signature from the offset to offset + 8
    // Convert the hexadecimal value to decimal
    // Bitwise AND (&) the decimal value with 0x7fffffff
    return hex2dec(signatureHex.slice(offset, offset + 8)) & 0x7fffffff;
};

/**
 * Calculates the One-Time Password (OTP) based on the provided signature and number of digits.
 *
 * @param {string} signatureHex - The hexadecimal signature used to calculate the OTP.
 * @param {number} digits - The number of digits the OTP should have.
 * @returns {number}
 * @example calculateOtp("b6a9dcc66852d95d39faec22a0fd2719d9441f9a4108969507e710d17dacf72c", 6) // 461529
 */
const calculateOtp = (signatureHex: string, digits: number): string => {
    const offset = calculateOffset(signatureHex);
    const maskedValue = calculateMaskedValue(signatureHex, offset);
    return maskedValue.toString().slice(-digits)
};

/**
 * Generate a One-Time Password (OTP) based on the provided key and options.
 *
 * @param {string} key
 * @param {Options} [options={}]
 * @returns {{ otp: number, expires: number }}
 * @example generate("JBSWY3DPEHPK3PXP", { timestamp: 1465324707000, algorithm: "SHA-256" }) // { otp: 461529, expires: 1465324707000 }
 */
const generate = (key: string, options: Options = {}): { otp: string, expires: number, remaining: number } => {
    const _options = initializeOptions(options);
    const { digits, algorithm, encoding, period, timestamp } = _options;

    const timeHex = calculateTimeHex(timestamp, period);
    const keyBuffer = encoding === 'hex' ? base32ToBuffer(key) : asciiToBuffer(key);
    const signatureHex = calculateSignatureHex(algorithm, keyBuffer, timeHex);
    const otp = calculateOtp(signatureHex, digits);

    const step = period * 1000;
    // Get expiration time, example if period is 30 seconds and timestamp is 1465324707000 then expiration is 1467873030000
    const expires = timestamp + step - (timestamp % step);
    // Remaining time in seconds
    const remaining = Math.ceil((expires - timestamp) / 1000);

    return { otp, expires, remaining };
};

export { generate, Options, Algorithm, Encoding };