import { Algorithm, generate, Options } from '../index';

describe('generate', () => {
    beforeEach(() => jest.useFakeTimers())
	afterEach(() => jest.resetAllMocks())
    it('should generate a 6-digit OTP with default options', () => {
        const key = 'JBSWY3DPEHPK3PXP';
        const { otp, expires } = generate(key);
        expect(otp.length).toBe(6);
        expect(typeof otp).toBe('string');
        expect(expires).toBeGreaterThan(Date.now());
    });
	test("should generate token with date now = 1971", () => {
		jest.setSystemTime(0);
        const key = 'JBSWY3DPEHPK3PXP';
        const expected = '282760';
        const { otp, expires } = generate(key);
        expect(otp).toBe(expected);
	})
    test("should generate token with date now = 2016", () => {
		jest.setSystemTime(1465324707000);
        const key = 'JBSWY3DPEHPK3PXP';
        const expected = '341128';
        const { otp, expires } = generate(key);
        expect(otp).toBe(expected);
	})
	test("should generate correct token at the start of the cycle", () => {
		const start = 1665644340000;
        const expected = '886842';
        const key = 'JBSWY3DPEHPK3PXP';
		jest.setSystemTime(start + 1);
        const { otp, expires } = generate(key);
        expect(otp).toBe(expected);
	})
    test("should generate correct token at the end of the cycle", () => {
		const start = 1665644340000;
        const expected = '134996';
        const key = 'JBSWY3DPEHPK3PXP';
		jest.setSystemTime(start - 1);
        const { otp, expires } = generate(key);
        expect(otp).toBe(expected);
	})
    test("should generate token with a leading zero", () => {
		jest.setSystemTime(1365324707000);
        const expected = '089029';
        const key = 'JBSWY3DPEHPK3PXP';
        const { otp, expires } = generate(key);
        expect(otp).toBe(expected);
	})
    test("should generate longer-lasting token with date now = 2016", () => {
        jest.setSystemTime(1465324707000);
        const expected = '43341128';
        const key = 'JBSWY3DPEHPK3PXP';
        const { otp, expires } = generate(key,  { digits: 8 });
        expect(otp).toBe(expected);
	})
    test("should generate SHA-512-based token with date now = 2016", () => {
        jest.setSystemTime(1465324707000);
        const expected = '093730';
        const key = 'JBSWY3DPEHPK3PXP';
        const { otp, expires } = generate(key,  { algorithm: Algorithm.SHA512 });
        expect(otp).toBe(expected);
	})
});