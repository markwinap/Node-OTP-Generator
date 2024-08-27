import { generate, Options } from './index';

const main = () => {

    const key = 'JBSWY3DPEHPK3PXP';

    setInterval(() => {
        const { otp, expires, remaining } = generate(key);
        console.log(otp, expires, remaining);
    }, 1000);
};
main();