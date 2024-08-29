import { generate, Options } from './index';

const main = () => {

    const key = 'JBSWY3DPEHPK3PXP';

    setInterval(() => {
        const result = generate(key);
        console.log(result);
    }, 1000);
};
main();