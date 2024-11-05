# Node TOTP Generator

Node Typescript TOTP Generator with step by step instructions, easy to use and library easy to debug and understand.

## Installation

Install my-project with npm

```bash
  npm i node-ts-otp-generator
```
    
## Features

- ASCII and Base32 support
- Expiration timestamp
- Remaining seconds

## Usage/Examples

```javascript
import { generate, Options } from 'node-ts-otp-generator';

setInterval(() => {
    const result = generate(key,  { digits: 6 });
    console.log(result);
}, 1000);
```

## Authors

- [@markwinap](https://www.github.com/markwinap)
