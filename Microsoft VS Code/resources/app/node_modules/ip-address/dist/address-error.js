"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AddressError = void 0;
class AddressError extends Error {
    constructor(message, parseMessage) {
        super(message);
        this.name = 'AddressError';
        if (parseMessage !== null) {
            this.parseMessage = parseMessage;
        }
    }
}
exports.AddressError = AddressError;//# sourceMappingURL=https://main.vscode-cdn.net/sourcemaps/6f17636121051a53c88d3e605c491d22af2ba755/node_modules/ip-address/dist/address-error.js.map