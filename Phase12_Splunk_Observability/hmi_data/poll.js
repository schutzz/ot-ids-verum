const dgram = require('dgram');
const client = dgram.createSocket('udp4');

// BACnet Who-Is packet (APDU) - Correct 8-byte structure
const msg = Buffer.from([0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08]);

console.log("Starting BACnet background polling...");

setInterval(() => {
    client.send(msg, 47808, '192.168.151.22', (err) => {
        if (err) console.error(err);
    });
}, 2000);
