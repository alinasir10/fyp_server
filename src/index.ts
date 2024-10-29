import http from 'http';
import app from './app'
import { configDotenv } from 'dotenv'

import initSocket from './sockets'
import {instrument} from "@socket.io/admin-ui";

import {redis} from './lib/redis'
configDotenv();

const server = http.createServer(app);

const io = initSocket.init(server);

instrument(io, {
    auth: false,
    mode: 'development'
})

const port = process.env.PORT || 5000;

redis.once("connect", () => {
    console.log("Connected to Aiven Redis successfully!");
});

server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
