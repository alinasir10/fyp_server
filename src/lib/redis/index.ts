import {Redis} from "ioredis";

const serviceUri = "rediss://default:AVNS_e_Dpr_aJYN3LZTQP1fn@caching-d6b09f6-mr-3220.c.aivencloud.com:26417"

export const redis = new Redis(serviceUri)
// export const redis = new Redis({
//     host: 'caching-d6b09f6-mr-3220.c.aivencloud.com',
//     port: 26417,
//     password: 'AVNS_e_Dpr_aJYN3LZTQP1fn',
//     username: 'default'
// })