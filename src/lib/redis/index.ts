import {Redis} from "ioredis";

const serviceURL = `${process.env.REDIS_SERVICE_URL}` || 'redis://localhost:6379'
export const redis = new Redis(serviceURL);