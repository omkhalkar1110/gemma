import serverless from 'serverless-http';
import { createExpressApp } from '../../src/expressApp';

const app = createExpressApp();

export const handler = serverless(app);
