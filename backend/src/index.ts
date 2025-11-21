import Server from './server';
import { logger } from './config/logger';

const server = new Server();

server.start().catch((error) => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});
