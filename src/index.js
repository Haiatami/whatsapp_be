import app from './app.js';
import dotenv from 'dotenv';
import logger from './configs/logger.config.js';

// dotenv config
dotenv.config();

// env variables
const PORT = process.env.PORT || 5000;

let server;

server = app.listen(PORT, () => {
	logger.info(`Server is listening at ${PORT}.`);
});

//handle server errors
const exitHandler = () => {
	if (server) {
		logger.info('Server closed.');
		process.exit(1);
	} else {
		process.exit(1);
	}
};

const unexpectedErrorHandler = (error) => {
	logger.error(error);
	exitHandler();
};
process.on('uncaughtException', unexpectedErrorHandler);
process.on('unhandledRejection', unexpectedErrorHandler);

//SIGTERM
process.on('SIGTERM', () => {
	if (server) {
		logger.info('Server closed.');
		process.exit(1);
	}
});
