import app from './app.js';
import dotenv from 'dotenv';
import logger from './configs/logger.config.js';

// dotenv config
dotenv.config();

// env variables
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
	logger.info(`Server is listening at ${PORT}.`);
});
