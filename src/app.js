import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import fileUpload from 'express-fileupload';
import cors from 'cors';

// create express app
const app = express();

// morgan
if (process.env.NODE_ENV !== 'production') {
	app.use(morgan('dev'));
}

// helmet
app.use(helmet());

// parse json request url
app.use(express.json());

// parse json request body
app.use(express.urlencoded({ extended: true }));

// sanitize request data
app.use(mongoSanitize());

// enable body parser
app.use(bodyParser.json());

// enable cookie parser
app.use(cookieParser());

// gzip compression
app.use(compression());

// file upload
app.use(
	fileUpload({
		useTempFiles: true,
	})
);

// cors
app.use(cors());

export default app;
