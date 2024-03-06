import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import fileUpload from 'express-fileupload';
import cors from 'cors';
import errorHandler from './middlewares/errorMiddleware.js';
import routes from './routes/index.js';

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

//api v1 routes
app.use('/api/v1', routes);

// cors
app.use(cors());
app.use(function (req, res, next) {
	res.header('Access-Control-Allow-Origin', '*');
	res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
	next();
});

//error handling
app.use(async (req, res, next) => {
	next(createHttpError.NotFound('This route does not exist.'));
});

app.use(errorHandler);

app.use(async (err, req, res, next) => {
	res.status(err.status || 500);
	res.send({
		error: {
			status: err.status || 500,
			message: err.message,
		},
	});
});

export default app;
