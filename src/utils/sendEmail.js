import nodemailer from 'nodemailer';
import hbs from 'nodemailer-express-handlebars';
import path from 'path';

export const sendEmail = async (subject, send_to, send_from, reply_to, template, name, link) => {
	// Create Email Transporter
	const transporter = nodemailer.createTransport({
		host: process.env.EMAIL_HOST,
		port: 587,
		secure: false,
		auth: {
			user: process.env.EMAIL_USER,
			pass: process.env.EMAIL_PASS,
		},
		tls: {
			rejectUnauthorized: false,
		},
	});

	const handlearOptions = {
		viewEngine: {
			extName: '.handlebars',
			partialsDir: path.resolve('./src/views'),
			defaultLayout: false,
		},
		viewPath: path.resolve('./src/views'),
		extName: '.handlebars',
	};

	transporter.use('compile', hbs(handlearOptions));

	// Options f0r sending email
	const options = {
		from: send_from,
		to: send_to,
		replyTo: reply_to,
		subject,
		template,
		context: {
			name,
			link,
		},
	};

	// Send Email
	transporter.sendMail(options, function (err, info) {
		if (err) {
			console.log(err);
		} else {
			console.log(info);
		}
	});
};
