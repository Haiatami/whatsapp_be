import mongoose from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcrypt';

const userSchema = mongoose.Schema(
	{
		name: {
			type: String,
			required: [true, 'Please provide your name'],
		},
		email: {
			type: String,
			required: [true, 'Please provide tour email address'],
			unqiue: [true, 'This email address already exist'],
			lowercase: true,
			validate: [validator.isEmail, 'Please provide a valid email address'],
			trim: true,
			match: [
				/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
				'Please enter a valid email',
			],
		},
		picture: {
			type: String,
			required: [true, 'Please add a photo'],
			default: 'https://res.cloudinary.com/dkd5jblv5/image/upload/v1675976806/Default_ProfilePicture_gjngnb.png',
		},
		phone: {
			type: String,
			default: '+234',
		},
		status: {
			type: String,
			default: 'Hey there ! I am using whatsapp',
		},
		password: {
			type: String,
			required: [true, 'Please provide your password'],
			minLength: [6, 'Plase make sure your password is atleast 6 characters long'],
			maxLength: [128, 'Plase make sure your password is less than 128 characters long'],
		},
		role: {
			type: String,
			required: true,
			default: 'subscriber',
			// subscriber, author, and admin (suspended)
		},
		isVerified: {
			type: Boolean,
			default: false,
		},
		userAgent: {
			type: Array,
			required: true,
			default: [],
		},
	},
	{
		collection: 'users',
		timestamps: true,
		minimize: false,
	}
);
userSchema.pre('save', async function (next) {
	try {
		if (!this.isModified('password')) {
			return next();
		}

		// Hash password
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(this.password, salt);
		this.password = hashedPassword;
		next();
	} catch (error) {
		next(error);
	}
});
const UserModel = mongoose.models.UserModel || mongoose.model('UserModel', userSchema);

export default UserModel;
