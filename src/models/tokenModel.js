import mongoose from 'mongoose';
const { ObjectId } = mongoose.Schema.Types;
const tokenSchema = mongoose.Schema(
	{
		userId: {
			type: ObjectId,
			required: true,
			ref: 'UserModel',
		},
		vToken: {
			type: String,
			default: '',
		},
		rToken: {
			type: String,
			default: '',
		},
		lToken: {
			type: String,
			default: '',
		},
		createdAt: {
			type: Date,
			required: true,
		},
		expiresAt: {
			type: Date,
			required: true,
		},
	},
	{
		collection: 'tokens',
		timestamps: true,
		minimize: false,
	}
);

const TokenModel = mongoose.models.TokenModel || mongoose.model('TokenModel', tokenSchema);

export default TokenModel;
