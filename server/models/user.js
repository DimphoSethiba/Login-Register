let mongoose =require('mongoose');
let Schema = mongoose.Schema;

let UserSchema = new Schema({
	email: String,
	fullName: String,
	passwordHash: String,
	passwordSalt: String
});

module.exports = mongoose.model('User', UserSchema);