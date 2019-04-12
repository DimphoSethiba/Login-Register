let accountController = function(userModel, session, session, mailer) {

	this.crypto = require('crypto');
	this.uuid = require('node-uuid');
	this.apiResponse =require('../models/api-response.js');
	this.apiMessages = require('../models/api-messages.js');
	this.userProfileModel = require('../models/api-profile.js');
	this.userModel = userModel;
	this.session = session;
	this.mailer = mailer;
};

accountController.prototype.getSession = function(){
	return this.session;
};

accountController.prototype.setSession = function(session){
	return this.session;
};

accountController.prototype.hashPassword = function(password, salt, callback){
	let iterations = 10000,
		keyLen = 64;
	this.crypto.pbkdf2(password, salt, iterations, keyLen, callback);	
};

accountController.prototype.logon = function(email, password,callback){
	let userAcc = this;

	userAcc.userModel.findOne({email: email}, function(err, user){
		
		if(err){
			return callback(err, new userAcc.apiResponse({
				success:false, extras:{ msg: userAcc.apiMessages.DB_ERROR }
			}));
		}

		if(user){
			userAcc.hashPassword(password, user.passwordSalt, function(err, passwordHash){
				if(passwordHash == user.passwordHash){

					let userProfileModel = new userAcc.userModel({
						email: user.email,
						fullName: user.fullName
					});

					userAcc.session.userProfileModel = userProfileModel;

					return callback(err, new userAcc.apiResponse({
						success: true, extras: { userProfileModel: userProfileModel}
					}));
				}

				else{
					return callback(err, new userAcc.apiResponse({
						success:false, extras: { msg: userAcc.apiMessages.INVALID_PWD}
					}));
				}
			});
		}

		else{
				return callback(err, new userAcc.apiResponse({
				success:false, extras: { msg: userAcc.apiMessages.EMAIL_NOT_FOUND}
			}));
				
		}
	
	});


};

accountController.prototype.logoff =function () {
	if(this.session.userProfileModel) delete this.session.userProfileModel;
	return;
};

accountController.prototype.register = function (newUser, callback){
	let userAcc = this;

	userAcc.userModel.findOne({email: newUser.email}, function (err, user){
		if(err){
			return callback(err, new userAcc.apiResponse({ success:false, extras:{msg: userAcc.apiMessages.DB_ERROR} }));
		}

		if(user){
			return callback(err, new userAcc.apiResponse({ success:false, extras:{msg: userAcc.apiMessages.EMAIL_ALREADY_EXISTS} }));
		}
		else{
			newUser.save(function(err, user, numberAffected){
				if(err){
					return callback(err, new userAcc.apiResponse({ success:false, extras:{msg: userAcc.apiMessages.DB_ERROR} }));
				}

				if(numberAffected === 1){
					let userProfileModel = new userAcc.UserProfileModel({
						email: user.email,
						fullName: user.fullName
					});

					return callback(err, new userAcc.apiResponse({
						success:true , extras: { userProfileModel: userProfileModel}
					}));
				}
				else{
					return callback(err, new userAcc.apiResponse({ success:false, extra: {msg: userAcc.apiMessages.COULD_NOT_CREATE_USER} }));
				}

			});

		}
	});
};

accountController.prototype.resetPassword = function (email, callback) {
    var userAcc = this;
    userAcc.userModel.findOne({ email: email }, function (err, user) {

        if (err) {
            return callback(err, new userAcc.apiResponse({ success: false, extras: { msg: user.apiMessages.DB_ERROR } }));
        }

       if(user){
	       	let passwordResetHash = userAcc.uuid.v4();
	        userAcc.session.passwordResetHash = passwordResetHash;
	        userAcc.session.emailWhoRequestedPasswordReset = email;
	       
			userAcc.mailer.sendPasswordResetHash(email, passwordResetHash);
	       
	        return callback(err, new userAcc.apiResponse({ success: true, extras: { passwordResetHash: passwordResetHash } }));
	   }

	   else{
	   		return callback(err, new userAcc.apiResponse({ success: false, extras: {msg: userAcc.apiMessages.EMAIL_NOT_FOUND}}))
	   }

    })
};

accountController.prototype.resetPasswordFinal = function (email, newPassword, passwordResetHash, callback) {
    let userAcc = this;
    if (!userAcc.session || !userAcc.session.passwordResetHash) {
        return callback(null, new userAcc.apiResponse({ success: false, extras: { msg: userAcc.apiMessages.PASSWORD_RESET_EXPIRED } }));
    }

    if (userAcc.session.passwordResetHash !== passwordResetHash) {
        return callback(null, new userAcc.apiResponse({ success: false, extras: { msg: userAcc.apiMessages.PASSWORD_RESET_HASH_MISMATCH } }));
    }

    if (userAcc.session.emailWhoRequestedPasswordReset !== email) {
        return callback(null, new userAcc.apiResponse({ success: false, extras: { msg: userAcc.apiMessages.PASSWORD_RESET_EMAIL_MISMATCH } }));
    }

    let passwordSalt = this.uuid.v4();

    userAcc.hashPassword(newPassword, passwordSalt, function (err, passwordHash) {

        userAcc.userModel.update({ email: email }, { passwordHash: passwordHash, passwordSalt: passwordSalt }, function (err, numberAffected, raw) {

            if (err) {
                return callback(err, new userAcc.ApiResponse({ success: false, extras: { msg: userAcc.apiMessages.DB_ERROR } }));
            }

            if (numberAffected < 1) {

                return callback(err, new userAcc.apiResponse({ success: false, extras: { msg: userAcc.apiMessages.COULD_NOT_RESET_PASSWORD } }));
            } else {
                return callback(err, new userAcc.apiResponse({ success: true, extras: null }));
            }                
        });
    });
};

module.exports = accountController;