let apiMessages = function(){
	apiMessages.EMAIL_NOT_FOUND = 0;
	apiMessages.INVALID_PWD = 1;
	apiMessages.DB_ERROR = 2;
	apiMessages.NOT_FOUND = 3;
	apiMessages.EMAIL_ALREADY_EXISTS = 4;
	apiMessages.COULD_NOT_CREATE_USER = 5;
	apiMessages.PASSWORD_RESET_EXPIRED = 6;
	apiMessages.PASSWORD_RESET_HASH_MISMATCH = 7;
	apiMessages.PASSWORD_RESET_EMAIL_MISMATCH =8;
	apiMessages.COULD_NOT_RESET_PASSWORD = 9;
}

module.exports = apiMessages;