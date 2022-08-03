const AWS = require("aws-sdk");
const cognito = new AWS.CognitoIdentityServiceProvider();
const pool_id = process.env.POOL_ID;
const client_id = process.env.CLIENT_ID;

exports.handler = (event, context, callback) => {

    if (event.newPassword !== undefined && event.password !== undefined && event.newPassword.length > 8) {
        const paramsForSetPass = {
            Password: event.newPassword, UserPoolId: pool_id, Username: event.email, Permanent: true
        };
        cognito.initiateAuth(params(event.email, event.password), function (err, data) {
            if (err) {
                callback(null, successResponse('Failed',err));
            } else {
                cognito.adminSetUserPassword(paramsForSetPass, (err, d) => {
                    if (err) {
                        callback(null, successResponse('Failed',err));
                    } else {
                        callback(null,successResponse('Password reset successful', null));
                    }
                });
            }
        });
    } else {
        cognito.initiateAuth(params(event.email, event.password), function (err, data) {
            if (err) {
                callback(null, successResponse('Failed',err));
            } else {
                console.log(data)
                if(data.ChallengeName !== undefined && data.ChallengeName == "NEW_PASSWORD_REQUIRED"){
                    const response = {
                        Message: data.ChallengeName,
                        Session: data.Session
                    };
                    callback(null, successResponse('Password reset is required',response));
                }else{
                    const response = {
                        AccessToken: data.AuthenticationResult.IdToken,
                        ExpiresIn: data.AuthenticationResult.ExpiresIn,
                        TokenType: 'auth'
                    };
                    callback(null, successResponse('Successful',response));
                }
            }
        });
    }
};

const successResponse = (msg,dat) => {
    return {
        message: msg,
        data: dat
    };
};

const params = (email, password) => {
    return {
        AuthFlow: "USER_PASSWORD_AUTH", ClientId: client_id, AuthParameters: {
            'USERNAME': email, 'PASSWORD': password
        },
    };
};