var sso = sso ||
    {
        userPoolId: '<pool_id>',
        clientId: '<client_id>',
        tempPassword: "!Qaz_2wsx$",
        cognitoIdentityServiceProvider: null,
        initCognitoIdentityServiceProvider: function () {
            AWS.config = new AWS.Config({
                accessKeyId: '<AWS access key id>',
                secretAccessKey: '<AWS secret access key>',
                region: 'us-east-1'
            });
            sso.cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider({ region: "us-east-1" });
        },
        findUserInUserPool: function (userName, paginationToken, callback) {
            var found = false;
            sso.cognitoIdentityServiceProvider.listUsers({ UserPoolId: sso.userPoolId, PaginationToken: paginationToken },
                function (err, data) {
                    if (err) { // an error occurred
                        alert(err.message);
                        console.log(err, err.stack);
                    } else {
                        paginationToken = data.PaginationToken;
                        found = $.inArray(userName, $.map(data.Users, function (user, i) {
                            return user.Username;
                        })) !== -1;
                        if (!paginationToken) {
                            if (!found) {
                                console.log("User " + userName + " was not found in Cognito User Pool");
                            }
                            callback(found);
                            return;
                        }
                        if (found) {
                            callback(found);
                            return;
                        }
                        sso.findUserInUserPool(userName, paginationToken, callback);
                    }
                });
        },
        createUser: function (userName, callback) {
            sso.cognitoIdentityServiceProvider.adminCreateUser({
                UserPoolId: sso.userPoolId,
                Username: userName,
                TemporaryPassword: sso.tempPassword,
                MessageAction: "SUPPRESS"
            },
                function (err, data) {
                    if (err) { // an error occurred
                        alert(err.message);
                        console.log(err, err.stack);
                    } else callback();
                });
        }
    };

sso.openServiceProviderWebSite = function () {
    var userName = $("#username").val();
    var password = $("#password").val();
    var awsSdk = $("input[name='aws-sdk']:checked").val();
    var authFlow = $('input[name="auth-flow"]:checked').val();

    function redirectToServiceProviderWebSiteWithToken(token) {
        var formForRedirect = $("#formForRedirect");
        var accessTokenHiddenInput = formForRedirect.find("input[name='idToken']");
        accessTokenHiddenInput.val(token);
        formForRedirect.submit();
    }

    if (awsSdk === "javascript") {
        if (authFlow === 'USER_SRP_AUTH') {
            sso.initCognitoIdentityServiceProvider();

            var authenticateUser = function (password) {
                var authenticationData = {
                    Username: userName,
                    Password: password
                };

                var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
                var poolData = {
                    UserPoolId: sso.userPoolId, // Your user pool id here
                    ClientId: sso.clientId // Your client id here
                };
                var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
                var userData = {
                    Username: userName,
                    Pool: userPool
                };
                var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
                cognitoUser.authenticateUser(authenticationDetails, {
                    onSuccess: function (result) {
                        var idToken = result.getIdToken().getJwtToken();
                        console.log('id token + ' + idToken);
                        redirectToServiceProviderWebSiteWithToken(idToken);
                    },
                    onFailure: function (err) {
                        alert(err.message || JSON.stringify(err));
                    },
                    newPasswordRequired: function (userAttributes, requiredAttributes) {
                        // User was signed up by an admin and must provide new
                        // password and required attributes, if any, to complete
                        // authentication.

                        // the api doesn't accept this field back
                        delete userAttributes.email_verified;

                        //var newPassword = "1qAz_2wsx$";
                        // Get these details and call
                        cognitoUser.completeNewPasswordChallenge(password, userAttributes, this);
                    }
                });
            };

            sso.findUserInUserPool(userName, null, function (found) {
                if (!found) {
                    sso.createUser(userName, function () {
                        authenticateUser(password);
                    });
                } else {
                    authenticateUser(password);
                }
            });
        }
    } else {
        $.ajax
            ({
                type: "POST",
                url: "api/CognitoToken/Login",
                dataType: 'json',
                data: {
                    Username: userName,
                    Password: password,
                    AuthFlow: authFlow
                },
                success: function (data) {
                    redirectToServiceProviderWebSiteWithToken(data.token);
                }
            });
    }
};

sso.init = function () {
    $(function () {
        $("#openServiceProviderWebSiteBtn").click(sso.openServiceProviderWebSite);

        $("input[name='aws-sdk']").change(function () {
            var sdk = $(this).filter(':checked').val();
            var customFlowRadioBtn = $(".custom-auth");
            sdk === "javascript" ? customFlowRadioBtn.hide() : customFlowRadioBtn.show();
        });

        $("input[name='auth-flow']").change(function () {
            var authFlow = $(this).filter(':checked').val();
            var passwordRow = $('.password-row');

            if (authFlow === 'CUSTOM_AUTH')
                passwordRow.hide();
            else
                passwordRow.show();
        });
    });
};

function defer(method) {
    if (window.jQuery) {
        method();
    } else {
        setTimeout(function () { defer(method) }, 50);
    }
}

defer(sso.init);
