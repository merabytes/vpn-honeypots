(function ($) {

	CTXS.ExtensionAPI.addPlugin({
		name: "ns-nfactor", // Name of plugin - must match name sent in configuration
		initialize: function () {

			/*
			 * Custom credential handler for Google ReCaptcha.
			 * If a credential of type "nf-recaptcha" is sent in any factor, this code
			 * will be executed. The "submit" button of the form will be disabled
			 * by default until the captcha is completed correctly.
			 *
			 * Use with the below WebAuth action:
			 * add authentication webAuthAction recaptcha -serverIP <IP Address of google.com> -serverPort 443 -fullReqExpr q{"POST /recaptcha/api/siteverify HTTP/1.1\r\n" + "Host: www.google.com\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 10000"+"\r\n\r\n" + "secret=<Secret key from Google Recaptcha>&response=" + http.req.body(10000).after_str("&recaptcha=")} -scheme https -successRule "http.RES.body(1000).REGEX_MATCH(re/\"success\": true.*\"hostname\": \"<FQDN of the Gateway/Auth vServer>\"/)"
			 *
			 */
			CTXS.ExtensionAPI.addCustomCredentialHandler({
				getCredentialTypeName: function () { return "nf-recaptcha"; },

				getCredentialTypeMarkup: function (requirements) {
					var reCaptchaSiteKey = ""; //Replace this with the SiteKey from Google ReCaptcha
					var div = $("<div></div>");
					captcha = $('<div id="g-recaptcha" class="g-recaptcha" data-callback="captchaSuccess"></div>').attr("data-sitekey", reCaptchaSiteKey);
					var input = $('<input id="captchaResponse" name="recaptcha" type="hidden" value=""/>');
					div.append(captcha, input);
					getCaptchaSiteKey();
					
					loadJSFile("https://www.google.com/recaptcha/api.js");
					
					$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
						var $form = data.authenticationElement.find('.credentialform');
						var $captcha = $form.find('#g-recaptcha');
						$loginButton = $form.find('#loginBtn');
						if ($captcha.length && $loginButton.length) {
							// This is a Captcha form
							// Disable the submit button by default
							disableFormsButton($loginButton);
						}
					});

					return div;
				}
			});

			
			/* End ReCaptcha code */

			/*
			 * Custom code to be run when there is a challenge response from the authentication server
			 */
			CTXS.ExtensionAPI.addCustomCredentialHandler({
				getCredentialTypeName: function () { return "ns-dialogue"; },

				getCredentialTypeMarkup: function (requirements) {
					//var challengeText = requirements.label.text;
					if(typeof generateDialogHTML != "undefined") {
						return generateDialogHTML(requirements.label.text);
					}
					return $("<div></div>");
				}
			});
			
			/*
			Move this funciton to script.js if you want custom HTML to be rendered during dialog mode
				
			function generateDialogHTML(challengeText) {
				return $("<img src='https://otp.com'/>");
			}
			*/
			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "dialogue-label"; },

				getLabelTypeMarkup: function (requirements) {
					var label = $('<div id="nf-dialogue" class="standaloneText label nsg_information" role="alert"></div>').html(requirements.label.text);
					return label;
				},
				parseAsType: function () {
				    	return "plain";
				    }
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg-change-pass-assistive-text"; },

				getLabelTypeMarkup: function (requirements) {
					var label = $("<div></div>");
					var assistiveText = "chpasswd-assistive-text";
					var localizedMsg = _localize(assistiveText);
					if(localizedMsg != assistiveText){
						//Assistive text message has been configured. Display it as an information label
						var label = $('<div class="standaloneText label nsg_information" role="alert"></div>').text(localizedMsg);
					}					
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg_confirmation"; },

				getLabelTypeMarkup: function (requirements) {
					var label_localized_str = "";
					var label_str_arr = requirements.label.text.split(" ");
					if (label_str_arr.length > 0) {
						for (i=0;i<label_str_arr.length;i++)
						{
							label_localized_str = label_localized_str + _localize(label_str_arr[i]);
						}
					}
					else
						label_localized_str = _localize(requirements.label.text)
					var label = $('<div class="standaloneText label confirmation" role="alert"></div>').text(label_localized_str);
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg_kba_registration_heading"; },

				getLabelTypeMarkup: function (requirements) {
					var label = $('<div class="standaloneText label registrationHeading"></div>').text(_localize(requirements.label.text));
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg_email_registration_heading"; },

				getLabelTypeMarkup: function (requirements) {
					var label = $('<div class="standaloneText label registrationHeading"></div>').text(_localize(requirements.label.text));
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg_kba_validation_question"; },

				getLabelTypeMarkup: function (requirements) {
					var label = $('<div class="standaloneText label kbaValidation"></div>').text(requirements.label.text);
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({

				getLabelTypeName: function () { return "nsg_sspr_success"; },

				getLabelTypeMarkup: function (requirements) {

					$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {

						var $form = data.authenticationElement.find('.credentialform');
						var logon = $('<a href="#" class="logon-button default button kba_logon">Log On</a>');
                        logon.on("click", function(){
                                window.location.href = CTXS.Location.origin + CTXS.Location.pathname;
                        });
						$form.find(".kbaValidation").append(logon);
					});
					var label = $('<div class="standaloneText label kbaValidation"></div>').text(_localize(requirements.label.text));
					return label;
				},
				parseAsType: function () {
					return "plain";
				}
			});
			/* End challenge response code */

			/*Custom Credential Handler for Gateway Test
			 * Session */
			CTXS.ExtensionAPI.addCustomCredentialHandler({
				getCredentialTypeName: function () { return "nf-gw-test"; },
				getCredentialTypeMarkup: function (requirements) {
					var div= $('<div id="gwtest-summary" class="gwtest-summary" align="left"><\div>');
					$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
						GetSummary();
					});
					return div;
			        }
			 });

			CTXS.ExtensionAPI.addCustomCredentialHandler({
				// The name of the credential, must match the type returned by the server
				getCredentialTypeName: function () {
					return "nf-poll";
				},
				// Generate HTML for the custom credential
				getCredentialTypeMarkup: function (requirements) {
					createTopMenu();
					var label = $('<div class="standaloneText label confirmation" role="alert"></div>').text(_localize("approve_push"));
					return label;
				},
				getDataToAutoPost: function ($form, requirements, success_callback) {
					//Postback after 3 seconds so that polling doesn't overload NS
					setTimeout(function() {success_callback()}, 3000);
				},
				parseAsType: function () {
					return "plain";
				}
			});

			CTXS.ExtensionAPI.addCustomAuthLabelHandler({
				// The name of the credential, must match the type returned by the server
				getLabelTypeName: function () { return "nf-manage-otp"; },
				// Generate HTML for the custom credential
				getLabelTypeMarkup: function (requirements) {
					var div = $("<div></div>").attr("id", "otp-main").addClass("otp-main");                
					var span = $("<span></span>").text(_localize("OTPRegisteredDevices")).addClass("standaloneText label plain").css("display","block");
					div.append(span);
					var br = $("<br/>");
					div.append(br);

					
					nonce = atob(requirements.input.text.initialValue);
					var selectWrapper = $("<div></div>").css("width","1800px");
					var select = $("<select name='registered-otp'></select>").attr("id", "registered-otp").addClass("unified-width");
					
					selectWrapper.append(select);
					
					var addButton = $("<a></a>").attr({"href":"#", "id":"add-otp", "title":_localize("OTPAddDeviceToolTip")}).addClass("otp-action default button padding-normal");
					if(isInsideVPN())
					{
						addButton.text(_localize("Add"))
					}
					selectWrapper.append(addButton);
					
					addButton.click(function (e) {
						e.preventDefault();
						showTextBox(this, "add", _localize("OTPEnterName"));
					});
					
					var testButton = $("<a></a>").attr({"href":"#", "id":"test-otp", "title":_localize("OTPTestDeviceToolTip")}).addClass("otp-action otp-test-delete default button").text(_localize("OTPTest"));
					
					testButton.click(function (e) {
						e.preventDefault();
						showTextBox(this, "test", _localize("OTPEnterTestValue"));
					});
					selectWrapper.append(testButton);
					
					var deleteButton = $("<a></a>").attr({"id":"delete-otp","href":"#"}).addClass("default button otp-action otp-test-delete").text(_localize("Delete"));
					deleteButton.click(function(e) {
							deleteDevice(e);
					});
					
					selectWrapper.append(deleteButton);					
									
					div.append(selectWrapper);
					div.append(br.clone());
					
					var right = $("<div></div>").addClass("left").css({"margin-top": "10px", "display": "none"}).attr("id", "text-container");
					var text = $("<input/>").attr({"id" : "otp-value", "name" : "otp-value", "type" : "text", "autocomplete" : "off", "spellcheck" : "false", "command" : "none", "maxlength" : "126"}).addClass("unified-width otp-text");
					
					right.append(text);
					
					var go = $("<a></a>").attr({"id":"otp-go","class":"default button"}).css("cursor", "pointer").text(_localize("Go"));
					
					go.click(function (e) {
						e.preventDefault();
						handleGo();
					});
					right.append(go);
					div.append(right);
					
					createTopMenu();
					$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
						ListDevices();
					});
					return div;
				},
				parseAsType: function () {
				    	return "plain";
				    }
			});

			CTXS.ExtensionAPI.addCustomCredentialHandler({
			    // The name of the credential, must match the type returned by the server
			    getCredentialTypeName: function () { return "nsg_qrcode"; },
			    // Generate HTML for the custom credential
			    getCredentialTypeMarkup: function (requirements) {
					var image = $("<div/>").attr({"id" : "image"});
					var secret = atob(requirements.input.text.initialValue); //Get the secret from the response
					var data = secret.split(":");
					var messageLabel = $("<p></p>").attr({"role": "alert", "id" : "add-info-msg"});
					var message = _localize("OTPCode").split("{0}");
					var code = $("<p></p>").text(data[0]).addClass("otp-bold");
					messageLabel.append(message);
					loadJSFile("plugins/ns-gateway/qrcode.min.js", "image", data);

					var table = $("<table></table>").addClass("qrcode-image-table");
					var tr = $("<tr></tr>");
					tr.append($("<td></td>").addClass("qrcode-image-column").append(image));
					tr.append($("<td></td>").append(messageLabel, code).addClass("standaloneText label"));
					table.append(tr);
					return table;
			    },
			});

			CTXS.ExtensionAPI.addCustomCredentialHandler({
			    // The name of the credential, must match the type returned by the server
				getCredentialTypeName: function () { return "nsg_manageotp"; },
			    // Generate HTML for the custom credential
			    getCredentialTypeMarkup: function (requirements) {
				var div = $("<div></div>");
				var devicehint = $('<input name="otpdevice" id="otpdevice" type="text"><br>');
				div.append(devicehint);
				
				//This code is run just before a form is displayed to the user
				//Register this only if nsg_manageotp is sent in the authv2 form
				$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
					var otpDevice = $(".CredentialTypensg_manageotp");
					otpDevice.hide(); //Hide by default
					$('#otpregister').click(function() {
						var rsaField = $($(".credentialform").find(".CredentialTypepassword")[1]);
						if (rsaField) {
							if($(this).is(':checked')){
								$("#passwd1").val("");
								rsaField.hide();
								otpDevice.show();
							} else {
								$("#otpdevice").val("");
								rsaField.show();
								otpDevice.hide();
							}
				}
			});
				});

				return div;
		}
	});

		}
	});
})(jQuery);

var $loginButton;
function captchaSuccess(data) {
	$("#captchaResponse").val(data);
	enableFormsButton($loginButton);
}

function disableFormsButton($button) {
	// Disable the button and stop it appearing clickable
	$button.addClass('disabled').removeAttr('href');
}
function enableFormsButton($button) {
	// Enable the button and make it clickable again
	$button.removeClass('disabled').attr('href', '#');
}


function loadJSFile(path, qrcodeDiv, data)
{
	var script = document.createElement("script");
	script.type = "text/javascript";
	script.src = path;
	script.onerror = function(){
		var $form = $(".credentialform")[0];
		var fieldDiv = $('<div class="field CredentialTypenone"></div>');
		var leftDiv = $('<div class="left"></div>');
		var label = $('<div class="standaloneText label error qrerror" role="alert"></div>').text(_localize("OTPQRError"));
		leftDiv.append(label);
		fieldDiv.append(leftDiv);
		$($form).append(fieldDiv);
	};
	if(qrcodeDiv != null && data != null)
	{
		var qrcode_text = "otpauth://totp/" + data[1] + "?secret=" + data[0] + "&device=" + data[2];
		if (data[3] != undefined) {
			qrcode_text = qrcode_text + "&code=" + data[3];
		}
		script.onload = function(){
			var qrcode = new QRCode(qrcodeDiv, {
			text: qrcode_text,
			width: 128,
			height: 128,
			colorDark : "#000000",
			colorLight : "#ffffff",
			correctLevel : QRCode.CorrectLevel.L
			});
		};
	}

	$("head")[0].appendChild(script);
}

/* OTP Functions start */


function showTextBox(btn, command, message) {
	if($(btn).hasClass("otp-disabled")) {
		return;
	}
	removeInfoMessage();
	var textBox = $(".otp-text");
	textBox.val("");
	textBox.attr({"placeholder": message, "title": message});
	if(command === "test") {
		textBox.attr("id","otp-value");
	} else if (command === "add") {
		textBox.attr("id","device-name");
	}

	var prevCommand = textBox.attr("command");
	if(textBox.is(":visible")) {
		if(prevCommand === command) {
			textBox.attr("command", "none");
			$("#text-container").slideUp(250);
		} else {
			textBox.attr("command", command);
		}	
	} else {
		textBox.attr("command", command);
		$("#text-container").slideDown(250);
	}
}

function handleGo() {
	var textBox = $(".otp-text");
	var command = textBox.attr("command");
	removeInfoMessage();
	$("#otp-conf-div").remove();
	if(command === "test") {
		testDevice();
	} else if (command === "add") {
		AddOTPDevice();
	}
}

function removeInfoMessage() {
	$("#confirmation-msg").remove();
}

function testDevice(e) {

	if($("#registered-otp").find("option").length == 0) {
		return;
	}
	if($(".otp-text").val() == "") {
		displayMessage("error", "OTPEnterTestValue");
		return;
	}
	var postData = {};
	postData['command'] = 'test';
	postData['devicename'] = $("#registered-otp").val();
	postData['otp'] = $(".otp-text").val();
	postData['csrf'] = nonce;
	sendOTPRequest(otpURL, postData, testSuccess, testError);
	
}

function testSuccess(responseData, textStatus, XMLHttpRequest) {
	var deviceName = $("#registered-otp option:selected").text();
	if (responseData.indexOf("yes") != -1) {
		displayMessage("confirmation", "OTPTestSuccess", deviceName);
	} else {
		displayMessage("error", "OTPTestFailure", deviceName);
	}
}

function testError(responseData, textStatus, XMLHttpRequest) {
	var deviceName = $("#registered-otp option:selected").text();
	displayMessage("error", "OTPTestFailure", deviceName);
}

function AddOTPDevice(e) {
	var deviceName = $.trim($(".otp-text").val());
	var exists = false;
	if(deviceName == "" || deviceName == undefined) {
		displayMessage("error", "OTPEnterName");
		return;
	}
	$('#registered-otp option').each(function(){
	    if (this.value == deviceName) {
	        exists = true;
	        return false;
	    }
	});
	if(exists == true)
	{
		displayMessage("error", "OTPDeviceExists", deviceName);
		return;
	}
	var postData = {};
	postData['devicename'] = deviceName;
	postData['command'] = 'add';
	postData['csrf'] = nonce;
	sendOTPRequest(otpURL, postData, AddOTPDeviceSuccess, AddOTPDeviceSuccess);
}

function AddOTPDeviceSuccess(responseData, textStatus, XMLHttpRequest) {
	return OTPAddDeleteDeviceQRCode(1, responseData, textStatus, XMLHttpRequest);
}

function OTPAddDeleteDeviceQRCode(add, responseData, textStatus, XMLHttpRequest) {
	var deviceName = $.trim($(".otp-text").val());
	if (responseData.indexOf("code") == -1) {
		if (responseData.match(/maximum otp devices/i) != null) {
			displayMessage("error", "OTPAddMaxDevices", deviceName);
		} else if (add == 1) {
			displayMessage("error", "OTPAddFailure", deviceName);
		} else {
			displayMessage("error", "OTPDeleteDeviceFailure", deviceName);
		}
		return;
	}
    //format: code=foobar&url=foobar:uname
    var resp = responseData.split("&");
    var image = $("<img/>");
    var code = resp[0].split("=");
    var url = resp[1].split("=");
    data = url[1].split(":")
    var clear = $("<div></div>").attr("id", "clear-div").addClass("field");
    var addDiv = $("<div></div>").attr("id", "otp-conf-div").addClass("field unified-width");


    var image = $("<div/>").attr({"id" : "image"});
    var messageLabel = $("<p></p>").attr({"role": "alert", "id" : "add-info-msg"});
    var message;
	var code;
	if (add == 1) {
		message	= _localize("OTPCode").split("{0}");
		code = $("<p></p>").text(data[0]).addClass("otp-bold");
	} else {
		message	= _localize("OTPDeleteDevice");
	}
    messageLabel.append(message);
    loadJSFile("plugins/ns-gateway/qrcode.min.js", "image", data);

    var table = $("<table></table>").addClass("qrcode-image-table");
    var tr = $("<tr></tr>");
    tr.append($("<td></td>").addClass("qrcode-image-column").append(image));
	if (add == 1) {
		tr.append($("<td></td>").append(messageLabel, code).addClass("standaloneText label"));
	} else {
		tr.append($("<td></td>").append(messageLabel).addClass("standaloneText label"));
	}
	table.append(tr);
    addDiv.append(table);
	
	var testButton = $("<a></a>").attr({"id":"conf-device-button","class":"default button"}).css("cursor", "pointer").text(_localize("Done"));
	testButton.click(function(e) {
		e.preventDefault();
		$("#otp-conf-div").remove();
		$("#clear-div").remove();
		removeInfoMessage();
		$("#otp-val").val("");
		$("#text-container").slideUp(250);
		enableOTPButtons();
		if (add == 1) {
			displayMessage("confirmation", "OTPAddSuccess", deviceName);
		} else {
			displayMessage("confirmation", "OTPDeleteDeviceSuccess", deviceName);
		}
	});
	
	disableOTPButtons();
	addDiv.append(testButton);
	
	$("#text-container").hide();
	
	$("#registered-otp").prop('disabled', false);
	$("#otp-main").append(clear, addDiv);
	var option = $("<option></option>").text(deviceName).val(deviceName);
	var exists = false;
	$('#registered-otp option').each(function(){
		if (this.value == deviceName) {
			exists = true;
		}
	});
	if (exists == false) {
		$("#registered-otp").append(option);
		var noDevicesOption = $("#no-devices");
		if(noDevicesOption.length) {
			//Device was added from FTU. Shrink add button and show test and delete.
			$("#add-otp").text("").removeClass("padding-FTU").addClass("padding-normal");
			$(".otp-test-delete").show();
			noDevicesOption.remove();
		}
	}

	ListDevices();
}

function deleteDevice(e) { 
	e.preventDefault();
	if(($("#registered-otp").find("option").length == 0) ||
		($("#delete-otp").hasClass("otp-disabled"))) {
			return;
	}
	var deviceName = $("#registered-otp option:selected").text();

	CTXS.ExtensionAPI.showMessage({
		localize: true,
		messageText: _localize("OTPDeleteDeviceConfirm", deviceName),
		messageTitle: "OTPConfirmDelete",
		okButtonText: "Yes",
		cancelButtonText: "No",
		isalert: true,
		okAction: function() {
				$(".otp-text").val("").attr("command", "none");
				$("#text-container").slideUp(250);
				var postData = {};
				postData['devicename'] = $("#registered-otp").val();
				postData['command'] = 'rm';
				postData['csrf'] = nonce;
				sendOTPRequest(otpURL, postData, deleteSuccess, deleteSuccess);
		},
		cancelAction: function() {
		}
	});
}

function displayFTUUI() {
	$("#add-otp").text(_localize("OTPAddDeviceToolTip")).removeClass("padding-normal").addClass("padding-FTU");
	var noDevice = $("<option></option>").attr("id", "no-devices").text(_localize("OTPNoDevices"));
	$("#registered-otp").append(noDevice).prop('disabled', 'disabled');
	$(".otp-test-delete").hide();
}

function ListSuccess(responseData, textStatus, XMLHttpRequest) {
	if (responseData.length == 0 || responseData == "no") {
		//FTU Case
		displayFTUUI();
		return;
	}
	$("#registered-otp").empty().prop('disabled', false);
	var current_device = $(".otp-text").val();
	var devicenames = responseData.split(",")
	for(i=0; i<devicenames.length; i++) {
		var deviceName = decodeURIComponent(devicenames[i].replace(/\+/g, ' '));
		option = $("<option></option>").text(deviceName).val(deviceName);
		if(current_device == deviceName)
        {
           option.attr("selected","selected");
        }
		$("#registered-otp").append(option);
	}
}

function deleteAllDevices(e) {
	//e.preventDefault();
	if($("#registered-otp").find("option").length == 0) {
			//return;
	}
	CTXS.ExtensionAPI.showMessage({
			localize: true,
			messageText: "OTPDeleteAllConfirm",
			messageTitle: "OTPConfirmDelete",
			okButtonText: "Yes",
			cancelButtonText: "No",
			isalert: true,
			okAction: function() {
					var postData = {};
					postData['command'] = 'rm';
					postData['csrf'] = nonce;
					sendOTPRequest(otpURL, postData, deleteAllSuccess, deleteAllSuccess);
			},
			cancelAction: function() {
			}
	});
}

function deleteSuccess(responseData, textStatus, XMLHttpRequest) {
	var deviceName = $("#registered-otp option:selected").text();
	/* if push is enabled, show qrcode for deletion as well */
	if (responseData.indexOf("code=DUMMYCODEFORREMV") != -1) {
		OTPAddDeleteDeviceQRCode(0, responseData, testSuccess, XMLHttpRequest);
		return;
	}
	if (responseData.indexOf("yes") != -1) {
		$("#registered-otp option:selected").remove();
		displayMessage("confirmation", "OTPDeleteDeviceSuccess", deviceName);
		if($("#registered-otp option").length == 0) {
			displayFTUUI();
		}
	} else {
		displayMessage("error", "OTPDeleteDeviceFailure", deviceName);
	}
}

function deleteAllSuccess(responseData, textStatus, XMLHttpRequest) {
	if (responseData.indexOf("yes") != -1) {
		displayMessage("confirmation", "OTPDeleteAllSuccess");
		$("#registered-otp").empty();
	} else {
		displayMessage("error", "OTPDeleteAllFailure");
	}
        
}

function ListDevices(e) {
	sendOTPRequest(otpURL, "command=list&csrf=" + nonce, ListSuccess, ListSuccess);
	
	//adding button in ListDevices, so credentialform will be ready
	if(isInsideVPN())
	{
		var buttonRowDiv = $("<div></div>").addClass("field buttonsrow");
		var buttonDiv = $("<div></div>").addClass("buttonscontainer right");
		var buttonLink = $("<a></a>").addClass("button forms-authentication-button last-child default").text(_localize('LogOff'));
		buttonLink.click( function() {
			CTXS.Environment.logOff();
		});
		
		buttonRowDiv.append(buttonDiv);
		buttonDiv.append(buttonLink);
		$(".credentialform").append(buttonRowDiv);
		return;
	}
}

function displayMessage(type, text)
{
	$("#confirmation-msg").remove();
	var localizedText = text;

	if(arguments.length > 2) {
		localizedText = _localize(text, arguments[2]);
	} else {
		localizedText = _localize(text);
	}
	
	var message = $("<div></div>").addClass("standaloneText label " + type).attr({"role": "alert", "id" : "otp-message-text"}).text(localizedText);
	var div = $("<div></div>").addClass("left");
	div.append(message);
	var div2 = $("<div></div>").addClass("field").attr("id", "confirmation-msg");
	div2.append(div);
	$(".credentialform").append(div2);
}

function errorHandler(responseData, textStatus, XMLHttpRequest) {
	console.log("Error! Status = " + textStatus);
}

var nonce;
var otpURL = "/nf/auth/nsotp";

function sendOTPRequest(url, postData, successFunction, failureFunction)
{
	$.ctxsAjax({
			store: null,
			type: 'POST',
			url: url,
			dataType: 'text',
			data: postData,
			async: false,
			refreshSession: true,
			success: successFunction,
			error: failureFunction
	});
}


function createTopMenu() {
	//Inside VPN don't show menu. Instead we will show log off button 
	if(isInsideVPN())
		return;
	
	var menuItems = [];
	var $header = $("#customExplicitAuthHeader");
	$header.html("<header class=\"gateway store-header theme-header-bgcolor\"><span class=\"header-title theme-header-color phone-only\"></span><div class=\"headerRight\"><div class=\"dropdown-menu-container user-menu\"><a id=\"userMenuBtn\" href=\"#\" class=\"dropdown-menu-trigger settings-button\"><p class=\"theme-header-color user-display-name _ctxstxt_Menu\"></p><div class=\"settings-button-arrow view-sprite\"></div></a><div class=\"dropdown-menu\"><div class=\"dropdown-menu-top\"></div><div class=\"dropdown-menu-body\"></div><div class=\"dropdown-menu-bottom\"></div></div></div><a class=\"help-icon view-sprite\" href=\"#\"></a></div></header>");

	var $userMenu = $header.find('.user-menu.dropdown-menu-container');

	menuItems.push({
		linkId: "menuLogOffBtn_gateway",
		linkText: _localize('LogOff'),
		ariaLabel: _localize('LogOff'),
		toolTip: null,
		onClick: function() {
			// Wrapped so 'this' is set correctly
			CTXS.Environment.logOff();
		}
	});

	var userMenu = new CTXS.Widgets.DropDownMenuWidget($userMenu, $('#user-menu-overlay'), {
		menuItems: menuItems,
		menuItemClass: 'theme-highlight-color'
	});

	function SuccessCallback_username(username){
		$(".user-display-name").text(username);
	}
	CTXS.Environment.getUserDisplayName(SuccessCallback_username);
}

function disableOTPButtons() {
	$(".otp-action").addClass("otp-disabled");
}

function enableOTPButtons() {
	$(".otp-action").removeClass("otp-disabled");
}

/* OTP Functions End */

/*GwTest Functions Start */

/*Getting session details from PPE to display on RfWebUI */
function GetSummary(e) {
	sendGWTestRequest("/gwtest/getsummary", "command=list", GetSummarySuccess, GetSummarySuccess);
		$.ctxsAjax({
			store: null,
			type: 'GET',
			url: "/cgi/tmlogout",
			dataType: 'text',
			data: null,
			async: false,
			refreshSession: true,
			success: null,
			error: null
		});
}


/*Formatting the session details */
function GetSummarySuccess(responseData, textStatus, XMLHttpRequest) {
        $("#gwtest-summary").empty();
	var user_details = responseData.split("&");
	var table = $('<table border="1" bordercolor="black" style="font-family:Times New Roman, Times, serif; color:white;font-size:15px;text-align : center; border:solid black;"></table>');
	var i;
	for(i=0; i<user_details.length; i++) {
		var pair = user_details[i].split('=');
		table.append('<tr height="30px"><td>' + pair[0] + '</td><td>' + pair[1] + '</td></tr>');
	}
	$("#gwtest-summary").append(table);
}

/*Sending Ajax request to PPE to fetch session details for display */
function sendGWTestRequest(url, postData, successFunction, failureFunction) {
	$.ctxsAjax({
		store: null,
		type: 'POST',
		url: url,
	        dataType: 'text',
		data: postData,
		async: false,
		refreshSession: true,
		success: successFunction,
		error: failureFunction
	});
}

/*Gwtest Functions End */
/* Credential handler for handling negotiate/ntlm */
CTXS.ExtensionAPI.addCustomCredentialHandler({
    // The name of the credential, must match the type returned by the server
    getCredentialTypeName: function () { return "negotiate"; },
    // Generate HTML for the custom credential
    getCredentialTypeMarkup: function (requirements) {
        return $("<div></div>");
    },
    getDataToAutoPost: function ($form, requirements, success_callback) {
        var callback = success_callback;
		var negotiateURL = base64decode(requirements.input.text.initialValue);
		var context = negotiateURL;
		negotiateURL = "/nf/auth/doNegotiate.do?" + negotiateURL;
        $.ctxsAjax({
            store: null,
            type: 'POST',
            url: negotiateURL,
            dataType: 'text',
            async: false,
            refreshSession: true,
            success: function (data) {
                success_callback(data);
            },
            error: function (data) {
                success_callback("failure&"+context);
            }
        });
    }
});

/* Custom credential handler for otp or push based on checkbox */
CTXS.ExtensionAPI.addCustomCredentialHandler({
	// The name of the credential, must match the type returned by the server
	getCredentialTypeName: function () { return "nsg_push"; },
	// Generate HTML for the custom credential
	getCredentialTypeMarkup: function (requirements) {
		//This code is run just before a form is displayed to the user
		$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
			$('#otppush').click(function() {
				var passcodeField = $($(".credentialform").find(".CredentialTypepassword")[1]);
				var passwordField = $($(".credentialform").find(".CredentialTypepassword")[0]);
				if (passcodeField) {
					if($(this).is(':checked')){
						$("#passwd1").val("");
						passcodeField.hide();
						passwordField.show();
					} else {
						passcodeField.show();
						passwordField.show();
					}
				}
			});
		});
	}
});


/* Custom credential handler for push with fallback to manual otp based on checkbox */
CTXS.ExtensionAPI.addCustomCredentialHandler({
	// The name of the credential, must match the type returned by the server
	getCredentialTypeName: function () { return "nsg_push_otp"; },
	// Generate HTML for the custom credential
	getCredentialTypeMarkup: function (requirements) {
		//This code is run just before a form is displayed to the user
		$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
			var passcodeField = $($(".credentialform").find(".CredentialTypepassword")[1]);
			if (passcodeField) {
				if($('#otpmanualentry').is(':checked')) {
					passcodeField.show();
					$('#otppush').val("false");
				} else {
					$("#passwd1").val("");
					passcodeField.hide();
					$('#otppush').val("true");
				}
			}

			$('#otpmanualentry').click(function() {
				var passcodeField = $($(".credentialform").find(".CredentialTypepassword")[1]);
				var passwordField = $($(".credentialform").find(".CredentialTypepassword")[0]);
				if (passcodeField) {
					if($(this).is(':checked')){
						passcodeField.show();
						passwordField.show();
						$('#otppush').val("false");
					} else {
						$("#passwd1").val("");
						passcodeField.hide();
						passwordField.show();
						$('#otppush').val("true");
					}
				}
			});
		});
	}
});

CTXS.ExtensionAPI.addCustomCredentialHandler({
	// The name of the credential, must match the type returned by the server
	getCredentialTypeName: function () { return "nf_sspr_rem"; },
	// Generate HTML for the custom credential
	getCredentialTypeMarkup: function (requirements) {
		var div = $("<div></div>");
		var addLink = $("<a></a>").attr({"href":"#", "id":"forgotpasswddel", "title":_localize("ForgotPassword")});

		div.append(addLink);
		addLink.append(_localize("ForgotPassword"));

		//This code is run just before a form is displayed to the user
		$(document).on('ctxsformsauthenticationdisplayform', function (e, data) {
			$('#forgotpasswddel').click(function() {
				var passwordField = $('#passwd').parent().parent();
				var ssprField = $('#passwdreset');
				var forgotpasswdField = $('#forgotpasswddel').parent().parent();
				passwordField.remove();
				ssprField.val(1);
				forgotpasswdField.remove();
				$('#login').select();
			});
		});

		return div;
	},
});

/* We use same function for success/failure because incorrect sitekey
 * fails to load the captcha anyway.
 */
function captchaSiteKeySuccess(responseData, textStatus, XMLHttpRequest) {
	captcha.attr("data-sitekey", responseData);
}

function getCaptchaSiteKey()
{
	$.ctxsAjax({
			store: null,
			type: 'GET',
			url: "/nf/auth/captcha/sitekey",
			dataType: 'text',
			data: '',
			async: false,
			refreshSession: true,
			success: captchaSiteKeySuccess,
			error: captchaSiteKeySuccess
	});
}

function checkHeader(data, textStatus, myXMLHttpRequest){
       var header =  myXMLHttpRequest.getResponseHeader('X-VSERVER');
       if(header == "AAA"){
            $(".loading-logo").addClass("NS-AAA");
            $(".logon-logo-container").addClass("NS-AAA");
            $(".header_left").addClass("NS-AAA");
            $(".loading-message").show();

        }
        else{
            $(".loading-message").show();
            $("._ctxstxt_NetscalerAAA").addClass("_ctxstxt_NetscalerGateway").removeClass("_ctxstxt_NetscalerAAA");
        }
}

if (window.location.pathname === "/logon/LogonPoint/tmindex.html") {
    $.ajax({
        url : "/cgi/Resources/List",
        success : checkHeader,
        error : function (){
        	    $(".loading-message").show();
        	    return;
        },
        async :false,
        dataType : 'json'
    });
}

// Adding the Array.prototype.fill polyfill to enable Array.fill() usage in Elliptic.js file for older browsers(IE).
if (!Array.prototype.fill) {
	Array.prototype.fill = function (value) {
		if (this == null) {
			throw new Error('this is null or not defined');
		}
		var O = Object(this);
		var len = O.length >>> 0;
		var start = arguments[1];
		var relativeStart = start >> 0;
		var k = relativeStart < 0 ?
				Math.max(len + relativeStart, 0) :
				Math.min(relativeStart, len);
		var end = arguments[2];
		var relativeEnd = end === undefined ? len : end >> 0;
		var final = relativeEnd < 0 ?
		Math.max(len + relativeEnd, 0) :
		Math.min(relativeEnd, len);
		while (k < final) {
			O[k] = value;
			k++;
		}
		return O;
	};
}