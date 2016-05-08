'use strict'
requirejs.config({
	urlArgs : "ver=" + (new Date()).getTime(),
	paths : {
		"jquery" : "jquery-2.1.3.min",
		"sha256" : "sha256.min",
		"bootstrap" : "bootstrap.min"
	},
	shim : {
		"jquery" : {
			exports : [ "$", "jQuery" ]
		},
		"sha256" : {},
		"bootstrap" : {
			deps : [ "jquery" ]
		}
	}
});

define([ "jquery", "bootstrap", "sha256" ], function($) {
	$('#login-form').on('submit', function() {
		var pass = $('#login-password').val();
		var key = $('#login-key').val();
		if (pass) {
			var hash = Sha256.hash(pass);
			if (key) {
				hash = Sha256.hash(hash + key);
			}
			$('#login-encrypted').val(hash);
			$('#login-password').val("");
			$('#login-form').attr("action", "login.html");
			$('#login-form').submit();
		}
	});
	
	var count=900; //15min
	var counter = setInterval(timer, 1000);
	function timer() {
		count = count - 1;
		if (count <= 0) {
			clearInterval(counter);
			$('#login-form input').prop("disabled", true);
			$('#login-message').html('<i class="icon-exclamation"></i> Please refresh this page. <a href="login.html" class="warning"><i class="icon-cw"></i> Refresh</a>');
			return;
		}
	}
});
