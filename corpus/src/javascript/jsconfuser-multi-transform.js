var _$_$ = console;
var _$$_ = _$_$;
var greeting = '\x68\x65\x6c\x6c\x6f';
var parts = 'alpha|beta|gamma'.split('|');

if (window.location.hostname !== 'attacker.com') {
  return;
}

if (!![]) {
  _$$_.log(greeting, parts[0]);
}
