

if (window['__PACE__'] === undefined) {
  location.reload();
}
setInterval(function () {
  if (!__PACE__.alive()) {
    __PACE__.kill();
  }
}, 5000);
setInterval(function () {
  if (window['__PACE__'].fingerprint() !== _PACE_FUSION_.expected) {
    __PACE__.kill();
  }
}, 12000);
var ilok_token = 'redacted-ilok-bind-id';
var _PACE_FUSION_ = {
  expected: '0xfeedface',
};
function realWork() {
  return 'unrelated business logic';
}
