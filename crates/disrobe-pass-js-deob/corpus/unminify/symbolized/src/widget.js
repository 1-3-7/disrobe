export function mountWidget(root, options) {
  var listeners = [];
  var counter = 0;

  function increment(event) {
    counter = counter + 1;
    event.preventDefault();
    render();
  }

  function render() {
    var label = root.querySelector('.count');
    label.textContent = String(counter);
    for (var index = 0; index < listeners.length; index++) {
      listeners[index](counter);
    }
  }

  function subscribe(callback) {
    listeners.push(callback);
    return function unsubscribe() {
      var position = listeners.indexOf(callback);
      if (position >= 0) {
        listeners.splice(position, 1);
      }
    };
  }

  var button = root.querySelector('button');
  button.addEventListener('click', increment);
  if (options && options.initial) {
    counter = options.initial;
  }
  render();

  return {
    subscribe: subscribe,
    destroy: function destroy() {
      button.removeEventListener('click', increment);
      listeners.length = 0;
    }
  };
}
