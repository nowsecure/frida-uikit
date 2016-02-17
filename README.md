# frida-uikit

Inspect and manipulate UIKit-based GUIs through [Frida](http://frida.re).

## Example

```js
const ui = require('frida-uikit');

const username = yield ui.get(node => node.type === 'UITextField');
username.setText('john.doe');
```
