# frida-uikit

Inspect and manipulate UIKit-based GUIs through [Frida](https://www.frida.re).

## Example

```js
const ui = require('frida-uikit');

const username = await ui.get(node => node.type === 'UITextField');
username.setText('john.doe');
```
