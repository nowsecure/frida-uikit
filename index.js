import { UINode } from './lib/node.js';
export { UINode } from './lib/node.js';

const UIWindow = ObjC.classes.UIWindow;

export function get(predicate) {
  return new Promise((resolve, reject) => {
    let tries = 0;
    function tryResolve() {
      ObjC.schedule(ObjC.mainQueue, () => {
        const window = UIWindow.keyWindow();
        const layout = new UINode(window);
        const node = layout.find(predicate);
        if (node !== null) {
          resolve(node);
          return;
        }

        // TODO: configurable timeout and retry interval
        tries++;
        if (tries < 40) {
          setTimeout(tryResolve, 500);
        } else {
          reject(new Error('Timed out'));
        }
      });
    }
    tryResolve();
  });
}

