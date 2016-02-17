'use strict';

const NSThread = ObjC.classes.NSThread;
const UIButtonClass = ObjC.classes.UIButton.class();
const UILabelClass = ObjC.classes.UILabel.class();
const UITextFieldClass = ObjC.classes.UITextField.class();
let UIWebViewClass = null;
const UIWindow = ObjC.classes.UIWindow;
const UIWindowClass = UIWindow.class();

const UIControlEventTouchUpInside = 1 << 6;

function get(predicate) {
  return new Promise(function (resolve, reject) {
    let tries = 0;
    function tryResolve() {
      ObjC.schedule(ObjC.mainQueue, function () {
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

function UINode(view) {
  this.instance = view;

  if (UIWebViewClass === null) {
    // Cannot access this type early
    UIWebViewClass = ObjC.classes.UIWebView.class();
  }

  if (view.isKindOfClass_(UIWindowClass)) {
    this.type = 'UIWindow';
  } else if (view.isKindOfClass_(UIButtonClass)) {
    this.type = 'UIButton';
  } else if (view.isKindOfClass_(UILabelClass)) {
    this.type = 'UILabel';
  } else if (view.isKindOfClass_(UITextFieldClass)) {
    this.type = 'UITextField';
  } else if (view.isKindOfClass_(UIWebViewClass)) {
    this.type = 'UIWebView';
  } else {
    this.type = 'UIView';
  }
  this.className = view.$className;
  this._enabled = null;
  this._label = null;

  const children = [];
  const subviews = view.subviews();
  const count = subviews.count();
  for (let i = 0; i !== count; i++) {
    children.push(new UINode(subviews.objectAtIndex_(i)));
  }
  this.children = children;
}

UINode.prototype = {
  get enabled() {
    if (this._enabled === null) {
      const instance = this.instance;
      if ('enabled' in instance) {
        this._enabled = !!instance.enabled();
      } else {
        this._enabled = true;
      }
    }
    return this._enabled;
  },
  get label() {
    if (this._label === null) {
      const instance = this.instance;
      if ('accessibilityLabel' in instance) {
        const accLabel = instance.accessibilityLabel();
        if (accLabel !== null) {
          this._label = accLabel.toString();
        }
      }
      if (this._label === null) {
        if ('placeholder' in instance) {
          this._label = readStringProperty(instance.placeholder());
        } else if ('text' in instance) {
          this._label = readStringProperty(instance.text());
        } else {
          this._label = '';
        }
      }
    }
    return this._label;
  },
  forEach(fn) {
    fn(this);
    this.children.forEach(child => child.forEach(fn));
  },
  find(predicate) {
    if (predicate(this)) {
      return this;
    }

    const children = this.children;
    for (let i = 0; i !== children.length; i++) {
      const child = children[i].find(predicate);
      if (child !== null) {
        return child;
      }
    }

    return null;
  },
  setText(text) {
    return performOnMainThread(() => {
      const instance = this.instance;
      instance.becomeFirstResponder();
      instance.setText_('');
      instance.deleteBackward();
      instance.insertText_(text);
      instance.resignFirstResponder();
    });
  },
  tap() {
    return performOnMainThread(() => {
      this.instance.sendActionsForControlEvents_(UIControlEventTouchUpInside);
    });
  }
};

function performOnMainThread(action) {
  return new Promise(function (resolve, reject) {
    if (NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }

    function performAction() {
      try {
        const result = action();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    }
  });
}

function readStringProperty(value) {
  return (value !== null) ? value.toString() : '';
}

module.exports = {
  get: get,
  UINode: UINode
};
