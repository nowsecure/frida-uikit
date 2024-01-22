const UITouchPhaseBegan = 0;
const UITouchPhaseMoved = 1;
const UITouchPhaseStationary = 2;
const UITouchPhaseEnded = 3;
const UITouchPhaseCancelled = 4;

const UITOUCH_FLAG_IS_FIRST_TOUCH_FOR_VIEW = 1;
const UITOUCH_FLAG_IS_TAP = 2;

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
const CGPoint = [CGFloat, CGFloat];
const CGSize = [CGFloat, CGFloat];

const kIOHIDDigitizerEventRange = 0x00000001;
const kIOHIDDigitizerEventTouch = 0x00000002;
const kIOHIDDigitizerEventPosition = 0x00000004;

const Injector = ObjC.registerClass({
  methods: {
    '- init': function () {
      const self = this.super.init();
      const api = getApi();
      if (self !== null) {
        const displayLink = api.CADisplayLink.displayLinkWithTarget_selector_(self, ObjC.selector('dispatchTouch:'));
        ObjC.bind(self, {
          displayLink: displayLink,
          window: null,
          touch: null,
          pending: [],
          previous: null,
          onComplete: function () {}
        });
        displayLink.addToRunLoop_forMode_(api.NSRunLoop.mainRunLoop(), api.NSRunLoopCommonModes);
        displayLink.setPaused_(false);
      }
      return self;
    },
    '- dealloc': function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    '- dispatchTouch:': {
      retType: 'void',
      argTypes: ['object'],
      implementation: function (sender) {
        const priv = this.data;

        if (priv.pending.length === 0) {
          priv.displayLink.invalidate();
          priv.displayLink = null;

          priv.onComplete();
          return;
        }

        const api = getApi();
        let touch, phase;
        let point = priv.pending.shift();
        const isLastTouch = priv.pending.length === 0;

        if (priv.touch === null) {
          touch = api.UITouch.alloc().init();
          priv.touch = touch;
          touch.setTapCount_(1);
          setIsTap(touch, true);
          phase = UITouchPhaseBegan;
          touch.setPhase_(phase);
          touch.setWindow_(priv.window);
          touch['- _setLocationInWindow:resetPrevious:'].call(touch, point, true);
          touch.setView_(priv.window.hitTest_withEvent_(point, NULL));
          setIsFirstTouchForView(touch, true);
        } else {
          touch = priv.touch;

          if (isLastTouch) {
            touch['- _setLocationInWindow:resetPrevious:'].call(touch, priv.previous, false);
            phase = UITouchPhaseEnded;
            point = priv.previous;
          } else {
            touch['- _setLocationInWindow:resetPrevious:'].call(touch, point, false);
            phase = api.CGPointEqualToPoint(point, priv.previous) ? UITouchPhaseStationary : UITouchPhaseMoved;
          }

          touch.setPhase_(phase);
        }

        const app = api.UIApplication.sharedApplication();
        const event = app['- _touchesEvent'].call(app);
        event['- _clearTouches'].call(event);

        const absoluteTime = api.mach_absolute_time();

        const timestamp = [
            absoluteTime.shr(32).toNumber(),
            absoluteTime.and(0xffffffff).toNumber()
        ];

        touch.setTimestamp_(api.CFGetSystemUptime());

        const eventMask = (phase === UITouchPhaseMoved)
            ? kIOHIDDigitizerEventPosition
            : (kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch);
        const isRangeAndTouch = (phase !== UITouchPhaseEnded) ? 1 : 0;

        const hidEvent = api.IOHIDEventCreateDigitizerFingerEvent(
            api.kCFAllocatorDefault,
            timestamp,
            0,
            2,
            eventMask,
            point[0],
            point[1],
            0,
            0,
            0,
            isRangeAndTouch,
            isRangeAndTouch,
            0);

        if ('- _setHidEvent:' in touch) {
          touch['- _setHidEvent:'].call(touch, hidEvent);
        }

        event['- _setHIDEvent:'].call(event, hidEvent);
        event['- _addTouch:forDelayedDelivery:'].call(event, touch, false);

        const pool = api.NSAutoreleasePool.alloc().init();
        try {
          app.sendEvent_(event);
        } finally {
          pool.release();

          api.CFRelease(hidEvent);

          priv.previous = point;
          if (isLastTouch) {
            touch.release();
            priv.touch = null;
          }
        }
      }
    }
  }
});

export function tap(view, x, y) {
  return new Promise(function (resolve, reject) {
    const window = view.window();
    if (window === null) {
      reject(new Error('Cannot tap on NULL window'));
      return;
    }
    const { CGPointZero } = getApi();
    const point = view.convertPoint_toView_([x, y], NULL);

    const injector = Injector.alloc().init();
    const priv = ObjC.getBoundData(injector);
    priv.window = window;
    priv.pending.push(point, CGPointZero);
    priv.onComplete = function () {
      injector.release();
      resolve();
    };
  });
}

function setIsTap (touch, isTap) {
  const flags = touch.$ivars['_touchFlags'];
  const newFlags = [...flags];
  if (isTap) {
    newFlags[0] |= UITOUCH_FLAG_IS_TAP;
  } else {
    newFlags[0] &= ~UITOUCH_FLAG_IS_TAP;
  }
  touch.$ivars['_touchFlags'] = newFlags;
}

function setIsFirstTouchForView (touch, isFirst) {
  const flags = touch.$ivars['_touchFlags'];
  const newFlags = [...flags];
  if (isFirst) {
    newFlags[0] |= UITOUCH_FLAG_IS_FIRST_TOUCH_FOR_VIEW;
  } else {
    newFlags[0] &= ~UITOUCH_FLAG_IS_FIRST_TOUCH_FOR_VIEW;
  }
  touch.$ivars['_touchFlags'] = newFlags;
}

let _api = null;

function getApi () {
  if (_api === null) {
    _api = {
      CADisplayLink: ObjC.classes.CADisplayLink,
      NSAutoreleasePool: ObjC.classes.NSAutoreleasePool,
      NSRunLoop: ObjC.classes.NSRunLoop,
      UIApplication: ObjC.classes.UIApplication,
      UITouch: ObjC.classes.UITouch,
      CGPointEqualToPoint: new NativeFunction(
          Module.getExportByName('CoreGraphics', 'CGPointEqualToPoint'),
          'uint8',
          [CGPoint, CGPoint]
      ),
      CGPointZero: Module.getExportByName('CoreGraphics', 'CGPointZero').readPointer(),
      IOHIDEventCreateDigitizerFingerEvent: new NativeFunction(
          Module.getExportByName(null, 'IOHIDEventCreateDigitizerFingerEvent'),
          'pointer',
          [
              'pointer',            // allocator
              ['uint32', 'uint32'], // timestamp
              'uint32',             // index
              'uint32',             // identity
              'uint32',             // eventMask
              CGFloat,              // x
              CGFloat,              // y
              CGFloat,              // z
              CGFloat,              // tipPressure
              CGFloat,              // twist
              'uint8',              // range
              'uint8',              // touch
              'uint32'              // options
          ]
      ),
      kCFAllocatorDefault: Module.getExportByName('CoreFoundation', 'kCFAllocatorDefault').readPointer(),
      NSRunLoopCommonModes: Module.getExportByName('Foundation', 'NSRunLoopCommonModes').readPointer(),
      CFGetSystemUptime: new NativeFunction(
          Module.getExportByName('CoreFoundation', 'CFGetSystemUptime'),
          'double',
          []
      ),
      CFRelease: new NativeFunction(
          Module.getExportByName('CoreFoundation', 'CFRelease'),
          'void',
          ['pointer']
      ),
      mach_absolute_time: new NativeFunction(
          Module.getExportByName('libSystem.B.dylib', 'mach_absolute_time'),
          'uint64',
          []
      ),
    };
  }

  return _api;
}
